//! Routing intents ("these networks go this way") enforced by the helper.
//!
//! The rules (what a request may say, which routes it wants, how the system's
//! table compares) live in `core::route_intents` and are tested there. This
//! module keeps the intents across restarts, installs and removes the routes,
//! and reconciles them with the live network: an intent whose device is absent
//! waits, a route someone removed is put back, a route that is not ours is
//! never touched.
//!
//! The store also records the exact routes the helper installed, so a removal
//! or a crash recovery undoes those and nothing else.

use crate::routes::{RouteOp, Target};
use crate::sysexec::Runner;
use crate::xray::Error;
use ipnet::IpNet;
use net_manager_core::daemon_protocol::{
    CondRulesPutResult, CondRulesRemoveResult, ConditionalRouteRule, ConditionalRuleEntry,
    NetIntentResult, NetIntentSetParams, NetIntentView,
};
use net_manager_core::models::RouteEntry;
use net_manager_core::route_conditions::{
    condition_match, derive_rule, rule_status, validate_rule, MAX_RULES,
};
use net_manager_core::route_intents::{
    derive, judge, normalize, view, Derivation, NetworkView, RouteState, RouteTarget, WantedRoute,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DOCUMENT_VERSION: u32 = 1;
const MAX_INTENTS_PER_UID: usize = 64;
const MAX_DESTINATIONS_TOTAL: usize = 256;
/// A full comparison with the route table at least this often.
const FULL_CHECK: Duration = Duration::from_secs(10);

/// The network as the reconcile sees it. Real on the machine, a fake in tests.
pub trait NetworkProbe: Send + Sync {
    fn view(&self) -> NetworkView;
    fn routes(&self) -> Vec<RouteEntry>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    uid: u32,
    /// The request as it was accepted; checked again when it is loaded.
    params: NetIntentSetParams,
    /// Routes this helper installed for the intent.
    #[serde(default)]
    installed: Vec<RouteOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRule {
    uid: u32,
    rule: ConditionalRouteRule,
    #[serde(default)]
    installed: Vec<RouteOp>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    version: u32,
    intents: Vec<Stored>,
    /// Absent in a store written before conditional rules existed.
    #[serde(default)]
    conditions: Vec<StoredRule>,
}

struct State {
    intents: Vec<Stored>,
    rules: Vec<StoredRule>,
    last_view: Option<NetworkView>,
    last_full: Option<Instant>,
}

pub struct IntentExecutor {
    runner: Box<dyn Runner>,
    probe: Box<dyn NetworkProbe>,
    path: PathBuf,
    state: Mutex<State>,
}

fn target_of(target: &RouteTarget) -> Target {
    match target {
        RouteTarget::Gateway(address) => Target::Gateway { address: *address },
        RouteTarget::Interface(name) => Target::Interface { name: name.clone() },
    }
}

fn op_of(wanted: &WantedRoute) -> RouteOp {
    RouteOp {
        network: wanted.destination.network(),
        prefix: wanted.destination.prefix_len(),
        target: target_of(&wanted.target),
        optional: false,
    }
}

/// The route an installed op stands for.
fn wanted_of(op: &RouteOp) -> Option<WantedRoute> {
    Some(WantedRoute {
        destination: IpNet::new(op.network, op.prefix).ok()?.trunc(),
        target: match &op.target {
            Target::Gateway { address } => RouteTarget::Gateway(*address),
            Target::Interface { name } => RouteTarget::Interface(name.clone()),
        },
    })
}

fn invalid(message: String) -> Error {
    Error::Invalid(message)
}

impl IntentExecutor {
    /// Loads the stored intents. A document that cannot be read is an error:
    /// silently starting empty would forget routes the helper installed.
    pub fn new(
        runner: Box<dyn Runner>,
        probe: Box<dyn NetworkProbe>,
        path: PathBuf,
    ) -> io::Result<Self> {
        let (intents, rules) = match fs::read(&path) {
            Ok(bytes) => {
                let document: Document = serde_json::from_slice(&bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "corrupt intents"))?;
                (document.intents, document.conditions)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Vec::new(), Vec::new()),
            Err(error) => return Err(error),
        };
        Ok(Self {
            runner,
            probe,
            path,
            state: Mutex::new(State {
                intents,
                rules,
                last_view: None,
                last_full: None,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, state: &State) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let document = Document {
            version: DOCUMENT_VERSION,
            intents: state.intents.clone(),
            conditions: state.rules.clone(),
        };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&serde_json::to_vec(&document).map_err(io::Error::other)?)?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)
    }

    /// Adds or replaces the caller's intent and applies it at once.
    pub fn set(&self, uid: u32, params: NetIntentSetParams) -> Result<NetIntentResult, Error> {
        let intent = normalize(&params).map_err(invalid)?;
        let mut state = self.lock();
        let position = state
            .intents
            .iter()
            .position(|s| s.uid == uid && s.params.id == intent.id);
        let mine = state.intents.iter().filter(|s| s.uid == uid).count();
        if position.is_none() && mine >= MAX_INTENTS_PER_UID {
            return Err(Error::Conflict(format!(
                "There can be at most {MAX_INTENTS_PER_UID} intents"
            )));
        }
        let others: usize = state
            .intents
            .iter()
            .enumerate()
            .filter(|(index, _)| Some(*index) != position)
            .map(|(_, s)| s.params.destinations.len())
            .sum::<usize>()
            + state
                .rules
                .iter()
                .map(|r| r.rule.routes.len())
                .sum::<usize>();
        if others + intent.destinations.len() > MAX_DESTINATIONS_TOTAL {
            return Err(Error::Conflict(format!(
                "All intents together can route at most {MAX_DESTINATIONS_TOTAL} networks"
            )));
        }
        // Keep what the old version installed so the reconcile can diff it.
        let installed = position
            .map(|index| state.intents[index].installed.clone())
            .unwrap_or_default();
        let stored = Stored {
            uid,
            params: NetIntentSetParams {
                id: intent.id.clone(),
                destinations: intent
                    .destinations
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                path: params.path,
                metric: Some(intent.metric),
                enabled: Some(intent.enabled),
            },
            installed,
        };
        match position {
            Some(index) => state.intents[index] = stored,
            None => state.intents.push(stored),
        }
        self.reconcile_locked(&mut state);
        self.save(&state)
            .map_err(|_| Error::Unavailable("The intents could not be saved".into()))?;
        Ok(NetIntentResult { id: intent.id })
    }

    /// Removes the caller's intent and the routes it installed.
    pub fn delete(&self, uid: u32, id: &str) -> Result<NetIntentResult, Error> {
        let mut state = self.lock();
        let Some(index) = state
            .intents
            .iter()
            .position(|s| s.uid == uid && s.params.id == id)
        else {
            return Err(Error::NotFound("There is no intent with that name".into()));
        };
        let table = self.probe.routes();
        let removed = state.intents.remove(index);
        self.withdraw(&removed.installed, &table);
        self.save(&state)
            .map_err(|_| Error::Unavailable("The intents could not be saved".into()))?;
        Ok(NetIntentResult { id: id.to_string() })
    }

    /// The caller's intents with their live status. Changes nothing.
    pub fn list(&self, uid: u32) -> Vec<NetIntentView> {
        let state = self.lock();
        let network = self.probe.view();
        let table = self.probe.routes();
        state
            .intents
            .iter()
            .filter(|s| s.uid == uid)
            .filter_map(|stored| {
                let intent = normalize(&stored.params).ok()?;
                let derivation = derive(&intent, &network);
                let states = self.judge_all(&derivation, &stored.installed, &table);
                Some(view(&intent, &derivation, &states))
            })
            .collect()
    }

    // ---- conditional rules ----------------------------------------------

    fn rule_entry(
        &self,
        stored: &StoredRule,
        network: &NetworkView,
        table: &[RouteEntry],
    ) -> ConditionalRuleEntry {
        let derivation = derive_rule(&stored.rule, network);
        let states = self.judge_all(&derivation, &stored.installed, table);
        let matched = condition_match(&stored.rule, network);
        ConditionalRuleEntry {
            rule: stored.rule.clone(),
            status: rule_status(&stored.rule, &derivation, &states, matched.as_deref()),
        }
    }

    /// Adds or replaces the caller's rule and evaluates it at once.
    pub fn put_rule(
        &self,
        uid: u32,
        rule: ConditionalRouteRule,
    ) -> Result<CondRulesPutResult, Error> {
        validate_rule(&rule).map_err(invalid)?;
        let mut state = self.lock();
        let position = state
            .rules
            .iter()
            .position(|r| r.uid == uid && r.rule.id == rule.id);
        let mine = state.rules.iter().filter(|r| r.uid == uid).count();
        if position.is_none() && mine >= MAX_RULES {
            return Err(Error::Conflict(format!(
                "There can be at most {MAX_RULES} conditional rules"
            )));
        }
        let others: usize = state
            .intents
            .iter()
            .map(|s| s.params.destinations.len())
            .sum::<usize>()
            + state
                .rules
                .iter()
                .enumerate()
                .filter(|(index, _)| Some(*index) != position)
                .map(|(_, r)| r.rule.routes.len())
                .sum::<usize>();
        if others + rule.routes.len() > MAX_DESTINATIONS_TOTAL {
            return Err(Error::Conflict(format!(
                "All intents and rules together can route at most {MAX_DESTINATIONS_TOTAL} networks"
            )));
        }
        let installed = position
            .map(|index| state.rules[index].installed.clone())
            .unwrap_or_default();
        let id = rule.id.clone();
        let stored = StoredRule {
            uid,
            rule,
            installed,
        };
        match position {
            Some(index) => state.rules[index] = stored,
            None => state.rules.push(stored),
        }
        self.reconcile_locked(&mut state);
        self.save(&state)
            .map_err(|_| Error::Unavailable("The rules could not be saved".into()))?;
        let network = self.probe.view();
        let table = self.probe.routes();
        let entry = state
            .rules
            .iter()
            .find(|r| r.uid == uid && r.rule.id == id)
            .map(|stored| self.rule_entry(stored, &network, &table))
            .expect("just stored");
        Ok(CondRulesPutResult {
            stored: true,
            status: entry.status,
        })
    }

    /// Removes the caller's rule and the routes it installed.
    pub fn remove_rule(&self, uid: u32, id: &str) -> CondRulesRemoveResult {
        let mut state = self.lock();
        let Some(index) = state
            .rules
            .iter()
            .position(|r| r.uid == uid && r.rule.id == id)
        else {
            return CondRulesRemoveResult { removed: false };
        };
        let table = self.probe.routes();
        let removed = state.rules.remove(index);
        self.withdraw(&removed.installed, &table);
        let _ = self.save(&state);
        CondRulesRemoveResult { removed: true }
    }

    /// The caller's rules with their live status. Changes nothing.
    pub fn list_rules(&self, uid: u32) -> Vec<ConditionalRuleEntry> {
        let state = self.lock();
        let network = self.probe.view();
        let table = self.probe.routes();
        state
            .rules
            .iter()
            .filter(|r| r.uid == uid)
            .map(|stored| self.rule_entry(stored, &network, &table))
            .collect()
    }

    /// Whether any intent is stored (the background tick does nothing else).
    pub fn is_empty(&self) -> bool {
        let state = self.lock();
        state.intents.is_empty() && state.rules.is_empty()
    }

    /// Brings the system in line with every intent, regardless of caller.
    pub fn reconcile(&self) {
        let mut state = self.lock();
        self.reconcile_locked(&mut state);
        let _ = self.save(&state);
    }

    /// Cheap enough for a 2-second loop: nothing to do without intents, a
    /// full comparison when the network changed or every [`FULL_CHECK`].
    pub fn tick(&self) {
        let mut state = self.lock();
        if state.intents.is_empty() && state.rules.is_empty() {
            return;
        }
        let view = self.probe.view();
        let changed = state.last_view.as_ref() != Some(&view);
        let due = state.last_full.is_none_or(|at| at.elapsed() >= FULL_CHECK);
        if !changed && !due {
            return;
        }
        self.reconcile_locked(&mut state);
        let _ = self.save(&state);
    }

    /// Takes the installed routes out of the system and keeps the intents, so
    /// nothing lingers while the helper is not running; they come back at the
    /// next start.
    pub fn shutdown(&self) {
        let mut state = self.lock();
        let table = self.probe.routes();
        let mut installed: Vec<RouteOp> = state
            .intents
            .iter_mut()
            .flat_map(|s| std::mem::take(&mut s.installed))
            .collect();
        installed.extend(
            state
                .rules
                .iter_mut()
                .flat_map(|r| std::mem::take(&mut r.installed)),
        );
        self.withdraw(&installed, &table);
        let _ = self.save(&state);
    }

    // ---- internals -------------------------------------------------------

    /// One verdict per route the derivation wants.
    fn judge_all(
        &self,
        derivation: &Derivation,
        installed: &[RouteOp],
        table: &[RouteEntry],
    ) -> Vec<RouteState> {
        match derivation {
            Derivation::Routes { routes, .. } => routes
                .iter()
                .map(|wanted| judge(wanted, installed.contains(&op_of(wanted)), table))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Deletes routes this helper installed, but only those still in place as
    /// installed: a foreign route that took the destination over is left.
    fn withdraw(&self, ops: &[RouteOp], table: &[RouteEntry]) {
        for op in ops {
            let still_ours = wanted_of(op)
                .is_some_and(|wanted| judge(&wanted, true, table) == RouteState::Present);
            if still_ours {
                let _ = op.delete(&*self.runner);
            }
        }
    }

    fn reconcile_locked(&self, state: &mut State) {
        let network = self.probe.view();
        let mut table = self.probe.routes();
        for stored in &mut state.intents {
            let Ok(intent) = normalize(&stored.params) else {
                continue;
            };
            let derivation = derive(&intent, &network);
            // What the previous steps changed must be visible to the next
            // comparison, or a route we just removed looks like a rival.
            if self.apply(&mut stored.installed, &derivation, &table) {
                table = self.probe.routes();
            }
        }
        for stored in &mut state.rules {
            let derivation = derive_rule(&stored.rule, &network);
            if self.apply(&mut stored.installed, &derivation, &table) {
                table = self.probe.routes();
            }
        }
        state.last_view = Some(network);
        state.last_full = Some(Instant::now());
    }

    /// Makes `installed` match what `derivation` wants: removes routes no
    /// longer wanted, adds missing ones, forgets (never deletes) routes
    /// someone else now holds. Returns whether it ran a route command.
    fn apply(
        &self,
        installed: &mut Vec<RouteOp>,
        derivation: &Derivation,
        table: &[RouteEntry],
    ) -> bool {
        let wanted = match derivation {
            Derivation::Routes { routes, .. } => routes.as_slice(),
            _ => &[],
        };
        let wanted_ops: Vec<RouteOp> = wanted.iter().map(op_of).collect();
        // Routes no longer wanted (path changed, switched off, device gone).
        let (keep, stale): (Vec<RouteOp>, Vec<RouteOp>) =
            installed.drain(..).partition(|op| wanted_ops.contains(op));
        let mut changed = !stale.is_empty();
        self.withdraw(&stale, table);
        *installed = keep;
        let fresh;
        let table = if changed {
            fresh = self.probe.routes();
            &fresh[..]
        } else {
            table
        };
        for (route, op) in wanted.iter().zip(&wanted_ops) {
            let ours = installed.contains(op);
            match judge(route, ours, table) {
                RouteState::Present => {}
                RouteState::Missing => {
                    changed = true;
                    if op.add(&*self.runner).is_ok() && !ours {
                        installed.push(op.clone());
                    }
                }
                RouteState::Conflicted(_) => installed.retain(|existing| existing != op),
            }
        }
        changed
    }
}

/// The real network: `route`/`ifconfig` through the runner, the route table
/// through the same reader the app uses, run on the helper's runtime.
pub struct SystemProbe {
    runner: Box<dyn Runner>,
    runtime: tokio::runtime::Handle,
}

impl SystemProbe {
    pub fn new(runner: Box<dyn Runner>, runtime: tokio::runtime::Handle) -> Self {
        Self { runner, runtime }
    }
}

impl NetworkProbe for SystemProbe {
    fn view(&self) -> NetworkView {
        let uplink = crate::routes::detect_uplink(&*self.runner)
            .ok()
            .map(|uplink| net_manager_core::route_intents::Uplink {
                interface: uplink.interface,
                gateway: uplink.gateway.map(std::net::IpAddr::V4),
            });
        let interfaces = self
            .runner
            .run(crate::sysexec::IFCONFIG, &["-l".to_string()])
            .map(|list| list.split_whitespace().map(String::from).collect())
            .unwrap_or_default();
        // Addresses for conditional rules, as the app's own interface list
        // reads them.
        let addresses = net_manager_core::explorer::list_interfaces()
            .unwrap_or_default()
            .into_iter()
            .flat_map(|interface| {
                let (if_index, name) = (interface.if_index, interface.name);
                interface.addresses.into_iter().filter_map(move |a| {
                    Some(net_manager_core::route_intents::IfaceAddr {
                        if_index,
                        interface: name.clone(),
                        address: IpNet::new(a.address, a.prefix_len).ok()?,
                    })
                })
            })
            .collect();
        NetworkView {
            uplink,
            interfaces,
            addresses,
        }
    }

    fn routes(&self) -> Vec<RouteEntry> {
        self.runtime
            .block_on(net_manager_core::explorer::list_routes())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{
        ConditionalRouteRule, ConditionalRuleState, ExplainStatus, NetIntentPath, RouteCondition,
    };
    use net_manager_core::models::PolicyRoute;
    use net_manager_core::route_conditions::MAX_RULES;
    use net_manager_core::route_intents::{Uplink, MAX_DESTINATIONS};
    use std::net::IpAddr;
    use std::sync::Arc;

    /// A route table the runner really edits, so a reconcile can be followed
    /// from the commands it runs to what it finds next time.
    #[derive(Default)]
    struct World {
        table: Mutex<Vec<RouteEntry>>,
        view: Mutex<NetworkView>,
        commands: Mutex<Vec<String>>,
        fail_adds: Mutex<bool>,
    }

    impl World {
        fn new(interfaces: &[&str]) -> Arc<Self> {
            let world = Arc::new(Self::default());
            *world.view.lock().unwrap() = NetworkView {
                uplink: Some(Uplink {
                    interface: "en0".into(),
                    gateway: Some("192.168.1.1".parse().unwrap()),
                }),
                interfaces: interfaces.iter().map(ToString::to_string).collect(),
                addresses: Vec::new(),
            };
            world
        }
        fn commands(&self) -> Vec<String> {
            self.commands.lock().unwrap().clone()
        }
        fn routes(&self) -> Vec<(String, String)> {
            self.table
                .lock()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        format!("{}/{}", e.destination, e.prefix_len),
                        e.gateway
                            .map(|g| g.to_string())
                            .unwrap_or_else(|| e.interface_name.clone()),
                    )
                })
                .collect()
        }
        fn foreign(&self, destination: &str, prefix: u8, interface: &str) {
            self.table.lock().unwrap().push(RouteEntry {
                destination: destination.parse().unwrap(),
                prefix_len: prefix,
                gateway: None,
                interface_index: 1,
                interface_name: interface.into(),
                metric: 0,
            });
        }
    }

    struct Sim(Arc<World>);
    impl Runner for Sim {
        fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
            self.0.commands.lock().unwrap().push(format!(
                "{} {}",
                program.rsplit('/').next().unwrap(),
                args.join(" ")
            ));
            if program != crate::sysexec::ROUTE {
                return Ok(String::new());
            }
            let add = args[1] == "add";
            if add && *self.0.fail_adds.lock().unwrap() {
                return Err(io::Error::other(
                    "route: writing to routing socket: File exists",
                ));
            }
            // -net A -netmask M | -host A, then -gateway G | -interface I
            let word = |key: &str| {
                args.iter()
                    .position(|a| a == key)
                    .map(|i| args[i + 1].clone())
            };
            let destination: IpAddr = word("-net")
                .or_else(|| word("-host"))
                .unwrap()
                .parse()
                .unwrap();
            let prefix = match word("-netmask") {
                Some(mask) => {
                    let mask: std::net::Ipv4Addr = mask.parse().unwrap();
                    u32::from(mask).count_ones() as u8
                }
                None => {
                    if destination.is_ipv4() {
                        32
                    } else {
                        128
                    }
                }
            };
            let mut table = self.0.table.lock().unwrap();
            if add {
                table.push(RouteEntry {
                    destination,
                    prefix_len: prefix,
                    gateway: word("-gateway").map(|g| g.parse().unwrap()),
                    interface_index: 1,
                    interface_name: word("-interface").unwrap_or_else(|| "en0".into()),
                    metric: 0,
                });
            } else {
                table.retain(|e| !(e.destination == destination && e.prefix_len == prefix));
            }
            Ok(String::new())
        }
    }

    struct Probe(Arc<World>);
    impl NetworkProbe for Probe {
        fn view(&self) -> NetworkView {
            self.0.view.lock().unwrap().clone()
        }
        fn routes(&self) -> Vec<RouteEntry> {
            self.0.table.lock().unwrap().clone()
        }
    }

    fn executor(world: &Arc<World>, dir: &tempfile::TempDir) -> IntentExecutor {
        IntentExecutor::new(
            Box::new(Sim(world.clone())),
            Box::new(Probe(world.clone())),
            dir.path().join("intents.json"),
        )
        .unwrap()
    }

    fn params(id: &str, destinations: &[&str], path: NetIntentPath) -> NetIntentSetParams {
        NetIntentSetParams {
            id: id.into(),
            destinations: destinations.iter().map(ToString::to_string).collect(),
            path,
            metric: None,
            enabled: None,
        }
    }
    fn via(name: &str) -> NetIntentPath {
        NetIntentPath {
            gateway: None,
            kind: "interface".into(),
            interface: Some(name.into()),
        }
    }
    fn direct() -> NetIntentPath {
        NetIntentPath {
            gateway: None,
            kind: "direct".into(),
            interface: None,
        }
    }
    const ME: u32 = 501;

    #[test]
    fn setting_an_intent_installs_its_routes_and_lists_them_as_effective() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(
            ME,
            params("office", &["10.0.0.0/8", "172.16.0.0/12"], via("utun5")),
        )
        .unwrap();
        assert_eq!(
            world.routes(),
            [
                ("10.0.0.0/8".into(), "utun5".into()),
                ("172.16.0.0/12".into(), "utun5".into())
            ]
        );
        let list = exec.list(ME);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, ExplainStatus::Effective);
        assert_eq!((list[0].installed, list[0].wanted), (2, 2));
    }

    #[test]
    fn a_direct_intent_goes_through_the_uplink_gateway() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("lan", &["10.9.0.0/16"], direct()))
            .unwrap();
        assert_eq!(
            world.routes(),
            [("10.9.0.0/16".into(), "192.168.1.1".into())]
        );
    }

    #[test]
    fn a_gateway_intent_waits_for_its_network_and_leaves_with_it() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        let gateway = NetIntentPath {
            gateway: Some("10.0.0.1".into()),
            kind: "gateway".into(),
            interface: None,
        };
        exec.set(ME, params("lab", &["192.0.2.0/24"], gateway))
            .unwrap();
        assert!(world.routes().is_empty());
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Deferred);
        {
            let mut view = world.view.lock().unwrap();
            view.addresses = vec![net_manager_core::route_intents::IfaceAddr {
                if_index: 15,
                interface: "en0".into(),
                address: "10.0.0.5/24".parse().unwrap(),
            }];
        }
        exec.tick();
        assert_eq!(world.routes(), [("192.0.2.0/24".into(), "10.0.0.1".into())]);
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Effective);
        exec.delete(ME, "lab").unwrap();
        assert!(world.routes().is_empty());
    }

    #[test]
    fn an_intent_for_a_missing_device_waits_and_installs_when_it_appears() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        assert!(world.routes().is_empty());
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Deferred);
        world.view.lock().unwrap().interfaces.push("utun5".into());
        exec.tick();
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "utun5".into())]);
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Effective);
    }

    #[test]
    fn a_route_someone_removed_is_put_back_by_the_next_check() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        world.table.lock().unwrap().clear();
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Missing);
        exec.reconcile();
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "utun5".into())]);
        // Put back once, not duplicated.
        exec.reconcile();
        assert_eq!(world.routes().len(), 1);
    }

    #[test]
    fn a_foreign_route_to_the_destination_is_a_conflict_and_is_never_deleted() {
        let world = World::new(&["en0", "utun5"]);
        world.foreign("10.0.0.0", 8, "en7");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Conflicted);
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "en7".into())]);
        assert!(
            !world.commands().iter().any(|c| c.contains("add")),
            "{:?}",
            world.commands()
        );
        exec.delete(ME, "office").unwrap();
        assert!(!world.commands().iter().any(|c| c.contains("delete")));
        assert_eq!(world.routes().len(), 1, "the foreign route is still there");
    }

    #[test]
    fn deleting_an_intent_removes_only_what_it_installed() {
        let world = World::new(&["en0", "utun5"]);
        world.foreign("192.0.2.0", 24, "en7");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        exec.delete(ME, "office").unwrap();
        assert_eq!(world.routes(), [("192.0.2.0/24".into(), "en7".into())]);
        assert!(exec.list(ME).is_empty());
        assert!(matches!(exec.delete(ME, "office"), Err(Error::NotFound(_))));
    }

    #[test]
    fn a_route_that_someone_else_took_over_is_not_deleted_when_the_intent_goes() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        // Our route vanishes and another one takes the destination.
        world.table.lock().unwrap().clear();
        world.foreign("10.0.0.0", 8, "en7");
        exec.delete(ME, "office").unwrap();
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "en7".into())]);
    }

    #[test]
    fn changing_the_path_moves_the_routes() {
        let world = World::new(&["en0", "utun5", "utun6"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun6")))
            .unwrap();
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "utun6".into())]);
        assert_eq!(exec.list(ME).len(), 1);
    }

    #[test]
    fn turning_an_intent_off_withdraws_its_routes_and_keeps_it() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        let mut off = params("office", &["10.0.0.0/8"], via("utun5"));
        off.enabled = Some(false);
        exec.set(ME, off).unwrap();
        assert!(world.routes().is_empty());
        let list = exec.list(ME);
        assert_eq!(list[0].status, ExplainStatus::Disabled);
        assert!(!list[0].enabled);
    }

    #[test]
    fn a_failed_route_add_is_retried_and_not_recorded_as_ours() {
        let world = World::new(&["en0", "utun5"]);
        *world.fail_adds.lock().unwrap() = true;
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        assert!(world.routes().is_empty());
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Missing);
        *world.fail_adds.lock().unwrap() = false;
        exec.reconcile();
        assert_eq!(exec.list(ME)[0].status, ExplainStatus::Effective);
    }

    #[test]
    fn intents_of_different_users_stay_apart() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(501, params("mine", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        exec.set(502, params("mine", &["172.16.0.0/12"], via("utun5")))
            .unwrap();
        assert_eq!(exec.list(501)[0].destinations, ["10.0.0.0/8"]);
        assert_eq!(exec.list(502)[0].destinations, ["172.16.0.0/12"]);
        assert!(matches!(exec.delete(503, "mine"), Err(Error::NotFound(_))));
        exec.delete(501, "mine").unwrap();
        assert_eq!(exec.list(502).len(), 1);
        assert_eq!(world.routes(), [("172.16.0.0/12".into(), "utun5".into())]);
    }

    #[test]
    fn intents_survive_a_restart_and_adopt_the_routes_they_installed() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        executor(&world, &dir)
            .set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        // A new process: same store, routes still in the table.
        let again = executor(&world, &dir);
        assert_eq!(again.list(ME)[0].status, ExplainStatus::Effective);
        again.reconcile();
        assert_eq!(world.routes().len(), 1);
        // Routes lost while the helper was down come back.
        world.table.lock().unwrap().clear();
        again.reconcile();
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "utun5".into())]);
    }

    #[test]
    fn shutdown_clears_the_routes_but_keeps_the_intents_for_the_next_start() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        exec.shutdown();
        assert!(world.routes().is_empty());
        let next = executor(&world, &dir);
        next.reconcile();
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "utun5".into())]);
    }

    #[test]
    fn bad_requests_and_limits_are_refused_before_anything_is_changed() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        for bad in [
            params("Bad Id", &["10.0.0.0/8"], via("utun5")),
            params("x", &["127.0.0.0/8"], via("utun5")),
            params("x", &[], via("utun5")),
            params("x", &["10.0.0.0/8"], via("lo0")),
        ] {
            assert!(matches!(exec.set(ME, bad), Err(Error::Invalid(_))));
        }
        for n in 0..MAX_INTENTS_PER_UID {
            exec.set(
                ME,
                params(&format!("i{n}"), &["10.0.0.0/8"], via("missing0")),
            )
            .unwrap();
        }
        assert!(matches!(
            exec.set(ME, params("one-too-many", &["10.0.0.0/8"], via("missing0"))),
            Err(Error::Conflict(_))
        ));
        // Replacing an existing one is not "one more".
        exec.set(ME, params("i0", &["10.1.0.0/16"], via("missing0")))
            .unwrap();
        assert!(world.commands().iter().all(|c| !c.starts_with("route")));
    }

    #[test]
    fn the_total_number_of_routed_networks_is_capped() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        let block = |n: usize| -> Vec<String> {
            (0..MAX_DESTINATIONS)
                .map(|i| format!("10.{n}.{i}.0/24"))
                .collect()
        };
        for n in 0..4 {
            let owned = block(n);
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            exec.set(ME, params(&format!("b{n}"), &refs, via("gone0")))
                .unwrap();
        }
        let owned = block(9);
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        assert!(matches!(
            exec.set(ME, params("b9", &refs, via("gone0"))),
            Err(Error::Conflict(_))
        ));
    }

    #[test]
    fn the_background_tick_is_idle_without_intents_and_cheap_without_changes() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        assert!(exec.is_empty());
        exec.tick();
        assert!(world.commands().is_empty());
        exec.set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        let before = world.commands().len();
        exec.tick();
        exec.tick();
        assert_eq!(
            world.commands().len(),
            before,
            "nothing changed, nothing to run"
        );
    }

    #[test]
    fn a_corrupt_store_is_an_error_not_an_empty_start() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("intents.json"), b"{not json").unwrap();
        let result = IntentExecutor::new(
            Box::new(Sim(world.clone())),
            Box::new(Probe(world)),
            dir.path().join("intents.json"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn the_real_table_can_be_read_from_a_blocking_task_and_from_a_plain_thread() {
        // The helper's handlers run in `spawn_blocking`; the watcher is a
        // plain thread. Neither may panic on the nested runtime.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let probe = Arc::new(SystemProbe::new(
            Box::new(crate::sysexec::fake::FakeRunner::default()),
            runtime.handle().clone(),
        ));
        let from_blocking = probe.clone();
        let _ = runtime
            .block_on(
                async move { tokio::task::spawn_blocking(move || from_blocking.routes()).await },
            )
            .unwrap();
        let _ = std::thread::spawn(move || probe.routes()).join().unwrap();
    }

    // ---- conditional rules ----------------------------------------------

    fn office_rule(id: &str, prefix: &str, destination: &str) -> ConditionalRouteRule {
        ConditionalRouteRule {
            id: id.into(),
            name: "Office LAN direct".into(),
            enabled: true,
            condition: RouteCondition::InterfaceAddressIn {
                prefix: prefix.parse().unwrap(),
            },
            routes: vec![PolicyRoute {
                destination: destination.parse().unwrap(),
                metric: 5,
                via: None,
            }],
        }
    }

    fn on_lan(world: &Arc<World>, cidr: &str) {
        let mut view = world.view.lock().unwrap();
        view.addresses = vec![net_manager_core::route_intents::IfaceAddr {
            if_index: 15,
            interface: "en7".into(),
            address: cidr.parse().unwrap(),
        }];
        if !view.interfaces.iter().any(|i| i == "en7") {
            view.interfaces.push("en7".into());
        }
    }

    fn off_lan(world: &Arc<World>) {
        world.view.lock().unwrap().addresses.clear();
    }

    #[test]
    fn a_rule_installs_its_routes_while_the_condition_holds_and_withdraws_them_after() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        let status = exec
            .put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        assert_eq!(status.status.state, ConditionalRuleState::Inactive);
        assert!(world.routes().is_empty());
        on_lan(&world, "10.228.33.7/21");
        exec.tick();
        assert_eq!(world.routes(), [("10.99.0.0/24".into(), "en7".into())]);
        let list = exec.list_rules(ME);
        assert_eq!(list[0].status.state, ConditionalRuleState::Active);
        assert_eq!(list[0].status.matched_interface.as_deref(), Some("en7"));
        assert_eq!(list[0].status.applied_routes, 1);
        off_lan(&world);
        exec.tick();
        assert!(world.routes().is_empty(), "left the office: the routes go");
        assert_eq!(
            exec.list_rules(ME)[0].status.state,
            ConditionalRuleState::Inactive
        );
    }

    #[test]
    fn a_rule_that_holds_when_it_is_saved_applies_at_once() {
        let world = World::new(&["en0"]);
        on_lan(&world, "10.228.33.7/21");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        let put = exec
            .put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        assert!(put.stored);
        assert_eq!(put.status.state, ConditionalRuleState::Active);
        assert_eq!(world.routes(), [("10.99.0.0/24".into(), "en7".into())]);
    }

    #[test]
    fn switching_a_rule_off_or_removing_it_withdraws_what_it_installed() {
        let world = World::new(&["en0"]);
        on_lan(&world, "10.228.33.7/21");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        let mut off = office_rule("office", "10.228.32.0/21", "10.99.0.0/24");
        off.enabled = false;
        let status = exec.put_rule(ME, off).unwrap().status;
        assert_eq!(status.state, ConditionalRuleState::Disabled);
        assert!(world.routes().is_empty());
        exec.put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        assert_eq!(world.routes().len(), 1);
        assert!(exec.remove_rule(ME, "office").removed);
        assert!(world.routes().is_empty());
        assert!(!exec.remove_rule(ME, "office").removed);
    }

    #[test]
    fn rules_are_per_user_and_coexist_with_intents() {
        let world = World::new(&["en0", "utun5"]);
        on_lan(&world, "10.228.33.7/21");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.set(ME, params("tunnel", &["172.16.0.0/12"], via("utun5")))
            .unwrap();
        exec.put_rule(501, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        exec.put_rule(502, office_rule("office", "10.228.32.0/21", "10.98.0.0/24"))
            .unwrap();
        assert_eq!(exec.list_rules(501).len(), 1);
        assert_eq!(
            exec.list_rules(501)[0].rule.routes[0]
                .destination
                .to_string(),
            "10.99.0.0/24"
        );
        assert!(!exec.remove_rule(503, "office").removed);
        assert!(exec.remove_rule(501, "office").removed);
        assert_eq!(exec.list_rules(502).len(), 1);
        assert_eq!(exec.list(501).len(), 1, "the intent is untouched");
        assert!(world
            .routes()
            .contains(&("172.16.0.0/12".into(), "utun5".into())));
    }

    #[test]
    fn a_foreign_route_to_a_rules_destination_is_left_alone() {
        let world = World::new(&["en0"]);
        on_lan(&world, "10.228.33.7/21");
        world.foreign("10.99.0.0", 24, "en0");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        let status = exec
            .put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap()
            .status;
        assert_eq!(status.state, ConditionalRuleState::Error);
        assert!(status.detail.unwrap().contains("10.99.0.0/24"));
        assert_eq!(world.routes(), [("10.99.0.0/24".into(), "en0".into())]);
        exec.remove_rule(ME, "office");
        assert_eq!(world.routes().len(), 1, "never deleted");
    }

    #[test]
    fn rules_survive_a_restart_and_follow_the_network_afterwards() {
        let world = World::new(&["en0"]);
        on_lan(&world, "10.228.33.7/21");
        let dir = tempfile::tempdir().unwrap();
        executor(&world, &dir)
            .put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        let again = executor(&world, &dir);
        assert_eq!(
            again.list_rules(ME)[0].status.state,
            ConditionalRuleState::Active
        );
        off_lan(&world);
        again.reconcile();
        assert!(world.routes().is_empty());
    }

    #[test]
    fn bad_rules_and_the_limits_are_refused_before_anything_changes() {
        let world = World::new(&["en0"]);
        on_lan(&world, "10.228.33.7/21");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        for bad in [
            office_rule("-bad", "10.228.32.0/21", "10.99.0.0/24"),
            office_rule("ok", "10.228.32.5/21", "10.99.0.0/24"),
            office_rule("ok", "10.228.32.0/21", "127.0.0.0/8"),
        ] {
            assert!(matches!(exec.put_rule(ME, bad), Err(Error::Invalid(_))));
        }
        for n in 0..MAX_RULES {
            exec.put_rule(
                ME,
                office_rule(&format!("r{n}"), "172.30.0.0/16", "10.99.0.0/24"),
            )
            .unwrap();
        }
        assert!(matches!(
            exec.put_rule(
                ME,
                office_rule("one-too-many", "172.30.0.0/16", "10.99.0.0/24")
            ),
            Err(Error::Conflict(_))
        ));
        exec.put_rule(ME, office_rule("r0", "172.30.0.0/16", "10.98.0.0/24"))
            .unwrap();
        assert!(world.routes().is_empty());
    }

    #[test]
    fn shutdown_withdraws_rule_routes_and_keeps_the_rules() {
        let world = World::new(&["en0"]);
        on_lan(&world, "10.228.33.7/21");
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        exec.shutdown();
        assert!(world.routes().is_empty());
        let next = executor(&world, &dir);
        next.reconcile();
        assert_eq!(world.routes().len(), 1);
    }

    #[test]
    fn an_address_change_alone_triggers_the_evaluation() {
        let world = World::new(&["en0"]);
        let dir = tempfile::tempdir().unwrap();
        let exec = executor(&world, &dir);
        exec.put_rule(ME, office_rule("office", "10.228.32.0/21", "10.99.0.0/24"))
            .unwrap();
        exec.tick(); // nothing changed since the put
        let before = world.commands().len();
        on_lan(&world, "10.228.33.7/21");
        exec.tick();
        assert!(
            world.commands().len() > before,
            "the new address must be noticed"
        );
    }

    #[test]
    fn a_store_written_before_rules_existed_still_loads() {
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("intents.json"),
            br#"{"version":1,"intents":[{"uid":501,"params":{"id":"old","destinations":["10.0.0.0/8"],"path":{"kind":"interface","interface":"utun5"},"metric":100,"enabled":true},"installed":[]}]}"#,
        )
        .unwrap();
        let exec = executor(&world, &dir);
        assert_eq!(exec.list(ME)[0].id, "old");
        assert!(exec.list_rules(ME).is_empty());
        exec.reconcile();
        assert_eq!(world.routes(), [("10.0.0.0/8".into(), "utun5".into())]);
    }

    #[test]
    fn the_store_is_private_to_root() {
        use std::os::unix::fs::PermissionsExt;
        let world = World::new(&["en0", "utun5"]);
        let dir = tempfile::tempdir().unwrap();
        executor(&world, &dir)
            .set(ME, params("office", &["10.0.0.0/8"], via("utun5")))
            .unwrap();
        let mode = std::fs::metadata(dir.path().join("intents.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
