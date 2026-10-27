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
use net_manager_core::daemon_protocol::{NetIntentResult, NetIntentSetParams, NetIntentView};
use net_manager_core::models::RouteEntry;
use net_manager_core::route_intents::{
    derive, judge, normalize, view, Derivation, Intent, NetworkView, RouteState, RouteTarget,
    WantedRoute,
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

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    version: u32,
    intents: Vec<Stored>,
}

struct State {
    intents: Vec<Stored>,
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
        let intents = match fs::read(&path) {
            Ok(bytes) => {
                let document: Document = serde_json::from_slice(&bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "corrupt intents"))?;
                document.intents
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            runner,
            probe,
            path,
            state: Mutex::new(State {
                intents,
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
            .sum();
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

    /// Whether any intent is stored (the background tick does nothing else).
    pub fn is_empty(&self) -> bool {
        self.lock().intents.is_empty()
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
        if state.intents.is_empty() {
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
        let installed: Vec<RouteOp> = state
            .intents
            .iter_mut()
            .flat_map(|s| std::mem::take(&mut s.installed))
            .collect();
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
            // What the previous steps changed must be visible to the next
            // comparison, or a route we just removed looks like a rival.
            if self.reconcile_one(&intent, stored, &network, &table) {
                table = self.probe.routes();
            }
        }
        state.last_view = Some(network);
        state.last_full = Some(Instant::now());
    }

    /// Returns whether it ran a route command.
    fn reconcile_one(
        &self,
        intent: &Intent,
        stored: &mut Stored,
        network: &NetworkView,
        table: &[RouteEntry],
    ) -> bool {
        let wanted = match derive(intent, network) {
            Derivation::Routes { routes, .. } => routes,
            _ => Vec::new(),
        };
        let wanted_ops: Vec<RouteOp> = wanted.iter().map(op_of).collect();
        // Routes no longer wanted (path changed, intent off, device gone).
        let (keep, stale): (Vec<RouteOp>, Vec<RouteOp>) = stored
            .installed
            .drain(..)
            .partition(|op| wanted_ops.contains(op));
        let mut changed = !stale.is_empty();
        self.withdraw(&stale, table);
        stored.installed = keep;
        let fresh;
        let table = if changed {
            fresh = self.probe.routes();
            &fresh[..]
        } else {
            table
        };
        for (route, op) in wanted.iter().zip(&wanted_ops) {
            let ours = stored.installed.contains(op);
            match judge(route, ours, table) {
                RouteState::Present => {}
                RouteState::Missing => {
                    changed = true;
                    if op.add(&*self.runner).is_ok() && !ours {
                        stored.installed.push(op.clone());
                    }
                }
                // Someone else holds the destination now: forget our claim
                // without deleting what is there.
                RouteState::Conflicted(_) => stored.installed.retain(|installed| installed != op),
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
    use net_manager_core::daemon_protocol::{ExplainStatus, NetIntentPath};
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
            kind: "interface".into(),
            interface: Some(name.into()),
        }
    }
    fn direct() -> NetIntentPath {
        NetIntentPath {
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
