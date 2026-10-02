//! Conditional routes: persisted per-user rules that install a route set
//! only while a network condition holds — e.g. "this machine is on the
//! office LAN" (`interfaceAddressIn`). Conditions read kernel state (local
//! interface addresses); an active probe could be answered by the very
//! tunnel it is meant to decide about, so matching is deliberately local.
//!
//! The module is pure over its inputs: [`match_interface`] evaluates a
//! snapshot of [`IfaceAddr`], [`plan_routes`] turns a rule into concrete
//! [`AppliedRoute`]s, and [`CondRuleStore`] persists rules per uid like the
//! always-on store does.

use crate::always_on::{check_private_dir, current_uid};
use ipnet::IpNet;
use net_manager_core::daemon_protocol::{ConditionalRouteRule, RouteCondition};
use net_manager_core::models::{AppliedRoute, PolicyRoute};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

/// Journal owner prefix: conditional routes are managed only through rule
/// evaluation, never through `routes.apply`/`routes.remove`.
pub const OWNER_PREFIX: &str = "cond:";

const VERSION: u32 = 1;
const FILE: &str = "rules.json";
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_RULES: usize = 32;
const MAX_RULE_ROUTES: usize = 256;
const MAX_ID_BYTES: usize = 48;
const MAX_NAME_BYTES: usize = 128;

/// One address found on a local interface. `scope` is the kernel
/// `rt_scope`: only `0` (`RT_SCOPE_UNIVERSE`, iproute2's `global`) counts —
/// link-local and host addresses must not satisfy a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceAddr {
    pub ifindex: u32,
    pub name: String,
    pub address: IpNet,
    pub scope: u8,
}

/// What the evaluator needs from the kernel. The production implementation
/// is the netlink executor; tests drive [`DaemonCore`](crate::core::DaemonCore)
/// with an inline snapshot.
pub trait NetworkObservation: Send + Sync {
    /// Every address currently assigned, across all interfaces.
    fn interface_addrs(&self) -> io::Result<Vec<IfaceAddr>>;
    /// Daemon-owned routes (`RTPROT_NETWORK_ORCHESTRATOR`) in the kernel.
    fn owned_routes(&self) -> io::Result<Vec<AppliedRoute>>;
    /// `ip route get <to>` through the policy rules — the egress a packet
    /// would take right now. Used by the DNS probe; unavailable observers
    /// (tests, degraded setups) return `Unsupported`.
    fn route_lookup(
        &self,
        _to: IpAddr,
    ) -> io::Result<net_manager_core::daemon_protocol::RouteLookup> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Used when no observer is wired (tests, degraded setups): no address can
/// match, so all rules evaluate inactive and already-applied routes are
/// withdrawn — the safe direction.
pub struct NoObservation;

impl NetworkObservation for NoObservation {
    fn interface_addrs(&self) -> io::Result<Vec<IfaceAddr>> {
        Ok(Vec::new())
    }
    fn owned_routes(&self) -> io::Result<Vec<AppliedRoute>> {
        Ok(Vec::new())
    }
}

/// Interface names that can never be a physical uplink: tunnels (ours and
/// foreign), container plumbing, virtual plumbing. A daemon-owned link is
/// additionally excluded by ifindex at evaluation time — this list is only
/// the name heuristic for foreign and leftover interfaces.
const NON_UPLINK_PREFIXES: &[&str] = &[
    "lo",
    "wg",
    "xray",
    "ovpn",
    "tun",
    "tap",
    "tailscale",
    "happ",
    "docker",
    "veth",
    "br-",
    "virbr",
    "vnet",
    "podman",
    "cni",
    "flannel",
    "lxc",
    "ppp",
    "gre",
    "gretap",
    "erspan",
    "ipip",
    "sit",
    "ip6tnl",
    "vti",
    "ifb",
    "dummy",
    "vcan",
    "vxcan",
    "nlmon",
    "zt",
];

pub fn non_uplink_name(name: &str) -> bool {
    NON_UPLINK_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// The interface satisfying "has a global address inside `prefix`", or
/// `None`. When several interfaces match, the lowest ifindex wins so the
/// choice is stable across evaluations.
pub fn match_interface(
    addrs: &[IfaceAddr],
    prefix: IpNet,
    owned_ifindices: &HashSet<u32>,
) -> Option<(u32, String)> {
    addrs
        .iter()
        .filter(|addr| {
            addr.scope == 0
                && addr.ifindex != 0
                && !owned_ifindices.contains(&addr.ifindex)
                && !non_uplink_name(&addr.name)
                && prefix.contains(&addr.address.addr())
        })
        .min_by_key(|addr| addr.ifindex)
        .map(|addr| (addr.ifindex, addr.name.clone()))
}

/// The routes a rule wants installed while `ifindex` is the matched
/// interface.
pub fn plan_routes(rule: &ConditionalRouteRule, ifindex: u32) -> Vec<AppliedRoute> {
    rule.routes
        .iter()
        .map(|route| AppliedRoute {
            destination: route.destination,
            interface_index: ifindex,
            metric: route.metric,
            gateway: route.via,
            table: None,
        })
        .collect()
}

fn validate_policy_route(route: &PolicyRoute) -> Result<(), String> {
    if route.destination.trunc() != route.destination {
        return Err(format!(
            "destination {} has host bits set",
            route.destination
        ));
    }
    if let Some(via) = route.via {
        let same_family = matches!(
            (route.destination, via),
            (IpNet::V4(_), std::net::IpAddr::V4(_)) | (IpNet::V6(_), std::net::IpAddr::V6(_))
        );
        if !same_family {
            return Err(format!(
                "gateway {via} is not in the address family of {}",
                route.destination
            ));
        }
        if via.is_unspecified() || via.is_multicast() {
            return Err(format!("gateway {via} must be a unicast address"));
        }
    }
    Ok(())
}

/// What `condRules.put` accepts. The id becomes part of the journal owner
/// `cond:<id>`, so it is deliberately stricter than an owner string.
pub fn validate_rule(rule: &ConditionalRouteRule) -> Result<(), String> {
    if rule.id.is_empty()
        || rule.id.len() > MAX_ID_BYTES
        || !rule
            .id
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        || !rule
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "rule id must be 1-{MAX_ID_BYTES} bytes of [a-zA-Z0-9._-] starting with a letter or digit"
        ));
    }
    if rule.name.is_empty()
        || rule.name.len() > MAX_NAME_BYTES
        || rule.name.chars().any(char::is_control)
    {
        return Err(format!(
            "rule name must be 1-{MAX_NAME_BYTES} bytes without control characters"
        ));
    }
    match &rule.condition {
        RouteCondition::InterfaceAddressIn { prefix } => {
            if prefix.trunc() != *prefix {
                return Err(format!("condition prefix {prefix} has host bits set"));
            }
        }
    }
    if rule.routes.is_empty() || rule.routes.len() > MAX_RULE_ROUTES {
        return Err(format!(
            "a rule needs 1-{MAX_RULE_ROUTES} routes, got {}",
            rule.routes.len()
        ));
    }
    let mut seen = HashSet::new();
    for route in &rule.routes {
        validate_policy_route(route)?;
        if !seen.insert((route.destination, route.metric)) {
            return Err(format!(
                "duplicate route {} with metric {}",
                route.destination, route.metric
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CondRulesDocument {
    version: u32,
    pub rules: Vec<ConditionalRouteRule>,
}

impl Default for CondRulesDocument {
    fn default() -> Self {
        Self {
            version: VERSION,
            rules: Vec::new(),
        }
    }
}

/// Per-user rule store under `<state>/cond-rules/<uid>/rules.json`, with the
/// same ACL/atomicity rules as the always-on store.
#[derive(Clone)]
pub struct CondRuleStore {
    root: PathBuf,
}

impl CondRuleStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn uid_dir(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }

    fn path(&self, uid: u32) -> PathBuf {
        self.uid_dir(uid).join(FILE)
    }

    pub fn load_uid(&self, uid: u32) -> io::Result<CondRulesDocument> {
        if !check_private_dir(&self.root, false)? || !check_private_dir(&self.uid_dir(uid), false)?
        {
            return Ok(CondRulesDocument::default());
        }
        let path = self.path(uid);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(CondRulesDocument::default());
            }
            Err(err) => return Err(err),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != current_uid()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_DOCUMENT_BYTES as u64
        {
            return Err(invalid_data());
        }
        let bytes = fs::read(path)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid_data());
        }
        let document: CondRulesDocument =
            serde_json::from_slice(&bytes).map_err(|_| invalid_data())?;
        if document.version != VERSION || document.rules.len() > MAX_RULES {
            return Err(invalid_data());
        }
        Ok(document)
    }

    /// Every uid document, loaded independently so one broken store does
    /// not hide the others. Non-directory entries are ignored.
    pub fn load_all(&self) -> io::Result<Vec<(u32, io::Result<CondRulesDocument>)>> {
        if !check_private_dir(&self.root, false)? {
            return Ok(Vec::new());
        }
        let mut uids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if let Some(uid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            {
                uids.push(uid);
            }
        }
        uids.sort_unstable();
        Ok(uids
            .into_iter()
            .map(|uid| (uid, self.load_uid(uid)))
            .collect())
    }

    /// Flat `(uid, rule)` list for evaluation; unreadable stores are logged
    /// and skipped like `always_on::replay` does.
    pub fn load_all_rules(&self) -> io::Result<Vec<(u32, ConditionalRouteRule)>> {
        let mut rules = Vec::new();
        for (uid, document) in self.load_all()? {
            match document {
                Ok(document) => rules.extend(document.rules.into_iter().map(|rule| (uid, rule))),
                Err(_) => eprintln!(
                    "network-orchestrator-daemon: conditional rule store of uid {uid} is unreadable"
                ),
            }
        }
        Ok(rules)
    }

    /// Insert or replace the rule with the same id.
    pub fn upsert(&self, uid: u32, rule: ConditionalRouteRule) -> io::Result<bool> {
        let mut document = self.load_uid(uid)?;
        if let Some(existing) = document.rules.iter_mut().find(|item| item.id == rule.id) {
            if *existing == rule {
                return Ok(false);
            }
            *existing = rule;
        } else {
            if document.rules.len() >= MAX_RULES {
                return Err(invalid_data());
            }
            document.rules.push(rule);
        }
        self.save(uid, &document)?;
        Ok(true)
    }

    pub fn remove(&self, uid: u32, rule_id: &str) -> io::Result<bool> {
        let mut document = self.load_uid(uid)?;
        let before = document.rules.len();
        document.rules.retain(|rule| rule.id != rule_id);
        if document.rules.len() == before {
            return Ok(false);
        }
        self.save(uid, &document)?;
        Ok(true)
    }

    fn save(&self, uid: u32, document: &CondRulesDocument) -> io::Result<()> {
        check_private_dir(&self.root, true)?;
        let dir = self.uid_dir(uid);
        check_private_dir(&dir, true)?;
        let bytes = serde_json::to_vec(document).map_err(|_| invalid_data())?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid_data());
        }
        let path = self.path(uid);
        let temp = dir.join("rules.json.tmp");
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(dir)?.sync_all()
    }
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "conditional rules are not safe to load",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netorch-cond-rules-{}-{label}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn addr(ifindex: u32, name: &str, ip: &str, prefix_len: u8) -> IfaceAddr {
        IfaceAddr {
            ifindex,
            name: name.into(),
            address: IpNet::new(ip.parse().unwrap(), prefix_len).unwrap(),
            scope: 0,
        }
    }

    fn rule(id: &str) -> ConditionalRouteRule {
        ConditionalRouteRule {
            id: id.into(),
            name: "Office LAN direct".into(),
            enabled: true,
            condition: RouteCondition::InterfaceAddressIn {
                prefix: "10.228.32.0/21".parse().unwrap(),
            },
            routes: vec![PolicyRoute {
                destination: "10.99.0.0/24".parse().unwrap(),
                metric: 5,
                via: Some("10.228.32.1".parse().unwrap()),
            }],
        }
    }

    #[test]
    fn match_finds_global_address_on_physical_interface() {
        let addrs = vec![
            addr(1, "lo", "127.0.0.1", 8),
            addr(2, "enp59s0u2", "10.228.33.5", 21),
            addr(3, "wlp0s20f3", "192.168.1.40", 24),
        ];
        let prefix = "10.228.32.0/21".parse().unwrap();
        assert_eq!(
            match_interface(&addrs, prefix, &HashSet::new()),
            Some((2, "enp59s0u2".into()))
        );
    }

    #[test]
    fn match_ignores_tunnels_owned_links_and_non_global_scopes() {
        let prefix: IpNet = "10.228.32.0/21".parse().unwrap();
        let owned = HashSet::from([7]);
        let addrs = vec![
            addr(4, "wg-kzn2", "10.228.33.5", 32),
            addr(5, "tailscale0", "10.228.33.5", 32),
            addr(6, "xray-tun", "10.228.33.5", 32),
            addr(7, "enp1s0", "10.228.33.5", 21), // daemon-owned ifindex
            IfaceAddr {
                scope: 253, // link scope, like IPv6 fe80::
                ..addr(8, "enp2s0", "10.228.33.5", 32)
            },
        ];
        assert_eq!(match_interface(&addrs, prefix, &owned), None);
        let without_owned = match_interface(&addrs[..3], prefix, &HashSet::new());
        assert_eq!(without_owned, None);
    }

    #[test]
    fn match_prefers_lowest_ifindex_for_stability() {
        let addrs = vec![
            addr(9, "enp9s0", "10.228.33.9", 21),
            addr(3, "enp3s0", "10.228.33.3", 21),
        ];
        let prefix = "10.228.32.0/21".parse().unwrap();
        assert_eq!(
            match_interface(&addrs, prefix, &HashSet::new()),
            Some((3, "enp3s0".into()))
        );
    }

    #[test]
    fn match_uses_the_host_address_not_the_prefix_network() {
        // /21 host bits are normal: an address carries its host part.
        let addrs = vec![addr(2, "enp1s0", "10.228.39.200", 21)];
        let prefix = "10.228.32.0/21".parse().unwrap();
        assert!(match_interface(&addrs, prefix, &HashSet::new()).is_some());
        let office_wifi: IpNet = "10.228.40.0/21".parse().unwrap();
        assert!(match_interface(&addrs, office_wifi, &HashSet::new()).is_none());
    }

    #[test]
    fn plan_binds_routes_to_the_matched_ifindex() {
        let mut rule = rule("office");
        rule.routes.push(PolicyRoute {
            destination: "192.0.2.0/24".parse().unwrap(),
            metric: 10,
            via: None,
        });
        let routes = plan_routes(&rule, 42);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].interface_index, 42);
        assert_eq!(routes[0].gateway, Some("10.228.32.1".parse().unwrap()));
        assert_eq!(routes[1].gateway, None);
        assert_eq!(routes[0].metric, 5);
        assert!(routes[0].table.is_none());
    }

    #[test]
    fn validate_accepts_a_well_formed_rule() {
        assert!(validate_rule(&rule("office-lan")).is_ok());
        let mut ipv6 = rule("v6");
        ipv6.routes = vec![PolicyRoute {
            destination: "2001:db8::/32".parse().unwrap(),
            metric: 0,
            via: Some("fe80::1".parse().unwrap()),
        }];
        assert!(validate_rule(&ipv6).is_ok());
    }

    #[test]
    fn validate_rejects_bad_ids() {
        for id in ["", ".hidden", "-flag", "has space", "with/slash", "cond:x"] {
            let mut bad = rule(id);
            assert!(validate_rule(&bad).is_err(), "{id}");
            bad.id = id.into();
        }
        assert!(validate_rule(&rule(&"a".repeat(49))).is_err());
    }

    #[test]
    fn validate_rejects_bad_conditions_and_routes() {
        let mut host_bits = rule("x");
        host_bits.condition = RouteCondition::InterfaceAddressIn {
            prefix: "10.228.33.5/21".parse().unwrap(),
        };
        assert!(validate_rule(&host_bits).is_err());

        let mut empty = rule("x");
        empty.routes = Vec::new();
        assert!(validate_rule(&empty).is_err());

        let mut host_route = rule("x");
        host_route.routes[0].destination = "10.99.0.5/24".parse().unwrap();
        assert!(validate_rule(&host_route).is_err());

        let mut family = rule("x");
        family.routes[0].via = Some(IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, 1]));
        assert!(validate_rule(&family).is_err());

        let mut dup = rule("x");
        dup.routes.push(dup.routes[0].clone());
        assert!(validate_rule(&dup).is_err());
    }

    #[test]
    fn store_roundtrip_upsert_remove_and_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("store");
        let store = CondRuleStore::new(dir.join("cond-rules"));
        assert!(store.upsert(1000, rule("office")).unwrap());
        assert!(
            !store.upsert(1000, rule("office")).unwrap(),
            "same rule is a no-op"
        );
        let mut changed = rule("office");
        changed.enabled = false;
        assert!(
            store.upsert(1000, changed).unwrap(),
            "changed rule replaces"
        );

        let reopened = CondRuleStore::new(dir.join("cond-rules"));
        let document = reopened.load_uid(1000).unwrap();
        assert_eq!(document.rules.len(), 1);
        assert!(!document.rules[0].enabled);
        assert!(reopened.load_uid(1001).unwrap().rules.is_empty());
        assert_eq!(
            fs::metadata(dir.join("cond-rules/1000/rules.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.join("cond-rules/1000"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        assert!(reopened.remove(1000, "office").unwrap());
        assert!(!reopened.remove(1000, "office").unwrap());
        assert!(reopened.load_uid(1000).unwrap().rules.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_rejects_symlinked_uid_dir_and_malformed_documents() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("symlink");
        let target = dir.join("outside");
        fs::create_dir(&target).unwrap();
        let root = dir.join("cond-rules");
        fs::create_dir(&root).unwrap();
        symlink(&target, root.join("1000")).unwrap();
        let store = CondRuleStore::new(&root);
        assert!(store.upsert(1000, rule("office")).is_err());
        assert!(fs::read_dir(&target).unwrap().next().is_none());

        let ok_dir = test_dir("malformed");
        let root = ok_dir.join("cond-rules");
        let uid_dir = root.join("1000");
        fs::create_dir_all(&uid_dir).unwrap();
        fs::write(uid_dir.join("rules.json"), "{not json").unwrap();
        let store = CondRuleStore::new(&root);
        assert!(store.load_uid(1000).is_err());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(ok_dir).unwrap();
    }

    #[test]
    fn load_all_rules_skips_broken_stores() {
        let dir = test_dir("loadall");
        let store = CondRuleStore::new(dir.join("cond-rules"));
        store.upsert(1000, rule("office")).unwrap();
        let uid_dir = dir.join("cond-rules/1001");
        fs::create_dir_all(&uid_dir).unwrap();
        fs::write(uid_dir.join("rules.json"), "{bad").unwrap();
        let rules = store.load_all_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0, 1000);
        assert_eq!(rules[0].1.id, "office");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cap_is_enforced() {
        let dir = test_dir("cap");
        let store = CondRuleStore::new(dir.join("cond-rules"));
        for index in 0..MAX_RULES {
            store.upsert(1000, rule(&format!("r{index}"))).unwrap();
        }
        assert!(store.upsert(1000, rule("overflow")).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn no_observation_reports_empty() {
        let observer = NoObservation;
        assert!(observer.interface_addrs().unwrap().is_empty());
        assert!(observer.owned_routes().unwrap().is_empty());
    }

    #[test]
    fn non_uplink_names_cover_tunnels_and_virtual_links() {
        for name in [
            "lo",
            "wg0",
            "wg-kzn2",
            "xray-tun",
            "ovpn-abc",
            "tun0",
            "tailscale0",
            "docker0",
            "br-9f3c",
            "veth1234",
            "virbr0",
            "ppp0",
            "happ0",
            "zt0",
        ] {
            assert!(non_uplink_name(name), "{name}");
        }
        for name in ["enp59s0u2", "wlp0s20f3", "eth0", "wlan0", "eno1"] {
            assert!(!non_uplink_name(name), "{name}");
        }
    }

    #[test]
    fn observation_trait_is_object_safe() {
        fn accept(_: &dyn NetworkObservation) {}
        accept(&NoObservation);
        let _unused: Option<&Path> = None;
    }
}
