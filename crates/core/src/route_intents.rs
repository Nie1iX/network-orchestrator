//! Routing intents ("these networks go this way") as pure rules: what a
//! request is allowed to say, which routes it wants given the live network,
//! and how the routes found in the system compare. The privileged helper does
//! the effects; nothing here touches the machine, so every rule is tested
//! without a route table.

use crate::daemon_protocol::{ExplainStatus, NetIntentPath, NetIntentSetParams, NetIntentView};
use crate::models::RouteEntry;
use ipnet::IpNet;
use std::net::IpAddr;

pub const MAX_DESTINATIONS: usize = 64;
const DEFAULT_METRIC: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentPath {
    /// The current physical uplink, so the traffic bypasses tunnels.
    Direct,
    /// Any device, a tunnel included; armed until it exists.
    Interface(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub id: String,
    pub destinations: Vec<IpNet>,
    pub path: IntentPath,
    /// Informational on macOS: `route add` has no metric.
    pub metric: u32,
    pub enabled: bool,
}

impl Intent {
    /// Halves of the address space (`0.0.0.0/1`, `::/1`) or all of it: the
    /// shape a full tunnel uses. Worth a warning in the UI.
    pub fn captures_default(&self) -> bool {
        self.destinations.iter().any(|net| net.prefix_len() <= 1)
    }
}

fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    id.len() <= 48
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// macOS device names: a letter, then letters and digits, 15 at most.
fn valid_interface(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 15
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric())
}

/// A destination no intent or rule may route: loopback, multicast, link-local
/// and a single unspecified host.
pub fn check_routable(net: &IpNet, text: &str) -> Result<(), String> {
    let address = net.network();
    let host = net.prefix_len() == net.max_prefix_len();
    let link_local = match address {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    if address.is_loopback()
        || address.is_multicast()
        || link_local
        || (address.is_unspecified() && host)
    {
        return Err(format!("'{text}' cannot be routed by an intent"));
    }
    Ok(())
}

fn parse_destination(text: &str) -> Result<IpNet, String> {
    let text = text.trim();
    let net = text
        .parse::<IpNet>()
        .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| format!("'{text}' is not an address or network"))?
        .trunc();
    check_routable(&net, text)?;
    Ok(net)
}

/// Checks a `net.intent.set` request and fills in the defaults.
pub fn normalize(params: &NetIntentSetParams) -> Result<Intent, String> {
    if !valid_id(&params.id) {
        return Err("The intent name must be lowercase letters, digits, '-' or '_'".into());
    }
    if params.destinations.is_empty() {
        return Err("An intent needs at least one destination".into());
    }
    if params.destinations.len() > MAX_DESTINATIONS {
        return Err(format!(
            "An intent can have at most {MAX_DESTINATIONS} destinations"
        ));
    }
    let mut destinations: Vec<IpNet> = Vec::with_capacity(params.destinations.len());
    for text in &params.destinations {
        let net = parse_destination(text)?;
        if !destinations.contains(&net) {
            destinations.push(net);
        }
    }
    let path = match params.path.kind.as_str() {
        "direct" => IntentPath::Direct,
        "interface" => {
            let name = params.path.interface.as_deref().unwrap_or_default();
            if !valid_interface(name) || name == "lo0" {
                return Err("Choose a network interface for this intent".into());
            }
            IntentPath::Interface(name.to_string())
        }
        _ => return Err("The path must be 'direct' or an interface".into()),
    };
    Ok(Intent {
        id: params.id.clone(),
        destinations,
        path,
        metric: params.metric.unwrap_or(DEFAULT_METRIC),
        enabled: params.enabled.unwrap_or(true),
    })
}

/// The physical default route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    pub interface: String,
    pub gateway: Option<IpAddr>,
}

/// One address assigned to a local interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceAddr {
    pub if_index: u32,
    pub interface: String,
    pub address: IpNet,
}

/// What the helper sees of the network when it reconciles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkView {
    pub uplink: Option<Uplink>,
    pub interfaces: Vec<String>,
    /// Addresses on those interfaces, for conditional rules.
    pub addresses: Vec<IfaceAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    Gateway(IpAddr),
    Interface(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WantedRoute {
    pub destination: IpNet,
    pub target: RouteTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Derivation {
    Disabled,
    /// Nothing to install yet (device absent, no uplink); retried on change.
    Deferred(String),
    Routes {
        routes: Vec<WantedRoute>,
        /// Destinations held back, with the reason.
        skipped: Vec<(IpNet, String)>,
    },
}

/// The routes an intent wants right now. A destination that contains the
/// uplink gateway is never sent away from the uplink: the tunnel's own packets
/// would loop back into it.
pub fn derive(intent: &Intent, network: &NetworkView) -> Derivation {
    if !intent.enabled {
        return Derivation::Disabled;
    }
    let (target, protect) = match &intent.path {
        IntentPath::Direct => {
            let Some(uplink) = &network.uplink else {
                return Derivation::Deferred(
                    "there is no network connection to route through".into(),
                );
            };
            let target = match uplink.gateway {
                Some(gateway) => RouteTarget::Gateway(gateway),
                None => RouteTarget::Interface(uplink.interface.clone()),
            };
            (target, None)
        }
        IntentPath::Interface(name) => {
            if !network.interfaces.iter().any(|known| known == name) {
                return Derivation::Deferred(format!("interface {name} is absent"));
            }
            let protect = network
                .uplink
                .as_ref()
                .filter(|uplink| &uplink.interface != name)
                .and_then(|uplink| uplink.gateway);
            (RouteTarget::Interface(name.clone()), protect)
        }
    };
    let mut routes = Vec::new();
    let mut skipped = Vec::new();
    for destination in &intent.destinations {
        match protect {
            Some(gateway) if destination.contains(&gateway) => skipped.push((
                *destination,
                format!("it contains the uplink gateway {gateway}"),
            )),
            _ => routes.push(WantedRoute {
                destination: *destination,
                target: target.clone(),
            }),
        }
    }
    Derivation::Routes { routes, skipped }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteState {
    Present,
    Missing,
    Conflicted(String),
}

/// Compares one wanted route with the system's table. `ours` says the helper
/// installed it; an identical route it did not install, or a different route
/// to the same destination, is a conflict it never touches.
pub fn judge(wanted: &WantedRoute, ours: bool, table: &[RouteEntry]) -> RouteState {
    let mut found = table.iter().filter(|entry| {
        IpNet::new(entry.destination, entry.prefix_len)
            .is_ok_and(|net| net.trunc() == wanted.destination)
    });
    let matches = |entry: &RouteEntry| match &wanted.target {
        RouteTarget::Gateway(gateway) => entry.gateway == Some(*gateway),
        RouteTarget::Interface(name) => &entry.interface_name == name,
    };
    let Some(first) = found.next() else {
        return RouteState::Missing;
    };
    let same = matches(first) || found.any(matches);
    if same && ours {
        RouteState::Present
    } else if same {
        RouteState::Conflicted(
            "an identical route that was not installed by this app is in place".into(),
        )
    } else {
        RouteState::Conflicted(format!(
            "another route to {} via {} is in place",
            wanted.destination, first.interface_name
        ))
    }
}

fn path_of(path: &IntentPath) -> NetIntentPath {
    match path {
        IntentPath::Direct => NetIntentPath {
            kind: "direct".into(),
            interface: None,
        },
        IntentPath::Interface(name) => NetIntentPath {
            kind: "interface".into(),
            interface: Some(name.clone()),
        },
    }
}

/// The list entry for an intent: `states` holds one verdict per wanted route.
pub fn view(intent: &Intent, derivation: &Derivation, states: &[RouteState]) -> NetIntentView {
    let (status, mut detail, installed, wanted) = match derivation {
        Derivation::Disabled => (ExplainStatus::Disabled, "turned off".to_string(), 0, 0),
        Derivation::Deferred(reason) => (ExplainStatus::Deferred, reason.clone(), 0, 0),
        Derivation::Routes { routes, skipped } => {
            let installed = states.iter().filter(|s| **s == RouteState::Present).count();
            let conflict = states.iter().find_map(|s| match s {
                RouteState::Conflicted(detail) => Some(detail.clone()),
                _ => None,
            });
            let (status, detail) = if routes.is_empty() && !skipped.is_empty() {
                (
                    ExplainStatus::Conflicted,
                    "every destination was skipped".to_string(),
                )
            } else if let Some(detail) = conflict {
                (ExplainStatus::Conflicted, detail)
            } else if states.contains(&RouteState::Missing) {
                (
                    ExplainStatus::Missing,
                    format!("{} route(s) will be retried", routes.len() - installed),
                )
            } else {
                (
                    ExplainStatus::Effective,
                    format!("{installed} route(s) in place"),
                )
            };
            (status, detail, installed, routes.len())
        }
    };
    if let Derivation::Routes { skipped, .. } = derivation {
        for (destination, reason) in skipped {
            detail.push_str(&format!("; skipped {destination}: {reason}"));
        }
    }
    NetIntentView {
        id: intent.id.clone(),
        destinations: intent
            .destinations
            .iter()
            .map(ToString::to_string)
            .collect(),
        path: path_of(&intent.path),
        metric: intent.metric,
        enabled: intent.enabled,
        status,
        detail,
        installed,
        wanted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_protocol::{ExplainStatus, NetIntentPath, NetIntentSetParams};
    use crate::models::RouteEntry;

    fn params(id: &str, destinations: &[&str], path: NetIntentPath) -> NetIntentSetParams {
        NetIntentSetParams {
            id: id.into(),
            destinations: destinations.iter().map(ToString::to_string).collect(),
            path,
            metric: None,
            enabled: None,
        }
    }

    fn direct() -> NetIntentPath {
        NetIntentPath {
            kind: "direct".into(),
            interface: None,
        }
    }

    fn via(name: &str) -> NetIntentPath {
        NetIntentPath {
            kind: "interface".into(),
            interface: Some(name.into()),
        }
    }

    fn intent(destinations: &[&str], path: NetIntentPath) -> Intent {
        normalize(&params("office", destinations, path)).unwrap()
    }

    fn uplink() -> Uplink {
        Uplink {
            interface: "en0".into(),
            gateway: Some("192.168.1.1".parse().unwrap()),
        }
    }

    fn network(interfaces: &[&str]) -> NetworkView {
        NetworkView {
            uplink: Some(uplink()),
            interfaces: interfaces.iter().map(ToString::to_string).collect(),
            addresses: Vec::new(),
        }
    }

    fn entry(destination: &str, prefix: u8, interface: &str, gateway: Option<&str>) -> RouteEntry {
        RouteEntry {
            destination: destination.parse().unwrap(),
            prefix_len: prefix,
            gateway: gateway.map(|g| g.parse().unwrap()),
            interface_index: 1,
            interface_name: interface.into(),
            metric: 0,
        }
    }

    // ---- normalize -------------------------------------------------------

    #[test]
    fn a_valid_request_is_normalised_with_defaults() {
        let i = normalize(&params(
            "office-vpn",
            &["10.1.2.3/8", "192.0.2.9"],
            direct(),
        ))
        .unwrap();
        assert_eq!(i.id, "office-vpn");
        // Host bits are masked and a bare address becomes a host route.
        assert_eq!(
            i.destinations,
            [
                "10.0.0.0/8".parse::<IpNet>().unwrap(),
                "192.0.2.9/32".parse().unwrap()
            ]
        );
        assert_eq!((i.metric, i.enabled), (100, true));
        assert_eq!(i.path, IntentPath::Direct);
    }

    #[test]
    fn ids_must_be_short_lowercase_slugs() {
        for good in ["a", "office", "wg-home_2", &"a".repeat(48)] {
            assert!(
                normalize(&params(good, &["10.0.0.0/8"], direct())).is_ok(),
                "{good}"
            );
        }
        for bad in [
            "",
            "Office",
            "-lead",
            "has space",
            "a/b",
            "ünï",
            &"a".repeat(49),
            "a:b",
        ] {
            assert!(
                normalize(&params(bad, &["10.0.0.0/8"], direct())).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn destinations_must_be_routable_and_few() {
        let reject = |dest: &str| normalize(&params("x", &[dest], direct())).is_err();
        for bad in [
            "",
            "nonsense",
            "10.0.0.0/33",
            "127.0.0.0/8",
            "127.0.0.1",
            "224.0.0.0/4",
            "169.254.0.0/16",
            "0.0.0.0",
            "::1",
            "ff02::1",
            "fe80::/10",
            "::",
            "10.0.0.0/8; reboot",
        ] {
            assert!(reject(bad), "{bad:?}");
        }
        assert!(
            normalize(&params("x", &[], direct())).is_err(),
            "an intent needs a destination"
        );
        let many: Vec<String> = (0..=MAX_DESTINATIONS)
            .map(|n| format!("10.{}.0.0/16", n % 250))
            .collect();
        let many_refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(normalize(&params("x", &many_refs, direct())).is_err());
        // Duplicates collapse instead of installing a route twice.
        let i = normalize(&params("x", &["10.0.0.0/8", "10.9.9.9/8"], direct())).unwrap();
        assert_eq!(i.destinations.len(), 1);
    }

    #[test]
    fn default_capturing_destinations_are_recognised() {
        let halves = intent(&["0.0.0.0/1", "128.0.0.0/1"], via("utun5"));
        assert!(halves.captures_default());
        assert!(intent(&["0.0.0.0/0"], via("utun5")).captures_default());
        assert!(intent(&["::/1"], via("utun5")).captures_default());
        assert!(!intent(&["10.0.0.0/8"], via("utun5")).captures_default());
        assert!(!intent(&["0.0.0.0/8"], via("utun5")).captures_default());
    }

    #[test]
    fn paths_are_checked() {
        assert_eq!(
            intent(&["10.0.0.0/8"], via("utun5")).path,
            IntentPath::Interface("utun5".into())
        );
        for bad in ["", "lo0", "en0; ls", "-v", "0en", "utun5 up"] {
            assert!(
                normalize(&params("x", &["10.0.0.0/8"], via(bad))).is_err(),
                "{bad:?}"
            );
        }
        let no_name = NetIntentPath {
            kind: "interface".into(),
            interface: None,
        };
        assert!(normalize(&params("x", &["10.0.0.0/8"], no_name)).is_err());
        let unknown = NetIntentPath {
            kind: "tunnel".into(),
            interface: None,
        };
        assert!(normalize(&params("x", &["10.0.0.0/8"], unknown)).is_err());
        // A name on a direct path is ignored, not trusted.
        let sloppy = NetIntentPath {
            kind: "direct".into(),
            interface: Some("evil".into()),
        };
        assert_eq!(
            normalize(&params("x", &["10.0.0.0/8"], sloppy))
                .unwrap()
                .path,
            IntentPath::Direct
        );
    }

    #[test]
    fn enabled_and_metric_are_taken_from_the_request() {
        let mut p = params("x", &["10.0.0.0/8"], direct());
        p.enabled = Some(false);
        p.metric = Some(7);
        let i = normalize(&p).unwrap();
        assert_eq!((i.enabled, i.metric), (false, 7));
    }

    // ---- derive ----------------------------------------------------------

    #[test]
    fn a_direct_intent_follows_the_uplink_gateway() {
        let i = intent(&["10.0.0.0/8"], direct());
        let Derivation::Routes { routes, skipped } = derive(&i, &network(&[])) else {
            panic!("expected routes");
        };
        assert!(skipped.is_empty());
        assert_eq!(
            routes,
            [WantedRoute {
                destination: "10.0.0.0/8".parse().unwrap(),
                target: RouteTarget::Gateway("192.168.1.1".parse().unwrap()),
            }]
        );
    }

    #[test]
    fn a_direct_intent_on_a_gatewayless_uplink_uses_the_interface() {
        let i = intent(&["10.0.0.0/8"], direct());
        let mut net = network(&[]);
        net.uplink = Some(Uplink {
            interface: "en7".into(),
            gateway: None,
        });
        let Derivation::Routes { routes, .. } = derive(&i, &net) else {
            panic!()
        };
        assert_eq!(routes[0].target, RouteTarget::Interface("en7".into()));
    }

    #[test]
    fn without_an_uplink_a_direct_intent_waits() {
        let i = intent(&["10.0.0.0/8"], direct());
        let mut net = network(&[]);
        net.uplink = None;
        assert!(
            matches!(derive(&i, &net), Derivation::Deferred(reason) if reason.contains("network connection"))
        );
    }

    #[test]
    fn an_interface_intent_is_armed_until_the_device_appears() {
        let i = intent(&["10.0.0.0/8"], via("utun5"));
        assert!(matches!(
            derive(&i, &network(&["en0"])),
            Derivation::Deferred(reason) if reason.contains("utun5")
        ));
        let Derivation::Routes { routes, .. } = derive(&i, &network(&["en0", "utun5"])) else {
            panic!("expected routes once the device exists");
        };
        assert_eq!(routes[0].target, RouteTarget::Interface("utun5".into()));
    }

    #[test]
    fn a_disabled_intent_wants_nothing() {
        let mut p = params("x", &["10.0.0.0/8"], direct());
        p.enabled = Some(false);
        assert!(matches!(
            derive(&normalize(&p).unwrap(), &network(&[])),
            Derivation::Disabled
        ));
    }

    #[test]
    fn a_destination_holding_the_uplink_gateway_is_never_routed_away() {
        // A default-capturing intent through a tunnel must not swallow the
        // gateway the tunnel's own packets leave through.
        let i = intent(&["0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/8"], via("utun5"));
        let Derivation::Routes { routes, skipped } = derive(&i, &network(&["utun5"])) else {
            panic!()
        };
        let wanted: Vec<String> = routes.iter().map(|r| r.destination.to_string()).collect();
        // 192.168.1.1 lies in the upper half, so only that half is held back.
        assert_eq!(wanted, ["0.0.0.0/1", "10.0.0.0/8"]);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0.to_string(), "128.0.0.0/1");
        assert!(skipped[0].1.contains("uplink gateway"));
        // The same destinations are fine on the direct path.
        let direct_all = intent(&["128.0.0.0/1"], direct());
        let Derivation::Routes { routes, skipped } = derive(&direct_all, &network(&[])) else {
            panic!()
        };
        assert_eq!((routes.len(), skipped.len()), (1, 0));
        // Routing through the uplink device itself is not "away".
        let via_uplink = intent(&["128.0.0.0/1"], via("en0"));
        let Derivation::Routes { skipped, .. } = derive(&via_uplink, &network(&["en0"])) else {
            panic!()
        };
        assert!(skipped.is_empty());
    }

    // ---- judge -----------------------------------------------------------

    fn wanted_if(dest: &str, interface: &str) -> WantedRoute {
        WantedRoute {
            destination: dest.parse().unwrap(),
            target: RouteTarget::Interface(interface.into()),
        }
    }

    #[test]
    fn a_route_we_installed_and_find_is_present() {
        let w = wanted_if("10.0.0.0/8", "utun5");
        let table = [entry("10.0.0.0", 8, "utun5", None)];
        assert_eq!(judge(&w, true, &table), RouteState::Present);
    }

    #[test]
    fn an_absent_route_is_missing() {
        let w = wanted_if("10.0.0.0/8", "utun5");
        assert_eq!(
            judge(&w, false, &[entry("10.1.0.0", 16, "utun5", None)]),
            RouteState::Missing
        );
        assert_eq!(judge(&w, true, &[]), RouteState::Missing);
    }

    #[test]
    fn someone_elses_route_to_the_same_destination_is_a_conflict_we_leave_alone() {
        let w = wanted_if("10.0.0.0/8", "utun5");
        let other = [entry("10.0.0.0", 8, "en0", Some("192.168.1.1"))];
        assert!(matches!(judge(&w, false, &other), RouteState::Conflicted(d) if d.contains("en0")));
        // Identical but not installed by us: still not ours to manage.
        let same = [entry("10.0.0.0", 8, "utun5", None)];
        assert!(
            matches!(judge(&w, false, &same), RouteState::Conflicted(d) if d.contains("not installed"))
        );
    }

    #[test]
    fn a_gateway_target_matches_on_the_gateway() {
        let w = WantedRoute {
            destination: "10.0.0.0/8".parse().unwrap(),
            target: RouteTarget::Gateway("192.168.1.1".parse().unwrap()),
        };
        assert_eq!(
            judge(
                &w,
                true,
                &[entry("10.0.0.0", 8, "en0", Some("192.168.1.1"))]
            ),
            RouteState::Present
        );
        assert!(matches!(
            judge(
                &w,
                true,
                &[entry("10.0.0.0", 8, "en0", Some("192.168.1.254"))]
            ),
            RouteState::Conflicted(_)
        ));
    }

    #[test]
    fn a_route_of_the_other_family_or_prefix_is_not_the_same_route() {
        let w = wanted_if("10.0.0.0/8", "utun5");
        let table = [
            entry("10.0.0.0", 9, "en0", None),
            entry("fd00::", 8, "en0", None),
        ];
        assert_eq!(judge(&w, false, &table), RouteState::Missing);
    }

    // ---- view ------------------------------------------------------------

    fn derived(routes: Vec<WantedRoute>, skipped: Vec<(IpNet, String)>) -> Derivation {
        Derivation::Routes { routes, skipped }
    }

    #[test]
    fn the_view_summarises_the_worst_state() {
        let i = intent(&["10.0.0.0/8", "172.16.0.0/12"], via("utun5"));
        let routes = vec![
            wanted_if("10.0.0.0/8", "utun5"),
            wanted_if("172.16.0.0/12", "utun5"),
        ];
        let all_ok = view(
            &i,
            &derived(routes.clone(), vec![]),
            &[RouteState::Present, RouteState::Present],
        );
        assert_eq!(all_ok.status, ExplainStatus::Effective);
        assert_eq!((all_ok.installed, all_ok.wanted), (2, 2));
        assert_eq!(all_ok.metric, 100);

        let retry = view(
            &i,
            &derived(routes.clone(), vec![]),
            &[RouteState::Present, RouteState::Missing],
        );
        assert_eq!(retry.status, ExplainStatus::Missing);
        assert_eq!((retry.installed, retry.wanted), (1, 2));

        let clash = view(
            &i,
            &derived(routes, vec![]),
            &[
                RouteState::Missing,
                RouteState::Conflicted("another route to 172.16.0.0/12 via en0".into()),
            ],
        );
        assert_eq!(clash.status, ExplainStatus::Conflicted);
        assert!(clash.detail.contains("172.16.0.0/12"));
    }

    #[test]
    fn deferred_and_disabled_intents_report_why() {
        let i = intent(&["10.0.0.0/8"], via("utun5"));
        let waiting = view(
            &i,
            &Derivation::Deferred("interface utun5 is absent".into()),
            &[],
        );
        assert_eq!(waiting.status, ExplainStatus::Deferred);
        assert_eq!((waiting.installed, waiting.wanted), (0, 0));
        assert!(waiting.detail.contains("utun5"));
        let off = view(&i, &Derivation::Disabled, &[]);
        assert_eq!(off.status, ExplainStatus::Disabled);
    }

    #[test]
    fn skipped_destinations_are_mentioned_and_all_skipped_is_a_conflict() {
        let i = intent(&["0.0.0.0/1", "10.0.0.0/8"], via("utun5"));
        let skipped = vec![(
            "0.0.0.0/1".parse().unwrap(),
            "contains the uplink gateway".to_string(),
        )];
        let partial = view(
            &i,
            &derived(vec![wanted_if("10.0.0.0/8", "utun5")], skipped.clone()),
            &[RouteState::Present],
        );
        assert_eq!(partial.status, ExplainStatus::Effective);
        assert!(partial.detail.contains("0.0.0.0/1") && partial.detail.contains("skipped"));
        let nothing = view(&i, &derived(vec![], skipped), &[]);
        assert_eq!(nothing.status, ExplainStatus::Conflicted);
    }

    #[test]
    fn the_view_carries_the_request_back_to_the_ui() {
        let i = intent(&["10.0.0.0/8"], via("utun5"));
        let v = view(&i, &Derivation::Disabled, &[]);
        assert_eq!(v.id, "office");
        assert_eq!(v.destinations, ["10.0.0.0/8"]);
        assert_eq!(v.path, via("utun5"));
        assert_eq!(v.enabled, i.enabled);
    }
}
