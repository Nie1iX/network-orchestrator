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
pub const MAX_ID_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentPath {
    /// The current physical uplink, so the traffic bypasses tunnels.
    Direct,
    /// Any device, a tunnel included; armed until it exists.
    Interface(String),
    /// A next hop on a connected network; armed until one is connected.
    Gateway(IpAddr),
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
    id.len() <= MAX_ID_LEN
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

/// A next hop that can be reached through a connected network.
fn check_gateway(gateway: IpAddr) -> Result<(), String> {
    let link_local = match gateway {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    if gateway.is_unspecified() || gateway.is_loopback() || gateway.is_multicast() || link_local {
        return Err("This address cannot be used as a gateway".into());
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
        "gateway" => {
            let text = params.path.gateway.as_deref().unwrap_or_default();
            let gateway = text
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| "Enter the gateway as an IP address".to_string())?;
            check_gateway(gateway)?;
            IntentPath::Gateway(gateway)
        }
        _ => return Err("The path must be 'direct', an interface or a gateway".into()),
    };
    Ok(Intent {
        id: params.id.clone(),
        destinations,
        path,
        metric: params.metric.unwrap_or(DEFAULT_METRIC),
        enabled: params.enabled.unwrap_or(true),
    })
}

// ---- static-route profiles ---------------------------------------------

/// Intents the app creates for static-route profiles carry this prefix, and
/// the Intents page leaves them to the profile's own switch.
pub const STATIC_PREFIX: &str = "static-";

pub fn is_static_intent_id(id: &str) -> bool {
    id.starts_with(STATIC_PREFIX)
}

/// `static-<profile id>`, lowercased with anything else turned into `-`. Room
/// is left for the `-bypass` and `-gwN` suffixes.
pub fn static_intent_id(profile_id: &str) -> Result<String, String> {
    let slug: String = profile_id
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let id = format!("{STATIC_PREFIX}{slug}");
    if slug.is_empty() || id.len() + BYPASS_SUFFIX.len() > MAX_ID_LEN || !valid_id(&id) {
        return Err("This profile's identifier is too long for static routes".into());
    }
    Ok(id)
}

const BYPASS_SUFFIX: &str = "-bypass";
const GATEWAY_SUFFIX: &str = "-gw";

/// Whether `intent_id` is one of the intents `static_intents` derives for
/// the profile (its routes, its gateway groups or its endpoint bypass).
pub fn static_belongs(profile_id: &str, intent_id: &str) -> bool {
    let Ok(base) = static_intent_id(profile_id) else {
        return false;
    };
    let Some(rest) = intent_id.strip_prefix(&base) else {
        return false;
    };
    rest.is_empty()
        || rest == BYPASS_SUFFIX
        || rest
            .strip_prefix(GATEWAY_SUFFIX)
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// The intents that carry a static-route profile, in the order to apply them:
/// the endpoint bypass first (so the tunnel's own packets never loop), then
/// the routes through the profile's interface, then one intent per distinct
/// gateway. `bypass` holds the endpoints already resolved to addresses.
pub fn static_intents(
    profile: &crate::models::Profile,
    bypass: &[IpAddr],
) -> Result<Vec<NetIntentSetParams>, String> {
    use crate::models::TunnelBackend;
    if profile.backend != TunnelBackend::None {
        return Err("This is not a static-route profile".into());
    }
    if profile.routes.is_empty() {
        return Err("Add at least one route".into());
    }
    let base = static_intent_id(&profile.id)?;
    let interface = profile.interface_name.trim();
    let needs_interface = profile.routes.iter().any(|route| route.via.is_none());
    if needs_interface && interface.is_empty() {
        return Err("Choose the interface these routes go through".into());
    }
    if !interface.is_empty() && (!valid_interface(interface) || interface == "lo0") {
        return Err(format!(
            "'{interface}' is not a macOS interface name such as en0 or utun4"
        ));
    }
    let mut intents = Vec::new();
    let mut bypassed: Vec<IpNet> = Vec::new();
    for address in bypass {
        let net = IpNet::from(*address);
        check_routable(&net, &net.to_string())?;
        if !bypassed.contains(&net) {
            bypassed.push(net);
        }
    }
    if !bypassed.is_empty() {
        intents.push(NetIntentSetParams {
            id: format!("{base}{BYPASS_SUFFIX}"),
            destinations: bypassed.iter().map(ToString::to_string).collect(),
            path: NetIntentPath {
                gateway: None,
                kind: "direct".into(),
                interface: None,
            },
            metric: None,
            enabled: Some(true),
        });
    }
    let direct: Vec<_> = profile.routes.iter().filter(|r| r.via.is_none()).collect();
    if !direct.is_empty() {
        intents.push(NetIntentSetParams {
            id: base.clone(),
            destinations: direct.iter().map(|r| r.destination.to_string()).collect(),
            path: NetIntentPath {
                gateway: None,
                kind: "interface".into(),
                interface: Some(interface.to_string()),
            },
            metric: direct.first().map(|route| route.metric),
            enabled: Some(true),
        });
    }
    let mut gateways: Vec<(IpAddr, Vec<&crate::models::PolicyRoute>)> = Vec::new();
    for route in profile.routes.iter().filter(|r| r.via.is_some()) {
        let gateway = route.via.expect("filtered");
        check_gateway(gateway)?;
        match gateways.iter_mut().find(|(known, _)| *known == gateway) {
            Some((_, routes)) => routes.push(route),
            None => gateways.push((gateway, vec![route])),
        }
    }
    for (index, (gateway, routes)) in gateways.iter().enumerate() {
        intents.push(NetIntentSetParams {
            id: format!("{base}{GATEWAY_SUFFIX}{}", index + 1),
            destinations: routes.iter().map(|r| r.destination.to_string()).collect(),
            path: NetIntentPath {
                gateway: Some(gateway.to_string()),
                kind: "gateway".into(),
                interface: None,
            },
            metric: routes.first().map(|route| route.metric),
            enabled: Some(true),
        });
    }
    Ok(intents)
}

/// What a static-route profile reports, given the helper's view of its
/// intents (none when the helper has none). Waiting for the interface still
/// counts as running: the routes are armed. One conflicted intent fails the
/// whole profile.
pub fn static_state(views: &[NetIntentView]) -> (crate::models::TunnelState, Option<String>) {
    use crate::models::TunnelState;
    if let Some(view) = views
        .iter()
        .find(|view| view.status == ExplainStatus::Conflicted)
    {
        return (TunnelState::Failed, Some(view.detail.clone()));
    }
    if views
        .iter()
        .all(|view| view.status == ExplainStatus::Disabled)
    {
        return (TunnelState::Stopped, None);
    }
    let waiting = views.iter().find(|view| {
        matches!(
            view.status,
            ExplainStatus::Deferred | ExplainStatus::Missing
        )
    });
    (
        TunnelState::Running,
        waiting.map(|view| view.detail.clone()),
    )
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
        IntentPath::Gateway(gateway) => {
            if !network
                .addresses
                .iter()
                .any(|local| local.address.contains(gateway))
            {
                return Derivation::Deferred(format!(
                    "the gateway {gateway} is not on a connected network"
                ));
            }
            (RouteTarget::Gateway(*gateway), Some(*gateway))
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
        IntentPath::Gateway(gateway) => NetIntentPath {
            gateway: Some(gateway.to_string()),
            kind: "gateway".into(),
            interface: None,
        },
        IntentPath::Direct => NetIntentPath {
            gateway: None,
            kind: "direct".into(),
            interface: None,
        },
        IntentPath::Interface(name) => NetIntentPath {
            gateway: None,
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
            gateway: None,
            kind: "direct".into(),
            interface: None,
        }
    }

    fn via(name: &str) -> NetIntentPath {
        NetIntentPath {
            gateway: None,
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
        for good in ["a", "office", "wg-home_2", &"a".repeat(64)] {
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
            &"a".repeat(65),
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
            gateway: None,
            kind: "interface".into(),
            interface: None,
        };
        assert!(normalize(&params("x", &["10.0.0.0/8"], no_name)).is_err());
        let unknown = NetIntentPath {
            gateway: None,
            kind: "tunnel".into(),
            interface: None,
        };
        assert!(normalize(&params("x", &["10.0.0.0/8"], unknown)).is_err());
        // A name on a direct path is ignored, not trusted.
        let sloppy = NetIntentPath {
            gateway: None,
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

    // ---- static-route profiles ------------------------------------------

    fn static_profile(id: &str, interface: &str, routes: &[&str]) -> crate::models::Profile {
        crate::models::Profile {
            id: id.into(),
            name: "Static".into(),
            backend: crate::models::TunnelBackend::None,
            interface_name: interface.into(),
            routes: routes
                .iter()
                .map(|r| crate::models::PolicyRoute {
                    destination: r.parse().unwrap(),
                    metric: 5,
                    via: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn gateway_path(gateway: &str) -> NetIntentPath {
        NetIntentPath {
            gateway: Some(gateway.into()),
            kind: "gateway".into(),
            interface: None,
        }
    }

    fn addr(interface: &str, cidr: &str) -> IfaceAddr {
        IfaceAddr {
            if_index: 1,
            interface: interface.into(),
            address: cidr.parse().unwrap(),
        }
    }

    #[test]
    fn a_static_profile_becomes_an_interface_intent_with_a_reserved_name() {
        let p = static_profile("office-lan", "en7", &["192.0.2.0/24", "198.51.100.0/24"]);
        let intents = static_intents(&p, &[]).unwrap();
        assert_eq!(intents.len(), 1);
        let intent = &intents[0];
        assert_eq!(intent.id, "static-office-lan");
        assert_eq!(intent.destinations, ["192.0.2.0/24", "198.51.100.0/24"]);
        assert_eq!(intent.path.kind, "interface");
        assert_eq!(intent.path.interface.as_deref(), Some("en7"));
        assert_eq!(intent.metric, Some(5));
        // The helper accepts what the profile produces.
        assert!(normalize(intent).is_ok());
        assert!(is_static_intent_id("static-office-lan"));
        assert!(!is_static_intent_id("office"));
    }

    #[test]
    fn a_profile_id_is_made_a_valid_intent_id_or_refused() {
        assert_eq!(static_intent_id("Office.LAN").unwrap(), "static-office-lan");
        // A UUID fits with room for the `-bypass` and `-gwN` suffixes.
        assert!(static_intent_id("0b6f0c1e-8a53-4f0e-9a3e-2f1d5c7b9a10").is_ok());
        assert_eq!(static_intent_id(&"a".repeat(50)).unwrap().len(), 57);
        assert!(static_intent_id(&"a".repeat(51)).is_err());
        assert!(static_intent_id("").is_err());
    }

    #[test]
    fn a_static_profile_that_cannot_be_enforced_is_refused_with_a_reason() {
        let ok = static_profile("s", "en7", &["192.0.2.0/24"]);
        let mut other_backend = ok.clone();
        other_backend.backend = crate::models::TunnelBackend::WireGuard;
        assert!(static_intents(&other_backend, &[]).is_err());
        let mut no_interface = ok.clone();
        no_interface.interface_name = " ".into();
        assert!(static_intents(&no_interface, &[])
            .unwrap_err()
            .contains("interface"));
        let mut bad_interface = ok.clone();
        bad_interface.interface_name = "Ethernet 2".into();
        assert!(static_intents(&bad_interface, &[])
            .unwrap_err()
            .contains("macOS"));
        let none = static_profile("s", "en7", &[]);
        assert!(static_intents(&none, &[]).unwrap_err().contains("route"));
        let mut loopback = ok;
        loopback.routes[0].via = Some("127.0.0.1".parse().unwrap());
        assert!(static_intents(&loopback, &[])
            .unwrap_err()
            .contains("gateway"));
    }

    #[test]
    fn routes_with_their_own_gateway_get_one_intent_per_gateway() {
        let mut p = static_profile(
            "s",
            "",
            &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
        );
        p.routes[0].via = Some("10.0.0.1".parse().unwrap());
        p.routes[1].via = Some("10.0.0.2".parse().unwrap());
        p.routes[2].via = Some("10.0.0.1".parse().unwrap());
        // No interface is needed when every route names its gateway.
        let intents = static_intents(&p, &[]).unwrap();
        let ids: Vec<_> = intents.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["static-s-gw1", "static-s-gw2"]);
        assert_eq!(intents[0].destinations, ["192.0.2.0/24", "203.0.113.0/24"]);
        assert_eq!(intents[0].path, gateway_path("10.0.0.1"));
        assert_eq!(intents[1].destinations, ["198.51.100.0/24"]);
        for intent in &intents {
            assert!(normalize(intent).is_ok(), "{}", intent.id);
            assert!(static_belongs("s", &intent.id));
        }
        // Mixed: interface routes first, then gateways.
        p.routes[1].via = None;
        p.interface_name = "en7".into();
        let ids: Vec<_> = static_intents(&p, &[])
            .unwrap()
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(ids, ["static-s", "static-s-gw1"]);
    }

    #[test]
    fn endpoint_bypasses_come_first_and_go_direct() {
        let p = static_profile("s", "utun4", &["10.0.0.0/8"]);
        let bypass: Vec<IpAddr> = vec![
            "203.0.113.7".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        let intents = static_intents(&p, &bypass).unwrap();
        assert_eq!(intents[0].id, "static-s-bypass");
        assert_eq!(intents[0].path.kind, "direct");
        assert_eq!(
            intents[0].destinations,
            ["203.0.113.7/32", "2001:db8::1/128"]
        );
        assert_eq!(intents[1].id, "static-s");
        assert!(intents.iter().all(|i| normalize(i).is_ok()));
        // Unroutable endpoints are caught when the intent is normalised.
        let bad = static_intents(&p, &["127.0.0.1".parse().unwrap()]).unwrap_err();
        assert!(bad.contains("cannot be routed"), "{bad}");
    }

    #[test]
    fn an_intent_belongs_to_a_profile_by_its_exact_derived_name() {
        assert!(static_belongs("office", "static-office"));
        assert!(static_belongs("office", "static-office-bypass"));
        assert!(static_belongs("office", "static-office-gw12"));
        assert!(!static_belongs("office", "static-office2"));
        assert!(!static_belongs("office", "static-office-gw"));
        assert!(!static_belongs("office", "static-officer-gw1"));
        assert!(!static_belongs("office", "office"));
    }

    #[test]
    fn the_gateway_path_is_checked() {
        for good in ["10.0.0.1", "2001:db8::1"] {
            let i = normalize(&params("g", &["192.0.2.0/24"], gateway_path(good))).unwrap();
            assert_eq!(i.path, IntentPath::Gateway(good.parse().unwrap()));
        }
        for bad in [
            "",
            "host",
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "fe80::1",
            "::1",
        ] {
            assert!(
                normalize(&params("g", &["192.0.2.0/24"], gateway_path(bad))).is_err(),
                "{bad}"
            );
        }
        let none = NetIntentPath {
            gateway: None,
            kind: "gateway".into(),
            interface: None,
        };
        assert!(normalize(&params("g", &["192.0.2.0/24"], none)).is_err());
    }

    #[test]
    fn a_gateway_route_waits_until_the_gateway_is_on_a_connected_network() {
        let i = intent(&["192.0.2.0/24"], gateway_path("10.0.0.1"));
        let mut net = network(&["en0", "en7"]);
        assert!(
            matches!(derive(&i, &net), Derivation::Deferred(reason) if reason.contains("10.0.0.1"))
        );
        net.addresses = vec![addr("en7", "10.0.0.5/24")];
        let Derivation::Routes { routes, .. } = derive(&i, &net) else {
            panic!("routes expected");
        };
        assert_eq!(
            routes,
            [WantedRoute {
                destination: "192.0.2.0/24".parse().unwrap(),
                target: RouteTarget::Gateway("10.0.0.1".parse().unwrap()),
            }]
        );
        // A destination holding the gateway itself would loop.
        let loopy = intent(&["10.0.0.0/8"], gateway_path("10.0.0.1"));
        let Derivation::Routes { routes, skipped } = derive(&loopy, &net) else {
            panic!("routes expected");
        };
        assert!(routes.is_empty() && skipped.len() == 1);
        // The other address family does not count.
        let v6 = intent(&["2001:db8::/32"], gateway_path("2001:db8:1::1"));
        assert!(matches!(derive(&v6, &net), Derivation::Deferred(_)));
        // The view reports the path back.
        let v = view(&i, &derive(&i, &net), &[RouteState::Missing]);
        assert_eq!(v.path, gateway_path("10.0.0.1"));
    }

    #[test]
    fn the_state_of_a_static_profile_follows_its_intents() {
        use crate::models::TunnelState;
        let make = |status: ExplainStatus, detail: &str| {
            let mut v = view(
                &intent(&["192.0.2.0/24"], via("en7")),
                &Derivation::Routes {
                    routes: vec![wanted_if("192.0.2.0/24", "en7")],
                    skipped: vec![],
                },
                &[RouteState::Present],
            );
            v.status = status;
            v.detail = detail.into();
            v
        };
        let effective = make(ExplainStatus::Effective, "1 route(s) in place");
        assert_eq!(static_state(&[]), (TunnelState::Stopped, None));
        assert_eq!(
            static_state(std::slice::from_ref(&effective)).0,
            TunnelState::Running
        );
        let deferred = make(ExplainStatus::Deferred, "interface en7 is absent");
        assert_eq!(
            static_state(std::slice::from_ref(&deferred)),
            (TunnelState::Running, Some("interface en7 is absent".into()))
        );
        assert_eq!(
            static_state(&[make(ExplainStatus::Missing, "retry")]).0,
            TunnelState::Running
        );
        let conflict = make(ExplainStatus::Conflicted, "another route is in place");
        // One bad intent fails the profile, whatever the others do.
        assert_eq!(
            static_state(&[effective.clone(), conflict.clone()]),
            (
                TunnelState::Failed,
                Some("another route is in place".into())
            )
        );
        assert_eq!(
            static_state(&[deferred, effective.clone()]).1.as_deref(),
            Some("interface en7 is absent")
        );
        assert_eq!(
            static_state(&[make(ExplainStatus::Disabled, "off")]),
            (TunnelState::Stopped, None)
        );
    }
}
