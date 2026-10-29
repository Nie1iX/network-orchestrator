//! A read-only "doctor" for routing intents: it looks at the stored intents,
//! the system's routes and interfaces and the endpoints of the user's
//! connections, and turns recognisable breakage into ready-made fixes. Port of
//! the web client's `intentDoctor.ts`; the caller supplies the endpoints, so
//! the rules are tested without a machine.

use crate::daemon_protocol::{ExplainStatus, NetIntentPath, NetIntentSetParams, NetIntentView};
use crate::explorer;
use crate::models::{InterfaceCategory, NetworkInterface, RouteEntry};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

/// Metric of the bypass intents the doctor proposes (informational on macOS).
const BYPASS_METRIC: u32 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SuggestionKind {
    /// A VPN endpoint resolves out a tunnel: the handshake never reaches the
    /// server (the classic TLS-timeout incident).
    EndpointViaTunnel,
    /// A default-capturing intent through a tunnel will swallow endpoints that
    /// are not pinned to the uplink yet.
    UncoveredEndpoints,
    /// A route that is not the app's occupies an intent's destination.
    Conflict,
}

/// A literal address of a VPN server, with the connection it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownEndpoint {
    pub ip: IpAddr,
    pub profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentSuggestion {
    /// Dedup key; also how the UI dismisses a card for the session.
    pub key: String,
    pub kind: SuggestionKind,
    /// The tunnel interface involved (endpoint kinds).
    pub via_interface: Option<String>,
    /// The intent that is in conflict (conflict kind).
    pub intent_id: Option<String>,
    /// The destination another route occupies (conflict kind).
    pub destination: Option<String>,
    /// Endpoints the fix pins to the uplink.
    pub endpoints: Vec<String>,
    pub foreign_route: Option<RouteEntry>,
    /// Ready-to-apply intents; empty for a conflict.
    pub fixes: Vec<NetIntentSetParams>,
}

/// Whether `cidr` (a network or a bare address) contains `ip`; junk and the
/// other address family do not.
pub fn cidr_covers(cidr: &str, ip: IpAddr) -> bool {
    let cidr = cidr.trim();
    cidr.parse::<IpNet>()
        .or_else(|_| cidr.parse::<IpAddr>().map(IpNet::from))
        .is_ok_and(|net| net.contains(&ip))
}

/// Interfaces traffic should not take unless a rule says so. An interface the
/// inventory knows is judged by its category; an unknown one by its name.
fn tunnelish(name: &str, interfaces: &[NetworkInterface]) -> bool {
    match interfaces.iter().find(|i| i.name == name) {
        Some(known) => matches!(
            known.category,
            InterfaceCategory::Vpn | InterfaceCategory::Tunnel
        ),
        None => {
            let lower = name.to_ascii_lowercase();
            ["tun", "wg", "utun", "vpn", "ppp", "tailscale"]
                .iter()
                .any(|prefix| lower.starts_with(prefix))
        }
    }
}

fn unique_endpoints(endpoints: &[KnownEndpoint]) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    endpoints
        .iter()
        .filter(|e| seen.insert(e.ip))
        .map(|e| e.ip)
        .collect()
}

/// An enabled `direct` intent already pins `ip` to the physical uplink.
fn covered_by_direct(ip: IpAddr, intents: &[NetIntentView]) -> bool {
    intents.iter().any(|intent| {
        intent.enabled
            && intent.path.kind == "direct"
            && intent.destinations.iter().any(|dest| cidr_covers(dest, ip))
    })
}

/// A free `bypass-…` id that collides with neither a stored intent nor an id
/// the caller is about to create.
fn bypass_id(base: &str, intents: &[NetIntentView], taken_extra: &[String]) -> String {
    let mut slug = String::new();
    let mut gap = false;
    for c in base.to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            slug.push(c);
            gap = false;
        } else if !gap {
            slug.push('-');
            gap = true;
        }
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "uplink" } else { slug };
    let taken: HashSet<&str> = intents
        .iter()
        .map(|i| i.id.as_str())
        .chain(taken_extra.iter().map(String::as_str))
        .collect();
    let mut id = format!("bypass-{slug}");
    let mut n = 2;
    while taken.contains(id.as_str()) {
        id = format!("bypass-{slug}-{n}");
        n += 1;
    }
    id
}

fn bypass_intent(id: String, mut ips: Vec<String>) -> NetIntentSetParams {
    ips.sort();
    NetIntentSetParams {
        id,
        destinations: ips
            .iter()
            .map(|ip| {
                let host = if ip.contains(':') { 128 } else { 32 };
                format!("{ip}/{host}")
            })
            .collect(),
        path: NetIntentPath {
            gateway: None,
            kind: "direct".into(),
            interface: None,
        },
        metric: Some(BYPASS_METRIC),
        enabled: None,
    }
}

/// One intent that pins every known endpoint no `direct` intent covers to the
/// uplink. Offered alongside an "all traffic to a tunnel" rule so the rule does
/// not swallow the servers its own connections need.
pub fn uncovered_endpoint_intents(
    endpoints: &[KnownEndpoint],
    intents: &[NetIntentView],
    via: &str,
    taken_extra: &[String],
) -> Vec<NetIntentSetParams> {
    let mut ips: Vec<String> = unique_endpoints(endpoints)
        .into_iter()
        .filter(|ip| !covered_by_direct(*ip, intents))
        .map(|ip| ip.to_string())
        .collect();
    ips.sort();
    if ips.is_empty() {
        return Vec::new();
    }
    vec![bypass_intent(bypass_id(via, intents, taken_extra), ips)]
}

fn network_of(route: &RouteEntry) -> Option<IpNet> {
    IpNet::new(route.destination, route.prefix_len)
        .ok()
        .map(|net| net.trunc())
}

pub fn analyze(
    intents: &[NetIntentView],
    routes: &[RouteEntry],
    interfaces: &[NetworkInterface],
    endpoints: &[KnownEndpoint],
) -> Vec<IntentSuggestion> {
    let mut suggestions = Vec::new();
    let endpoint_ips = unique_endpoints(endpoints);
    let mut claimed: HashSet<IpAddr> = HashSet::new();

    // 1. An endpoint currently resolves out a tunnel: pin it to the uplink.
    let mut swallowed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for ip in &endpoint_ips {
        if covered_by_direct(*ip, intents) {
            continue;
        }
        let Some(route) = explorer::longest_prefix_match(*ip, routes) else {
            continue;
        };
        if !tunnelish(&route.interface_name, interfaces) {
            continue;
        }
        swallowed
            .entry(route.interface_name.clone())
            .or_default()
            .push(ip.to_string());
        claimed.insert(*ip);
    }
    for (via, mut ips) in swallowed {
        ips.sort();
        suggestions.push(IntentSuggestion {
            key: format!("endpoint-via-tunnel:{via}:{}", ips.join(",")),
            kind: SuggestionKind::EndpointViaTunnel,
            via_interface: Some(via.clone()),
            intent_id: None,
            destination: None,
            endpoints: ips.clone(),
            foreign_route: None,
            fixes: vec![bypass_intent(bypass_id(&via, intents, &[]), ips)],
        });
    }

    // 2. A default-capturing intent through a tunnel: every endpoint not
    //    pinned to the uplink breaks the moment it lands.
    let broad = intents.iter().find(|intent| {
        intent.enabled
            && intent.path.kind == "interface"
            && intent
                .destinations
                .iter()
                .any(|dest| dest.parse::<IpNet>().is_ok_and(|net| net.prefix_len() <= 1))
    });
    if let Some(broad) = broad {
        let mut uncovered: Vec<String> = endpoint_ips
            .iter()
            .filter(|ip| !claimed.contains(ip) && !covered_by_direct(**ip, intents))
            .map(ToString::to_string)
            .collect();
        uncovered.sort();
        if !uncovered.is_empty() {
            let via = broad.path.interface.clone().unwrap_or_else(|| "?".into());
            suggestions.push(IntentSuggestion {
                key: format!("uncovered-endpoints:{via}:{}", uncovered.join(",")),
                kind: SuggestionKind::UncoveredEndpoints,
                via_interface: Some(via.clone()),
                intent_id: None,
                destination: None,
                endpoints: uncovered.clone(),
                foreign_route: None,
                fixes: vec![bypass_intent(bypass_id(&via, intents, &[]), uncovered)],
            });
        }
    }

    // 3. A conflicted intent: say which route holds the destination. macOS
    //    cannot suppress it, so there is no fix to offer.
    for intent in intents
        .iter()
        .filter(|i| i.status == ExplainStatus::Conflicted)
    {
        for destination in &intent.destinations {
            let Ok(wanted) = destination.parse::<IpNet>().map(|net| net.trunc()) else {
                continue;
            };
            let Some(foreign) = routes
                .iter()
                .find(|route| network_of(route) == Some(wanted))
            else {
                continue;
            };
            suggestions.push(IntentSuggestion {
                key: format!("conflict:{}:{destination}", intent.id),
                kind: SuggestionKind::Conflict,
                via_interface: None,
                intent_id: Some(intent.id.clone()),
                destination: Some(destination.clone()),
                endpoints: Vec::new(),
                foreign_route: Some(foreign.clone()),
                fixes: Vec::new(),
            });
            break;
        }
    }
    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_protocol::{ExplainStatus, NetIntentPath, NetIntentView};
    use crate::models::{
        InterfaceCategory, InterfaceKind, InterfaceState, NetworkInterface, RouteEntry,
    };

    fn iface(name: &str, category: InterfaceCategory) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            friendly_name: name.into(),
            kind: InterfaceKind::Ethernet,
            state: InterfaceState::Up,
            addresses: Vec::new(),
            dns_servers: Vec::new(),
            dns_suffix: None,
            mtu: Some(1500),
            if_index: 1,
            physical: category == InterfaceCategory::Physical,
            mac: None,
            gateway: None,
            ipv6_gateway: None,
            rx_bytes: None,
            tx_bytes: None,
            link_speed_mbps: None,
            category,
            description: String::new(),
            if_type: 6,
            tunnel_type: None,
        }
    }

    fn route(destination: &str, prefix: u8, interface: &str) -> RouteEntry {
        RouteEntry {
            destination: destination.parse().unwrap(),
            prefix_len: prefix,
            gateway: Some("192.168.1.1".parse().unwrap()),
            interface_index: 1,
            interface_name: interface.into(),
            metric: 100,
        }
    }

    fn intent(id: &str, destinations: &[&str], path: NetIntentPath) -> NetIntentView {
        NetIntentView {
            id: id.into(),
            destinations: destinations.iter().map(ToString::to_string).collect(),
            path,
            metric: 100,
            enabled: true,
            status: ExplainStatus::Effective,
            detail: String::new(),
            installed: 1,
            wanted: 1,
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

    fn endpoint(ip: &str, profile: &str) -> KnownEndpoint {
        KnownEndpoint {
            ip: ip.parse().unwrap(),
            profile: profile.into(),
        }
    }

    #[test]
    fn prefixes_cover_addresses_of_their_own_family_only() {
        let covers = |cidr: &str, ip: &str| cidr_covers(cidr, ip.parse().unwrap());
        assert!(covers("10.20.0.0/16", "10.20.9.9"));
        assert!(!covers("10.20.0.0/16", "10.21.9.9"));
        assert!(covers("0.0.0.0/0", "8.8.8.8"));
        assert!(covers("91.245.41.31/32", "91.245.41.31"));
        assert!(!covers("91.245.41.31/32", "91.245.41.30"));
        assert!(!covers("not-a-cidr", "1.2.3.4"));
        assert!(!covers("10.0.0.0/8", "fe80::1"));
        assert!(covers("fd00::/8", "fd12::1"));
        // A bare address is a host route.
        assert!(covers("91.245.41.31", "91.245.41.31"));
    }

    #[test]
    fn an_endpoint_routed_out_a_tunnel_gets_a_direct_bypass_fix() {
        let suggestions = analyze(
            &[],
            &[
                route("0.0.0.0", 0, "en0"),
                route("0.0.0.0", 1, "utun5"),
                route("128.0.0.0", 1, "utun5"),
            ],
            &[
                iface("en0", InterfaceCategory::Physical),
                iface("utun5", InterfaceCategory::Vpn),
            ],
            &[endpoint("91.245.41.31", "office")],
        );
        assert_eq!(suggestions.len(), 1);
        let s = &suggestions[0];
        assert_eq!(s.kind, SuggestionKind::EndpointViaTunnel);
        assert_eq!(s.via_interface.as_deref(), Some("utun5"));
        assert_eq!(s.endpoints, ["91.245.41.31"]);
        assert_eq!(s.fixes[0].destinations, ["91.245.41.31/32"]);
        assert_eq!(s.fixes[0].path.kind, "direct");
        assert_eq!(s.fixes[0].metric, Some(50));
        assert_eq!(s.fixes[0].id, "bypass-utun5");
    }

    #[test]
    fn an_endpoint_already_pinned_by_a_direct_intent_stays_quiet() {
        let pinned = intent("ep", &["91.245.41.31/32"], direct());
        let suggestions = analyze(
            &[pinned],
            &[route("0.0.0.0", 1, "utun5")],
            &[iface("utun5", InterfaceCategory::Vpn)],
            &[endpoint("91.245.41.31", "office")],
        );
        assert!(suggestions.is_empty());
    }

    #[test]
    fn a_disabled_direct_intent_does_not_count_as_coverage() {
        let mut off = intent("ep", &["91.245.41.31/32"], direct());
        off.enabled = false;
        let suggestions = analyze(
            &[off],
            &[route("0.0.0.0", 1, "utun5")],
            &[iface("utun5", InterfaceCategory::Vpn)],
            &[endpoint("91.245.41.31", "office")],
        );
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].kind, SuggestionKind::EndpointViaTunnel);
    }

    #[test]
    fn an_unclassified_interface_is_judged_by_its_name() {
        // Not in the inventory: the usual tunnel names still count.
        for name in ["utun9", "tun0", "wg0", "ppp0", "tailscale0", "vpn1"] {
            let suggestions = analyze(
                &[],
                &[route("0.0.0.0", 0, name)],
                &[],
                &[endpoint("203.0.113.7", "p")],
            );
            assert_eq!(suggestions.len(), 1, "{name}");
        }
        let plain = analyze(
            &[],
            &[route("0.0.0.0", 0, "en0")],
            &[],
            &[endpoint("203.0.113.7", "p")],
        );
        assert!(plain.is_empty());
        // A known interface is judged by its category, whatever it is called.
        let named_like_a_tunnel = analyze(
            &[],
            &[route("0.0.0.0", 0, "utun-lan")],
            &[iface("utun-lan", InterfaceCategory::Physical)],
            &[endpoint("203.0.113.7", "p")],
        );
        assert!(named_like_a_tunnel.is_empty());
    }

    #[test]
    fn the_most_specific_route_decides_where_an_endpoint_goes() {
        // The /32 to the endpoint via the uplink beats the tunnel's halves.
        let suggestions = analyze(
            &[],
            &[
                route("0.0.0.0", 1, "utun5"),
                route("91.245.41.31", 32, "en0"),
            ],
            &[
                iface("utun5", InterfaceCategory::Vpn),
                iface("en0", InterfaceCategory::Physical),
            ],
            &[endpoint("91.245.41.31", "office")],
        );
        assert!(suggestions.is_empty());
    }

    #[test]
    fn a_broad_intent_through_a_tunnel_surfaces_uncovered_endpoints_early() {
        let all = intent("all", &["0.0.0.0/1", "128.0.0.0/1"], via("utun9"));
        let suggestions = analyze(
            &[all],
            &[route("0.0.0.0", 0, "en0")],
            &[iface("en0", InterfaceCategory::Physical)],
            &[
                endpoint("91.245.41.31", "office"),
                endpoint("203.0.113.7", "media"),
            ],
        );
        assert_eq!(suggestions.len(), 1);
        let s = &suggestions[0];
        assert_eq!(s.kind, SuggestionKind::UncoveredEndpoints);
        assert_eq!(s.via_interface.as_deref(), Some("utun9"));
        assert_eq!(s.endpoints, ["203.0.113.7", "91.245.41.31"]);
        assert_eq!(s.fixes[0].path.kind, "direct");
    }

    #[test]
    fn a_narrow_intent_or_a_direct_one_is_not_a_default_capture() {
        let narrow = intent("n", &["10.0.0.0/8"], via("utun9"));
        let direct_all = intent("d", &["0.0.0.0/0"], direct());
        let mut off = intent("o", &["0.0.0.0/1"], via("utun9"));
        off.enabled = false;
        let suggestions = analyze(
            &[narrow, direct_all, off],
            &[route("0.0.0.0", 0, "en0")],
            &[iface("en0", InterfaceCategory::Physical)],
            &[endpoint("203.0.113.7", "media")],
        );
        assert!(suggestions.is_empty());
    }

    #[test]
    fn an_endpoint_already_flagged_is_not_flagged_twice() {
        let all = intent("all", &["0.0.0.0/1"], via("utun9"));
        let suggestions = analyze(
            &[all],
            &[route("0.0.0.0", 1, "utun5")],
            &[iface("utun5", InterfaceCategory::Vpn)],
            &[endpoint("91.245.41.31", "office")],
        );
        assert_eq!(suggestions.len(), 1, "only the endpoint-via-tunnel card");
        assert_eq!(suggestions[0].kind, SuggestionKind::EndpointViaTunnel);
    }

    #[test]
    fn a_conflicted_intent_points_at_the_route_that_occupies_its_destination() {
        let mut media = intent("media", &["203.0.113.0/24"], via("utun9"));
        media.status = ExplainStatus::Conflicted;
        let foreign = route("203.0.113.0", 24, "en0");
        let suggestions = analyze(&[media], std::slice::from_ref(&foreign), &[], &[]);
        assert_eq!(suggestions.len(), 1);
        let s = &suggestions[0];
        assert_eq!(s.kind, SuggestionKind::Conflict);
        assert_eq!(s.intent_id.as_deref(), Some("media"));
        assert_eq!(s.destination.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(s.foreign_route.as_ref(), Some(&foreign));
        assert!(
            s.fixes.is_empty(),
            "macOS cannot suppress a route, so this is advice only"
        );
        assert_eq!(s.key, "conflict:media:203.0.113.0/24");
    }

    #[test]
    fn a_conflict_without_a_visible_route_makes_no_card() {
        let mut media = intent("media", &["203.0.113.0/24"], via("utun9"));
        media.status = ExplainStatus::Conflicted;
        assert!(analyze(&[media], &[route("10.0.0.0", 8, "en0")], &[], &[]).is_empty());
    }

    #[test]
    fn bypass_ids_avoid_the_ids_in_use() {
        let taken = intent("bypass-utun5", &["10.0.0.0/8"], via("utun5"));
        let second = intent("bypass-utun5-2", &["10.1.0.0/16"], via("utun5"));
        let suggestions = analyze(
            &[taken, second],
            &[route("0.0.0.0", 1, "utun5")],
            &[iface("utun5", InterfaceCategory::Vpn)],
            &[endpoint("91.245.41.31", "office")],
        );
        assert_eq!(suggestions[0].fixes[0].id, "bypass-utun5-3");
    }

    #[test]
    fn every_unknown_endpoint_is_pinned_by_one_intent() {
        let fixes = uncovered_endpoint_intents(
            &[
                endpoint("91.245.41.31", "office"),
                endpoint("203.0.113.7", "media"),
            ],
            &[],
            "Mihomo Tunnel",
            &["everything".to_string()],
        );
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].id, "bypass-mihomo-tunnel");
        assert_eq!(fixes[0].destinations, ["203.0.113.7/32", "91.245.41.31/32"]);
        assert_eq!(fixes[0].path.kind, "direct");
        assert_eq!(fixes[0].metric, Some(50));
        // The id the caller is about to use is avoided too.
        let clash = uncovered_endpoint_intents(
            &[endpoint("91.245.41.31", "office")],
            &[],
            "x",
            &["bypass-x".to_string()],
        );
        assert_eq!(clash[0].id, "bypass-x-2");
    }

    #[test]
    fn endpoints_a_direct_intent_covers_need_no_new_bypass() {
        let pinned = intent("ep", &["91.245.41.31/32"], direct());
        assert!(uncovered_endpoint_intents(
            &[endpoint("91.245.41.31", "office")],
            &[pinned],
            "x",
            &[]
        )
        .is_empty());
        assert!(uncovered_endpoint_intents(&[], &[], "x", &[]).is_empty());
    }

    #[test]
    fn ipv6_endpoints_are_pinned_with_a_host_prefix() {
        let fixes = uncovered_endpoint_intents(&[endpoint("2001:db8::7", "p")], &[], "x", &[]);
        assert_eq!(fixes[0].destinations, ["2001:db8::7/128"]);
    }

    #[test]
    fn the_same_endpoint_from_two_profiles_is_listed_once() {
        let fixes = uncovered_endpoint_intents(
            &[endpoint("203.0.113.7", "a"), endpoint("203.0.113.7", "b")],
            &[],
            "x",
            &[],
        );
        assert_eq!(fixes[0].destinations, ["203.0.113.7/32"]);
    }
}
