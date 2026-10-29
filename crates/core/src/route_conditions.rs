//! Conditional routes ("on the office LAN, reach these networks directly") as
//! pure rules: when a condition holds, which routes it wants, and how a rule is
//! reported. The helper evaluates them on every network change; nothing here
//! touches the machine.

use crate::daemon_protocol::{
    ConditionalRouteRule, ConditionalRuleState, ConditionalRuleStatus, RouteCondition,
};
use crate::route_intents::{
    check_routable, Derivation, IfaceAddr, NetworkView, RouteState, RouteTarget, WantedRoute,
};
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;

pub const MAX_RULES: usize = 32;
pub const MAX_RULE_ROUTES: usize = 256;
const MAX_ID_BYTES: usize = 48;
const MAX_NAME_BYTES: usize = 128;

/// Interfaces that can never be the conditioned physical network: tunnels
/// (this app's and foreign), loopback and Apple's plumbing.
const NON_UPLINK_PREFIXES: &[&str] = &[
    "lo", "utun", "utap", "gif", "stf", "ipsec", "ppp", "tun", "tap", "awdl", "llw", "anpi", "ap",
    "p2p", "bridge", "vmenet", "vmnet",
];

pub fn non_uplink_name(name: &str) -> bool {
    NON_UPLINK_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Link-local, loopback, multicast and unspecified addresses say nothing about
/// which network the machine is on.
fn global_scope(address: &IpAddr) -> bool {
    let link_local = match address {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    !(address.is_loopback() || address.is_multicast() || address.is_unspecified() || link_local)
}

/// The interface holding a global address inside `prefix`; the lowest index
/// wins so the choice is stable between evaluations.
pub fn match_interface(addresses: &[IfaceAddr], prefix: IpNet) -> Option<String> {
    addresses
        .iter()
        .filter(|a| {
            a.if_index != 0
                && !non_uplink_name(&a.interface)
                && global_scope(&a.address.addr())
                && prefix.contains(&a.address.addr())
        })
        .min_by_key(|a| a.if_index)
        .map(|a| a.interface.clone())
}

/// What `condRules.put` accepts.
pub fn validate_rule(rule: &ConditionalRouteRule) -> Result<(), String> {
    let id_ok = !rule.id.is_empty()
        && rule.id.len() <= MAX_ID_BYTES
        && rule
            .id
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && rule
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !id_ok {
        return Err(format!(
            "The rule id must be 1-{MAX_ID_BYTES} characters of letters, digits, '.', '_' or '-'"
        ));
    }
    if rule.name.is_empty()
        || rule.name.len() > MAX_NAME_BYTES
        || rule.name.chars().any(char::is_control)
    {
        return Err(format!(
            "The rule name must be 1-{MAX_NAME_BYTES} characters without control characters"
        ));
    }
    let RouteCondition::InterfaceAddressIn { prefix } = &rule.condition;
    if prefix.trunc() != *prefix {
        return Err(format!("The condition network {prefix} has host bits set"));
    }
    if rule.routes.is_empty() || rule.routes.len() > MAX_RULE_ROUTES {
        return Err(format!(
            "A rule needs 1-{MAX_RULE_ROUTES} routes, got {}",
            rule.routes.len()
        ));
    }
    let mut seen = HashSet::new();
    for route in &rule.routes {
        if route.destination.trunc() != route.destination {
            return Err(format!(
                "The destination {} has host bits set",
                route.destination
            ));
        }
        check_routable(&route.destination, &route.destination.to_string())?;
        if let Some(via) = route.via {
            let same_family = matches!(
                (route.destination, via),
                (IpNet::V4(_), IpAddr::V4(_)) | (IpNet::V6(_), IpAddr::V6(_))
            );
            if !same_family {
                return Err(format!(
                    "The gateway {via} is not in the address family of {}",
                    route.destination
                ));
            }
            if via.is_unspecified() || via.is_multicast() {
                return Err(format!("The gateway {via} must be a unicast address"));
            }
        }
        if !seen.insert(route.destination) {
            return Err(format!("The route {} is listed twice", route.destination));
        }
    }
    Ok(())
}

/// The interface that satisfies the rule's condition right now.
pub fn condition_match(rule: &ConditionalRouteRule, network: &NetworkView) -> Option<String> {
    let RouteCondition::InterfaceAddressIn { prefix } = &rule.condition;
    match_interface(&network.addresses, *prefix)
}

/// The routes a rule wants now: none while it is off or the condition does
/// not hold, otherwise its routes on the matched interface (or via the
/// explicit gateway). A destination that contains the uplink gateway is not
/// pulled off the uplink.
pub fn derive_rule(rule: &ConditionalRouteRule, network: &NetworkView) -> Derivation {
    if !rule.enabled {
        return Derivation::Disabled;
    }
    let RouteCondition::InterfaceAddressIn { prefix } = &rule.condition;
    let Some(matched) = condition_match(rule, network) else {
        return Derivation::Deferred(format!("no interface has an address inside {prefix}"));
    };
    let protect = network
        .uplink
        .as_ref()
        .filter(|uplink| uplink.interface != matched)
        .and_then(|uplink| uplink.gateway);
    let mut routes = Vec::new();
    let mut skipped = Vec::new();
    for route in &rule.routes {
        match protect {
            Some(gateway) if route.destination.contains(&gateway) => skipped.push((
                route.destination,
                format!("it contains the uplink gateway {gateway}"),
            )),
            _ => routes.push(WantedRoute {
                destination: route.destination,
                target: match route.via {
                    Some(gateway) => RouteTarget::Gateway(gateway),
                    None => RouteTarget::Interface(matched.clone()),
                },
            }),
        }
    }
    Derivation::Routes { routes, skipped }
}

/// The status a rule reports: `states` has one verdict per wanted route.
pub fn rule_status(
    _rule: &ConditionalRouteRule,
    derivation: &Derivation,
    states: &[RouteState],
    matched: Option<&str>,
) -> ConditionalRuleStatus {
    let status = |state, applied: usize, detail: Option<String>| ConditionalRuleStatus {
        state,
        matched_interface: matched.map(String::from),
        applied_routes: applied,
        detail,
    };
    match derivation {
        Derivation::Disabled => status(ConditionalRuleState::Disabled, 0, None),
        Derivation::Deferred(_) => status(ConditionalRuleState::Inactive, 0, None),
        Derivation::Routes { routes, skipped } => {
            let applied = states.iter().filter(|s| **s == RouteState::Present).count();
            let note = (!skipped.is_empty()).then(|| {
                skipped
                    .iter()
                    .map(|(destination, reason)| format!("skipped {destination}: {reason}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            });
            let conflict = states.iter().find_map(|s| match s {
                RouteState::Conflicted(detail) => Some(detail.clone()),
                _ => None,
            });
            if routes.is_empty() && !skipped.is_empty() {
                status(ConditionalRuleState::Error, 0, note)
            } else if let Some(detail) = conflict {
                status(ConditionalRuleState::Error, applied, Some(detail))
            } else if states.contains(&RouteState::Missing) {
                status(
                    ConditionalRuleState::Error,
                    applied,
                    Some(format!(
                        "{} route(s) will be retried",
                        routes.len() - applied
                    )),
                )
            } else {
                status(ConditionalRuleState::Active, applied, note)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_protocol::{ConditionalRouteRule, ConditionalRuleState, RouteCondition};
    use crate::models::PolicyRoute;
    use crate::route_intents::{
        Derivation, IfaceAddr, NetworkView, RouteState, RouteTarget, Uplink,
    };

    fn addr(index: u32, name: &str, cidr: &str) -> IfaceAddr {
        IfaceAddr {
            if_index: index,
            interface: name.into(),
            address: cidr.parse().unwrap(),
        }
    }

    fn route(destination: &str, via: Option<&str>) -> PolicyRoute {
        PolicyRoute {
            destination: destination.parse().unwrap(),
            metric: 5,
            via: via.map(|v| v.parse().unwrap()),
        }
    }

    fn rule(prefix: &str, routes: Vec<PolicyRoute>) -> ConditionalRouteRule {
        ConditionalRouteRule {
            id: "office".into(),
            name: "Office LAN direct".into(),
            enabled: true,
            condition: RouteCondition::InterfaceAddressIn {
                prefix: prefix.parse().unwrap(),
            },
            routes,
        }
    }

    fn network(addresses: Vec<IfaceAddr>) -> NetworkView {
        NetworkView {
            uplink: Some(Uplink {
                interface: "en0".into(),
                gateway: Some("10.228.32.1".parse().unwrap()),
            }),
            interfaces: addresses.iter().map(|a| a.interface.clone()).collect(),
            addresses,
        }
    }

    // ---- matching --------------------------------------------------------

    #[test]
    fn a_global_address_inside_the_prefix_on_a_real_interface_matches() {
        let addrs = [
            addr(15, "en0", "10.228.33.7/21"),
            addr(13, "en7", "192.168.1.5/24"),
        ];
        let found = match_interface(&addrs, "10.228.32.0/21".parse().unwrap());
        assert_eq!(found.as_deref(), Some("en0"));
        assert_eq!(
            match_interface(&addrs, "172.16.0.0/12".parse().unwrap()),
            None
        );
    }

    #[test]
    fn the_lowest_interface_index_wins_so_the_choice_is_stable() {
        let addrs = [
            addr(20, "en9", "10.1.0.5/16"),
            addr(15, "en0", "10.1.0.9/16"),
        ];
        assert_eq!(
            match_interface(&addrs, "10.1.0.0/16".parse().unwrap()).as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn tunnels_and_plumbing_never_count_as_the_conditioned_network() {
        for name in [
            "utun5",
            "lo0",
            "gif0",
            "stf0",
            "ipsec0",
            "ppp0",
            "tun1",
            "awdl0",
            "llw0",
            "bridge100",
            "vmenet0",
        ] {
            let addrs = [addr(3, name, "10.1.0.5/16")];
            assert_eq!(
                match_interface(&addrs, "10.1.0.0/16".parse().unwrap()),
                None,
                "{name}"
            );
            assert!(non_uplink_name(name), "{name}");
        }
        for name in ["en0", "en7", "en12"] {
            assert!(!non_uplink_name(name), "{name}");
        }
    }

    #[test]
    fn link_local_loopback_and_multicast_addresses_never_satisfy_a_rule() {
        let any = "0.0.0.0/0".parse().unwrap();
        for cidr in ["169.254.10.2/16", "127.0.0.1/8", "224.0.0.9/4"] {
            assert_eq!(
                match_interface(&[addr(4, "en0", cidr)], any),
                None,
                "{cidr}"
            );
        }
        let any6 = "::/0".parse().unwrap();
        for cidr in ["fe80::1/64", "::1/128", "ff02::1/16"] {
            assert_eq!(
                match_interface(&[addr(4, "en0", cidr)], any6),
                None,
                "{cidr}"
            );
        }
        assert_eq!(
            match_interface(&[addr(4, "en0", "2001:db8::5/64")], any6).as_deref(),
            Some("en0")
        );
    }

    // ---- validation ------------------------------------------------------

    #[test]
    fn a_sensible_rule_is_accepted() {
        assert!(validate_rule(&rule("10.228.32.0/21", vec![route("10.99.0.0/24", None)])).is_ok());
        assert!(validate_rule(&rule(
            "10.228.32.0/21",
            vec![route("10.99.0.0/24", Some("10.228.32.1"))]
        ))
        .is_ok());
    }

    #[test]
    fn ids_and_names_are_bounded() {
        let ok = vec![route("10.99.0.0/24", None)];
        for good in ["a", "office-lan", "Office.LAN_2", &"a".repeat(48)] {
            let mut r = rule("10.0.0.0/8", ok.clone());
            r.id = good.into();
            assert!(validate_rule(&r).is_ok(), "{good}");
        }
        for bad in ["", "-x", ".x", "has space", "a/b", &"a".repeat(49), "ünï"] {
            let mut r = rule("10.0.0.0/8", ok.clone());
            r.id = bad.into();
            assert!(validate_rule(&r).is_err(), "{bad:?}");
        }
        let mut nameless = rule("10.0.0.0/8", ok.clone());
        nameless.name = String::new();
        assert!(validate_rule(&nameless).is_err());
        let mut control = rule("10.0.0.0/8", ok.clone());
        control.name = "bad\nname".into();
        assert!(validate_rule(&control).is_err());
        let mut long = rule("10.0.0.0/8", ok);
        long.name = "n".repeat(129);
        assert!(validate_rule(&long).is_err());
    }

    #[test]
    fn routes_must_be_present_few_unique_and_routable() {
        assert!(validate_rule(&rule("10.0.0.0/8", vec![])).is_err());
        let many: Vec<PolicyRoute> = (0..=MAX_RULE_ROUTES)
            .map(|n| route(&format!("10.{}.{}.0/24", n / 250, n % 250), None))
            .collect();
        assert!(validate_rule(&rule("10.0.0.0/8", many)).is_err());
        let dupes = vec![route("10.99.0.0/24", None), route("10.99.0.0/24", None)];
        assert!(validate_rule(&rule("10.0.0.0/8", dupes)).is_err());
        for bad in ["127.0.0.0/8", "224.0.0.0/4", "169.254.0.0/16", "0.0.0.0/32"] {
            assert!(
                validate_rule(&rule("10.0.0.0/8", vec![route(bad, None)])).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn host_bits_and_gateways_are_checked() {
        let host_bits = PolicyRoute {
            destination: "10.99.0.5/24".parse().unwrap(),
            metric: 5,
            via: None,
        };
        assert!(validate_rule(&rule("10.0.0.0/8", vec![host_bits])).is_err());
        assert!(validate_rule(&rule("10.228.32.5/21", vec![route("10.99.0.0/24", None)])).is_err());
        let wrong_family = route("10.99.0.0/24", Some("fd00::1"));
        assert!(validate_rule(&rule("10.0.0.0/8", vec![wrong_family])).is_err());
        for gw in ["0.0.0.0", "224.0.0.1"] {
            assert!(
                validate_rule(&rule("10.0.0.0/8", vec![route("10.99.0.0/24", Some(gw))])).is_err(),
                "{gw}"
            );
        }
    }

    // ---- derivation ------------------------------------------------------

    #[test]
    fn while_the_condition_holds_the_routes_go_out_the_matched_interface() {
        let r = rule(
            "10.228.32.0/21",
            vec![
                route("10.99.0.0/24", None),
                route("10.98.0.0/16", Some("10.228.32.9")),
            ],
        );
        let net = network(vec![addr(15, "en0", "10.228.33.7/21")]);
        let derived = derive_rule(&r, &net);
        let Derivation::Routes { routes, skipped } = derived else {
            panic!("expected routes")
        };
        assert!(skipped.is_empty());
        assert_eq!(routes[0].target, RouteTarget::Interface("en0".into()));
        assert_eq!(
            routes[1].target,
            RouteTarget::Gateway("10.228.32.9".parse().unwrap())
        );
        assert_eq!(condition_match(&r, &net).as_deref(), Some("en0"));
    }

    #[test]
    fn away_from_the_conditioned_network_nothing_is_wanted() {
        let r = rule("10.228.32.0/21", vec![route("10.99.0.0/24", None)]);
        let net = network(vec![addr(15, "en0", "192.168.1.5/24")]);
        let Derivation::Deferred(reason) = derive_rule(&r, &net) else {
            panic!("expected inactive")
        };
        assert!(reason.contains("10.228.32.0/21"), "{reason}");
        assert_eq!(condition_match(&r, &net), None);
    }

    #[test]
    fn a_disabled_rule_wants_nothing_even_where_it_would_hold() {
        let mut r = rule("10.228.32.0/21", vec![route("10.99.0.0/24", None)]);
        r.enabled = false;
        let net = network(vec![addr(15, "en0", "10.228.33.7/21")]);
        assert!(matches!(derive_rule(&r, &net), Derivation::Disabled));
    }

    #[test]
    fn a_destination_holding_the_uplink_gateway_is_not_pulled_off_the_uplink() {
        // Matched on en7 while the uplink is en0 with gateway 10.228.32.1.
        let r = rule(
            "172.20.0.0/16",
            vec![route("10.228.32.0/21", None), route("10.99.0.0/24", None)],
        );
        let net = network(vec![addr(13, "en7", "172.20.1.5/16")]);
        let Derivation::Routes { routes, skipped } = derive_rule(&r, &net) else {
            panic!()
        };
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination.to_string(), "10.99.0.0/24");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0.to_string(), "10.228.32.0/21");
        assert!(skipped[0].1.contains("uplink gateway"));
    }

    // ---- status ----------------------------------------------------------

    #[test]
    fn the_status_names_the_state_the_matched_interface_and_the_count() {
        let r = rule(
            "10.228.32.0/21",
            vec![route("10.99.0.0/24", None), route("10.98.0.0/16", None)],
        );
        let net = network(vec![addr(15, "en0", "10.228.33.7/21")]);
        let derived = derive_rule(&r, &net);
        let ok = rule_status(
            &r,
            &derived,
            &[RouteState::Present, RouteState::Present],
            Some("en0"),
        );
        assert_eq!(ok.state, ConditionalRuleState::Active);
        assert_eq!(
            (ok.matched_interface.as_deref(), ok.applied_routes),
            (Some("en0"), 2)
        );

        let failing = rule_status(
            &r,
            &derived,
            &[RouteState::Present, RouteState::Missing],
            Some("en0"),
        );
        assert_eq!(failing.state, ConditionalRuleState::Error);
        assert_eq!(failing.applied_routes, 1);
        assert!(failing.detail.as_deref().unwrap().contains("retried"));

        let clash = rule_status(
            &r,
            &derived,
            &[
                RouteState::Conflicted("another route to 10.99.0.0/24 via en7 is in place".into()),
                RouteState::Present,
            ],
            Some("en0"),
        );
        assert_eq!(clash.state, ConditionalRuleState::Error);
        assert!(clash.detail.as_deref().unwrap().contains("10.99.0.0/24"));

        let away = rule_status(&r, &Derivation::Deferred("x".into()), &[], None);
        assert_eq!(away.state, ConditionalRuleState::Inactive);
        assert_eq!((away.matched_interface, away.applied_routes), (None, 0));
        let off = rule_status(&r, &Derivation::Disabled, &[], None);
        assert_eq!(off.state, ConditionalRuleState::Disabled);
    }
}
