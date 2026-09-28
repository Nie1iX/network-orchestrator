//! Request validation. The daemon never trusts the client: every field that
//! reaches netlink is checked here first, before polkit is even asked.

use ipnet::IpNet;
use net_manager_core::daemon_protocol::{MAX_OWNER_BYTES, MAX_ROUTES_PER_REQUEST};
use net_manager_core::models::AppliedRoute;
use std::collections::HashSet;
use std::net::IpAddr;

/// Detect a full address-family union even when no single route is `/0`.
pub fn full_coverage(routes: impl IntoIterator<Item = IpNet>) -> (bool, bool) {
    let networks: Vec<_> = routes.into_iter().collect();
    let aggregated = IpNet::aggregate(&networks);
    (
        aggregated.iter().any(|net| net.to_string() == "0.0.0.0/0"),
        aggregated.iter().any(|net| net.to_string() == "::/0"),
    )
}

/// Linux interface names are limited to `IFNAMSIZ - 1` = 15 bytes. Beyond
/// that we accept only characters that can never be mistaken for a flag or a
/// shell metacharacter, even though nothing here ever touches a shell.
pub fn validate_iface_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!(
            "interface name must be 1-15 bytes, got {}",
            name.len()
        ));
    }
    if name.starts_with('-') {
        return Err("interface name must not start with '-'".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("interface name contains unsupported characters".into());
    }
    Ok(())
}

pub fn validate_owner(owner: &str) -> Result<(), String> {
    if owner.is_empty() || owner.len() > MAX_OWNER_BYTES {
        return Err(format!(
            "owner must be 1-{MAX_OWNER_BYTES} bytes, got {}",
            owner.len()
        ));
    }
    if owner.chars().any(char::is_control) {
        return Err("owner must not contain control characters".into());
    }
    Ok(())
}

pub fn validate_route(route: &AppliedRoute) -> Result<(), String> {
    let destination = route.destination;
    if destination.trunc() != destination {
        return Err(format!("destination {destination} has host bits set"));
    }
    if route.table.is_some() {
        return Err("routing table is chosen by the daemon, not the client".into());
    }
    if route.interface_index == 0 {
        return Err(format!("route {destination} has no interface index"));
    }
    if let Some(gateway) = route.gateway {
        let same_family = matches!(
            (destination, gateway),
            (IpNet::V4(_), IpAddr::V4(_)) | (IpNet::V6(_), IpAddr::V6(_))
        );
        if !same_family {
            return Err(format!(
                "gateway {gateway} is not in the address family of {destination}"
            ));
        }
        if gateway.is_unspecified() || gateway.is_multicast() {
            return Err(format!("gateway {gateway} must be a unicast address"));
        }
    }
    Ok(())
}

pub fn validate_apply(routes: &[AppliedRoute]) -> Result<(), String> {
    if routes.len() > MAX_ROUTES_PER_REQUEST {
        return Err(format!(
            "at most {MAX_ROUTES_PER_REQUEST} routes per request, got {}",
            routes.len()
        ));
    }
    let mut seen = HashSet::new();
    for route in routes {
        validate_route(route)?;
        if !seen.insert((route.destination, route.metric)) {
            return Err(format!(
                "duplicate route {} with metric {}",
                route.destination, route.metric
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::MAX_ROUTES_PER_REQUEST;
    use net_manager_core::models::AppliedRoute;

    fn route(dest: &str, metric: u32) -> AppliedRoute {
        AppliedRoute::on_link(dest.parse().unwrap(), 2, metric)
    }

    fn via(dest: &str, gateway: &str) -> AppliedRoute {
        AppliedRoute {
            gateway: Some(gateway.parse().unwrap()),
            ..route(dest, 5)
        }
    }

    #[test]
    fn full_coverage_detects_decomposed_ipv4_and_ipv6_unions() {
        let networks: Vec<IpNet> = [
            "0.0.0.0/2",
            "64.0.0.0/2",
            "128.0.0.0/2",
            "192.0.0.0/2",
            "::/2",
            "4000::/2",
            "8000::/2",
            "c000::/2",
        ]
        .into_iter()
        .map(|network| network.parse().unwrap())
        .collect();
        assert_eq!(full_coverage(networks.iter().copied()), (true, true));
        assert_eq!(full_coverage(networks[..3].iter().copied()), (false, false));
    }

    #[test]
    fn iface_name_accepts_typical_linux_names() {
        for name in ["wg0", "eth0", "veth-abc123", "br_lan", "tun.100"] {
            assert!(validate_iface_name(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn iface_name_rejects_empty_and_oversized() {
        assert!(validate_iface_name("").is_err());
        assert!(validate_iface_name("this-name-is-16c").is_err());
        assert!(validate_iface_name("exactly15chars.").is_ok());
    }

    #[test]
    fn iface_name_rejects_leading_dash_and_unsafe_characters() {
        assert!(
            validate_iface_name("-f").is_err(),
            "must not look like an ip flag"
        );
        assert!(validate_iface_name("wg0; rm -rf /").is_err());
        assert!(validate_iface_name("wg 0").is_err());
        assert!(validate_iface_name("wg0/24").is_err());
    }

    #[test]
    fn owner_accepts_profile_ids_up_to_128_bytes() {
        assert!(validate_owner("static-office").is_ok());
        assert!(validate_owner("профиль").is_ok());
        assert!(validate_owner(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn owner_rejects_empty_oversized_and_control_characters() {
        assert!(validate_owner("").is_err());
        assert!(validate_owner(&"a".repeat(129)).is_err());
        assert!(validate_owner("a\nb").is_err());
        assert!(validate_owner("a\u{7f}").is_err());
    }

    #[test]
    fn route_accepts_on_link_and_gateway_routes() {
        assert!(validate_route(&route("203.0.113.0/24", 5)).is_ok());
        assert!(validate_route(&route("2001:db8::/32", 5)).is_ok());
        assert!(validate_route(&via("203.0.113.0/24", "192.168.1.1")).is_ok());
        assert!(validate_route(&via("2001:db8::/32", "fe80::1")).is_ok());
    }

    #[test]
    fn route_rejects_host_bits() {
        assert!(validate_route(&route("203.0.113.7/24", 5)).is_err());
        assert!(validate_route(&route("2001:db8::1/32", 5)).is_err());
    }

    #[test]
    fn route_rejects_client_chosen_table() {
        let mut r = route("203.0.113.0/24", 5);
        r.table = Some(255);
        assert!(validate_route(&r).unwrap_err().contains("table"));
    }

    #[test]
    fn route_rejects_zero_interface_index() {
        let mut r = route("203.0.113.0/24", 5);
        r.interface_index = 0;
        assert!(validate_route(&r).is_err());
    }

    #[test]
    fn route_rejects_gateway_family_mismatch() {
        assert!(validate_route(&via("203.0.113.0/24", "fe80::1")).is_err());
        assert!(validate_route(&via("2001:db8::/32", "192.168.1.1")).is_err());
    }

    #[test]
    fn route_rejects_unspecified_and_multicast_gateway() {
        assert!(validate_route(&via("203.0.113.0/24", "0.0.0.0")).is_err());
        assert!(validate_route(&via("203.0.113.0/24", "224.0.0.1")).is_err());
        assert!(validate_route(&via("2001:db8::/32", "::")).is_err());
        assert!(validate_route(&via("2001:db8::/32", "ff02::1")).is_err());
    }

    #[test]
    fn apply_rejects_more_than_the_route_limit() {
        let routes: Vec<AppliedRoute> = (0..=MAX_ROUTES_PER_REQUEST as u32)
            .map(|metric| route("10.0.0.0/8", metric))
            .collect();
        assert!(validate_apply(&routes).is_err());
        assert!(validate_apply(&routes[..MAX_ROUTES_PER_REQUEST]).is_ok());
    }

    #[test]
    fn apply_rejects_duplicate_destination_and_metric() {
        let routes = vec![route("10.0.0.0/8", 1), route("10.0.0.0/8", 1)];
        assert!(validate_apply(&routes).unwrap_err().contains("duplicate"));
        let routes = vec![route("10.0.0.0/8", 1), route("10.0.0.0/8", 2)];
        assert!(validate_apply(&routes).is_ok());
    }

    #[test]
    fn apply_validates_every_route() {
        let routes = vec![route("10.0.0.0/8", 1), route("10.0.0.1/8", 2)];
        assert!(validate_apply(&routes).is_err());
    }
}
