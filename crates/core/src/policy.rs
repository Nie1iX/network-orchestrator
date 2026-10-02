use crate::models::{
    AppliedProfileRoutes, AppliedRoute, InterfaceCategory, NetworkInterface, PolicyRoute, Profile,
};
use ipnet::IpNet;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_NOT_FOUND, WIN32_ERROR};
#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT,
};

pub trait RouteExecutor: Send {
    fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()>;
    fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()>;
    /// Physical default gateways present in the main table, as
    /// `(gateway, output interface)`. Used to install host bypass routes for
    /// a tunnel's own upstream traffic (proxy server, captured DNS). An
    /// executor that cannot inspect the host table returns an empty list.
    fn default_gateways(&self) -> io::Result<Vec<(IpAddr, u32)>> {
        Ok(Vec::new())
    }
    /// Connected (gateway-less) subnets in the main table, as
    /// `(output interface, destination)`. A host covered by one on the
    /// uplink's interface is reachable directly: a bypass must then be a
    /// `dev` route — routing it `via` the default gateway hairpins the flow
    /// through a box that sees only the request direction (strict conntrack
    /// or firewalls drop the one-sided stream).
    fn on_link_networks(&self) -> io::Result<Vec<(u32, IpNet)>> {
        Ok(Vec::new())
    }
    /// Full kernel routing inventory: routes across every table plus all
    /// policy rules (`ip route`/`ip rule` equivalent). Executors that
    /// cannot inspect the privileged host view return `Unsupported`.
    fn net_tables(&self) -> io::Result<crate::daemon_protocol::NetTablesResult> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Add `routes` in order; on the first failure remove the ones already
/// added (in reverse). The error keeps the original kind and comes with the
/// routes whose rollback failed, i.e. those that may still be installed.
pub fn apply_routes_transactional(
    executor: &mut dyn RouteExecutor,
    routes: &[AppliedRoute],
) -> Result<(), (io::Error, Vec<AppliedRoute>)> {
    for (added, route) in routes.iter().enumerate() {
        if let Err(err) = executor.add_route(route) {
            let mut message = err.to_string();
            let mut still_applied = Vec::new();
            for rollback in routes[..added].iter().rev() {
                if let Err(rb_err) = executor.remove_route(rollback) {
                    message.push_str(&format!(
                        "; rollback failed for {}: {}",
                        rollback.destination, rb_err
                    ));
                    still_applied.push(rollback.clone());
                }
            }
            return Err((io::Error::new(err.kind(), message), still_applied));
        }
    }
    Ok(())
}

/// Remove `routes` in reverse order, continuing past failures. On error
/// returns the routes that could not be removed and a joined message.
pub fn remove_routes_best_effort(
    executor: &mut dyn RouteExecutor,
    routes: &[AppliedRoute],
) -> Result<(), (Vec<AppliedRoute>, String)> {
    let mut failed: Vec<AppliedRoute> = Vec::new();
    let mut messages: Vec<String> = Vec::new();
    for route in routes.iter().rev() {
        if let Err(err) = executor.remove_route(route) {
            messages.push(format!("{}: {}", route.destination, err));
            failed.push(route.clone());
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err((failed, messages.join("; ")))
    }
}

pub struct PolicyManager {
    executor: Box<dyn RouteExecutor>,
    applied: HashMap<String, Vec<AppliedRoute>>,
}

impl PolicyManager {
    pub fn new() -> Self {
        #[cfg(windows)]
        let executor: Box<dyn RouteExecutor> = Box::new(WindowsRouteExecutor);
        #[cfg(not(windows))]
        let executor: Box<dyn RouteExecutor> = Box::new(UnsupportedRouteExecutor);
        Self::with_executor(executor)
    }

    pub fn with_executor(executor: Box<dyn RouteExecutor>) -> Self {
        Self {
            executor,
            applied: HashMap::new(),
        }
    }

    pub fn apply_profile(
        &mut self,
        profile: &Profile,
        interfaces: &[NetworkInterface],
    ) -> io::Result<Vec<AppliedRoute>> {
        if self.applied.contains_key(&profile.id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("profile '{}' already has applied routes", profile.id),
            ));
        }
        let routes = plan_profile_routes(profile, interfaces)?;
        apply_routes_transactional(self.executor.as_mut(), &routes).map_err(|(err, _)| err)?;
        self.applied.insert(profile.id.clone(), routes.clone());
        Ok(routes)
    }

    pub fn remove_profile(&mut self, profile_id: &str) -> io::Result<()> {
        let Some(routes) = self.applied.remove(profile_id) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("profile '{profile_id}' has no applied routes"),
            ));
        };
        match remove_routes_best_effort(self.executor.as_mut(), &routes) {
            Ok(()) => Ok(()),
            Err((failed, message)) => {
                self.applied.insert(profile_id.to_string(), failed);
                Err(io::Error::other(message))
            }
        }
    }

    pub fn applied_for(&self, profile_id: &str) -> &[AppliedRoute] {
        self.applied
            .get(profile_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn snapshot(&self) -> Vec<AppliedProfileRoutes> {
        let mut profiles: Vec<AppliedProfileRoutes> = self
            .applied
            .iter()
            .map(|(profile_id, routes)| AppliedProfileRoutes {
                profile_id: profile_id.clone(),
                routes: routes.clone(),
            })
            .collect();
        profiles.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
        profiles
    }

    pub fn restore(&mut self, profiles: Vec<AppliedProfileRoutes>) -> io::Result<()> {
        let mut applied = HashMap::new();
        for entry in profiles {
            if entry.profile_id.trim().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "applied route entry has a blank profile id",
                ));
            }
            if applied
                .insert(entry.profile_id.clone(), entry.routes)
                .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "duplicate applied route entry for profile '{}'",
                        entry.profile_id
                    ),
                ));
            }
        }
        self.applied = applied;
        Ok(())
    }

    pub fn has_applied_profile(&self, profile_id: &str) -> bool {
        self.applied.contains_key(profile_id)
    }

    pub fn applied_profile_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.applied.keys().cloned().collect();
        ids.sort();
        ids
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Metric for endpoint bypass host routes. Matches NetworkManager's own
/// VPN-server route convention so the entries coexist instead of fighting.
pub const ENDPOINT_BYPASS_METRIC: u32 = 50;

/// Full routing plan for a profile: routes installable now plus intents that
/// cannot be expressed yet — declared routes awaiting their target interface
/// and bypass entries still needing resolution or an uplink gateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// Installable routes bound to the resolved profile interface.
    pub routes: Vec<AppliedRoute>,
    /// Declared policy routes deferred because the target interface is
    /// absent (armed `wait_for_interface` profiles only).
    pub deferred: Vec<PolicyRoute>,
    /// Host routes pinning `endpoint_bypasses` to the physical uplink.
    pub bypasses: Vec<AppliedRoute>,
    /// `endpoint_bypasses` entries not yet expressible as routes: DNS names
    /// awaiting resolution, or literals without a same-family uplink gateway.
    pub pending_bypasses: Vec<String>,
}

pub fn plan_profile(profile: &Profile, interfaces: &[NetworkInterface]) -> io::Result<RoutePlan> {
    // The profile interface is only needed to bind declared routes; a
    // bypass-only profile never touches it.
    let (routes, deferred) = if profile.routes.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        match resolve_interface(profile, interfaces) {
            Ok(interface) => (plan_routes_on(profile, interface), Vec::new()),
            Err(err)
                if profile.wait_for_interface
                    && !profile.interface_name.is_empty()
                    && err.kind() == io::ErrorKind::NotFound =>
            {
                (Vec::new(), profile.routes.clone())
            }
            Err(err) => return Err(err),
        }
    };
    let mut plan = RoutePlan {
        routes,
        deferred,
        bypasses: Vec::new(),
        pending_bypasses: Vec::new(),
    };
    plan_endpoint_bypasses(profile, interfaces, &mut plan);
    Ok(plan)
}

pub fn plan_profile_routes(
    profile: &Profile,
    interfaces: &[NetworkInterface],
) -> io::Result<Vec<AppliedRoute>> {
    Ok(plan_profile(profile, interfaces)?.routes)
}

fn plan_routes_on(profile: &Profile, interface: &NetworkInterface) -> Vec<AppliedRoute> {
    profile
        .routes
        .iter()
        .map(|route| {
            let destination = route.destination.trunc();
            AppliedRoute {
                destination,
                interface_index: interface.if_index,
                metric: route.metric,
                gateway: route
                    .via
                    .or_else(|| interface_gateway_for(interface, &destination)),
                table: None,
            }
        })
        .collect()
}

/// Host routes pinning `endpoint_bypasses` to the physical uplink. Literal
/// IPs become routes immediately; DNS names and literals without a
/// same-family uplink gateway stay pending for the caller.
fn plan_endpoint_bypasses(
    profile: &Profile,
    interfaces: &[NetworkInterface],
    plan: &mut RoutePlan,
) {
    let mut seen_routes = std::collections::HashSet::new();
    let mut seen_pending = std::collections::HashSet::new();
    for entry in &profile.endpoint_bypasses {
        let route = entry
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| uplink_route(ip, interfaces));
        match route {
            Some(route) if seen_routes.insert(route.destination) => plan.bypasses.push(route),
            Some(_) => {}
            None if seen_pending.insert(entry.clone()) => plan.pending_bypasses.push(entry.clone()),
            None => {}
        }
    }
}

/// A bypass host route goes through the physical interface carrying that
/// family's uplink gateway — tunnels are never a valid bypass next hop.
/// With several physical uplinks the lowest if_index wins (deterministic);
/// the daemon retargets on uplink changes anyway.
fn uplink_route(host: IpAddr, interfaces: &[NetworkInterface]) -> Option<AppliedRoute> {
    interfaces
        .iter()
        .filter(|i| i.category == InterfaceCategory::Physical)
        .filter_map(|i| {
            let gateway = if host.is_ipv4() {
                i.gateway
            } else {
                i.ipv6_gateway
            };
            gateway
                .filter(|g| g.is_ipv4() == host.is_ipv4())
                .map(|g| (i, g))
        })
        .min_by_key(|(i, _)| i.if_index)
        .map(|(i, gateway)| AppliedRoute {
            destination: host.into(),
            interface_index: i.if_index,
            metric: ENDPOINT_BYPASS_METRIC,
            gateway: Some(gateway),
            table: None,
        })
}

/// The interface's default gateway is a valid next hop only on a physical
/// uplink and for the same address family; VPN/tunnel routes stay on-link.
fn interface_gateway_for(interface: &NetworkInterface, destination: &IpNet) -> Option<IpAddr> {
    if interface.category != InterfaceCategory::Physical {
        return None;
    }
    interface
        .gateway
        .filter(|gateway| gateway.is_ipv4() == destination.addr().is_ipv4())
}

fn resolve_interface<'a>(
    profile: &Profile,
    interfaces: &'a [NetworkInterface],
) -> io::Result<&'a NetworkInterface> {
    let friendly: Vec<&NetworkInterface> = interfaces
        .iter()
        .filter(|iface| iface.friendly_name == profile.interface_name)
        .collect();
    if friendly.len() == 1 {
        return Ok(friendly[0]);
    }
    if friendly.len() > 1 {
        return Err(ambiguous_interface(&profile.interface_name));
    }
    let named: Vec<&NetworkInterface> = interfaces
        .iter()
        .filter(|iface| iface.name == profile.interface_name)
        .collect();
    match named.len() {
        1 => Ok(named[0]),
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface '{}' not found", profile.interface_name),
        )),
        _ => Err(ambiguous_interface(&profile.interface_name)),
    }
}

fn ambiguous_interface(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("interface name '{name}' matches multiple interfaces"),
    )
}

#[cfg(windows)]
fn populate_forward_row(row: &mut MIB_IPFORWARD_ROW2, route: &AppliedRoute) {
    row.InterfaceIndex = route.interface_index;
    row.DestinationPrefix.PrefixLength = route.destination.prefix_len();
    row.Metric = route.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    match route.destination.network() {
        IpAddr::V4(v4) => {
            row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            row.DestinationPrefix.Prefix.Ipv4.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(v4.octets()),
                },
            };
            row.NextHop.Ipv4.sin_family = AF_INET;
            if let Some(IpAddr::V4(gateway)) = route.gateway {
                row.NextHop.Ipv4.sin_addr = IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(gateway.octets()),
                    },
                };
            }
        }
        IpAddr::V6(v6) => {
            row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            row.DestinationPrefix.Prefix.Ipv6.sin6_addr = IN6_ADDR {
                u: IN6_ADDR_0 { Byte: v6.octets() },
            };
            row.NextHop.Ipv6.sin6_family = AF_INET6;
            if let Some(IpAddr::V6(gateway)) = route.gateway {
                row.NextHop.Ipv6.sin6_addr = IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: gateway.octets(),
                    },
                };
            }
        }
    }
}

#[cfg(windows)]
fn win32_result(error: WIN32_ERROR) -> io::Result<()> {
    if error.0 == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(error.0 as i32))
    }
}

#[cfg(windows)]
fn win32_remove_result(error: WIN32_ERROR) -> io::Result<()> {
    if error == ERROR_NOT_FOUND {
        Ok(())
    } else {
        win32_result(error)
    }
}

#[cfg(windows)]
pub struct WindowsRouteExecutor;

#[cfg(windows)]
impl RouteExecutor for WindowsRouteExecutor {
    fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        unsafe {
            let mut row = MIB_IPFORWARD_ROW2::default();
            InitializeIpForwardEntry(&mut row);
            populate_forward_row(&mut row, route);
            win32_result(CreateIpForwardEntry2(&row))
        }
    }

    fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        unsafe {
            let mut row = MIB_IPFORWARD_ROW2::default();
            InitializeIpForwardEntry(&mut row);
            populate_forward_row(&mut row, route);
            win32_remove_result(DeleteIpForwardEntry2(&row))
        }
    }
}

#[cfg(not(windows))]
struct UnsupportedRouteExecutor;

#[cfg(not(windows))]
impl RouteExecutor for UnsupportedRouteExecutor {
    fn add_route(&mut self, _route: &AppliedRoute) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "policy routes are only supported on Windows and Linux",
        ))
    }

    fn remove_route(&mut self, _route: &AppliedRoute) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "policy routes are only supported on Windows and Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{InterfaceKind, InterfaceState, PolicyRoute, TunnelBackend};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    fn iface(name: &str, friendly_name: &str, if_index: u32) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            friendly_name: friendly_name.into(),
            kind: InterfaceKind::Other("test".into()),
            state: InterfaceState::Up,
            addresses: vec![],
            dns_servers: vec![],
            dns_suffix: None,
            mtu: None,
            if_index,
            physical: true,
            mac: None,
            gateway: None,
            ipv6_gateway: None,
            rx_bytes: None,
            tx_bytes: None,
            link_speed_mbps: None,
            category: InterfaceCategory::Physical,
            description: String::new(),
            if_type: 6,
            tunnel_type: None,
        }
    }

    fn profile(routes: Vec<PolicyRoute>) -> Profile {
        Profile {
            id: "p1".into(),
            name: "P1".into(),
            backend: TunnelBackend::WireGuard,
            config_path: PathBuf::from(r"C:\configs\p1.conf"),
            interface_name: "wg-work".into(),
            routes,
            ..Default::default()
        }
    }

    fn route(dest: &str, metric: u32) -> PolicyRoute {
        PolicyRoute {
            destination: dest.parse().unwrap(),
            metric,
            via: None,
        }
    }

    #[derive(Default)]
    struct FakeExecutor {
        calls: Arc<Mutex<Vec<String>>>,
        fail_add_nth: usize,
        add_count: usize,
        fail_remove_dests: Vec<String>,
    }

    impl FakeExecutor {
        fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    calls: Arc::clone(&calls),
                    fail_add_nth: usize::MAX,
                    add_count: 0,
                    fail_remove_dests: Vec::new(),
                },
                calls,
            )
        }
    }

    impl RouteExecutor for FakeExecutor {
        fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("add {}", route.destination));
            self.add_count += 1;
            if self.add_count == self.fail_add_nth {
                return Err(io::Error::other("injected add failure"));
            }
            Ok(())
        }

        fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("remove {}", route.destination));
            if self
                .fail_remove_dests
                .iter()
                .any(|d| *d == route.destination.to_string())
            {
                return Err(io::Error::other("injected remove failure"));
            }
            Ok(())
        }
    }

    fn manager(executor: FakeExecutor) -> PolicyManager {
        PolicyManager::with_executor(Box::new(executor))
    }

    #[test]
    fn planner_prefers_exact_friendly_name_and_copies_if_index() {
        let interfaces = vec![
            iface("Ethernet0", "wg-work", 7),
            iface("wg-work", "other", 9),
        ];
        let p = profile(vec![route("10.7.0.0/24", 5)]);
        let planned = plan_profile_routes(&p, &interfaces).unwrap();
        assert_eq!(
            planned,
            vec![AppliedRoute {
                destination: "10.7.0.0/24".parse().unwrap(),
                interface_index: 7,
                metric: 5,
                gateway: None,
                table: None,
            }]
        );
    }

    fn iface_with_gateway(
        category: InterfaceCategory,
        gateway: Option<IpAddr>,
    ) -> NetworkInterface {
        let mut interface = iface("x", "wg-work", 7);
        interface.category = category;
        interface.gateway = gateway;
        interface
    }

    #[test]
    fn planner_copies_explicit_via_to_gateway() {
        let interfaces = vec![iface_with_gateway(
            InterfaceCategory::Vpn,
            Some("10.0.0.1".parse().unwrap()),
        )];
        let mut r = route("10.7.0.0/24", 5);
        r.via = Some("10.7.0.254".parse().unwrap());
        let planned = plan_profile_routes(&profile(vec![r]), &interfaces).unwrap();
        assert_eq!(planned[0].gateway, Some("10.7.0.254".parse().unwrap()));
        assert_eq!(planned[0].table, None);
    }

    #[test]
    fn planner_uses_interface_gateway_for_physical_only() {
        let gateway = Some("192.168.1.1".parse().unwrap());
        let p = profile(vec![route("10.7.0.0/24", 5)]);

        let physical = vec![iface_with_gateway(InterfaceCategory::Physical, gateway)];
        let planned = plan_profile_routes(&p, &physical).unwrap();
        assert_eq!(planned[0].gateway, gateway);
        assert_eq!(planned[0].table, None);

        for category in [
            InterfaceCategory::Virtual,
            InterfaceCategory::System,
            InterfaceCategory::Tunnel,
            InterfaceCategory::Filter,
        ] {
            let interfaces = vec![iface_with_gateway(category, gateway)];
            let planned = plan_profile_routes(&p, &interfaces).unwrap();
            assert_eq!(planned[0].gateway, None, "{category:?}");
        }
    }

    #[test]
    fn planner_skips_default_gateway_for_vpn_interface() {
        let interfaces = vec![iface_with_gateway(
            InterfaceCategory::Vpn,
            Some("10.0.0.1".parse().unwrap()),
        )];
        let p = profile(vec![route("10.7.0.0/24", 5)]);
        let planned = plan_profile_routes(&p, &interfaces).unwrap();
        assert_eq!(planned[0].gateway, None);
    }

    #[test]
    fn planner_skips_gateway_on_family_mismatch() {
        let v4_gateway = vec![iface_with_gateway(
            InterfaceCategory::Physical,
            Some("192.168.1.1".parse().unwrap()),
        )];
        let v6_route = profile(vec![route("2001:db8::/32", 5)]);
        let planned = plan_profile_routes(&v6_route, &v4_gateway).unwrap();
        assert_eq!(planned[0].gateway, None);

        let v6_gateway = vec![iface_with_gateway(
            InterfaceCategory::Physical,
            Some("fe80::1".parse().unwrap()),
        )];
        let v4_route = profile(vec![route("10.7.0.0/24", 5)]);
        let planned = plan_profile_routes(&v4_route, &v6_gateway).unwrap();
        assert_eq!(planned[0].gateway, None);
    }

    #[test]
    fn planner_truncates_host_bits() {
        let interfaces = vec![iface("x", "wg-work", 7)];
        let p = profile(vec![route("10.7.0.99/24", 5), route("fd00::1/64", 5)]);
        let planned = plan_profile_routes(&p, &interfaces).unwrap();
        assert_eq!(planned[0].destination.to_string(), "10.7.0.0/24");
        assert_eq!(planned[1].destination.to_string(), "fd00::/64");
    }

    #[test]
    fn planner_falls_back_to_exact_raw_name() {
        let interfaces = vec![
            iface("Ethernet0", "LAN", 3),
            iface("wg-work", "WireGuard Tunnel", 11),
        ];
        let p = profile(vec![route("10.7.0.0/24", 5)]);
        let planned = plan_profile_routes(&p, &interfaces).unwrap();
        assert_eq!(planned[0].interface_index, 11);
    }

    #[test]
    fn planner_rejects_missing_interface() {
        let interfaces = vec![iface("Ethernet0", "LAN", 3)];
        let p = profile(vec![route("10.7.0.0/24", 5)]);
        let err = plan_profile_routes(&p, &interfaces).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn armed_profile_defers_routes_when_interface_is_missing() {
        let interfaces = vec![iface("enp59s0u2", "Ethernet", 3)];
        let mut p = profile(vec![route("10.0.0.0/8", 50)]);
        p.interface_name = "tun0".into();
        p.wait_for_interface = true;
        let plan = plan_profile(&p, &interfaces).unwrap();
        assert!(plan.routes.is_empty());
        assert_eq!(plan.deferred, p.routes);
        // Strict planning stays strict: the same profile without the flag
        // still fails on the absent interface.
        p.wait_for_interface = false;
        assert_eq!(
            plan_profile(&p, &interfaces).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn armed_profile_keeps_deferred_empty_when_interface_exists() {
        let interfaces = vec![iface("tun0", "tun0", 9)];
        let mut p = profile(vec![route("10.0.0.0/8", 50)]);
        p.interface_name = "tun0".into();
        p.wait_for_interface = true;
        let plan = plan_profile(&p, &interfaces).unwrap();
        assert_eq!(plan.routes.len(), 1);
        assert!(plan.deferred.is_empty());
    }

    fn uplink(name: &str, if_index: u32, gateway: &str) -> NetworkInterface {
        let mut i = iface(name, name, if_index);
        i.category = InterfaceCategory::Physical;
        i.gateway = Some(gateway.parse().unwrap());
        i
    }

    #[test]
    fn endpoint_bypass_literal_routes_via_uplink_gateway() {
        let interfaces = vec![
            uplink("enp59s0u2", 3, "192.168.1.1"),
            iface("happ-xray", "happ-xray", 8),
        ];
        let mut p = profile(vec![]);
        p.endpoint_bypasses = vec!["91.245.41.31".into()];
        let plan = plan_profile(&p, &interfaces).unwrap();
        assert_eq!(
            plan.bypasses,
            vec![AppliedRoute {
                destination: "91.245.41.31/32".parse().unwrap(),
                interface_index: 3,
                metric: ENDPOINT_BYPASS_METRIC,
                gateway: Some("192.168.1.1".parse().unwrap()),
                table: None,
            }]
        );
        assert!(plan.pending_bypasses.is_empty());
    }

    #[test]
    fn endpoint_bypass_hostname_stays_pending_for_resolution() {
        let interfaces = vec![uplink("enp59s0u2", 3, "192.168.1.1")];
        let mut p = profile(vec![]);
        p.endpoint_bypasses = vec!["vpn.example.com".into()];
        let plan = plan_profile(&p, &interfaces).unwrap();
        assert!(plan.bypasses.is_empty());
        assert_eq!(plan.pending_bypasses, vec!["vpn.example.com".to_string()]);
    }

    #[test]
    fn endpoint_bypass_without_matching_uplink_stays_pending() {
        // Tunnel interfaces are never a bypass next hop, and a v4 host needs
        // a v4 uplink gateway.
        let mut tunnel_uplink = iface("happ-xray", "happ-xray", 8);
        tunnel_uplink.category = InterfaceCategory::Vpn;
        tunnel_uplink.gateway = Some("172.19.0.1".parse().unwrap());
        let interfaces = vec![tunnel_uplink];
        let mut p = profile(vec![]);
        p.endpoint_bypasses = vec!["91.245.41.31".into()];
        let plan = plan_profile(&p, &interfaces).unwrap();
        assert!(plan.bypasses.is_empty());
        assert_eq!(plan.pending_bypasses, vec!["91.245.41.31".to_string()]);
    }

    #[test]
    fn endpoint_bypass_dedupes_and_pairs_ipv6_with_v6_gateway() {
        let interfaces = vec![{
            let mut i = uplink("enp59s0u2", 3, "192.168.1.1");
            i.ipv6_gateway = Some("fe80::1".parse().unwrap());
            i
        }];
        let mut p = profile(vec![]);
        p.endpoint_bypasses = vec![
            "91.245.41.31".into(),
            "91.245.41.31".into(),
            "2001:db8::7".into(),
        ];
        let plan = plan_profile(&p, &interfaces).unwrap();
        assert_eq!(plan.bypasses.len(), 2);
        assert_eq!(
            plan.bypasses[1].destination,
            "2001:db8::7/128".parse().unwrap()
        );
        assert_eq!(plan.bypasses[1].gateway, Some("fe80::1".parse().unwrap()));
    }

    #[test]
    fn plan_profile_routes_keeps_strict_compatible_behavior() {
        // The legacy wrapper returns only installable routes: bypasses go to
        // the uplink, not the profile interface, so they are not part of it.
        let interfaces = vec![
            uplink("enp59s0u2", 3, "192.168.1.1"),
            iface("wg-work", "wg-work", 7),
        ];
        let mut p = profile(vec![route("10.7.0.0/24", 5)]);
        p.endpoint_bypasses = vec!["91.245.41.31".into()];
        let routes = plan_profile_routes(&p, &interfaces).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].interface_index, 7);
    }

    #[test]
    fn empty_routes_plan_empty() {
        let interfaces = vec![iface("x", "wg-work", 7)];
        let p = profile(vec![]);
        assert!(plan_profile_routes(&p, &interfaces).unwrap().is_empty());
    }

    #[test]
    fn apply_records_adds_in_order_and_exposes_applied() {
        let (executor, calls) = FakeExecutor::new();
        let mut mgr = manager(executor);
        let interfaces = vec![iface("x", "wg-work", 7)];
        let p = profile(vec![route("10.7.0.0/24", 5), route("10.8.0.0/24", 6)]);

        let applied = mgr.apply_profile(&p, &interfaces).unwrap();

        assert_eq!(applied.len(), 2);
        assert_eq!(applied, mgr.applied_for("p1"));
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["add 10.7.0.0/24", "add 10.8.0.0/24"]
        );
    }

    #[test]
    fn second_add_failure_rolls_back_first_in_reverse() {
        let (mut executor, calls) = FakeExecutor::new();
        executor.fail_add_nth = 2;
        let mut mgr = manager(executor);
        let interfaces = vec![iface("x", "wg-work", 7)];
        let p = profile(vec![route("10.7.0.0/24", 5), route("10.8.0.0/24", 6)]);

        let err = mgr.apply_profile(&p, &interfaces).unwrap_err();

        assert_eq!(err.to_string(), "injected add failure");
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["add 10.7.0.0/24", "add 10.8.0.0/24", "remove 10.7.0.0/24"]
        );
        assert!(mgr.applied_for("p1").is_empty());
    }

    #[test]
    fn repeated_apply_including_empty_routes_returns_already_exists() {
        let (executor, _calls) = FakeExecutor::new();
        let mut mgr = manager(executor);
        let interfaces = vec![iface("x", "wg-work", 7)];
        let p = profile(vec![route("10.7.0.0/24", 5)]);
        mgr.apply_profile(&p, &interfaces).unwrap();
        let err = mgr.apply_profile(&p, &interfaces).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        let (executor2, _) = FakeExecutor::new();
        let mut mgr2 = manager(executor2);
        let empty = profile(vec![]);
        mgr2.apply_profile(&empty, &interfaces).unwrap();
        let err = mgr2.apply_profile(&empty, &interfaces).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn remove_executes_reverse_order_and_clears_state() {
        let (executor, calls) = FakeExecutor::new();
        let mut mgr = manager(executor);
        let interfaces = vec![iface("x", "wg-work", 7)];
        let p = profile(vec![route("10.7.0.0/24", 5), route("10.8.0.0/24", 6)]);
        mgr.apply_profile(&p, &interfaces).unwrap();
        calls.lock().unwrap().clear();

        mgr.remove_profile("p1").unwrap();

        assert_eq!(
            *calls.lock().unwrap(),
            vec!["remove 10.8.0.0/24", "remove 10.7.0.0/24"]
        );
        assert!(mgr.applied_for("p1").is_empty());
        let err = mgr.remove_profile("p1").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn partial_remove_attempts_all_and_retains_only_failures() {
        let (mut executor, calls) = FakeExecutor::new();
        executor.fail_remove_dests = vec!["10.7.0.0/24".to_string()];
        let mut mgr = manager(executor);
        let interfaces = vec![iface("x", "wg-work", 7)];
        let p = profile(vec![route("10.7.0.0/24", 5), route("10.8.0.0/24", 6)]);
        mgr.apply_profile(&p, &interfaces).unwrap();
        calls.lock().unwrap().clear();

        let err = mgr.remove_profile("p1").unwrap_err();

        assert_eq!(
            *calls.lock().unwrap(),
            vec!["remove 10.8.0.0/24", "remove 10.7.0.0/24"]
        );
        let retained = mgr.applied_for("p1");
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].destination, "10.7.0.0/24".parse().unwrap());
        drop(err);
    }

    #[cfg(windows)]
    #[test]
    fn forward_row_ipv4_fields() {
        let applied = AppliedRoute {
            destination: "10.7.0.99/24".parse().unwrap(),
            interface_index: 42,
            metric: 5,
            gateway: None,
            table: None,
        };
        let mut row = unsafe { std::mem::zeroed::<MIB_IPFORWARD_ROW2>() };
        populate_forward_row(&mut row, &applied);
        assert_eq!(row.InterfaceIndex, 42);
        assert_eq!(row.Metric, 5);
        assert_eq!(row.DestinationPrefix.PrefixLength, 24);
        unsafe {
            assert_eq!(row.DestinationPrefix.Prefix.Ipv4.sin_family, AF_INET);
            assert_eq!(
                row.DestinationPrefix
                    .Prefix
                    .Ipv4
                    .sin_addr
                    .S_un
                    .S_addr
                    .to_ne_bytes(),
                [10, 7, 0, 0]
            );
            assert_eq!(row.NextHop.Ipv4.sin_family, AF_INET);
            assert_eq!(row.NextHop.Ipv4.sin_addr.S_un.S_addr, 0);
        }
        assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
    }

    #[cfg(windows)]
    #[test]
    fn forward_row_ipv4_next_hop_from_gateway() {
        let applied = AppliedRoute {
            destination: "10.7.0.0/24".parse().unwrap(),
            interface_index: 42,
            metric: 5,
            gateway: Some("192.168.1.1".parse().unwrap()),
            table: None,
        };
        let mut row = unsafe { std::mem::zeroed::<MIB_IPFORWARD_ROW2>() };
        populate_forward_row(&mut row, &applied);
        unsafe {
            assert_eq!(row.NextHop.Ipv4.sin_family, AF_INET);
            assert_eq!(
                row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                [192, 168, 1, 1]
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn forward_row_ipv6_fields() {
        let applied = AppliedRoute {
            destination: "fd00::1/64".parse().unwrap(),
            interface_index: 13,
            metric: 7,
            gateway: None,
            table: None,
        };
        let mut row = unsafe { std::mem::zeroed::<MIB_IPFORWARD_ROW2>() };
        populate_forward_row(&mut row, &applied);
        assert_eq!(row.InterfaceIndex, 13);
        assert_eq!(row.Metric, 7);
        assert_eq!(row.DestinationPrefix.PrefixLength, 64);
        let fd00_network: IpAddr = "fd00::".parse().unwrap();
        let IpAddr::V6(expected) = fd00_network else {
            panic!("expected v6")
        };
        unsafe {
            assert_eq!(row.DestinationPrefix.Prefix.Ipv6.sin6_family, AF_INET6);
            assert_eq!(
                row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
                expected.octets()
            );
            assert_eq!(row.NextHop.Ipv6.sin6_family, AF_INET6);
            assert_eq!(row.NextHop.Ipv6.sin6_addr.u.Byte, [0u8; 16]);
        }
        assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
    }

    #[test]
    fn snapshot_sorts_by_profile_id_and_retains_route_order() {
        let (executor, _calls) = FakeExecutor::new();
        let mut mgr = manager(executor);
        let interfaces = vec![iface("Ethernet0", "wg-work", 7)];
        mgr.apply_profile(
            &{
                let mut p = profile(vec![route("10.7.0.0/24", 5), route("10.8.0.0/24", 5)]);
                p.id = "z-last".into();
                p
            },
            &interfaces,
        )
        .unwrap();
        mgr.apply_profile(
            &{
                let mut p = profile(vec![route("10.9.0.0/24", 5)]);
                p.id = "a-first".into();
                p
            },
            &interfaces,
        )
        .unwrap();

        let snap = mgr.snapshot();
        assert_eq!(
            snap.iter()
                .map(|p| p.profile_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a-first", "z-last"]
        );
        assert_eq!(
            snap[1]
                .routes
                .iter()
                .map(|r| r.destination.to_string())
                .collect::<Vec<_>>(),
            vec!["10.7.0.0/24", "10.8.0.0/24"]
        );
    }

    #[test]
    fn restore_roundtrips_and_distinguishes_tracked_empty() {
        let (executor, _calls) = FakeExecutor::new();
        let mut mgr = manager(executor);
        let snapshot = vec![
            AppliedProfileRoutes {
                profile_id: "empty-owner".into(),
                routes: vec![],
            },
            AppliedProfileRoutes {
                profile_id: "with-routes".into(),
                routes: vec![AppliedRoute {
                    destination: "10.1.0.0/24".parse().unwrap(),
                    interface_index: 3,
                    metric: 9,
                    gateway: None,
                    table: None,
                }],
            },
        ];
        mgr.restore(snapshot.clone()).unwrap();
        assert_eq!(mgr.snapshot(), snapshot);
        assert!(mgr.has_applied_profile("empty-owner"));
        assert!(mgr.has_applied_profile("with-routes"));
        assert!(!mgr.has_applied_profile("absent"));
    }

    #[test]
    fn restore_rejects_blank_and_duplicate_ids() {
        let (executor, _calls) = FakeExecutor::new();
        let mut mgr = manager(executor);
        let blank = vec![AppliedProfileRoutes {
            profile_id: "  ".into(),
            routes: vec![],
        }];
        assert_eq!(
            mgr.restore(blank).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let dup = vec![
            AppliedProfileRoutes {
                profile_id: "x".into(),
                routes: vec![],
            },
            AppliedProfileRoutes {
                profile_id: "x".into(),
                routes: vec![],
            },
        ];
        assert_eq!(
            mgr.restore(dup).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!mgr.has_applied_profile("x"));
    }

    #[test]
    fn applied_profile_ids_sorted_including_empty() {
        let (executor, _calls) = FakeExecutor::new();
        let mut mgr = manager(executor);
        mgr.restore(vec![
            AppliedProfileRoutes {
                profile_id: "z".into(),
                routes: vec![],
            },
            AppliedProfileRoutes {
                profile_id: "a".into(),
                routes: vec![AppliedRoute {
                    destination: "10.1.0.0/24".parse().unwrap(),
                    interface_index: 3,
                    metric: 9,
                    gateway: None,
                    table: None,
                }],
            },
        ])
        .unwrap();
        assert_eq!(mgr.applied_profile_ids(), vec!["a", "z"]);
    }

    #[cfg(windows)]
    #[test]
    fn remove_result_tolerates_not_found() {
        assert!(win32_remove_result(WIN32_ERROR(0)).is_ok());
        assert!(win32_remove_result(ERROR_NOT_FOUND).is_ok());
        let err = win32_remove_result(WIN32_ERROR(5)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(5));
    }
}
