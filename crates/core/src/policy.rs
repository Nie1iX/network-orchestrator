use crate::models::{AppliedProfileRoutes, AppliedRoute, NetworkInterface, Profile};
use std::collections::HashMap;
use std::io;

#[cfg(windows)]
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
        let mut added: Vec<AppliedRoute> = Vec::with_capacity(routes.len());
        for route in &routes {
            if let Err(err) = self.executor.add_route(route) {
                let mut message = err.to_string();
                for rollback in added.iter().rev() {
                    if let Err(rb_err) = self.executor.remove_route(rollback) {
                        message.push_str(&format!(
                            "; rollback failed for {}: {}",
                            rollback.destination, rb_err
                        ));
                    }
                }
                return Err(io::Error::new(err.kind(), message));
            }
            added.push(route.clone());
        }
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
        let mut failed: Vec<AppliedRoute> = Vec::new();
        let mut messages: Vec<String> = Vec::new();
        for route in routes.iter().rev() {
            if let Err(err) = self.executor.remove_route(route) {
                messages.push(format!("{}: {}", route.destination, err));
                failed.push(route.clone());
            }
        }
        if failed.is_empty() {
            return Ok(());
        }
        self.applied.insert(profile_id.to_string(), failed);
        Err(io::Error::other(messages.join("; ")))
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

pub fn plan_profile_routes(
    profile: &Profile,
    interfaces: &[NetworkInterface],
) -> io::Result<Vec<AppliedRoute>> {
    let interface = resolve_interface(profile, interfaces)?;
    Ok(profile
        .routes
        .iter()
        .map(|route| AppliedRoute {
            destination: route.destination,
            interface_index: interface.if_index,
            metric: route.metric,
        })
        .collect())
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
        }
        IpAddr::V6(v6) => {
            row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            row.DestinationPrefix.Prefix.Ipv6.sin6_addr = IN6_ADDR {
                u: IN6_ADDR_0 { Byte: v6.octets() },
            };
            row.NextHop.Ipv6.sin6_family = AF_INET6;
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
            "policy routes are only supported on Windows",
        ))
    }

    fn remove_route(&mut self, _route: &AppliedRoute) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "policy routes are only supported on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        InterfaceCategory, InterfaceKind, InterfaceState, PolicyRoute, TunnelBackend,
    };
    use std::net::IpAddr;
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
            auto_connect: false,
            domain_policies: vec![],
            xray_socks_port: None,
        }
    }

    fn route(dest: &str, metric: u32) -> PolicyRoute {
        PolicyRoute {
            destination: dest.parse().unwrap(),
            metric,
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
            }]
        );
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
    fn forward_row_ipv6_fields() {
        let applied = AppliedRoute {
            destination: "fd00::1/64".parse().unwrap(),
            interface_index: 13,
            metric: 7,
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
