use crate::models::*;
use ipnet::IpNet;
use net_route::Handle as RouteHandle;
use std::collections::HashMap;
use std::net::IpAddr;

// ── Route table reading (cross-platform via net-route) ──────────────────

/// List all IPv4 routes from the system routing table.
pub async fn list_routes() -> std::io::Result<Vec<RouteEntry>> {
    let handle = RouteHandle::new()?;
    let routes = handle.list().await?;

    let name_map = build_ifindex_name_map();

    let mut result = Vec::new();
    for r in routes {
        if r.destination.is_ipv6() {
            continue; // IPv4 only in MVP-0
        }
        let if_index = r.ifindex.unwrap_or(0);
        let name = name_map
            .get(&if_index)
            .cloned()
            .unwrap_or_else(|| format!("ifindex {}", if_index));
        result.push(RouteEntry {
            destination: r.destination,
            prefix_len: r.prefix,
            gateway: r.gateway,
            interface_index: if_index,
            interface_name: name,
            metric: route_metric(&r),
        });
    }
    Ok(result)
}

/// Build a map of interface index → friendly name.
/// Uses the platform-specific interface listing.
fn build_ifindex_name_map() -> HashMap<u32, String> {
    list_interfaces()
        .unwrap_or_default()
        .into_iter()
        .map(|i| (i.if_index, i.friendly_name))
        .collect()
}

/// Extract metric from a net-route Route (platform-dependent field).
fn route_metric(r: &net_route::Route) -> u32 {
    #[cfg(target_os = "linux")]
    { r.metric.unwrap_or(0) }
    #[cfg(not(target_os = "linux"))]
    { r.metric }
}

// ── Route lookup (cross-platform, pure logic) ──────────────────────────

/// Given a destination IP, find which route and interface the OS would use.
pub async fn lookup_route(dest: IpAddr) -> std::io::Result<RouteLookupResult> {
    let routes = list_routes().await?;

    let mut best: Option<&RouteEntry> = None;
    let mut best_prefix: u8 = 0;
    let mut best_metric: u32 = u32::MAX;

    for r in &routes {
        if let IpAddr::V4(dst) = r.destination {
            let net = match ipnet::Ipv4Net::new(dst, r.prefix_len) {
                Ok(n) => IpNet::V4(n),
                Err(_) => continue,
            };
            if net.contains(&dest) {
                // Longest prefix wins; tie-break by lowest metric
                if r.prefix_len > best_prefix
                    || (r.prefix_len == best_prefix && r.metric < best_metric)
                {
                    best = Some(r);
                    best_prefix = r.prefix_len;
                    best_metric = r.metric;
                }
            }
        }
    }

    let matched = best.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no matching route")
    })?;

    Ok(RouteLookupResult {
        destination: dest,
        matched_route: matched.clone(),
        interface_name: matched.interface_name.clone(),
    })
}

// ── Route change watcher (cross-platform via net-route) ─────────────────

use futures::StreamExt;

/// Spawn a background task that calls the callback whenever the routing table changes.
pub fn spawn_route_watcher<F>(callback: F)
where
    F: Fn() + Send + 'static,
{
    tokio::spawn(async move {
        let handle = match RouteHandle::new() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("route watcher init failed: {e}");
                return;
            }
        };
        let stream = handle.route_listen_stream();
        tokio::pin!(stream);
        while let Some(_change) = stream.next().await {
            callback();
        }
    });
}

// ── Interface inventory ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES,
        GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    let mut buf_len: u32 = 0;
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buf_len,
        );
    }

    let mut buf = vec![0u8; buf_len as usize];
    let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(head),
            &mut buf_len,
        )
    };
    if ret != NO_ERROR {
        return Err(std::io::Error::from_raw_os_error(ret as i32));
    }

    let mut result = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        result.push(adapter_to_model(adapter));
        cur = unsafe { (*cur).Next };
    }

    // FreeMibTable expects the pointer that was allocated by GetAdaptersAddresses
    // (which writes into our buffer), so we must NOT free it — the buffer is
    // owned by `buf` and will be dropped. FreeMibTable is for tables allocated
    // by functions like GetIpForwardTable2. Skip it here.
    Ok(result)
}

#[cfg(target_os = "windows")]
fn adapter_to_model(adapter: &IP_ADAPTER_ADDRESSES_LH) -> NetworkInterface {
    use windows::Win32::Networking::WinSock::{SOCKADDR_IN, SOCKADDR_IN6};

    let friendly_name = unsafe { adapter.FriendlyName.to_string().unwrap_or_default() };
    let raw_name = unsafe { adapter.AdapterName.to_string().unwrap_or_default() };
    let kind = classify_interface(&raw_name, &friendly_name);
    let state = if adapter.OperStatus == 1 {
        InterfaceState::Up
    } else {
        InterfaceState::Down
    };

    let mut addresses = Vec::new();
    let mut ip = adapter.FirstUnicastAddress;
    while !ip.is_null() {
        let ua = unsafe { &*ip };
        let sockaddr = unsafe { ua.Address.lpSockaddr };
        if !sockaddr.is_null() {
            let sa = unsafe { *sockaddr };
            let family = sa.sa_family;
            if family == AF_INET as u16 || family == AF_INET6 as u16 {
                if let Some(addr) = sockaddr_to_ip(sockaddr) {
                    addresses.push(InterfaceAddress {
                        address: addr,
                        prefix_len: ua.OnLinkPrefixLength,
                        family: if addr.is_ipv4() {
                            AddressFamily::Ipv4
                        } else {
                            AddressFamily::Ipv6
                        },
                    });
                }
            }
        }
        ip = unsafe { ua.Next };
    }

    let dns_servers = collect_dns(adapter);

    NetworkInterface {
        name: raw_name,
        friendly_name,
        kind,
        state,
        addresses,
        dns_servers,
        mtu: Some(adapter.Mtu),
        if_index: adapter.Ipv4IfIndex,
    }
}

#[cfg(target_os = "windows")]
fn sockaddr_to_ip(
    sa: *const windows::Win32::Networking::WinSock::SOCKADDR,
) -> Option<IpAddr> {
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    let raw = unsafe { *sa };
    match raw.sa_family {
        f if f == AF_INET as u16 => {
            let sin = unsafe { *(sa as *const SOCKADDR_IN) };
            let bytes = sin.sin_addr.S_un.S_addr.to_ne_bytes();
            Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)))
        }
        f if f == AF_INET6 as u16 => {
            let sin6 = unsafe { *(sa as *const SOCKADDR_IN6) };
            let bytes = sin6.sin6_addr.u.Byte;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn collect_dns(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
    let mut dns = Vec::new();
    let mut cur = adapter.FirstDnsServerAddress;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        let sa = entry.Address.lpSockaddr;
        if !sa.is_null() {
            if let Some(addr) = sockaddr_to_ip(sa) {
                dns.push(addr);
            }
        }
        cur = entry.Next;
    }
    dns
}

#[cfg(target_os = "windows")]
fn classify_interface(raw: &str, friendly: &str) -> InterfaceKind {
    let lower = friendly.to_lowercase();
    if lower.contains("wireguard") || raw.starts_with("wg") {
        return InterfaceKind::WireGuard;
    }
    if lower.contains("openvpn") || lower.contains("tap-") || lower.contains("tun-") {
        return InterfaceKind::OpenVpn;
    }
    if lower.contains("xray") || lower.contains("wintun") {
        return InterfaceKind::Xray;
    }
    if lower.contains("wi-fi") || lower.contains("wifi") || lower.contains("wireless") {
        return InterfaceKind::Wifi;
    }
    if lower.contains("ethernet") {
        return InterfaceKind::Ethernet;
    }
    if lower.contains("loopback") || raw == "lo" {
        return InterfaceKind::Loopback;
    }
    InterfaceKind::Other(lower)
}

// ── Non-Windows stub ────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "interface inventory is only implemented on Windows",
    ))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;
    use std::net::Ipv4Addr;

    #[test]
    fn longest_prefix_match_logic() {
        let routes = vec![
            RouteEntry {
                destination: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                prefix_len: 0,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                interface_index: 1,
                interface_name: "Wi-Fi".into(),
                metric: 25,
            },
            RouteEntry {
                destination: IpAddr::V4(Ipv4Addr::new(10, 228, 0, 0)),
                prefix_len: 16,
                gateway: None,
                interface_index: 7,
                interface_name: "WireGuard".into(),
                metric: 5,
            },
        ];

        let dest: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 228, 32, 10));
        let dest_v4 = match dest {
            IpAddr::V4(v) => v,
            _ => unreachable!(),
        };
        let best = routes
            .iter()
            .filter(|r| {
                if let IpAddr::V4(d) = r.destination {
                    let net = ipnet::Ipv4Net::new(d, r.prefix_len).unwrap();
                    net.contains(&dest_v4)
                } else {
                    false
                }
            })
            .min_by_key(|r| (Reverse(r.prefix_len), r.metric))
            .unwrap();

        assert_eq!(best.interface_name, "WireGuard");
        assert_eq!(best.prefix_len, 16);
    }

    #[test]
    fn default_route_matches_any_ip() {
        let routes = vec![RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 0,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            interface_index: 1,
            interface_name: "Wi-Fi".into(),
            metric: 25,
        }];

        let dest_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let net = ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap();
        assert!(net.contains(&dest_v4));

        let best = routes
            .iter()
            .filter(|r| {
                if let IpAddr::V4(d) = r.destination {
                    let net = ipnet::Ipv4Net::new(d, r.prefix_len).unwrap();
                    net.contains(&dest_v4)
                } else {
                    false
                }
            })
            .min_by_key(|r| (Reverse(r.prefix_len), r.metric))
            .unwrap();
        assert_eq!(best.interface_name, "Wi-Fi");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn list_interfaces_returns_nonempty() {
        let ifaces = list_interfaces().expect("should list interfaces");
        assert!(!ifaces.is_empty(), "Windows always has at least loopback");
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn list_routes_returns_default() {
        let routes = list_routes().await.expect("should list routes");
        assert!(
            routes.iter().any(|r| r.destination.is_unspecified()),
            "should have a default route"
        );
    }
}
