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
    {
        r.metric.unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        r.metric.unwrap_or(0)
    }
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

    let matched =
        best.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no matching route"))?;

    Ok(RouteLookupResult {
        destination: dest,
        matched_route: matched.clone(),
        interface_name: matched.interface_name.clone(),
    })
}

// ── Route change watcher (cross-platform via net-route) ─────────────────

use futures::StreamExt;

/// Async loop that calls the callback whenever the routing table changes.
/// The caller is responsible for spawning this on an appropriate runtime.
pub async fn route_watcher_loop<F>(callback: F)
where
    F: Fn() + Send + 'static,
{
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
}

// ── Interface inventory ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;

#[cfg(target_os = "windows")]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_PREFIX,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let mut buf_len: u32 = 0;
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
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
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(head),
            &mut buf_len,
        )
    };
    if ret != 0 {
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
    use windows::Win32::NetworkManagement::Ndis::IF_OPER_STATUS;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let friendly_name = unsafe { adapter.FriendlyName.to_string().unwrap_or_default() };
    let raw_name = unsafe { adapter.AdapterName.to_string().unwrap_or_default() };
    let description = unsafe { adapter.Description.to_string().unwrap_or_default() };
    let if_type = adapter.IfType;
    let tunnel_type = tunnel_type_name(adapter.TunnelType);
    let kind = classify_interface(&raw_name, &friendly_name, &description, if_type);
    let state = if adapter.OperStatus == IF_OPER_STATUS(1) {
        InterfaceState::Up
    } else {
        InterfaceState::Down
    };

    let mut addresses = Vec::new();
    let mut ip = adapter.FirstUnicastAddress;
    while !ip.is_null() {
        let ua = unsafe { &*ip };
        let sockaddr = ua.Address.lpSockaddr;
        if !sockaddr.is_null() {
            let sa = unsafe { *sockaddr };
            let family = sa.sa_family;
            if family == AF_INET || family == AF_INET6 {
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
        ip = ua.Next;
    }

    let dns_servers = collect_dns(adapter);

    // MAC address
    let mac = if adapter.PhysicalAddressLength == 6 {
        let bytes = &adapter.PhysicalAddress[..adapter.PhysicalAddressLength as usize];
        Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        ))
    } else {
        None
    };

    // Gateway from FirstGatewayAddress
    let gateway = if !adapter.FirstGatewayAddress.is_null() {
        let gw = unsafe { &*adapter.FirstGatewayAddress };
        sockaddr_to_ip(gw.Address.lpSockaddr)
    } else {
        None
    };

    // DNS suffix
    let dns_suffix = unsafe { adapter.DnsSuffix.to_string() }
        .ok()
        .filter(|s| !s.is_empty());

    // Link speed (ReceiveLinkSpeed is in bps, convert to Mbps)
    // Some virtual adapters report u64::MAX — filter those out.
    let link_speed_mbps =
        if adapter.ReceiveLinkSpeed > 0 && adapter.ReceiveLinkSpeed < 1_000_000_000_000 {
            Some(adapter.ReceiveLinkSpeed / 1_000_000)
        } else {
            None
        };

    // MTU: some virtual adapters report absurd values — filter those out.
    let mtu = if adapter.Mtu > 0 && adapter.Mtu <= 65535 {
        Some(adapter.Mtu)
    } else {
        None
    };

    let category = classify_category(&friendly_name, &description, &kind, if_type);

    NetworkInterface {
        name: raw_name,
        friendly_name,
        kind,
        state,
        addresses,
        dns_servers,
        dns_suffix,
        mtu,
        if_index: unsafe { adapter.Anonymous1.Anonymous.IfIndex },
        physical: is_physical_windows(adapter.IfType),
        mac,
        gateway,
        rx_bytes: None, // requires GetIfEntry2 — deferred
        tx_bytes: None, // requires GetIfEntry2 — deferred
        link_speed_mbps,
        category,
        description,
        if_type,
        tunnel_type,
    }
}

#[cfg(target_os = "windows")]
fn sockaddr_to_ip(sa: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<IpAddr> {
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    let raw = unsafe { *sa };
    match raw.sa_family {
        f if f == AF_INET => {
            let sin = unsafe { *(sa as *const SOCKADDR_IN) };
            let bytes = unsafe { sin.sin_addr.S_un.S_addr.to_ne_bytes() };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)))
        }
        f if f == AF_INET6 => {
            let sin6 = unsafe { *(sa as *const SOCKADDR_IN6) };
            let bytes = unsafe { sin6.sin6_addr.u.Byte };
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
fn is_physical_windows(if_type: u32) -> bool {
    // IF_TYPE_ETHERNET_CSMACD = 6, IF_TYPE_IEEE80211 = 71
    if_type == 6 || if_type == 71
}

#[cfg(target_os = "windows")]
fn tunnel_type_name(t: windows::Win32::NetworkManagement::Ndis::TUNNEL_TYPE) -> Option<String> {
    use windows::Win32::NetworkManagement::Ndis::*;
    match t {
        TUNNEL_TYPE_NONE => None,
        TUNNEL_TYPE_OTHER => Some("Other".into()),
        TUNNEL_TYPE_DIRECT => Some("Direct".into()),
        TUNNEL_TYPE_6TO4 => Some("6to4".into()),
        TUNNEL_TYPE_ISATAP => Some("ISATAP".into()),
        TUNNEL_TYPE_TEREDO => Some("Teredo".into()),
        TUNNEL_TYPE_IPHTTPS => Some("IP-HTTPS".into()),
        _ => Some(format!("{:?}", t)),
    }
}

#[cfg(target_os = "windows")]
fn classify_category(
    friendly_name: &str,
    description: &str,
    kind: &InterfaceKind,
    if_type: u32,
) -> InterfaceCategory {
    let lower = friendly_name.to_lowercase();
    let desc_lower = description.to_lowercase();

    // Filter drivers and lightweight filters — by friendly name suffix
    const FILTER_KEYWORDS: &[&str] = &[
        "lightweight filter",
        "wfp native mac layer",
        "wfp 802.3 mac layer",
        "npcap packet driver",
        "qos packet scheduler",
        "hyper-v virtual switch extension",
        "virtual filtering platform vmswitch",
        "virtual wifi filter driver",
        "native wifi filter driver",
    ];
    if FILTER_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return InterfaceCategory::Filter;
    }

    // Description-based classification (more reliable than friendly name)
    // Wi-Fi Direct virtual adapters — virtual, not tunnel
    if desc_lower.contains("wi-fi direct") {
        return InterfaceCategory::Virtual;
    }
    // WAN Miniports — Windows built-in VPN miniports (PPTP, L2TP, IKEv2, SSTP, PPPOE, IP, IPv6, NetMon)
    if desc_lower.contains("wan miniport") {
        return InterfaceCategory::Tunnel;
    }
    // Kernel debug adapter — system
    if desc_lower.contains("kernel debug") {
        return InterfaceCategory::System;
    }
    // Bluetooth PAN — virtual (Windows uses if_type 6, not 7)
    if desc_lower.contains("bluetooth") {
        return InterfaceCategory::Virtual;
    }

    // OS-internal tunnel pseudo-interfaces by if_type
    // IF_TYPE_TUNNEL = 131
    if if_type == 131 {
        return InterfaceCategory::Tunnel;
    }
    const TUNNEL_KEYWORDS: &[&str] = &["teredo", "6to4", "ip-https", "isatap"];
    if TUNNEL_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return InterfaceCategory::Tunnel;
    }
    // Remaining "Подключение по локальной сети* N" not caught by description above
    if lower.starts_with("подключение по локальной сети*") || lower.starts_with("lan connection*")
    {
        return InterfaceCategory::Tunnel;
    }

    match kind {
        InterfaceKind::Loopback => InterfaceCategory::System,
        InterfaceKind::WireGuard | InterfaceKind::OpenVpn | InterfaceKind::Xray => {
            InterfaceCategory::Vpn
        }
        InterfaceKind::Other(s) => {
            let s = s.to_lowercase();
            match s.as_str() {
                "tailscale" => InterfaceCategory::Vpn,
                "hyper-v" | "cellular" | "bluetooth" => InterfaceCategory::Virtual,
                _ => {
                    // If description mentions VPN/tunnel driver, it's a VPN
                    if desc_lower.contains("wireguard")
                        || desc_lower.contains("wintun")
                        || desc_lower.contains("tap-windows")
                        || desc_lower.contains("tun/tap")
                    {
                        InterfaceCategory::Vpn
                    } else {
                        InterfaceCategory::Physical
                    }
                }
            }
        }
        InterfaceKind::Ethernet | InterfaceKind::Wifi => InterfaceCategory::Physical,
    }
}

#[cfg(target_os = "windows")]
fn classify_interface(
    raw: &str,
    friendly: &str,
    description: &str,
    _if_type: u32,
) -> InterfaceKind {
    let lower = friendly.to_lowercase();
    let desc_lower = description.to_lowercase();

    // VPN detection by driver description (most reliable)
    if desc_lower.contains("wireguard") || desc_lower.contains("wintun") {
        return InterfaceKind::WireGuard;
    }
    if desc_lower.contains("tap-windows") || desc_lower.contains("tun/tap") {
        return InterfaceKind::OpenVpn;
    }

    // VPN by friendly name
    if lower.contains("wireguard") || raw.starts_with("wg") {
        return InterfaceKind::WireGuard;
    }
    if lower.contains("openvpn") || lower.contains("tap-") || lower.contains("tun-") {
        return InterfaceKind::OpenVpn;
    }
    if lower.contains("xray") || lower.contains("wintun") {
        return InterfaceKind::Xray;
    }
    if lower.contains("tailscale") {
        return InterfaceKind::Other("Tailscale".into());
    }

    // Bluetooth: by description (Windows uses if_type 6 for Bluetooth PAN, not 7)
    if desc_lower.contains("bluetooth") || lower.contains("bluetooth") {
        return InterfaceKind::Other("Bluetooth".into());
    }

    // Kernel debug adapter
    if desc_lower.contains("kernel debug") {
        return InterfaceKind::Other("Kernel Debug".into());
    }

    // Wi-Fi Direct virtual adapters
    if desc_lower.contains("wi-fi direct") {
        return InterfaceKind::Other("Wi-Fi Direct".into());
    }

    // WiFi by description (Russian friendly names like "Беспроводная сеть" don't contain "wifi")
    if desc_lower.contains("wi-fi") || desc_lower.contains("wireless") {
        return InterfaceKind::Wifi;
    }

    // Hyper-V virtual switches
    if lower.starts_with("vethernet") || lower.contains("hyper-v") || lower.starts_with("vswitch") {
        return InterfaceKind::Other("Hyper-V".into());
    }

    // Cellular (wwan) — note: real wwan adapters have if_type 106, not name-based
    if lower.starts_with("wwan") && !desc_lower.contains("wintun") {
        return InterfaceKind::Other("Cellular".into());
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

// ── Linux interface inventory ───────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    use std::ffi::CStr;
    use std::mem;

    unsafe {
        let mut ifap: *mut libc::ifaddrs = mem::zeroed();
        let ret = libc::getifaddrs(&mut ifap);
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let head = ifap;

        // First pass: collect unique interface names in insertion order
        let mut names: Vec<String> = Vec::new();
        let mut name_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut is_up_map: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();

        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let is_up = (ifa.ifa_flags & libc::IFF_UP as u32) != 0;
                if name_set.insert(name.clone()) {
                    names.push(name.clone());
                }
                *is_up_map.entry(name).or_insert(false) |= is_up;
            }
            cur = ifa.ifa_next;
        }

        // Second pass: collect addresses per interface
        let mut addr_map: std::collections::HashMap<String, Vec<InterfaceAddress>> =
            std::collections::HashMap::new();

        cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let family = (*ifa.ifa_addr).sa_family as i32;

                let addr = if family == libc::AF_INET {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let bytes = sin.sin_addr.s_addr.to_ne_bytes();
                    Some((
                        IpAddr::V4(std::net::Ipv4Addr::from(bytes)),
                        AddressFamily::Ipv4,
                    ))
                } else if family == libc::AF_INET6 {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let bytes = sin6.sin6_addr.s6_addr;
                    Some((
                        IpAddr::V6(std::net::Ipv6Addr::from(bytes)),
                        AddressFamily::Ipv6,
                    ))
                } else {
                    None
                };

                if let Some((ip, fam)) = addr {
                    let prefix_len = get_prefix_len(ifa.ifa_netmask, family);
                    addr_map.entry(name).or_default().push(InterfaceAddress {
                        address: ip,
                        prefix_len,
                        family: fam,
                    });
                }
            }
            cur = ifa.ifa_next;
        }

        libc::freeifaddrs(head);

        // Build result in deterministic order
        let mut result = Vec::new();
        for (idx, name) in names.iter().enumerate() {
            let if_index = (idx + 1) as u32;
            let addresses = addr_map.remove(name).unwrap_or_default();
            let kind = classify_interface_linux(name);
            let is_up = *is_up_map.get(name).unwrap_or(&false);
            let state = if is_up {
                InterfaceState::Up
            } else {
                InterfaceState::Down
            };

            let mtu = read_linux_mtu(name);
            let physical = std::path::Path::new(&format!("/sys/class/net/{name}/device"))
                .symlink_metadata()
                .is_ok();
            let mac = read_linux_mac(name);
            let gateway = read_linux_gateway(name);
            let dns_suffix = read_linux_dns_suffix();
            let rx_bytes = read_linux_stat(name, "statistics/rx_bytes");
            let tx_bytes = read_linux_stat(name, "statistics/tx_bytes");
            let link_speed_mbps = read_linux_speed(name);

            result.push(NetworkInterface {
                name: name.clone(),
                friendly_name: name.clone(),
                kind,
                state,
                addresses,
                dns_servers: Vec::new(),
                dns_suffix,
                mtu,
                if_index,
                physical,
                mac,
                gateway,
                rx_bytes,
                tx_bytes,
                link_speed_mbps,
                category: classify_category_linux(&kind, physical, name),
                description: read_linux_description(name),
                if_type: read_linux_if_type(name),
                tunnel_type: None,
            });
        }

        Ok(result)
    }
}

#[cfg(target_os = "linux")]
fn get_prefix_len(netmask: *const libc::sockaddr, family: i32) -> u8 {
    if netmask.is_null() {
        return if family == libc::AF_INET { 32 } else { 128 };
    }
    if family == libc::AF_INET {
        let sin = unsafe { &*(netmask as *const libc::sockaddr_in) };
        let mask = u32::from_be(sin.sin_addr.s_addr);
        mask.count_ones() as u8
    } else if family == libc::AF_INET6 {
        let sin6 = unsafe { &*(netmask as *const libc::sockaddr_in6) };
        sin6.sin6_addr
            .s6_addr
            .iter()
            .map(|&b| b.count_ones() as u8)
            .sum()
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
fn read_linux_mtu(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(target_os = "linux")]
fn read_linux_mac(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00")
}

#[cfg(target_os = "linux")]
fn read_linux_stat(name: &str, stat: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/{stat}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(target_os = "linux")]
fn read_linux_speed(name: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/speed"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(target_os = "linux")]
fn read_linux_description(name: &str) -> String {
    // /sys/class/net/<name>/device/driver symlink gives the driver name
    let driver_path = std::path::Path::new(&format!("/sys/class/net/{name}/device/driver"));
    if let Ok(target) = std::fs::read_link(driver_path) {
        if let Some(fname) = target.file_name() {
            return format!("{} driver", fname.to_string_lossy());
        }
    }
    // Fallback: /sys/class/net/<name>/uevent has interface info
    std::fs::read_to_string(format!("/sys/class/net/{name}/uevent"))
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("INTERFACE="))
        .map(|l| l.trim_start_matches("INTERFACE=").to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn read_linux_if_type(name: &str) -> u32 {
    // /sys/class/net/<name>/type contains the ARP type (1=Ethernet, 772=Loopback,
    // 801=Wifi, 6to4=42, etc.)
    std::fs::read_to_string(format!("/sys/class/net/{name}/type"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1)
}

#[cfg(target_os = "linux")]
fn read_linux_gateway(_name: &str) -> Option<IpAddr> {
    // Gateway resolution via netlink is async; for the synchronous list_interfaces
    // we read /proc/net/route for the default route on this interface.
    // This is a best-effort heuristic.
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in routes.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // Field 1 = Destination (0.0.0.0 for default), Field 2 = Gateway
        if fields[1] == "00000000" {
            let gw_hex = fields[2];
            if gw_hex.len() == 8 {
                let gw_u32 = u32::from_str_radix(gw_hex, 16).ok()?;
                let bytes = gw_u32.to_ne_bytes();
                return Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)));
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_linux_dns_suffix() -> Option<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()?
        .lines()
        .find(|l| l.starts_with("search "))
        .map(|l| l.trim_start_matches("search ").trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn classify_interface_linux(name: &str) -> InterfaceKind {
    if name == "lo" {
        return InterfaceKind::Loopback;
    }
    if name.starts_with("wg") || name.contains("wireguard") {
        return InterfaceKind::WireGuard;
    }
    if name.starts_with("tun") || name.starts_with("tap") || name.contains("openvpn") {
        return InterfaceKind::OpenVpn;
    }
    if name.starts_with("eth") || name.starts_with("en") {
        return InterfaceKind::Ethernet;
    }
    if name.starts_with("wlan") || name.starts_with("wl") || name.starts_with("wlp") {
        return InterfaceKind::Wifi;
    }
    if name.contains("xray") || name.contains("utun") {
        return InterfaceKind::Xray;
    }
    InterfaceKind::Other(name.to_string())
}

#[cfg(target_os = "linux")]
fn classify_category_linux(kind: &InterfaceKind, physical: bool, name: &str) -> InterfaceCategory {
    match kind {
        InterfaceKind::Loopback => InterfaceCategory::System,
        InterfaceKind::WireGuard | InterfaceKind::OpenVpn | InterfaceKind::Xray => {
            InterfaceCategory::Vpn
        }
        InterfaceKind::Ethernet | InterfaceKind::Wifi => {
            if physical {
                InterfaceCategory::Physical
            } else {
                InterfaceCategory::Virtual
            }
        }
        InterfaceKind::Other(_) => {
            // Virtual interfaces on Linux: docker0, br-*, veth*, virbr*, etc.
            if physical {
                InterfaceCategory::Physical
            } else {
                InterfaceCategory::Virtual
            }
        }
    }
}

// ── Non-Windows/Linux stub ──────────────────────────────────────────────

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "interface inventory is only implemented on Windows and Linux",
    ))
}

// ── Interface state control ─────────────────────────────────────────────

/// Bring an interface up or down by name.
/// Requires administrator/root privileges.
pub fn set_interface_state(name: &str, up: bool) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let action = if up { "up" } else { "down" };
        let output = std::process::Command::new("ip")
            .args(["link", "set", name, action])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "ip link set {} {}: {}",
                    name,
                    action,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        let admin = if up { "enable" } else { "disable" };
        let output = std::process::Command::new("netsh")
            .args([
                "interface",
                "set",
                "interface",
                name,
                &format!("admin={admin}"),
            ])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "netsh interface set interface {} admin={}: {}",
                    name,
                    admin,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "interface state control is only implemented on Windows and Linux",
        ))
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;
    use std::net::Ipv4Addr;

    #[test]
    fn longest_prefix_match_logic() {
        let routes = [
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
        let routes = [RouteEntry {
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
