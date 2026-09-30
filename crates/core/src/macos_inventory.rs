//! Read-only Darwin interface inventory. No subprocesses or network changes.
use crate::models::*;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct Addresses(*mut libc::ifaddrs);
impl Drop for Addresses {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.0) };
    }
}
unsafe fn ip(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match unsafe { (*address).sa_family as i32 } {
        libc::AF_INET => {
            let addr = unsafe { &*address.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(Ipv4Addr::from(
                addr.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            let addr = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}
fn prefix(mask: Option<IpAddr>) -> u8 {
    match mask {
        Some(IpAddr::V4(mask)) => u32::from(mask).leading_ones() as u8,
        Some(IpAddr::V6(mask)) => u128::from(mask).leading_ones() as u8,
        None => 0,
    }
}
pub fn list_interfaces() -> io::Result<Vec<NetworkInterface>> {
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _addresses = Addresses(head);
    let mut next = head;
    let mut result = BTreeMap::new();
    while !next.is_null() {
        let entry = unsafe { &*next };
        next = entry.ifa_next;
        if entry.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let loopback = entry.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
        let tunnel =
            name.starts_with("utun") || entry.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0;
        let physical = name.starts_with("en");
        let row = result
            .entry(name.clone())
            .or_insert_with(|| NetworkInterface {
                name: name.clone(),
                friendly_name: name.clone(),
                kind: if loopback {
                    InterfaceKind::Loopback
                } else if physical {
                    InterfaceKind::Ethernet
                } else {
                    InterfaceKind::Other("Darwin interface".into())
                },
                state: if entry.ifa_flags & libc::IFF_UP as u32 != 0 {
                    InterfaceState::Up
                } else {
                    InterfaceState::Down
                },
                addresses: Vec::new(),
                dns_servers: Vec::new(),
                dns_suffix: None,
                mtu: None,
                if_index: unsafe { libc::if_nametoindex(entry.ifa_name) },
                physical,
                mac: None,
                gateway: None,
                ipv6_gateway: None,
                rx_bytes: None,
                tx_bytes: None,
                link_speed_mbps: None,
                category: if loopback {
                    InterfaceCategory::System
                } else if tunnel {
                    InterfaceCategory::Tunnel
                } else if physical {
                    InterfaceCategory::Physical
                } else {
                    InterfaceCategory::Virtual
                },
                description: "macOS network interface".into(),
                if_type: if loopback {
                    24
                } else if physical {
                    6
                } else {
                    0
                },
                tunnel_type: tunnel.then(|| "utun / point-to-point".into()),
            });
        if let Some(address) = unsafe { ip(entry.ifa_addr) } {
            if !row.addresses.iter().any(|a| a.address == address) {
                row.addresses.push(InterfaceAddress {
                    address,
                    prefix_len: prefix(unsafe { ip(entry.ifa_netmask) }),
                    family: if address.is_ipv4() {
                        AddressFamily::Ipv4
                    } else {
                        AddressFamily::Ipv6
                    },
                });
            }
        }
    }
    Ok(result.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readonly_inventory_includes_loopback_addresses_and_real_indexes() {
        let interfaces = list_interfaces().unwrap();
        let loopback = interfaces.iter().find(|i| i.name == "lo0").unwrap();
        assert!(loopback.if_index > 0);
        assert!(loopback.addresses.iter().any(|a| a.address.is_loopback()));
        assert!(matches!(loopback.category, InterfaceCategory::System));
    }
}
