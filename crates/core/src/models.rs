use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    pub name: String,
    pub friendly_name: String,
    pub kind: InterfaceKind,
    pub state: InterfaceState,
    pub addresses: Vec<InterfaceAddress>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_suffix: Option<String>,
    pub mtu: Option<u32>,
    pub if_index: u32,
    pub physical: bool,
    pub mac: Option<String>,
    pub gateway: Option<IpAddr>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub link_speed_mbps: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceKind {
    Ethernet,
    Wifi,
    WireGuard,
    OpenVpn,
    Xray,
    Loopback,
    Other(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub family: AddressFamily,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub interface_index: u32,
    pub interface_name: String,
    pub metric: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteLookupResult {
    pub destination: IpAddr,
    pub matched_route: RouteEntry,
    pub interface_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_serializes_to_camel_case() {
        let iface = NetworkInterface {
            name: "wg0".into(),
            friendly_name: "WireGuard".into(),
            kind: InterfaceKind::WireGuard,
            state: InterfaceState::Up,
            addresses: vec![],
            dns_servers: vec![],
            dns_suffix: None,
            mtu: Some(1420),
            if_index: 7,
            physical: false,
            mac: None,
            gateway: None,
            rx_bytes: None,
            tx_bytes: None,
            link_speed_mbps: None,
        };
        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"friendlyName\""));
        assert!(json.contains("\"ifIndex\""));
        assert!(json.contains("\"linkSpeedMbps\""));
    }
}
