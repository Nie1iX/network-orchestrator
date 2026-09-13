use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

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
    pub category: InterfaceCategory,
    pub description: String,
    pub if_type: u32,
    pub tunnel_type: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceCategory {
    Physical,
    Vpn,
    Virtual,
    System,
    Tunnel,
    Filter,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TunnelBackend {
    WireGuard,
    OpenVpn,
    Xray,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DomainRouteTarget {
    Proxy,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DomainPolicy {
    pub domains: Vec<String>,
    pub target: DomainRouteTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRoute {
    pub destination: IpNet,
    pub metric: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub backend: TunnelBackend,
    pub config_path: PathBuf,
    pub interface_name: String,
    pub routes: Vec<PolicyRoute>,
    pub auto_connect: bool,
    #[serde(default)]
    pub domain_policies: Vec<DomainPolicy>,
    #[serde(default)]
    pub xray_socks_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TunnelState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    pub profile_id: String,
    pub state: TunnelState,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzedRoute {
    pub destination: IpNet,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalListener {
    pub address: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEndpoint {
    pub address: String,
    pub port: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConflictKind {
    RouteOverlap,
    ListenerCollision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConflict {
    pub kind: ConflictKind,
    pub message: String,
    pub other_profile_id: Option<String>,
    pub blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigAnalysis {
    pub profile_id: String,
    pub os_routes: Vec<AnalyzedRoute>,
    pub internal_routes: Vec<AnalyzedRoute>,
    pub listeners: Vec<LocalListener>,
    pub endpoints: Vec<RemoteEndpoint>,
    pub domain_patterns: Vec<String>,
    pub warnings: Vec<String>,
    pub route_knowledge_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInspection {
    pub analysis: ConfigAnalysis,
    pub conflicts: Vec<ProfileConflict>,
    pub managed_config: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppliedProfileRoutes {
    pub profile_id: String,
    pub routes: Vec<AppliedRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppliedRoute {
    pub destination: IpNet,
    pub interface_index: u32,
    pub metric: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticLevel {
    Healthy,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticCheck {
    pub name: String,
    pub level: DiagnosticLevel,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDiagnostics {
    pub profile_id: String,
    pub status: TunnelStatus,
    pub inspection: Option<ProfileInspection>,
    pub checks: Vec<DiagnosticCheck>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryIssueKind {
    SurvivingWireGuardService,
    OwnedRoutes,
    MissingOwnedRoutes,
    OrphanRouteOwnership,
    StatusCheckFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryIssue {
    pub kind: RecoveryIssueKind,
    pub profile_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReport {
    pub issues: Vec<RecoveryIssue>,
    pub requires_elevation: bool,
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
            category: InterfaceCategory::Physical,
            description: String::new(),
            if_type: 6,
            tunnel_type: None,
        };
        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"friendlyName\""));
        assert!(json.contains("\"ifIndex\""));
        assert!(json.contains("\"linkSpeedMbps\""));
    }
}
