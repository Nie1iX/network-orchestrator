use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    /// Default IPv6 next hop on this interface (often link-local).
    #[serde(default)]
    pub ipv6_gateway: Option<IpAddr>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TunnelBackend {
    None,
    WireGuard,
    OpenVpn,
    Xray,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DomainRouteTarget {
    Proxy,
    Direct,
    Block,
}

/// Xray operating mode. `Socks` (default) creates a SOCKS5 inbound on
/// 127.0.0.1 and relies on system proxy for traffic capture. `Tun` creates a
/// TUN inbound (Wintun on Windows) that captures all IP traffic at the
/// interface level, making Xray a full-tunnel backend comparable to
/// WireGuard/OpenVPN.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum XrayMode {
    #[default]
    Socks,
    Tun,
}

impl XrayMode {
    /// Mode assigned to freshly created/imported Xray profiles. On Linux a
    /// SOCKS listener captures no system traffic (no system-proxy consumer
    /// exists), so TUN via the network daemon is the only mode that actually
    /// tunnels.
    pub fn platform_default() -> Self {
        if cfg!(target_os = "linux") {
            Self::Tun
        } else {
            Self::Socks
        }
    }
}

/// User-supplied WireGuard tunnel fields for manual profile creation.
/// All values are written verbatim into the generated `.conf`; the vault
/// directory ACL protects the resulting file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardFields {
    /// Interface private key (base64).
    pub private_key: String,
    /// Interface address(es), comma-separated, e.g. `10.0.0.2/24`.
    pub address: String,
    /// Optional DNS servers, comma-separated.
    #[serde(default)]
    pub dns: String,
    /// Peer public key (base64).
    pub peer_public_key: String,
    /// Peer endpoint `host:port`.
    pub peer_endpoint: String,
    /// Peer allowed IPs, comma-separated, e.g. `0.0.0.0/0`.
    pub allowed_ips: String,
    /// Optional pre-shared key (base64).
    #[serde(default)]
    pub preshared_key: String,
    /// Optional persistent keepalive interval (seconds).
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
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
    /// Explicit next hop; `None` means the interface gateway or on-link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<IpAddr>,
}

/// Xray `routing.domainStrategy`: when the router resolves a domain name
/// before testing it against IP rules.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum XrayDomainStrategy {
    /// Domains stay unresolved; IP rules only see literal-IP destinations.
    AsIs,
    /// Unmatched domains are resolved and re-tested against IP rules.
    IpIfNonMatch,
    /// Every domain is resolved before routing (slowest, most precise).
    IpOnDemand,
}

impl XrayDomainStrategy {
    pub fn as_xray_str(self) -> &'static str {
        match self {
            Self::AsIs => "AsIs",
            Self::IpIfNonMatch => "IPIfNonMatch",
            Self::IpOnDemand => "IPOnDemand",
        }
    }
}

/// Xray `routing.domainMatcher` algorithm: `mph` (minimal perfect hash)
/// trades startup time for lookup speed, `hybrid` is its accepted alias,
/// `linear` is the classic matcher.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum XrayDomainMatcher {
    Mph,
    Hybrid,
    Linear,
}

impl XrayDomainMatcher {
    pub fn as_xray_str(self) -> &'static str {
        match self {
            Self::Mph => "mph",
            Self::Hybrid => "hybrid",
            Self::Linear => "linear",
        }
    }
}

/// Xray `dns.queryStrategy` — which A/AAAA answers the built-in resolver
/// requests.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum XrayDnsQueryStrategy {
    UseIp,
    UseIpv4,
    UseIpv6,
}

impl XrayDnsQueryStrategy {
    pub fn as_xray_str(self) -> &'static str {
        match self {
            Self::UseIp => "UseIP",
            Self::UseIpv4 => "UseIPv4",
            Self::UseIpv6 => "UseIPv6",
        }
    }
}

/// Whether a DNS server's own address is pinned to an outbound — the
/// split-DNS pattern where the "remote" resolver is reached through the
/// proxy and the "domestic" one goes direct.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum XrayDnsRoute {
    /// No dedicated rule; normal routing decides.
    #[default]
    None,
    /// Route the resolver address through the proxy outbound.
    Proxy,
    /// Route the resolver address through the direct outbound.
    Direct,
}

/// One `dns.servers` entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayDnsServer {
    /// `udp://`/`tcp://`/`tls://`/`https://`/`https+local://`/
    /// `quic+local://` URL, `localhost`, `fakedns`, or a bare IP/hostname
    /// (plain values are treated as `udp://`).
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Restrict the resolver to these domain selectors (`geosite:` allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    #[serde(default)]
    pub skip_fallback: bool,
    /// Pin the resolver's own address to an outbound.
    #[serde(default)]
    pub route: XrayDnsRoute,
}

/// Profile-level Xray `dns` policy: ordered resolvers, static host
/// overrides and fake-DNS capture.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XrayDnsConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<XrayDnsServer>,
    /// Static host overrides: hostname → one or more IPs (or a domain).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hosts: BTreeMap<String, Vec<String>>,
    /// Intercept DNS answers with fake pool IPs (`198.18.0.0/16`); the TUN
    /// inbound's sniffing translates them back to the original names.
    #[serde(default)]
    pub fake_dns: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_strategy: Option<XrayDnsQueryStrategy>,
}

impl XrayDnsConfig {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.hosts.is_empty() && !self.fake_dns
    }
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
    pub private_lan_direct: bool,
    #[serde(default)]
    pub xray_socks_port: Option<u16>,
    #[serde(default)]
    pub xray_http_port: Option<u16>,
    #[serde(default)]
    pub use_system_proxy: bool,
    #[serde(default)]
    pub proxy_bypass: Vec<String>,
    #[serde(default)]
    pub subscription: Option<SubscriptionMeta>,
    #[serde(default)]
    pub xray_mode: XrayMode,
    /// TUN interface name for Xray TUN mode (e.g. "xray-tun"). Ignored in
    /// SOCKS mode.
    #[serde(default)]
    pub xray_tun_interface: Option<String>,
    /// TUN interface IPv4 address with prefix (e.g. "172.19.0.1/30"). Ignored
    /// in SOCKS mode.
    #[serde(default)]
    pub xray_tun_ip: Option<String>,
    /// Optional HTTPS URL overriding the bundled geoip.dat. Downloaded by the
    /// app into a per-profile cache and staged by the daemon next to the
    /// generated config. Ignored in SOCKS mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_geoip_url: Option<String>,
    /// Optional HTTPS URL overriding the bundled geosite.dat. Same staging
    /// rules as `xray_geoip_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_geosite_url: Option<String>,
    /// `routing.domainStrategy` override; `None` keeps the base config's
    /// (our generated configs ship `AsIs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_domain_strategy: Option<XrayDomainStrategy>,
    /// `routing.domainMatcher` override (`mph` is the fast path for large
    /// geosite lists).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_domain_matcher: Option<XrayDomainMatcher>,
    /// Profile DNS policy: resolver list, static hosts and fake-DNS capture.
    #[serde(default, skip_serializing_if = "XrayDnsConfig::is_empty")]
    pub xray_dns: XrayDnsConfig,
    /// In TUN full-capture mode, install the def1 halves `0.0.0.0/1` +
    /// `128.0.0.0/1` instead of a single `0.0.0.0/0` default route — the same
    /// trick other route managers use, so tunnels coexist more politely.
    /// Ignored in SOCKS mode and when explicit profile routes are set.
    #[serde(default)]
    pub xray_split_default: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            backend: TunnelBackend::None,
            config_path: PathBuf::new(),
            interface_name: String::new(),
            routes: Vec::new(),
            auto_connect: false,
            domain_policies: Vec::new(),
            private_lan_direct: false,
            xray_socks_port: None,
            xray_http_port: None,
            use_system_proxy: false,
            proxy_bypass: Vec::new(),
            subscription: None,
            xray_mode: XrayMode::default(),
            xray_tun_interface: None,
            xray_tun_ip: None,
            xray_geoip_url: None,
            xray_geosite_url: None,
            xray_domain_strategy: None,
            xray_domain_matcher: None,
            xray_dns: XrayDnsConfig::default(),
            xray_split_default: false,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionMeta {
    pub url: String,
    pub hwid: String,
    pub endpoint_count: usize,
    pub active_index: usize,
    #[serde(default)]
    pub refresh_interval_minutes: Option<u32>,
    #[serde(default)]
    pub last_refresh_at_unix: Option<u64>,
    #[serde(default)]
    pub last_refresh_error: Option<String>,
    #[serde(default)]
    pub user_info: Option<SubscriptionUserInfo>,
    #[serde(default)]
    pub provider_title: Option<String>,
    #[serde(default)]
    pub announce: Option<String>,
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub web_page_url: Option<String>,
    #[serde(default)]
    pub update_interval_hours: Option<u32>,
    #[serde(default)]
    pub skipped_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionUserInfo {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: Option<u64>,
    pub expires_at_unix: Option<u64>,
}

impl std::fmt::Debug for SubscriptionMeta {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubscriptionMeta")
            .field("url", &"<redacted>")
            .field("hwid", &"<redacted>")
            .field("endpoint_count", &self.endpoint_count)
            .field("active_index", &self.active_index)
            .field("refresh_interval_minutes", &self.refresh_interval_minutes)
            .field("last_refresh_at_unix", &self.last_refresh_at_unix)
            .field("last_refresh_error", &self.last_refresh_error)
            .field("user_info", &self.user_info)
            .field("provider_title", &self.provider_title)
            .field("announce", &self.announce)
            .field(
                "support_url",
                &self.support_url.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "web_page_url",
                &self.web_page_url.as_ref().map(|_| "<redacted>"),
            )
            .field("update_interval_hours", &self.update_interval_hours)
            .field("skipped_protocols", &self.skipped_protocols)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionEndpointInfo {
    pub name: String,
    pub active: bool,
    #[serde(default)]
    pub protocol: Option<String>,
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
    /// Live interface name assigned by the network daemon (e.g.
    /// `wg-44c5d5827e76`), when the profile is daemon-managed and running.
    #[serde(default)]
    pub interface_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzedRoute {
    pub destination: IpNet,
    pub source: String,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedRoute {
    pub destination: IpNet,
    pub owner_profile_id: String,
    pub owner_name: String,
    pub source: String,
    pub interface_name: Option<String>,
    pub metric: Option<u32>,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RoutePlanDiffKind {
    Missing,
    InterfaceMismatch,
    ExactCompetition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutePlanDiff {
    pub kind: RoutePlanDiffKind,
    pub destination: IpNet,
    pub message: String,
    pub profile_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteMap {
    pub predicted: Vec<PlannedRoute>,
    pub effective: Vec<RouteEntry>,
    pub diffs: Vec<RoutePlanDiff>,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub pushed_routes: Vec<PlannedRoute>,
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
    /// WireGuard `[Peer]` sections: the endpoint plus the AllowedIPs it owns.
    /// Empty for backends without peers.
    pub peers: Vec<ConfigPeer>,
    /// Non-secret interface-level facts from the config (Address, DNS, MTU…)
    /// shown in the profile detail pane. Never populated with private keys,
    /// preshared keys, or credential material.
    pub interface_details: Vec<ConfigField>,
}

/// A `[Peer]` section of a WireGuard config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigPeer {
    pub endpoint: Option<RemoteEndpoint>,
    pub routes: Vec<AnalyzedRoute>,
}

/// One displayable non-secret fact about a tunnel config, e.g. `Address`,
/// `DNS`, `MTU`, `ListenPort` for WireGuard or `proto`/`dev` for OpenVPN.
/// `field` is a stable machine name the UI maps to a localized label.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigField {
    pub field: String,
    pub value: String,
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
    /// Next hop; `None` installs the route on-link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// Routing table chosen by the Linux daemon; `None` means the main table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<u32>,
}

impl AppliedRoute {
    pub fn on_link(destination: IpNet, interface_index: u32, metric: u32) -> Self {
        Self {
            destination,
            interface_index,
            metric,
            gateway: None,
            table: None,
        }
    }
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
    ProxyOwnership,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolHealthState {
    Unknown,
    Healthy,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolHealth {
    pub state: ProtocolHealthState,
    pub summary: String,
    pub last_handshake_unix: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub log_tail: Option<String>,
    #[serde(default)]
    pub pushed_routes: Vec<AnalyzedRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryIssue {
    pub kind: RecoveryIssueKind,
    pub profile_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BackendExecutableSource {
    AutoDetected,
    Configured,
    Managed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackendExecutableSetting {
    pub path: PathBuf,
    pub source: BackendExecutableSource,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackendAvailability {
    pub backend: TunnelBackend,
    pub available: bool,
    pub path: Option<PathBuf>,
    pub source: Option<BackendExecutableSource>,
    pub version: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReport {
    pub issues: Vec<RecoveryIssue>,
    pub requires_elevation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BatchImportError {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BatchImportResult {
    pub profiles: Vec<Profile>,
    pub errors: Vec<BatchImportError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_platform_default_is_tun_only_on_linux() {
        let expected = if cfg!(target_os = "linux") {
            XrayMode::Tun
        } else {
            XrayMode::Socks
        };
        assert_eq!(XrayMode::platform_default(), expected);
    }

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
            ipv6_gateway: None,
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

    #[test]
    fn subscription_debug_hides_url_and_hwid() {
        let subscription = SubscriptionMeta {
            url: "https://example.test/private-token".into(),
            hwid: "private-hwid".into(),
            endpoint_count: 2,
            active_index: 1,
            refresh_interval_minutes: None,
            last_refresh_at_unix: None,
            last_refresh_error: None,
            user_info: None,
            provider_title: None,
            announce: None,
            support_url: None,
            web_page_url: None,
            update_interval_hours: None,
            skipped_protocols: Vec::new(),
        };
        let debug = format!("{subscription:?}");
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("private-hwid"));
        assert!(debug.contains("endpoint_count"));
    }

    #[test]
    fn old_profile_json_defaults_http_port_to_none() {
        let mut json = serde_json::to_value(Profile::default()).unwrap();
        json.as_object_mut().unwrap().remove("xrayHttpPort");
        let restored: Profile = serde_json::from_value(json).unwrap();
        assert_eq!(restored.xray_http_port, None);
        let mut upgraded = restored;
        upgraded.xray_http_port = Some(10809);
        assert_eq!(
            serde_json::to_value(upgraded).unwrap()["xrayHttpPort"],
            10809
        );
    }

    #[test]
    fn old_profile_json_defaults_private_lan_preset_to_off() {
        let mut json = serde_json::to_value(Profile::default()).unwrap();
        json.as_object_mut().unwrap().remove("privateLanDirect");
        let restored: Profile = serde_json::from_value(json).unwrap();
        assert!(!restored.private_lan_direct);
    }

    #[test]
    fn old_subscription_metadata_defaults_refresh_and_usage_fields() {
        let old = serde_json::json!({
            "url": "https://example.test/private-token",
            "hwid": "private-hwid",
            "endpointCount": 2,
            "activeIndex": 1
        });
        let restored: SubscriptionMeta = serde_json::from_value(old).unwrap();
        assert_eq!(restored.refresh_interval_minutes, None);
        assert_eq!(restored.last_refresh_at_unix, None);
        assert!(restored.last_refresh_error.is_none());
        assert!(restored.user_info.is_none());
    }
}
