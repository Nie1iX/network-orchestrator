export type InterfaceKind =
  | "ethernet"
  | "wifi"
  | "wireGuard"
  | "openVpn"
  | "xray"
  | "loopback"
  | { other: string };

export type InterfaceState = "up" | "down" | "unknown";

export interface InterfaceAddress {
  address: string;
  prefixLen: number;
  family: "Ipv4" | "Ipv6";
}

export type InterfaceCategory =
  | "physical"
  | "vpn"
  | "virtual"
  | "system"
  | "tunnel"
  | "filter";

export interface NetworkInterface {
  name: string;
  friendlyName: string;
  kind: InterfaceKind;
  state: InterfaceState;
  addresses: InterfaceAddress[];
  dnsServers: string[];
  dnsSuffix: string | null;
  mtu: number | null;
  ifIndex: number;
  physical: boolean;
  mac: string | null;
  gateway: string | null;
  ipv6Gateway: string | null;
  rxBytes: number | null;
  txBytes: number | null;
  linkSpeedMbps: number | null;
  category: InterfaceCategory;
  description: string;
  ifType: number;
  tunnelType: string | null;
}

export interface RouteEntry {
  destination: string;
  prefixLen: number;
  gateway: string | null;
  interfaceIndex: number;
  interfaceName: string;
  metric: number;
}

export interface RouteLookupResult {
  destination: string;
  matchedRoute: RouteEntry;
  interfaceName: string;
  table?: string | null;
}

export function formatKind(kind: InterfaceKind): string {
  if (typeof kind === "string") {
    switch (kind) {
      case "ethernet": return "Ethernet";
      case "wifi": return "WiFi";
      case "wireGuard": return "WireGuard";
      case "openVpn": return "OpenVPN";
      case "xray": return "Xray";
      case "loopback": return "Loopback";
      default: return kind;
    }
  }
  return kind.other;
}

export const CATEGORY_ORDER: InterfaceCategory[] = [
  "physical",
  "vpn",
  "virtual",
  "system",
  "tunnel",
  "filter",
];

// IANA ifType values (https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib)
export const IF_TYPE_NAMES: Record<number, string> = {
  1: "Other",
  6: "Ethernet",
  7: "Bluetooth",
  9: "IEEE 802.11 (WiFi)",
  23: "PPP",
  24: "Software Loopback",
  53: "Prop Virtual (TAP/Wintun)",
  71: "IEEE 802.11 (WiFi)",
  106: "WWAN (Cellular)",
  131: "Tunnel",
  144: "IEEE 1394 (FireWire)",
};

export function ifTypeName(ifType: number): string {
  return IF_TYPE_NAMES[ifType] ?? `Type ${ifType}`;
}

export type TunnelBackend = "none" | "wireGuard" | "openVpn" | "xray";

export interface PolicyRoute {
  destination: string;
  metric: number;
  via?: string | null;
}

export interface DaemonStatus {
  state: "notRequired" | "notInstalled" | "notRunning" | "incompatible" | "ready" | "error";
  message: string;
}

export type AlwaysOnKind = "wireGuard" | "staticRoutes";

export interface AlwaysOnListResult {
  profiles: { kind: AlwaysOnKind; profileId: string; enabled: boolean }[];
  paused: boolean;
  supportedKinds: AlwaysOnKind[];
}

export interface AlwaysOnSetResult {
  stored: boolean;
  active: boolean;
}

export type DomainRouteTarget = "proxy" | "direct" | "block";

export interface DomainPolicy {
  domains: string[];
  target: DomainRouteTarget;
}

export interface SubscriptionMeta {
  url: string;
  hwid: string;
  endpointCount: number;
  activeIndex: number;
  refreshIntervalMinutes: number | null;
  lastRefreshAtUnix: number | null;
  lastRefreshError: string | null;
  userInfo: SubscriptionUserInfo | null;
  providerTitle: string | null;
  announce: string | null;
  supportUrl: string | null;
  webPageUrl: string | null;
  updateIntervalHours: number | null;
  skippedProtocols: string[];
}

export interface SubscriptionUserInfo {
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number | null;
  expiresAtUnix: number | null;
}

export interface SubscriptionEndpointInfo {
  name: string;
  active: boolean;
  protocol: string | null;
}

export interface SubscriptionRefreshResult {
  endpointCount: number;
  activeIndex: number;
  skippedCount: number;
  fallbackUsed: boolean;
  cleanupFailed: boolean;
}

export interface SubscriptionDelayResult {
  delayMs: number | null;
  error: string | null;
}

export interface WireGuardFields {
  privateKey: string;
  address: string;
  dns: string;
  peerPublicKey: string;
  peerEndpoint: string;
  allowedIps: string;
  presharedKey: string;
  persistentKeepalive: number | null;
}

export type XrayMode = "socks" | "tun";

export interface Profile {
  id: string;
  name: string;
  backend: TunnelBackend;
  configPath: string;
  interfaceName: string;
  routes: PolicyRoute[];
  autoConnect: boolean;
  domainPolicies: DomainPolicy[];
  privateLanDirect: boolean;
  xraySocksPort: number | null;
  xrayHttpPort: number | null;
  useSystemProxy: boolean;
  proxyBypass: string[];
  subscription: SubscriptionMeta | null;
  xrayMode: XrayMode;
  xrayTunInterface: string | null;
  xrayTunIp: string | null;
  /** Optional HTTPS URLs overriding the bundled geoip.dat / geosite.dat. */
  xrayGeoipUrl?: string | null;
  xrayGeositeUrl?: string | null;
}

export type TunnelState = "stopped" | "running" | "failed";

export interface TunnelStatus {
  profileId: string;
  state: TunnelState;
  message: string | null;
  /** Live kernel interface name reported by the daemon when running. */
  interfaceName?: string | null;
}

export interface AutoConnectResult {
  failedCount: number;
  startupFailed: boolean;
}

export type LogLevel = "info" | "warn" | "error";
export type LogSource = "app" | "daemon";

export interface LogEvent {
  tsUnix: number;
  level: LogLevel;
  source: LogSource;
  message: string;
}

export interface AnalyzedRoute {
  destination: string;
  source: string;
}

export type OpenVpnPlanConflict =
  | "activeConnection"
  | "activeProbe"
  | "interfaceOccupied"
  | "stagingLeftover";

export interface OpenVpnPlan {
  profileId: string;
  owner: string;
  interfaceName: string;
  fallbackInterfaceName: string;
  stagingDir: string;
  configPath: string;
  managementSocket: string;
  conflicts: OpenVpnPlanConflict[];
}

export interface LocalListener {
  address: string;
  port: number;
  protocol: string;
}

export interface RemoteEndpoint {
  address: string;
  port: number | null;
  protocol: string;
}

export type ConflictKind = "routeOverlap" | "listenerCollision";

export interface ProfileConflict {
  kind: ConflictKind;
  message: string;
  otherProfileId: string | null;
  blocking: boolean;
}

export interface ConfigPeer {
  endpoint: RemoteEndpoint | null;
  routes: AnalyzedRoute[];
}

export interface ConfigField {
  field: string;
  value: string;
}

export interface ConfigAnalysis {
  profileId: string;
  osRoutes: AnalyzedRoute[];
  internalRoutes: AnalyzedRoute[];
  listeners: LocalListener[];
  endpoints: RemoteEndpoint[];
  domainPatterns: string[];
  warnings: string[];
  routeKnowledgeComplete: boolean;
  peers: ConfigPeer[];
  interfaceDetails: ConfigField[];
}

export interface ProfileInspection {
  analysis: ConfigAnalysis;
  conflicts: ProfileConflict[];
  managedConfig: boolean;
}

export type DiagnosticLevel = "healthy" | "warning" | "error";

export interface DiagnosticCheck {
  name: string;
  level: DiagnosticLevel;
  message: string;
}

export interface ProfileDiagnostics {
  profileId: string;
  status: TunnelStatus;
  inspection: ProfileInspection | null;
  checks: DiagnosticCheck[];
}

export type RecoveryIssueKind =
  | "survivingWireGuardService"
  | "ownedRoutes"
  | "missingOwnedRoutes"
  | "orphanRouteOwnership"
  | "statusCheckFailed"
  | "proxyOwnership";

export interface RecoveryIssue {
  kind: RecoveryIssueKind;
  profileId: string | null;
  message: string;
}

export interface RecoveryReport {
  issues: RecoveryIssue[];
  requiresElevation: boolean;
}

export interface PlannedRoute {
  destination: string;
  ownerProfileId: string;
  ownerName: string;
  source: string;
  interfaceName: string | null;
  metric: number | null;
  active: boolean;
}

export type RoutePlanDiffKind =
  | "missing"
  | "interfaceMismatch"
  | "exactCompetition";

export interface RoutePlanDiff {
  kind: RoutePlanDiffKind;
  destination: string;
  message: string;
  profileIds: string[];
}

export interface RouteMap {
  predicted: PlannedRoute[];
  effective: RouteEntry[];
  diffs: RoutePlanDiff[];
  warnings: string[];
  pushedRoutes: PlannedRoute[];
}

export type BackendExecutableSource = "autoDetected" | "configured" | "managed";

export interface BackendAvailability {
  backend: TunnelBackend;
  available: boolean;
  path: string | null;
  source: BackendExecutableSource | null;
  version: string | null;
  message: string;
}

export interface BackendInstallProgress {
  backend: TunnelBackend;
  stage:
    | "downloading"
    | "verifying"
    | "installing"
    | "validating"
    | "ready"
    | "cancelled";
  downloaded: number;
  total: number | null;
}

/** Daemon-enforced rule for when connecting a VPN asks for an admin password. */
export type VpnAuthMode = "noPrompt" | "fullTunnelOnly" | "always";

export interface PlatformCapabilities {
  os: string;
  systemProxy: boolean;
  wireguardStandardImport: boolean;
  managedXrayInstall: boolean;
  elevationRelaunch: boolean;
  appUpdates: boolean;
  executableExtensions: string[];
}

export interface ManagedXrayOffer {
  version: string;
  sourceUrl: string;
  sha256: string;
  maxDownloadBytes: number;
}

export interface BatchImportError {
  path: string;
  error: string;
}

export interface BatchImportResult {
  profiles: Profile[];
  errors: BatchImportError[];
}

export interface ExitIpEntry {
  name: string;
  ip: string | null;
  country: string | null;
  error: string | null;
}

export interface TailscalePeer {
  hostName: string;
  dnsName?: string | null;
  tailscaleIps: string[];
  /** Subnet routes this peer advertises (its own /32,/128 addresses excluded). */
  routes: string[];
  exitNode: boolean;
  exitNodeOption: boolean;
  online: boolean;
  os: string;
}

export interface TailscaleStatusResult {
  /** False when tailscaled is absent or unreachable — a state, not an error. */
  available: boolean;
  /** ipnstate BackendState verbatim: "Running", "Stopped", "NeedsLogin"… */
  backendState: string;
  tailnet?: string | null;
  magicDnsSuffix?: string | null;
  selfHostName?: string | null;
  selfDnsName?: string | null;
  selfIps: string[];
  exitNodeActive: boolean;
  peers: TailscalePeer[];
}

// ── Conditional rules (Linux daemon) ──────────────────────────────────

/** When a conditional rule's routes may be installed. */
export type RouteCondition = {
  kind: "interfaceAddressIn";
  /** Active while a physical uplink holds a global address inside this. */
  prefix: string;
};

export interface ConditionalRouteRule {
  id: string;
  name: string;
  enabled: boolean;
  condition: RouteCondition;
  routes: PolicyRoute[];
}

export type ConditionalRuleState = "disabled" | "inactive" | "active" | "error";

export interface ConditionalRuleStatus {
  state: ConditionalRuleState;
  /** Interface that satisfied the condition during the last evaluation. */
  matchedInterface?: string | null;
  appliedRoutes: number;
  detail?: string | null;
}

export interface ConditionalRuleEntry {
  rule: ConditionalRouteRule;
  status: ConditionalRuleStatus;
}

export interface CondRulesListResult {
  rules: ConditionalRuleEntry[];
}

export interface CondRulesPutResult {
  stored: boolean;
  status: ConditionalRuleStatus;
}

export interface CondRulesRemoveResult {
  removed: boolean;
}
