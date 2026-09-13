export type InterfaceKind =
  | "ethernet"
  | "wifi"
  | "wireGuard"
  | "openVpn"
  | "xray"
  | "loopback"
  | { other: string };

export type InterfaceState = "Up" | "Down" | "Unknown";

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

export const CATEGORY_LABELS: Record<InterfaceCategory, string> = {
  physical: "Physical",
  vpn: "VPN",
  virtual: "Virtual",
  system: "System",
  tunnel: "Tunnel",
  filter: "Filter",
};

export const CATEGORY_DESCRIPTIONS: Record<InterfaceCategory, string> = {
  physical: "Real network adapters: Ethernet, Wi-Fi, Bluetooth",
  vpn: "VPN tunnels: WireGuard, OpenVPN, Xray, Tailscale",
  virtual: "Virtual switches and bridges: Hyper-V, WSL, Wi-Fi Direct",
  system: "OS-internal: Loopback, Kernel Debug",
  tunnel: "OS tunnel pseudo-interfaces: Teredo, 6to4, WAN Miniports",
  filter: "Filter drivers: WFP, Npcap, QoS — sub-interfaces of real adapters",
};

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

export type TunnelBackend = "wireGuard" | "openVpn" | "xray";

export interface PolicyRoute {
  destination: string;
  metric: number;
}

export type DomainRouteTarget = "proxy" | "direct";

export interface DomainPolicy {
  domains: string[];
  target: DomainRouteTarget;
}

export interface Profile {
  id: string;
  name: string;
  backend: TunnelBackend;
  configPath: string;
  interfaceName: string;
  routes: PolicyRoute[];
  autoConnect: boolean;
  domainPolicies: DomainPolicy[];
  xraySocksPort: number | null;
}

export type TunnelState = "stopped" | "running" | "failed";

export interface TunnelStatus {
  profileId: string;
  state: TunnelState;
  message: string | null;
}

export interface AnalyzedRoute {
  destination: string;
  source: string;
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

export interface ConfigAnalysis {
  profileId: string;
  osRoutes: AnalyzedRoute[];
  internalRoutes: AnalyzedRoute[];
  listeners: LocalListener[];
  endpoints: RemoteEndpoint[];
  domainPatterns: string[];
  warnings: string[];
  routeKnowledgeComplete: boolean;
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
