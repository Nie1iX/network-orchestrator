export type InterfaceKind =
  | "Ethernet"
  | "Wifi"
  | "WireGuard"
  | "OpenVpn"
  | "Xray"
  | "Loopback"
  | { Other: string };

export type InterfaceState = "Up" | "Down" | "Unknown";

export interface InterfaceAddress {
  address: string;
  prefixLen: number;
  family: "Ipv4" | "Ipv6";
}

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
    return kind;
  }
  return `Other: ${kind.Other}`;
}
