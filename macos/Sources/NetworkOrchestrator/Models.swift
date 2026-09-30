import Foundation

struct Capabilities: Decodable, Sendable {
  let os: String
  let minimumOS: String
  let nativeUI: Bool
  let networkMutations: Bool
  let version: String
}

struct Profile: Decodable, Identifiable, Sendable {
  let id: String
  let name: String
  let backend: String
  let interfaceName: String
  let routes: [PolicyRoute]
  let xraySocksPort: UInt16?
  let xrayHttpPort: UInt16?
  var kind: String {
    switch backend {
    case "wireGuard": "WireGuard"
    case "openVpn": "OpenVPN"
    case "xray": "Xray"
    default: "Static routes"
    }
  }
  var symbol: String {
    switch backend {
    case "wireGuard": "shield.lefthalf.filled"
    case "openVpn": "lock.shield"
    case "xray": "network"
    default: "arrow.triangle.branch"
    }
  }
}

struct PolicyRoute: Decodable, Sendable {
  let destination: String
  let metric: UInt32
  let via: String?
}
struct NetworkAddress: Decodable, Sendable {
  let address: String
  let prefixLen: UInt8
  let family: String
}
enum InterfaceKindValue: Decodable, Sendable {
  case named(String)
  case other(String)
  init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer()
    if let name = try? value.decode(String.self) {
      self = .named(name)
    } else {
      self = .other(try value.decode([String: String].self)["other"] ?? "Other")
    }
  }
  var label: String {
    switch self {
    case .named(let value):
      value == "ethernet" ? "Ethernet" : value == "loopback" ? "Loopback" : value.capitalized
    case .other(let value): value
    }
  }
}
struct NetworkInterface: Decodable, Identifiable, Sendable {
  let name: String
  let friendlyName: String
  let ifIndex: UInt32
  let state: String
  let addresses: [NetworkAddress]
  let category: String
  let kind: InterfaceKindValue
  let physical: Bool
  let description: String
  let mtu: UInt32?
  let mac: String?
  let gateway: String?
  let ipv6Gateway: String?
  let dnsServers: [String]
  let dnsSuffix: String?
  let linkSpeedMbps: UInt64?
  let rxBytes: UInt64?
  let txBytes: UInt64?
  let tunnelType: String?
  var id: UInt32 { ifIndex }
}
struct Route: Decodable, Identifiable, Sendable {
  let destination: String
  let prefixLen: UInt8
  let gateway: String?
  let interfaceIndex: UInt32
  let interfaceName: String
  let metric: UInt32
  var cidr: String { "\(destination)/\(prefixLen)" }
  var id: String { "\(cidr)|\(interfaceIndex)|\(gateway ?? "")|\(metric)" }
}
struct PlannedRoute: Decodable, Sendable {
  let destination: String
  let ownerProfileId: String
  let ownerName: String
  let interfaceName: String?
  let active: Bool
  let source: String
  let metric: UInt32?
}
struct RouteDiff: Decodable, Sendable {
  let kind: String
  let destination: String
  let message: String
}
struct RouteMap: Decodable, Sendable {
  let predicted: [PlannedRoute]
  let warnings: [String]
  let diffs: [RouteDiff]
}
struct Snapshot: Decodable, Sendable {
  let profiles: [Profile]
  let interfaces: [NetworkInterface]
  let routes: [Route]
  let routeMap: RouteMap
  let networkError: String?
}
struct Lookup: Decodable, Sendable {
  let destination: String
  let matchedRoute: Route
  let interfaceName: String
}
struct AnalyzedRoute: Decodable, Sendable {
  let destination: String
  let source: String
}
struct Listener: Decodable, Sendable {
  let address: String
  let port: UInt16
  let `protocol`: String
}
struct Inspection: Decodable, Sendable {
  let osRoutes: [AnalyzedRoute]
  let internalRoutes: [AnalyzedRoute]
  let listeners: [Listener]
  let warnings: [String]
  let routeKnowledgeComplete: Bool
}

enum Section: String, CaseIterable, Identifiable {
  case home = "Home"
  case connections = "Connections"
  case network = "Network"
  case routes = "Routes"
  case settings = "Settings"
  var id: Self { self }
  var iconName: String {
    switch self {
    case .home: "HomeIcon"
    case .connections: "ProfileIcon"
    case .network: "NetworkIcon"
    case .routes: "RouteIcon"
    case .settings: "SettingsIcon"
    }
  }
  var symbol: String {
    switch self {
    case .home: "square.grid.2x2"
    case .connections: "shield.lefthalf.filled"
    case .network: "network"
    case .routes: "arrow.triangle.branch"
    case .settings: "gearshape"
    }
  }
}
