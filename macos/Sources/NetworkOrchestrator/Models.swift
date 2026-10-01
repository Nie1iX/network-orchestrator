import Foundation

struct Capabilities: Decodable, Sendable {
  let os: String
  let minimumOS: String
  let nativeUI: Bool
  let networkMutations: Bool
  let proxyConnections: Bool?
  let version: String
}

struct TunnelStatus: Decodable, Sendable {
  let profileId: String
  let state: String
  let message: String?
}
struct RuntimeState: Decodable, Sendable {
  let xrayInstalled: Bool
  let xrayVersion: String
  let statuses: [TunnelStatus]
  let systemProxyOwner: String?
}

struct Profile: Decodable, Identifiable, Sendable {
  let id: String
  let name: String
  let backend: String
  let interfaceName: String
  let routes: [PolicyRoute]
  let xraySocksPort: UInt16?
  let xrayHttpPort: UInt16?
  let subscription: SubscriptionMeta?
  let xrayMode: String?
  var domainPolicies: [DomainPolicy]? = nil
  var privateLanDirect: Bool? = nil
  /// Rule lines of one target (block / proxy / direct), comments included.
  func rules(_ target: String) -> [String] {
    (domainPolicies ?? []).filter { $0.target == target }.flatMap(\.domains)
  }
  /// Name shown for the profile: a generated "{provider} - {server}" name
  /// reads as the provider group, a user-chosen name is shown as typed.
  var groupName: String {
    guard let title = subscription?.providerTitle, !title.isEmpty,
      name == title || name.hasPrefix(title + " - ")
    else { return name }
    return title
  }
  /// A server name without the provider prefix the panel repeats on each.
  func serverLabel(_ server: String) -> String {
    guard let title = subscription?.providerTitle, !title.isEmpty else { return server }
    for separator in [" - ", " – ", " — ", " | "] where server.hasPrefix(title + separator) {
      return String(server.dropFirst(title.count + separator.count))
    }
    return server
  }
  /// Xray in loopback SOCKS/HTTP mode is the only kind this client can start
  /// without the privileged helper.
  var startsWithoutHelper: Bool { backend == "xray" && (xrayMode ?? "socks") == "socks" }
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

struct SubscriptionMeta: Decodable, Sendable {
  let endpointCount: Int
  let activeIndex: Int
  let userInfo: SubscriptionUsage?
  var refreshIntervalMinutes: UInt32? = nil
  var lastRefreshAtUnix: UInt64? = nil
  var lastRefreshError: String? = nil
  /// What the provider announces about the subscription (response headers).
  let providerTitle: String?
  let announce: String?
  let supportUrl: String?
  let webPageUrl: String?
  let updateIntervalHours: UInt32?
  let skippedProtocols: [String]?
}
struct DomainPolicy: Decodable, Sendable {
  let domains: [String]
  let target: String
}
struct SubscriptionUsage: Decodable, Sendable {
  let uploadBytes: UInt64
  let downloadBytes: UInt64
  let totalBytes: UInt64?
  let expiresAtUnix: UInt64?
}
struct DelayResult: Decodable, Sendable {
  let index: Int
  let delayMs: UInt64?
}
struct RefreshOutcome: Decodable, Sendable {
  let endpointCount: Int
  let activeIndex: Int
  let skippedCount: Int
  let fallbackUsed: Bool
}
struct SubscriptionEndpoint: Decodable, Sendable {
  let name: String
  let active: Bool
  var `protocol`: String? = nil
}
struct SubscriptionImportResult: Decodable, Sendable {
  let profiles: [Profile]
  let skippedCount: Int
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
struct RemoteEndpoint: Decodable, Sendable {
  let address: String
  let port: UInt16?
  var label: String { port.map { "\(address):\($0)" } ?? address }
}
struct ConfigPeer: Decodable, Sendable {
  let endpoint: RemoteEndpoint?
  let routes: [AnalyzedRoute]
}
struct ConfigField: Decodable, Sendable {
  let field: String
  let value: String
}
struct Inspection: Decodable, Sendable {
  let endpoints: [RemoteEndpoint]
  let peers: [ConfigPeer]
  let interfaceDetails: [ConfigField]
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

struct ExitIpEntry: Decodable, Sendable {
  let name: String
  let ip: String?
  let country: String?
  let error: String?
}

/// A VPN configured by another app (e.g. incy), toggled with `scutil --nc`.
struct ExternalVpn: Decodable, Identifiable, Sendable {
  let id: String
  let name: String
  let state: String
  let provider: String?
  let enabled: Bool
}

/// A saved combination of connections restored in one click (kept in
/// UserDefaults, like the web client's localStorage sets).
struct ConnectionSet: Codable, Identifiable, Sendable, Equatable {
  var id: String
  var name: String
  var profileIds: [String]
}
