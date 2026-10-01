import AppKit
import Foundation
import SwiftUI
import Testing

@testable import NetworkOrchestrator

// Optional render acceptance: synthetic data only; no real window/network interaction.
@Test(.enabled(if: ProcessInfo.processInfo.environment["NETORCH_DESIGN_PREVIEWS"] != nil))
@MainActor func renderBothThemesAndAllPages() throws {
  guard let path = ProcessInfo.processInfo.environment["NETORCH_DESIGN_PREVIEWS"] else { return }
  let output = URL(fileURLWithPath: path, isDirectory: true)
  let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: temp) }
  let model = AppModel(dataDirectory: temp)
  let defaultsName = "netorch-language-preview-" + UUID().uuidString
  let defaults = try #require(UserDefaults(suiteName: defaultsName))
  let previousLocalizer = L10n.shared
  L10n.shared = LocalizationStore(defaults: defaults, systemLanguages: ["en"])
  defer {
    L10n.shared = previousLocalizer
    defaults.removePersistentDomain(forName: defaultsName)
  }
  let profiles: [[String: Any]] = [
    [
      "id": "design-wg", "name": "Work VPN", "backend": "wireGuard", "interfaceName": "utun4",
      "routes": [["destination": "10.20.0.0/16", "metric": 5]],
    ],
    [
      "id": "design-ovpn", "name": "Office", "backend": "openVpn", "interfaceName": "utun5",
      "routes": [],
    ],
    [
      "id": "design-xray", "name": "Personal proxy", "backend": "xray", "interfaceName": "",
      "routes": [], "xraySocksPort": 10808, "xrayHttpPort": 10809,
      "subscription": [
        "endpointCount": 2, "activeIndex": 0,
        "userInfo": [
          "uploadBytes": 0, "downloadBytes": 8_151_449_629, "expiresAtUnix": 1_802_708_026,
        ],
        "panel": [
          "title": "QA Panel",
          "announce": "Servers in Europe were updated. Use the Asia server if Europe is slow.",
          "supportUrl": "https://support.example.test/",
          "webPageUrl": "https://account.example.test/",
        ],
      ],
    ],
    [
      "id": "design-static", "name": "Local network", "backend": "none", "interfaceName": "en0",
      "routes": [["destination": "192.0.2.0/24", "metric": 5]],
    ],
  ]
  let interfaces: [[String: Any]] = [
    [
      "name": "en0", "friendlyName": "en0", "ifIndex": 4, "state": "up",
      "addresses": [["address": "192.0.2.10", "prefixLen": 24, "family": "Ipv4"]],
      "category": "physical", "kind": "ethernet", "physical": true,
      "description": "macOS network interface", "dnsServers": [], "mtu": 1500,
      "linkSpeedMbps": 1000, "rxBytes": 1_048_576, "txBytes": 524_288,
    ],
    [
      "name": "lo0", "friendlyName": "lo0", "ifIndex": 1, "state": "up",
      "addresses": [
        ["address": "127.0.0.1", "prefixLen": 8, "family": "Ipv4"],
        ["address": "::1", "prefixLen": 128, "family": "Ipv6"],
      ], "category": "system", "kind": "loopback", "physical": false,
      "description": "macOS network interface", "dnsServers": [],
    ],
  ]
  let routes: [[String: Any]] = [
    [
      "destination": "0.0.0.0", "prefixLen": 0, "gateway": "192.0.2.1", "interfaceIndex": 4,
      "interfaceName": "en0", "metric": 0,
    ],
    [
      "destination": "192.0.2.0", "prefixLen": 24, "interfaceIndex": 4, "interfaceName": "en0",
      "metric": 0,
    ],
    [
      "destination": "127.0.0.0", "prefixLen": 8, "interfaceIndex": 1, "interfaceName": "lo0",
      "metric": 0,
    ],
  ]
  let predicted: [[String: Any]] = [
    [
      "destination": "10.20.0.0/16", "ownerProfileId": "design-wg", "ownerName": "Work VPN",
      "interfaceName": "utun4", "active": false, "source": "profile policy", "metric": 5,
    ],
    [
      "destination": "192.0.2.0/24", "ownerProfileId": "design-static",
      "ownerName": "Local network", "interfaceName": "en0", "active": false,
      "source": "profile policy", "metric": 5,
    ],
  ]
  model.snapshot = try JSONDecoder().decode(
    Snapshot.self,
    from: JSONSerialization.data(withJSONObject: [
      "profiles": profiles, "interfaces": interfaces, "routes": routes,
      "routeMap": ["predicted": predicted, "warnings": [], "diffs": []],
    ]))
  model.capabilities = try JSONDecoder().decode(
    Capabilities.self,
    from: JSONSerialization.data(withJSONObject: [
      "os": "macos", "minimumOS": "27.0", "nativeUI": true, "networkMutations": false,
      "proxyConnections": true, "version": "Preview",
    ]))
  model.subscriptionEndpoints = [
    "design-xray": [
      SubscriptionEndpoint(name: "QA Europe", active: true),
      SubscriptionEndpoint(name: "QA Asia", active: false),
    ]
  ]
  model.runtime = RuntimeState(
    xrayInstalled: true, xrayVersion: "v26.7.28",
    statuses: [
      TunnelStatus(profileId: "design-xray", state: "running", message: nil),
      TunnelStatus(profileId: "design-wg", state: "stopped", message: nil),
    ], systemProxyOwner: "design-xray")
  model.primaryInterface = "en0"
  model.delays["design-xray"] = [0: UInt64?.some(142)]
  model.probing["design-xray"] = [1]
  model.inspections["design-wg"] = try JSONDecoder().decode(
    Inspection.self,
    from: JSONSerialization.data(withJSONObject: [
      "endpoints": [], "osRoutes": [], "internalRoutes": [], "listeners": [], "warnings": [],
      "routeKnowledgeComplete": true,
      "interfaceDetails": [
        ["field": "address", "value": "10.20.0.2/32"], ["field": "dns", "value": "10.20.0.1"],
      ],
      "peers": [
        [
          "endpoint": ["address": "vpn.example.invalid", "port": 51820, "protocol": "udp"],
          "routes": [["destination": "10.20.0.0/16", "source": "AllowedIPs"]],
        ]
      ],
    ]))
  for language in ["en", "ru"] {
    L10n.shared.preference = language
    for theme in [ColorScheme.dark, .light] {
      let name = theme == .dark ? "dark" : "light"
      let directory = output.appendingPathComponent(language, isDirectory: true)
        .appendingPathComponent(name, isDirectory: true)
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
      for section in Section.allCases {
        model.section = section
        model.selectedProfileID = section == .connections ? "design-xray" : nil
        let view = ContentView(model: model, loadsOnAppear: false).environment(\.colorScheme, theme)
          .frame(width: 1200, height: 754)
        try render(
          view, to: directory.appendingPathComponent(section.rawValue.lowercased() + ".png"))
      }
      model.section = .connections
      model.selectedProfileID = "design-wg"
      try render(
        ContentView(model: model, loadsOnAppear: false).environment(\.colorScheme, theme)
          .frame(width: 1200, height: 754),
        to: directory.appendingPathComponent("connections-wireguard.png"))
      let palette = AppPalette(scheme: theme)
      for tab in RouteTab.allCases {
        let view = ScrollView {
          RoutesView(model: model, initialTab: tab).padding(.horizontal, 28).padding(.vertical, 21)
        }.background(palette.app).foregroundStyle(palette.text)
          .environment(\.palette, palette).environment(\.colorScheme, theme)
          .font(.system(size: 14)).buttonStyle(TauriButtonStyle())
        try render(
          view,
          to: directory.appendingPathComponent(
            "routes-" + tab.rawValue.lowercased().replacingOccurrences(of: " ", with: "-") + ".png")
        )
      }
      for (filename, modal) in [
        ("add", ConnectionModal.add), ("import", .importConfig(nil)), ("static", .staticRoutes),
      ] {
        let view = ConnectionModalView(model: model, modal: modal, onClose: {}, onChoose: { _ in })
          .frame(maxWidth: .infinity, maxHeight: .infinity).background(palette.app)
          .foregroundStyle(palette.text).environment(\.palette, palette)
          .environment(\.colorScheme, theme).buttonStyle(TauriButtonStyle())
        try render(view, to: directory.appendingPathComponent("dialog-" + filename + ".png"))
      }
      let linkView = ImportConfigurationView(
        model: model, preferredBackend: "xray", onClose: {}, initialTab: "Link"
      )
      .frame(maxWidth: .infinity, maxHeight: .infinity).background(palette.app)
      .foregroundStyle(palette.text).environment(\.palette, palette)
      .environment(\.colorScheme, theme).buttonStyle(TauriButtonStyle())
      try render(linkView, to: directory.appendingPathComponent("dialog-import-link.png"))
      let subscriptionView = ImportConfigurationView(
        model: model, preferredBackend: nil, onClose: {}, initialTab: "Subscription"
      )
      .frame(maxWidth: .infinity, maxHeight: .infinity).background(palette.app)
      .foregroundStyle(palette.text).environment(\.palette, palette)
      .environment(\.colorScheme, theme).buttonStyle(TauriButtonStyle())
      try render(
        subscriptionView, to: directory.appendingPathComponent("dialog-import-subscription.png"))
    }
  }
}

@MainActor private func render<V: View>(_ view: V, to file: URL) throws {
  let host = NSHostingView(rootView: view.frame(width: 1200, height: 754))
  host.frame = NSRect(x: 0, y: 0, width: 1200, height: 754)
  host.layoutSubtreeIfNeeded()
  guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else {
    throw CocoaError(.fileWriteUnknown)
  }
  host.cacheDisplay(in: host.bounds, to: bitmap)
  guard let png = bitmap.representation(using: .png, properties: [:]) else {
    throw CocoaError(.fileWriteUnknown)
  }
  try png.write(to: file)
  #expect(bitmap.pixelsWide >= 1200)
  #expect(png.count > 5000)
}

@Test @MainActor func nativeVectorIconsArePackagedAndReadable() throws {
  for name in [
    "HomeIcon", "ProfileIcon", "NetworkIcon", "RouteIcon", "SettingsIcon", "ChevronIcon",
    "WireGuardIcon", "OpenVpnIcon", "XrayIcon", "StaticRoutesIcon", "ImportIcon", "CloseIcon",
  ] {
    let image = try #require(NativeIcon.load(name))
    #expect(image.size.width == 24)
    #expect(image.size.height == 24)
  }
}
