import AppKit
import Foundation
import Observation
import OSLog
import SystemConfiguration

@MainActor @Observable final class AppModel {
  let core: CoreBridge
  /// Separate channel for multi-second delay probes so status polling and
  /// edits never wait behind them.
  let probeCore: CoreBridge
  /// Last measured delay per profile and endpoint index; nil = no response.
  var delays: [String: [Int: UInt64?]] = [:]
  /// Endpoint indices still being measured, per profile.
  var probing: [String: Set<Int>] = [:]
  var refreshing = Set<String>()
  /// Exit-IP results per route: "direct" or a running profile id.
  var exitIPs: [String: [ExitIpEntry]] = [:]
  var checkingExitIP = Set<String>()
  var externalVPNs: [ExternalVpn] = []
  var switchingExternal = Set<String>()
  var snapshot: Snapshot?
  var capabilities: Capabilities?
  var section: Section = .home
  var search = ""
  /// User-facing error. Bridge errors are secret-free by design, so they are
  /// also mirrored to the unified log (Xcode console, Console.app).
  var error: String? {
    didSet { if let error { Self.log.error("\(error, privacy: .public)") } }
  }
  private static let log = Logger(subsystem: "com.netmanager.app.macos", category: "app")
  var busy = false
  var subscriptionEndpoints: [String: [SubscriptionEndpoint]] = [:]
  var importSkippedCount = 0
  var inspecting: Profile?
  var inspection: Inspection?
  var lookup: Lookup?
  var lookupDestination = ""
  var runtime: RuntimeState?
  var selectedProfileID: String?
  var inspections: [String: Inspection] = [:]
  var pending = Set<String>()
  var installingXray = false
  /// Interface carrying the system default route, e.g. `en0` or a VPN `utun9`.
  var primaryInterface: String?
  var notice: String?

  init(dataDirectory: URL? = nil) {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    // Dedicated native store; does not modify the Tauri app's data.
    let root =
      dataDirectory ?? ProcessInfo.processInfo.environment["NETORCH_MACOS_DATA_DIR"].map {
        URL(fileURLWithPath: $0)
      }
      ?? base.appendingPathComponent("com.netmanager.app.macos", isDirectory: true)
    core = CoreBridge(root: root)
    probeCore = CoreBridge(root: root)
    isDuplicate = !Self.acquireInstanceLock(root: root)
    connectionSets = Self.loadSets()
  }
  /// Another process already serves this data directory; this one must not
  /// touch the bridge (startup recovery would stop the other's connections).
  let isDuplicate: Bool
  private static var instanceLock: Int32 = -1
  private static func acquireInstanceLock(root: URL) -> Bool {
    try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let descriptor = open(root.appendingPathComponent(".instance.lock").path, O_CREAT | O_RDWR, 0o600)
    guard descriptor >= 0 else { return true }
    if flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
      close(descriptor)
      return false
    }
    instanceLock = descriptor
    return true
  }

  var connectionSets: [ConnectionSet] = []
  private static let setsKey = "connectionSets"
  private static func loadSets() -> [ConnectionSet] {
    guard let data = UserDefaults.standard.data(forKey: setsKey) else { return [] }
    return (try? JSONDecoder().decode([ConnectionSet].self, from: data)) ?? []
  }
  private func saveSets() {
    if let data = try? JSONEncoder().encode(connectionSets) {
      UserDefaults.standard.set(data, forKey: Self.setsKey)
    }
  }
  /// Saves the running connections as a set; an identical set is not duplicated.
  func saveCurrentSet(name: String) {
    let ids = (snapshot?.profiles ?? []).filter { isRunning($0) }.map(\.id)
    guard !ids.isEmpty else { return }
    let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
    connectionSets.append(
      ConnectionSet(id: UUID().uuidString, name: trimmed.isEmpty ? L10n.text("sets.label") : trimmed, profileIds: ids))
    saveSets()
  }
  func deleteSet(_ set: ConnectionSet) {
    connectionSets.removeAll { $0.id == set.id }
    saveSets()
  }
  /// Switch to exactly the set's connections among those this client can start.
  func applySet(_ set: ConnectionSet) async {
    for profile in snapshot?.profiles ?? [] where profile.startsWithoutHelper {
      let wanted = set.profileIds.contains(profile.id)
      if wanted != isRunning(profile) { await toggle(profile) }
    }
  }
  /// Moves a profile within its backend group (drag and drop or Move up/down).
  func move(_ profile: Profile, to target: Profile? = nil, by offset: Int = 0) async {
    var group = (snapshot?.profiles ?? []).filter { $0.backend == profile.backend }.map(\.id)
    guard let from = group.firstIndex(of: profile.id) else { return }
    group.remove(at: from)
    var to = from + offset
    if let target, let index = group.firstIndex(of: target.id) { to = index }
    group.insert(profile.id, at: max(0, min(group.count, to)))
    _ = await change("reorder", args: ["backend": profile.backend, "ids": group.joined(separator: ",")])
  }
  var profiles: [Profile] {
    (snapshot?.profiles ?? []).filter {
      search.isEmpty || $0.name.localizedCaseInsensitiveContains(search)
        || $0.kind.localizedCaseInsensitiveContains(search)
    }
  }
  var selectedProfile: Profile? {
    let all = snapshot?.profiles ?? []
    return all.first { $0.id == selectedProfileID } ?? profiles.first
  }
  func status(_ profile: Profile) -> TunnelStatus? {
    runtime?.statuses.first { $0.profileId == profile.id }
  }
  func isRunning(_ profile: Profile) -> Bool { status(profile)?.state == "running" }
  var activeCount: Int { runtime?.statuses.filter { $0.state == "running" }.count ?? 0 }
  var canStartConnections: Bool { capabilities?.proxyConnections ?? false }
  /// A packet-tunnel VPN (e.g. incy) owns the primary service, so macOS takes
  /// proxy settings from it and ignores ours on Wi-Fi/Ethernet.
  var systemProxyOverridden: Bool { primaryInterface?.hasPrefix("utun") ?? false }

  func refreshRuntime() async {
    guard !isDuplicate else { return }
    primaryInterface = Self.currentPrimaryInterface()
    do { runtime = try await core.call("runtime") } catch { runtime = nil }
    if let list: [ExternalVpn] = try? await core.call("external_vpns") { externalVPNs = list }
  }
  /// Connect or disconnect another app's VPN, as the VPN menu would.
  func setExternalVPN(_ vpn: ExternalVpn, connect: Bool) async {
    switchingExternal.insert(vpn.id)
    defer { switchingExternal.remove(vpn.id) }
    do {
      externalVPNs = try await core.call(
        "set_external_vpn", args: ["id": vpn.id, "connect": connect ? "true" : "false"])
      // Connecting takes a moment; pick up the settled state.
      try? await Task.sleep(for: .seconds(2))
      await refreshRuntime()
    } catch { self.error = error.localizedDescription }
  }
  func toggle(_ profile: Profile) async {
    guard !pending.contains(profile.id) else { return }
    pending.insert(profile.id)
    defer { pending.remove(profile.id) }
    do {
      runtime = try await core.call(
        isRunning(profile) ? "disconnect" : "connect", args: ["id": profile.id])
      error = nil
    } catch {
      self.error = error.localizedDescription
      await refreshRuntime()
    }
  }
  func setSystemProxy(_ profile: Profile, enabled: Bool) async {
    do {
      runtime = try await core.call(
        "set_system_proxy", args: ["id": profile.id, "enabled": enabled ? "true" : "false"])
      if enabled && systemProxyOverridden {
        notice = "native.proxyOverridden"
      }
    } catch { self.error = error.localizedDescription }
  }
  func installXray(archive: URL? = nil) async {
    installingXray = true
    defer { installingXray = false }
    do {
      let _: [String: Bool] = try await core.call(
        "install_xray", args: archive.map { ["archivePath": $0.path] } ?? [:])
      await refreshRuntime()
    } catch { self.error = error.localizedDescription }
  }
  func loadInspection(_ profile: Profile) async {
    guard inspections[profile.id] == nil else { return }
    if let result: Inspection = try? await core.call("inspect", args: ["id": profile.id]) {
      inspections[profile.id] = result
    }
  }
  /// Opens a separate Chrome profile that sends everything through this
  /// connection's SOCKS listener; DNS is resolved remotely by the proxy.
  func openBrowser(_ profile: Profile) {
    guard let port = profile.xraySocksPort else { return }
    let data = core.root.appendingPathComponent("browser", isDirectory: true)
      .appendingPathComponent(profile.id, isDirectory: true)
    try? FileManager.default.createDirectory(at: data, withIntermediateDirectories: true)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    process.arguments = [
      "-na", "Google Chrome", "--args", "--user-data-dir=\(data.path)",
      "--proxy-server=socks5://127.0.0.1:\(port)", "--no-first-run",
      "https://www.youtube.com/",
    ]
    do { try process.run() } catch { self.error = "native.browserFailed" }
  }
  func terminalProxyCommands(_ profile: Profile) -> String? {
    guard let socks = profile.xraySocksPort else { return nil }
    let http = profile.xrayHttpPort.map { "http://127.0.0.1:\($0)" } ?? "socks5h://127.0.0.1:\(socks)"
    return
      "export HTTP_PROXY=\(http) HTTPS_PROXY=\(http) ALL_PROXY=socks5h://127.0.0.1:\(socks) NO_PROXY=localhost,127.0.0.1,.local"
  }
  func copyTerminalProxy(_ profile: Profile) {
    guard let text = terminalProxyCommands(profile) else { return }
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
    notice = "native.copied"
  }
  /// Stops our Xray processes and rolls back the system proxy. Blocking: runs
  /// from applicationWillTerminate.
  nonisolated func shutdown() {
    if !isDuplicate { core.callSync("shutdown") }
  }

  nonisolated static func currentPrimaryInterface() -> String? {
    guard let store = SCDynamicStoreCreate(nil, "NetworkOrchestrator" as CFString, nil, nil),
      let value = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString)
        as? [String: Any]
    else { return nil }
    return value["PrimaryInterface"] as? String
  }

  func refresh() async {
    guard !busy, !isDuplicate else { return }
    busy = true
    defer { busy = false }
    do {
      if capabilities == nil { capabilities = try await core.call("capabilities") }
      snapshot = try await core.call("snapshot")
      var endpoints: [String: [SubscriptionEndpoint]] = [:]
      for profile in snapshot?.profiles ?? [] where profile.subscription != nil {
        endpoints[profile.id] = try await core.call(
          "subscription_endpoints", args: ["id": profile.id])
      }
      subscriptionEndpoints = endpoints
      inspections = [:]
      await refreshRuntime()
      error = nil
    } catch { self.error = error.localizedDescription }
  }
  func createStatic(name: String, interface: String, cidrs: String) async -> Bool {
    await change(
      "create_static",
      args: ["id": UUID().uuidString, "name": name, "interfaceName": interface, "cidrs": cidrs])
  }
  func importConfig(url: URL, backend: String, name: String) async -> Bool {
    let access = url.startAccessingSecurityScopedResource()
    defer { if access { url.stopAccessingSecurityScopedResource() } }
    return await change(
      "import", args: ["id": UUID().uuidString, "name": name, "backend": backend, "path": url.path])
  }
  func importShareLink(_ link: String, name: String) async -> Bool {
    await change("import_share_link", args: ["id": UUID().uuidString, "name": name, "link": link])
  }
  func rename(_ profile: Profile, name: String) async -> Bool {
    await change("rename", args: ["id": profile.id, "name": name])
  }
  func importSubscription(url: String, hwid: String, name: String) async -> Bool {
    guard !busy else { return false }
    busy = true
    importSkippedCount = 0
    error = nil
    do {
      let result: SubscriptionImportResult = try await core.call(
        "import_subscription",
        args: [
          "id": UUID().uuidString, "url": url.trimmingCharacters(in: .whitespacesAndNewlines),
          "hwid": hwid.trimmingCharacters(in: .whitespacesAndNewlines), "name": name,
        ])
      busy = false
      await refresh()
      importSkippedCount = result.skippedCount
      return true
    } catch {
      busy = false
      self.error = error.localizedDescription
      return false
    }
  }
  /// Stable per-device HWID, derived in the core from this Mac's hardware ID.
  func generateHWID() async -> String? {
    do {
      let value: String = try await core.call("generate_hwid")
      return value
    } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  /// Switching a running connection reconnects it on the new server.
  func switchEndpoint(_ profile: Profile, index: Int) async {
    guard !pending.contains(profile.id) else { return }
    pending.insert(profile.id)
    defer { pending.remove(profile.id) }
    _ = await change(
      "switch_subscription_endpoint", args: ["id": profile.id, "index": String(index)])
  }
  /// Name of the selected server of a subscription profile.
  func activeServer(_ profile: Profile) -> String? {
    guard let subscription = profile.subscription,
      let endpoints = subscriptionEndpoints[profile.id],
      endpoints.indices.contains(subscription.activeIndex)
    else { return nil }
    return profile.serverLabel(endpoints[subscription.activeIndex].name)
  }
  /// Probes every server, up to eight at once, publishing each result the
  /// moment it arrives so the list fills in live.
  func measureDelays(_ profile: Profile) async {
    let id = profile.id
    guard probing[id] == nil, let count = subscriptionEndpoints[id]?.count, count > 0 else {
      return
    }
    delays[id] = [:]
    probing[id] = Set(0..<count)
    defer { probing[id] = nil }
    let core = probeCore
    await withTaskGroup(of: (Int, Result<DelayResult, Error>).self) { group in
      var next = 0
      while next < min(8, count) {
        let index = next
        group.addTask {
          do {
            let result: DelayResult = try await core.callConcurrently(
              "measure_delay", args: ["id": id, "index": String(index)])
            return (index, .success(result))
          } catch { return (index, .failure(error)) }
        }
        next += 1
      }
      for await (index, outcome) in group {
        switch outcome {
        case .success(let result): delays[id, default: [:]][index] = .some(result.delayMs)
        case .failure(let failure):
          delays[id, default: [:]][index] = .some(nil)
          if failure.localizedDescription.hasPrefix("Install Xray") {
            self.error = failure.localizedDescription
          }
        }
        probing[id]?.remove(index)
        if next < count {
          let index = next
          group.addTask {
            do {
              let result: DelayResult = try await core.callConcurrently(
                "measure_delay", args: ["id": id, "index": String(index)])
              return (index, .success(result))
            } catch { return (index, .failure(error)) }
          }
          next += 1
        }
      }
    }
  }
  /// Re-fetches a subscription. The download runs off the core actor (the
  /// bridge only locks the store to apply it), so the UI keeps polling.
  func refreshSubscription(_ profile: Profile, quiet: Bool = false) async {
    guard !refreshing.contains(profile.id) else { return }
    refreshing.insert(profile.id)
    defer { refreshing.remove(profile.id) }
    do {
      let outcome: RefreshOutcome = try await probeCore.callConcurrently(
        "refresh_subscription", args: ["id": profile.id])
      delays[profile.id] = nil
      if !quiet {
        notice = L10n.text("native.refreshed", ["count": String(outcome.endpointCount)])
      }
    } catch {
      if !quiet { self.error = error.localizedDescription }
    }
    await refresh()
  }
  func setRefreshInterval(_ profile: Profile, minutes: UInt32?) async {
    _ = await change(
      "set_refresh_interval",
      args: ["id": profile.id, "minutes": minutes.map(String.init) ?? ""])
  }
  /// Refreshes subscriptions whose interval elapsed. Running connections are
  /// left alone so a background refresh never drops traffic.
  func autoRefreshDue() async {
    let now = UInt64(Date().timeIntervalSince1970)
    for profile in snapshot?.profiles ?? [] where !isRunning(profile) {
      guard let subscription = profile.subscription,
        let minutes = subscription.refreshIntervalMinutes
      else { continue }
      let last = subscription.lastRefreshAtUnix ?? 0
      if now >= last + UInt64(minutes) * 60 {
        await refreshSubscription(profile, quiet: true)
      }
    }
  }
  /// Toolbar refresh: re-fetch every subscription, then reload everything.
  func refreshAll() async {
    for profile in snapshot?.profiles ?? [] where profile.subscription != nil {
      await refreshSubscription(profile)
    }
    await refresh()
  }
  /// Checks the exit IP directly and through every running connection at
  /// once; each route's result appears as soon as its checkers finish.
  func checkExitIPs() async {
    let routes = ["direct"] + (snapshot?.profiles ?? []).filter { isRunning($0) }.map(\.id)
    exitIPs = exitIPs.filter { routes.contains($0.key) }
    let core = probeCore
    await withTaskGroup(of: (String, [ExitIpEntry]?).self) { group in
      for route in routes where !checkingExitIP.contains(route) {
        checkingExitIP.insert(route)
        group.addTask {
          let entries: [ExitIpEntry]? = try? await core.callConcurrently(
            "check_exit_ip", args: ["via": route])
          return (route, entries)
        }
      }
      for await (route, entries) in group {
        exitIPs[route] = entries ?? []
        checkingExitIP.remove(route)
      }
    }
  }
  func connectionLog(_ profile: Profile) async -> String {
    (try? await core.call("log", args: ["id": profile.id]) as String) ?? ""
  }
  func importLog() async -> String {
    (try? await core.call("import_log") as String) ?? ""
  }
  /// Saves the rule sets and DNS options; a running connection restarts to apply them.
  func setRoutingRules(_ profile: Profile, options: RoutingOptions) async -> Bool {
    var args = options.bridgeArgs
    args["id"] = profile.id
    return await change("set_routing_rules", args: args)
  }
  func routingOptions(_ profile: Profile) async -> RoutingOptions? {
    try? await core.call("routing_options", args: ["id": profile.id])
  }
  /// Parses a Happ/Incy export without touching the profile.
  func parseHappRouting(_ payload: String) async -> HappRouting? {
    do { return try await core.call("parse_happ_routing", args: ["payload": payload]) } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  /// Replays the draft rules for one host or IP, offline.
  func checkRoute(_ target: String, options: RoutingOptions) async -> RouteCheckResult? {
    var args = options.bridgeArgs
    args["target"] = target
    do { return try await core.call("check_route", args: args) } catch {
      self.error = error.localizedDescription
      return nil
    }
  }
  func remove(_ profile: Profile) async { _ = await change("delete", args: ["id": profile.id]) }
  private func change(_ method: String, args: [String: String]) async -> Bool {
    guard !busy else { return false }
    busy = true
    do {
      let _: [Profile] = try await core.call(method, args: args)
      busy = false
      await refresh()
      return true
    } catch {
      busy = false
      self.error = error.localizedDescription
      return false
    }
  }
  func inspect(_ profile: Profile) async {
    inspecting = profile
    inspection = nil
    do { inspection = try await core.call("inspect", args: ["id": profile.id]) } catch {
      self.error = error.localizedDescription
    }
  }
  func lookupRoute() async {
    lookup = nil
    do {
      lookup = try await core.call(
        "lookup",
        args: ["destination": lookupDestination.trimmingCharacters(in: .whitespacesAndNewlines)])
    } catch { self.error = error.localizedDescription }
  }
}
