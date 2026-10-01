import Foundation
import Testing

@testable import NetworkOrchestrator

/// Opt-in live acceptance: downloads the pinned Xray into a temporary data
/// directory, runs a loopback VLESS server with it, connects through the
/// bridge and fetches a URL via the client's SOCKS port. Never touches the
/// system proxy, routes or the user's profiles. The loopback server resolves
/// names over DoH: a fake-IP VPN resolver (240.0.0.0/4) would be refused by
/// Xray's freedom outbound as a reserved range.
///   NETORCH_LIVE_XRAY=https://www.youtube.com/ swift test --filter liveProxy
@Test(.enabled(if: ProcessInfo.processInfo.environment["NETORCH_LIVE_XRAY"] != nil))
func liveProxyConnectionCarriesTraffic() async throws {
  let target = ProcessInfo.processInfo.environment["NETORCH_LIVE_XRAY"] ?? ""
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer {
    if ProcessInfo.processInfo.environment["NETORCH_KEEP_LIVE_DIR"] == nil {
      try? FileManager.default.removeItem(at: directory)
    }
  }
  let core = CoreBridge(root: directory)
  // NETORCH_XRAY_ARCHIVE skips the download with a local official zip.
  let archive = ProcessInfo.processInfo.environment["NETORCH_XRAY_ARCHIVE"] ?? ""
  let _: [String: Bool] = try await core.call("install_xray", args: ["archivePath": archive])
  let xray = directory.appendingPathComponent("backends/xray/v26.7.28/xray")

  let serverPort = 24443
  let uuid = UUID().uuidString.lowercased()
  let serverConfig = directory.appendingPathComponent("server.json")
  try Data(
    """
    {"log":{"loglevel":"info"},"inbounds":[{"listen":"127.0.0.1","port":\(serverPort),"protocol":"vless",
      "settings":{"clients":[{"id":"\(uuid)"}],"decryption":"none"},
      "streamSettings":{"network":"tcp","security":"none"}}],
     "dns":{"servers":["https://1.1.1.1/dns-query"]},
     "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]}
    """.utf8
  ).write(to: serverConfig)
  // A copy: startup recovery stops stale processes of the managed binary.
  let serverBinary = directory.appendingPathComponent("xray-server")
  try FileManager.default.copyItem(at: xray, to: serverBinary)
  let server = Process()
  server.executableURL = serverBinary
  server.arguments = ["run", "-c", serverConfig.path]
  let serverLog = directory.appendingPathComponent("server.log")
  FileManager.default.createFile(atPath: serverLog.path, contents: nil)
  let serverHandle = try FileHandle(forWritingTo: serverLog)
  server.standardOutput = serverHandle
  server.standardError = serverHandle
  try server.run()
  defer { server.terminate() }

  let link = "vless://\(uuid)@127.0.0.1:\(serverPort)?security=none&type=tcp#Loopback"
  let profiles: [Profile] = try await core.call(
    "import_share_link", args: ["id": "live", "name": "", "link": link])
  let profile = try #require(profiles.first { $0.id == "live" })
  let socks = try #require(profile.xraySocksPort)

  let running: RuntimeState = try await core.call("connect", args: ["id": "live"])
  #expect(running.statuses.first { $0.profileId == "live" }?.state == "running")

  // The loopback server needs a moment for its first DoH lookup.
  var code = ""
  var curlError = ""
  for attempt in 1...3 {
    try await Task.sleep(for: .seconds(attempt))
    let curl = Process()
    curl.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    curl.arguments = [
      "-sS", "-o", "/dev/null", "-m", "20", "-w", "%{http_code}",
      "--proxy", "socks5h://127.0.0.1:\(socks)", target,
    ]
    let output = Pipe()
    let errors = Pipe()
    curl.standardOutput = output
    curl.standardError = errors
    try curl.run()
    curl.waitUntilExit()
    code = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    curlError = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    if code != "000" { break }
  }
  print("live proxy HTTP status:", code)
  if !["200", "301", "302", "303"].contains(code) {
    print("curl:", curlError)
    let log: String = try await core.call("log", args: ["id": "live"])
    print("xray log:", log)
    print("data dir:", directory.path)
    print("server log:", (try? String(contentsOf: serverLog, encoding: .utf8)) ?? "")
  }
  #expect(["200", "301", "302", "303"].contains(code))

  // Delay probes are only offered for subscriptions; a single link is refused.
  do {
    let _: [DelayResult] = try await core.call("measure_delays", args: ["id": "live"])
    Issue.record("measure_delays must require a subscription")
  } catch {}
  let stopped: RuntimeState = try await core.call("disconnect", args: ["id": "live"])
  #expect(stopped.statuses.first { $0.profileId == "live" }?.state == "stopped")
  let _: [String: String] = try await core.call("shutdown")
}

/// Opt-in: imports a real subscription into a temporary directory and prints
/// only counts. NETORCH_LIVE_SUBSCRIPTION=https://… swift test --filter liveSubscription
@Test(.enabled(if: ProcessInfo.processInfo.environment["NETORCH_LIVE_SUBSCRIPTION"] != nil))
func liveSubscriptionImports() async throws {
  let url = ProcessInfo.processInfo.environment["NETORCH_LIVE_SUBSCRIPTION"] ?? ""
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let core = CoreBridge(root: directory)
  do {
    let result: SubscriptionImportResult = try await core.call(
      "import_subscription", args: ["id": "live-sub", "url": url, "hwid": "", "name": ""])
    let endpoints: [SubscriptionEndpoint] = try await core.call(
      "subscription_endpoints", args: ["id": "live-sub"])
    print(
      "live subscription: profiles=\(result.profiles.count) endpoints=\(endpoints.count)",
      "skipped=\(result.skippedCount)")
  } catch {
    print("live subscription error:", error.localizedDescription)
    throw error
  }
}

/// Opt-in: NETORCH_XRAY_ARCHIVE=/path/Xray-macos-arm64-v8a.zip NETORCH_LIVE_PING=1.
/// One reachable loopback server and three closed ports must yield results
/// one by one, with the in-flight set shrinking as they land.
@Test(.enabled(if: ProcessInfo.processInfo.environment["NETORCH_LIVE_PING"] != nil))
@MainActor func livePingPublishesResultsProgressively() async throws {
  let archive = ProcessInfo.processInfo.environment["NETORCH_XRAY_ARCHIVE"] ?? ""
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let model = AppModel(dataDirectory: directory)
  let _: [String: Bool] = try await model.core.call("install_xray", args: ["archivePath": archive])
  let xray = directory.appendingPathComponent("backends/xray/v26.7.28/xray")
  let serverBinary = directory.appendingPathComponent("xray-server")
  try FileManager.default.copyItem(at: xray, to: serverBinary)
  let uuid = UUID().uuidString.lowercased()
  let serverConfig = directory.appendingPathComponent("server.json")
  try Data(
    """
    {"inbounds":[{"listen":"127.0.0.1","port":24555,"protocol":"vless",
      "settings":{"clients":[{"id":"\(uuid)"}],"decryption":"none"},
      "streamSettings":{"network":"tcp","security":"none"}}],
     "dns":{"servers":["https://1.1.1.1/dns-query"]},
     "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]}
    """.utf8
  ).write(to: serverConfig)
  let server = Process()
  server.executableURL = serverBinary
  server.arguments = ["run", "-c", serverConfig.path]
  server.standardOutput = FileHandle.nullDevice
  server.standardError = FileHandle.nullDevice
  try server.run()
  defer { server.terminate() }
  let site = directory.appendingPathComponent("site", isDirectory: true)
  try FileManager.default.createDirectory(at: site, withIntermediateDirectories: true)
  let links = ["Loopback": 24555, "Closed A": 1, "Closed B": 2, "Closed C": 3].sorted { $0.key < $1.key }
    .map { "vless://\(uuid)@127.0.0.1:\($0.value)?security=none&type=tcp#\($0.key.replacingOccurrences(of: " ", with: "%20"))" }
  try Data(links.joined(separator: "\n").utf8).write(to: site.appendingPathComponent("sub"))
  let http = Process()
  http.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
  http.arguments = ["-m", "http.server", "24556", "--bind", "127.0.0.1", "--directory", site.path]
  http.standardOutput = FileHandle.nullDevice
  http.standardError = FileHandle.nullDevice
  try http.run()
  defer { http.terminate() }
  try await Task.sleep(for: .seconds(1))
  #expect(await model.importSubscription(url: "http://127.0.0.1:24556/sub", hwid: "", name: "Live"))
  let profile = try #require(model.snapshot?.profiles.first)
  var observations: [Int] = []
  let watcher = Task { @MainActor in
    while !Task.isCancelled {
      if let pending = model.probing[profile.id], observations.last != pending.count {
        observations.append(pending.count)
      }
      try? await Task.sleep(for: .milliseconds(20))
    }
  }
  await model.measureDelays(profile)
  watcher.cancel()
  let names = model.subscriptionEndpoints[profile.id]?.map(\.name) ?? []
  let results = model.delays[profile.id] ?? [:]
  print("live ping in-flight counts:", observations)
  print("live ping results:", names.indices.map { "\(names[$0])=\(results[$0].map { $0.map(String.init) ?? "none" } ?? "?")" })
  #expect(model.probing[profile.id] == nil)
  #expect(results.count == names.count)
  let loopback = try #require(names.firstIndex(of: "Loopback"))
  #expect((results[loopback] ?? nil) != nil)
  #expect(observations.count >= 2, "results should arrive progressively")
}
