import Foundation
import Testing

@testable import NetworkOrchestrator

@Test func diagnosticsDecodeFromTheBridgeAnswer() throws {
  let json = #"""
    {"profileId":"p","status":{"profileId":"p","state":"running","message":null,"interfaceName":"utun5"},
     "inspection":null,
     "checks":[{"name":"Configuration","level":"healthy","message":"ok"},
               {"name":"Privileged helper","level":"error","message":"not running"},
               {"name":"Tunnel DNS","level":"warning","message":"not applied"}]}
    """#
  let report = try JSONDecoder().decode(ProfileDiagnostics.self, from: Data(json.utf8))
  #expect(report.checks.map(\.level) == [.healthy, .error, .warning])
  #expect(report.checks[1].name == "Privileged helper")
  #expect(report.status.interfaceName == "utun5")
}

@Test func theWorstLevelSummarisesAReport() throws {
  func report(_ levels: [String]) throws -> ProfileDiagnostics {
    let checks = levels.map { #"{"name":"n","level":"\#($0)","message":"m"}"# }.joined(separator: ",")
    let json =
      #"{"profileId":"p","status":{"profileId":"p","state":"stopped"},"inspection":null,"checks":[\#(checks)]}"#
    return try JSONDecoder().decode(ProfileDiagnostics.self, from: Data(json.utf8))
  }
  #expect(try report(["healthy", "healthy"]).worst == .healthy)
  #expect(try report(["healthy", "warning"]).worst == .warning)
  #expect(try report(["warning", "error", "healthy"]).worst == .error)
  #expect(try report([]).worst == .healthy)
  #expect(try report(["warning", "error", "warning"]).counts == DiagnosticCounts(warnings: 2, errors: 1))
}

@Test @MainActor func aLoopbackProfileIsDiagnosedThroughTheBridgeWithoutTouchingTheNetwork() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let core = CoreBridge(root: directory)
  let _: [Profile] = try await core.call(
    "import_share_link",
    args: [
      "id": "dg", "name": "",
      "link": "vless://synthetic-private-id@node.test:443?security=tls#Diag",
    ])
  let model = AppModel(dataDirectory: directory)
  model.snapshot = try await core.call("snapshot")
  let profile = try #require(model.snapshot?.profiles.first)
  let report = try #require(await model.diagnose(profile))
  #expect(report.profileId == "dg")
  #expect(report.checks.first?.name == "Configuration")
  // A fresh data directory has no Xray, and nothing is running.
  #expect(report.checks.first { $0.name == "Backend executable" }?.level == .error)
  #expect(report.checks.first { $0.name == "Tunnel status" }?.level == .warning)
  #expect(report.worst == .error)
  #expect(model.error == nil)
}

@Test @MainActor func aFailedDiagnosisReportsAnErrorInsteadOfCrashing() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  let ghost = try JSONDecoder().decode(
    Profile.self,
    from: Data(#"{"id":"ghost","name":"G","backend":"xray","interfaceName":"","routes":[]}"#.utf8))
  #expect(await model.diagnose(ghost) == nil)
  #expect(model.error == "Profile not found")
}
