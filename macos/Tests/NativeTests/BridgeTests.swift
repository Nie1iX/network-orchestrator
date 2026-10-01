import Foundation
import Testing

@testable import NetworkOrchestrator

@Test func nativeSubscriptionRejectsInvalidUrlsWithoutPersistingAnything() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let core = CoreBridge(root: directory)
  do {
    let _: SubscriptionImportResult = try await core.call(
      "import_subscription",
      args: [
        "id": "invalid-sub", "url": "file:///synthetic-private-token", "hwid": "", "name": "",
      ])
    Issue.record("A non-HTTP subscription URL must be rejected")
  } catch {
    #expect(error.localizedDescription.contains("HTTP or HTTPS"))
    #expect(!error.localizedDescription.contains("synthetic-private-token"))
  }
  #expect(!FileManager.default.fileExists(atPath: directory.path))
  let result = try JSONDecoder().decode(
    SubscriptionImportResult.self,
    from: Data(
      #"{"profiles":[{"id":"sub","name":"Lab","backend":"xray","interfaceName":"","routes":[],"subscription":{"endpointCount":2,"activeIndex":1}}],"skippedCount":1}"#
        .utf8))
  #expect(result.profiles.first?.subscription?.activeIndex == 1)
  #expect(result.profiles.first?.subscription?.endpointCount == 2)
  #expect(result.skippedCount == 1)
}

@Test func nativeShareLinkImportCanBeInspectedWithoutActivatingNetworking() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let core = CoreBridge(root: directory)
  let profiles: [Profile] = try await core.call(
    "import_share_link",
    args: [
      "id": "share-link", "name": "",
      "link": "vless://synthetic-private-id@node.test:443?security=tls#Swift%20Node",
    ])
  let profile = try #require(profiles.first)
  #expect(profile.name == "Swift Node")
  #expect(profile.kind == "Xray")
  let inspection: Inspection = try await core.call("inspect", args: ["id": profile.id])
  #expect(inspection.listeners.count == 2)
  #expect(inspection.listeners.allSatisfy { $0.address == "127.0.0.1" })
  let saved: [Profile] = try await core.call("profiles")
  #expect(saved.first?.name == "Swift Node")
}

@Test func nativeBridgePreservesProfilesAcrossRequests() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let core = CoreBridge(root: directory)
  let caps: Capabilities = try await core.call("capabilities")
  #expect(caps.os == "macos")
  #expect(caps.minimumOS == "27.0")
  #expect(caps.nativeUI)
  #expect(!caps.networkMutations)
  let _: [Profile] = try await core.call(
    "create_static",
    args: ["id": "swift-test", "name": "Lab", "interfaceName": "en0", "cidrs": "10.77.0.0/24"])
  let profiles: [Profile] = try await core.call("profiles")
  #expect(profiles.count == 1)
  #expect(profiles[0].name == "Lab")
  #expect(profiles[0].routes[0].destination == "10.77.0.0/24")
}

@Test func nativeMutationsFailWithAProviderMessage() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let core = CoreBridge(root: directory)
  do {
    let _: [Profile] = try await core.call("apply_routes")
    Issue.record("Route mutations must stay with the privileged helper")
  } catch {
    #expect(error.localizedDescription.contains("VPN provider"))
  }
  do {
    let _: RuntimeState = try await core.call("connect", args: ["id": "missing"])
    Issue.record("Connecting an unknown profile must fail")
  } catch {
    #expect(error.localizedDescription == "Profile not found")
  }
}

@Test func nativeSnapshotAndLookupDecodeRealDarwinNetworkData() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let core = CoreBridge(root: directory)
  let snapshot: Snapshot = try await core.call("snapshot")
  #expect(snapshot.networkError == nil)
  #expect(snapshot.interfaces.contains { $0.name == "lo0" && $0.ifIndex > 0 })
  #expect(!snapshot.routes.isEmpty)
  let lookup: Lookup = try await core.call("lookup", args: ["destination": "127.0.0.1"])
  #expect(lookup.interfaceName == "lo0")
}

@Test func nativeImportAndInspectionDecodeTheSharedAnalysis() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: directory) }
  let source = directory.appendingPathComponent("synthetic.json")
  try Data(
    #"{"inbounds":[{"listen":"127.0.0.1","port":10890,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}"#
      .utf8
  ).write(to: source)
  let core = CoreBridge(root: directory.appendingPathComponent("vault-root"))
  let profiles: [Profile] = try await core.call(
    "import",
    args: ["id": "fixture", "name": "Synthetic Xray", "backend": "xray", "path": source.path])
  #expect(profiles.first?.kind == "Xray")
  let inspection: Inspection = try await core.call("inspect", args: ["id": "fixture"])
  #expect(inspection.listeners.first?.address == "127.0.0.1")
  #expect(inspection.listeners.first?.port == 10890)
}
