import Foundation
import Testing

@testable import NetworkOrchestrator

private func profile(_ backend: String, mode: String?) throws -> Profile {
  var json: [String: Any] = [
    "id": "p", "name": "P", "backend": backend, "interfaceName": "", "routes": [],
  ]
  if let mode { json["xrayMode"] = mode }
  return try JSONDecoder().decode(Profile.self, from: JSONSerialization.data(withJSONObject: json))
}

private func helper(_ capabilities: [String], reachable: Bool = true) throws -> HelperStatus {
  try JSONDecoder().decode(
    HelperStatus.self,
    from: JSONSerialization.data(withJSONObject: [
      "reachable": reachable, "denied": false, "version": "1", "capabilities": capabilities,
    ]))
}

@MainActor private func model(_ helperStatus: HelperStatus?) throws -> AppModel {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  model.capabilities = try JSONDecoder().decode(
    Capabilities.self,
    from: JSONSerialization.data(withJSONObject: [
      "os": "macos", "minimumOS": "27.0", "nativeUI": true, "networkMutations": false,
      "proxyConnections": true, "version": "T",
    ]))
  model.helperStatus = helperStatus
  return model
}

@Test @MainActor func tunnelProfilesStartOnlyWhenTheHelperServesThem() throws {
  let tun = try profile("xray", mode: "tun")
  let socks = try profile("xray", mode: "socks")
  let wireGuard = try profile("wireGuard", mode: nil)
  #expect(tun.isTun && !socks.isTun && !wireGuard.isTun)

  let without = try model(nil)
  #expect(!without.canStart(tun))
  #expect(without.canStart(socks))
  #expect(!without.canStart(wireGuard))

  let unreachable = try model(try helper([], reachable: false))
  #expect(!unreachable.canStart(tun))

  let oldHelper = try model(try helper(["owned.list"]))
  #expect(!oldHelper.canStart(tun))

  let ready = try model(try helper(["owned.list", "xray.connect"]))
  #expect(ready.canStart(tun) && ready.canStart(socks))
  #expect(!ready.canStart(wireGuard))
}

@Test @MainActor func ownTunnelIsNotReportedAsAForeignVpn() throws {
  let model = try model(try helper(["xray.connect"]))
  model.primaryInterface = "utun10"
  #expect(model.systemProxyOverridden)  // someone else's tunnel
  model.runtime = RuntimeState(
    xrayInstalled: true, xrayVersion: "v",
    statuses: [
      TunnelStatus(profileId: "p", state: "running", message: nil, interfaceName: "utun10")
    ], systemProxyOwner: nil)
  #expect(!model.systemProxyOverridden)  // ours
  model.primaryInterface = "utun4"
  #expect(model.systemProxyOverridden)
  model.primaryInterface = "en0"
  #expect(!model.systemProxyOverridden)
}

@Test @MainActor func startingTunWithoutTheHelperOffersToInstallIt() async throws {
  let tun = try profile("xray", mode: "tun")
  let without = try model(nil)
  #expect(without.canTryStart(tun) && !without.canStart(tun))
  #expect(!without.helperPrompt)
  await without.toggle(tun)
  #expect(without.helperPrompt)  // asks instead of failing
  #expect(without.error == nil)

  let ready = try model(try helper(["xray.connect"]))
  #expect(ready.canTryStart(tun))
  let wireGuard = try profile("wireGuard", mode: nil)
  #expect(!ready.canTryStart(wireGuard))
}

@Test func helperBuildIsNilOutsideAnAppBundle() {
  // The test runner has no bundled helper, so no registration is ever retired.
  #expect(AppModel.currentHelperBuild() == nil)
}
