import Foundation
import Testing

@testable import NetworkOrchestrator

private func profile(_ backend: String, wait: Bool? = nil) throws -> Profile {
  var json: [String: Any] = [
    "id": "st", "name": "Static", "backend": backend, "interfaceName": "en7", "routes": [],
  ]
  if let wait { json["waitForInterface"] = wait }
  return try JSONDecoder().decode(Profile.self, from: JSONSerialization.data(withJSONObject: json))
}

@MainActor private func model(_ capabilities: [String]?) throws -> AppModel {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  model.capabilities = try JSONDecoder().decode(
    Capabilities.self,
    from: JSONSerialization.data(withJSONObject: [
      "os": "macos", "minimumOS": "27.0", "nativeUI": true, "networkMutations": false,
      "proxyConnections": true, "version": "T",
    ]))
  if let capabilities {
    model.helperStatus = try JSONDecoder().decode(
      HelperStatus.self,
      from: JSONSerialization.data(withJSONObject: [
        "reachable": true, "denied": false, "version": "1", "capabilities": capabilities,
      ]))
  }
  return model
}

@Test func onlyTheRouteBackendIsStatic() throws {
  #expect(try profile("none").isStatic)
  for other in ["xray", "wireGuard", "openVpn"] { #expect(try !profile(other).isStatic) }
}

@Test func aStaticProfileNeedsTheHelperButCreatesNoTunnel() throws {
  let st = try profile("none")
  #expect(st.needsHelper && !st.runsTunnel && st.helperCapability == "net.intent.set")
  let wg = try profile("wireGuard")
  #expect(wg.needsHelper && wg.runsTunnel)
  #expect(!(try profile("xray")).needsHelper)
}

@Test @MainActor func aStaticProfileStartsOnlyWhenTheHelperOffersIntents() throws {
  let st = try profile("none")
  #expect(try !model(nil).canStart(st))
  #expect(try model(nil).canTryStart(st))  // pressing it offers to install the helper
  #expect(try !model(["xray.connect"]).canStart(st))  // an older helper
  #expect(try model(["net.intent.set"]).canStart(st))
}

@Test @MainActor func startingAStaticProfileWithoutTheHelperOffersToInstallIt() async throws {
  let model = try model(nil)
  await model.toggle(try profile("none"))
  #expect(model.helperPrompt && model.error == nil)
}

@Test func theWaitFlagDecodesAndDefaultsToOff() throws {
  #expect(try profile("none", wait: true).waitsForInterface)
  #expect(try !profile("none", wait: false).waitsForInterface)
  #expect(try !profile("none").waitsForInterface)
}

@Test func theIntentsOfStaticProfilesBelongToTheirConnectionSwitch() throws {
  func intent(_ id: String) throws -> RouteIntent {
    let json: [String: Any] = [
      "id": id, "destinations": ["192.0.2.0/24"], "path": ["kind": "direct"], "metric": 5,
      "enabled": true, "status": "effective", "detail": "", "installed": 1, "wanted": 1,
    ]
    return try JSONDecoder().decode(RouteIntent.self, from: JSONSerialization.data(withJSONObject: json))
  }
  #expect(try intent("static-office").isProfileOwned)
  #expect(try !intent("office").isProfileOwned)
}

@MainActor private func isolatedModel() -> AppModel {
  AppModel(
    dataDirectory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
}

@MainActor @Test func aStaticProfileCanCarryGatewaysAndAnEndpointBypass() async throws {
  let model = isolatedModel()
  let saved = await model.createStatic(
    name: "External", interface: "utun4", cidrs: "10.0.0.0/8\n192.0.2.0/24 via 10.9.0.1",
    bypass: "203.0.113.7, vpn.example")
  #expect(saved && model.error == nil)
  #expect(model.snapshot?.profiles.first?.isStatic == true)
  // Every route names its gateway: no interface is needed.
  let gatewayOnly = await model.createStatic(
    name: "Gateway", interface: "", cidrs: "198.51.100.0/24 via 10.9.0.1")
  #expect(gatewayOnly)
}

@MainActor @Test func aStaticProfileThatCouldNeverConnectIsRefusedWithTheReason() async throws {
  let model = isolatedModel()
  let saved = await model.createStatic(name: "Bare", interface: "", cidrs: "192.0.2.0/24")
  #expect(!saved)
  #expect(model.error?.contains("interface") == true)
  #expect(model.snapshot?.profiles.isEmpty ?? true)
}
