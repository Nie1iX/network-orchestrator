import Foundation
import Testing

@testable import NetworkOrchestrator

private func interface(_ name: String, state: String = "up") throws -> NetworkInterface {
  let json: [String: Any] = [
    "name": name, "friendlyName": name, "ifIndex": 7, "state": state, "addresses": [],
    "category": "physical", "kind": "ethernet", "physical": true, "description": "",
    "dnsServers": [],
  ]
  return try JSONDecoder().decode(
    NetworkInterface.self, from: JSONSerialization.data(withJSONObject: json))
}

@MainActor private func model(capabilities: [String], reachable: Bool = true) throws -> AppModel {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  model.helperStatus = try JSONDecoder().decode(
    HelperStatus.self,
    from: JSONSerialization.data(withJSONObject: [
      "reachable": reachable, "denied": false, "version": "1", "capabilities": capabilities,
    ]))
  return model
}

@Test @MainActor func switchingNeedsAHelperThatOffersIt() throws {
  let wifi = try interface("en0")
  #expect(try model(capabilities: ["link.set_state"]).canSwitch(wifi))
  #expect(try !model(capabilities: ["xray.connect"]).canSwitch(wifi))  // an older helper
  #expect(try !model(capabilities: ["link.set_state"], reachable: false).canSwitch(wifi))
  let none = AppModel(
    dataDirectory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
  #expect(!none.canSwitch(wifi))
}

@Test @MainActor func loopbackAndTheAppsOwnTunnelsCannotBeSwitched() throws {
  let model = try model(capabilities: ["link.set_state"])
  #expect(!model.canSwitch(try interface("lo0")))
  model.runtime = try JSONDecoder().decode(
    RuntimeState.self,
    from: JSONSerialization.data(withJSONObject: [
      "xrayInstalled": true, "xrayVersion": "v", "systemProxyOwner": NSNull(),
      "statuses": [["profileId": "p", "state": "running", "interfaceName": "utun9"]],
    ]))
  #expect(!model.canSwitch(try interface("utun9")))
  #expect(model.canSwitch(try interface("utun3")))
}

@Test @MainActor func turningOffTheInterfaceWithTheDefaultRouteGetsTheStrongerWarning() throws {
  let model = try model(capabilities: ["link.set_state"])
  model.primaryInterface = "en0"
  #expect(model.switchOffWarning(try interface("en0")) == "native.link.offDefault")
  #expect(model.switchOffWarning(try interface("en7")) == "native.link.off")
  model.primaryInterface = nil
  #expect(model.switchOffWarning(try interface("en0")) == "native.link.off")
}
