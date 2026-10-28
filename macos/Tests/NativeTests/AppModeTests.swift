import Foundation
import Testing

@testable import NetworkOrchestrator

private func profile(_ backend: String) throws -> Profile {
  try JSONDecoder().decode(
    Profile.self,
    from: JSONSerialization.data(withJSONObject: [
      "id": "p-\(backend)", "name": backend, "backend": backend, "interfaceName": "en7", "routes": [],
    ]))
}

@Test func anUnknownStoredModeIsCombined() {
  #expect(AppMode(stored: nil) == .combined)
  #expect(AppMode(stored: "bogus") == .combined)
  #expect(AppMode(stored: "orchestrator") == .orchestrator)
  #expect(AppMode(stored: "manager") == .manager)
}

@Test func onlyOrchestratorLocksManagedBackends() throws {
  for backend in ["xray", "wireGuard", "openVpn"] {
    let p = try profile(backend)
    #expect(AppMode.orchestrator.locks(p))
    #expect(!AppMode.combined.locks(p))
    #expect(!AppMode.manager.locks(p))
  }
  let route = try profile("none")
  for mode in AppMode.allCases { #expect(!mode.locks(route)) }
}

@Test func everyModeHasATitleKey() {
  #expect(Set(AppMode.allCases.map(\.titleKey)).count == 3)
}

@MainActor @Test func orchestratorModeBlocksStartingButNotStopping() throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  defer { model.appMode = .combined }
  model.capabilities = try JSONDecoder().decode(
    Capabilities.self,
    from: JSONSerialization.data(withJSONObject: [
      "os": "macos", "minimumOS": "27.0", "nativeUI": true, "networkMutations": false,
      "proxyConnections": true, "version": "T",
    ]))
  let wg = try profile("wireGuard")
  model.appMode = .orchestrator
  #expect(model.modeLocks(wg) && !model.canStart(wg) && !model.canTryStart(wg))
  model.appMode = .combined
  #expect(!model.modeLocks(wg) && model.canTryStart(wg))
}
