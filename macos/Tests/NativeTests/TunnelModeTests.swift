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
  // Static routes create no tunnel and stay unavailable.
  #expect(!ready.canTryStart(try profile("none", mode: nil)))
}

@Test func helperBuildIsNilOutsideAnAppBundle() {
  // The test runner has no bundled helper, so no registration is ever retired.
  #expect(AppModel.currentHelperBuild() == nil)
}

@Test @MainActor func wireGuardAndOpenVpnStartOnlyWhenTheHelperOffersThem() throws {
  let wireGuard = try profile("wireGuard", mode: nil)
  let openVpn = try profile("openVpn", mode: nil)
  #expect(wireGuard.needsHelper && openVpn.needsHelper)
  #expect(wireGuard.helperCapability == "wireguard.connect")
  #expect(openVpn.helperCapability == "openvpn.connect")
  #expect(try profile("xray", mode: "socks").helperCapability == nil)

  let without = try model(nil)
  #expect(!without.canStart(wireGuard) && !without.canStart(openVpn))
  // The switch stays usable so that pressing it can offer to install the helper.
  #expect(without.canTryStart(wireGuard) && without.canTryStart(openVpn))

  let xrayOnly = try model(try helper(["xray.connect"]))
  #expect(!xrayOnly.canStart(wireGuard) && !xrayOnly.canStart(openVpn))

  let ready = try model(try helper(["wireguard.connect", "openvpn.connect", "xray.connect"]))
  #expect(ready.canStart(wireGuard) && ready.canStart(openVpn))
  #expect(ready.helperOffers("openvpn.connect") && !ready.helperOffers("nope"))
}

@Test @MainActor func startingWireGuardWithoutTheHelperOffersToInstallIt() async throws {
  let wireGuard = try profile("wireGuard", mode: nil)
  let without = try model(nil)
  await without.toggle(wireGuard)
  #expect(without.helperPrompt)
  #expect(without.error == nil)
}

@Test func credentialsAreSentOnlyWhenTheProfileAsksForThem() {
  var secrets = OpenVpnSecrets(username: "u", password: "p", passphrase: "k")
  let both = CredentialNeeds(userPass: true, keyPassphrase: true)
  let loginOnly = CredentialNeeds(userPass: true, keyPassphrase: false)
  let none = CredentialNeeds(userPass: false, keyPassphrase: false)
  #expect(secrets.arguments(for: both) == ["username": "u", "password": "p", "passphrase": "k"])
  #expect(secrets.arguments(for: loginOnly) == ["username": "u", "password": "p"])
  #expect(secrets.arguments(for: none).isEmpty && !none.any)
  #expect(secrets.satisfies(both) && secrets.satisfies(none))
  secrets.password = ""
  #expect(!secrets.satisfies(loginOnly) && !secrets.satisfies(both))
  secrets = OpenVpnSecrets(username: "u", password: "p", passphrase: "")
  #expect(secrets.satisfies(loginOnly) && !secrets.satisfies(both))
}

@Test func credentialNeedsDecodeFromTheBridgeAnswer() throws {
  let needs = try JSONDecoder().decode(
    CredentialNeeds.self, from: Data(#"{"userPass":true,"keyPassphrase":false}"#.utf8))
  #expect(needs == CredentialNeeds(userPass: true, keyPassphrase: false))
}

@Test func rolesDecodeAndDefaultToPrimary() throws {
  let plain = try profile("wireGuard", mode: nil)
  #expect(!plain.isSecondary && plain.tunnelNetworks == nil)
  let secondary = try JSONDecoder().decode(
    Profile.self,
    from: JSONSerialization.data(withJSONObject: [
      "id": "p", "name": "P", "backend": "openVpn", "interfaceName": "", "routes": [],
      "tunnelRole": "secondary", "tunnelNetworks": ["10.10.0.0/16"],
      "tunnelDnsDomains": ["corp.example"],
    ]))
  #expect(secondary.isSecondary)
  #expect(secondary.tunnelNetworks == ["10.10.0.0/16"])
  #expect(secondary.tunnelDnsDomains == ["corp.example"])
  #expect(secondary.needsHelper)
}

@Test func netBirdStateDecodesAndOnlyTogglesWhenTheDaemonAnswers() throws {
  func decode(_ json: String) throws -> NetBirdState {
    try JSONDecoder().decode(NetBirdState.self, from: Data(json.utf8))
  }
  let connected = try decode(
    #"{"installed":true,"state":"connected","ip":"10.85.18.199/16","peersConnected":2,"peersTotal":2,"networks":["10.10.40.0/24"]}"#
  )
  #expect(connected.isOn && connected.canToggle && connected.networks == ["10.10.40.0/24"])
  #expect(try decode(#"{"installed":true,"state":"connecting"}"#).isOn)
  let login = try decode(#"{"installed":true,"state":"needsLogin"}"#)
  #expect(!login.isOn && login.canToggle)
  for blocked in ["daemonStopped", "unavailable"] {
    let state = try decode(#"{"installed":true,"state":"\#(blocked)"}"#)
    #expect(!state.canToggle, "\(blocked)")
  }
  #expect(!(try decode(#"{"installed":false,"state":"notInstalled"}"#).canToggle))
}

@Test @MainActor func netBirdIsLeftAloneWhenItCannotBeToggled() async throws {
  let model = try model(nil)
  model.netbird = NetBirdState(installed: true, state: "daemonStopped")
  await model.toggleNetBird()
  #expect(!model.netbirdBusy && model.error == nil)
  model.netbird = nil
  await model.toggleNetBird()
  #expect(model.error == nil)
}
