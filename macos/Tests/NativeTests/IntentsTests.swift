import Foundation
import Testing

@testable import NetworkOrchestrator

private func intentJSON(
  id: String = "office", destinations: [String] = ["10.0.0.0/8"], kind: String = "direct",
  interface: String? = nil, status: String = "effective", enabled: Bool = true,
  installed: Int = 1, wanted: Int = 1
) -> [String: Any] {
  var path: [String: Any] = ["kind": kind]
  if let interface { path["interface"] = interface }
  return [
    "id": id, "destinations": destinations, "path": path, "metric": 100, "enabled": enabled,
    "status": status, "detail": "1 route(s) in place", "installed": installed, "wanted": wanted,
  ]
}

private func decode(_ object: Any) throws -> [RouteIntent] {
  try JSONDecoder().decode(
    [RouteIntent].self, from: JSONSerialization.data(withJSONObject: object))
}

@Test func intentsDecodeFromTheBridgeAnswer() throws {
  let list = try decode([
    intentJSON(),
    intentJSON(id: "wg", kind: "interface", interface: "utun5", status: "deferred", installed: 0, wanted: 0),
  ])
  #expect(list.map(\.id) == ["office", "wg"])
  #expect(list[0].isDirect && list[0].pathText == "direct")
  #expect(!list[1].isDirect && list[1].pathText == "utun5")
  #expect(list[1].status == .deferred)
}

@Test func statusesMapToTheSameColoursAsTheWebClient() throws {
  let all = try decode(
    ["effective", "active", "deferred", "conflicted", "missing", "disabled"].map {
      intentJSON(id: $0, status: $0)
    })
  #expect(all.map(\.status.badgeColor) == ["up", "up", "info", "down", "warn", "unknown"])
}

@Test func anUnknownStatusFromANewerHelperDoesNotBreakTheList() throws {
  let list = try decode([intentJSON(status: "somethingNew")])
  #expect(list.count == 1)
  #expect(list[0].status == .unknown)
}

@Test func onlyHalvesOfTheInternetOrAllOfItCountAsDefaultCapturing() {
  #expect(RouteIntent.capturesDefault(["0.0.0.0/1", "128.0.0.0/1"]))
  #expect(RouteIntent.capturesDefault(["0.0.0.0/0"]))
  #expect(RouteIntent.capturesDefault(["::/1"]))
  #expect(RouteIntent.capturesDefault(["10.0.0.0/8", " 0.0.0.0/0 "]))
  #expect(!RouteIntent.capturesDefault(["10.0.0.0/8", "0.0.0.0/8", "192.0.2.1"]))
  #expect(!RouteIntent.capturesDefault(["not-a-network", ""]))
}

@Test func theDraftBecomesTheBridgeArguments() {
  var draft = IntentDraft()
  draft.id = " office "
  draft.destinations = "10.0.0.0/8\n172.16.0.0/12"
  draft.useInterface = true
  draft.interface = "utun5"
  draft.enabled = false
  let args = draft.arguments
  #expect(args["id"] == "office" && args["kind"] == "interface" && args["interface"] == "utun5")
  #expect(args["destinations"] == "10.0.0.0/8\n172.16.0.0/12" && args["enabled"] == "false")
  draft.useInterface = false
  #expect(draft.arguments["kind"] == "direct" && draft.arguments["interface"] == "")
}

@Test func theDraftIsCompleteOnlyWithANameDestinationsAndADeviceWhenOneIsChosen() {
  var draft = IntentDraft()
  #expect(!draft.isComplete)
  draft.id = "office"
  #expect(!draft.isComplete)
  draft.destinations = "10.0.0.0/8"
  #expect(draft.isComplete)
  draft.useInterface = true
  #expect(!draft.isComplete)
  draft.interface = "utun5"
  #expect(draft.isComplete)
}

@Test func editingStartsFromTheStoredIntent() throws {
  let intent = try #require(
    try decode([intentJSON(destinations: ["10.0.0.0/8", "172.16.0.0/12"], kind: "interface", interface: "utun5", enabled: false)]).first)
  let draft = IntentDraft(editing: intent)
  #expect(draft.id == "office" && draft.editing)
  #expect(draft.destinations == "10.0.0.0/8\n172.16.0.0/12")
  #expect(draft.useInterface && draft.interface == "utun5" && !draft.enabled)
}

@Test @MainActor func listingIntentsWithoutTheHelperReportsItInsteadOfCrashing() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  model.helperStatus = try JSONDecoder().decode(
    HelperStatus.self,
    from: JSONSerialization.data(withJSONObject: [
      "reachable": true, "denied": false, "version": "1", "capabilities": ["xray.connect"],
    ]))
  #expect(!model.canUseIntents)  // an older helper does not offer them
  model.helperStatus = try JSONDecoder().decode(
    HelperStatus.self,
    from: JSONSerialization.data(withJSONObject: [
      "reachable": true, "denied": false, "version": "1",
      "capabilities": ["net.intent.list", "net.intent.set", "net.intent.del"],
    ]))
  #expect(model.canUseIntents)
}
