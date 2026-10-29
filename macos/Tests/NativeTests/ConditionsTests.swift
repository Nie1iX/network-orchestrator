import Foundation
import Testing

@testable import NetworkOrchestrator

private func entryJSON(
  id: String = "office", enabled: Bool = true, state: String = "active",
  matched: String? = "en7", applied: Int = 2, detail: String? = nil,
  routes: [[String: Any]] = [
    ["destination": "10.99.0.0/24", "metric": 5],
    ["destination": "10.98.0.0/16", "metric": 5, "via": "10.228.32.9"],
  ]
) -> [String: Any] {
  var status: [String: Any] = ["state": state, "appliedRoutes": applied]
  if let matched { status["matchedInterface"] = matched }
  if let detail { status["detail"] = detail }
  return [
    "rule": [
      "id": id, "name": "Office LAN", "enabled": enabled,
      "condition": ["kind": "interfaceAddressIn", "prefix": "10.228.32.0/21"], "routes": routes,
    ],
    "status": status,
  ]
}

private func decode(_ object: Any) throws -> [ConditionalRuleEntry] {
  try JSONDecoder().decode(
    [ConditionalRuleEntry].self, from: JSONSerialization.data(withJSONObject: object))
}

@Test func rulesDecodeFromTheBridgeAnswer() throws {
  let list = try decode([entryJSON(), entryJSON(id: "away", state: "inactive", matched: nil, applied: 0)])
  #expect(list.map(\.id) == ["office", "away"])
  #expect(list[0].rule.prefix == "10.228.32.0/21" && list[0].rule.name == "Office LAN")
  #expect(list[0].status.state == .active && list[0].status.matchedInterface == "en7")
  #expect(list[0].rule.routes[1].via == "10.228.32.9" && list[0].rule.routes[0].via == nil)
  #expect(list[1].status.matchedInterface == nil && list[1].status.appliedRoutes == 0)
}

@Test func stateColoursAndHintsFollowTheWebClient() throws {
  let all = try decode(
    ["active", "inactive", "disabled", "error"].map { entryJSON(id: $0, state: $0) })
  #expect(all.map(\.status.state.badgeColor) == ["up", "unknown", "unknown", "down"])
  #expect(all.map(\.status.state.label) == ["cond.stateActive", "cond.stateInactive", "cond.stateDisabled", "cond.stateError"])
  #expect(all.map(\.status.state.hint) == ["cond.hintActive", "cond.hintInactive", "cond.hintDisabled", "cond.hintError"])
}

@Test func aStateFromANewerHelperReadsAsUnknown() throws {
  let list = try decode([entryJSON(state: "paused")])
  #expect(list[0].status.state == .unknown)
}

@Test func routesAreShownAsTheyAreTyped() throws {
  let rule = try #require(try decode([entryJSON()]).first).rule
  #expect(rule.routes[0].text == "10.99.0.0/24")
  #expect(rule.routes[1].text == "10.98.0.0/16 via 10.228.32.9")
}

@Test func theRuleDraftBecomesTheBridgeArguments() {
  var draft = RuleDraft()
  draft.id = " office "
  draft.name = "Office LAN"
  draft.prefix = " 10.228.32.0/21 "
  draft.routes = "10.99.0.0/24\n10.98.0.0/16 via 10.228.32.9"
  draft.enabled = false
  let args = draft.arguments
  #expect(args["id"] == "office" && args["name"] == "Office LAN" && args["prefix"] == "10.228.32.0/21")
  #expect(args["routes"] == "10.99.0.0/24\n10.98.0.0/16 via 10.228.32.9" && args["enabled"] == "false")
}

@Test func theDraftIsCompleteOnlyWithEverythingTheHelperNeeds() {
  var draft = RuleDraft()
  #expect(!draft.isComplete)
  draft.id = "office"
  draft.name = "Office"
  draft.prefix = "10.228.32.0/21"
  #expect(!draft.isComplete)  // no routes yet
  draft.routes = "\n  \n"
  #expect(!draft.isComplete)
  draft.routes = "10.99.0.0/24"
  #expect(draft.isComplete)
}

@Test func editingStartsFromTheStoredRule() throws {
  let entry = try #require(try decode([entryJSON(enabled: false)]).first)
  let draft = RuleDraft(editing: entry)
  #expect(draft.editing && draft.id == "office" && draft.name == "Office LAN")
  #expect(draft.prefix == "10.228.32.0/21" && !draft.enabled)
  #expect(draft.routes == "10.99.0.0/24\n10.98.0.0/16 via 10.228.32.9")
}

@Test @MainActor func rulesNeedAHelperThatOffersAllThreeMethods() throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  func helper(_ capabilities: [String]) throws -> HelperStatus {
    try JSONDecoder().decode(
      HelperStatus.self,
      from: JSONSerialization.data(withJSONObject: [
        "reachable": true, "denied": false, "version": "1", "capabilities": capabilities,
      ]))
  }
  model.helperStatus = try helper(["condRules.list", "condRules.put"])
  #expect(!model.canUseRules)
  model.helperStatus = try helper(["condRules.list", "condRules.put", "condRules.remove"])
  #expect(model.canUseRules)
}
