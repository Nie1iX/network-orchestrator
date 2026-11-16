import Foundation
import Testing

@testable import NetworkOrchestrator

@Test func routingPolicyRoundTripsOrderedRowsAndConditions() throws {
  let policy = RoutingPolicy(
    base: [RoutingRule(selectors: ["geoip:ru"], target: .direct, port: 53, network: "udp")],
    user: [RoutingRule(selectors: ["domain:example.test"], target: .node(endpointKey: "node-a", missing: true), port: nil, network: nil)]
  )
  let data = try JSONEncoder().encode(policy)
  #expect(try JSONDecoder().decode(RoutingPolicy.self, from: data) == policy)
}

@Test func movingRuleBetweenLayersPreservesRuleAndBothLayerOrders() throws {
  let first = RoutingRule(selectors: ["domain:first.test"], target: .block, port: nil, network: nil)
  let moved = RoutingRule(selectors: ["domain:moved.test"], target: .proxy, port: 443, network: "tcp")
  let last = RoutingRule(selectors: ["domain:last.test"], target: .direct, port: nil, network: nil)
  var policy = RoutingPolicy(base: [first, moved, last], user: [])

  policy.moveRule(at: 1, from: .base, to: .user)

  #expect(policy.base == [first, last])
  #expect(policy.user == [moved])
  #expect(policy.user[0].port == 443)
  #expect(policy.user[0].network == "tcp")
}

@Test func reorderingKeepsCanonicalRuleOrder() {
  let first = RoutingRule(selectors: ["domain:first.test"], target: .block, port: nil, network: nil)
  let second = RoutingRule(selectors: ["domain:second.test"], target: .proxy, port: nil, network: nil)
  var policy = RoutingPolicy(base: [], user: [first, second])

  policy.moveRule(at: 1, from: .user, to: .user, insertionIndex: 0)

  #expect(policy.user == [second, first])
}

@Test func happImportReplacesBaseAndPreservesUserOverrides() {
  let user = RoutingRule(selectors: ["domain:override.test"], target: .block, port: 53, network: "udp")
  var options = RoutingOptions()
  options.routing = RoutingPolicy(base: [], user: [user])
  let imported = RoutingRule(selectors: ["geosite:private"], target: .direct, port: nil, network: nil)
  options.apply(HappRouting(name: nil, routing: RoutingPolicy(base: [imported], user: []), warnings: []))

  #expect(options.routing.base == [imported])
  #expect(options.routing.user == [user])
}

@Test func routingOptionsRetainTheFetchedEditRevision() throws {
  let data = try JSONSerialization.data(withJSONObject: [
    "routing": ["base": [], "user": []],
    "privateLanDirect": false, "domainStrategy": "", "domainMatcher": "",
    "dnsServers": "", "dnsHosts": "", "fakeDns": false, "queryStrategy": "",
    "geoipUrl": "", "geositeUrl": "", "editRevision": "snapshot-17",
  ])

  let options = try JSONDecoder().decode(RoutingOptions.self, from: data)

  #expect(options.editRevision == "snapshot-17")
}
