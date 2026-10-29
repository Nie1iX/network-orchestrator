import Foundation
import Testing

@testable import NetworkOrchestrator

private func happ(_ extra: [String: Any]) throws -> HappRouting {
  var json: [String: Any] = ["block": "", "proxy": "", "direct": "", "warnings": []]
  json.merge(extra) { $1 }
  return try JSONDecoder().decode(HappRouting.self, from: JSONSerialization.data(withJSONObject: json))
}

@Test func geoAddressesTravelWithTheRoutingOptions() {
  var options = RoutingOptions()
  #expect(options.bridgeArgs["geoipUrl"] == "" && options.bridgeArgs["geositeUrl"] == "")
  options.geoipUrl = "https://cdn.example/geoip.dat"
  #expect(options.bridgeArgs["geoipUrl"] == "https://cdn.example/geoip.dat")
}

@Test func aHappExportFillsTheGeoAddressesItMentionsAndKeepsTheRest() throws {
  var options = RoutingOptions()
  options.geositeUrl = "https://mine.example/geosite.dat"
  options.apply(try happ(["geoipUrl": "https://cdn.example/geoip.dat"]))
  #expect(options.geoipUrl == "https://cdn.example/geoip.dat")
  #expect(options.geositeUrl == "https://mine.example/geosite.dat")
}
