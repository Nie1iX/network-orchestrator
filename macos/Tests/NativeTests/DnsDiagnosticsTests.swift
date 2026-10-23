import Foundation
import Testing

@testable import NetworkOrchestrator

private let resolverJSON = #"""
  {"resolvers":[
    {"index":1,"domain":null,"searchDomains":["corp.example"],"nameservers":["169.254.10.1"],
     "port":null,"scoped":false,"interface":null,"ifIndex":null,"supplemental":false,
     "mdns":false,"reachable":true,"order":null,"timeout":null,"flags":["Request A records"]},
    {"index":2,"domain":"lab.internal","searchDomains":[],"nameservers":["10.99.0.53","fd00::53"],
     "port":5353,"scoped":false,"interface":null,"ifIndex":null,"supplemental":true,
     "mdns":false,"reachable":true,"order":105001,"timeout":null,"flags":["Supplemental"]},
    {"index":3,"domain":"local","searchDomains":[],"nameservers":[],"port":null,"scoped":false,
     "interface":null,"ifIndex":null,"supplemental":false,"mdns":true,"reachable":false,
     "order":300000,"timeout":5,"flags":[]}],
   "scoped":[
    {"index":1,"domain":null,"searchDomains":[],"nameservers":["10.228.32.2"],"port":null,
     "scoped":true,"interface":"en0","ifIndex":15,"supplemental":false,"mdns":false,
     "reachable":true,"order":null,"timeout":null,"flags":["Scoped"]}]}
  """#

@Test func theResolverListDecodesFromTheBridgeAnswer() throws {
  let config = try JSONDecoder().decode(DnsConfig.self, from: Data(resolverJSON.utf8))
  #expect(config.resolvers.count == 3 && config.scoped.count == 1)
  #expect(config.resolvers[1].domain == "lab.internal" && config.resolvers[1].supplemental)
  #expect(config.scoped[0].interface == "en0" && config.scoped[0].scoped)
  // Same index in both sections must not collide in a list.
  #expect(config.resolvers[0].id != config.scoped[0].id)
}

@Test func serversAreWrittenWithTheirPortOnlyWhenItIsNotTheDefault() throws {
  let config = try JSONDecoder().decode(DnsConfig.self, from: Data(resolverJSON.utf8))
  #expect(config.resolvers[0].serverTexts == ["169.254.10.1"])
  #expect(config.resolvers[1].serverTexts == ["10.99.0.53:5353", "[fd00::53]:5353"])
  #expect(config.resolvers[2].serverTexts.isEmpty)
}

@Test func aResolverIsTitledByItsDomainOrAsTheDefault() throws {
  let config = try JSONDecoder().decode(DnsConfig.self, from: Data(resolverJSON.utf8))
  #expect(config.resolvers[0].title == nil)
  #expect(config.resolvers[1].title == "lab.internal")
  #expect(config.scoped[0].title == nil)
}

@Test func aProbeAnswerDecodesWithItsPathAndResolver() throws {
  let json = #"""
    {"probe":{"server":"10.99.0.53","port":5353,"status":"NOERROR",
              "answers":["host.lab.internal 60 A 10.0.0.9"],"truncated":false,
              "fakePool":true,"rttMs":12},
     "resolverIndex":2,"resolverDomain":"lab.internal",
     "path":{"interfaceName":"utun5","gateway":null}}
    """#
  let answer = try JSONDecoder().decode(DnsProbeAnswer.self, from: Data(json.utf8))
  #expect(answer.probe.status == "NOERROR" && answer.probe.rttMs == 12)
  #expect(answer.probe.fakePool && answer.resolverDomain == "lab.internal")
  #expect(answer.path?.interfaceName == "utun5" && answer.path?.gateway == nil)
}

@Test @MainActor func theSystemResolversLoadThroughTheBridgeWithoutTheStore() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let model = AppModel(dataDirectory: directory)
  await model.loadDns()
  // The machine's own answer: only its shape is known.
  #expect(model.dnsConfig != nil && model.error == nil)
  #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("profiles.json").path))
}

@Test @MainActor func aBadProbeInputIsReportedNotSent() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  #expect(await model.probeDns(host: "not a name", server: "127.0.0.1", ipv6: false) == nil)
  #expect(model.error == "Enter a valid host name")
  model.error = nil
  #expect(await model.probeDns(host: "example.com", server: "dns.example", ipv6: false) == nil)
  #expect(model.error == "Enter an IPv4 or IPv6 address as the server")
}
