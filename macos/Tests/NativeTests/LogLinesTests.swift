import Testing

@testable import NetworkOrchestrator

@Test func logTextSplitsIntoLinesAndSkipsBlankOnes() {
  let lines = LogLines.parse("first\n\n  \nsecond\r\nthird")
  #expect(lines.map(\.text) == ["first", "second", "third"])
  #expect(lines.map(\.id) == [0, 1, 2])
  #expect(LogLines.parse("").isEmpty)
}

@Test func levelsComeFromTheTagsXrayAndOpenVpnWrite() {
  func level(_ text: String) -> LogLevel { LogLines.parse(text)[0].level }
  #expect(level("2026/10/23 12:00:00 [Error] app/dns: lookup failed") == .error)
  #expect(level("2026/10/23 [Warning] core: reducing sockets") == .warn)
  #expect(level("[Info] transport/internet: dialing") == .info)
  #expect(level("Fri Oct 23 openvpn: Options error: unknown option") == .error)
  #expect(level("openvpn: WARNING: this configuration may cache passwords") == .warn)
  #expect(level("TUN/TAP device utun4 opened") == .info)
  #expect(level("[error] and [warning] together") == .error)  // the worse one wins
}

@Test func theLevelFilterIsExactAndTheQueryIsCaseInsensitive() {
  let lines = LogLines.parse("[Error] boom\n[Warning] hmm\n[Info] Dialing Server\n[Info] other")
  #expect(LogLines.filter(lines, level: .error, query: "").shown.map(\.text) == ["[Error] boom"])
  #expect(LogLines.filter(lines, level: nil, query: "dialing").shown.count == 1)
  #expect(LogLines.filter(lines, level: .info, query: "SERVER").shown.map(\.id) == [2])
  #expect(LogLines.filter(lines, level: .warn, query: "boom").shown.isEmpty)
  #expect(LogLines.filter(lines, level: nil, query: "  ").shown.count == 4)  // blank query = no query
}

@Test func onlyTheLastLinesAreRenderedAndTheTotalIsReported() {
  let text = (0..<1_500).map { "line \($0)" }.joined(separator: "\n")
  let result = LogLines.filter(LogLines.parse(text), level: nil, query: "")
  #expect(result.shown.count == LogLines.maxRendered && LogLines.maxRendered == 1_000)
  #expect(result.shown.first?.text == "line 500" && result.shown.last?.text == "line 1499")
  #expect(result.total == 1_500)
}
