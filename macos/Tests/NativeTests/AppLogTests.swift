import Foundation
import Testing

@testable import NetworkOrchestrator

private let moment = Date(timeIntervalSince1970: 1_800_000_000)

@Test func appLogLinesCarryTheTagsTheLogsPageFilters() {
  var log = AppLog()
  log.add(.info, "Connected Home", at: moment)
  log.add(.warn, "Helper outdated", at: moment)
  log.add(.error, "Could not start", at: moment)
  let lines = LogLines.parse(log.text)
  #expect(lines.map(\.level) == [.info, .warn, .error])
  #expect(lines[0].text.hasSuffix("[Info] Connected Home"))
  #expect(lines[1].text.hasSuffix("[Warning] Helper outdated"))
  #expect(lines[2].text.hasSuffix("[Error] Could not start"))
  // `2026/10/23 12:00:00 [Info] …` (the date part depends on the time zone)
  #expect(lines[0].text.dropFirst(4).first == "/")
}

@Test func anEntryCannotSpanOrForgeLines() {
  var log = AppLog()
  log.add(.info, "one\ntwo\r\nthree", at: moment)
  #expect(log.text.split(separator: "\n").count == 1)
}

@Test func theLogKeepsOnlyTheNewestFiveHundredEntries() {
  var log = AppLog()
  for index in 0..<650 { log.add(.info, "event \(index)", at: moment) }
  #expect(log.entries.count == AppLog.capacity && AppLog.capacity == 500)
  #expect(log.entries.first?.message == "event 150" && log.entries.last?.message == "event 649")
}

@Test func anEmptyLogReadsAsEmptyText() {
  #expect(AppLog().text.isEmpty)
}

@Test @MainActor func modelErrorsAndEventsLandInTheAppLog() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  model.error = "Something failed"
  model.error = "Something failed"  // the same banner re-set is one event
  model.error = nil
  model.record(.info, "Connected Home")
  let lines = LogLines.parse(await model.logText(for: .app))
  #expect(lines.map(\.level) == [.error, .info])
  #expect(lines[0].text.hasSuffix("Something failed"))
}

@Test @MainActor func everySourceReadsThroughTheModel() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let model = AppModel(dataDirectory: directory)
  // Nothing to read yet, and no source may throw or hang.
  #expect(await model.logText(for: .importer).isEmpty)
  #expect(await model.logText(for: .connection("missing")).isEmpty)
  #expect(await model.logText(for: .netbird).isEmpty)  // nothing written in a fresh data directory
  _ = await model.logText(for: .helper)  // the machine's own file, if any: only must not fail
  #expect(await model.logText(for: .app).isEmpty)
}
