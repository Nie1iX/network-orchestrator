import Foundation

enum LogLevel: String, CaseIterable, Sendable {
  case error, warn, info
}

struct LogLine: Identifiable, Equatable, Sendable {
  let id: Int
  let text: String
  let level: LogLevel
}

/// Splits backend log text into lines and filters them for the Logs page.
enum LogLines {
  /// The page renders this many of the newest lines, like the web client.
  static let maxRendered = 1_000

  /// Xray writes `[Error]`/`[Warning]`/`[Info]`, OpenVPN `Options error:` and
  /// `WARNING:`; anything else reads as info. The worse level wins.
  static func level(of line: String) -> LogLevel {
    let lower = line.lowercased()
    if lower.contains("[error]") || lower.contains("error:") || lower.contains("[fatal]") {
      return .error
    }
    if lower.contains("[warning]") || lower.contains("[warn]") || lower.contains("warning:") {
      return .warn
    }
    return .info
  }

  static func parse(_ text: String) -> [LogLine] {
    text.split(whereSeparator: \.isNewline)
      .map(String.init)
      .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
      .enumerated()
      .map { LogLine(id: $0.offset, text: $0.element, level: level(of: $0.element)) }
  }

  /// `level == nil` keeps every level; the query is a case-insensitive
  /// substring. `total` counts the matches before the render cap.
  static func filter(_ lines: [LogLine], level: LogLevel?, query: String) -> (
    shown: [LogLine], total: Int
  ) {
    let needle = query.trimmingCharacters(in: .whitespaces)
    let matches = lines.filter { line in
      (level == nil || line.level == level)
        && (needle.isEmpty || line.text.localizedCaseInsensitiveContains(needle))
    }
    return (Array(matches.suffix(maxRendered)), matches.count)
  }
}
