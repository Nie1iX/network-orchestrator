import Foundation

/// What a Logs page can read.
enum LogSource: Hashable, Sendable {
  /// The app's own events (connections started or stopped, errors shown).
  case app
  /// The privileged helper's stderr.
  case helper
  /// What `netbird up` printed.
  case netbird
  /// The subscription/import log.
  case importer
  /// A connection's backend log, by profile id.
  case connection(String)
}

/// The app's own event log. macOS has no daemon feeding one, so the model
/// records what the user did and what went wrong; it lives in memory for the
/// run and holds no secrets (only messages already shown to the user).
struct AppLog: Sendable {
  static let capacity = 500
  struct Entry: Sendable {
    let date: Date
    let level: LogLevel
    let message: String
  }
  private(set) var entries: [Entry] = []

  mutating func add(_ level: LogLevel, _ message: String, at date: Date = Date()) {
    // One event, one line.
    let line = message.replacingOccurrences(of: "\r\n", with: " ")
      .replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
    entries.append(Entry(date: date, level: level, message: line))
    if entries.count > Self.capacity { entries.removeFirst(entries.count - Self.capacity) }
  }

  /// `2026/10/23 12:00:00 [Info] message`, the shape Xray's lines have.
  var text: String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyy/MM/dd HH:mm:ss"
    return entries.map { entry in
      let tag =
        switch entry.level {
        case .error: "Error"
        case .warn: "Warning"
        case .info: "Info"
        }
      return "\(formatter.string(from: entry.date)) [\(tag)] \(entry.message)"
    }.joined(separator: "\n")
  }
}
