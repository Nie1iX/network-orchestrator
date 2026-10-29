import Foundation

/// Bytes per second in each direction.
struct RateSample: Equatable, Sendable {
  var rx: Double
  var tx: Double
  /// `1023 B/s`, `1.5 KB/s`, `5.0 MB/s`: the same steps as the web client.
  static func format(_ bytesPerSecond: Double) -> String {
    let value = max(0, bytesPerSecond)
    if value < 1_024 { return String(format: "%.0f B/s", value) }
    if value < 1_048_576 { return String(format: "%.1f KB/s", value / 1_024) }
    return String(format: "%.1f MB/s", value / 1_048_576)
  }
}

/// One interface's byte counters at a moment, under every name it is known by.
struct CounterReading: Sendable {
  let id: UInt32
  let names: [String]
  let rx: UInt64?
  let tx: UInt64?
  func matches(_ tracked: Set<String>) -> Bool { names.contains { tracked.contains($0) } }
}

/// Turns the interfaces' ever-growing byte counters into rates, plus a short
/// history of the total over the tracked (tunnel) interfaces for the chart.
struct ThroughputSampler: Sendable {
  static let maxSamples = 90
  private struct Counter {
    var rx: UInt64
    var tx: UInt64
    var at: Date
  }
  private var last: [UInt32: Counter] = [:]
  /// Latest rate of every interface that has counters, by interface index.
  private(set) var rates: [UInt32: RateSample] = [:]
  /// Total over the tracked interfaces, one entry per reading.
  private(set) var series: [RateSample] = []

  /// A counter that went backwards (interface re-created) reads as zero, and
  /// two readings at the same instant are ignored rather than divided by zero.
  mutating func ingest(_ readings: [CounterReading], tracked: Set<String>, now: Date) {
    var next: [UInt32: RateSample] = [:]
    var total = RateSample(rx: 0, tx: 0)
    var measured = false
    for reading in readings {
      guard let rx = reading.rx, let tx = reading.tx else { continue }
      defer { last[reading.id] = Counter(rx: rx, tx: tx, at: now) }
      guard let before = last[reading.id] else { continue }
      let seconds = now.timeIntervalSince(before.at)
      guard seconds > 0 else { continue }
      let rate = RateSample(
        rx: rx >= before.rx ? Double(rx - before.rx) / seconds : 0,
        tx: tx >= before.tx ? Double(tx - before.tx) / seconds : 0)
      next[reading.id] = rate
      measured = true
      if reading.matches(tracked) {
        total.rx += rate.rx
        total.tx += rate.tx
      }
    }
    rates = next
    if measured {
      series.append(total)
      if series.count > Self.maxSamples { series.removeFirst(series.count - Self.maxSamples) }
    }
  }
}
