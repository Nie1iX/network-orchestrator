import Foundation
import Testing

@testable import NetworkOrchestrator

private let t0 = Date(timeIntervalSince1970: 1_000)
private func reading(_ id: UInt32, _ name: String, rx: UInt64?, tx: UInt64?) -> CounterReading {
  CounterReading(id: id, names: [name], rx: rx, tx: tx)
}

@Test func theFirstReadingOnlyRemembersTheCounters() {
  var sampler = ThroughputSampler()
  sampler.ingest([reading(1, "utun4", rx: 100, tx: 50)], tracked: ["utun4"], now: t0)
  #expect(sampler.rates.isEmpty)
  #expect(sampler.series.isEmpty)
}

@Test func ratesAreBytesPerSecondBetweenTwoReadings() {
  var sampler = ThroughputSampler()
  sampler.ingest([reading(1, "utun4", rx: 1_000, tx: 0)], tracked: ["utun4"], now: t0)
  sampler.ingest(
    [reading(1, "utun4", rx: 5_000, tx: 2_000)], tracked: ["utun4"],
    now: t0.addingTimeInterval(2))
  #expect(sampler.rates[1] == RateSample(rx: 2_000, tx: 1_000))
  #expect(sampler.series.last == RateSample(rx: 2_000, tx: 1_000))
}

@Test func aCounterThatGoesBackwardsReadsAsZeroNotNegativeOrHuge() {
  var sampler = ThroughputSampler()
  sampler.ingest([reading(1, "utun4", rx: 9_000, tx: 9_000)], tracked: ["utun4"], now: t0)
  sampler.ingest(
    [reading(1, "utun4", rx: 10, tx: 20)], tracked: ["utun4"], now: t0.addingTimeInterval(1))
  #expect(sampler.rates[1] == RateSample(rx: 0, tx: 0))
}

@Test func twoReadingsAtTheSameInstantAreIgnored() {
  var sampler = ThroughputSampler()
  sampler.ingest([reading(1, "utun4", rx: 0, tx: 0)], tracked: ["utun4"], now: t0)
  sampler.ingest([reading(1, "utun4", rx: 500, tx: 500)], tracked: ["utun4"], now: t0)
  #expect(sampler.rates.isEmpty && sampler.series.isEmpty)
}

@Test func theTotalCoversOnlyTrackedInterfaces() {
  var sampler = ThroughputSampler()
  let first = [
    reading(1, "utun4", rx: 0, tx: 0), reading(2, "en0", rx: 0, tx: 0),
    reading(3, "utun5", rx: 0, tx: 0),
  ]
  let second = [
    reading(1, "utun4", rx: 100, tx: 10), reading(2, "en0", rx: 9_999, tx: 9_999),
    reading(3, "utun5", rx: 300, tx: 30),
  ]
  sampler.ingest(first, tracked: ["utun4", "utun5"], now: t0)
  sampler.ingest(second, tracked: ["utun4", "utun5"], now: t0.addingTimeInterval(1))
  #expect(sampler.series.last == RateSample(rx: 400, tx: 40))
  #expect(sampler.rates[2] == RateSample(rx: 9_999, tx: 9_999))  // still measured, not summed
}

@Test func interfacesWithoutCountersAreSkipped() {
  var sampler = ThroughputSampler()
  sampler.ingest([reading(1, "lo0", rx: nil, tx: nil)], tracked: ["lo0"], now: t0)
  sampler.ingest(
    [reading(1, "lo0", rx: nil, tx: nil)], tracked: ["lo0"], now: t0.addingTimeInterval(1))
  #expect(sampler.rates.isEmpty)
}

@Test func theSeriesKeepsOnlyTheLastNinetySamples() {
  var sampler = ThroughputSampler()
  for second in 0..<120 {
    sampler.ingest(
      [reading(1, "utun4", rx: UInt64(second) * 10, tx: 0)], tracked: ["utun4"],
      now: t0.addingTimeInterval(Double(second)))
  }
  #expect(sampler.series.count == ThroughputSampler.maxSamples)
  #expect(ThroughputSampler.maxSamples == 90)
}

@Test func nothingTrackedGivesAnEmptyTotalButStillMeasuresInterfaces() {
  var sampler = ThroughputSampler()
  sampler.ingest([reading(1, "en0", rx: 0, tx: 0)], tracked: [], now: t0)
  sampler.ingest(
    [reading(1, "en0", rx: 100, tx: 0)], tracked: [], now: t0.addingTimeInterval(1))
  #expect(sampler.series.last == RateSample(rx: 0, tx: 0))
  #expect(sampler.rates[1]?.rx == 100)
}

@Test func anInterfaceIsMatchedByNameOrByFriendlyName() {
  let both = CounterReading(id: 7, names: ["utun4", "VPN (utun4)"], rx: 1, tx: 1)
  #expect(both.matches(["VPN (utun4)"]) && both.matches(["utun4"]) && !both.matches(["en0"]))
}

@Test func ratesReadLikeTheWebClient() {
  #expect(RateSample.format(0) == "0 B/s")
  #expect(RateSample.format(1_023.4) == "1023 B/s")
  #expect(RateSample.format(1_536) == "1.5 KB/s")
  #expect(RateSample.format(5 * 1_048_576) == "5.0 MB/s")
  #expect(RateSample.format(-5) == "0 B/s")
}
