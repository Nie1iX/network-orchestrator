import SwiftUI

/// Live throughput of the running tunnels, like the web client's Monitor tab.
struct MonitorView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  private var profiles: [Profile] { model.snapshot?.profiles ?? [] }
  var body: some View {
    let running = profiles.filter { model.isRunning($0) }
    let failed = profiles.filter { model.status($0)?.state == "failed" }
    let total = running.compactMap { model.rate(of: $0) }.reduce(RateSample(rx: 0, tx: 0)) {
      RateSample(rx: $0.rx + $1.rx, tx: $0.tx + $1.tx)
    }
    VStack(alignment: .leading, spacing: 21) {
      statusStrip(running: running.count, failed: failed.count, total: total)
      VStack(alignment: .leading, spacing: 0) {
        AppHeading(title: "monitor.throughput")
        AppCard {
          VStack(alignment: .leading, spacing: 8) {
            ThroughputChart(samples: model.throughput.series)
            HStack(spacing: 14) {
              legend("monitor.download", color: "up", icon: "ArrowDownIcon")
              legend("monitor.upload", color: "info", icon: "ArrowUpIcon")
            }
          }
        }
      }
      ExitIPSection(model: model)
      VStack(alignment: .leading, spacing: 0) {
        AppHeading(title: "monitor.activeTunnels")
        if running.isEmpty && failed.isEmpty {
          AppEmptyState { Text(L10n.text("monitor.noTunnels")) }
        } else {
          ForEach(running) { runningRow($0) }
          ForEach(failed) { failedRow($0) }
        }
      }
    }
    // Only while the page is open; leaving cancels the loop. A fresh sampler
    // keeps a gap from smearing into the first reading.
    .task {
      model.throughput = ThroughputSampler()
      while !Task.isCancelled {
        await model.pollThroughput()
        try? await Task.sleep(for: .seconds(1))
      }
    }
  }

  private func statusStrip(running: Int, failed: Int, total: RateSample) -> some View {
    HStack(spacing: 10.5) {
      Circle().fill(running > 0 ? p["up"] : failed > 0 ? p["down"] : p["unknown"])
        .frame(width: 12, height: 12)
      VStack(alignment: .leading, spacing: 2) {
        Text(
          running > 0
            ? L10n.text("monitor.tunnelsRunning", ["count": String(running)])
            : failed > 0
              ? L10n.text("monitor.tunnelsFailed", ["count": String(failed)])
              : L10n.text("monitor.allDisconnected")
        ).font(.system(size: 14.7, weight: .bold))
        if running > 0 {
          RateLabel(rate: total)
        } else {
          Text(L10n.text("monitor.profilesConfigured", ["count": String(profiles.count)]))
            .font(.system(size: 11.9)).foregroundStyle(p.muted)
        }
      }
      Spacer()
    }
    .padding(.horizontal, 17.5).padding(.vertical, 14)
    .background(p.card, in: RoundedRectangle(cornerRadius: 12))
    .overlay(RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
  }

  private func legend(_ key: String, color: String, icon: String) -> some View {
    HStack(spacing: 4) {
      NativeIcon(name: icon, size: 11)
      Text(L10n.text(key))
    }.font(.system(size: 11.2)).foregroundStyle(p[color])
  }

  private func row<Trailing: View>(
    _ profile: Profile, dot: String, @ViewBuilder trailing: () -> Trailing
  ) -> some View {
    HStack(spacing: 10) {
      StateDot(state: dot)
      NativeIcon(name: NativeIcon.backend(profile.backend), size: 16).foregroundStyle(
        p[backendTint(profile.backend)])
      Text(profile.name).font(.system(size: 13.3, weight: .semibold)).lineLimit(1)
      Text(profile.kind).font(.system(size: 10.92)).foregroundStyle(p.muted).lineLimit(1)
      Spacer(minLength: 12)
      trailing()
    }
    .padding(.horizontal, 8).padding(.vertical, 8)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }

  private func runningRow(_ profile: Profile) -> some View {
    row(profile, dot: "running") {
      Text(model.status(profile)?.interfaceName ?? "—")
        .font(.system(size: 11.2, design: .monospaced)).foregroundStyle(p.secondary)
        .frame(width: 80, alignment: .trailing)
      if let rate = model.rate(of: profile) {
        RateLabel(rate: rate).frame(width: 230, alignment: .trailing)
      } else {
        Text("—").foregroundStyle(p.muted).frame(width: 230, alignment: .trailing)
      }
      Button(L10n.text("common.disconnect")) { Task { await model.toggle(profile) } }
        .buttonStyle(TauriButtonStyle(compact: true)).disabled(model.pending.contains(profile.id))
    }
  }

  private func failedRow(_ profile: Profile) -> some View {
    row(profile, dot: "failed") {
      Text(model.status(profile)?.message ?? L10n.text("monitor.connectionFailed"))
        .font(.system(size: 11.2)).foregroundStyle(p["down"]).lineLimit(2)
    }
  }
}

/// `↓ 1.2 MB/s  ↑ 30 KB/s`.
struct RateLabel: View {
  @Environment(\.palette) private var p
  let rate: RateSample
  var body: some View {
    HStack(spacing: 2) {
      NativeIcon(name: "ArrowDownIcon", size: 11).foregroundStyle(p["up"])
      Text(RateSample.format(rate.rx))
      NativeIcon(name: "ArrowUpIcon", size: 11).foregroundStyle(p["info"]).padding(.leading, 6)
      Text(RateSample.format(rate.tx))
    }.font(.system(size: 11.9, design: .monospaced)).foregroundStyle(p.secondary)
  }
}

/// Download and upload over the last ninety readings, scaled to the peak (at
/// least 1 KB/s so an idle tunnel draws a flat line, not noise).
struct ThroughputChart: View {
  @Environment(\.palette) private var p
  let samples: [RateSample]
  var body: some View {
    Group {
      if samples.count < 2 {
        Text(L10n.text("monitor.collecting")).font(.system(size: 11.9)).foregroundStyle(p.muted)
          .frame(maxWidth: .infinity, minHeight: 96)
      } else {
        Canvas { context, size in
          let peak = max(1_024, samples.map { max($0.rx, $0.tx) }.max() ?? 0)
          let slots = CGFloat(ThroughputSampler.maxSamples - 1)
          let offset = ThroughputSampler.maxSamples - samples.count
          func line(_ value: KeyPath<RateSample, Double>) -> Path {
            var path = Path()
            for (index, sample) in samples.enumerated() {
              let point = CGPoint(
                x: size.width * CGFloat(index + offset) / slots,
                y: size.height * (1 - CGFloat(sample[keyPath: value] / peak)))
              index == 0 ? path.move(to: point) : path.addLine(to: point)
            }
            return path
          }
          let style = StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round)
          context.stroke(line(\.tx), with: .color(p["info"]), style: style)
          context.stroke(line(\.rx), with: .color(p["up"]), style: style)
        }.frame(height: 96)
      }
    }
    .accessibilityLabel(L10n.text("monitor.throughput"))
  }
}
