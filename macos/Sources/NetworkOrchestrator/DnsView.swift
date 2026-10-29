import SwiftUI

/// The system's DNS resolvers and a one-off query that shows which resolver
/// answers a name and which way the request travels. Read-only.
struct DnsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var host = ""
  @State private var server = ""
  @State private var ipv6 = false
  @State private var answer: DnsProbeAnswer?
  @State private var querying = false

  var body: some View {
    VStack(alignment: .leading, spacing: 21) {
      probeCard
      if let config = model.dnsConfig {
        section("native.dns.resolvers", config.resolvers)
        if !config.scoped.isEmpty { section("native.dns.scoped", config.scoped) }
      } else {
        AppEmptyState { Text(L10n.text("native.dns.empty")) }
      }
    }
    .task { await model.loadDns() }
  }

  // MARK: Probe

  private var probeCard: some View {
    VStack(alignment: .leading, spacing: 0) {
      AppHeading(title: "native.dns.probe.title")
      AppCard {
        VStack(alignment: .leading, spacing: 10) {
          HStack(spacing: 7) {
            AppInput(placeholder: "native.dns.probe.host", text: $host)
            AppInput(placeholder: "native.dns.probe.server", text: $server).frame(width: 190)
            Picker("", selection: $ipv6) {
              Text("A").tag(false)
              Text("AAAA").tag(true)
            }.labelsHidden().pickerStyle(.segmented).frame(width: 100)
            Button(L10n.text("native.dns.probe.run")) { Task { await run() } }
              .buttonStyle(TauriButtonStyle(kind: .accent))
              .disabled(querying || host.trimmingCharacters(in: .whitespaces).isEmpty)
              .keyboardShortcut(.defaultAction)
          }
          if querying {
            ProgressView().controlSize(.small)
          } else if let answer {
            result(answer)
          }
        }
      }
    }
  }

  @ViewBuilder private func result(_ answer: DnsProbeAnswer) -> some View {
    let probe = answer.probe
    VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 8) {
        AppBadge(text: probe.status, color: probe.status == "NOERROR" ? "up" : "down")
        Text("\(probe.server)\(probe.port == 53 ? "" : ":\(probe.port)")")
          .font(.system(size: 11.9, design: .monospaced))
        Text("\(probe.rttMs) ms").font(.system(size: 11.2)).foregroundStyle(p.muted)
        Spacer()
      }
      Text(
        answer.resolverIndex == nil
          ? ""
          : answer.resolverDomain.map { L10n.text("native.dns.probe.viaDomain", ["domain": $0]) }
            ?? L10n.text("native.dns.probe.viaDefault")
      ).font(.system(size: 11.2)).foregroundStyle(p.secondary)
      if let path = answer.path {
        Text(
          path.gateway.map {
            L10n.text(
              "native.dns.probe.pathVia", ["interface": path.interfaceName, "gateway": $0])
          } ?? L10n.text("native.dns.probe.path", ["interface": path.interfaceName])
        ).font(.system(size: 11.2)).foregroundStyle(p.secondary)
      }
      if probe.answers.isEmpty {
        Text(L10n.text("native.dns.probe.noAnswer")).font(.system(size: 11.9)).foregroundStyle(
          p.muted)
      }
      ForEach(probe.answers, id: \.self) { line in
        Text(line).font(.system(size: 11.5, design: .monospaced)).textSelection(.enabled)
      }
      if probe.fakePool {
        Text(L10n.text("native.dns.probe.fake")).font(.system(size: 11.5)).foregroundStyle(
          p["warn"])
      }
      if probe.truncated {
        Text(L10n.text("native.dns.probe.truncated")).font(.system(size: 11.5)).foregroundStyle(
          p["warn"])
      }
    }
  }

  private func run() async {
    querying = true
    defer { querying = false }
    answer = nil
    answer = await model.probeDns(
      host: host.trimmingCharacters(in: .whitespaces), server: server, ipv6: ipv6)
  }

  // MARK: Resolvers

  private func section(_ title: String, _ resolvers: [DnsResolver]) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      AppHeading(title: title)
      ForEach(resolvers) { resolver in row(resolver) }
    }
  }

  private func row(_ resolver: DnsResolver) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      HStack(spacing: 8) {
        Circle().fill(resolver.reachable ? p["up"] : p["unknown"]).frame(width: 7, height: 7)
        Text(resolver.title ?? L10n.text("native.dns.default"))
          .font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        if let interface = resolver.interface {
          Text(interface).font(.system(size: 10.92, design: .monospaced)).foregroundStyle(
            p.secondary)
        }
        if resolver.supplemental { AppBadge(text: "native.dns.supplemental", color: "info") }
        if resolver.mdns { AppBadge(text: "native.dns.mdns") }
        if !resolver.reachable { AppBadge(text: "native.dns.unreachable", color: "warn") }
        Spacer()
        if let order = resolver.order {
          Text(L10n.text("native.dns.order", ["order": String(order)])).font(.system(size: 10.92))
            .foregroundStyle(p.muted)
        }
      }
      if !resolver.serverTexts.isEmpty {
        Text(resolver.serverTexts.joined(separator: "   ")).font(
          .system(size: 11.2, design: .monospaced)
        ).foregroundStyle(p.secondary).textSelection(.enabled)
      }
      if !resolver.searchDomains.isEmpty {
        Text(
          L10n.text("native.dns.search", ["domains": resolver.searchDomains.joined(separator: ", ")])
        ).font(.system(size: 10.92)).foregroundStyle(p.muted)
      }
    }
    .padding(.horizontal, 8).padding(.vertical, 8)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }
}
