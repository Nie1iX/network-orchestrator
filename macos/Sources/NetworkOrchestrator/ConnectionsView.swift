import AppKit
import SwiftUI
import UniformTypeIdentifiers

enum ConnectionModal: Identifiable {
  case add
  case importConfig(String?)
  case staticRoutes
  var id: String {
    switch self {
    case .add: "add"
    case .importConfig(let backend): "import-" + (backend ?? "auto")
    case .staticRoutes: "static"
    }
  }
}
struct ConnectionsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @Binding var modal: ConnectionModal?
  @State private var collapsed = Set<String>()
  @State private var renaming: Profile?
  @State private var deleting: Profile?
  @State private var name = ""
  var body: some View {
    VStack(alignment: .leading, spacing: 10.5) {
      HStack(spacing: 7) {
        Text(L10n.text("profiles.title")).font(.system(size: 14.7, weight: .semibold))
        Spacer()
        AppInput(placeholder: "profiles.searchPh", text: $model.search).frame(width: 240)
        Button(L10n.text(model.refreshing.isEmpty ? "common.refresh" : "detail.refreshing")) {
          Task { await model.refreshAll() }
        }.disabled(!model.refreshing.isEmpty || model.busy)
          .help(L10n.text("native.refreshAllHint"))
        Button(L10n.text("profiles.import")) { modal = .importConfig(nil) }
        Button(L10n.text("+ Add connection")) { modal = .add }.buttonStyle(
          TauriButtonStyle(kind: .accent))
      }
      notices
      if model.profiles.isEmpty {
        AppEmptyState {
          Text(
            model.search.isEmpty
              ? L10n.text("profiles.empty")
              : L10n.text("profiles.noMatch", ["query": model.search]))
        }
      } else {
        HStack(alignment: .top, spacing: 0) {
          list.frame(width: 400)
          Rectangle().fill(p.border).frame(width: 1).padding(.horizontal, 14)
          if let profile = model.selectedProfile {
            ProfileDetailView(
              model: model, profile: profile,
              onRename: {
                name = profile.name
                renaming = profile
              }, onDelete: { deleting = profile }
            ).id(profile.id)
          }
        }
      }
    }
    .sheet(item: $renaming) { profile in
      AppModal(title: "Rename connection", width: 440, onClose: { renaming = nil }) {
        VStack(alignment: .leading, spacing: 14) {
          AppInput(placeholder: "Name", text: $name)
          HStack {
            Spacer()
            Button(L10n.text("Cancel")) { renaming = nil }
            Button(L10n.text("Save")) {
              Task { if await model.rename(profile, name: name) { renaming = nil } }
            }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(
              name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.busy)
          }
        }.padding(14)
      }.environment(\.palette, p)
    }
    .alert(
      L10n.text("Delete connection?"),
      isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })
    ) {
      Button(L10n.text("Cancel"), role: .cancel) { deleting = nil }
      Button(L10n.text("Delete"), role: .destructive) {
        if let profile = deleting { Task { await model.remove(profile) } }
        deleting = nil
      }
    } message: {
      Text(L10n.text("The saved profile and its managed configuration will be removed."))
    }
  }
  @ViewBuilder private var notices: some View {
    if model.importSkippedCount > 0 {
      Text(
        L10n.text(
          "Skipped {count} unsupported or invalid endpoints.",
          ["count": String(model.importSkippedCount)])
      ).font(.system(size: 11.9)).foregroundStyle(p.secondary)
    }
    if model.canStartConnections, let runtime = model.runtime, !runtime.xrayInstalled,
      model.snapshot?.profiles.contains(where: { $0.backend == "xray" }) ?? false
    {
      NoticeBar(color: "info") {
        Text(L10n.text("native.xrayMissing", ["version": runtime.xrayVersion]))
        Spacer()
        Button(L10n.text(model.installingXray ? "native.installing" : "native.installXray")) {
          Task { await model.installXray() }
        }.buttonStyle(TauriButtonStyle(kind: .accent, compact: true)).disabled(
          model.installingXray)
        Button(L10n.text("native.installXrayFile")) {
          let panel = NSOpenPanel()
          panel.allowedContentTypes = [.zip]
          panel.message = L10n.text("native.installXrayFileHint")
          if panel.runModal() == .OK, let url = panel.url {
            Task { await model.installXray(archive: url) }
          }
        }.buttonStyle(TauriButtonStyle(compact: true)).disabled(model.installingXray)
      }
    }
    if let notice = model.notice {
      NoticeBar(color: notice == "native.proxyOverridden" ? "warn" : "up") {
        Text(L10n.text(notice, ["iface": model.primaryInterface ?? ""]))
        Spacer()
        Button(L10n.text("common.dismiss")) { model.notice = nil }.buttonStyle(
          TauriButtonStyle(compact: true))
      }
    }
  }
  private var list: some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(["wireGuard", "openVpn", "xray", "none"], id: \.self) { backend in
        let profiles = model.profiles.filter { $0.backend == backend }
        if !profiles.isEmpty {
          Button {
            if !collapsed.insert(backend).inserted { collapsed.remove(backend) }
          } label: {
            HStack(spacing: 7) {
              NativeIcon(name: "ChevronIcon", size: 12).rotationEffect(
                .degrees(collapsed.contains(backend) ? 0 : 180))
              NativeIcon(name: NativeIcon.backend(backend), size: 15)
              Text(L10n.text(profiles[0].kind)).font(.system(size: 11.2, weight: .semibold))
              Text("· \(profiles.count)").font(.system(size: 10.08)).foregroundStyle(p.muted)
              Spacer()
            }.foregroundStyle(p.secondary).padding(.horizontal, 8).padding(.top, 14)
              .padding(.bottom, 5).contentShape(Rectangle())
          }.buttonStyle(.plain).accessibilityLabel(L10n.text(profiles[0].kind))
          Rectangle().fill(p.border).frame(height: 1)
          if !collapsed.contains(backend) {
            ForEach(profiles) { profile in row(profile) }
          }
        }
      }
    }
  }
  private func row(_ profile: Profile) -> some View {
    let selected = model.selectedProfile?.id == profile.id
    let state = model.status(profile)?.state ?? "stopped"
    return HStack(spacing: 8) {
      StateDot(state: state)
      NativeIcon(name: NativeIcon.backend(profile.backend), size: 14).foregroundStyle(
        p[backendTint(profile.backend)])
      // A subscription reads as a group: its name, then the chosen server.
      VStack(alignment: .leading, spacing: 1) {
        Text(profile.groupName).font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        if let server = model.activeServer(profile), server != profile.groupName {
          Text(profile.serverLabel(server)).font(.system(size: 10.5)).foregroundStyle(
            p.secondary
          ).lineLimit(1)
        }
      }
      Spacer(minLength: 8)
      Text(rowMeta(profile)).font(.system(size: 11, design: .monospaced)).foregroundStyle(
        p.muted
      ).lineLimit(1)
      ConnectionSwitch(model: model, profile: profile)
    }
    .padding(.horizontal, 8).padding(.vertical, 5)
    .background(selected ? p["bg-elev"] : .clear)
    .overlay(alignment: .leading) {
      if selected || state == "running" || state == "failed" {
        Rectangle().fill(selected ? p.accent : state == "running" ? p["up"] : p["down"]).frame(
          width: 2)
      }
    }
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
    .contentShape(Rectangle())
    .onTapGesture { model.selectedProfileID = profile.id }
    .contextMenu {
      if profile.startsWithoutHelper && model.canStartConnections {
        Button(L10n.text(model.isRunning(profile) ? "common.disconnect" : "common.connect")) {
          Task { await model.toggle(profile) }
        }
        Divider()
      }
      Button(L10n.text("Rename")) {
        name = profile.name
        renaming = profile
      }
      Button(L10n.text("Inspect configuration")) { Task { await model.inspect(profile) } }
      Divider()
      Button(L10n.text("Delete"), role: .destructive) { deleting = profile }
    }
    .accessibilityElement(children: .combine).accessibilityAddTraits(
      selected ? [.isSelected, .isButton] : [.isButton])
  }
  private func rowMeta(_ profile: Profile) -> String {
    if profile.backend == "xray", let port = profile.xraySocksPort { return ":\(port)" }
    return profile.interfaceName.isEmpty ? "—" : profile.interfaceName
  }
}

func backendTint(_ backend: String) -> String {
  switch backend {
  case "wireGuard": "wg-color"
  case "openVpn": "ovpn-color"
  case "xray": "xray-color"
  default: "none-color"
  }
}

struct StateDot: View {
  @Environment(\.palette) private var p
  let state: String
  var body: some View {
    Circle().fill(state == "running" ? p["up"] : state == "failed" ? p["down"] : p["unknown"])
      .frame(width: 7, height: 7)
  }
}

struct NoticeBar<Content: View>: View {
  @Environment(\.palette) private var p
  let color: String
  @ViewBuilder let content: Content
  var body: some View {
    HStack(spacing: 10.5) { content }.font(.system(size: 11.9)).padding(.horizontal, 12)
      .padding(.vertical, 7).background(p[color + "-bg"]).overlay(
        RoundedRectangle(cornerRadius: 6).stroke(p[color + "-border"], lineWidth: 1)
      ).clipShape(RoundedRectangle(cornerRadius: 6))
  }
}

/// Real on/off switch for connections this client can start; others render a
/// disabled switch explaining that the privileged helper is still missing.
struct ConnectionSwitch: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  var body: some View {
    let running = model.isRunning(profile)
    let busy = model.pending.contains(profile.id)
    let enabled =
      model.canStartConnections && profile.startsWithoutHelper
      && (model.runtime?.xrayInstalled ?? false) && !busy
    Button {
      Task { await model.toggle(profile) }
    } label: {
      Capsule().fill(running ? p["up"] : p.border).frame(width: 34, height: 20).overlay(
        alignment: running ? .trailing : .leading
      ) {
        Circle().fill(.white).frame(width: 16, height: 16).shadow(
          color: .black.opacity(0.2), radius: 1, y: 1
        ).padding(2)
      }.opacity(busy ? 0.6 : 1).animation(.easeOut(duration: 0.12), value: running)
    }.buttonStyle(.plain).disabled(!enabled)
      .help(
        L10n.text(
          !profile.startsWithoutHelper
            ? "native.helperRequired"
            : running ? "common.disconnect" : "common.connect")
      )
      .accessibilityLabel(L10n.text(running ? "common.disconnect" : "common.connect"))
  }
}

/// What the subscription provider says about itself: title, announcement and
/// support / account links (https only, opened in the default browser).
struct PanelInfoView: View {
  @Environment(\.palette) private var p
  let subscription: SubscriptionMeta
  let profileName: String
  var body: some View {
    let links: [(String, URL)] = [
      ("native.panelSupport", subscription.supportUrl),
      ("native.panelAccount", subscription.webPageUrl),
    ].compactMap { label, value in
      guard let value, let url = URL(string: value), ["https", "http"].contains(url.scheme ?? "")
      else { return nil }
      return (label, url)
    }
    let skipped = subscription.skippedProtocols ?? []
    if subscription.providerTitle != nil || subscription.announce != nil || !links.isEmpty
      || !skipped.isEmpty
    {
      VStack(alignment: .leading, spacing: 5) {
        if let title = subscription.providerTitle, title != profileName {
          Text(title).font(.system(size: 11.9, weight: .semibold))
        }
        if let announce = subscription.announce {
          Text(announce).font(.system(size: 11.9)).foregroundStyle(p.secondary)
            .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
        }
        if !skipped.isEmpty {
          Text(L10n.text("native.skippedProtocols", ["list": skipped.joined(separator: ", ")]))
            .font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
        if !links.isEmpty {
          HStack(spacing: 7) {
            ForEach(links, id: \.0) { label, url in
              Button(L10n.text(label)) { NSWorkspace.shared.open(url) }
                .buttonStyle(TauriButtonStyle(compact: true)).help(url.host() ?? "")
            }
          }.padding(.top, 2)
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.horizontal, 12).padding(.vertical, 9)
      .background(p["info-bg"], in: RoundedRectangle(cornerRadius: 6))
      .overlay(RoundedRectangle(cornerRadius: 6).stroke(p["info-border"], lineWidth: 1))
    }
  }
}

struct ProfileDetailView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var editingRules = false
  @State private var showingLog = false
  let profile: Profile
  let onRename: () -> Void
  let onDelete: () -> Void
  var body: some View {
    let status = model.status(profile)
    let running = status?.state == "running"
    let proxyOwner = model.runtime?.systemProxyOwner == profile.id
    VStack(alignment: .leading, spacing: 0) {
      HStack(alignment: .top, spacing: 10.5) {
        NativeIcon(name: NativeIcon.backend(profile.backend), size: 18)
          .foregroundStyle(p[backendTint(profile.backend)]).frame(width: 34, height: 34)
          .background(p[backendTint(profile.backend)].opacity(0.14), in: Circle())
        VStack(alignment: .leading, spacing: 3) {
          HStack(spacing: 7) {
            Text(profile.name).font(.system(size: 14.7, weight: .semibold)).lineLimit(1)
            if profile.backend != "none" { AppBadge(text: "detail.managed") }
            if proxyOwner { AppBadge(text: "native.systemProxy", color: "up") }
          }
          Text(statusLine(status)).font(.system(size: 11.2)).foregroundStyle(
            status?.state == "failed" ? p["down"] : p.muted
          ).lineLimit(2)
        }
        Spacer()
        ConnectionSwitch(model: model, profile: profile)
        Menu {
          Button(L10n.text("Rename"), action: onRename)
          Button(L10n.text("Inspect configuration")) { Task { await model.inspect(profile) } }
          if profile.backend == "xray" {
            Button(L10n.text("native.connectionLog")) { showingLog = true }
            Divider()
            Button(L10n.text("native.openBrowser")) { model.openBrowser(profile) }.disabled(
              !running)
            Button(L10n.text("native.copyTerminal")) { model.copyTerminalProxy(profile) }
          }
          Divider()
          Button(L10n.text("Delete"), role: .destructive, action: onDelete)
        } label: {
          NativeIcon(name: "DotsVerticalIcon", size: 16).frame(width: 28, height: 28)
        }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).foregroundStyle(
          p.secondary
        ).frame(width: 28).help(L10n.text("detail.actions"))
      }.padding(.bottom, 10.5)
      Rectangle().fill(p.border).frame(height: 1).padding(.bottom, 7)
      if let subscription = profile.subscription {
        PanelInfoView(subscription: subscription, profileName: profile.groupName)
          .padding(.bottom, 7)
      }
      row("detail.backend", L10n.text(profile.kind), mono: false)
      if let server = model.activeServer(profile) {
        row("native.server", server, mono: false)
      }
      if let usage = profile.subscription?.userInfo {
        row("detail.traffic", Self.usageText(usage), mono: false)
      }
      if profile.backend != "xray" {
        row(
          "detail.interface",
          profile.interfaceName.isEmpty ? L10n.text("detail.notAssigned") : profile.interfaceName)
      }
      if let port = profile.xraySocksPort { row("SOCKS5", "127.0.0.1:\(port)", translate: false) }
      if let port = profile.xrayHttpPort {
        row("HTTP CONNECT", "127.0.0.1:\(port)", translate: false)
      }
      if profile.startsWithoutHelper && model.canStartConnections {
        HStack {
          VStack(alignment: .leading, spacing: 2) {
            Text(L10n.text("native.systemProxy")).foregroundStyle(p.muted)
            Text(L10n.text("native.systemProxyHint")).font(.system(size: 10.08)).foregroundStyle(
              p.muted)
          }
          Spacer()
          Toggle(
            "",
            isOn: Binding(
              get: { proxyOwner },
              set: { value in Task { await model.setSystemProxy(profile, enabled: value) } })
          ).toggleStyle(.switch).controlSize(.small).labelsHidden().disabled(
            !running || (!proxyOwner && model.runtime?.systemProxyOwner != nil))
        }.font(.system(size: 11.9)).padding(.vertical, 5)
        if running {
          HStack(spacing: 7) {
            Button(L10n.text("native.openBrowser")) { model.openBrowser(profile) }.buttonStyle(
              TauriButtonStyle(compact: true))
            Button(L10n.text("native.copyTerminal")) { model.copyTerminalProxy(profile) }
              .buttonStyle(TauriButtonStyle(compact: true))
          }.padding(.vertical, 5)
        }
      }
      if profile.backend == "xray" { routingRules }
      tunnelConfig
      endpoints
      if !profile.routes.isEmpty {
        section("detail.routes")
        ForEach(Array(profile.routes.enumerated()), id: \.offset) { _, route in
          HStack(spacing: 7) {
            Text("• " + route.destination).font(.system(size: 11.9, design: .monospaced))
            Text(L10n.text("detail.metric", ["n": String(route.metric)])).font(
              .system(size: 9.8)
            ).foregroundStyle(p.muted).padding(.horizontal, 5).padding(.vertical, 1).background(
              p["bg-elev"], in: Capsule())
          }.padding(.vertical, 2)
        }
      }
      Spacer(minLength: 0)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .task(id: profile.id) { await model.loadInspection(profile) }
    .sheet(isPresented: $showingLog) {
      LogSheet(
        title: L10n.text("diag.title", ["name": profile.groupName]),
        load: { await model.connectionLog(profile) }, onClose: { showingLog = false }
      ).environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
    .sheet(isPresented: $editingRules) {
      RoutingRulesEditor(model: model, profile: profile) { editingRules = false }
        .environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
  }
  /// Compact per-set summary; the sets are edited in a full-size sheet.
  @ViewBuilder private var routingRules: some View {
    HStack {
      section("detail.domainRules")
      Spacer()
      Button(L10n.text("common.edit")) { editingRules = true }.buttonStyle(
        TauriButtonStyle(compact: true)
      ).padding(.top, 6)
    }
    ForEach(RoutingRulesEditor.sets, id: \.target) { set in
      let count = profile.rules(set.target).filter { !$0.hasPrefix("#") }.count
      HStack(spacing: 7) {
        Circle().fill(p[set.color]).frame(width: 7, height: 7)
        Text(L10n.text(set.title)).foregroundStyle(p.muted)
        Spacer()
        Text(L10n.text("rules.entryCount", ["count": String(count)]))
          .foregroundStyle(count == 0 ? p.muted : p.text)
      }.font(.system(size: 11.9)).padding(.vertical, 2)
    }
    if profile.privateLanDirect ?? false {
      Text(L10n.text("form.privateLanDirect")).font(.system(size: 10.92)).foregroundStyle(p.muted)
    }
  }
  @ViewBuilder private var tunnelConfig: some View {
    if let inspection = model.inspections[profile.id],
      profile.backend == "wireGuard" || profile.backend == "openVpn"
    {
      let wireGuard = profile.backend == "wireGuard"
      let flatEndpoints = wireGuard ? [] : inspection.endpoints
      let flatRoutes = wireGuard ? [] : inspection.osRoutes
      if !inspection.interfaceDetails.isEmpty || !inspection.peers.isEmpty
        || !flatEndpoints.isEmpty || !flatRoutes.isEmpty
      {
        section("detail.tunnelConfig")
        ForEach(Array(inspection.interfaceDetails.enumerated()), id: \.offset) { _, detail in
          row(Self.fieldKeys[detail.field] ?? "detail.tunnelConfig", detail.value)
        }
        if wireGuard {
          ForEach(Array(inspection.peers.enumerated()), id: \.offset) { index, peer in
            row(
              L10n.text("detail.peerN", ["n": String(index + 1)]), peer.endpoint?.label ?? "—",
              translate: false)
            ForEach(Array(peer.routes.enumerated()), id: \.offset) { _, route in
              bullet(route.destination)
            }
          }
        }
        ForEach(Array(flatEndpoints.enumerated()), id: \.offset) { _, endpoint in
          row("detail.peerEndpoint", endpoint.label)
        }
        ForEach(Array(flatRoutes.enumerated()), id: \.offset) { _, route in
          bullet(route.destination)
        }
      }
    }
  }
  @ViewBuilder private var endpoints: some View {
    if let subscription = profile.subscription,
      let endpoints = model.subscriptionEndpoints[profile.id]
    {
      HStack(spacing: 7) {
        section(L10n.text("detail.endpoints") + " · \(endpoints.count)", translate: false)
        Spacer()
        let pending = model.probing[profile.id]
        Button {
          Task { await model.measureDelays(profile) }
        } label: {
          HStack(spacing: 6) {
            if let pending {
              Spinner(size: 10)
              Text(
                L10n.text(
                  "native.pingProgress",
                  ["done": String(endpoints.count - pending.count), "total": String(endpoints.count)]))
            } else {
              Text(L10n.text("native.ping"))
            }
          }
        }.buttonStyle(TauriButtonStyle(compact: true))
          .disabled(pending != nil || !(model.runtime?.xrayInstalled ?? false))
          .help(L10n.text("detail.testAllTitle"))
        Button(L10n.text(model.refreshing.contains(profile.id) ? "detail.refreshing" : "detail.refreshSub")) {
          Task { await model.refreshSubscription(profile) }
        }.buttonStyle(TauriButtonStyle(compact: true)).disabled(
          model.refreshing.contains(profile.id) || model.busy)
      }.padding(.top, 6)
      let busy = model.busy || model.pending.contains(profile.id)
      ForEach(Array(endpoints.enumerated()), id: \.offset) { index, endpoint in
        let active = index == subscription.activeIndex
        Button {
          Task { await model.switchEndpoint(profile, index: index) }
        } label: {
          HStack(spacing: 7) {
            Circle().fill(active ? p.accent : .clear).frame(width: 6, height: 6)
            Text(profile.serverLabel(endpoint.name)).font(
              .system(size: 11.9, weight: active ? .semibold : .regular)
            ).lineLimit(1)
            if let proto = endpoint.protocol {
              Text(proto).font(.system(size: 9.8, design: .monospaced)).foregroundStyle(p.muted)
                .padding(.horizontal, 4).padding(.vertical, 1)
                .overlay(RoundedRectangle(cornerRadius: 3).stroke(p.border, lineWidth: 1))
            }
            Spacer()
            if model.probing[profile.id]?.contains(index) ?? false {
              Spinner(size: 10)
            } else {
              delayBadge(model.delays[profile.id]?[index])
            }
          }.padding(.horizontal, 7).padding(.vertical, 4).background(
            active ? p["accent-dim"] : .clear, in: RoundedRectangle(cornerRadius: 5)
          ).contentShape(Rectangle())
        }.buttonStyle(.plain).disabled(active || busy)
          .help(L10n.text(active ? "detail.activeEndpoint" : "detail.switchEndpoint"))
      }
    }
  }
  /// Delay readout: green under 300 ms, amber under 800 ms, red above or
  /// when the server did not answer; nothing until measured.
  @ViewBuilder private func delayBadge(_ value: UInt64??) -> some View {
    switch value {
    case .some(.some(let ms)):
      Text(L10n.text("native.ms", ["ms": String(ms)])).font(
        .system(size: 10.5, weight: .medium, design: .monospaced)
      ).foregroundStyle(p[ms < 300 ? "up" : ms < 800 ? "warn" : "down"])
    case .some(.none):
      Text(L10n.text("detail.unreachable")).font(.system(size: 10.5)).foregroundStyle(p["down"])
    case .none:
      EmptyView()
    }
  }
  static func usageText(_ usage: SubscriptionUsage) -> String {
    let format = { (bytes: UInt64) in
      ByteCountFormatter.string(fromByteCount: Int64(clamping: bytes), countStyle: .binary)
    }
    var text = format(usage.uploadBytes + usage.downloadBytes)
    text += " / " + (usage.totalBytes.map(format) ?? L10n.text("detail.unlimited"))
    if let expires = usage.expiresAtUnix {
      let date = Date(timeIntervalSince1970: TimeInterval(expires))
      text += " · " + L10n.text("native.until", [
        "date": date.formatted(.dateTime.day().month().year().locale(Locale(identifier: L10n.shared.language)))
      ])
    }
    return text
  }
  private static let fieldKeys: [String: String] = [
    "address": "detail.cfg.address", "dns": "detail.cfg.dns", "mtu": "detail.cfg.mtu",
    "listenPort": "detail.cfg.listenPort", "protocol": "detail.cfg.protocol",
    "device": "detail.cfg.device", "cipher": "detail.cfg.cipher",
    "authUserPass": "detail.cfg.authUserPass",
  ]
  private func statusLine(_ status: TunnelStatus?) -> String {
    switch status?.state {
    case "running":
      L10n.text("detail.runningOn", ["iface": profile.xraySocksPort.map { "127.0.0.1:\($0)" } ?? "tunnel"])
        + (model.activeServer(profile).map { " · \($0)" } ?? "")
    case "failed": status?.message.map { L10n.text($0) } ?? L10n.text("detail.failed")
    default:
      profile.startsWithoutHelper || !model.canStartConnections
        ? L10n.text("detail.stopped") : L10n.text("native.helperRequired")
    }
  }
  private func section(_ title: String, translate: Bool = true) -> some View {
    Text(translate ? L10n.text(title) : title).font(.system(size: 11.2, weight: .semibold))
      .foregroundStyle(p.secondary).padding(.top, 12).padding(.bottom, 3)
  }
  private func row(_ label: String, _ value: String, mono: Bool = true, translate: Bool = true)
    -> some View
  {
    HStack {
      Text(translate ? L10n.text(label) : label).foregroundStyle(p.muted)
      Spacer()
      Text(value).font(.system(size: 11.9, design: mono ? .monospaced : .default)).lineLimit(1)
        .textSelection(.enabled)
    }.font(.system(size: 11.9)).padding(.vertical, 3)
  }
  private func bullet(_ value: String) -> some View {
    Text("• " + value).font(.system(size: 11.9, design: .monospaced)).padding(.vertical, 1)
      .padding(.leading, 7)
  }
}
struct ConnectionModalView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let modal: ConnectionModal
  let onClose: () -> Void
  let onChoose: (ConnectionModal) -> Void
  var body: some View {
    switch modal {
    case .add:
      AppModal(title: "Add a connection", width: 480, onClose: onClose) {
        VStack(spacing: 7) {
          option(
            "ImportIcon", "Paste a link or import a file",
            "Subscription URL, share link, or a config file", .importConfig(nil))
          option(
            "WireGuardIcon", "WireGuard", "Enter tunnel keys, or open an existing .conf file.",
            .importConfig("wireGuard"))
          option(
            "OpenVpnIcon", "OpenVPN", "Use an existing .ovpn client config.",
            .importConfig("openVpn"))
          option(
            "XrayIcon", "Xray", "Import a share link, or an Xray JSON config.",
            .importConfig("xray"))
          option(
            "StaticRoutesIcon", "Static routes",
            "Route traffic through an existing interface, no tunnel.", .staticRoutes)
        }.padding(14)
      }
    case .importConfig(let backend):
      ImportConfigurationView(model: model, preferredBackend: backend, onClose: onClose)
    case .staticRoutes: StaticProfileView(model: model, onClose: onClose)
    }
  }
  private func option(
    _ icon: String, _ title: String, _ description: String, _ destination: ConnectionModal
  ) -> some View {
    Button {
      onChoose(destination)
    } label: {
      HStack(spacing: 10.5) {
        NativeIcon(name: icon, size: 18).foregroundStyle(p.accent).frame(width: 36, height: 36)
          .background(p["accent-dim"], in: Circle())
        VStack(alignment: .leading, spacing: 2) {
          Text(L10n.text(title)).font(.system(size: 12.6, weight: .semibold))
          Text(L10n.text(description)).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
        Spacer(minLength: 0)
      }.padding(10.5).background(p["bg-elev"], in: RoundedRectangle(cornerRadius: 12)).overlay(
        RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
    }.buttonStyle(.plain)
  }
}
struct ImportConfigurationView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let preferredBackend: String?
  let onClose: () -> Void
  @State private var tab = "Files"
  @State private var name = ""
  @State private var backend = "wireGuard"
  @State private var file: URL?
  @State private var shareLink = ""
  @State private var subscriptionURL = ""
  @State private var hwid = ""
  @AppStorage("autoHWID") private var autoHWID = true
  init(
    model: AppModel, preferredBackend: String?, onClose: @escaping () -> Void,
    initialTab: String? = nil
  ) {
    self.model = model
    self.preferredBackend = preferredBackend
    self.onClose = onClose
    _tab = State(initialValue: initialTab ?? (preferredBackend == "xray" ? "Link" : "Files"))
  }
  var body: some View {
    AppModal(title: "Import configurations", width: 520, onClose: onClose) {
      VStack(alignment: .leading, spacing: 10.5) {
        AppTabs(
          titles: ["Files", "Link", "Subscription", "WireGuard location"], selected: $tab
        )
        .disabled(model.busy)
        if tab == "Files" {
          Text(
            L10n.text("Import WireGuard (.conf), OpenVPN (.ovpn), or Xray (.json) configurations.")
          ).font(
            .system(size: 11.9)
          ).foregroundStyle(p.secondary)
          Button(L10n.text("Choose files…")) { chooseFile() }
          if let file {
            Text(file.lastPathComponent).font(.system(size: 11.9)).foregroundStyle(p.secondary)
            Text(L10n.text("Name")).font(.system(size: 11.9))
            AppInput(placeholder: "Connection name", text: $name)
            HStack {
              Text(L10n.text("Backend")).font(.system(size: 11.9))
              Spacer()
              Picker("Backend", selection: $backend) {
                Text(L10n.text("WireGuard")).tag("wireGuard")
                Text(L10n.text("OpenVPN")).tag("openVpn")
                Text(L10n.text("Xray")).tag("xray")
              }.labelsHidden().frame(width: 170)
            }
          }
          Text(L10n.text("A private, managed copy is stored locally. Import does not start a VPN."))
            .font(
              .system(size: 10.92)
            ).foregroundStyle(p.muted)
        } else if tab == "Link" {
          Text(
            L10n.text(
              "native.linkHint"
            )
          )
          .font(.system(size: 11.9)).foregroundStyle(p.secondary)
          Text(L10n.text("Share link")).font(.system(size: 11.9))
          AppInput(placeholder: "native.linkPlaceholder", text: $shareLink)
            .disabled(model.busy)
            .onChange(of: shareLink) { model.error = nil }
          Text(L10n.text("Connection name (optional)")).font(.system(size: 11.9))
          AppInput(placeholder: "Use the name from the link", text: $name).disabled(model.busy)
        } else if tab == "Subscription" {
          Text(
            L10n.text(
              "Import a subscription URL. Supported vless:// and hysteria2:// endpoints are grouped into a profile with an endpoint selector."
            )
          )
          .font(.system(size: 11.9)).foregroundStyle(p.secondary)
          Text(L10n.text("Subscription URL")).font(.system(size: 11.9))
          AppInput(placeholder: "https://example.com/sub", text: $subscriptionURL)
            .disabled(model.busy)
            .onChange(of: subscriptionURL) { model.error = nil }
          Text(L10n.text("HWID (X-HWID header, optional)")).font(.system(size: 11.9))
          HStack(spacing: 10.5) {
            AppInput(
              placeholder: autoHWID ? "native.hwidAutoPlaceholder" : "device-hwid", text: $hwid
            ).disabled(model.busy || autoHWID)
            Toggle(L10n.text("native.hwidAuto"), isOn: $autoHWID).toggleStyle(.checkbox)
              .font(.system(size: 11.9)).fixedSize().disabled(model.busy)
              .onChange(of: autoHWID) { _, enabled in if enabled { hwid = "" } }
          }
          Text(L10n.text("Connection name (optional)")).font(.system(size: 11.9))
          AppInput(placeholder: "Use the name from the link", text: $name).disabled(model.busy)
          Text(
            L10n.text(
              "Import does not start a VPN. Automatic subscription refresh is not available in this native version yet."
            )
          )
          .font(.system(size: 10.92)).foregroundStyle(p.muted)
        } else {
          AppEmptyState {
            Text(
              L10n.text(
                "Automatic discovery is not implemented on macOS yet. Use Files to choose your WireGuard configuration."
              ))
          }
        }
        if let error = model.error {
          Text(L10n.text(error)).foregroundStyle(p["down"]).font(.system(size: 11.9))
        }
        HStack {
          Spacer()
          Button(L10n.text("Cancel"), action: onClose)
          Button(
            model.busy
              ? (tab == "Subscription" ? L10n.text("Fetching…") : L10n.text("Importing…"))
              : (tab == "Subscription" ? L10n.text("Fetch subscription") : L10n.text("Import"))
          ) {
            Task {
              let imported: Bool
              let link = shareLink.trimmingCharacters(in: .whitespacesAndNewlines)
              if tab == "Link" && Self.isSubscriptionURL(link) {
                var generated = ""
                if autoHWID {
                  guard let value = await model.generateHWID() else { return }
                  generated = value
                }
                imported = await model.importSubscription(url: link, hwid: generated, name: name)
              } else if tab == "Link" {
                imported = await model.importShareLink(link, name: name)
              } else if tab == "Subscription" {
                if autoHWID {
                  guard let value = await model.generateHWID() else { return }
                  hwid = value
                }
                imported = await model.importSubscription(
                  url: subscriptionURL, hwid: hwid, name: name)
              } else if let file {
                imported = await model.importConfig(url: file, backend: backend, name: name)
              } else {
                imported = false
              }
              if imported {
                onClose()
                model.section = .connections
              }
            }
          }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(
            model.busy
              || (tab == "Link"
                ? shareLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                : tab == "Subscription"
                  ? subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                  : tab != "Files" || file == nil
                    || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
          )
        }
      }.padding(14)
    }
    .dropDestination(for: URL.self) { urls, _ in
      guard let url = urls.first, url.isFileURL else { return false }
      use(url)
      return true
    }
    .onAppear {
      backend = preferredBackend ?? "wireGuard"
      model.error = nil
    }
  }
  private func chooseFile() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    // Any file: configs often arrive as .txt or without an extension; the
    // backend picker and the shared analysis decide what is importable.
    panel.message = L10n.text("Import WireGuard (.conf), OpenVPN (.ovpn), or Xray (.json) configurations.")
    if panel.runModal() == .OK, let url = panel.url { use(url) }
  }
  static func isSubscriptionURL(_ text: String) -> Bool {
    let lower = text.lowercased()
    return lower.hasPrefix("https://") || lower.hasPrefix("http://")
  }
  private func use(_ url: URL) {
    tab = "Files"
    file = url
    if name.isEmpty { name = url.deletingPathExtension().lastPathComponent }
    backend =
      preferredBackend
      ?? (url.pathExtension == "ovpn"
        ? "openVpn" : url.pathExtension == "json" ? "xray" : "wireGuard")
  }
}
struct StaticProfileView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let onClose: () -> Void
  @State private var name = ""
  @State private var interface = ""
  @State private var cidrs = ""
  var body: some View {
    AppModal(title: "New connection", width: 620, onClose: onClose) {
      VStack(alignment: .leading, spacing: 10.5) {
        Text(L10n.text("Static routes")).font(.system(size: 13.3, weight: .semibold))
        Text(L10n.text("Name")).font(.system(size: 11.9))
        AppInput(placeholder: "Connection name", text: $name)
        Text(L10n.text("Interface")).font(.system(size: 11.9))
        AppInput(placeholder: "Interface name, e.g. en0", text: $interface)
        Text(L10n.text("Routes")).font(.system(size: 13.3, weight: .semibold))
        TextEditor(text: $cidrs).font(.system(size: 11.9, design: .monospaced))
          .scrollContentBackground(.hidden).padding(7).frame(height: 120).background(
            p.input, in: RoundedRectangle(cornerRadius: 6)
          ).overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
          .accessibilityLabel(L10n.text("Bulk CIDRs"))
        Text(
          L10n.text(
            "Paste IPv4/IPv6 CIDRs. Duplicates and adjacent networks are aggregated. Routes are saved and analyzed, never applied in this native version."
          )
        ).font(.system(size: 10.92)).foregroundStyle(p.muted)
        if let error = model.error {
          Text(L10n.text(error)).font(.system(size: 11.9)).foregroundStyle(p["down"])
        }
        HStack {
          Spacer()
          Button(L10n.text("Cancel"), action: onClose)
          Button(L10n.text(model.busy ? "Saving…" : "Save")) {
            Task {
              if await model.createStatic(name: name, interface: interface, cidrs: cidrs) {
                onClose()
                model.section = .connections
              }
            }
          }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(
            model.busy
              || [name, interface, cidrs].contains {
                $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
              })
        }
      }.padding(14)
    }
  }
}
struct InspectionView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  @Environment(\.dismiss) private var dismiss
  var body: some View {
    AppModal(
      title: L10n.text(
        "Configuration analysis — {name}", ["name": String(describing: profile.name)]), width: 650,
      onClose: dismiss.callAsFunction
    ) {
      ScrollView {
        VStack(alignment: .leading, spacing: 14) {
          if let inspection = model.inspection {
            AppHeading(title: "OS routes")
            if inspection.osRoutes.isEmpty {
              Text(L10n.text("No declared OS routes")).foregroundStyle(p.muted)
            }
            ForEach(Array(inspection.osRoutes.enumerated()), id: \.offset) { _, route in
              Text("\(route.destination) · \(route.source)").font(
                .system(size: 11.9, design: .monospaced))
            }
            if !inspection.internalRoutes.isEmpty {
              AppHeading(title: "Internal proxy routes")
              ForEach(Array(inspection.internalRoutes.enumerated()), id: \.offset) { _, route in
                Text("\(route.destination) · \(route.source)").font(
                  .system(size: 11.9, design: .monospaced))
              }
            }
            if !inspection.listeners.isEmpty {
              AppHeading(title: "Local listeners")
              ForEach(Array(inspection.listeners.enumerated()), id: \.offset) { _, listener in
                Text("\(listener.protocol.uppercased()) · \(listener.address):\(listener.port)")
                  .font(.system(size: 11.9, design: .monospaced))
              }
            }
            ForEach(inspection.warnings, id: \.self) { Text($0).foregroundStyle(p["virtual"]) }
            if !inspection.routeKnowledgeComplete {
              Text(L10n.text("Server-pushed routes are not known until connection"))
                .foregroundStyle(p.muted)
            }
          } else if let error = model.error {
            Text(L10n.text(error)).foregroundStyle(p["down"])
          } else {
            ProgressView(L10n.text("Analyzing configuration…"))
          }
        }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
      }.frame(height: 420)
    }
  }
}

/// Full-size editor for the three Xray rule sets (block → proxy → direct).
struct RoutingRulesEditor: View {
  struct RuleSet { let target: String; let title: String; let color: String }
  static let sets = [
    RuleSet(target: "block", title: "rules.block", color: "down"),
    RuleSet(target: "proxy", title: "rules.proxy", color: "accent"),
    RuleSet(target: "direct", title: "rules.direct", color: "up"),
  ]
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  let onClose: () -> Void
  @State private var selected = "proxy"
  @State private var texts: [String: String] = [:]
  @State private var privateLanDirect = false
  var body: some View {
    AppModal(title: "detail.domainRules", width: 720, onClose: onClose) {
      VStack(alignment: .leading, spacing: 10.5) {
        HStack(spacing: 6) {
          ForEach(Self.sets, id: \.target) { set in
            let count = (texts[set.target] ?? "").split(separator: "\n")
              .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty && !$0.hasPrefix("#") }.count
            Button {
              selected = set.target
            } label: {
              HStack(spacing: 6) {
                Circle().fill(p[set.color]).frame(width: 7, height: 7)
                Text(L10n.text(set.title))
                Text("\(count)").foregroundStyle(p.muted)
              }.font(.system(size: 11.9, weight: selected == set.target ? .semibold : .regular))
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(
                  selected == set.target ? p["bg-elev"] : .clear,
                  in: RoundedRectangle(cornerRadius: 6))
            }.buttonStyle(.plain)
          }
          Spacer()
        }
        TextEditor(
          text: Binding(get: { texts[selected] ?? "" }, set: { texts[selected] = $0 })
        )
        .font(.system(size: 11.9, design: .monospaced)).scrollContentBackground(.hidden)
        .padding(7).frame(height: 340)
        .background(p.input, in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
        .accessibilityLabel(L10n.text("detail.domainRules"))
        Text(L10n.text("form.rulesHint")).font(.system(size: 10.92)).foregroundStyle(p.muted)
          .fixedSize(horizontal: false, vertical: true)
        Toggle(L10n.text("form.privateLanDirect"), isOn: $privateLanDirect)
          .toggleStyle(.checkbox).font(.system(size: 11.9))
        if let error = model.error {
          Text(L10n.text(error)).foregroundStyle(p["down"]).font(.system(size: 11.9))
        }
        HStack {
          Spacer()
          Button(L10n.text("Cancel"), action: onClose)
          Button(L10n.text("Save")) {
            Task {
              if await model.setRoutingRules(
                profile, block: texts["block"] ?? "", proxy: texts["proxy"] ?? "",
                direct: texts["direct"] ?? "", privateLanDirect: privateLanDirect)
              {
                onClose()
              }
            }
          }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(model.busy)
        }
      }.padding(14)
    }
    .onAppear {
      model.error = nil
      for set in Self.sets { texts[set.target] = profile.rules(set.target).joined(separator: "\n") }
      privateLanDirect = profile.privateLanDirect ?? false
    }
  }
}
