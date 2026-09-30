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
  @State private var expanded = Set<String>()
  @State private var renaming: Profile?
  @State private var deleting: Profile?
  @State private var name = ""
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack(spacing: 10.5) {
        Text(L10n.text("Connections")).font(.system(size: 14.7, weight: .semibold))
        Spacer()
        Button(L10n.text("+ Add connection")) { modal = .add }.buttonStyle(
          TauriButtonStyle(kind: .accent))
        Button(L10n.text("Import…")) { modal = .importConfig(nil) }
      }
      Text(
        L10n.text(
          "VPN activation is not implemented in this native version. Profiles, imports, and configuration analysis are available."
        )
      ).font(.system(size: 10.92)).foregroundStyle(p.muted)
      if !(model.snapshot?.profiles.isEmpty ?? true) {
        HStack(spacing: 10.5) {
          Text(L10n.text("SNIPPETS")).font(.system(size: 10.08, weight: .semibold)).tracking(0.7)
            .foregroundStyle(p.muted)
          Button(L10n.text("+ Save current")) {}.buttonStyle(
            TauriButtonStyle(kind: .chip, compact: true)
          )
          .disabled(true).help(
            L10n.text("Connect something first. VPN activation is not available yet."))
        }
        AppInput(placeholder: "Search connections…", text: $model.search)
      }
      if model.profiles.isEmpty {
        AppEmptyState {
          Text(
            model.search.isEmpty
              ? "No profiles yet. Create one to get started."
              : L10n.text(
                "No connections match \"{search}\".", ["search": String(describing: model.search)]))
        }
      } else {
        ForEach(["wireGuard", "openVpn", "xray", "none"], id: \.self) { backend in
          let profiles = model.profiles.filter { $0.backend == backend }
          if !profiles.isEmpty {
            VStack(alignment: .leading, spacing: 10.5) {
              Button {
                if !collapsed.insert(backend).inserted { collapsed.remove(backend) }
              } label: {
                HStack(spacing: 7) {
                  NativeIcon(name: "ChevronIcon", size: 13).rotationEffect(
                    .degrees(collapsed.contains(backend) ? 0 : 180))
                  NativeIcon(name: NativeIcon.backend(backend), size: 18)
                  Text(L10n.text(profiles[0].kind)).font(.system(size: 11.2, weight: .semibold))
                    .tracking(0.28)
                  Text("\(profiles.count)").font(.system(size: 10.08)).padding(.horizontal, 7)
                    .padding(.vertical, 1).background(p.border, in: Capsule())
                }.foregroundStyle(p.secondary).padding(.horizontal, 12).padding(.vertical, 5)
                  .background(p.card, in: Capsule()).overlay(
                    Capsule().stroke(p.border, lineWidth: 1))
              }.buttonStyle(.plain).accessibilityLabel(L10n.text(profiles[0].kind))
              if !collapsed.contains(backend) {
                ForEach(profiles) { profile in
                  AppCard(padding: 0) {
                    VStack(alignment: .leading, spacing: 7) {
                      HStack(spacing: 10.5) {
                        NativeIcon(name: NativeIcon.backend(profile.backend), size: 16)
                          .foregroundStyle(p[tint(profile.backend)]).frame(width: 36, height: 36)
                          .background(p[tint(profile.backend)].opacity(0.14), in: Circle())
                        VStack(alignment: .leading, spacing: 2) {
                          HStack(spacing: 7) {
                            Text(profile.name).font(.system(size: 13.3, weight: .semibold))
                            if profile.backend != "none" { AppBadge(text: "Managed", color: "up") }
                          }
                          Text(
                            profile.interfaceName.isEmpty ? "Not connected" : profile.interfaceName
                          ).font(.system(size: 10.92)).foregroundStyle(p.muted)
                        }
                        Spacer()
                        ReadOnlySwitch()
                        Menu {
                          Button(L10n.text("Rename")) {
                            name = profile.name
                            renaming = profile
                          }
                          Button(L10n.text("Inspect configuration")) {
                            Task { await model.inspect(profile) }
                          }
                          Button(L10n.text("Diagnostics — requires VPN provider")) {}.disabled(true)
                          Button(L10n.text("Delete"), role: .destructive) { deleting = profile }
                        } label: {
                          Text("⋮").font(.system(size: 19)).frame(width: 32, height: 32)
                        }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden)
                          .foregroundStyle(
                            p.secondary
                          ).frame(width: 32)
                      }
                      if let port = profile.xraySocksPort { meta("SOCKS5", "127.0.0.1:\(port)") }
                      if let port = profile.xrayHttpPort {
                        meta("HTTP CONNECT", "127.0.0.1:\(port)")
                      }
                      if !profile.routes.isEmpty {
                        Rectangle().fill(p.border).frame(height: 1)
                        Button {
                          if !expanded.insert(profile.id).inserted { expanded.remove(profile.id) }
                        } label: {
                          HStack(spacing: 3.5) {
                            NativeIcon(name: "ChevronIcon", size: 13).rotationEffect(
                              .degrees(expanded.contains(profile.id) ? 180 : 0))
                            Text(
                              L10n.text("{count} routes", ["count": String(profile.routes.count)])
                            ).font(.system(size: 10.92))
                          }.foregroundStyle(p.secondary)
                        }.buttonStyle(.plain)
                        if expanded.contains(profile.id) {
                          ForEach(Array(profile.routes.enumerated()), id: \.offset) { _, route in
                            HStack {
                              Text("•  " + route.destination).font(
                                .system(size: 11.9, design: .monospaced))
                              Text(
                                L10n.text(
                                  "metric {metric}", ["metric": String(describing: route.metric)])
                              ).font(.system(size: 9.1))
                                .foregroundStyle(p.muted)
                            }
                          }
                        }
                      }
                    }.padding(.horizontal, 14).padding(.vertical, 10.5)
                  }
                }
              }
            }.padding(.bottom, 3.5)
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
  private func tint(_ backend: String) -> String {
    switch backend {
    case "wireGuard": "wg-color"
    case "openVpn": "ovpn-color"
    case "xray": "xray-color"
    default: "none-color"
    }
  }
  private func meta(_ label: String, _ value: String) -> some View {
    HStack {
      Text(L10n.text(label)).foregroundStyle(p.muted)
      Spacer()
      Text(value).font(.system(size: 11.9, design: .monospaced))
    }.font(.system(size: 11.9))
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
  var body: some View {
    AppModal(title: "Import configurations", width: 520, onClose: onClose) {
      VStack(alignment: .leading, spacing: 10.5) {
        AppTabs(titles: ["Files", "Subscription URL", "WireGuard location"], selected: $tab)
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
        } else {
          AppEmptyState {
            Text(
              tab == "Subscription URL"
                ? "Subscription URLs and share links are not implemented in the native version yet. Use Files to import a configuration."
                : "Automatic discovery is not implemented on macOS yet. Use Files to choose your WireGuard configuration."
            )
          }
        }
        if let error = model.error {
          Text(L10n.text(error)).foregroundStyle(p["down"]).font(.system(size: 11.9))
        }
        HStack {
          Spacer()
          Button(L10n.text("Cancel"), action: onClose)
          Button(L10n.text(model.busy ? "Importing…" : "Import")) {
            Task {
              if let file, await model.importConfig(url: file, backend: backend, name: name) {
                onClose()
                model.section = .connections
              }
            }
          }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(
            model.busy || tab != "Files" || file == nil
              || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
      }.padding(14)
    }.onAppear { backend = preferredBackend ?? "wireGuard" }
  }
  private func chooseFile() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.allowedContentTypes = [
      UTType(filenameExtension: "conf"), UTType(filenameExtension: "ovpn"), .json,
    ].compactMap { $0 }
    if panel.runModal() == .OK, let url = panel.url {
      file = url
      if name.isEmpty { name = url.deletingPathExtension().lastPathComponent }
      backend =
        preferredBackend
        ?? (url.pathExtension == "ovpn"
          ? "openVpn" : url.pathExtension == "json" ? "xray" : "wireGuard")
    }
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
