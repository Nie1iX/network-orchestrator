import SwiftUI

struct ContentView: View {
  @Bindable var model: AppModel
  @Environment(\.colorScheme) private var scheme
  @State private var modal: ConnectionModal?
  var loadsOnAppear = true
  var body: some View {
    HStack(spacing: 0) {
      NavigationRail(selection: $model.section)
      ScrollView {
        VStack(alignment: .leading, spacing: 21) {
          if let error = model.error {
            AppCard {
              HStack {
                Text(L10n.text(error)).foregroundStyle(AppPalette(scheme: scheme)["down"])
                Spacer()
                Button(L10n.text("Dismiss")) { model.error = nil }
              }
            }
          }
          switch model.section {
          case .home: HomeView(model: model, modal: $modal)
          case .connections: ConnectionsView(model: model, modal: $modal)
          case .network: NetworkView(model: model)
          case .routes: RoutesView(model: model)
          case .settings: SettingsView(model: model)
          }
        }.frame(
          maxWidth: model.section == .network || model.section == .routes
            ? .infinity : DesignMetrics.pageNarrow, alignment: .leading
        )
        .frame(maxWidth: .infinity, alignment: .top).padding(
          .horizontal, DesignMetrics.contentHorizontal
        ).padding(.vertical, DesignMetrics.contentVertical)
      }.background(AppPalette(scheme: scheme).app)
    }
    .font(.system(size: 14)).foregroundStyle(AppPalette(scheme: scheme).text).tint(
      AppPalette(scheme: scheme).accent
    )
    .environment(\.palette, AppPalette(scheme: scheme)).buttonStyle(TauriButtonStyle())
    .environment(\.locale, Locale(identifier: L10n.shared.language))
    .environment(\.layoutDirection, L10n.shared.direction)
    .task { if loadsOnAppear { await model.refresh() } }
    .sheet(item: $modal) { value in
      ConnectionModalView(
        model: model, modal: value, onClose: { modal = nil }, onChoose: { modal = $0 }
      )
      .environment(\.palette, AppPalette(scheme: scheme)).buttonStyle(TauriButtonStyle())
      .environment(\.locale, Locale(identifier: L10n.shared.language))
      .environment(\.layoutDirection, L10n.shared.direction)
    }
    .sheet(item: $model.inspecting) { profile in
      InspectionView(model: model, profile: profile).environment(
        \.palette, AppPalette(scheme: scheme)
      ).buttonStyle(TauriButtonStyle())
    }
  }
}
struct NavigationRail: View {
  @Environment(\.palette) private var p
  @Binding var selection: Section
  @State private var hovered: Section?
  var body: some View {
    VStack(spacing: 4) {
      NativeIcon(name: "NetworkIcon", size: 20).foregroundStyle(p.accent).frame(
        width: 36, height: 36
      ).padding(.bottom, 10.5).help(L10n.text("Network Orchestrator"))
      railButton(.home)
      railButton(.connections)
      Rectangle().fill(p.border).frame(width: 28, height: 1).padding(.vertical, 7)
      railButton(.network, muted: true)
      railButton(.routes, muted: true)
      Spacer(minLength: 0)
      railButton(.settings)
    }.padding(.vertical, 10.5).frame(width: DesignMetrics.railWidth).frame(maxHeight: .infinity)
      .background(p.sidebar)
      .overlay(alignment: .trailing) { Rectangle().fill(p.border).frame(width: 1) }
  }
  private func railButton(_ section: Section, muted: Bool = false) -> some View {
    Button {
      selection = section
    } label: {
      NativeIcon(name: section.iconName, size: 20).frame(width: 40, height: 40)
        .foregroundStyle(
          selection == section
            ? p.accent : hovered == section ? p.text : muted ? p.muted : p.secondary
        )
        .background(
          selection == section ? p["accent-dim"] : hovered == section ? p.hover : .clear,
          in: RoundedRectangle(cornerRadius: 8)
        )
        .overlay(alignment: .leading) {
          if selection == section {
            Capsule().fill(p.accent).frame(width: 3, height: 18).offset(x: -8)
          }
        }
    }.buttonStyle(.plain).help(L10n.text(section.rawValue)).accessibilityLabel(
      L10n.text(section.rawValue)
    )
    .accessibilityAddTraits(selection == section ? [.isSelected] : [])
    .onHover { hovered = $0 ? section : nil }
  }
}
struct HomeView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @Binding var modal: ConnectionModal?
  var body: some View {
    VStack(alignment: .leading, spacing: 21) {
      HStack(spacing: 10.5) {
        Circle().fill(p["unknown"]).frame(width: 12, height: 12)
        Text(L10n.text("All disconnected")).font(.system(size: 14.7, weight: .bold))
        Spacer()
      }
      .padding(.horizontal, 17.5).padding(.vertical, 14).background(
        p.card, in: RoundedRectangle(cornerRadius: 12)
      ).overlay(RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
      VStack(spacing: 0) {
        AppHeading(title: "Active now")
        AppEmptyState {
          HStack(spacing: 4) {
            Text(L10n.text("No tunnels are running."))
            Button(L10n.text("Open Connections")) { model.section = .connections }.buttonStyle(
              .plain
            )
            .foregroundStyle(p.accent).underline()
            Text(L10n.text("to view your profiles."))
          }.font(.system(size: 13.3))
        }
      }
      VStack(alignment: .leading, spacing: 0) {
        AppHeading(title: "Quick actions")
        HStack(spacing: 7) {
          Button(L10n.text("+ Add connection")) { modal = .add }.buttonStyle(
            TauriButtonStyle(kind: .accent))
          Button(L10n.text("Import…")) { modal = .importConfig(nil) }.buttonStyle(
            TauriButtonStyle(kind: .accent))
        }
      }
      VStack(alignment: .leading, spacing: 0) {
        AppHeading(title: "Advanced")
        HStack(spacing: 10.5) {
          shortcut("Network", "Inspect adapters, addresses, and live throughput.", .network)
          shortcut("Routes", "Diagnose routing conflicts and traffic flow.", .routes)
        }
      }
    }
  }
  private func shortcut(_ title: String, _ detail: String, _ section: Section) -> some View {
    Button {
      model.section = section
    } label: {
      VStack(alignment: .leading, spacing: 4) {
        Text(L10n.text(title)).font(.system(size: 12.6, weight: .semibold))
        Text(L10n.text(detail)).font(.system(size: 10.92)).foregroundStyle(p.muted).fixedSize(
          horizontal: false, vertical: true)
      }.frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 14).padding(
        .vertical, 10.5
      )
      .background(p.card, in: RoundedRectangle(cornerRadius: 12)).overlay(
        RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
    }.buttonStyle(.plain)
  }
}
