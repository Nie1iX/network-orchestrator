import AppKit
import SwiftUI

struct AppPalette: Sendable {
  let scheme: ColorScheme
  subscript(_ key: String) -> Color {
    (scheme == .dark ? SharedTheme.dark : SharedTheme.light)[key] ?? .clear
  }
  var app: Color { self["bg-app"] }
  var sidebar: Color { self["bg-sidebar"] }
  var card: Color { self["bg-card"] }
  var hover: Color { self["bg-card-hover"] }
  var input: Color { self["bg-input"] }
  var border: Color { self["border"] }
  var text: Color { self["text-primary"] }
  var secondary: Color { self["text-secondary"] }
  var muted: Color { self["text-muted"] }
  var accent: Color { self["accent"] }
}
private struct PaletteKey: EnvironmentKey { static let defaultValue = AppPalette(scheme: .dark) }
extension EnvironmentValues {
  var palette: AppPalette {
    get { self[PaletteKey.self] }
    set { self[PaletteKey.self] = newValue }
  }
}

struct NativeIcon: View {
  let name: String
  var size: CGFloat = 18
  @MainActor static var bundle: Bundle {
    if let url = Bundle.main.url(
      forResource: "NetworkOrchestratorMac_NetworkOrchestrator", withExtension: "bundle"),
      let bundle = Bundle(url: url)
    {
      return bundle
    }
    return .module
  }
  var body: some View {
    Image(nsImage: Self.load(name) ?? NSImage()).resizable().renderingMode(.template).frame(
      width: size, height: size
    ).accessibilityHidden(true)
  }
  @MainActor private static var images: [String: NSImage] = [:]
  @MainActor static func load(_ name: String) -> NSImage? {
    if let image = images[name] { return image }
    guard let url = bundle.url(forResource: name, withExtension: "pdf"),
      let image = NSImage(contentsOf: url)
    else { return nil }
    images[name] = image
    return image
  }
  static func backend(_ value: String) -> String {
    switch value {
    case "wireGuard": "WireGuardIcon"
    case "openVpn": "OpenVpnIcon"
    case "xray": "XrayIcon"
    default: "StaticRoutesIcon"
    }
  }
  static func category(_ value: String) -> String {
    switch value {
    case "physical": "EthernetIcon"
    case "system": "LoopbackIcon"
    case "tunnel": "RouteIcon"
    case "vpn": "WireGuardIcon"
    default: "NetworkIcon"
    }
  }
}

enum ActionStyle { case neutral, accent, danger, chip }
struct TauriButtonStyle: ButtonStyle {
  @Environment(\.palette) private var p
  @Environment(\.isEnabled) private var enabled
  @State private var hovered = false
  var kind: ActionStyle = .neutral
  var compact = false
  func makeBody(configuration: Configuration) -> some View {
    configuration.label.font(.system(size: compact ? 11.2 : 11.9, weight: .medium))
      .foregroundStyle(kind == .danger ? p["down"] : p.text)
      .padding(.horizontal, compact ? 10 : 14).padding(.vertical, compact ? 4 : 7)
      .background(
        configuration.isPressed || (hovered && enabled)
          ? p.hover
          : kind == .accent ? p["accent-dim"] : kind == .danger ? p["down-bg"] : p["bg-elev"]
      )
      .clipShape(RoundedRectangle(cornerRadius: kind == .chip ? 999 : 8))
      .overlay(
        RoundedRectangle(cornerRadius: kind == .chip ? 999 : 8).stroke(
          kind == .accent
            ? p["accent-border"]
            : kind == .danger ? p["down-border"] : hovered ? p["border-hover"] : p.border,
          lineWidth: 1)
      )
      .opacity(enabled ? 1 : 0.5)
      .onHover { hovered = $0 }
  }
}
struct AppHeading: View {
  @Environment(\.palette) private var p
  let title: String
  var body: some View {
    VStack(spacing: 7) {
      Text(L10n.text(title)).font(.system(size: DesignMetrics.headingFont, weight: .semibold))
        .tracking(-0.16)
        .frame(maxWidth: .infinity, minHeight: 25, alignment: .leading)
      Rectangle().fill(p.border).frame(height: 1)
    }.padding(.bottom, 14)
  }
}
struct AppCard<Content: View>: View {
  @Environment(\.palette) private var p
  var padding: CGFloat = 14
  @ViewBuilder let content: Content
  var body: some View {
    content.padding(padding).frame(maxWidth: .infinity, alignment: .leading).background(p.card)
      .clipShape(RoundedRectangle(cornerRadius: 12)).overlay(
        RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
  }
}
struct AppEmptyState<Content: View>: View {
  @Environment(\.palette) private var p
  @ViewBuilder let content: Content
  var body: some View {
    content.font(.system(size: 13.3)).foregroundStyle(p.muted).frame(maxWidth: .infinity).padding(
      .horizontal, 14
    ).padding(.vertical, 28)
      .background(p.card).clipShape(RoundedRectangle(cornerRadius: 12)).overlay(
        RoundedRectangle(cornerRadius: 12).stroke(
          p.border, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
      ).padding(.vertical, 14)
  }
}
struct AppInput: View {
  @Environment(\.palette) private var p
  let placeholder: String
  @Binding var text: String
  @FocusState private var focused: Bool
  var body: some View {
    TextField("", text: $text, prompt: Text(L10n.text(placeholder)).foregroundColor(p.muted))
      .textFieldStyle(
        .plain
      ).font(.system(size: 11.9))
      .padding(.horizontal, 10).padding(.vertical, 7).background(p.input).clipShape(
        RoundedRectangle(cornerRadius: 6)
      )
      .overlay(
        RoundedRectangle(cornerRadius: 6).stroke(focused ? p.accent : p.border, lineWidth: 1)
      ).focused($focused).accessibilityLabel(L10n.text(placeholder))
  }
}
struct AppBadge: View {
  @Environment(\.palette) private var p
  let text: String
  var color: String = "unknown"
  var body: some View {
    Text(L10n.text(text).uppercased()).font(.system(size: 9.1, weight: .semibold)).tracking(0.42)
      .foregroundStyle(p[color]).padding(.horizontal, 7).padding(.vertical, 3)
      .background(p[color + "-bg"]).clipShape(Capsule())
  }
}
struct ReadOnlySwitch: View {
  @Environment(\.palette) private var p
  var body: some View {
    Capsule().fill(p.border).frame(width: 40, height: 24).overlay(alignment: .leading) {
      Circle().fill(.white).frame(width: 20, height: 20).shadow(
        color: .black.opacity(0.2), radius: 1, y: 1
      ).padding(2)
    }
    .accessibilityLabel(L10n.text("Connect")).accessibilityValue(
      L10n.text("Unavailable in the native macOS version")
    )
    .help(L10n.text("VPN activation is not implemented in this native version."))
  }
}
struct AppModal<Content: View>: View {
  @Environment(\.palette) private var p
  let title: String
  let width: CGFloat
  let onClose: () -> Void
  var translatesTitle = true
  @ViewBuilder let content: Content
  var body: some View {
    VStack(spacing: 0) {
      HStack {
        Text(translatesTitle ? L10n.text(title) : title).font(
          .system(size: 14.7, weight: .semibold))
        Spacer()
        Button(action: onClose) { NativeIcon(name: "CloseIcon", size: 18) }.buttonStyle(.plain)
          .padding(4).accessibilityLabel(L10n.text("Close"))
      }
      .padding(.horizontal, 14).padding(.vertical, 10.5)
      Rectangle().fill(p.border).frame(height: 1)
      content
    }.frame(width: width).foregroundStyle(p.text).background(p.card).clipShape(
      RoundedRectangle(cornerRadius: 16)
    )
    .overlay(RoundedRectangle(cornerRadius: 16).stroke(p.border, lineWidth: 1))
  }
}
struct AppTabs: View {
  @Environment(\.palette) private var p
  let titles: [String]
  @Binding var selected: String
  var body: some View {
    HStack(spacing: 2) {
      ForEach(titles, id: \.self) { title in
        Button {
          selected = title
        } label: {
          Text(L10n.text(title)).font(.system(size: 11.9, weight: .medium)).foregroundStyle(
            selected == title ? p.accent : p.secondary
          )
          .padding(.horizontal, 14).padding(.vertical, 7).overlay(alignment: .bottom) {
            Rectangle().fill(selected == title ? p.accent : .clear).frame(height: 2)
          }
        }.buttonStyle(.plain).accessibilityAddTraits(selected == title ? [.isSelected] : [])
      }
      Spacer(minLength: 0)
    }.overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }.padding(
      .bottom, 14)
  }
}

struct FlowLayout: Layout {
  var spacing: CGFloat = 7
  func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
    positions(width: proposal.width ?? .infinity, subviews: subviews).size
  }
  func placeSubviews(
    in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
  ) {
    let result = positions(width: bounds.width, subviews: subviews)
    for (index, point) in result.points.enumerated() {
      subviews[index].place(
        at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y), anchor: .topLeading,
        proposal: .unspecified)
    }
  }
  private func positions(width: CGFloat, subviews: Subviews) -> (points: [CGPoint], size: CGSize) {
    var x: CGFloat = 0
    var y: CGFloat = 0
    var rowHeight: CGFloat = 0
    var maxWidth: CGFloat = 0
    var points: [CGPoint] = []
    for view in subviews {
      let size = view.sizeThatFits(.unspecified)
      if x > 0 && x + size.width > width {
        x = 0
        y += rowHeight + spacing
        rowHeight = 0
      }
      points.append(CGPoint(x: x, y: y))
      maxWidth = max(maxWidth, x + size.width)
      x += size.width + spacing
      rowHeight = max(rowHeight, size.height)
    }
    return (points, CGSize(width: width.isFinite ? width : maxWidth, height: y + rowHeight))
  }
}

struct AppSelect: View {
  @Environment(\.palette) private var p
  let label: String
  @Binding var selection: String
  let options: [(value: String, title: String)]
  var body: some View {
    Menu {
      ForEach(Array(options.enumerated()), id: \.offset) { _, option in
        Button(L10n.text(option.title)) { selection = option.value }
      }
    } label: {
      HStack(spacing: 7) {
        Text(L10n.text(options.first { $0.value == selection }?.title ?? selection))
        Spacer(minLength: 0)
        NativeIcon(name: "ChevronIcon", size: 12)
      }
      .font(.system(size: 11.9)).foregroundStyle(p.text).padding(.horizontal, 10).padding(
        .vertical, 7
      )
      .background(p.input, in: RoundedRectangle(cornerRadius: 6)).overlay(
        RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
    }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).accessibilityLabel(
      L10n.text(label))
  }
}
struct DesignTable: View {
  @Environment(\.palette) private var p
  let headers: [String]
  let rows: [[String]]
  var body: some View {
    VStack(spacing: 0) {
      row(headers, header: true)
      ForEach(Array(rows.enumerated()), id: \.offset) { _, values in row(values, header: false) }
    }
  }
  private func row(_ values: [String], header: Bool) -> some View {
    HStack(spacing: 0) {
      ForEach(Array(values.enumerated()), id: \.offset) { _, value in
        Text(header ? L10n.text(value) : value).font(
          .system(size: 11.9, weight: header ? .semibold : .regular)
        )
        .foregroundStyle(header ? p.secondary : p.text).frame(
          maxWidth: .infinity, alignment: .leading
        ).padding(.horizontal, 10.5).padding(.vertical, 7).lineLimit(1).minimumScaleFactor(0.8)
      }
    }.background(header ? p["bg-elev"] : .clear).overlay(alignment: .bottom) {
      Rectangle().fill(p.border).frame(height: 1)
    }
  }
}

/// Small indeterminate spinner (browser-tab style) for work in progress.
struct Spinner: View {
  @Environment(\.palette) private var p
  var size: CGFloat = 11
  @State private var spinning = false
  var body: some View {
    Circle().trim(from: 0.12, to: 0.82)
      .stroke(p.accent, style: StrokeStyle(lineWidth: 1.6, lineCap: .round))
      .frame(width: size, height: size)
      .rotationEffect(.degrees(spinning ? 360 : 0))
      .animation(.linear(duration: 0.8).repeatForever(autoreverses: false), value: spinning)
      .onAppear { spinning = true }
      .accessibilityLabel(L10n.text("profiles.testing"))
  }
}
