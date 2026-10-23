import SwiftUI

/// Every check for one connection: what the helper and the app see, the
/// configuration, routes and endpoints. Runs when opened and on Refresh.
struct DiagnosticsSheet: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  let onClose: () -> Void
  @State private var report: ProfileDiagnostics?
  @State private var running = false

  var body: some View {
    AppModal(
      title: L10n.text("diag.title", ["name": profile.groupName]), width: 680,
      onClose: onClose, translatesTitle: false
    ) {
      VStack(alignment: .leading, spacing: 10.5) {
        summary
        ScrollView {
          VStack(alignment: .leading, spacing: 0) {
            ForEach(report?.checks ?? []) { check in row(check) }
          }
        }.frame(height: 380).background(p.input, in: RoundedRectangle(cornerRadius: 6))
          .overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
        HStack {
          Button(L10n.text("common.refresh")) { Task { await run() } }.disabled(running)
          Button(L10n.text("native.copyLog")) { copy() }.disabled(report == nil)
          Spacer()
          Button(L10n.text("common.close"), action: onClose)
        }
      }.padding(14)
    }.task { await run() }
  }

  @ViewBuilder private var summary: some View {
    HStack(spacing: 8) {
      if running {
        ProgressView().controlSize(.small)
      } else if let report {
        Circle().fill(color(report.worst)).frame(width: 10, height: 10)
        let counts = report.counts
        Text(
          counts.errors + counts.warnings == 0
            ? L10n.text("native.diag.clean")
            : L10n.text(
              "native.diag.issues",
              ["errors": String(counts.errors), "warnings": String(counts.warnings)])
        ).font(.system(size: 12.3, weight: .semibold))
      }
      Spacer()
    }.frame(minHeight: 18)
  }

  private func row(_ check: DiagnosticCheck) -> some View {
    HStack(alignment: .top, spacing: 8) {
      AppBadge(text: label(check.level), color: badge(check.level)).frame(width: 78, alignment: .leading)
      Text(check.name).font(.system(size: 11.9, weight: .semibold)).frame(width: 150, alignment: .leading)
      Text(check.message).font(.system(size: 11.9)).foregroundStyle(p.secondary)
        .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
    }
    .padding(.horizontal, 10).padding(.vertical, 7)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }

  private func label(_ level: DiagnosticLevel) -> String {
    switch level {
    case .healthy: "native.diag.ok"
    case .warning: "logs.levelWarn"
    case .error: "logs.levelError"
    }
  }
  private func badge(_ level: DiagnosticLevel) -> String {
    switch level {
    case .healthy: "up"
    case .warning: "warn"
    case .error: "down"
    }
  }
  private func color(_ level: DiagnosticLevel) -> Color { p[badge(level)] }

  private func run() async {
    running = true
    defer { running = false }
    report = await model.diagnose(profile)
  }

  private func copy() {
    guard let report else { return }
    let text = report.checks.map { "[\($0.level.rawValue)] \($0.name): \($0.message)" }
      .joined(separator: "\n")
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
  }
}
