import SwiftUI

/// The app's events, a connection's backend log, the helper's, NetBird's or
/// the import log, with level and text filters, refreshed while the page is open. Text is already redacted by the
/// core; nothing here reads a log file itself.
struct LogsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var source: LogSource?
  @State private var lines: [LogLine] = []
  @State private var level: LogLevel?
  @State private var query = ""
  private var profiles: [Profile] { model.snapshot?.profiles ?? [] }
  /// A running connection first; otherwise the app's own events.
  private var activeSource: LogSource {
    source ?? profiles.first { model.isRunning($0) }.map { .connection($0.id) } ?? .app
  }
  var body: some View {
    let result = LogLines.filter(lines, level: level, query: query)
    VStack(alignment: .leading, spacing: 14) {
      AppHeading(title: "Logs")
      controls(result.shown)
      AppCard(padding: 0) {
        if lines.isEmpty {
          Text(L10n.text("logs.empty")).foregroundStyle(p.muted).font(.system(size: 12))
            .frame(maxWidth: .infinity, minHeight: 120)
        } else if result.shown.isEmpty {
          Text(L10n.text("logs.noMatch")).foregroundStyle(p.muted).font(.system(size: 12))
            .frame(maxWidth: .infinity, minHeight: 120)
        } else {
          ScrollViewReader { proxy in
            ScrollView {
              LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(result.shown) { line in
                  Text(line.text).font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(color(line.level)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).id(line.id)
                }
              }.padding(10)
            }
            .onChange(of: result.shown.last?.id) { _, last in
              if let last { proxy.scrollTo(last, anchor: .bottom) }
            }
            .onAppear {
              if let last = result.shown.last?.id { proxy.scrollTo(last, anchor: .bottom) }
            }
          }.frame(height: 420)
        }
      }
      if result.total > result.shown.count {
        Text(
          L10n.text(
            "logs.showingLast",
            ["shown": String(result.shown.count), "total": String(result.total)])
        ).font(.system(size: 11)).foregroundStyle(p.muted)
      }
    }
    // Reads again every two seconds while the page is open, and at once when
    // the connection changes.
    .task(id: activeSource) {
      while !Task.isCancelled {
        await load()
        try? await Task.sleep(for: .seconds(2))
      }
    }
  }

  private func controls(_ shown: [LogLine]) -> some View {
    HStack(spacing: 8) {
      Picker("", selection: Binding(get: { activeSource }, set: { source = $0 })) {
        Text(L10n.text("native.logs.app")).tag(LogSource.app)
        ForEach(profiles) { Text($0.name).tag(LogSource.connection($0.id)) }
        Text(L10n.text("native.logs.helper")).tag(LogSource.helper)
        if model.netbird?.installed == true { Text("NetBird").tag(LogSource.netbird) }
        Text(L10n.text("native.importLog")).tag(LogSource.importer)
      }.labelsHidden().frame(maxWidth: 220)
      Picker("", selection: $level) {
        Text(L10n.text("logs.allLevels")).tag(LogLevel?.none)
        Text(L10n.text("logs.levelError")).tag(LogLevel?.some(.error))
        Text(L10n.text("logs.levelWarn")).tag(LogLevel?.some(.warn))
        Text(L10n.text("logs.levelInfo")).tag(LogLevel?.some(.info))
      }.labelsHidden().frame(maxWidth: 150)
      AppInput(placeholder: "logs.filterPlaceholder", text: $query)
      Button(L10n.text("common.refresh")) { Task { await load() } }
      Button(L10n.text("native.copyLog")) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(shown.map(\.text).joined(separator: "\n"), forType: .string)
      }.disabled(shown.isEmpty)
    }
  }

  private func color(_ level: LogLevel) -> Color {
    switch level {
    case .error: p["down"]
    case .warn: p["warn"]
    case .info: p.text
    }
  }

  private func load() async {
    let chosen = activeSource
    let text = await model.logText(for: chosen)
    // A slow read must not overwrite what the user switched to meanwhile.
    guard chosen == activeSource else { return }
    lines = LogLines.parse(text)
  }
}
