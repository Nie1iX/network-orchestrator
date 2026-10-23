import SwiftUI

/// Backend logs of one connection (or the import log) with level and text
/// filters, refreshed while the page is open. Text is already redacted by the
/// core; nothing here reads a log file itself.
struct LogsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  /// A profile id, or `importSource` for the subscription/import log.
  @State private var source: String?
  @State private var lines: [LogLine] = []
  @State private var level: LogLevel?
  @State private var query = ""
  private static let importSource = "·import"
  private var profiles: [Profile] { model.snapshot?.profiles ?? [] }
  /// Running connection first, then any connection, then the import log.
  private var activeSource: String {
    source ?? profiles.first { model.isRunning($0) }?.id ?? profiles.first?.id
      ?? Self.importSource
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
        ForEach(profiles) { Text($0.name).tag($0.id) }
        Text(L10n.text("native.importLog")).tag(Self.importSource)
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
    let id = activeSource
    let text: String
    if id == Self.importSource {
      text = await model.importLog()
    } else if let profile = profiles.first(where: { $0.id == id }) {
      text = await model.connectionLog(profile)
    } else {
      text = ""
    }
    // A slow read must not overwrite what the user switched to meanwhile.
    guard id == activeSource else { return }
    lines = LogLines.parse(text)
  }
}
