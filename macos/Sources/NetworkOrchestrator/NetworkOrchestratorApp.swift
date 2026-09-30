import SwiftUI

@main struct NetworkOrchestratorApp: App {
  @State private var model = AppModel()
  @AppStorage("appearance") private var appearance = "system"
  var body: some Scene {
    WindowGroup("Network Orchestrator", id: "main") {
      ContentView(model: model).frame(minWidth: 960, minHeight: 640)
        .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
    }
    .defaultSize(width: 1200, height: 780)
    .commands {
      CommandGroup(replacing: .newItem) {}
      CommandGroup(after: .toolbar) {
        Button(L10n.text("Refresh network")) { Task { await model.refresh() } }
          .keyboardShortcut("r", modifiers: .command)
      }
    }
    Settings { NativeSettingsWindow(model: model).frame(width: 700) }
  }
}

struct NativeSettingsWindow: View {
  @Bindable var model: AppModel
  @Environment(\.colorScheme) private var scheme
  @AppStorage("appearance") private var appearance = "system"
  var body: some View {
    ScrollView { SettingsView(model: model).padding(.horizontal, 28).padding(.vertical, 21) }
      .environment(\.locale, Locale(identifier: L10n.shared.language))
      .environment(\.layoutDirection, L10n.shared.direction)
      .background(AppPalette(scheme: scheme).app).foregroundStyle(AppPalette(scheme: scheme).text)
      .environment(\.palette, AppPalette(scheme: scheme)).buttonStyle(TauriButtonStyle())
      .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
  }
}
