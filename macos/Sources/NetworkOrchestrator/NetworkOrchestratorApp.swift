import AppKit
import SwiftUI

/// Rolls back the system proxy and stops Xray when the app quits.
final class AppDelegate: NSObject, NSApplicationDelegate {
  var onTerminate: (() -> Void)?
  /// One app per data directory: a second launch brings the first forward.
  func applicationWillFinishLaunching(_ notification: Notification) {
    guard AppDelegate.duplicate else { return }
    let me = NSRunningApplication.current
    NSWorkspace.shared.runningApplications.first {
      $0.processIdentifier != me.processIdentifier
        && ($0.bundleIdentifier == me.bundleIdentifier && me.bundleIdentifier != nil
          || $0.localizedName == me.localizedName)
    }?.activate()
    exit(0)
  }
  nonisolated(unsafe) static var duplicate = false
  /// A bare SwiftPM executable (e.g. run from Xcode) starts without a bundle
  /// and never becomes the key app, so text fields get no keyboard or paste.
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate()
  }
  func applicationWillTerminate(_ notification: Notification) { onTerminate?() }
}

@main struct NetworkOrchestratorApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
  @State private var model: AppModel
  init() {
    let model = AppModel()
    AppDelegate.duplicate = model.isDuplicate
    _model = State(initialValue: model)
  }
  @AppStorage("appearance") private var appearance = "system"
  var body: some Scene {
    WindowGroup("Network Orchestrator", id: "main") {
      ContentView(model: model).frame(minWidth: 960, minHeight: 640)
        .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
        .onAppear { delegate.onTerminate = { [model] in model.shutdown() } }
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
