import AppKit
import SwiftUI
import Testing

@testable import NetworkOrchestrator

/// Window probes share AppKit state, so they run one at a time.
@Suite(.serialized) struct ImportInputProbes {
/// Opt-in: hosts the import dialog in a real window and checks that its text
/// fields accept focus and pasted text. NETORCH_UI_PROBE=1 swift test --filter importFields
@Test(.enabled(if: ProcessInfo.processInfo.environment["NETORCH_UI_PROBE"] != nil))
@MainActor func importFieldsAcceptPastedText() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let model = AppModel(dataDirectory: directory)
  await model.refresh()
  print("probe busy after refresh:", model.busy, "error:", model.error ?? "-")
  let palette = AppPalette(scheme: .light)
  let view = ImportConfigurationView(
    model: model, preferredBackend: nil, onClose: {}, initialTab: "Subscription"
  ).environment(\.palette, palette).buttonStyle(TauriButtonStyle())
  let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 520, height: 520), styleMask: [.titled],
    backing: .buffered, defer: false)
  window.contentView = NSHostingView(rootView: view)
  window.makeKeyAndOrderFront(nil)
  try await Task.sleep(for: .milliseconds(300))
  var fields: [NSTextField] = []
  func collect(_ view: NSView) {
    if let field = view as? NSTextField, field.isEditable {
      fields.append(field)
    }
    view.subviews.forEach(collect)
  }
  collect(window.contentView!)
  for field in fields {
    print(
      "probe field:", type(of: field), "enabled:", field.isEnabled, "editable:", field.isEditable,
      "placeholder:", field.placeholderString ?? "-")
  }
  let target = try #require(fields.first)
  #expect(window.makeFirstResponder(target))
  let editor = try #require(window.fieldEditor(true, for: target) as? NSTextView)
  NSPasteboard.general.clearContents()
  NSPasteboard.general.setString("https://sub.example.test/", forType: .string)
  editor.paste(nil)
  target.validateEditing()
  try await Task.sleep(for: .milliseconds(100))
  print("probe value after insert:", target.stringValue.isEmpty ? "<empty>" : "<set>")
  #expect(!target.stringValue.isEmpty)
  window.close()
}

@Test(.enabled(if: ProcessInfo.processInfo.environment["NETORCH_UI_PROBE"] != nil))
@MainActor func importFieldsWorkInsideTheAppSheet() async throws {
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: directory) }
  let model = AppModel(dataDirectory: directory)
  model.section = .connections
  let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 1200, height: 780), styleMask: [.titled, .resizable],
    backing: .buffered, defer: false)
  window.contentView = NSHostingView(
    rootView: ContentView(model: model, initialModal: .importConfig("xray")))
  window.makeKeyAndOrderFront(nil)
  NSApp.activate()
  // Let the initial refresh and two runtime polls happen.
  try await Task.sleep(for: .seconds(7))
  let sheet = try #require(window.attachedSheet, "the import dialog should be a sheet")
  print("probe sheet key:", sheet.isKeyWindow, "busy:", model.busy)
  var fields: [NSTextField] = []
  func collect(_ view: NSView) {
    if let field = view as? NSTextField, field.isEditable { fields.append(field) }
    view.subviews.forEach(collect)
  }
  collect(sheet.contentView!)
  print("probe sheet fields:", fields.map { "\(type(of: $0)) enabled=\($0.isEnabled)" })
  guard let target = fields.first else {
    Issue.record("no editable field in the sheet")
    return
  }
  print("probe first responder:", sheet.makeFirstResponder(target))
  let editor = try #require(sheet.fieldEditor(true, for: target) as? NSTextView)
  NSPasteboard.general.clearContents()
  NSPasteboard.general.setString("https://sub.example.test/", forType: .string)
  editor.paste(nil)
  try await Task.sleep(for: .seconds(4))
  print("probe sheet value after paste + poll:", target.stringValue.isEmpty ? "<empty>" : "<set>")
  window.close()
}
}
