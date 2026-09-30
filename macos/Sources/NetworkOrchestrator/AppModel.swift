import Foundation
import Observation

@MainActor @Observable final class AppModel {
  let core: CoreBridge
  var snapshot: Snapshot?
  var capabilities: Capabilities?
  var section: Section = .home
  var search = ""
  var error: String?
  var busy = false
  var inspecting: Profile?
  var inspection: Inspection?
  var lookup: Lookup?
  var lookupDestination = ""

  init(dataDirectory: URL? = nil) {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    // Dedicated native store; does not modify the Tauri app's data.
    let root =
      dataDirectory ?? ProcessInfo.processInfo.environment["NETORCH_MACOS_DATA_DIR"].map {
        URL(fileURLWithPath: $0)
      }
      ?? base.appendingPathComponent("com.netmanager.app.macos", isDirectory: true)
    core = CoreBridge(root: root)
  }
  var profiles: [Profile] {
    (snapshot?.profiles ?? []).filter {
      search.isEmpty || $0.name.localizedCaseInsensitiveContains(search)
        || $0.kind.localizedCaseInsensitiveContains(search)
    }
  }
  func refresh() async {
    guard !busy else { return }
    busy = true
    defer { busy = false }
    do {
      if capabilities == nil { capabilities = try await core.call("capabilities") }
      snapshot = try await core.call("snapshot")
      error = nil
    } catch { self.error = error.localizedDescription }
  }
  func createStatic(name: String, interface: String, cidrs: String) async -> Bool {
    await change(
      "create_static",
      args: ["id": UUID().uuidString, "name": name, "interfaceName": interface, "cidrs": cidrs])
  }
  func importConfig(url: URL, backend: String, name: String) async -> Bool {
    let access = url.startAccessingSecurityScopedResource()
    defer { if access { url.stopAccessingSecurityScopedResource() } }
    return await change(
      "import", args: ["id": UUID().uuidString, "name": name, "backend": backend, "path": url.path])
  }
  func rename(_ profile: Profile, name: String) async -> Bool {
    await change("rename", args: ["id": profile.id, "name": name])
  }
  func remove(_ profile: Profile) async { _ = await change("delete", args: ["id": profile.id]) }
  private func change(_ method: String, args: [String: String]) async -> Bool {
    guard !busy else { return false }
    busy = true
    do {
      let _: [Profile] = try await core.call(method, args: args)
      busy = false
      await refresh()
      return true
    } catch {
      busy = false
      self.error = error.localizedDescription
      return false
    }
  }
  func inspect(_ profile: Profile) async {
    inspecting = profile
    inspection = nil
    do { inspection = try await core.call("inspect", args: ["id": profile.id]) } catch {
      self.error = error.localizedDescription
    }
  }
  func lookupRoute() async {
    lookup = nil
    do {
      lookup = try await core.call(
        "lookup",
        args: ["destination": lookupDestination.trimmingCharacters(in: .whitespacesAndNewlines)])
    } catch { self.error = error.localizedDescription }
  }
}
