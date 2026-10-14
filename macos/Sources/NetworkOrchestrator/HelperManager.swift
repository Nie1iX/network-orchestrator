import Foundation
import ServiceManagement

/// Registration state of the privileged launchd helper (`SMAppService.daemon`).
enum HelperRegistration: Sendable, Equatable {
  case notRegistered, enabled, requiresApproval, notFound
}

/// Answer of the helper's socket, from the bridge's `helper_status`.
struct HelperStatus: Decodable, Sendable, Equatable {
  let reachable: Bool
  let denied: Bool
  let version: String
  let capabilities: [String]
}

/// Installs and removes the helper bundled at
/// `Contents/Library/LaunchDaemons/com.netmanager.app.helper.plist`. Installing
/// needs the user's approval in System Settings → Login Items; the app never
/// asks for or stores an administrator password itself.
@MainActor enum HelperManager {
  static let plistName = "com.netmanager.app.helper.plist"
  private static var service: SMAppService { .daemon(plistName: plistName) }

  static var registration: HelperRegistration {
    switch service.status {
    case .enabled: .enabled
    case .requiresApproval: .requiresApproval
    case .notFound: .notFound
    default: .notRegistered
    }
  }
  static func register() throws { try service.register() }
  static func unregister() async throws { try await service.unregister() }
  static func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}
