import Foundation
import Security

/// What a profile needs typed in before OpenVPN can start.
struct CredentialNeeds: Decodable, Sendable, Equatable {
  let userPass: Bool
  let keyPassphrase: Bool
  var any: Bool { userPass || keyPassphrase }
}

/// What the user typed (or Keychain remembered) for one OpenVPN profile.
struct OpenVpnSecrets: Codable, Sendable, Equatable {
  var username: String = ""
  var password: String = ""
  var passphrase: String = ""

  /// Whether this covers everything `needs` asks for.
  func satisfies(_ needs: CredentialNeeds) -> Bool {
    (!needs.userPass || (!username.isEmpty && !password.isEmpty))
      && (!needs.keyPassphrase || !passphrase.isEmpty)
  }

  /// Flat arguments for the bridge; only what the profile asks for is sent.
  func arguments(for needs: CredentialNeeds) -> [String: String] {
    var args: [String: String] = [:]
    if needs.userPass {
      args["username"] = username
      args["password"] = password
    }
    if needs.keyPassphrase { args["passphrase"] = passphrase }
    return args
  }
}

/// Remembered OpenVPN credentials live in the login Keychain, never in the
/// app's data folder: one generic-password item per profile.
enum CredentialStore {
  static let service = "com.netmanager.app.macos.openvpn"

  private static func query(_ profileID: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: profileID,
    ]
  }

  static func load(_ profileID: String) -> OpenVpnSecrets? {
    var request = query(profileID)
    request[kSecReturnData as String] = true
    request[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    guard SecItemCopyMatching(request as CFDictionary, &item) == errSecSuccess,
      let data = item as? Data
    else { return nil }
    return try? JSONDecoder().decode(OpenVpnSecrets.self, from: data)
  }

  @discardableResult
  static func save(_ secrets: OpenVpnSecrets, for profileID: String) -> Bool {
    guard let data = try? JSONEncoder().encode(secrets) else { return false }
    delete(profileID)
    var item = query(profileID)
    item[kSecValueData as String] = data
    item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
  }

  static func delete(_ profileID: String) {
    SecItemDelete(query(profileID) as CFDictionary)
  }
}

/// A connect that is waiting for the user to type credentials.
struct CredentialRequest: Identifiable, Equatable {
  let id = UUID()
  let profile: String
  let name: String
  let needs: CredentialNeeds
  /// Saved credentials were tried and the server refused them.
  let rejected: Bool

  static func == (lhs: CredentialRequest, rhs: CredentialRequest) -> Bool { lhs.id == rhs.id }
}
