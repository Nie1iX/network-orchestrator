import SwiftUI

/// Asks for what OpenVPN needs before it can sign in: username and password,
/// and/or the passphrase of an encrypted key. Optionally remembers them in the
/// Keychain.
struct CredentialSheet: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let request: CredentialRequest
  @State private var secrets = OpenVpnSecrets()
  @State private var remember = true

  private var complete: Bool { secrets.satisfies(request.needs) }

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text(L10n.text("native.credentials.title", ["name": request.name]))
        .font(.system(size: 16, weight: .semibold))
      if request.rejected {
        Text(L10n.text("native.credentials.rejected")).font(.system(size: 11.9))
          .foregroundStyle(p["down"])
      }
      if request.needs.userPass {
        field("native.credentials.username") {
          TextField("", text: $secrets.username).textFieldStyle(.roundedBorder)
        }
        field("native.credentials.password") {
          SecureField("", text: $secrets.password).textFieldStyle(.roundedBorder)
        }
      }
      if request.needs.keyPassphrase {
        field("native.credentials.passphrase") {
          SecureField("", text: $secrets.passphrase).textFieldStyle(.roundedBorder)
        }
      }
      Toggle(L10n.text("native.credentials.remember"), isOn: $remember).toggleStyle(.checkbox)
        .font(.system(size: 11.9))
      HStack {
        Spacer()
        Button(L10n.text("common.cancel")) { model.credentialRequest = nil }
          .keyboardShortcut(.cancelAction)
        Button(L10n.text("common.connect")) {
          Task { await model.submitCredentials(request, secrets: secrets, remember: remember) }
        }.keyboardShortcut(.defaultAction).disabled(!complete)
      }
    }.padding(20).frame(width: 380)
  }

  private func field<Content: View>(_ label: String, @ViewBuilder _ content: () -> Content)
    -> some View
  {
    VStack(alignment: .leading, spacing: 4) {
      Text(L10n.text(label)).font(.system(size: 11.2)).foregroundStyle(p.muted)
      content()
    }
  }
}
