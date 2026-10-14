import SwiftUI

/// First-time or changed NetBird server: the management address and, optionally,
/// a setup key. Without a key the NetBird CLI opens the browser for SSO.
struct NetBirdSetupSheet: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var url = ""
  @State private var key = ""

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("NetBird").font(.system(size: 16, weight: .semibold))
      VStack(alignment: .leading, spacing: 4) {
        Text(L10n.text("native.netbird.url")).font(.system(size: 11.2)).foregroundStyle(p.muted)
        TextField("https://netbird.example.com", text: $url).textFieldStyle(.roundedBorder)
      }
      VStack(alignment: .leading, spacing: 4) {
        Text(L10n.text("native.netbird.key")).font(.system(size: 11.2)).foregroundStyle(p.muted)
        SecureField("", text: $key).textFieldStyle(.roundedBorder)
      }
      Text(L10n.text("native.netbird.setupHint")).font(.system(size: 10.8))
        .foregroundStyle(p.muted).fixedSize(horizontal: false, vertical: true)
      HStack {
        Spacer()
        Button(L10n.text("common.cancel")) { model.showingNetBirdSetup = false }
          .keyboardShortcut(.cancelAction)
        Button(L10n.text("common.connect")) {
          let address = url.trimmingCharacters(in: .whitespaces)
          let secret = key.trimmingCharacters(in: .whitespaces)
          model.showingNetBirdSetup = false
          Task { await model.toggleNetBird(managementUrl: address, setupKey: secret) }
        }.keyboardShortcut(.defaultAction)
          .disabled(url.trimmingCharacters(in: .whitespaces).isEmpty)
      }
    }.padding(20).frame(width: 400)
      .onAppear { url = model.netbird?.managementUrl ?? "" }
  }
}
