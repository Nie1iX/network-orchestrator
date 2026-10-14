import SwiftUI

/// Which networks a secondary connection carries, and which DNS suffixes use its
/// own resolvers. Validation happens in the core; its message is shown here.
struct TunnelNetworksSheet: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  let onClose: () -> Void
  @State private var networks = ""
  @State private var domains = ""
  @State private var message: String?
  @State private var saving = false

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(L10n.text("native.networksTitle", ["name": profile.groupName]))
        .font(.system(size: 16, weight: .semibold))
      Text(L10n.text("native.networksHint")).font(.system(size: 11.2)).foregroundStyle(p.muted)
        .fixedSize(horizontal: false, vertical: true)
      TextEditor(text: $networks).font(.system(size: 12, design: .monospaced))
        .frame(height: 130).scrollContentBackground(.hidden)
        .padding(6).background(p.card, in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
      VStack(alignment: .leading, spacing: 4) {
        Text(L10n.text("native.dnsDomains")).font(.system(size: 11.2)).foregroundStyle(p.muted)
        TextField("corp.example", text: $domains).textFieldStyle(.roundedBorder)
        Text(L10n.text("native.dnsDomainsHint")).font(.system(size: 10.5)).foregroundStyle(p.muted)
          .fixedSize(horizontal: false, vertical: true)
      }
      if let message {
        Text(L10n.text(message)).font(.system(size: 11.5)).foregroundStyle(p["down"])
      }
      HStack {
        Spacer()
        Button(L10n.text("common.cancel"), action: onClose).keyboardShortcut(.cancelAction)
        Button(L10n.text("common.save")) {
          Task {
            saving = true
            defer { saving = false }
            if await model.setTunnelNetworks(profile, networks: networks, dnsDomains: domains) {
              onClose()
            } else {
              // The bridge's message belongs in the sheet, not behind it.
              message = model.error
              model.error = nil
            }
          }
        }.keyboardShortcut(.defaultAction).disabled(saving)
      }
    }.padding(20).frame(width: 440)
      .onAppear {
        networks = (profile.tunnelNetworks ?? []).joined(separator: "\n")
        domains = (profile.tunnelDnsDomains ?? []).joined(separator: ", ")
      }
  }
}
