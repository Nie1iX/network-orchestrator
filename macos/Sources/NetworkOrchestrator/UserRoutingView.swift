import SwiftUI

/// Read-only list of routing settings a person made on this Mac.
struct UserRoutingView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  var loadsOnAppear = true
  @State private var loading = false
  private var settings: UserNetworkSettings? { model.userNetwork }

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack(alignment: .top, spacing: 10.5) {
        Text(
          L10n.text(
            "Settings you or your apps added on this Mac. Read-only: nothing here changes the system."
          )
        ).font(.system(size: 11.9)).foregroundStyle(p.secondary)
        Spacer(minLength: 0)
        if loading { Spinner() }
        Button(L10n.text("Refresh")) { Task { await load() } }.disabled(loading)
      }
      if let settings {
        if !settings.unreadable.isEmpty {
          Text(
            L10n.text(
              "Some sources could not be read: {value0}",
              ["value0": settings.unreadable.joined(separator: ", ")])
          ).font(.system(size: 11.9)).foregroundStyle(p["warn"])
        }
        section(
          "Persistent routes",
          "Saved in network service settings; restored after every restart.",
          empty: settings.persistentRoutes.isEmpty
        ) {
          table(
            ["Destination", "Gateway", "Service", "Status"],
            settings.persistentRoutes.map { route in
              [
                .mono(route.destination), .mono(route.gateway ?? route.interface ?? "—"),
                .plain(
                  [route.service, route.interface].compactMap { $0 }.joined(separator: " · ")),
                status(route.active),
              ]
            })
        }
        section(
          "Startup jobs", "launchd jobs that run route or routing scripts.",
          empty: settings.startupJobs.isEmpty
        ) {
          VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(settings.startupJobs.enumerated()), id: \.offset) { _, job in
              jobRow(job)
            }
          }
        }
        section(
          "Static routes in the kernel table",
          "Live until restart unless something adds them again.",
          empty: settings.staticRoutes.isEmpty
        ) {
          table(
            ["Destination", "Gateway", "Interface", "Source"],
            settings.staticRoutes.map { route in
              [
                .mono(route.destination), .mono(route.gateway), .mono(route.interface),
                sourceBadge(route.source),
              ]
            })
        }
        section(
          "Per-domain DNS", "Files in /etc/resolver send queries for a domain to specific servers.",
          empty: settings.resolvers.isEmpty
        ) {
          table(
            ["Domain", "Nameservers"],
            settings.resolvers.map { resolver in
              [
                .mono(resolver.domain),
                .mono(
                  ([resolver.nameservers.joined(separator: ", ")]
                    + [resolver.port.map { L10n.text("Port {value0}", ["value0": String($0)]) }]
                    .compactMap { $0 }).joined(separator: " · ")),
              ]
            })
        }
        section(
          "Hosts file", "Names pinned to addresses in /etc/hosts.", empty: settings.hosts.isEmpty
        ) {
          table(
            ["Address", "Names"],
            settings.hosts.map { [.mono($0.address), .mono($0.names.joined(separator: " "))] })
        }
        section(
          "Network service settings",
          "Manual addresses, DNS and proxies set in System Settings → Network.",
          empty: settings.services.isEmpty
        ) {
          VStack(alignment: .leading, spacing: 10.5) {
            ForEach(Array(settings.services.enumerated()), id: \.offset) { _, service in
              serviceBlock(service)
            }
          }
        }
      } else if !loading {
        AppEmptyState { Text(L10n.text("Nothing configured.")) }
      }
    }.task { if loadsOnAppear { await load() } }
  }

  private func load() async {
    loading = true
    await model.loadUserNetwork()
    loading = false
  }

  private enum Cell {
    case plain(String)
    case mono(String)
    case badge(String, String)
  }

  private func status(_ active: Bool) -> Cell {
    active ? .badge("Active", "up") : .badge("Not in table", "down")
  }

  private func sourceBadge(_ source: String) -> Cell {
    switch source {
    case "persistent": .badge("Persistent route", "info")
    case "startupJob": .badge("Startup job", "info")
    case "tunnel": .badge("VPN tunnel", "virtual")
    default: .badge("Manual or script", "unknown")
    }
  }

  private func section<C: View>(
    _ title: String, _ detail: String, empty: Bool, @ViewBuilder content: () -> C
  ) -> some View {
    AppCard {
      VStack(alignment: .leading, spacing: 10.5) {
        VStack(alignment: .leading, spacing: 3.5) {
          Text(L10n.text(title)).font(.system(size: 13.3, weight: .semibold))
          Text(L10n.text(detail)).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
        if empty {
          Text(L10n.text("Nothing configured.")).font(.system(size: 11.9)).foregroundStyle(
            p.muted)
        } else {
          content()
        }
      }
    }
  }

  private func table(_ headers: [String], _ rows: [[Cell]]) -> some View {
    VStack(spacing: 0) {
      HStack(spacing: 0) {
        ForEach(headers, id: \.self) { header in
          Text(L10n.text(header)).font(.system(size: 11.2, weight: .semibold)).foregroundStyle(
            p.secondary
          ).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10.5).padding(
            .vertical, 7)
        }
      }.background(p["bg-elev"])
      ForEach(Array(rows.enumerated()), id: \.offset) { _, cells in
        HStack(spacing: 0) {
          ForEach(Array(cells.enumerated()), id: \.offset) { _, cell in
            Group {
              switch cell {
              case .plain(let value): Text(value).font(.system(size: 11.9))
              case .mono(let value): Text(value).font(.system(size: 11.9, design: .monospaced))
              case .badge(let text, let color): AppBadge(text: text, color: color)
              }
            }.lineLimit(1).truncationMode(.middle).textSelection(.enabled).frame(
              maxWidth: .infinity, alignment: .leading
            ).padding(.horizontal, 10.5).padding(.vertical, 7)
          }
        }.overlay(alignment: .top) { Rectangle().fill(p.border).frame(height: 1) }
      }
    }.clipShape(RoundedRectangle(cornerRadius: 6)).overlay(
      RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
  }

  private func jobRow(_ job: UserNetworkSettings.StartupJob) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      HStack(spacing: 7) {
        Text(job.label).font(.system(size: 11.9, weight: .semibold))
        AppBadge(text: scopeLabel(job.scope), color: "info")
        Spacer(minLength: 0)
        if let active = job.active {
          AppBadge(
            text: active ? "Active" : "Not in table", color: active ? "up" : "down")
        }
      }
      Text(job.command).font(.system(size: 11.2, design: .monospaced)).foregroundStyle(p.text)
        .textSelection(.enabled)
      Text(
        ([job.runAtLoad ? L10n.text("At startup") : nil]
          + [
            job.intervalSeconds.map {
              L10n.text("Every {value0} s", ["value0": String(describing: $0)])
            }
          ] + [job.path]).compactMap { $0 }.joined(separator: " · ")
      ).font(.system(size: 10.5)).foregroundStyle(p.muted).textSelection(.enabled)
    }.padding(.vertical, 7).overlay(alignment: .bottom) {
      Rectangle().fill(p.border).frame(height: 1)
    }
  }

  private func scopeLabel(_ scope: String) -> String {
    switch scope {
    case "daemon": "System daemon"
    case "agent": "Agent for all users"
    default: "Your agent"
    }
  }

  private func serviceBlock(_ service: UserNetworkSettings.Service) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      HStack(spacing: 7) {
        Text(service.service).font(.system(size: 11.9, weight: .semibold))
        if let interface = service.interface {
          Text(interface).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(p.muted)
        }
        if !service.enabled { AppBadge(text: "Disabled", color: "unknown") }
      }
      ForEach(Array(service.items.enumerated()), id: \.offset) { _, item in
        HStack(alignment: .top, spacing: 7) {
          Text(L10n.text(settingLabel(item.kind))).foregroundStyle(p.muted)
          Spacer(minLength: 0)
          Text(item.kind == "proxyAutoDiscovery" ? L10n.text("On") : item.value).font(
            .system(size: 11.9, design: .monospaced)
          ).multilineTextAlignment(.trailing).textSelection(.enabled)
        }.font(.system(size: 11.9))
      }
    }
  }

  private func settingLabel(_ kind: String) -> String {
    switch kind {
    case "ipv4Address": "Manual IPv4 address"
    case "ipv4Router": "IPv4 router"
    case "ipv6Address": "Manual IPv6 address"
    case "ipv6Router": "IPv6 router"
    case "dnsServers": "DNS servers"
    case "searchDomains": "Search domains"
    case "httpProxy": "Web proxy (HTTP)"
    case "httpsProxy": "Secure web proxy (HTTPS)"
    case "socksProxy": "SOCKS proxy"
    case "pacUrl": "Automatic proxy configuration"
    default: "Proxy auto-discovery"
    }
  }
}
