# Platform support matrix

Which features work on which OS, and where the branch lives in code.
Update this when a capability flag or a `cfg!(…)` branch is added.

Legend: ✅ supported · ⚠️ a generic code path exists but has never been
built or tested on that OS · ❌ no code path · — not applicable.

Sources of truth:
- `get_platform_capabilities` → `src-tauri/src/commands/system.rs`
  (`PlatformCapabilities`, surfaced to the UI as `caps` via
  `usePlatformCapabilities()`)
- `#[cfg(target_os = …)]` blocks in `crates/core` and `crates/daemon`
- `caps.os === "linux"` / `caps.appUpdates` gates in `src/`

macOS is served by the **native SwiftUI client** (`macos/`, Rust core via
`crates/macos-bridge`), not by the Tauri shell. The macOS column describes
that client. Without a privileged helper it runs only user-level operations:
profiles, import, analysis, read-only network inventory, Xray in loopback
SOCKS/HTTP mode and the per-user system proxy. Everything that needs root
waits for the launchd helper
(`docs/plans/2026-09-30-14-macos-privileged-helper.md`). Android and iOS are out of scope entirely.

## Backends

| Feature | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| WireGuard profile | ✅ | ✅ | ❌ | Win: embedded tunnel lib + service install; Linux: `wireguard-tools` + daemon; macOS has neither path |
| OpenVPN profile | ✅ | ✅ | ❌ helper | Generic `Command` spawn compiles, but route/DNS plumbing and credential flow are OS-specific; never verified |
| Xray — SOCKS mode | ✅ | ✅ | ✅ native, arm64 | macOS: native client runs managed Xray via `TunnelManager` in `crates/macos-bridge/src/runtime.rs` |
| Xray — TUN mode | ✅ manual | ✅ managed | ❌ | Win: user sets iface name/IP; Linux: daemon generates config (`xrayMode: "tun"` default) |
| Static routes (`none`) | ✅ | ✅ | ❌ helper | Policy routes only, no tunnel; route mutation is IP Helper / netlink |
| Managed Xray install | ✅ x86_64 only | ✅ x86_64 only | ✅ arm64, download or local zip | `managedXrayInstall`; fixed-version, hash-pinned download. Win: app-local store; Linux: archive goes to the daemon (`xray.install`), which re-verifies hashes and installs root-owned files under `/usr/lib/network-orchestrator/xray`; macOS: per-user managed root |
| WireGuard standard `.conf` import | ✅ | — | — | `wireguardStandardImport` |

## System integration

| Feature | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| Privileged ops | ✅ elevated relaunch | ✅ daemon | ⚠️ helper installs, no mutations yet | Win: `elevationRelaunch` respawn; Linux: `net-manager-daemon` (systemd + polkit + Unix socket); macOS: launchd helper (`SMAppService.daemon`) answers `hello` and verifies the app, but has no tunnel executors yet — see the helper plan |
| Ask for admin password (polkit policy) | — | ✅ | — | `get/set_vpn_auth_mode`; Settings → System |
| Always-on before sign-in | — | ✅ | — | WG + static routes only; daemon journal; OVPN/Xray unsupported |
| Start at login | — | ✅ | — | `get/set_login_autostart` |
| Conditional routes | — | ✅ | — | `CondRules` UI; condition = interface address in prefix; applied via daemon |
| Tailscale service row | — | ✅ | — | `tailscaled` proxied through the daemon's LocalAPI client; surfaced under Profiles → Services |
| System proxy toggle | ✅ | — | ✅ `networksetup`, hardware services; ignored while a packet-tunnel VPN is primary | Win: registry; macOS: `system_proxy::macos::MacProxyAdapter`; `UnsupportedProxyAdapter` on Linux |
| In-app updater | ✅ | — | ❌ | `appUpdates` is `windows`-only; Linux ships `.deb`/`.rpm`/AUR → package manager |
| Per-link DNS | — | ✅ | — | `crates/daemon/src/dns.rs`, systemd-resolved; Windows relies on pushed/adapter DNS |
| Recovery prompt (leftover resources) | ✅ | ✅ | ⚠️ | Win: orphaned adapters/routes; Linux: stale daemon owners; macOS would find nothing to recover |

## Observability (identical on both)

On macOS these have no backend: interface/route data flows through the
Linux daemon or win32-specific enumeration — nothing generic exists.

| Feature | Where |
|---|---|
| Interfaces, addresses, throughput rates | Network tab, `get_interfaces` |
| Exit-IP check per profile | Monitor tab, `ExitIpPanel` |
| Route map / tree / table / lookup / flow | Routes tab, `get_route_map`, `lookup_destination` |
| Per-endpoint delay measurement | Profiles → detail, `measure_subscription_endpoint_delay` (Xray spawn) |
| Diagnostics report | Profile → Diagnostics, `diagnose_profile` |
| App + daemon logs | Logs tab |

## Profiles & subscriptions (identical on both)

- Multiple profiles may run simultaneously; saved combinations = Sets
  (localStorage `netmanager.connections.snippets`).
- Subscription profiles: multi-endpoint list, per-endpoint delay,
  refresh interval, traffic quota display.
- Import: URI/file batch import (`ImportModal`); WireGuard `.conf` import
  additionally on Windows only.
- Domain/IP policies per profile (`block`/`proxy`/`direct`) — both OSes;
  conditional rules are Linux-only (see above).
- On macOS profile CRUD, sets and import are the only plausibly-working
  pieces (plain on-disk store, `protect_path` has a `cfg(not(windows))`
  fallback) — unverified.

## Deliberately absent

- Kill switch / lockdown mode — not implemented.
- Per-app split tunneling — not implemented.
- Android, iOS — out of scope, no port.

Notes:
- Every ✅ in this matrix should stay honest: when a row drifts, fix the
  code gate (`PlatformCapabilities` / `cfg!`) and this table together.
