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

macOS is **not a build target**: nothing branches on
`target_os = "macos"`, the privileged layer is Linux-only (daemon:
systemd + polkit + netlink) or Windows-only (IP Helper policy routes,
`wireguard.exe /installtunnelservice`, registry proxy). The macOS
column below maps where generic code paths would fall out — it is a
porting-cost estimate, not validation; the app has never been built
for macOS. Android and iOS are out of scope entirely.

## Backends

| Feature | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| WireGuard profile | ✅ | ✅ | ❌ | Win: embedded tunnel lib + service install; Linux: `wireguard-tools` + daemon; macOS has neither path |
| OpenVPN profile | ✅ | ✅ | ⚠️ | Generic `Command` spawn compiles, but route/DNS plumbing and credential flow are OS-specific; never verified |
| Xray — SOCKS mode | ✅ | ✅ | ⚠️ | `spawn_xray` is OS-generic, but no standard search paths exist — user must set the executable explicitly; no system-proxy glue |
| Xray — TUN mode | ✅ manual | ✅ managed | ❌ | Win: user sets iface name/IP; Linux: daemon generates config (`xrayMode: "tun"` default) |
| Static routes (`none`) | ✅ | ✅ | ❌ | Policy routes only, no tunnel; route mutation is IP Helper / netlink |
| Managed Xray install | ✅ x86_64 only | ✅ x86_64 only | — | `managedXrayInstall`; fixed-version, hash-pinned download. Win: app-local store; Linux: archive goes to the daemon (`xray.install`), which re-verifies hashes and installs root-owned files under `/usr/lib/network-orchestrator/xray` |
| WireGuard standard `.conf` import | ✅ | — | — | `wireguardStandardImport` |

## System integration

| Feature | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| Privileged ops | ✅ elevated relaunch | ✅ daemon | ❌ | Win: `elevationRelaunch` respawn; Linux: `net-manager-daemon` (systemd + polkit + Unix socket); no elevation path exists for macOS |
| Ask for admin password (polkit policy) | — | ✅ | — | `get/set_vpn_auth_mode`; Settings → System |
| Always-on before sign-in | — | ✅ | — | WG + static routes only; daemon journal; OVPN/Xray unsupported |
| Start at login | — | ✅ | — | `get/set_login_autostart` |
| Conditional routes | — | ✅ | — | `CondRules` UI; condition = interface address in prefix; applied via daemon |
| Tailscale service row | — | ✅ | — | `tailscaled` proxied through the daemon's LocalAPI client; surfaced under Profiles → Services |
| System proxy toggle | ✅ | — | ❌ | `systemProxy`; `UnsupportedProxyAdapter` on non-Windows — a macOS port would need `networksetup` |
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
