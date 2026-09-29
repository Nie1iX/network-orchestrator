# Platform support matrix

Which features work on which OS, and where the branch lives in code.
Update this when a capability flag or a `cfg!(…)` branch is added.

Sources of truth:
- `get_platform_capabilities` → `src-tauri/src/commands/system.rs`
  (`PlatformCapabilities`, surfaced to the UI as `caps` via
  `usePlatformCapabilities()`)
- `#[cfg(target_os = …)]` blocks in `crates/core` and `crates/daemon`
- `caps.os === "linux"` / `caps.appUpdates` gates in `src/`

macOS is **not supported**: the privileged layer is Linux-only
(`crates/daemon`, systemd + polkit + netlink) and all non-Windows
branches assume Linux.

## Backends

| Feature | Windows | Linux | Notes |
|---|---|---|---|
| WireGuard profile | ✅ | ✅ | Win: embedded tunnel lib; Linux: `wireguard-tools` + daemon |
| OpenVPN profile | ✅ | ✅ | External `openvpn` binary; on Linux credentials are handled via daemon auth prompt |
| Xray — SOCKS mode | ✅ | ✅ | Local 127.0.0.1 listeners + optional system proxy |
| Xray — TUN mode | ✅ manual | ✅ managed | Win: user sets iface name/IP; Linux: daemon generates config (`xrayMode: "tun"` default) |
| Static routes (`none`) | ✅ | ✅ | Policy routes only, no tunnel |
| Managed Xray install | ✅ x86_64 only | — | `managedXrayInstall`; fixed-version, hash-pinned download |
| WireGuard standard `.conf` import | ✅ | — | `wireguardStandardImport` |

## System integration

| Feature | Windows | Linux | Notes |
|---|---|---|---|
| Privileged ops | ✅ elevated relaunch | ✅ daemon | Win: `elevationRelaunch` respawn; Linux: `net-manager-daemon` (systemd + polkit + Unix socket) |
| Ask for admin password (polkit policy) | — | ✅ | `get/set_vpn_auth_mode`; Settings → System |
| Always-on before sign-in | — | ✅ | WG + static routes only; daemon journal; OVPN/Xray unsupported |
| Start at login | — | ✅ | `get/set_login_autostart` |
| Conditional routes | — | ✅ | `CondRules` UI; condition = interface address in prefix; applied via daemon |
| System proxy toggle | ✅ | — | `systemProxy`; per-profile `useSystemProxy` + bypass list |
| In-app updater | ✅ | — | `appUpdates`; Linux ships `.deb`/`.rpm`/AUR → package manager |
| Per-link DNS | — | ✅ | `crates/daemon/src/dns.rs`, systemd-resolved; Windows relies on pushed/adapter DNS |
| Recovery prompt (leftover resources) | ✅ | ✅ | Win: orphaned adapters/routes; Linux: stale daemon owners |

## Observability (identical on both)

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

## Deliberately absent

- Kill switch / lockdown mode — not implemented.
- Per-app split tunneling — not implemented.
- macOS, Android, iOS — out of scope.

Notes:
- `TailscalePanel.tsx` exists (Linux-only) but is not mounted anywhere —
  wire it into a page or remove it.
- Every ✅ in this matrix should stay honest: when a row drifts, fix the
  code gate (`PlatformCapabilities` / `cfg!`) and this table together.
