# Route ownership unification + Xray TUN mode

## Goal

Приложение становится единственным владельцем OS routes. Бэкенды (WireGuard,
OpenVPN) никогда не ставят routes сами — приложение всегда редактирует конфиг
до поднятия (`Table = off` / `--route-nopull`) и ставит routes через
`PolicyManager`. Xray получает TUN mode как full-tunnel альтернатива SOCKS.

## Stages (in order)

### Stage 1 — OpenVPN route probe

**Why first**: даёт данные для Stage 2 (OpenVPN routes без `profile.routes`).

- New command `probe_openvpn_routes(id)` in `src-tauri/src/commands/tunnels.rs`.
- Runs `openvpn.exe --config <path> --route-nopull` as short-lived child with
  log file in temp.
- Polls log up to ~20s for `PUSH_REPLY` or `Initialization Sequence Completed`.
- Parses routes via existing `parse_openvpn_pushed_reply` (vpn.rs).
- Kills process, removes temp log, returns `Vec<AnalyzedRoute>`.
- Frontend: "Probe routes" button in `ProfileFormModal` for OpenVPN backend
  (existing profiles only, requires config path).
- Result shown as read-only route list; user can copy destinations into
  `profile.routes`.

**Files**: `src-tauri/src/commands/tunnels.rs`, `src-tauri/src/lib.rs`,
`src-tauri/src/commands/mod.rs`, `src/components/ProfileFormModal.tsx`,
`src/types.ts`.

**Verification**: `cargo test -p net-manager-app` (new test with fake openvpn
log), `npm run build`.

### Stage 2 — Always-app routing

**Why second**: зависит от Stage 1 для OpenVPN route discovery.

- `wireguard_connect_spec`: ALWAYS inject `Table = off` (remove the
  `!profile.routes.is_empty()` condition).
- `openvpn_connect_spec`: ALWAYS add `--route-nopull`.
- `connect_profile`: after interface comes up, always install routes via
  `PolicyManager`:
  - If `profile.routes` non-empty → install them (current behavior).
  - Else → derive routes from `analyze_profile().os_routes`:
    - WG: AllowedIPs (static, already known).
    - OpenVPN: read pushed routes from log via `openvpn_pushed_routes()`
      (post-connect, after waiting for PUSH_REPLY in log).
    - Xray SOCKS: no OS routes (skip).
    - Xray TUN: Stage 4.
- `TunnelManager::connect`: always record transient config path (WG) so
  cleanup works on disconnect.
- `static_route_profiles` (backend None) — unchanged, already app-owned.

**Breaking change**: profiles without `routes` previously relied on backend
self-routing. Now app always installs. For WG seamless (AllowedIPs → routes).
For OpenVPN requires post-connect log parse.

**Files**: `crates/core/src/vpn.rs`, `src-tauri/src/commands/tunnels.rs`.

**Verification**: `cargo test --workspace` (update existing connect tests),
`npm run build`.

### Stage 3 — AllowedIPs transient rewrite

**Why third**: строится на Stage 2 (always `Table = off`).

- New function `wireguard_allowedips_config(source, profile_id, allowed_ips)`
  in `vpn.rs` — transient copy with modified `AllowedIPs` in `[Peer]`.
- In `wireguard_connect_spec`: if `profile.routes` non-empty, compute required
  AllowedIPs = union of original AllowedIPs + all `profile.routes` destinations.
  If original AllowedIPs already covers all policy routes, no rewrite needed.
  If not, generate transient with expanded AllowedIPs.
- This ensures WG crypto routing accepts all policy-routed traffic.
- Validation: warn (not block) if policy route is narrower than AllowedIPs
  (kill-switch narrowing) — this is intentional user choice.

**Files**: `crates/core/src/vpn.rs`.

**Verification**: `cargo test -p net-manager-core` (new tests for
`wireguard_allowedips_config` and union computation).

### Stage 4 — Xray TUN mode

**Why last**: зависит от Stage 2 (app-owned routes, conflict enforcement).

- New field `xray_mode: XrayMode` in `Profile` model (`Socks` | `Tun`).
  Default `Socks` for backward compat.
- `xray.rs` config generation: if `Tun` mode, inbound is
  `{ "protocol": "tun", "settings": { "interfaceName": "xray-tun", "ip": "...", "mtu": 1500 } }`
  instead of socks. Xray creates Wintun interface and installs `0.0.0.0/0`
  route internally (via its `table` setting) OR app installs via
  `PolicyManager`.
- `analysis.rs` `analyze_xray`: TUN inbound → `os_routes` with
  `0.0.0.0/0` (or configured tun route), `source: "Xray TUN"`.
- `connect_profile`: if Xray TUN mode, `ensureElevation` before connect
  (Wintun requires admin). After connect, wait for `xray-tun` interface,
  install routes via `PolicyManager` if Xray doesn't self-install.
- `conflicts_between`: already handles `0.0.0.0/0` overlap — second TUN
  profile blocked by `active_profile_conflicts`.
- DNS: `domainStrategy: "IPIfNonMatch"` + DNS outbound in Xray config, or
  leave system DNS (MVP: leave system, document limitation).
- Frontend: `XrayMode` selector in `ProfileFormModal` (Socks / Tun).
  TUN mode hides SOCKS port field, shows TUN interface name field.

**Files**: `crates/core/src/models.rs`, `crates/core/src/xray.rs`,
`crates/core/src/analysis.rs`, `crates/core/src/vpn.rs`,
`src-tauri/src/commands/tunnels.rs`, `src/types.ts`,
`src/components/ProfileFormModal.tsx`.

**Verification**: `cargo test --workspace`, `npm run build`.

## Cross-cutting

- `AGENTS.md` conventions: TDD, fake adapters, no real VPN in tests.
- Security: no secrets in logs, transient configs ACL-protected.
- All stages run full quality gate before reporting done:
  `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
  `npm run build`.
