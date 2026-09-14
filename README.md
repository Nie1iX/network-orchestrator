# Network Orchestrator

A Tauri 2 desktop app that manages WireGuard, OpenVPN, and Xray/VLESS tunnels
on Windows with versioned profiles, transactional policy routes, and a
predicted/effective route map — plus a cross-platform read-only network
explorer.

## Development status

The project is in pre-release stabilization. MVP-0–4 functionality is implemented, but the current release candidate has not yet completed disposable-VM E2E, packaged install/uninstall smoke testing, crash-recovery drills with real backends, or code signing.

Local development and release builds are supported and do not require CI/CD. GitHub Actions workflows exist in the repository, but CI/CD is intentionally deferred as a release gate until the application is stable.

The repository and documentation currently use **Network Orchestrator**. The Tauri package and window still use **Network Manager** and **Network Explorer**; choosing and applying one product name remains a future decision.

## Quick Start

```bash
npm install
npm run tauri dev
```

Requires Windows for tunnel management. WireGuard (`wireguard.exe`) and
OpenVPN (`openvpn.exe`) must be installed separately or selected as an
existing executable; Xray may likewise be selected, or explicitly installed
as a verified app-managed version from the Backend prerequisites section.
No backend is silently downloaded or updated; the Profiles tab shows which
backends were found.

## Features (MVP-0–4)

- **Network Explorer** — interface inventory (addresses, DNS, MTU, state),
  full IPv4/IPv6 route table, longest-prefix-match route lookup, and
  auto-refresh on OS route changes.
- **Profiles** — versioned profiles for WireGuard (`.conf`), OpenVPN
  (`.ovpn`), and Xray/VLESS (`vless://` import generates a managed config with
  a local SOCKS5 listener; existing Xray JSON can be imported as-is).
- **Managed config vault** — imported/generated configs live in
  `app_data/configs/<profile>/rev-N/` with explicit Windows DACLs
  (current user + SYSTEM + Administrators, protected). Generated Xray configs
  are additionally encrypted with DPAPI (`config.json.dpapi`) and decrypted
  only in memory.
- **Connect/disconnect** — WireGuard via `wireguard.exe /installtunnelservice`,
  OpenVPN and Xray as contained child processes under a Windows Job Object.
  Xray SOCKS ports are auto-allocated from 10808–10999 on conflict.
- **Policy routes** — per-profile CIDR routes applied transactionally through
  the IP Helper API, persisted for crash recovery, rolled back on failure.
- **Route map** — predicted routes from static config analysis vs. the
  effective OS route table; missing/mismatched-interface/exact-competition
  diffs, prefix tree, LPM + metric winner resolution.
- **Diagnostics** — per-profile checks: configuration, backend executable,
  tunnel status, protocol health (WireGuard `wg.exe show` dump, OpenVPN log
  markers, Xray process state), redacted bounded log tails, endpoints and
  listeners.
- **Backend management** — persistent custom executable paths for
  WireGuard, OpenVPN, and Xray; explicit managed Xray v26.7.28
  install/remove from the Backend prerequisites section with progress and
  cancellation. The managed archive is pinned (SHA-256
  `c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1`, plus
  required-file hashes), installed under the app data directory, and
  integrity-checked before use; the fixed official release URL is shown in
  the install confirmation and there is no automatic update.
- **Recovery** — on startup the app detects leftover WireGuard services,
  owned routes, and stale system-proxy ownership, and offers explicit
  cleanup. Graceful close restores proxy settings and removes owned routes
  before stopping tunnels.
- **Optional system proxy** — Xray profiles with a configured local SOCKS5
  port can set the Windows
  per-user proxy (`socks=127.0.0.1:<port>`) with a bypass list; previous
  settings are snapshotted, verified, and restored on disconnect/shutdown.
- **Elevation** — interface changes, WireGuard/OpenVPN, and policy routes
  require administrator; the app can restart itself elevated. The system
  proxy uses HKCU and needs no elevation.

## Documentation

- `docs/security.md` — threat model, vault ACL/DPAPI, redaction, trust.
- `docs/recovery.md` — crash recovery, Job Object, ownership model.
- `docs/testing.md` — opt-in Windows E2E harness (disposable VM only).
- `docs/plans/` — stage-by-stage implementation plans.
- `AGENTS.md` — contributor/agent commands and safety rules.

## Development

### Prerequisites

- Windows 10/11, [Rust](https://rustup.rs/) (MSVC toolchain),
  [Node.js](https://nodejs.org/), Visual Studio C++ build tools, WebView2.
- Backend executables are needed only for the profiles you actually use.
  WireGuard (`wireguard.exe`/`wg.exe`) and OpenVPN (`openvpn.exe`) external
  packages remain required because their drivers/services are not managed by
  the app; an external Xray (`xray.exe`) install is optional because a
  verified managed install exists.

### Quality gates

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build
```

### Local Windows installer

No CI/CD service is required:

```bash
npm ci
npm run tauri build -- --bundles nsis
```

Produces an unsigned release-mode NSIS installer under `target/release/bundle/nsis/`.

## Limitations

- Tunnel management and mutations are Windows-only; on Linux the explorer is
  read-only and VPN/proxy features return `Unsupported`.
- No process-based routing, no VPN chaining, and no custom TUN. Generated Xray configurations expose a local SOCKS5 inbound; imported Xray JSON may define other inbounds.
- The release-candidate gate is incomplete: real-backend VM E2E, packaged install/uninstall smoke testing, crash-recovery drills, and a secret scan remain pending.
- The destructive E2E harness runs only on a disposable Windows VM with
  explicit env acknowledgement (see `docs/testing.md`).
- Release artifacts are unsigned; expect SmartScreen warnings.

## License

[MIT](LICENSE)
