# Network Orchestrator

A Tauri 2 desktop app for WireGuard, OpenVPN, Xray/VLESS, policy routes, and
network exploration. Tunnel management works on Windows. On Linux, the
privileged daemon, WireGuard and OpenVPN split/full tunnels with per-link DNS,
Xray VLESS/Hysteria2 SOCKS5/HTTP proxy and Xray TUN have passed container E2E
on Ubuntu 26.04 and Fedora 44 clients. Packages: `.deb` (Ubuntu/Debian),
`.rpm` (Fedora) and an Arch `PKGBUILD`. Desktop acceptance on a real install
is still pending.

## Development status

The project is in pre-release stabilization. MVP-0–4 functionality is implemented. Linux container E2E and package install/remove smoke testing have passed; disposable-VM desktop acceptance and code signing remain open.

Local development and release builds are supported and do not require CI/CD. GitHub Actions workflows exist in the repository, but CI/CD is intentionally deferred as a release gate until the application is stable.

The repository, Tauri package, window and app UI use **Network Orchestrator**.

## Quick Start

```bash
npm install
npm run tauri dev
```

On Windows, WireGuard (`wireguard.exe`) and OpenVPN (`openvpn.exe`) must be
installed separately or selected as existing executables; Xray may likewise be
selected, or explicitly installed as a verified app-managed version from the
Backend prerequisites section. On Linux, WireGuard and OpenVPN require the
daemon plus `wireguard-tools` or `openvpn`; per-link DNS needs
`systemd-resolved`.
No backend is silently downloaded or updated; the Profiles tab shows which
backends were found.

## Features (MVP-0–4)

- **Network Explorer** — interface inventory (addresses, DNS, MTU, state),
  route table, Linux kernel route lookup that accounts for policy rules,
  and auto-refresh on OS route changes.
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
  the Windows IP Helper API or Linux daemon, persisted for crash recovery and
  rolled back on failure.
  The profile form accepts bulk IPv4/IPv6 CIDR paste or text files and
  aggregates duplicate or adjacent networks before adding routes.
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
- `docs/testing.md` — Linux container and opt-in Windows VM E2E instructions.
- `docs/versioning.md` — SemVer, commit message and release rules.
- `CHANGELOG.md` — changes by version.
- `docs/plans/` — stage-by-stage implementation plans.
- `AGENTS.md` — contributor/agent commands and safety rules.

### Linux development

On Ubuntu or Fedora, install the daemon and its polkit policy before testing
route or interface changes:

```bash
scripts/install-linux-daemon-dev.sh
systemctl status network-orchestrator.service
npm run tauri dev
```

The script builds the daemon, installs it under `/usr/local/bin/`, and starts
the service. It requires `sudo`; `--uninstall` stops the service and removes
the development installation and its state. Route changes require polkit
authorization. The daemon's Unix socket is
`/run/network-orchestrator/daemon.sock`.

The Linux E2E test runs in disposable Docker containers on a private network,
each with its own network namespace. The client is Ubuntu 26.04 by default or
Fedora 44 (firewalld and resolved enabled); the peer is Ubuntu:

```bash
e2e/linux/run.sh
E2E_DISTRO=fedora e2e/linux/run.sh
```

It needs Docker, `/dev/net/tun`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and an
unconfined AppArmor profile for systemd in the container. Do not run these
network scenarios on the host.

Build local Linux packages without installing them on the host:

```bash
scripts/build-linux-deb.sh
scripts/build-linux-deb.sh rpm
scripts/build-linux-arch.sh
```

The unsigned `.deb` and `.rpm` are under `target/release/bundle/{deb,rpm}/`;
the Arch package is under `target/arch/`. The Arch build uses a disposable Docker container.

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

- Linux WireGuard, OpenVPN, Xray SOCKS5/HTTP and Xray TUN pass container E2E.
  Desktop acceptance is pending (see
  `docs/plans/2026-09-22-02-ubuntu-completion-spec.md`). Linux system proxy is
  outside the plan.
- Pre-login always-on currently supports WireGuard and static routes. OpenVPN
  and Xray profiles can auto-connect when the user launches the app, but cannot
  be enrolled for pre-login daemon replay yet.
- No process-based routing, no VPN chaining, and no custom TUN. Generated Xray configurations expose a local SOCKS5 inbound; imported Xray JSON may define other inbounds.
- The release-candidate gate is incomplete: real-backend VM E2E, desktop tray
  interaction and a secret scan remain pending. Docker package smoke and daemon
  crash-recovery drills have passed.
- The destructive E2E harness runs only on a disposable Windows VM with
  explicit env acknowledgement (see `docs/testing.md`).
- Release artifacts are unsigned; expect SmartScreen warnings.

## License

[MIT](LICENSE)
