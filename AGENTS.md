# AGENTS

Guidance for agents/contributors working in this repository.

## Layout

- `crates/core` — pure Rust library: models, static analysis, config vault,
  DPAPI, policy routes, tunnel manager, route plan, system proxy, explorer,
  backend executable settings, managed Xray verification.
- `crates/daemon` — Linux privileged system service: Unix socket protocol,
  polkit authorization, netlink mutations, ownership journal and recovery.
- `src-tauri` — Tauri 2 shell: commands in `src-tauri/src/commands/`,
  `state.rs` (AppState + runtime mutex), `lifecycle.rs` (shutdown cleanup),
  `test_support.rs` fixtures.
- `src` — React/TypeScript frontend; `src/types.ts` mirrors Rust models
  (camelCase).
- `e2e/linux` — disposable Docker test harness for the Linux daemon.
- `docs/plans` — per-stage implementation plans; `docs/testing.md` — Linux
  Docker and Windows VM E2E contracts.

## Setup

```bash
npm install
cargo fetch
rustup component add clippy rustfmt
```

Windows + MSVC + WebView2 are required for Windows tunnel functionality.
On Linux, the daemon requires systemd and polkit for network mutations;
WireGuard also needs `wireguard-tools`, OpenVPN needs `openvpn`, and DNS needs
`systemd-resolved`.

## Quality gate (run before reporting done)

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build
```

## Commands

- `cargo test -p net-manager-core <filter>` / `-p net-manager-app <filter>` —
  focused tests.
- `npm run tauri dev` — dev run; on Windows,
  `npm run tauri build -- --bundles nsis` builds unsigned NSIS under
  `target/release/bundle/nsis/`; on Linux use `scripts/build-linux-deb.sh` or
  `scripts/build-linux-arch.sh`.
- `npm audit --audit-level=high` — dependency audit.
- `e2e/linux/run.sh` — Linux daemon/WireGuard E2E in disposable Docker containers;
  requires Docker, `/dev/net/tun`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and
  unconfined AppArmor for containerized systemd.

## Safety rules

- **Never** run `cargo test -- --ignored` or
  `cargo test --test windows_e2e -- --ignored` outside a disposable Windows
  VM — those tests mutate real routes/interfaces and spawn real VPN
  processes. They require the env contract in `docs/testing.md`.
- No VPN/UAC/registry/network mutations in ordinary tests — use fake
  adapters, temp dirs, and in-memory fixtures.
- Run Linux netlink/systemd E2E only inside the disposable `e2e/linux`
  container. Never run its scenario script directly on the host.
- Never log or return config contents, VLESS URIs, private keys, UUIDs, or
  passwords; use existing redaction helpers and keep paths out of errors
  where they may contain user secrets.
- Managed configs must be written only through `ConfigVault` (ACL +
  revisioning); generated Xray plaintext must go through
  `store_generated_xray` (DPAPI on Windows).
- Managed backend downloads must stay fixed-version, hash-pinned, bounded,
  allowlisted, and atomic; tests use synthetic archives and never hit the
  network or install into real app data.
- Do not commit unless explicitly asked; do not push to `main`/`master`.

## Conventions

- Rust: serde `camelCase` models in `crates/core/src/models.rs`; errors as
  `io::Result` in core, `Result<_, String>` in commands; TDD — tests first,
  report RED/GREEN.
- Frontend: components subscribe to `route-changed` window events for
  refresh; types stay in `src/types.ts`.
- App version has one source of truth: `[workspace.package].version` in the
  root `Cargo.toml`; do not duplicate it in `package.json` or `tauri.conf.json`.
- Store files are versioned documents written atomically (temp + rename)
  and ACL-protected via `config_security::protect_path`.
