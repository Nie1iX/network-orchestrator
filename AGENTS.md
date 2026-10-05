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
  Docker and Windows VM E2E contracts; `docs/platform-matrix.md` — per-OS
  feature support matrix (keep in sync with `PlatformCapabilities`).

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
- **Production binary:** never install a `cargo build --release` artifact as
  the prod app. Without the `tauri/custom-protocol` feature the release binary
  compiles with `cfg(dev)` and loads `devUrl` (`http://127.0.0.1:1420`) — the
  window then shows "Could not connect to 127.0.0.1". Build via
  `npm run tauri build` / `scripts/build-linux-deb.sh` (the CLI injects the
  feature), or pass `--features tauri/custom-protocol` to cargo explicitly.
- `scripts/macos-dev.sh build|run|test|preview|check|du|clean` — native
  macOS loop: `release-fast` bridge (no LTO, incremental) + Swift debug,
  isolated QA data for `run`, offscreen renders for `preview`.
- `npm run dev:app` — Linux dev run against the dev daemon
  (`network-orchestrator-dev.service`, socket `/run/network-orchestrator-dev/`,
  data dir `~/.local/share/com.netmanager.app.dev/`, "(Dev)" window title);
  `npm run tauri dev` keeps the production identity; on Windows,
  `npm run tauri build -- --bundles nsis` builds unsigned NSIS under
  `target/release/bundle/nsis/`; on Linux use `scripts/build-linux-deb.sh`
  (`.deb`), `scripts/build-linux-deb.sh rpm` (Fedora `.rpm`) or
  `scripts/build-linux-arch.sh`.
- `npm audit --audit-level=high` — dependency audit.
- `e2e/linux/run.sh` (`E2E_DISTRO=fedora` for a Fedora 44 client) — Linux
  daemon/tunnel E2E in disposable Docker containers;
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
- `crates/macos-bridge` stays unprivileged: never add `daemon_protocol`
  methods or network mutations to it. macOS mutations go through a launchd
  helper speaking `daemon_protocol` over a Unix socket
  (`docs/plans/2026-09-30-14-macos-privileged-helper.md`). The only
  exceptions are user-level: the managed Xray child listening on loopback and
  the per-user system proxy via `networksetup` (snapshot + rollback through
  `SystemProxyManager`), and an explicit user toggle of another app's VPN
  service via `scutil --nc start|stop <UUID>`. Routes, interfaces and DNS
  stay helper-only.
- Do not commit unless explicitly asked; do not push to `main`/`master`.

## Conventions

- Rust: serde `camelCase` models in `crates/core/src/models.rs`; errors as
  `io::Result` in core, `Result<_, String>` in commands; TDD — tests first,
  report RED/GREEN.
- Frontend: components subscribe to `route-changed` window events for
  refresh; types stay in `src/types.ts`.
- i18n: the web UI uses dotted keys (`t("profiles.title")`); the macOS app
  uses English text as the key (`L10n.text("Add a connection")`). Both share
  `locales/*.json` — never delete an English-text key that only appears in
  Swift sources.
- App version has one source of truth: `[workspace.package].version` in the
  root `Cargo.toml`; do not duplicate it in `package.json` or `tauri.conf.json`.
- Versioning, commit messages and releases follow `docs/versioning.md`
  (SemVer, Conventional Commits in English, `CHANGELOG.md`); bump the version
  in a separate `chore(release): X.Y.Z` commit after each group of changes.
- Store files are versioned documents written atomically (temp + rename)
  and ACL-protected via `config_security::protect_path`.

## Design system

- All colors come from the OKLCH design tokens in `design/tokens.json`
  (neutral surfaces, indigo accent, `--up/--down/--warn/--info` semantics,
  `--cat-*` categorical scale, dark + light themes). Edit `tokens.json` and
  run `python3 scripts/generate-ui-theme.py` — do not edit the generated
  outputs (`src/theme.generated.css`, `src/palette.ts`,
  `macos/Sources/NetworkOrchestrator/Theme.generated.swift`). No hardcoded
  hex/`rgba()` colors in CSS or TSX — JS-rendered visuals import from
  `src/palette.ts`. User-facing copy lives in `locales/*.json`; run
  `python3 scripts/generate-localizations.py` instead of editing
  `src/i18n/catalog.generated.ts` or the macOS `Localizations.json`.
- One primary CTA per screen: `btn-primary`. Default `<button>` is the
  secondary style; `btn-danger`, `btn-ghost`, `btn-sm`, `btn-with-icon` are
  the other sanctioned variants.
- Icons live in `src/icons.tsx` (24×24, stroke-based). No Unicode glyphs as
  UI icons; `…` is allowed only in placeholders/loading labels.
- Right-align numeric table cells with `.num`; use `formatBytes`/`formatRate`
  from `src/format.ts` and `<RateText>` for rx/tx readouts.
- Transient feedback uses `useToast()` (`ToastProvider` wraps the app in
  `src/App.tsx`); persistent banners keep `.runtime-notice`/`.save-notice`.
