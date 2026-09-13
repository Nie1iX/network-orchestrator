# AGENTS

Guidance for agents/contributors working in this repository.

## Layout

- `crates/core` — pure Rust library: models, static analysis, config vault,
  DPAPI, policy routes, tunnel manager, route plan, system proxy, explorer.
- `src-tauri` — Tauri 2 shell: commands in `src-tauri/src/commands/`,
  `state.rs` (AppState + runtime mutex), `lifecycle.rs` (shutdown cleanup),
  `test_support.rs` fixtures.
- `src` — React/TypeScript frontend; `src/types.ts` mirrors Rust models
  (camelCase).
- `docs/plans` — per-stage implementation plans; `docs/testing.md` — E2E env
  contract.
- Active development may happen in `.worktrees/stabilize-network-orchestrator`.

## Setup

```bash
npm install
cargo fetch
rustup component add clippy rustfmt
```

Windows + MSVC + WebView2 required for full functionality.

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
- `npm run tauri dev` — dev run; `npm run tauri build` — unsigned NSIS under
  `target/release/bundle/nsis/`.
- `npm audit --audit-level=high` — dependency audit.

## Safety rules

- **Never** run `cargo test -- --ignored` or
  `cargo test --test windows_e2e -- --ignored` outside a disposable Windows
  VM — those tests mutate real routes/interfaces and spawn real VPN
  processes. They require the env contract in `docs/testing.md`.
- No VPN/UAC/registry/network mutations in ordinary tests — use fake
  adapters, temp dirs, and in-memory fixtures.
- Never log or return config contents, VLESS URIs, private keys, UUIDs, or
  passwords; use existing redaction helpers and keep paths out of errors
  where they may contain user secrets.
- Managed configs must be written only through `ConfigVault` (ACL +
  revisioning); generated Xray plaintext must go through
  `store_generated_xray` (DPAPI on Windows).
- Do not commit unless explicitly asked; do not push to `main`/`master`.

## Conventions

- Rust: serde `camelCase` models in `crates/core/src/models.rs`; errors as
  `io::Result` in core, `Result<_, String>` in commands; TDD — tests first,
  report RED/GREEN.
- Frontend: components subscribe to `route-changed` window events for
  refresh; types stay in `src/types.ts`.
- Store files are versioned documents written atomically (temp + rename)
  and ACL-protected via `config_security::protect_path`.
