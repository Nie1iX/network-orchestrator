# Documentation, CI, Packaging, and Release Plan

**Goal:** Produce a reproducible Windows release with accurate documentation and automated quality gates.

**Architecture:** Make CI run the same checks as local development, package Tauri artifacts on Windows, and gate release publication on unit, static, security, and VM smoke evidence.

**Tech Stack:** GitHub Actions, Rust, npm, Tauri 2, Windows runner

---

### Task 1: Update documentation

**Files:**
- Modify: `README.md`
- Modify: `analysis.md`
- Create: `docs/security.md`
- Create: `docs/recovery.md`
- Create: `docs/testing.md`

Document MVP-0–4, prerequisites, managed vault, admin behavior, lifecycle, route composition, Xray SOCKS/system proxy limitations, and recovery.

### Task 2: Add repository guidance

Create/update `AGENTS.md` with exact setup, test, lint, build, safe E2E, and release commands learned during implementation.

### Task 3: Add Windows CI

Create `.github/workflows/ci.yml` running formatting, clippy with warnings denied, workspace tests, frontend build, and npm high-severity audit. Pin action versions and use dependency caching.

### Task 4: Add packaging workflow

Create a signed-ready Tauri bundle workflow that produces MSI/NSIS artifacts without publishing. Validate bundled capabilities and required WebView2 behavior.

### Task 5: Add backend prerequisite UX

At startup report whether WireGuard, OpenVPN, and Xray executables are installed. Provide verified download/documentation links or configurable executable paths; do not download executables silently.

### Task 6: Run release candidate gate

Run all local gates, CI, packaged-app smoke, Windows VM E2E, secret scan, config ACL verification, crash recovery, and clean uninstall checks.

### Validation

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm run build
npm audit --audit-level=high
npm run tauri build
```

Release only when the worktree is clean and all required artifacts/results are recorded.
