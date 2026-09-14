# Backend Executable Management Implementation Plan

**Goal:** Let users select persistent WireGuard/OpenVPN/Xray executables and optionally install a verified, app-managed Xray distribution.

**Architecture:** Store versioned backend settings under app data and feed the same resolved paths into availability, diagnostics, and `TunnelManager`. Keep network download in the Tauri shell; keep archive verification and transactional extraction in `net-manager-core`. Managed Xray versions are immutable directories, so a failed download/install/settings update never replaces the currently selected executable.

**Tech Stack:** Rust, Tauri 2, React 19, `reqwest`, `sha2`, `zip`, Windows protected ACLs

---

## Fixed managed artifact

- Version: `v26.7.28`
- Asset: `Xray-windows-64.zip`
- URL: `https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-windows-64.zip`
- SHA-256: `c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1`
- Maximum compressed download: 64 MiB
- Extracted allowlist: `xray.exe`, `geoip.dat`, `geosite.dat`, `LICENSE`, `README.md`
- Required files: `xray.exe`, `geoip.dat`, `geosite.dat`

Only the x86-64 Windows application target supports this pinned artifact. Other targets return `Unsupported` rather than downloading a mismatched binary.

## Task 1: Persistent backend settings

**Files:**
- Create: `crates/core/src/backend_settings.rs`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/src/models.rs`
- Modify: `crates/core/src/vpn.rs`
- Modify: `src-tauri/src/state.rs`

Define camelCase-serialized `BackendExecutableSource` (`autoDetected`, `configured`, `managed`), `BackendExecutableSetting { path, source, version }`, and version-1 `BackendSettingsDocument` with nullable `wireGuard`, `openVpn`, and `xray` settings. `autoDetected` is response-only and must be rejected in persisted settings.

`BackendSettingsStore` must load a default document when absent, reject unsupported versions, and save through a protected `.tmp` file followed by atomic rename and final ACL protection. Add typed get/set helpers by `TunnelBackend`.

Add an infallible `TunnelManager::set_executable(backend, Option<PathBuf>)` and construct the manager at startup from persisted settings while preserving the log directory.

**TDD cases:** missing document defaults; round-trip for all backends; unsupported version rejected; response-only source rejected; temp/final ACL protection on Windows; manager setter changes the resolver input.

## Task 2: Verified managed Xray extraction

**Files:**
- Create: `crates/core/src/managed_xray.rs`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/Cargo.toml`

Use `sha2 = 0.10.9` and stable `zip = 6.0.0` with only the deflate feature. Verify the complete archive before opening it. Extract only exact root-level allowlisted names, reject duplicate entries, enforce per-file and total uncompressed size limits, and require the three runtime files.

Extract into a protected staging directory under `app_data/backends/xray/`, protect every file, then atomically rename to immutable `v26.7.28`. If that final directory already contains all required files, return it unchanged. On every failure remove only the staging directory created by the current operation.

**TDD cases:** valid synthetic archive installs; wrong hash leaves no version; traversal/unknown entries are not written; missing/duplicate required entry fails; oversized metadata fails; existing complete version is idempotent.

## Task 3: Tauri backend commands

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/state.rs`
- Modify: `src-tauri/src/commands/system.rs`
- Modify: `src-tauri/src/commands/diagnostics.rs`
- Modify: `src-tauri/src/lib.rs`

Add direct `reqwest = 0.13.5` and `futures-util = 0.3` dependencies. Add a single-install mutex and cancellation flag to `AppState`.

Commands:

```text
get_backend_availability
set_backend_executable(backend, path)
reset_backend_executable(backend)
install_managed_xray
cancel_managed_xray_install
remove_managed_xray
```

All path changes must hold the runtime mutex, reject changes while a profile using that backend is running, persist settings, and update `TunnelManager`. Availability and diagnostics must resolve through the persisted setting, never a separate `None` path.

The managed installer must stream with a 64 MiB hard limit, reject non-success responses and mismatched `Content-Length`, emit `backend-install-progress` events, honor cancellation between chunks, verify/extract in a blocking task, run `xray.exe version` with a bounded timeout, then select the managed setting. A failed operation leaves the previous setting selected.

Managed removal must be explicit, reject a running Xray profile, and delete only a path proven to be inside the app-owned managed Xray root. External configured executables are never deleted.

**TDD cases:** availability source selection; configured missing path; active-backend mutation rejection; cancellation/size helper behavior; managed-path containment; diagnostics uses configured path.

## Task 4: Backend management UI

**Files:**
- Modify: `src/types.ts`
- Modify: `src/components/BackendStatus.tsx`
- Modify: `src/App.css`
- Modify: `src-tauri/capabilities/default.json`

For every backend provide `Choose existing…` through the Tauri dialog plugin and `Reset to auto-detect`. For Xray also provide `Install managed`, progress, cancel, and confirmed `Remove managed`. Display source, path, managed version, and errors. WireGuard/OpenVPN remain user-installed because their official packages include services/drivers; do not implement a portable downloader for them.

Disable conflicting buttons while an operation is running and refresh availability after every successful mutation.

**Verification:** `npm run build` and manual packaged-app smoke of picker, reset, cancellation, install, and removal without connecting a tunnel.

## Task 5: Documentation and gates

**Files:**
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/plans/2026-09-13-stabilization-roadmap.md`

Document custom paths, the pinned managed Xray source/hash, app-data location, explicit consent, no silent updates, and why WireGuard/OpenVPN remain external installations.

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
npm run build
npm audit --audit-level=high
git diff --check
npm run tauri build -- --bundles nsis
```

Do not run ignored Windows E2E tests, install the managed backend into real app data, connect tunnels, commit, or push without a separate explicit request.
