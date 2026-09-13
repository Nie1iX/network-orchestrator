# Tauri Backend Modularization Implementation Plan

**Goal:** Split the monolithic Tauri backend into focused modules without changing serialized commands or runtime behavior.

**Architecture:** Keep `lib.rs` as composition root only. Move state, profile storage/import, tunnel orchestration, diagnostics, lifecycle cleanup, and explorer commands into modules that share `AppState` through crate-visible APIs.

**Tech Stack:** Rust, Tauri 2, Tokio

---

### Task 1: Capture the public command contract

**Files:**
- Create: `src-tauri/src/commands/mod.rs`
- Test: `src-tauri/src/lib.rs`

1. Add a test-only list of expected command names.
2. Run `cargo test -p net-manager-app --lib` and verify RED before exporting the list.
3. Preserve every current command name and camelCase payload contract.

### Task 2: Extract application state

**Files:**
- Create: `src-tauri/src/state.rs`
- Modify: `src-tauri/src/lib.rs`

Move `AppState`, `RuntimeState`, path initialization, route-registry restoration, and atomics into `state.rs`. Expose one constructor:

```rust
pub(crate) fn build_state(data_dir: &Path) -> Result<AppState, String>;
```

Verify existing state-helper tests remain green.

### Task 3: Extract command modules

**Files:**
- Create: `src-tauri/src/commands/explorer.rs`
- Create: `src-tauri/src/commands/profiles.rs`
- Create: `src-tauri/src/commands/tunnels.rs`
- Create: `src-tauri/src/commands/diagnostics.rs`
- Modify: `src-tauri/src/lib.rs`

Move functions without changing signatures. Use `pub(crate)` only for command registration and shared helpers.

### Task 4: Extract lifecycle and elevation

**Files:**
- Create: `src-tauri/src/lifecycle.rs`
- Modify: `src-tauri/src/elevation.rs`
- Modify: `src-tauri/src/lib.rs`

Move stale-route cleanup, graceful shutdown, close-event handling, and elevated-restart coordination into `lifecycle.rs`.

### Task 5: Reduce composition root

`src-tauri/src/lib.rs` should contain module declarations, plugin setup, state registration, command registration, watcher startup, and event-loop wiring only. Target fewer than 180 lines.

### Validation

```bash
cargo test -p net-manager-app --lib
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
npm run build
```

Expected: the same command set, 140+ tests green, and no user-visible behavior changes.
