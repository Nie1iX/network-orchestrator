# Crash Recovery and Job Objects Implementation Plan

**Goal:** Ensure app-owned OpenVPN/Xray processes, WireGuard services, routes, and runtime state are recoverable after crashes or forced termination.

**Architecture:** Put child processes in a Windows Job Object with kill-on-close, persist a versioned runtime ownership registry, and reconcile the registry against SCM, interfaces, and the route table at startup. The Job Object is the crash-containment guarantee for OpenVPN/Xray; there is deliberately no PID-based process adoption because PID reuse makes it unsafe. WireGuard services, profiles, and routes still reconcile via durable service/profile/route metadata. Never adopt an unverified external process.

**Tech Stack:** Rust, Windows Job Objects, Toolhelp/Process APIs, Windows SCM, Tauri 2

---

### Task 1: Add runtime ownership models

**Files:**
- Modify: `crates/core/src/models.rs`
- Create: `crates/core/src/runtime_state.rs`

Persist backend, profile ID, WireGuard service name, owned routes, and cleanup status in a versioned atomic document. No PID/executable-path/creation-time adoption metadata is stored for OpenVPN/Xray children — the Job Object guarantees they die with the manager, so there is nothing to adopt. Tests cover malformed versions and registry metadata.

### Task 2: Add Windows Job Object wrapper

**Files:**
- Create: `crates/core/src/windows_job.rs`
- Modify: `crates/core/Cargo.toml`
- Modify: `crates/core/src/vpn.rs`

Use `CreateJobObjectW`, `SetInformationJobObject` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and `AssignProcessToJobObject`. Assign every OpenVPN/Xray child immediately after spawn; kill the child if assignment fails.

### Task 3: Reconcile without PID adoption

OpenVPN/Xray children are never re-adopted from persisted process identifiers: PID reuse makes identity claims unsafe, and the Job Object kill-on-close guarantee makes adoption unnecessary — a crashed manager's children are already dead. WireGuard tunnel services and owned routes still reconcile against durable metadata (service name, profile ID, route records). Stale or unverifiable records are reported in the `RecoveryReport`, not acted on.

### Task 4: Reconcile at startup

Produce a `RecoveryReport` containing:

- verified app-owned resources;
- already-gone resources;
- stale routes;
- mismatched/unverified processes;
- cleanup actions requiring elevation.

Never remove resources during discovery. Present recovery choices first.

### Task 5: Apply recovery actions

Support explicit actions: clean stale resources, leave unchanged, or forget missing ownership records. Persist after each successful mutation.

### Task 6: Test forced termination

Create ignored Windows VM integration tests that launch harmless sleeper children in the Job Object, terminate the parent, and verify children exit. Simulate stale and missing-route registries without touching real VPNs.

### Validation

```bash
cargo test -p net-manager-core runtime_state
cargo test -p net-manager-core windows_job
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
