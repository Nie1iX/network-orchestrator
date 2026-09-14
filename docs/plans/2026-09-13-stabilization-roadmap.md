# Network Orchestrator Stabilization Roadmap

**Goal:** Turn the implemented MVP-0–4 feature set into a reliable, secure, testable Windows desktop application.

**Architecture:** Keep `net-manager-core` independent from Tauri, move desktop orchestration into focused command/state modules, and treat every OS mutation as an owned transaction with durable recovery metadata. Complete reliability and security work before adding route visualization, system proxy integration, CI, and packaging.

**Tech Stack:** Rust, Windows API, Tauri 2, React 19, TypeScript, Vite

**Current status:** Stages 1–7 are implemented. Stage 8 is partially complete: documentation, Windows workflow definitions, backend prerequisite UX, and unsigned local packaging exist; the release-candidate gate is still pending. Backend executable management (persisted executable settings, verified managed Xray install/remove, Backend prerequisites UI) is implemented and locally checked. CI/CD adoption is deferred during stabilization, so local gates are currently authoritative.

---

## Execution order

1. [Tauri backend modularization](2026-09-13-01-tauri-backend-modularization.md)
2. [Crash recovery and Job Objects](2026-09-13-02-crash-recovery.md)
3. [Managed config security](2026-09-13-03-managed-config-security.md)
4. [Windows multi-tunnel E2E verification](2026-09-13-04-windows-e2e.md)
5. [Protocol health diagnostics](2026-09-13-05-protocol-diagnostics.md)
6. [Predicted/effective route map](2026-09-13-06-route-map.md)
7. [Optional Xray Windows system proxy](2026-09-13-07-system-proxy.md)
8. [Documentation, CI, packaging, release](2026-09-13-08-release-readiness.md)
9. [Backend executable management](2026-09-13-09-backend-management.md)

## Invariants

- Never log or serialize private keys, passwords, VLESS URLs, or credential-file contents.
- Never mutate a route, proxy setting, service, process, or config without durable ownership metadata.
- Preserve Windows longest-prefix-match behavior; nested routes are composable, exact duplicates are conflicts.
- Existing external VPN processes are not adopted or terminated without verified ownership.
- Every behavior change follows RED → GREEN → REFACTOR.
- Real network mutation tests run only in an isolated Windows VM with explicit operator approval.

## Global quality gate

Run after every stage:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
npm run build
npm audit --audit-level=high
git diff --check
```

## Target completion criteria (not fully verified)

- Normal exit leaves no app-owned tunnels, routes, proxy settings, or child processes.
- Crash recovery identifies and resolves all durable app-owned state.
- Managed secrets have explicit Windows ACLs; encryptable secrets use DPAPI.
- Diagnostics distinguish process/service state from actual protocol health.
- Predicted route decisions match the effective Windows route table after connect.
- Local quality gates pass; packaged artifacts pass a VM smoke test. CI/CD can be adopted after stabilization.

## Verification still pending

- Disposable-Windows-VM E2E with real WireGuard, OpenVPN, and Xray fixtures.
- Packaged NSIS install, launch, shutdown, and uninstall smoke testing.
- Forced-crash recovery drills for child processes, owned routes, WireGuard services, and system proxy state.
- Release artifact secret scan and code signing.
