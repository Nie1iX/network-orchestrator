# Managed Config Security Implementation Plan

**Goal:** Protect managed VPN credentials at rest and enforce explicit Windows access controls.

**Architecture:** Apply a private DACL to the vault root and every revision, encrypt data that can be supplied through memory with DPAPI, and retain plaintext only where external backends require a filesystem path. Security diagnostics report the protection level without exposing content.

**Tech Stack:** Rust, Windows ACL APIs, DPAPI, WireGuard `.conf.dpapi`, Tauri 2

---

### Task 1: Add ACL abstraction

**Files:**
- Create: `crates/core/src/config_security.rs`
- Modify: `crates/core/src/config_vault.rs`
- Modify: `crates/core/Cargo.toml`

Create an explicit protected DACL granting full access only to the current user, `SYSTEM`, and administrators. Apply it to vault/profile/revision/assets and verify effective ACLs in unit/integration tests.

Implemented: `protect_path` applies `D:P(A;OICI;FA;;;<user-sid>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` on directories and the same ACEs without `OICI` on files, via `SetFileSecurityW` with `PROTECTED_DACL_SECURITY_INFORMATION` so inherited ACEs are dropped. `inspect_path_protection` verifies `SE_DACL_PROTECTED` via `GetSecurityDescriptorControl` and the three full-access ACEs via SDDL conversion — never trusted from desired input. `ConfigVault` protects root/profile/staging/assets/revision/config at every import/store and `ensure_root_protected` hardens the vault root at startup without rewriting existing revisions; post-rename protection failure removes the renamed revision. External source files are never modified.

### Task 2: Add DPAPI envelope

Implement versioned `CryptProtectData`/`CryptUnprotectData` helpers with profile-scoped entropy. Tests cover round-trip, wrong entropy, corrupt blobs, and secret-free errors.

### Task 3: Encrypt generated VLESS source

Store generated VLESS material as DPAPI data. Decrypt only in memory, generate Xray JSON, and pass it through `stdin:`. Do not persist derived plaintext.

### Task 4: Support WireGuard DPAPI configs

Convert imported plaintext WireGuard configs to the `.conf.dpapi` format accepted by the official tunnel service. Preserve already encrypted imports without decrypting them.

### Task 5: Harden OpenVPN assets

OpenVPN requires readable files. Keep its managed bundle plaintext but under the protected DACL. Reject symlinks/reparse points and warn about executable script/plugin directives.

### Task 6: Add security diagnostics

Report: ACL healthy/error, DPAPI/plaintext storage, external config, executable content, and inaccessible referenced assets. Never include secret values.

### Validation

```bash
cargo test -p net-manager-core config_security
cargo test -p net-manager-core config_vault
cargo clippy --workspace --all-targets -- -D warnings
npm run build
```
