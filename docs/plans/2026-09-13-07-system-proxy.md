# Optional Xray Windows System Proxy Implementation Plan

**Goal:** Allow a generated Xray SOCKS/HTTP profile to opt into Windows system proxy configuration with reliable restoration.

**Architecture:** Treat proxy settings as another durable owned transaction. Snapshot the exact previous user settings, apply only after Xray listener health is confirmed, and restore on disconnect, shutdown, or recovery.

**Tech Stack:** Rust, Windows Internet Settings registry/API, Tauri 2, React

---

### Task 1: Add proxy-state models and store

Persist previous/current proxy values, owner profile ID, bypass list, timestamp, and apply phase in a versioned atomic document.

### Task 2: Implement Windows proxy adapter

Read/write current-user Internet Settings, broadcast `WM_SETTINGCHANGE`, and verify the effective values after mutation. Keep WinHTTP settings separate and unchanged unless explicitly requested later.

### Task 3: Add transactional ownership

Reject activation when another profile owns system proxy. On partial failure restore the snapshot. Make restore idempotent and crash-recoverable.

### Task 4: Integrate Xray lifecycle

Wait for the generated local listener to bind before applying system proxy. Restore proxy before stopping Xray. Never apply for existing JSON unless the user explicitly enables it.

### Task 5: Add UI controls

Add `Use Windows system proxy`, bypass-list editor, current owner display, elevation explanation if required, and recovery notice.

### Task 6: Test in VM

Verify apply/restore, pre-existing proxy preservation, crash recovery, port reallocation, two-profile ownership conflict, and apps that ignore system proxy.

### Validation

```bash
cargo test -p net-manager-core system_proxy
cargo test -p net-manager-app system_proxy
npm run build
```

---

## Implemented notes (stage 7)

- `Profile` gained `use_system_proxy` / `proxy_bypass` (`#[serde(default)]`); validation: Xray only, requires nonzero `xray_socks_port`, bypass entries nonblank and `;`-free.
- Core `system_proxy`: `ProxySnapshot`/`ProxyOwnership`/`ProxyStateDocument` (versioned atomic JSON at `data_dir/proxy-state.json`), `ProxyAdapter` trait, `SystemProxyManager`. Apply persists ownership **before** the adapter call, applies `socks=127.0.0.1:<port>` + `;`-joined bypass, and rolls back snapshot + clears ownership on adapter failure (combined error). `restore` requires matching owner (NotFound/InvalidInput otherwise); `restore_any` is idempotent for shutdown/recovery.
- Windows adapter: HKCU `Internet Settings` via `RegGetValueW`/`RegSetValueExW`/`RegDeleteValueW` (missing values deleted on restore), `WM_SETTINGCHANGE` broadcast via `SendMessageTimeoutW`. Non-Windows adapter returns `Unsupported`. No real-HKCU tests — fake adapter only.
- Connect flow: ownership pre-check blocks a second system-proxy profile; after Xray connect, bounded poll (10 s / 200 ms) on `127.0.0.1:<socks>`; listener timeout or proxy-apply failure disconnects; route-apply failures restore proxy before disconnect.
- Disconnect restores proxy before routes/tunnel and aborts on restore failure (Xray stays up). `cleanup_all` runs `restore_any` first. Recovery report surfaces `proxyOwnership`; diagnostics adds a `System proxy` check (healthy owner+running, warning configured-not-applied, error stale/other owner).
- UI: `Use Windows system proxy` checkbox for generated Xray profiles (VLESS import or existing with SOCKS port), comma-separated bypass editor with `<local>, localhost, 127.*, 10.*, 192.168.*` default, `System proxy` badge + bypass row on the card, disabled-with-explanation for plain imported JSON.
- Review fixes: `WM_SETTINGCHANGE` broadcast passes lParam = pointer to the UTF-16 `Internet Settings` subkey string; proxy-state file is `protect_path`-ed on temp write, after rename, and for legacy files on load; Windows adapter verifies values via registry read-back before broadcast (`snapshot_matches`, generic mismatch errors without proxy values).
- Not implemented (follow-up): WinHTTP/winhttp settings untouched; real-VM validation (Task 6) pending fixtures.
