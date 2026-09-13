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
