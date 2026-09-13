# Protocol Health Diagnostics Implementation Plan

**Goal:** Distinguish a running process/service from a healthy VPN session and expose actionable, redacted diagnostics.

**Architecture:** Implement one backend-specific health adapter per protocol and normalize results into diagnostic checks. Persist bounded redacted logs in AppData and never infer handshake success from process existence.

**Tech Stack:** Rust, WireGuard `wg.exe`, OpenVPN management interface, Xray logs/API, React

---

### Task 1: Add diagnostic health models

Represent connecting, healthy, degraded, authentication failure, endpoint failure, and unknown states with timestamps and redacted evidence.

### Task 2: WireGuard health

Query `wg show <interface> latest-handshakes`, transfer, and endpoints. Treat a recent handshake as healthy; no handshake as warning/error based on elapsed time. Redact public endpoint policy where configured.

### Task 3: OpenVPN health

Allocate a private localhost management port, authenticate it, and parse `state`, `status`, `AUTH_FAILED`, assigned address, and reconnect events. Do not expose management passwords.

### Task 4: Xray health

Capture bounded stdout/stderr logs, verify expected listeners are bound, and optionally query configured API/stats when present. Report outbound startup failures without config content.

### Task 5: Add endpoint probes

Only after an explicit Diagnostics action, perform bounded DNS/TCP probes where meaningful. Do not probe WireGuard UDP handshake by TCP.

### Task 6: Add UI timeline

Show current health, last transition, last handshake, assigned addresses, traffic counters, and a redacted log tail with Copy diagnostics.

### Validation

```bash
cargo test -p net-manager-core diagnostics
cargo test -p net-manager-app diagnostics
npm run build
```
