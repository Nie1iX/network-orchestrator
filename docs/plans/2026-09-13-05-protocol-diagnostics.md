# Protocol Health Diagnostics Implementation Plan

**Goal:** Distinguish a running process/service from a healthy VPN session and expose actionable, redacted diagnostics.

**Architecture:** Implement one backend-specific health adapter per protocol and normalize results into diagnostic checks. Persist bounded redacted logs in AppData and never infer handshake success from process existence.

**Tech Stack:** Rust, WireGuard `wg.exe`, OpenVPN management interface, Xray logs/API, React

---

### Task 1: Add diagnostic health models

Represent connecting, healthy, degraded, authentication failure, endpoint failure, and unknown states with timestamps and redacted evidence.

Implemented: `ProtocolHealth`/`ProtocolHealthState` (`unknown`/`healthy`/`degraded`/`failed`) carry summary, `last_handshake_unix`, rx/tx counters, and a redacted `log_tail`. `diagnose_profile` adds `Protocol health` and `Runtime log` checks; `redact_runtime_log` strips `vless://` URIs, UUID-shaped tokens, and `privatekey`/`password`/`token`/`authorization` values.

### Task 2: WireGuard health

Query `wg show <interface> latest-handshakes`, transfer, and endpoints. Treat a recent handshake as healthy; no handshake as warning/error based on elapsed time. Redact public endpoint policy where configured.

Implemented: running services are queried via `wg.exe show <tunnel> dump` (wg.exe resolved next to wireguard.exe, then `%ProgramFiles%\WireGuard`, then PATH). The dump parser takes peer fields 4/5/6 (latest handshake max, rx/tx saturated sums) and never echoes keys or endpoints; handshake >0 is Healthy, all-zero is Degraded, query failure is Degraded with an actionable summary.

### Task 3: OpenVPN health

Allocate a private localhost management port, authenticate it, and parse `state`, `status`, `AUTH_FAILED`, assigned address, and reconnect events. Do not expose management passwords.

Implemented (log-based, not management API): OpenVPN children write `<safe>-openvpn.log` under the ACL-protected `logs` dir. `Initialization Sequence Completed` maps to Healthy, `AUTH_FAILED` to Failed (priority over the success marker), otherwise Running is Degraded (`process running; connection not confirmed`). The management-interface probe remains a follow-up.

### Task 4: Xray health

Capture bounded stdout/stderr logs, verify expected listeners are bound, and optionally query configured API/stats when present. Report outbound startup failures without config content.

Implemented (log-based): Xray children write `<safe>-xray.log` under the protected `logs` dir; Running reports Degraded with `process running; outbound connectivity is not handshake-verified` until listener/API verification exists, Failed includes the redacted per-backend tail. Listener-bind verification and Xray API endpoint probes remain a follow-up.

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
