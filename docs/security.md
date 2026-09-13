# Security notes

## Threat model

Network Orchestrator manages VPN configurations that contain secrets
(WireGuard private keys, VLESS UUIDs, credentials) and performs privileged
system mutations (routes, interfaces, registry proxy values, child
processes). The main concerns:

- Secret exposure through files, errors, logs, UI, or crash dumps.
- Tampering with managed configs by other local users/processes.
- Stale or attacker-planted system state after crashes.
- Bugs in privileged mutations affecting unrelated OS state.

## Managed configuration vault

- Imported and generated configs are copied into
  `app_data/configs/<profile>/rev-N/` — the app never mutates external source
  files or their ACLs.
- Every managed directory and file gets an explicit protected DACL granting
  full control only to the current user SID, `SYSTEM`, and
  `Administrators` (SDDL `D:P(A;OICI;FA;;;<sid>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`).
  Inheritance is disabled; `inspect_path_protection` verifies the result via
  real `GetFileSecurityW` calls.
- Any ACL failure aborts the import/store and cleans up staged revisions.
- The vault root is hardened at app startup (`ensure_root_protected`).

## DPAPI for generated Xray configs

- `vless://` imports and generated SOCKS configs are stored as
  `config.json.dpapi`: `CryptProtectData` with
  `CRYPTPROTECT_UI_FORBIDDEN` and per-profile entropy
  (`network-orchestrator:xray:<profile-id>`).
- Decryption happens in memory only (`read_xray_config`); plaintext is fed
  to Xray via stdin and is never persisted again. Rewriting a legacy
  plaintext generated config (e.g. port reallocation) migrates it to DPAPI.
- Imported user-supplied Xray JSON stays plaintext but ACL-protected — the
  user chose an external full config.

## Plaintext constraints

- WireGuard `.conf` and OpenVPN `.ovpn` managed copies are ACL-protected but
  not encrypted — DPAPI only wraps generated Xray JSON. WireGuard private
  keys remain readable by the current user/SYSTEM/Administrators.
- The original external files are never modified; if the source is not
  protected, the managed copy is — but the source itself stays as-is.

## Redaction

- Runtime log tails shown in diagnostics pass through `redact_runtime_log`,
  which strips `vless://` URIs, UUID-shaped tokens, and values following
  `privatekey`/`password`/`token`/`authorization` (`=`/`:` separators) using
  ASCII case-insensitive byte matching that never slices transformed
  Unicode strings.
- Analysis failures surface profile name/id only — no config paths or
  contents in warnings or errors. E2E failure messages contain profile
  basenames only.

## External executable trust

- `wireguard.exe`, `openvpn.exe`, `xray.exe` (and `wg.exe` for health) are
  resolved from configured paths, install directories, or PATH and executed
  as-is. The app does not verify signatures — installing a trusted backend
  is the operator's responsibility. The Profiles tab reports resolution
  results; nothing is downloaded automatically.
- OpenVPN and Xray child processes run inside a Windows Job Object with
  `KILL_ON_JOB_CLOSE`, so a crashed app cannot orphan them.
- Xray receives its (decrypted) config via stdin, not a world-readable file.

## Privilege model

- Interface toggles, WireGuard service install, OpenVPN, and policy routes
  need administrator; the app offers an elevated restart via UAC.
- The Windows system proxy writes only to
  `HKCU\...\Internet Settings` and needs no elevation.
- The proxy ownership record (`proxy-state.json`) is ACL-protected like the
  vault.

## Known gaps

- Release artifacts are **unsigned** — no code-signing or update signing;
  SmartScreen warnings are expected.
- Tauri CSP is currently `null` (`tauri.conf.json`) — no CSP hardening yet.
- Xray health reports `Degraded` until listener/API/outbound verification
  is implemented; OpenVPN health relies on log markers, not the management
  interface.
- No `ProxyAutoConfigURL`/`AutoConfigURL` handling — only the explicit
  `ProxyServer`/`ProxyOverride`/`ProxyEnable` values are managed.
