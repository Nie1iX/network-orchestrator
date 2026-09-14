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
  as-is. The app does not signature-verify configured or auto-detected
  executables — selecting a trusted backend is the operator's
  responsibility. The Profiles tab reports resolution results.
- Managed Xray is the single exception: it is installed only on explicit
  user action from the fixed official v26.7.28 release URL shown in the
  confirmation dialog. The compressed archive is checked against pinned
  SHA-256
  `c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1`;
  required extracted files (`xray.exe`, `geoip.dat`, `geosite.dat`) are
  individually hash-verified; extraction is limited to a strict root-level
  allowlist with bounded compressed/uncompressed sizes; the versioned
  directory under app data is ACL-protected; the installed binary is
  validated with `xray version`; and integrity is rechecked before
  diagnostics and connect. There is no silent or automatic download/update.
- WireGuard and OpenVPN are not managed-downloaded because their installers
  carry drivers and services.
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
