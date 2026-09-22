# S0 — Linux baseline

**Spec:** `2026-09-22-02-ubuntu-completion-spec.md` §7 S0 · **Status:** done

## Goal

The app starts and is usable on Ubuntu 26.04 without showing Windows-only
features, and the Linux port is committed on `feat/linux-ubuntu-support`.

## Tasks

### 1. Commit the Linux port (done)

The previous uncommitted work (Linux build fixes, `LinuxRouteExecutor`,
`crates/linux-helper`, xray/openvpn detection) is committed on its own
after the full gate passed.

### 2. B1 — the OpenVPN route probe ignored the configured executable (done)

`probe_openvpn_routes` resolved the executable through
`state.resolve_backend_executable` and then discarded the result, calling
`resolve_openvpn_executable(None)`. It now uses the resolved path. Configured
resolution is already covered by `configured_backend_resolution_uses_persisted_path`.

### 3. `get_platform_capabilities` + UI gating (done)

- `src-tauri/src/commands/system.rs`: `PlatformCapabilities`
  (`os`, `systemProxy`, `wireguardStandardImport`, `managedXrayInstall`,
  `elevationRelaunch`, `appUpdates`, `executableExtensions`).
- `src/platform.ts`: a cached `getPlatformCapabilities()` and a
  `usePlatformCapabilities()` hook. While the capabilities are loading or if
  the query failed, the hook returns `null`, which hides every gated feature.
- Gated features:
  - system proxy block (`ProfileFormModal`);
  - "WireGuard (standard)" import tab (`ImportModal`);
  - managed Xray install (`BackendStatus`);
  - Updates section (`Settings`, spec G3).
- Found during the smoke test: the backend-executable picker filtered on
  `*.exe`, so extensionless Linux binaries could not be selected. The filter
  now comes from `executableExtensions`, and no filter is applied on Linux.
- `connect_profile` ignores `useSystemProxy` off Windows, so a profile
  imported from Windows still connects.
- TUN help text no longer says "Wintun".

**Tests (RED → GREEN):**

- `linux_capabilities_hide_windows_only_features`;
- `windows_capabilities_expose_windows_features` (`cfg(windows)`, not run
  here);
- `capabilities_serialize_with_frontend_field_names`, which pins the JSON
  contract with `src/types.ts`.

## Verification

- Full gate on Linux: `cargo fmt --check`, `clippy -D warnings`,
  `cargo test --workspace` (66 app + 213 core + 12 helper), `npm run build`.
- Manual smoke on Ubuntu 26.04 (Xvfb). The debug binary was launched and the
  window captured by the X window id of our own pid (a second, stale instance
  was running, and screenshots of it were discarded). Observed:
  - home renders;
  - Import shows only Files/Subscription;
  - Settings shows Xray auto-detected at `~/.local/bin/xray`, with no managed
    install button and no Updates section.

## Not covered (belongs to later stages)

- WireGuard still resolves `wireguard.exe` (S3).
- `ensureElevation` is a no-op on Linux because `is_elevated` returns `true`
  (replaced by `daemon_status` in S1).
- The Import "Files" hint still mentions `.conf.dpapi`.
