# Linux Policy-Route Backend Implementation Plan

**Goal:** Let the app apply/remove policy routes (IP-based routing) and run
Xray/OpenVPN tunnels on Linux, matching the trait-based adapter architecture
already used for Windows. WireGuard tunnel management and the Windows system
proxy feature are explicitly out of scope for this plan (see Scope below).

**Architecture:** Unchanged from the existing design — `RouteExecutor`
(`crates/core/src/policy.rs`) already separates route mutation behind a
trait with per-OS implementations (`WindowsRouteExecutor` /
`LinuxRouteExecutor` / `UnsupportedRouteExecutor`). The app itself never
runs elevated on Linux. Route mutations go through a narrow privileged
helper (`crates/linux-helper`, invoked via `pkexec`), authorized by a
`polkit` action scoped to exactly that one binary path
(`crates/linux-helper/resources/com.netmanager.app.linux-helper.policy`),
cached ~5 minutes per session (`auth_admin_keep`) so a connect/disconnect
cycle only prompts once. This mirrors `happd`'s "privileged work already
running as root" pattern, but as a per-call helper rather than a persistent
daemon, since routes are the only thing that needs root on Linux today.

**Tech Stack:** Rust, `libc` (`if_indextoname`), `ipnet`, `pkexec`/`polkit`,
`ip route` (iproute2).

## Scope decisions (made with the project owner, 2026-09-22)

- **System proxy (Windows registry-based) is dropped, not ported.** There is
  no Linux/Wayland equivalent every app respects (GNOME has gsettings, KDE
  has kioslaverc, Hyprland has neither); the owner's actual requirement is
  correct IP/domain routing, which policy routes + Xray's own routing config
  already cover without it.
- **Elevation uses a privileged helper, not a whole-GUI `pkexec` relaunch.**
  Decided explicitly after live-debugging a real-world example of the
  opposite failure mode: an AUR-packaged VPN client (`incy-bin`) whose polkit
  policy authorized a different path than the one it actually invoked,
  silently falling back to unathenticated-every-time `pkexec` prompts. The
  lesson applied here: the policy's `exec.path` annotation and the actual
  invoked path are kept in lockstep by
  `scripts/install-linux-helper-dev.sh`, and the whole pipeline was smoke-
  tested live (see Verification) rather than assumed correct from reading
  the code.
- **WireGuard Linux tunnel management is deferred**, not attempted here.
  Xray (domain + IP routing) and OpenVPN already ran on Linux with zero
  platform-specific connect/disconnect code once policy routes worked — see
  Task 1 finding — which covers the owner's stated need ("route by IP and
  domain") without touching `vpn.rs`'s much larger WireGuard surface
  (Windows service install/uninstall via `wireguard.exe`, no Linux
  equivalent implemented). A future plan can pick this up separately.

## Task 0: Get the workspace compiling and green on Linux (prerequisite, done)

The pulled Windows-developed code had never been compiled on Linux. Fixed
three pre-existing bugs blocking any Linux build, unrelated to this plan's
feature work but required before anything else could proceed:

- `explorer.rs`: `kind` (non-`Copy`) was moved into a struct literal, then
  borrowed again later in the same literal for `category`. Fixed by
  computing `category` before the literal.
- `explorer.rs`: `Path::new(&format!(...))` — the `format!` temporary was
  dropped before the resulting `&Path` was used. Fixed by passing the
  `String` directly to `read_link` (`impl AsRef<Path>`), matching the
  sibling functions in the same file.
- `config_security.rs`: the non-Windows `read_with_backup_semantics`/
  `protect_machine_data` were defined outside the `imp` module the blanket
  `pub use imp::{...}` re-export expects them from. Fixed by moving them
  in, and, since this module was being touched anyway, replaced the
  previously no-op `protect_path`/`inspect_path_protection` stubs with a
  real Unix implementation (`chmod 600` files / `700` dirs — the closest
  analogue of a Windows protected-DACL-owner-only file).

Also fixed 5 pre-existing test failures (Windows-style `C:\...` path
literals don't parse the way the tests assumed under Unix path semantics —
`file_name()`/`std::path::absolute()` behave differently) by making the
shared test fixtures platform-conditional (`sample_absolute_path` helper)
instead of Windows-only literals, and cleared all clippy warnings that were
only latent because the crate had never been linted for the `linux` target.

**Verification:** `cargo fmt -p net-manager-core -- --check`,
`cargo clippy -p net-manager-core --all-targets -- -D warnings`,
`cargo test -p net-manager-core` — 213 passed, 0 failed.

## Task 1: `LinuxRouteExecutor` (done)

**Files:**
- Created: `crates/linux-helper/` (new workspace member — `Cargo.toml`,
  `src/lib.rs`, `src/main.rs`, `resources/com.netmanager.app.linux-helper.policy`)
- Created: `scripts/install-linux-helper-dev.sh`
- Modified: `crates/core/src/policy.rs` (`LinuxRouteExecutor`,
  `resolve_linux_helper_path`, `interface_name_for_index`,
  `PolicyManager::new()` platform selection, narrowed
  `UnsupportedRouteExecutor` to non-Windows-non-Linux)
- Modified: `Cargo.toml` (workspace members)

`crates/linux-helper` is a small, separately-authorized binary: two verbs
(`route-add`, `route-del`), each argument validated before ever touching a
process spawn (CIDR via `ipnet`, interface name against Linux's `IFNAMSIZ`
and a conservative charset, metric as `u32`), then shells out to `ip route
replace|del ... dev <iface> metric <n>` with an explicit argv — never a
shell string, so there is no injection surface independent of the
validation. `LinuxRouteExecutor` resolves the interface name from
`AppliedRoute.interface_index` via `libc::if_indextoname` (the trait only
carries the index), then invokes the helper through `pkexec`.

**TDD cases:** helper argv/validation is fully unit-tested as pure
functions (12 tests in `crates/linux-helper`); `LinuxRouteExecutor`'s
`helper_args` building and `interface_name_for_index` (using loopback,
index 1, which is a read-only libc call safe to run for real) are unit-
tested in `policy.rs`. The actual `pkexec`/`ip` invocation is deliberately
*not* unit-tested — like `WindowsRouteExecutor`, it mutates real system
state and would either need root or risk popping a real auth dialog during
`cargo test`.

**Verification (live, not just unit tests):** built the release helper,
installed it and the policy via `scripts/install-linux-helper-dev.sh`'s
steps, then ran the actual pipeline end to end: `pkexec linux-helper
route-add 192.0.2.0/24 lo 0` (TEST-NET-1, RFC 5737 — safe, documentation-
only range), confirmed the route existed in the real kernel table
(`ip route show`), then `route-del` and confirmed it was gone. The second
`pkexec` call went through without a fresh password prompt, confirming
`auth_admin_keep` caching is working — i.e. the policy's `exec.path`
matches what the app actually invokes (the specific failure mode found
and diagnosed in `incy-bin` earlier the same day).

## Task 2: Xray/OpenVPN executable auto-detection on Linux (done)

**Files:** Modified: `crates/core/src/vpn.rs`

`resolve_xray_executable`/`resolve_openvpn_executable` hardcoded
`"xray.exe"`/`"openvpn.exe"` as the filename to search `PATH` for, and had
empty standard-paths lists on non-Windows — so even with `xray`/`openvpn`
correctly on `PATH`, Linux auto-detection always failed (only a manually
configured path worked, and only by accident, not by design). Added
platform-conditional exe-name constants (`xray`/`openvpn`, no extension)
and Linux standard paths (`/usr/bin`, `/usr/local/bin`, plus `/opt/xray/xray`
for Xray).

Xray and OpenVPN connect/disconnect in `vpn.rs` needed **no other changes**
— `TunnelBackend::OpenVpn`/`TunnelBackend::Xray` in `TunnelManager::connect`/
`disconnect` already spawn via plain `std::process::Command`, with only a
cosmetic `#[cfg(windows)] creation_flags(CREATE_NO_WINDOW)` skipped
harmlessly elsewhere. `windows_job.rs`'s Linux fallback (`ChildJob` as a
no-op) already compiles and runs; child processes just don't get the
Windows Job Object "kill on app crash" safety net on Linux yet (acceptable
gap, not attempted here — see Follow-ups).

**TDD cases:** `linux_standard_paths_use_unsuffixed_binary_names` (both
lists return bare `xray`/`openvpn`, no `.exe`).

## Follow-ups (not done, explicitly deferred)

- **Wiring into the Tauri app / UI.** `src-tauri` needs system libraries
  this machine doesn't have yet (`webkit2gtk`, `gtk3`, `librsvg`,
  `libayatana-appindicator`, `dbus`, `libsoup`) before it will even
  `cargo check`. Once installed, `src-tauri/src/commands/{tunnels,profiles,
  system}.rs` need auditing for any remaining `#[cfg(windows)]` gates that
  block the Linux paths now that the core crate supports them (a first pass
  found none blocking policy routes or Xray/OpenVPN specifically, but this
  needs verifying against a real compile, not just a read-through).
- **Child process containment on Linux** (`windows_job.rs`'s `ChildJob`):
  currently a no-op on Linux, so an Xray/OpenVPN child survives if the app
  crashes, unlike on Windows. `setsid` + process-group kill, or
  `prctl(PR_SET_PDEATHSIG)`, would close this gap — small, not attempted
  here since it wasn't blocking anything.
- **WireGuard on Linux** — see Scope decisions above. A real chunk of work
  (`wg-quick`/netlink instead of the Windows service model); deliberately
  out of scope for "route by IP and domain."
- **Real Linux packaging** (deb/rpm/AUR) would replace
  `scripts/install-linux-helper-dev.sh`'s manual `sudo install` steps with
  proper package-managed installation of the helper + policy at the same
  fixed paths — nothing else changes.

## Gate run for what's in scope here

```bash
cargo fmt -p net-manager-core -- --check
cargo fmt -p network-orchestrator-linux-helper -- --check
cargo clippy -p net-manager-core --all-targets -- -D warnings
cargo clippy -p network-orchestrator-linux-helper --all-targets -- -D warnings
cargo test -p net-manager-core
cargo test -p network-orchestrator-linux-helper
```

`cargo check --workspace` / `npm run build` were not run — `src-tauri`
needs the system libraries above first. Did not commit or push (per
`AGENTS.md`, explicit request only).
