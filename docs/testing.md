# E2E testing

## Browser sandbox on macOS

```bash
npm run dev:sandbox
# Open http://localhost:1422 in a browser.
npm run test:sandbox
```

The sandbox uses synthetic WireGuard, OpenVPN, Xray subscription, and static
route profiles. All IPC calls are intercepted by Tauri's mock transport and
handled in memory. There is no native-command fallback, VPN process, file
import, subscription HTTP request, keyring write, OS route, DNS, or proxy
mutation. Unknown commands, interface changes, elevation, backend installation,
and process restart are rejected. The installer refuses to run in a native
Tauri window. Production builds exclude the sandbox.

The green banner identifies this mode. Reload resets the synthetic backend;
connection snippets use this browser origin's localStorage and survive reload.
File dialogs and confirmations return synthetic choices. Subscription delays,
config analysis, conflicts, and traffic counters are fixtures. IPv4 lookup is
simulated; IPv6 parsing, bulk CIDR parsing, OpenVPN probes, and real config
generation are covered by Rust tests instead. Do not use sandbox results as
evidence that real VPN credentials or connectivity work.

## Local verification record — 2026-09-30

The app was launched on macOS with an isolated QA application identifier.
Browser checks used the sandbox above. Real Linux network checks used disposable
ARM64 Ubuntu containers in a separate Docker bridge with no published ports,
host networking, Docker socket mount, or user VPN files. WireGuard keys and
OpenVPN certificates/credentials were generated for the test peers. The initial
internal-only bridge prevented the full-tunnel underlay probe; the successful
run used the private bridge arrangement from the existing E2E contract.

This was a review of the main paths across core, daemon, Tauri commands, and
React, backed by tests and UI checks. It is not an exhaustive proof that every
line or every platform-specific path is correct.

| Area | Verification | Result |
| --- | --- | --- |
| macOS workspace | fmt, all-target check, strict clippy, workspace tests | 459 Rust tests passed |
| Linux x86_64 core + daemon | Docker Rust tests, daemon release build | 539 tests passed, including doc tests |
| Linux ARM64 core + daemon | fmt, strict all-target clippy, Rust tests | 530 tests passed, including doc tests |
| Frontend | TypeScript + production Vite build; pure sandbox tests | build passed; 6 tests passed; sandbox absent from dist |
| Native macOS shell | Tauri dev startup with QA identifier | launched; real host VPN connections were not attempted |
| Profiles UI | create static route, edit WireGuard, import file/subscription, delete, search/group controls | synthetic data only; passed |
| Connection UI | four concurrent backends, OpenVPN credential prompt, disconnect, save/apply connection snippet | synthetic data only; passed |
| Subscription UI | endpoint selection, refresh, interval, delay, disabled edits while active | synthetic data only; passed |
| Network and routes UI | adapters/details, route overview/table/tree/flow/by-interface, IPv4 longest-prefix lookup | synthetic data only; passed; display findings below |
| Recovery/settings UI | cleanup, diagnostics, always-on enable/disable and edit guard, login autostart, auth mode, executable selection/reset | synthetic data only; passed |
| Linux daemon | existing scenarios.sh, including IPv4/IPv6, policy rules, polkit/uid isolation, journal, restart/cleanup, 1,000 routes | all 45 checks passed |
| WireGuard | existing wg_scenarios.py, real split/full traffic, DNS, crash recovery, always-on | all 28 checks passed |
| OpenVPN | existing ovpn_scenarios.py, real split/full traffic, pushed DNS, crash recovery | all 19 checks passed |
| OpenVPN authentication/probe | existing ovpn_auth_scenarios.py | all 4 checks passed |
| Static always-on | existing always_on_scenarios.sh, pause/resume, repair, late interface, uid isolation | passed |
| Real Xray proxy/TUN | unit tests and sandbox only in this session | real traffic not verified; pinned Linux managed package is x86_64-only |
| Windows system proxy, DPAPI, UAC, tunnel services; desktop Linux polkit prompts/tray | applicable ordinary unit tests only | VM acceptance still required |
| Real subscription service / user's VPN | not used | network/provider behavior remains unverified |

### Reproduced and corrected

- macOS compilation accessed a nonexistent `net_route::Route.metric`; use the
  platform field only on Linux/Windows and an explicit unavailable-metric
  fallback elsewhere. Route conversion has a regression test.
- The Linux daemon's orchestration/process modules were exposed on macOS even
  though their DNS, D-Bus, and libc dependencies were Linux-only. Gate those
  modules by platform; neutral protocol/store tests still run on macOS.
- Concurrent `ProfileStore::upsert` operations could lose unrelated profiles
  or collide on the temporary file. Serialize write transactions on the shared
  store instance. A 12-thread regression failed before the fix and passed after.
  This lock does not provide coordination between separate processes or store
  instances pointing at the same file.
- Profile documents lacked private Unix permissions. Protect their directory
  and temporary document before atomic rename. The permission regression failed
  before the fix and now verifies modes 0700/0600.
- Xray profile validation accepted HTTP port 0 and identical SOCKS/HTTP ports.
  The regression failed before the fix; both invalid states are now rejected.
- Linux ARM64 daemon compilation referenced x86_64-only managed Xray helpers.
  ARM64 now builds and returns `Unsupported` for that managed executable;
  this does not add an ARM64 Xray package. Architecture-specific regression passed.
- Strict Linux clippy found three nonminimal boolean conditions in DNS/staging
  cleanup. Apply equivalent expressions and re-run the Linux tests.
- WireGuard E2E required a host `wg` tool although the documented prerequisite
  is Docker. Generate test keys through `wg` inside the disposable containers;
  the full integration suite passed with no host installation.
- Saved-profile warnings showed the old name or a new profile ID. Resolve the
  name from the returned saved profiles. Route lookup now asks for an IP literal
  rather than a hostname the backend does not resolve. The adapter panel close
  control has an accessible name.

### Remaining logic/display findings

1. **Linux local Xray auto-connect depends unnecessarily on the daemon.**
   `src-tauri/src/auto_connect.rs::connect_on_startup` calls `hello` and
   `owned.list` before starting any saved profile, even when all selected profiles
   are SOCKS Xray (`daemon_owner == None`). If the daemon is unavailable, local
   proxy auto-connect is skipped although the manual local process path does not
   require it. Separate local profiles from daemon-owned profiles and add an
   unavailable-daemon regression. Found by code inspection; not injected into a
   desktop Linux app during this session.
2. **Adapter details can display stale routes and hide read failures.**
   `src/components/InterfaceDetail.tsx` fetches only when `iface.ifIndex` changes,
   omits the `route-changed` subscription, and ignores errors. An open panel can
   keep an old route count; a failed initial read looks like an empty table.
   Subscribe and expose a read error. Found by code inspection.
3. **Traffic-flow profile identities and destination labels can mislead.**
   `src/components/RouteFlow.tsx` keys profiles by `ownerName`, so different
   profiles with the same permitted name merge. `destGroup` changes any IPv4
   prefix to `/16`, including broader routes such as `10.0.0.0/8`; this can show
   the wrong apparent coverage. The `/24` fixture rendered as `/16` in the UI.
   Use `ownerProfileId` for identity and mark aggregates clearly while preserving
   broader prefixes. Duplicate-name and broad-prefix cases were found by inspection.
4. **Occupied Xray HTTP listeners do not receive the SOCKS conflict handling.**
   `src-tauri/src/commands/tunnels.rs::connect_profile` checks/reassigns an
   occupied SOCKS listener but has no equivalent HTTP preflight, while creation
   reserves both ports. A program occupying the saved HTTP port can cause a
   later Xray startup failure. Add a dual-listener regression before extending
   replacement/rollback logic. Found by code inspection, not a real Xray run.

Sandbox browser logs included Tauri mock callback warnings during development
reloads/React effect cleanup; no browser error was observed in the completed
flows. These warnings are a mock-event limitation, not evidence of a native
backend failure. Production event behavior still needs platform UI acceptance.

## Linux daemon in a disposable container

`e2e/linux/run.sh` builds the daemon, starts an Ubuntu 26.04 (default) or
Fedora 44 (`E2E_DISTRO=fedora`; firewalld and resolved enabled, SELinux not
enforced in Docker) client and an Ubuntu peer container on a private Docker network, installs the service with systemd and
polkit in the client, and runs `scenarios.sh` there. The scenarios exercise
real netlink route and interface changes, polkit authorization, uid isolation,
restart recovery, shutdown cleanup, WireGuard and OpenVPN split/full tunnels
with real peer traffic and per-link DNS, OpenVPN management credentials,
Xray VLESS/Hysteria2 proxy through SOCKS5 and HTTP CONNECT, Xray TUN,
kernel policy-rule lookup, OpenVPN pushed-route probe, and WireGuard/static-route
always-on replay. Each container has
its own network namespace. Never run `scenarios.sh` directly on the host.

```bash
e2e/linux/run.sh
```

This requires Docker access and `/dev/net/tun`. The harness grants the
client container `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and unconfined AppArmor so systemd
can remount cgroup2. Use it on a development machine or CI worker that accepts
those container privileges. The peer container needs `CAP_NET_ADMIN`. The
current harness verifies the daemon and backends directly. Real Ubuntu desktop
interaction, polkit prompt rendering and login-session autostart still need VM
acceptance.

After building a `.deb` or `.rpm`, the packaged WebView-to-daemon static-route
path can be checked in another disposable container (Ubuntu for `.deb`,
Fedora 44 for `.rpm`):

```bash
e2e/linux/run_app_gui.sh --blank-config
e2e/linux/run_app_gui.sh target/release/bundle/rpm/*.rpm
```

This uses a container-only polkit rule for its headless user session, then
checks save/connect/disconnect through the installed app's WebView and the
kernel route table. It does not verify a visible polkit prompt or Wayland.

## Windows on a disposable VM

`crates/core/tests/windows_e2e.rs` contains opt-in integration scenarios that
exercise real WireGuard/OpenVPN/Xray binaries and mutate the routing table.
They are `#[ignore]`d, serialized behind a global mutex, and refuse to run
without explicit safety markers.

## Warning

These scenarios install tunnel services, spawn VPN processes, and change
routes. **Run them only inside a disposable Windows VM** with no production
connectivity requirements. A kill-switch fixture (`/0` route) is rejected by
the harness before any mutation.

## Safety gate

Before any mutation every scenario requires:

- `NETWORK_ORCHESTRATOR_E2E=disposable-windows-vm`
- `NETWORK_ORCHESTRATOR_E2E_ACK=routes-and-vpn-will-change`
- an elevated process token
- all used fixture paths to point to regular files
- no default route (`/0`) in the analyzed fixture profile

## Environment contract

| Variable | Meaning |
| --- | --- |
| `NO_E2E_WG_CONFIG` | Path to a WireGuard `.conf` fixture |
| `NO_E2E_WG_INTERFACE` | Expected WireGuard interface friendly name |
| `NO_E2E_WG_CIDR` | Expected private CIDR installed by WireGuard |
| `NO_E2E_OVPN_CONFIG` | Path to an OpenVPN `.ovpn`/`.conf` fixture |
| `NO_E2E_OVPN_INTERFACE` | Expected OpenVPN TAP interface friendly name |
| `NO_E2E_OVPN_CIDR` | Expected private CIDR installed by OpenVPN |
| `NO_E2E_XRAY_CONFIG` | Path to an Xray JSON fixture |
| `NO_E2E_XRAY_LISTENER` | Optional `127.0.0.1:port` listener to probe |

Use only private ranges (for example `10.x.y.z/NN` placeholder CIDRs); never
commit real endpoints, keys, or URIs. Fixture values must live outside the
repository.

## Commands

```bash
# compile only (default `cargo test` never runs the mutating scenarios)
cargo test -p net-manager-core --test windows_e2e --no-run

# run on the fixture VM, elevated:
cargo test -p net-manager-core --test windows_e2e -- --ignored --test-threads=1
```

The `wireguard_killswitch_is_rejected_by_fixture_guard` test is not ignored —
it only verifies that the `/0` fixture guard refuses to connect, using a
temporary synthetic config.
