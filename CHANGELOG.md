# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
See [`docs/versioning.md`](docs/versioning.md) for the release policy.

**This file is the history up to 0.10.0**, when the project had one version for
everything. From 0.10.0 on the core and each operating system have their own
version and their own changelog: [`changelog/core.md`](changelog/core.md),
[`changelog/macos.md`](changelog/macos.md),
[`changelog/linux.md`](changelog/linux.md) and
[`changelog/windows.md`](changelog/windows.md). All four lines start at 0.10.0.

## [Unreleased]

## [0.10.0] - 2026-10-29

### Added

- macOS: "Connect when the app starts" per connection. The flagged connections
  start once at launch, in saved order; a failure is reported without
  blocking the others.
- macOS: a menu bar item with the number of active connections, a switch per
  connection, "Disconnect all" and a shortcut to the window; it can be hidden
  in Settings. The state keeps updating with the window closed.
- macOS: at launch the app reports what a crashed session left behind
  (routes, DNS, a leftover tunnel) and offers a cleanup.
- macOS: a Monitor page (throughput per interface) and a Logs page (app events,
  each connection's log, the helper log, NetBird, import). WireGuard now
  writes a log through the helper.
- macOS: a Diagnostics sheet for a connection (path to the endpoint, static
  analysis, listeners, system proxy, helper, tunnel state), with checks shared
  in `net-manager-core::diagnostics`.
- macOS: routing intents. The helper keeps "these networks go this way" (via
  a named interface, or direct through the physical uplink) in a root-only
  store, installs the routes, checks them every 2 seconds on a network change
  and in full every 10 seconds, and deletes only routes it installed that
  still match. A route someone else owns is reported as a conflict, never
  replaced. Limits per user: 64 intents, 32 rules, 256 networks in total.
  New "Intents" tab on the Routes page; routes that capture the whole
  default route are allowed with a warning, as on Linux.
- macOS: conditional routes. A rule turns its routes on while a network
  condition holds (an interface address inside a given network) and off
  afterwards. "Conditions" tab on the Routes page.
- macOS: the intent doctor (a port of the Linux one): suggestions for
  endpoints a tunnel would loop back into and for destinations that skip the
  intended path, shown as cards on the Intents tab. On macOS a foreign
  conflicting route is only reported.
- macOS: static-route profiles (the `none` backend) connect. Connecting
  creates the profile's intents; disconnecting or quitting the app removes
  them. By default connecting fails while the interface is missing; "Wait for
  the interface" arms the routes in advance. Works from the app and from
  `netorch up` / `down`.
- macOS: app modes (Combined, Orchestrator, Manager) in Settings. Orchestrator
  does not start managed backends; static routes stay available and a running
  tunnel can be stopped.
- macOS: a network interface can be turned on or off from its card, through
  the helper, with a confirmation that is stricter for the interface carrying
  the default route. Loopback and tunnel devices owned by the helper are
  refused.
- macOS: the Network page gets a DNS tab: the resolvers the system uses, the
  server a name would go to (and whether it is a fake IP), and a real
  A/AAAA query to that server.
- `net-manager-core`: `route_intents`, `route_conditions`, `intent_doctor`,
  `dns_diag`, `dns_probe`.
- macOS: static-route profiles can send a route through its own gateway
  (`10.1.0.0/16 via 10.0.0.1`). Each gateway is kept by the helper as its own
  routing intent and waits until the gateway is on a connected network. A
  profile whose routes all name a gateway needs no interface.
- macOS: "Endpoint bypass" on a static-route profile (IP addresses or host
  names). They stay on the physical uplink while the routes through another
  client's tunnel are active; names are resolved when connecting, the bypass
  is applied first and removed last, and a failure part way leaves nothing
  behind.
- macOS: custom `geoip.dat` / `geosite.dat` for Xray, by https address in the
  routing rules editor or from a Happ/Incy export (which used to warn that
  they were ignored). The app downloads and caches them (https only, size
  limit, sha256 sidecar check, stale copy kept if a refresh fails) and lays
  them over the managed Xray's files. A tunnel receives them inline and the
  helper serves them from a root-owned directory that is removed with the
  tunnel; it never follows a symlink to read the managed files.
- `net-manager-core`: `geo_assets` (the download cache, shared with the
  clients; `src-tauri` keeps its own copy for now).
- Linux: `netorch`, a command line client of the network daemon. `ls`,
  `status`, `up`, `down` and `completions` connect the WireGuard, OpenVPN and
  Xray TUN profiles saved in the app; `add` (and `up <link|url|file>`) saves a
  vless:// / hysteria2:// link, a subscription URL or a `.conf` / `.ovpn` file
  with the same code as the app, so the CLI needs no GUI to get a profile;
  `rm` and `rename` manage them. OpenVPN credentials come from the terminal
  or `--auth-stdin`.
- Linux: `netorch` works with the servers inside a subscription: `endpoints`
  lists them, `use` picks one by number or part of its name (on a terminal
  without an argument it asks, with a filter), `switch` changes the server of
  a connected profile and reconnects (restoring the previous server if the new
  one does not come up), `up --endpoint` picks and connects, `refresh` fetches
  the list again and `test` measures every server's delay through a temporary
  Xray, fastest first. `ls` and `status` show the active server.
- Linux: `netorch up` leaves a background keeper process (`netorch hold`,
  hidden) so the connection outlives the command: the daemon removes a tunnel
  30 s after the last client process of the user has exited. `netorch down`
  stops the keeper, and `up --foreground` keeps the connection in the terminal
  until Ctrl+C.
- Linux: `netorch` checks the network daemon before it calls it, because the
  two are separate packages that can be at different versions. A different
  wire protocol, or a daemon that lacks a method `netorch` calls, is refused
  with what to update; a daemon from an older release line only warns.
  `netorch version` shows both versions and the verdict.
- Linux: when polkit refuses because the session has no authentication agent
  (SSH), `netorch up`, `down` and `switch` start a text agent (`pkttyagent`)
  on a terminal and ask for the administrator password once; without a
  terminal they explain the options (a terminal, `sudo netorch`, or a polkit
  rule). `sudo netorch ls|status|up|down` work from the invoking user's data;
  commands that write data still refuse to run as root.

### Changed

- The privileged helper advertises intent and interface capabilities only when
  they are configured, and the app asks the user to update an older helper.
- Intent identifiers may be up to 64 characters (was 48) so a profile's
  identifier fits with the `-bypass` and `-gwN` suffixes. Static profiles
  now own several intents: a profile's routes, one per gateway, and its bypass.
- The `net.intent.set` path accepts `kind: "gateway"` with a `gateway`
  address. Existing intents and the Linux daemon are unaffected.
- Profile import by file (`import_configs_into`, `detect_backend`,
  `generate_import_id`) moved from the Tauri app into `net-manager-core`; the
  app uses the shared code. No behavior change.

### Fixed

- macOS: the recovery cleanup no longer stops a tunnel that is running;
  Xray, WireGuard and OpenVPN leave a live session alone.
- Linux: subscriptions from panels that serve whole Xray configs (Remnawave,
  Geodema) can run as a system-wide Xray TUN again. The daemon rejected every
  such server ("unsupported generated Xray TUN config") because of the
  panel's observatory, policy, DNS, extra outbounds and balancer. The server
  itself is now reduced to the plain shape before it is sent
  (`xray::tun_compatible_config`, used by the app and `netorch`); the
  panel's own routing rules and DNS are not applied, the profile's are. An
  "automatic" entry that picks from a pool of servers is refused with advice
  to choose a specific server. 92 of the 93 servers of a real subscription
  now pass the daemon's validation.
- `net-manager-core` tests compile on Linux again (`spawn_xray` test call).

### Documentation

- A macOS-vs-Linux difference list with the order in which the remaining
  Linux features move to macOS, and a platform matrix in line with the code.
- Plan for route intents, conditions and the intent doctor on macOS.

### Known limitations (macOS)

- Routes, the helper, geo data and the interface switch were verified with
  fakes and simulated route tables only, not on a live system; the helper
  must be updated for any of the new helper features.
- A route on a scoped (`ifscope`) interface is not told apart and can read as
  a conflict.

## [0.9.1] - 2026-10-23

### Fixed

- Linux: the window no longer aborts with "Could not create GBM EGL display"
  on GPU/driver setups where WebKitGTK's DMABUF renderer fails (seen on
  NVIDIA); the renderer is disabled unless the user set it explicitly.
- Dialogs keep the focused field and open drop-downs while the screen behind
  them refreshes.

## [0.9.0] - 2026-10-23

### Added

- Linux: a Home screen with the running connections, a one-click reconnect of
  the last profile and a button that copies `HTTP(S)_PROXY`/`ALL_PROXY` for a
  terminal. A connection that needs OpenVPN credentials asks for them right
  there.
- Linux: the system proxy for Xray SOCKS profiles on GNOME (`gsettings`) and
  KDE Plasma (`kwriteconfig`), with the previous settings restored on
  disconnect. Hidden on other desktops.
- Linux: NetBird under Profiles → Services, driven through the user's own
  `netbird` CLI (on/off, server and setup key, browser sign-in).
- Linux: connection roles. A secondary WireGuard, OpenVPN or Xray TUN
  connection carries only the networks listed for it (pushed routes and
  gateway redirects are ignored) and, optionally, split-DNS domains through
  `systemd-resolved`; the primary keeps taking all traffic. The daemon rejects
  a secondary request that would take all traffic, and Profiles shows a role
  switch, a networks dialog and a Secondary badge.
- Linux: `LinuxEngine` in `net-manager-engine`, a typed connect/disconnect/
  status API over the daemon socket, as the groundwork for a Linux `netorch`.
- The import dialog lists the chosen files and lets you pick the backend (or
  detect it from the file) before importing, accepts a pasted subscription URL
  in the Link tab and submits on Enter, with one button and one error line for
  every tab.

### Changed

- The decisions behind connecting a profile (conflict checks, route and
  interface derivation, auto-connect selection) live in
  `net-manager-core::connect_plan`; the requests the app sends to the Linux
  daemon are built by `net_manager_engine::linux`. No behavior change.
- The NetBird driver moved from the macOS bridge into `net-manager-core` and
  is shared by both clients; the macOS bridge parses secondary networks and
  DNS domains with the shared helpers.
- The OpenVPN credentials dialog is a shared component used by Home and
  Profiles.
- The add-connection icon is round and tinted with the accent colour.

### Documentation

- The versioning policy defines a breaking change by what users depend on and
  adds the breaking-change commit footer; `CLAUDE.md` points Claude Code at
  `AGENTS.md` and the versioning policy.

### Tests

- End-to-end coverage of a secondary WireGuard tunnel with split DNS in the
  Linux Docker harness (not run yet: it needs Docker).

## [0.8.7] - 2026-10-20

### Added

- macOS: `netorch`, a command line tool in the app bundle that does what the
  app does without writing configs by hand: `netorch up <link | subscription
  URL | .conf | .ovpn | name>` imports, picks ports and mode, connects and
  undoes everything on exit. Also `ls`, `status`, `add`, `rm`, `rename`,
  `down`, `logs`, `test` (subscription delays, exit IP), `route
  show|set|check|lookup`, `doctor`, `backend install`, `service status` and
  shell completions; `--json` everywhere. It shares profiles with the app and
  talks to the privileged helper like the app does, or, with `sudo netorch up`,
  runs the helper's executors inside its own process (no helper needed; only
  for the user at the console). `sudo netorch service install` installs the
  helper without the app: it copies the helper into `/Library/PrivilegedHelperTools`
  (root-owned) and registers it with launchd; `service remove` undoes it.
- `net-manager-engine` crate: the connection engine (connect, disconnect,
  status, system proxy, Xray install, helper requests) behind a `Privileged`
  trait, shared by the native client's bridge and `netorch`.

- macOS: Tailscale stays reachable next to any primary tunnel (Xray, WireGuard,
  OpenVPN). The connections page gets a Tailscale row in "External" (status,
  tailnet, peers online, on/off, sign-in page) instead of the bare VPN entry.
  While a tunnel is up, the app asks the helper (`tailscale.protect`) to pin
  the tailnet prefixes to Tailscale's interface if another route wins them and
  to route Tailscale's own remote hosts (direct peers, DERP relays from the
  tailnet's map, the control server) around the tunnel through the physical
  gateway. Everything is journaled and released with the last tunnel.

### Changed

- macOS: the privileged helper admits the `netorch` tool of its own bundle next
  to the app executable; the same console-user rule applies.

## [0.8.6] - 2026-10-15

### Fixed

- Profiles page: dragging the list/detail splitter no longer makes the text
  flicker. macOS measured the drag in the splitter's own moving coordinate
  space; the web client re-rendered the whole screen on every pointer move and
  let scrollbars toggle mid-resize.

### Changed

- macOS: the title bar is one flat colour with the app name centred, instead of
  a white system material behind the window buttons.

## [0.8.5] - 2026-10-14

### Added

- macOS: WireGuard and OpenVPN run through the privileged helper. WireGuard uses
  a userspace engine (`boringtun`) inside the helper — no external binary. OpenVPN
  is a pinned, self-contained 2.6.17 built by `scripts/build-macos-openvpn.sh`
  and shipped in `Contents/Helpers/`; the helper verifies its SHA-256 and runs
  only a root-owned copy, with route/DNS/script handling switched off and done by
  the helper itself. Routes, DNS and the device are journaled and undone on any
  exit; one tunnel runs at a time. OpenVPN credentials are requested by the app
  and can be kept in the Keychain.
- `openvpn_config::credential_requirements` in core: which credentials a
  profile needs before it can connect (mirrors the Linux client's rules).

- macOS: Xray, OpenVPN and WireGuard can run together. One is the primary
  connection (default route and system DNS); the others are secondary and carry
  only the networks listed for them (CIDR), which win over the primary's capture
  because they are more specific. Secondary connections can also add split-DNS
  suffixes (`/etc/resolver`). Set per connection in the connection card; one
  active connection per protocol.

- macOS: NetBird. The app shows the state of your own NetBird daemon (IP,
  peers, networks, session expiry) among the external connections and switches
  it on and off through the NetBird CLI, signing in through the browser (SSO) or
  with a one-time setup key that never touches a command line.

### Changed

- `sanitize_openvpn_config` accepts the macOS runtime root
  (`/var/run/network-orchestrator`) as a staging location.
- macOS: the navigation rail now stops at the title bar and is wider, so the
  window's traffic-light buttons no longer straddle its edge.

## [0.8.0] - 2026-10-14

### Added

- Merged from `main` (Linux): persistent routing intents, kernel route/rule
  System tab, DNS path probing, NetworkManager inventory, external-tunnel
  attach with endpoint bypasses, opt-in localhost proxy discovery and the
  orchestrator/manager/combined app modes.
- macOS: Xray TUN mode. The privileged helper creates a `utun`, starts the
  managed Xray as the console user with the device passed through
  `XRAY_TUN_FD`, installs the capture routes (eight protected IPv4 prefixes
  plus two IPv6 halves) with bypass routes for the machine's resolvers, and
  points the uplink's network service at Xray's resolver. Everything is
  journaled and undone on disconnect, when Xray dies, on helper shutdown and at
  helper restart. The connection panel has a SOCKS/TUN switch; the app's own
  tunnel is no longer reported as a foreign VPN.
- macOS: Xray answers the system's DNS in TUN mode. A `dns` outbound handles
  lookups for the tunnel resolver; names the profile routes `direct`/`block`
  get fake-DNS answers so domain rules also match protocols without SNI (SSH);
  the network's search domains and resolvers keep serving local names; profile
  `dns` outbounds that forward everything to a fixed resolver are taught to
  hijack the routed names.
- macOS: the privileged helper is removed when the app build changes (version or
  helper code hash) and a banner asks to install it again; starting a TUN
  profile without the helper offers to install it.
- macOS: a read-only "My routing settings" tab on the Network page lists
  persistent service routes, static kernel routes with their likely source,
  launchd jobs that run `route`, `/etc/resolver` domains, `/etc/hosts`
  overrides and manual IP/DNS/proxy settings of network services.
- `scripts/build-macos-native.sh` signs with `CODESIGN_IDENTITY` when set.
  macOS does not let `SMAppService` find a daemon in an ad-hoc signed bundle,
  so the privileged helper needs a real identity.

### Changed

- `xray.connect` carries an optional `macosDataRoot` so the macOS helper finds
  the console user's managed Xray; Linux ignores it.

### Fixed

- Linux-only intents and proxy-discovery helpers no longer break
  `cargo clippy` on non-Linux hosts.

## [0.7.0] - 2026-10-02

### Added

- macOS privileged helper, stage 1: the `network-orchestrator-helper` launchd
  daemon (shared `daemon_protocol` over a Unix socket), console-user and
  app-path peer verification, `SMAppService` install/remove from Settings, a
  blocking `core::helper_client` and the bridge's `helper_status`. It performs
  no network changes yet; WireGuard/OpenVPN executors are the next stage.

## [0.6.0] - 2026-10-02

### Added

- Native domain rules editor gained a DNS tab (resolvers with proxy/direct
  pinning, static hosts, Fake DNS, query strategy), domain strategy and
  matcher pickers, an offline route checker and Happ/Incy routing import,
  sharing the core parsers with the Tauri client.

### Changed

- The native client moves a connection off occupied SOCKS/HTTP listener ports
  before starting it (shared `prepare_connect_ports` in the core); subscription
  names use a centered dot, matching the other clients.

## [0.5.0] - 2026-10-01

### Added

- Native Connections: saved connection sets applied in one click, drag and
  drop or Move up/down reordering within a group, a resizable list/detail
  divider (remembered), backend-colored group icons, Start at login (via
  SMAppService) and one app instance per data directory — a second launch
  brings the first forward instead of stopping its connections.

- Native Connections list VPN services configured by other apps (e.g.
  Network Extension VPNs) under "Discovered on system" with an External
  badge, and connect or disconnect them like the macOS VPN menu
  (`scutil --nc`; only well-formed service UUIDs are accepted).

- Native subscriptions auto-refresh every 15 minutes, hour or 6 hours
  (running connections are left alone), with the last check time, a failure
  marker and the provider's suggested interval. Refresh downloads outside
  the store lock so the UI keeps updating, and failed attempts back off a
  full interval. Refresh scheduling state moved into the core.

- Native home screen checks the exit IP directly and through every running
  connection (six IP-echo services, country, agreement count), connections
  show their redacted Xray log, and Settings shows the secret-free
  subscription import log. The exit-IP checkers moved into the core and can
  run through a loopback SOCKS proxy; the Tauri panel uses the same code.

- Native Xray connections edit their domain/IP rule sets (block → proxy →
  direct) and the private-LAN-direct switch in a full-size editor, with a
  per-set summary in the detail pane. Each line is validated with the core
  selector rules and the offending line is named; a running connection
  restarts to apply the rules.

- Subscriptions keep the provider's title, announcement and support/account
  links from `profile-title`, `announce` (plain or `base64:`),
  `support-url` and `profile-web-page-url` headers or `#…:` body comments;
  text is bounded and only https links are kept. The native client shows
  them at the top of the detail pane, and subscription rows read as a group:
  your name first, the selected server below in smaller type. Import
  diagnostics also list response header names (never values).

## [0.4.0] - 2026-10-01

### Added

- Native macOS starts Xray connections in loopback SOCKS/HTTP mode without
  administrator rights. A pinned, hash-verified Xray v26.7.28 for Apple
  Silicon installs by download or from a local copy of the official zip.
  Connections can drive the macOS system proxy (Wi-Fi/Ethernet services only,
  with snapshot and rollback), open a separate Chrome profile through the
  connection, or copy terminal proxy variables. Quitting the app, or the next
  launch after a crash, stops Xray and restores the previous proxy.
- Native macOS client follows the dense web shell: master-detail connection
  list with state edges, a context menu and working switches, a detail pane
  with tunnel config fields and grouped WireGuard peers, single-line network
  rows, and a bottom status bar showing Xray, system proxy ownership and the
  primary route. A warning explains when a packet-tunnel VPN (e.g. incy)
  owns the primary route and macOS ignores the system proxy.
- `scripts/macos-dev.sh` for the native build/run/test/preview loop.
- Subscriptions that return full Xray JSON configs (Remnawave and similar
  panels serve this to v2rayN) import one endpoint per server, named from
  `remarks`. Only `outbounds`, `routing`, `dns`, `policy` and observatory
  sections are kept; panel `inbounds`, `log`, `api` and `stats` are replaced
  or dropped. The response limit rises to 4 MiB.
- Native subscriptions: Refresh (per profile and for all in the toolbar),
  per-server delay probes (eight parallel temporary Xray processes, shown in
  ms), switching servers while connected (reconnects automatically), traffic
  and expiry from `Subscription-Userinfo`, and the active server name in the
  connection row, detail pane, home screen and status bar. The home screen
  now lists running connections with disconnect actions. Subscription refresh
  and delay probes moved from the Tauri shell into the shared core.
- A profile keeps a user-chosen name when the server changes; only profiles
  named after one of their servers follow the selection.
- Native subscription import can generate the HWID automatically: a stable
  per-Mac value derived (SHA-256 with an app salt) from the hardware UUID,
  never revealing it. Import failures log a secret-free summary (format,
  size, link schemes) to `runtime/logs/subscription-import.log` and the
  unified log.

- Native macOS imports HTTP/HTTPS subscription URLs with optional HWID and
  connection name, using the shared subscription parser and managed Xray
  storage. Imported profiles offer a server selector. Subscription loading
  has response and time limits, handles unpadded Base64, and strips private
  URL/HWID fields from native bridge responses.

- Import individual `vless://`, `hysteria2://` and `hy2://` share links directly
  in both the Tauri and native macOS import dialogs. An optional connection
  name overrides the link's name. Import stores a managed Xray configuration
  without activating a VPN or changing the system network.

### Changed

- Subscription requests identify as `v2rayN` so panels return real servers
  instead of an "App not supported" placeholder; placeholder-only responses
  are rejected instead of being saved or replacing working endpoints.
- Dependencies build without debug info in the dev profile and a
  `release-fast` profile skips LTO for local native iteration, cutting
  `target/` size and the native rebuild from about 30 s to about 3 s.

## [0.3.0] - 2026-09-30

### Added

- Native SwiftUI/AppKit client for macOS 27 linked directly to the Rust core
  (`crates/macos-bridge`), built with `npm run build:macos`. It supports
  managed configuration imports, static route profiles, static analysis,
  interface inventory and routing-table inspection with the shared theme and
  translations. VPN activation and network changes are not available on
  macOS yet and are refused explicitly.
- Core lists macOS interfaces through `getifaddrs`.

## [0.2.0] - 2026-09-30

### Added

- Interface localization in English and Russian with a Language selector in
  Settings; shared catalogs in `locales/` are validated and generated at build
  time.
- Light theme and a Theme selector (System, Light, Dark). Colors and layout
  metrics come from shared design tokens in `design/tokens.json`.
- In-memory browser sandbox for UI development (`npm run dev:sandbox`) with
  synthetic profiles, routes and adapters; excluded from production builds.

### Fixed

- The review notice after saving a profile shows the saved name.
- Route lookup asks for an IPv4 or IPv6 address instead of a hostname.
- The adapter panel close button has an accessible name.

### Documentation

- Recorded the 2026-09-30 local verification and its open findings in
  `docs/testing.md`.

## [0.1.2] - 2026-09-30

### Fixed

- Core and daemon crates build on macOS: route metrics are read only where
  `net-route` exposes them, and Linux-only daemon modules are gated by platform.
- The daemon builds on Linux ARM64; managed Xray reports `Unsupported` there
  because the pinned package is x86_64-only.
- Concurrent profile saves no longer lose profiles; profile documents are
  written with private permissions (0700/0600 on Unix).
- Profile validation rejects a zero Xray HTTP port or one equal to the SOCKS
  port.
- WireGuard E2E generates keys inside the containers and no longer needs a
  host `wg` tool.

### Changed

- Simplified boolean conditions flagged by strict Linux clippy (no behavior
  change).

## [0.1.1] - 2026-09-30

Baseline for this changelog: Windows and Linux Tauri app with the Linux
privileged daemon, WireGuard, OpenVPN and Xray on Ubuntu, Debian, Arch and
Fedora.
