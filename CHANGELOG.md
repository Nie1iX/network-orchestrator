# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
See [`docs/versioning.md`](docs/versioning.md) for the release policy.

## [Unreleased]

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
