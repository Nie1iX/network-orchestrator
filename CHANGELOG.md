# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
See [`docs/versioning.md`](docs/versioning.md) for the release policy.

## [Unreleased]

### Added

- Native macOS imports HTTP/HTTPS subscription URLs with optional HWID and
  connection name, using the shared subscription parser and managed Xray
  storage. Imported profiles offer a server selector. Subscription loading
  has response and time limits, handles unpadded Base64, and strips private
  URL/HWID fields from native bridge responses.

- Import individual `vless://`, `hysteria2://` and `hy2://` share links directly
  in both the Tauri and native macOS import dialogs. An optional connection
  name overrides the link's name. Import stores a managed Xray configuration
  without activating a VPN or changing the system network.

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
