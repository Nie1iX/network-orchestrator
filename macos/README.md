# Native macOS client

SwiftUI/AppKit application for macOS 27.0 or later. Rust core operations run
through an owned JSON C ABI (`crates/macos-bridge`) on a Swift actor, away from
the main UI actor. There is no HTTP server, child daemon or WebView in this
client. The existing Windows/Linux Tauri shell remains separate.

## Build and run

```bash
bash scripts/build-macos-native.sh
open "target/macos/Network Orchestrator.app"
```

Requires Xcode 27, Rust and Python 3 on macOS 27. The build uses the host
architecture; the first verified bundle is Apple Silicon (arm64). Intel and
universal builds are not yet verified. Bundle version is generated from the
Cargo workspace version. The local ad-hoc signature supports local development;
it is not a Developer ID signature or notarization for distribution.

## Available in this stage

- Home, connections, network, routes and settings screens styled after Tauri:
  icon rail, grouped connection cards, interface filters, six route tabs and
  themed dialogs. Native file picker, menus, sheets and Command-R refresh.
- Import WireGuard `.conf`, OpenVPN `.ovpn` or Xray JSON via ConfigVault.
  Imported configurations are private, revisioned copies, not references to
  mutable original files. Keys and configuration contents are not displayed.
- Import `vless://`, `hysteria2://` and `hy2://` links in Import → Link.
  The name is optional and defaults to the URL fragment. Generated Xray
  configurations use managed revisions and distinct loopback proxy ports.
  Import does not start a VPN, set a system proxy or apply routes.
- Create static IPv4/IPv6 route profiles, rename/delete profiles, search and
  inspect declared routes and local listeners with the shared Rust analysis.
- Fetch an HTTP/HTTPS subscription in Import → Subscription, with optional
  HWID and name. Plain-text and Base64 lists of VLESS/Hysteria2 links are
  grouped into one profile with a server selector. Responses are bounded to
  1 MiB and 30 seconds. Cross-origin redirects do not receive the HWID; HTTPS
  downgrades are rejected. URL tokens, HWID and endpoint credentials stay in
  the protected store and are removed from all bridge profile responses.
- Read live Darwin interface names, indexes, operational state and addresses
  using `getifaddrs`; read system IPv4/IPv6 routes through `net-route`.
- Inspect saved route plans and longest-prefix lookup. macOS interface-scoped
  policy can affect actual kernel selection; the lookup is a table preview.
  Route metrics, DNS, MTU and traffic counters are not claimed when unavailable.

VPN start/stop, route application, DNS, system proxy, interface mutations,
automatic connection, managed backend installation and automatic subscription refresh
are not implemented in the native client yet. These are not simulated as
successful operations: the bridge explicitly refuses mutation commands.
macOS tunnel integration needs a provider, its lifecycle and rollback design,
and the corresponding Apple signing/entitlement setup. No tunnel executable
is started by this client.

## Storage and isolation

Default data: `~/Library/Application Support/com.netmanager.app.macos`.
To test without touching saved native profiles, run the binary with a dedicated
absolute directory:

```bash
NETORCH_MACOS_DATA_DIR="$PWD/target/macos-qa-data" \
  "target/macos/Network Orchestrator.app/Contents/MacOS/NetworkOrchestrator"
```

The override changes only profile storage. All system-network operations in
this stage are read-only; imported default routes are analyzed, never applied.
The override should not point to another running client's data directory.

## Tests

Build the Rust library before Swift tests:

```bash
cargo test -p net-manager-macos-bridge
cargo build --release -p net-manager-macos-bridge
swift test --package-path macos --scratch-path target/macos-swift
```

Tests use temporary stores and synthetic configurations. Native integration
tests also read real loopback interfaces and routes. They need ordinary route
socket access, but do not require administrator privileges or network changes.
SwiftPM may need permission to use Xcode/Swift caches in restricted sandboxes.

## Shared appearance

Both clients offer System, Light and Dark in Settings. Colors and core layout
metrics come from `design/tokens.json`; run `python3 scripts/generate-ui-theme.py`
after editing it. Both build scripts reject stale generated CSS/Swift output.
Native PDF icons reproduce the SVG geometry in `src/icons.tsx`; the source hash
is checked at build time. Regenerating them uses
`python3 scripts/generate-native-icons.py` with ReportLab installed; ordinary
builds use the checked-in PDFs and need no graphics Python dependencies.

The native client still uses SwiftUI/AppKit throughout. OS window chrome,
file pickers and popup menus follow macOS. Screens for unavailable features
show the native client's actual capabilities. A pixel-perfect match across
platforms has not been established.

Render every page, route tab and supported creation/import dialog in both
themes using synthetic data, without opening a window or starting a VPN:

```bash
NETORCH_DESIGN_PREVIEWS="$PWD/target/macos/design-preview" \
  swift test --package-path macos --scratch-path target/macos-swift
```

The optional acceptance test writes 64 native PNG renders across English,
Russian, dark and light; the normal test
suite also checks packaged vector icons. These renders check appearance;
they do not replace interactive testing of a foreground window.

## Interface language

Settings → Appearance → Language offers System, English and Russian. The
selection is saved in this application's preferences and updates the views
in place. Shared catalogs, plural rules and the new-language workflow are
documented in [`../locales/README.md`](../locales/README.md). Run
`npm run i18n:generate` after editing catalogs; native packaging includes the
generated JSON resource and rejects stale translations.
