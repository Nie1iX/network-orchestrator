# Changelog: Linux

The Linux app, the network daemon and `netorch` for Linux (they are versioned together; the packages are separate, see `docs/versioning.md`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the line follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release rules: [`docs/versioning.md`](../docs/versioning.md). Everything up to
0.10.0, when the release lines were separated, is in
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Changed

- The Linux `.deb` is split into three packages that share this line's
  version: `network-orchestrator-daemon` (the daemon, its systemd unit, the
  polkit policy and the pinned Xray), `netorch` (the command line client, with
  bash, zsh and fish completions) and `network-orchestrator` (the app). The
  app and `netorch` depend on a daemon of their own `major.minor` or newer, so
  installing either keeps a suitable daemon as it is and installs or upgrades
  an unsuitable one; the former single package is replaced
  (`Replaces`/`Breaks`). A server needs only the daemon and `netorch`:
  `apt install ./network-orchestrator-daemon_*.deb ./netorch_*.deb`.
  `.rpm` and Arch packages are still one package.

### Fixed

- A system-wide Xray tunnel no longer stops carrying traffic when its server is
  given by name. The daemon now resolves the name before the tunnel comes up
  and has Xray dial the IP (the name stays the TLS/Reality server name), so a
  reconnect no longer needs the resolver that points into the tunnel. Because
  the server no longer has to be looked up, the DNS servers are not routed
  around the tunnel any more: on networks that drop DNS to outside resolvers
  the profile's DNS now works through the tunnel.

### Added

- `netorch route` manages the routing rules of Xray profiles from the terminal:
  `show` lists them, `add` and `rm` change single selectors, `set` replaces
  all of them, and `check <host or IP> --profile <profile>` tells which rule
  decides it. Selectors are `domain:`, `full:`, `geosite:`, `geoip:`, an address
  or a CIDR network. A bare name such as `ru` is a substring match in Xray, and
  the command says so. A connected profile applies the change when it
  reconnects.
- `netorch version` also shows the core version the build includes.

Core 0.10.0.
