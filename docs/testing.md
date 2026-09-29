# E2E testing

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

This requires Docker access and `/dev/net/tun`. `CONTAINER_ENGINE=podman`
runs the same suite under rootless Podman (systemd containers get
`--systemd=always` and `CAP_NET_RAW`, which `systemd-resolved` needs for
`SO_BINDTOINDEX` on per-link DNS sockets). The Xray scenarios take a host
binary via `XRAY_E2E_BINARY` (default `~/.local/bin/xray`) and pinned geo
assets via `XRAY_E2E_GEO_DIR` (default `~/.config/xray`, contents must match
the release hashes in `managed_xray.rs`). The harness grants the
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
