# E2E testing on a disposable Windows VM

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
