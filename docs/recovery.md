# Recovery and lifecycle

## Containment

- OpenVPN and Xray run as child processes inside a Windows Job Object with
  `KILL_ON_JOB_CLOSE`: if the app exits or crashes, the OS kills the
  children — they cannot be orphaned.
- WireGuard uses `wireguard.exe /installtunnelservice` — a real Windows
  service that survives process exit by design.

## Ownership records

Durable records make crash cleanup possible without guessing:

- `applied-routes.json` — policy routes the app created (profile id, CIDR,
  interface index, metric). Written atomically (temp + rename).
- `proxy-state.json` — system-proxy ownership: owning profile id, the exact
  pre-apply registry snapshot, and the applied values. Persisted **before**
  the registry write so a crash mid-apply still leaves evidence. ACL-protected
  like the config vault.
- WireGuard running state is discovered live by querying the tunnel service.

## Normal close

Window close / app exit runs `cleanup_all` under a shutdown flag:

1. `proxy.restore_any()` — restore snapshotted registry values (deleting
   values that did not exist before), then clear the record.
2. Remove every owned policy route and persist the emptied registry.
3. Stop every running tunnel (WireGuard service uninstall, child kill).

Close is deferred until cleanup finishes; failure keeps the app alive and
emits `shutdown-failed` instead of abandoning mutated state.

## Crash → startup prompt

On startup `get_recovery_report` inspects (no mutation):

- surviving WireGuard tunnel services for stored profiles,
- status-check failures,
- recorded route ownership: routes still present (`OwnedRoutes`), routes
  expected but absent (`MissingOwnedRoutes`), or records for deleted
  profiles (`OrphanRouteOwnership`),
- `proxy-state.json` ownership still applied (`ProxyOwnership`).

If issues exist, a prompt offers **Clean up** (runs `cleanup_all`, then
re-reports) or **Keep for now** (dismiss, no mutation). A failed inspection
shows `Recovery check failed` with **Retry** — cleanup is never offered
blindly. When cleanup needs administrator rights the app offers an elevated
restart; after restart the same check runs again.

## Safety properties

- Restore is idempotent: `restore_any` with no ownership is a no-op;
  `restore` for a non-owner fails instead of touching another profile's
  settings.
- Apply rollback: if the registry write fails, the snapshot is restored and
  ownership cleared; if that restore also fails, the ownership record is
  deliberately kept so recovery can still undo the partial apply.
- Read-back verification: the Windows adapter re-reads the registry after
  apply/restore and errors on mismatch before broadcasting
  `WM_SETTINGCHANGE`.
