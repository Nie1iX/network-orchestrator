# macOS: route intents (Intents, Conditions, intent doctor)

Port of the Linux daemon's `net.intent.*` and `condRules.*` to the launchd
helper (`docs/macos-vs-linux-tauri-diff.md`, items 8 and 9). The protocol types
already exist in `core::daemon_protocol` (`NetIntentSetParams`, `NetIntentView`,
`ExplainStatus`, `ConditionalRouteRule`, ...); nothing new is invented on the
wire.

## Slices

1. **Engine and Intents.** Helper: intent store, route executor, reconcile.
   Engine and bridge: list/set/delete. Swift: Intents tab.
2. **Conditions.** `interfaceAddressIn` evaluated by the same reconcile, on top
   of slice 1. Swift: Conditions page.
3. **Intent doctor.** Port of `src/intentDoctor.ts` into `core` with tests, and
   suggestion cards.

## What an intent is

A set of destinations (CIDR) and a path: `interface <name>` (any device,
including a tunnel; *armed* until the device exists) or `direct` (the current
physical uplink, so the traffic bypasses tunnels). The helper keeps it across
restarts and re-derives the routes whenever the network changes.

## Helper design

- `intents.rs`: `IntentStore` (a versioned JSON document under the helper's
  state directory, root-only, atomic temp + rename; one list per uid) and an
  executor with `set`, `del`, `list`, `reconcile`.
- Journal owner `intent:<uid>:<id>`. The store records the spec **and the exact
  routes the helper installed**, so removal and crash recovery undo only those.
- `reconcile` derives the wanted routes from the spec and the live network
  (uplink, interface list, route table), then diffs against what is installed:
  remove stale, add missing. It runs right after `set`/`del`, on helper start
  (after recovery), and from the existing 2-second watcher when its inputs
  (uplink, interfaces) changed, plus a full verify every ~10 seconds.
- Route table and interface list come through injectable traits, so every rule
  is tested with fakes and no test touches a route.
- Statuses reuse `ExplainStatus`: `effective`, `deferred` (device absent or no
  uplink), `conflicted` (a foreign route holds the destination), `missing`
  (wanted but absent, will be retried), `disabled`.
- Methods are advertised only when the executor is configured.

## Protections

1. **Validation.** Id is a slug `[a-z0-9][a-z0-9_-]{0,47}`. At most 64 intents
   per uid and 256 routes in total. Destinations are valid CIDRs, host bits
   masked. Loopback, multicast, link-local and unspecified-host destinations
   are refused.
2. **Never cut the helper's own ground.** A destination that contains the
   current uplink gateway is not routed away from the uplink (only `direct`
   may cover it).
3. **Never touch what is not ours.** Only journaled routes are deleted; a
   foreign route on the same destination makes the intent `conflicted` and is
   left alone. A tunnel's own routes (its journal) count as foreign.
4. **Per-uid isolation.** `list`/`set`/`del` only see the caller's intents;
   the peer uid comes from the socket, not from the request.
5. **Interface paths.** The name must be a valid interface name and not
   loopback; the device of the path may be a tunnel but its up/down state is
   never changed by an intent.
6. **Default-capturing intents** (`/0`, or the `/1` halves) are allowed through
   an interface, as on Linux, and shown with a warning in the UI; they can be
   deleted at any time, which restores the table.
7. `metric` is stored and shown but macOS `route add` has no metric; it is
   documented as informational.

## Bridge and engine

The bridge stays unprivileged: the Swift client calls `intents`, `set_intent`
and `delete_intent`; the engine turns them into `net.intent.*` requests.

## Out of scope here

Static-route profiles (`none` backend), always-on, endpoint bypass for external
clients and geo lists are item 9; they reuse this executor.
