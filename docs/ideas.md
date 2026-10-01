# Ideas borrowed from other clients

Backlog of features seen in ClashX/Clash-Verge/Mihomo, sing-box/NekoBox,
Streisand/Shadowrocket, NekoRay, and similar clients, evaluated against this
project's architecture. Ordered roughly by value-per-effort.

## Implemented

- **Route checker** (Clash-Verge "rule test" / sing-box `route check`) —
  simulates the generated rule chain for a target host/IP and reports which
  policy decides it. Lives in `crates/core/src/route_check.rs`, surfaced in
  the profile form's routing tab.

## Cheap / high value

### External rulesets (rule providers)

Clash's `rule-providers`: a policy whose selectors come from a periodically
refreshed URL instead of a literal list. Fits the existing model cleanly —
a ruleset is just another selector source feeding a `DomainPolicy`. Needs a
list parser (plain domain files, Loyalsoldier-style), the geo-assets cache
machinery for download/digest pinning, and a serializer back into
`domain_policies` (or a new `ruleset:` selector kind kept out of
`classify_routing_selector` until resolved).

### Latency in the profile list

The delay-probe infrastructure already exists (used for subscriptions);
ClashX/NekoRay show ping next to each server. A "probe" action per profile
row plus a cached result column solves "which server do I pick" without
guesswork.

### LAN sharing (`allowLan` from Clash)

Bind SOCKS/HTTP inbounds on `0.0.0.0` instead of loopback to share the tunnel
with LAN devices. One profile flag; needs a visible warning in the UI since
it exposes the proxy to the network.

## Medium effort

### Kill switch

Deliberately absent today (see `docs/platform-matrix.md`). The Linux shape is
straightforward: default-deny OUTPUT on the physical interface, allowing the
tunnel mark (`skmark`) and the daemon's bypass routes. Pattern is proven in
both Happ and Incy.

### Proxy groups (url-test / fallback)

Clash's proxy-group model: a profile with several member servers and a
selection policy — `url-test` (lowest latency), `fallback` (first reachable).
Xray supports this via `balancers` + `burstObservatory`. This is a new
`Profile` shape (group profile referencing member profiles), so it is the
heaviest item on the list, but also the most requested feature class across
clients.

### Local dashboard / connections view

A local HTTP endpoint exposing live connections, per-rule hits and traffic —
either Clash API-compatible (so yacd/zashboard work) or our own minimal one.
Xray has no connections API; this would be built on top of the StatsService
counters we already inject, plus sniffing logs. Non-trivial; the statsquery
plumbing is the foundation.

## Deferred / questionable

### Per-app split tunneling

NekoRay/Android-style per-app rules. On Linux this means cgroup2 + eBPF
sockmark, or `ip rule` on a cgroup-attached fwmark. Fragile under arbitrary
distros, hard to e2e-test. Only worth doing if a real user asks.

### Config mixin (raw JSON merge)

Clash-Verge lets users inject arbitrary YAML/JSON fragments into the
generated config. Conflicts directly with our typed model + daemon-side
`validate_generated` boundary; if ever added it must be a small set of typed
"advanced" fields, not a free-form merge.

### On-demand by SSID/cellular

iOS-client feature; already covered in spirit by daemon-managed `cond:*`
route owners reacting to network state.

### TUN stack selection (system/gVisor/mixed)

sing-box lets you pick the userspace stack. Relevant only if TUN throughput
complaints appear — the daemon-managed TUN is adequate today.
