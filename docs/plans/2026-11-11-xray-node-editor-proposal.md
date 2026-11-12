# Node editor over the complete profile configuration

**Agreed scope:** the complete NetOrch profile, not raw Xray alone. The Linux
client implements the constructor described here. Generated backend configuration
remains derived; this editor does not expose source credentials.

## One authoritative document

Text and graph edit the same versioned profile draft: subscription/source
references, specific endpoints and pools, ordered routing rules, DNS, named exits
and interface policies. Engine output is a derived, read-only effective config.
Do not introduce a separate graph settings model or write generated runtime JSON
back over the authoritative profile. Node positions are presentation state only.

- Editing text updates the graph; editing a supported node/edge updates that same
  document. Invalid text remains editable but cannot be applied through the graph.
- Node kinds represent sources, concrete endpoints/pools, selectors, route targets,
  DNS and interface bindings. Preserve routing precedence explicitly: crossing
  wires or moving a node must not reorder rules.
- Unsupported constructs remain in the protected source, with read-only graph
  sections and paths. Graph edits must preserve their values; unsupported execution
  remains blocked by existing backend validation, not silently removed.
- Use existing strict JSON initially. Disclose formatting normalization in the
  save preview; do not claim comment-preserving JSONC support.
- Credentials are protected vault references in the normal editable document.
  Never copy UUIDs, passwords or source tokens into graph labels, diagnostics,
  logs or effective-config previews.

## States, failures and apply

- Draft, saved and running revisions are distinct and visibly identified.
- Missing, duplicate or ambiguous endpoint identity is an unresolved reference,
  not permission to select an arbitrary alias or the first matching server.
  Identity must survive representation/credential changes while distinguishing
  genuinely different logical entries sharing a first hop.
- Show validation location, reason and recovery action at the affected node/edge
  and corresponding text path. A successful client parse is not proof of daemon
  acceptance: preview must include the privileged backend's safe validation result.
- Failed parse, validation or save retains the draft and last saved/running state.
  Saving does not silently reconnect. If a change requires restart, show that fact
  and require an explicit apply/reconnect action with a diff.
- External tunnels and generated TUN/routes are observed or derived overlays,
  never presented as editable saved nodes owned by this profile.

## Verification and boundary

Exercise text → graph → text with supported and opaque sections; missing and
duplicate endpoint references; ordered rules; failed daemon validation; stale
concurrent saves; and saved-versus-running differences. No case may silently
retarget pinned traffic, drop source settings, expose secrets or restart a tunnel.
Initial runtime verification targets the Linux client. Native macOS implementation
and native Windows validation are separate platform work, not implied by this plan.

## Using the Linux editor

Select a connection under Profiles and choose **Nodes / JSON**. Nodes, JSON and
the split view edit one draft. Select a node to edit its fields or choose its
connection target; dragging moves presentation only, while explicit move buttons
change ordered array entries. The canvas contains configured blocks and their
referenced endpoints, not the entire subscription catalog or empty feature
sections. **Add block** opens a searchable catalog of supported functions; choosing
one creates and selects an editable block in the same JSON draft. Incomplete new
blocks and unresolved references remain visible. The connection target picker
retains the full available endpoint catalog.

**Check draft** validates against the saved profile and catalog revision. Xray
TUN uses the daemon's pure `xray.validate` operation; other backends explicitly
identify local-only validation. Invalid or ambiguous references show their
profile JSON paths. Unsupported settings remain visible/read-only, and saves
reject unknown fields rather than silently discarding them.

**Save profile** keeps the current tunnel running. **Review reconnect** shows
changed paths and warns about interruption before an explicit revision-bound
apply. A running revision that cannot be proven is shown as unknown, not assumed
to match the saved file. Opaque vault references cannot be moved into unrelated
fields or replaced with arbitrary source paths.

## Subscription record identity

Endpoint keys are opaque persisted 16-hex IDs, scoped to the subscription catalog,
not hashes of a server address. A name unique in both catalog history and the next
response retains its ID when the provider changes address, port, credentials or
transport. A unique credential-insensitive whole-configuration fingerprint can
match a renamed record. Ambiguous matches, including simultaneous name and
connection changes, receive new IDs; old references remain unresolved.

The protected catalog keeps non-secret name/fingerprint hashes for removed nodes.
Primary, backup, pool, pinned, DNS, service-check and named-exit references migrate
together. A colliding legacy key is resolved only with unambiguous saved evidence,
not catalog order. Missing pins remain fail-closed. Migration is restartable and
does not reconnect a running tunnel.

Stop older GUI/runtime processes before deploying this catalog cutover; older
clients do not understand record IDs. Do not rewrite a live legacy catalog while
those clients are still in use.

## Provider endpoint graphs

Linux TUN preserves a supported source's default proxy selection graph: candidate
servers, transport dependencies, balancers and nested fallback chains. It does not
replace a multi-server source with its first proxy. Primary, backup, pinned, DNS,
named-exit and temporary-check paths use the same graph representation.

Each graph has isolated canonical outbound/balancer tags. Prefix selectors become
exact scoped candidate tags; scoped loopback dispatch cannot retarget a different
source. App routing, DNS, guards and pins remain authoritative over ordinary
traffic; provider-specific domain bypass rules are not imported.

Xray observation is per process. Sources using the same observation implementation
share the primary source's probe settings (or the first observing source when the
primary has none), while all scoped subjects are included. Individual source
strategies and candidate/fallback graphs remain intact. Different observation
implementations, routing scripts, cycles, missing required dependencies and
unrepresentable graph options are rejected explicitly. An absent optional terminal
fallback becomes a scoped blackhole, never an implicit direct route.

Temporary checks wait for bounded observation initialization separately from their
listener startup and HTTP request budgets. Cleanup is awaited on every outcome.
The daemon independently validates graph closure, namespaces, strategies,
observation subjects and transport fields. Explicit profile interface bindings
are allowed only on non-source freedom outbounds with bounded interface names;
provider graphs cannot inject them.

Rejected backup, pinned and DNS references retain their record ID and safe
conversion reason. Runtime verification of these graphs targets Linux; this does
not establish native Windows/macOS execution or TUN/network-mutation coverage.