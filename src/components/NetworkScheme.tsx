import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import { tr, useLanguage } from "../i18n";
import type { NetworkEditorState, ProfileEditorSession } from "../profileEditing";
import type { ProfileDocument } from "../profileDocument";
import type { NetworkInterface, Profile, RouteEntry, RouteMap, SubscriptionEndpointInfo, SystemProxyStatus, TunnelStatus } from "../types";
import ProfileDocumentEditor from "./profiles/ProfileDocumentEditor";
import RouteTracePanel from "./RouteTracePanel";
import Skeleton from "./ui/Skeleton";
import "./NetworkScheme.css";

type Mode = "setup" | "applied";
interface Snapshot {
  profiles: Profile[];
  statuses: TunnelStatus[];
  interfaces: NetworkInterface[];
  routes: RouteMap | null;
  proxy: SystemProxyStatus | null;
}
interface Props {
  focusProfileId: string | null;
  onFocusProfile: (id: string | null) => void;
  onEditorState: (state: NetworkEditorState) => void;
}
const EMPTY: Snapshot = { profiles: [], statuses: [], interfaces: [], routes: null, proxy: null };
const nameOf = (value: string, fallback: string) => /[a-z][a-z\d+.-]*:\/\/|[0-9a-f]{8}-[0-9a-f-]{27,}/i.test(value)
  ? fallback : value.replace(/[\r\n\t]/g, " ").slice(0, 120) || fallback;
const proxyOnly = (profile: Profile) => profile.backend === "xray" && profile.xrayMode === "socks" || profile.backend === "mihomo" && profile.mihomo?.mode === "proxy";
function captureLabel(profile: Profile): string {
  if (proxyOnly(profile)) return profile.useSystemProxy ? tr("Applications using the user proxy") : tr("Applications explicitly using this proxy");
  const networks = profile.tunnelNetworks?.length ? profile.tunnelNetworks : profile.routes.map((route) => route.destination);
  if (networks.length) return networks.slice(0, 2).join(", ") + (networks.length > 2 ? ` +${networks.length - 2}` : "");
  if (profile.tunnelRole === "secondary") return tr("No carried networks configured");
  return tr("Default traffic, subject to connection rules");
}
function routesOf(iface: string, routes: RouteEntry[]): RouteEntry[] { return routes.filter((route) => route.interfaceName === iface); }
const stateLabel = (state: string) => tr(({ running: "Running", stopped: "Stopped", failed: "Failed", up: "Up", down: "Down" } as Record<string, string>)[state] ?? "Unknown");
const backendLabel = (backend: string) => ({ xray: "Xray", mihomo: "Mihomo", wireGuard: "WireGuard", openVpn: "OpenVPN" } as Record<string, string>)[backend] ?? tr("Interface");

export default function NetworkScheme({ focusProfileId, onFocusProfile, onEditorState }: Props) {
  useLanguage();
  const [mode, setMode] = useState<Mode>("setup");
  const [snapshot, setSnapshot] = useState<Snapshot>(EMPTY);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<string[]>([]);
  const [observedAt, setObservedAt] = useState<Date | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedInterface, setSelectedInterface] = useState<string | null>(null);
  const [session, setSession] = useState<ProfileEditorSession | null>(null);
  const [defaultSession, setDefaultSession] = useState<ProfileEditorSession | null>(null);
  const [rememberedProfile, setRememberedProfile] = useState<Profile | null>(null);
  const [contextError, setContextError] = useState<string | null>(null);
  const [snapshotVersion, setSnapshotVersion] = useState(0);
  const mounted = useRef(true);
  const refreshInFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    const results = await Promise.allSettled([
      invoke<Profile[]>("get_profiles"), invoke<TunnelStatus[]>("get_tunnel_statuses"),
      invoke<NetworkInterface[]>("get_interfaces"), invoke<RouteMap>("get_route_map", { includeInactive: true }),
      invoke<SystemProxyStatus>("system_proxy_status"),
    ] as const);
    refreshInFlight.current = false;
    if (!mounted.current) return;
    const names = ["Connections", "Connection status", "Interfaces", "Kernel routes", "User proxy"];
    setErrors(results.flatMap((result, index) => result.status === "rejected" ? [`${tr(names[index])}: ${String(result.reason)}`] : []));
    setSnapshot((previous) => ({
      profiles: results[0].status === "fulfilled" ? results[0].value : previous.profiles,
      statuses: results[1].status === "fulfilled" ? results[1].value : [],
      interfaces: results[2].status === "fulfilled" ? results[2].value : [],
      routes: results[3].status === "fulfilled" ? results[3].value : null,
      proxy: results[4].status === "fulfilled" ? results[4].value : null,
    }));
    setLoading(false); setRefreshing(false); setObservedAt(new Date());
  }, []);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    const update = () => { void refresh(); };
    window.addEventListener("route-changed", update);
    const interval = window.setInterval(update, 5000);
    return () => { mounted.current = false; window.clearInterval(interval); window.removeEventListener("route-changed", update); };
  }, [refresh]);
  const sessionChanged = useCallback((next: ProfileEditorSession | null) => setSession(next), []);
  useEffect(() => {
    onEditorState({ dirty: session?.dirty ?? false, busy: session?.busy ?? false });
  }, [session?.dirty, session?.busy, onEditorState]);
  useEffect(() => () => onEditorState({ dirty: false, busy: false }), [onEditorState]);
  useEffect(() => { if (focusProfileId) setSelectedInterface(null); }, [focusProfileId]);

  const listedProfile = snapshot.profiles.find((profile) => profile.id === focusProfileId) ?? null;
  useEffect(() => { if (listedProfile) setRememberedProfile(listedProfile); else if (!focusProfileId) setRememberedProfile(null); }, [listedProfile, focusProfileId]);
  const selectedProfile = listedProfile ?? (rememberedProfile?.id === focusProfileId ? rememberedProfile : null);
  const currentStatus = selectedProfile ? snapshot.statuses.find((status) => status.profileId === selectedProfile.id) : undefined;
  const runningProfiles = snapshot.profiles.filter((profile) => snapshot.statuses.some((status) => status.profileId === profile.id && status.state === "running"));
  const defaultCandidates = runningProfiles.filter((profile) => profile.tunnelRole !== "secondary");
  const proxyOwner = runningProfiles.find((profile) => profile.id === snapshot.proxy?.ownerProfileId);
  const defaultProfile = proxyOwner ?? (defaultCandidates.length === 1 ? defaultCandidates[0] : null);
  const defaultFingerprint = useMemo(() => JSON.stringify(defaultProfile), [defaultProfile]);
  useEffect(() => {
    setContextError(null);
    if (selectedProfile || !defaultProfile) { setDefaultSession(null); return; }
    let cancelled = false;
    setDefaultSession(null);
    void invoke<{ document: ProfileDocument; revision: string; runningRevision: string | null; endpoints: SubscriptionEndpointInfo[] }>("get_profile_document", { id: defaultProfile.id })
      .then((result) => { if (!cancelled) setDefaultSession({ profileId: defaultProfile.id, ...result, dirty: false, busy: false }); })
      .catch((failure: unknown) => { if (!cancelled) setContextError(failure instanceof Error ? failure.message : String(failure)); });
    return () => { cancelled = true; };
  }, [selectedProfile?.id, defaultFingerprint, snapshotVersion]);
  const traceContext = selectedProfile ? session?.profileId === selectedProfile.id ? session : null : defaultSession;
  const traceProfile = selectedProfile ?? defaultProfile;
  const effective = snapshot.routes?.effective ?? [];
  const ownedInterfaces = new Set(snapshot.statuses.flatMap((status) => {
    const profile = snapshot.profiles.find((item) => item.id === status.profileId);
    return profile && profile.backend !== "none" && !proxyOnly(profile) && status.state === "running" && status.interfaceName ? [status.interfaceName] : [];
  }));
  const routedInterfaces = new Set(effective.map((route) => route.interfaceName));
  const relevantInterfaces = snapshot.interfaces.filter((iface) => iface.physical || ownedInterfaces.has(iface.name) || ["vpn", "tunnel", "filter"].includes(iface.category) || iface.category !== "system" && routedInterfaces.has(iface.name));
  const externalInterfaces = relevantInterfaces.filter((iface) => !iface.physical && !ownedInterfaces.has(iface.name));
  const appliedInterfaces = relevantInterfaces.filter((iface) => routesOf(iface.name, effective).length > 0);
  const selectedObserved = snapshot.interfaces.find((iface) => iface.name === (selectedInterface ?? currentStatus?.interfaceName));

  const mayLeave = async () => !session?.busy && (!session?.dirty || await confirm(tr("Discard unsaved profile changes?"), { title: tr("Network scheme"), kind: "warning" }));
  const focus = async (id: string | null) => {
    if (id === focusProfileId && !selectedInterface) return;
    if (!await mayLeave()) return;
    setSession(null); setSelectedInterface(null); onFocusProfile(id);
  };
  const inspectInterface = async (name: string) => {
    if (!await mayLeave()) return;
    setSession(null); onFocusProfile(null); setSelectedInterface(name);
  };
  const saved = async () => { await refresh(); setSnapshotVersion((value) => value + 1); };
  const profileForInterface = (name: string) => snapshot.profiles.find((profile) => snapshot.statuses.some((status) => status.profileId === profile.id && status.state === "running" && status.interfaceName === name));
  const routeSummary = (routes: RouteEntry[]) => routes.slice(0, 2).map((route) => `${route.destination}/${route.prefixLen}`).join(", ") + (routes.length > 2 ? ` +${routes.length - 2}` : "");

  return <section className="network-scheme" aria-label={tr("Network scheme")}>
    <header className="network-scheme-header">
      <div><h2>{tr("Network scheme")}</h2><p>{tr("See which traffic uses each connection. Open a connection to change its rules.")}</p></div>
      <div className="network-scheme-controls"><div className="segmented" aria-label={tr("Scheme mode")}>
        <button type="button" aria-pressed={mode === "setup"} disabled={session?.busy} onClick={() => setMode("setup")}>{tr("Setup")}</button>
        <button type="button" aria-pressed={mode === "applied"} disabled={session?.busy} onClick={() => setMode("applied")}>{tr("Applied")}</button>
      </div><button type="button" className="btn-sm" disabled={refreshing} onClick={() => { void refresh(); setSnapshotVersion((value) => value + 1); }}>{tr("Refresh observations")}</button></div>
    </header>
    <p className="network-scheme-legend">{mode === "setup" ? tr("Configured paths, not measured traffic. Opening or saving a connection never reconnects it.") : tr("Observed kernel routes and service status. Application routing is unknown unless its running revision is confirmed.")}</p>
    {errors.length > 0 && <div className="save-notice" role="alert"><strong>{tr("Some network observations are unavailable.")}</strong><ul>{errors.map((error, index) => <li key={index}>{error}</li>)}</ul></div>}
    {focusProfileId && !listedProfile && !loading && <p className="save-notice">{tr("The selected connection is no longer saved. Copy any draft you need before leaving this view.")}{!selectedProfile && <button type="button" className="btn-sm" onClick={() => { void focus(null); }}>{tr("Back to network overview")}</button>}</p>}
    <details className="network-trace-container" open={!focusProfileId && !selectedInterface}><summary>{tr("Explain a destination")}</summary>
      {contextError && <p className="save-notice" role="alert">{tr("Saved rules could not be loaded for explanation.")} {tr(contextError)}</p>}
      <RouteTracePanel mode={mode} context={traceContext} profile={traceProfile} />
    </details>
    <details className="network-overview-container" open={!focusProfileId && !selectedInterface}><summary>{tr("Network overview")}</summary>
    {loading ? <Skeleton height="220px" /> : <div className="network-overview" aria-label={mode === "setup" ? tr("Configured network") : tr("Observed network")}>
      <div className="network-overview-head"><span>{tr("Which traffic")}</span><span>{tr("Connection or output")}</span></div>
      {mode === "setup" ? <>
        {snapshot.profiles.map((profile) => {
          const status = snapshot.statuses.find((item) => item.profileId === profile.id);
          return <div className="network-branch" key={profile.id}>
            <div className="network-capture"><strong>{captureLabel(profile)}</strong><small>{tr("Configured scope")}</small></div>
            <span className="network-flow-connector" aria-hidden="true" />
            <button className={`network-connection${focusProfileId === profile.id ? " selected" : ""}`} type="button" disabled={session?.busy} onClick={() => { void focus(profile.id); }}>
              <strong>{nameOf(profile.name, tr("Connection"))}</strong><span>{backendLabel(profile.backend)} · {status ? stateLabel(status.state) : tr("Status unknown")}</span>
              {status?.interfaceName && <code>{status.interfaceName}</code>}
            </button>
          </div>;
        })}
        {externalInterfaces.map((iface) => <div className="network-branch external" key={iface.name}>
          <div className="network-capture"><strong>{routeSummary(routesOf(iface.name, effective)) || tr("Scope not observed")}</strong><small>{tr("Observed kernel routes")}</small></div>
          <span className="network-flow-connector" aria-hidden="true" />
          <button type="button" className={`network-connection${selectedInterface === iface.name ? " selected" : ""}`} disabled={session?.busy} onClick={() => { void inspectInterface(iface.name); }}><strong>{nameOf(iface.friendlyName, iface.name)}</strong><code>{iface.name}</code><span>{tr("Observed network — read-only")} · {stateLabel(iface.state)}</span></button>
        </div>)}
        {relevantInterfaces.filter((iface) => iface.physical).map((iface) => <div className="network-branch external" key={iface.name}>
          <div className="network-capture"><strong>{tr("Direct / local network output")}</strong><small>{tr("Physical uplink; VPN rules may take precedence")}</small></div>
          <span className="network-flow-connector" aria-hidden="true" />
          <button type="button" className="network-connection" disabled={session?.busy} onClick={() => { void inspectInterface(iface.name); }}><strong>{nameOf(iface.friendlyName, iface.name)}</strong><code>{iface.name}</code><span>{stateLabel(iface.state)}</span></button>
        </div>)}
        {snapshot.profiles.length === 0 && externalInterfaces.length === 0 && <p className="empty-state">{tr("No connections to show. Add a connection in Profiles.")}</p>}
      </> : <>
        {!snapshot.routes ? <p className="runtime-notice">{tr("Kernel route observations are unavailable. No path is marked as confirmed.")}</p> : appliedInterfaces.map((iface) => {
          const owner = profileForInterface(iface.name);
          return <div className="network-branch" key={iface.name}>
            <div className="network-capture"><strong>{routeSummary(routesOf(iface.name, effective))}</strong><small>{tr("Observed destination prefixes")}</small></div>
            <span className="network-flow-connector" aria-hidden="true" />
            <button type="button" className="network-connection" disabled={session?.busy} onClick={() => { if (owner && !iface.physical) void focus(owner.id); else void inspectInterface(iface.name); }}><strong>{iface.physical ? tr("Physical network") : nameOf(iface.friendlyName, iface.name)}</strong><code>{iface.name}</code>{owner && <small>{tr("Connection")}: {nameOf(owner.name, tr("Connection"))}</small>}<span>{tr("Route present in the kernel")}</span></button>
          </div>;
        })}
        {snapshot.routes && appliedInterfaces.length === 0 && <p className="runtime-notice">{tr("No matching kernel routes were observed. This does not confirm application proxy rules.")}</p>}
        {runningProfiles.filter(proxyOnly).map((profile) => <div className="network-proxy-observation" key={profile.id}><strong>{nameOf(profile.name, tr("Connection"))}</strong><span>{tr("Proxy service running; no kernel traffic path is inferred.")}</span><button type="button" className="btn-sm" onClick={() => { void focus(profile.id); }}>{tr("Inspect connection")}</button></div>)}
      </>}
    </div>}
    </details>
    {observedAt && <p className="row-hint">{tr("Last observation attempt at {time}", { time: observedAt.toLocaleTimeString() })}</p>}
    {selectedProfile && <section className="network-connection-detail" aria-label={tr("Selected connection")}>
      <header><h2>{nameOf(selectedProfile.name, tr("Connection"))}</h2><button type="button" className="btn-sm" disabled={session?.busy} onClick={() => { void focus(null); }}>{tr("Back to network overview")}</button></header>
      <p className="row-hint">{tr("Rules below only affect traffic captured by this connection.")} {captureLabel(selectedProfile)}</p>
      <div hidden={mode !== "setup"}><ProfileDocumentEditor key={selectedProfile.id} profileId={selectedProfile.id} status={currentStatus} interfaces={snapshot.interfaces} onSaved={saved} onSessionChange={sessionChanged} /></div>
      {mode === "applied" && <div className="network-applied-detail">
        <p>{tr("Service status")}: <strong>{currentStatus ? stateLabel(currentStatus.state) : tr("Unknown")}</strong></p>
        {currentStatus?.message && <p className="runtime-notice">{currentStatus.message}</p>}
        <p className="runtime-notice">{tr("Saved rules are not proof of running rules. Use Setup to edit; only observed routes are listed here.")}</p>
        <ObservedInterface iface={selectedObserved} routes={effective} />
        {currentStatus?.watchdog?.anomalies.map((message, index) => <p className="runtime-notice" key={index}>{message}</p>)}
      </div>}
    </section>}
    {selectedInterface && <section className="network-connection-detail"><header><h2>{tr("Interface")}</h2><button type="button" className="btn-sm" onClick={() => setSelectedInterface(null)}>{tr("Close")}</button></header><p className="row-hint">{tr("Interfaces are observed runtime state, not editable profile nodes.")}</p><ObservedInterface iface={selectedObserved} routes={effective} /></section>}
  </section>;
}

function ObservedInterface({ iface, routes }: { iface: NetworkInterface | undefined; routes: RouteEntry[] }) {
  if (!iface) return <p className="runtime-notice">{tr("No interface was observed for this connection. Proxy-only connections may not create one.")}</p>;
  const observedRoutes = routesOf(iface.name, routes);
  return <div className="network-observed-interface">
    <dl><div><dt>{tr("Interface")}</dt><dd>{iface.name}</dd></div><div><dt>{tr("State")}</dt><dd>{stateLabel(iface.state)}</dd></div><div><dt>{tr("DNS")}</dt><dd>{iface.dnsServers.join(", ") || tr("Unknown")}</dd></div></dl>
    <details><summary>{tr("Observed kernel routes")} ({observedRoutes.length})</summary><ul>{observedRoutes.map((route, index) => <li key={index}><code>{route.destination}/{route.prefixLen}</code>{route.gateway ? ` · ${route.gateway}` : ""}</li>)}</ul></details>
  </div>;
}
