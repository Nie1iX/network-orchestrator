import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { tr } from "../i18n";
import type { ProfileEditorSession } from "../profileEditing";
import type { NetworkPathProbe } from "../networkProbe";
import type { Profile, RouteCheckResult, RouteLookupResult } from "../types";

function normalizeTarget(value: string): { target: string; host: string } | null {
  const raw = value.trim();
  if (!raw) return null;
  const literalV6 = !raw.includes("://") && !raw.startsWith("[") && (raw.match(/:/g)?.length ?? 0) > 1;
  const url = new URL(raw.includes("://") ? raw : `https://${literalV6 ? `[${raw}]` : raw}`);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || !url.hostname) throw new Error("Enter a site or IP without credentials.");
  return { target: url.host, host: url.hostname.replace(/^\[|\]$/g, "") };
}
function literalIp(host: string): boolean {
  if (host.includes(":")) return true; // URL parsing above validates IPv6 literals.
  const parts = host.split(".");
  return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d*)$/.test(part) && Number(part) <= 255);
}

function stepLabel(label: string): string {
  const numbered = /^(pinned route|traffic rule|interface route|policy|resolver pin) #(\d+)$/.exec(label);
  const numberedLabels: Record<string, string> = {
    "pinned route": "Selected-server rule {number}", "traffic rule": "IP and port rule {number}",
    "interface route": "Interface rule {number}", policy: "Site or network rule {number}", "resolver pin": "DNS resolver route {number}",
  };
  if (numbered) return tr(numberedLabels[numbered[1]], { number: numbered[2] });
  const labels: Record<string, string> = {
    default: "Connection default", multicast: "Multicast", "private LAN": "Private networks",
    "dns capture (port 53)": "DNS capture", "traffic rule (transport unavailable)": "IP and port rule: protocol unknown",
  };
  return tr(labels[label] ?? label);
}

export default function RouteTracePanel({ mode, context, profile }: {
  mode: "setup" | "applied";
  context: ProfileEditorSession | null;
  profile: Profile | null;
}) {
  const [input, setInput] = useState("");
  const [decision, setDecision] = useState<RouteCheckResult | null>(null);
  const [lookup, setLookup] = useState<RouteLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [probe, setProbe] = useState<NetworkPathProbe | null>(null);
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [request, setRequest] = useState(0);
  const explanationId = useRef(0);
  const probeId = useRef(0);
  const parsed = useMemo(() => {
    try { return { value: normalizeTarget(input), error: null }; }
    catch { return { value: null, error: "Enter a site or IP without credentials." }; }
  }, [input]);

  useEffect(() => {
    const id = ++explanationId.current;
    ++probeId.current;
    setDecision(null); setLookup(null); setError(null); setProbe(null); setProbeError(null); setProbing(false); setExplaining(false);
    if (!parsed.value) return;
    const target = parsed.value;
    const timer = window.setTimeout(() => {
      if (mode === "setup" && context?.document && context.revision) {
        setExplaining(true);
        void invoke<RouteCheckResult>("explain_profile_document", {
          id: context.profileId, document: context.document, expectedRevision: context.revision, target: target.target,
        }).then((result) => { if (id === explanationId.current) setDecision(result); })
          .catch((failure: unknown) => { if (id === explanationId.current) setError(failure instanceof Error ? failure.message : String(failure)); })
          .finally(() => { if (id === explanationId.current) setExplaining(false); });
      } else if (literalIp(target.host)) {
        setExplaining(true);
        void invoke<RouteLookupResult>("lookup_destination", { dest: target.host })
          .then((result) => { if (id === explanationId.current) setLookup(result); })
          .catch((failure: unknown) => { if (id === explanationId.current) setError(failure instanceof Error ? failure.message : String(failure)); })
          .finally(() => { if (id === explanationId.current) setExplaining(false); });
      }
    }, 250);
    return () => { window.clearTimeout(timer); ++explanationId.current; ++probeId.current; };
  }, [parsed, mode, context?.document, context?.revision, context?.profileId, request]);

  const check = async () => {
    if (!parsed.value || probing) return;
    const id = ++probeId.current;
    setProbing(true); setProbe(null); setProbeError(null);
    try {
      const result = await invoke<NetworkPathProbe>("probe_current_path", { target: parsed.value.target });
      if (id === probeId.current) setProbe(result);
    } catch (failure) { if (id === probeId.current) setProbeError(failure instanceof Error ? failure.message : String(failure)); }
    finally { if (id === probeId.current) setProbing(false); }
  };

  const output = decision?.interfaceName ? `${tr("Interface")} · ${decision.interfaceName}`
    : decision?.endpointKey ? context?.endpoints.find((endpoint) => endpoint.key === decision.endpointKey && !endpoint.isMissing)?.name ?? tr("Pinned VPN server")
    : decision?.outbound === "proxy" ? profile?.name ?? tr("VPN")
    : decision?.outbound === "direct" ? tr("Direct internet")
    : decision?.outbound === "block" ? tr("Blocked")
    : decision?.outbound === "dns" ? tr("DNS service") : tr("Unknown");

  return <section className="network-trace" aria-label={tr("Explain a destination")}>
    <header><h3>{tr("Why does this site take this path?")}</h3><p>{tr("Typing only explains rules. Network requests start only when you press Check current path.")}</p></header>
    <form className="network-trace-form" onSubmit={(event) => { event.preventDefault(); setRequest((value) => value + 1); }}>
      <label>{tr("Site or IP")}<input value={input} onChange={(event) => setInput(event.target.value)} placeholder={tr("example.com or 10.10.0.5")} autoComplete="off" spellCheck={false} /></label>
      <button type="button" disabled={!parsed.value || probing} onClick={() => { void check(); }}>{probing ? tr("Checking…") : tr("Check current path")}</button>
    </form>
    {parsed.error && <p className="save-notice" role="alert">{tr(parsed.error)}</p>}
    {mode === "setup" && profile && <p className="row-hint">{tr("Configured rules of {name}", { name: profile.name })}{context?.dirty ? ` · ${tr("Unsaved changes")}` : ""}</p>}
    {parsed.value && <div className="network-trace-explanation" aria-live="polite">
      {explaining ? <p>{tr("Explaining…")}</p> : error ? <p className="save-notice" role="alert">{tr(error)}</p> : decision ? <>
        <div className={`network-decision ${decision.certainty === "certain" ? "" : "uncertain"}`}>
          <strong>{decision.certainty === "certain" ? tr("Configured path") : tr("Possible path — not confirmed")}</strong>
          <span>{decision.target}</span><span className="network-flow-connector" aria-hidden="true" /><span>{output}</span>
        </div>
        {decision.layer && decision.ruleIndex != null && <p className="row-hint">
          {decision.layer === "user" ? tr("User rule {number}", { number: decision.ruleIndex + 1 }) : tr("Base rule {number}", { number: decision.ruleIndex + 1 })}
        </p>}
        {decision.matchedSelector && <p className="row-hint">{tr("Matched condition: {selector}", { selector: decision.matchedSelector })}</p>}
        <details><summary>{tr("Decision details")}</summary>
        <ol className="network-trace-steps">{decision.steps.map((step, index) => <li key={index} data-outcome={step.outcome}>
          <span>{stepLabel(step.label)}</span>{step.selector && <code>{step.selector}</code>}<small>{tr(({ match: "Matched", miss: "Not matched", unknown: "Unknown", skipped: "Skipped" })[step.outcome])}</small>
        </li>)}</ol>
        {decision.notes.map((note, index) => <p className="row-hint" key={index}>{tr(note)}</p>)}
        </details>
        {decision.certainty !== "certain" && <p className="runtime-notice">{tr("An earlier unresolved condition may change the result. No DNS query was sent.")}</p>}
      </> : lookup ? <div className="network-decision"><strong>{tr("Observed kernel route")}</strong><span>{lookup.matchedRoute.destination}/{lookup.matchedRoute.prefixLen}</span><span className="network-flow-connector" aria-hidden="true" /><span>{lookup.interfaceName}</span></div>
        : <p className="runtime-notice">{mode === "setup" && profile && !context?.document ? tr("A valid connection document is required to explain its draft.") : tr("The address or running application rules are not known without a network check. No DNS query was sent.")}</p>}
    </div>}
    <p className="row-hint">{tr("Check current path tests the running network, not the saved or unsaved connection selected here.")}</p>
    {probeError && <p className="save-notice" role="alert">{tr(probeError)}</p>}
    {probe && <section className="network-probe-result" aria-live="polite">
      <h4>{probe.scope === "systemProxy" ? tr("Checked through the current user proxy") : tr("Checked through the current system route")}</h4>
      <p className="row-hint">{tr("HTTPS status confirms transport reachability, not that the website is functioning correctly.")}</p>
      <ol className="network-probe-stages">{probe.stages.map((stage) => <li key={stage.stage} data-outcome={stage.outcome}>
        <strong>{stage.stage === "dns" ? tr("DNS") : stage.stage === "route" ? tr("Route") : tr("HTTPS")}</strong>
        <span>{tr(stage.message)}</span>
        {stage.interfaceName && <code>{stage.interfaceName}</code>}
        {stage.statusCode != null && <span>HTTP {stage.statusCode}</span>}
        {stage.durationMs != null && <span className="num">{tr("{value} ms", { value: stage.durationMs })}</span>}
        <small>{tr(({ healthy: "Reachable", failed: "Failed", unknown: "Unknown" })[stage.outcome])}</small>
      </li>)}</ol>
    </section>}
  </section>;
}
