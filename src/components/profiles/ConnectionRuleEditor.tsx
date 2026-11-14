import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { tr } from "../../i18n";
import type { NetworkInterface, SubscriptionEndpointInfo } from "../../types";
import { type JsonValue, type ProfileDocument, removeDocumentValue, setDocumentValue } from "../../profileDocument";
import "./ConnectionRuleEditor.css";

interface Props {
  document: ProfileDocument;
  endpoints: SubscriptionEndpointInfo[];
  interfaces: NetworkInterface[];
  selectedPath: string | null;
  onSelect: (path: string) => void;
  onChange: (document: ProfileDocument) => void;
  disabled?: boolean;
}
type Rule = { path: string; key: string; index: number; kind: string; value: Record<string, JsonValue> };
type Exit = { id: string; label: string; detail?: string; unavailable?: boolean };
type Point = { x: number; y: number };
type Wire = { x1: number; y1: number; x2: number; y2: number };
type Drag = { kind: "card" | "wire"; id: string; pointerId: number; x: number; y: number; start: Point; scroll: Point };
const CONDITION_SIZE = { width: 280, height: 120 };
const OUTPUT_SIZE = { width: 240, height: 72 };
const categories = [
  ["pinnedPolicies", "Selected-server rules"], ["xrayTrafficRules", "IP and port rules"],
  ["xrayInterfaceRoutes", "Interface rules"], ["domainPolicies", "Site and network rules"], ["routes", "IP network routes"],
] as const;
function getRules(document: ProfileDocument): Rule[] {
  return categories.flatMap(([key, kind]) => {
    const values = document.profile[key];
    return Array.isArray(values) ? values.flatMap((value, index) => value !== null && typeof value === "object" && !Array.isArray(value)
      ? [{ path: `/profile/${key}/${index}`, key, index, kind, value }] : []) : [];
  });
}
function selectorKey(rule: Rule): string {
  return rule.key === "routes" ? "destination" : rule.key === "domainPolicies" ? "domains" : rule.key === "xrayTrafficRules" ? "ips" : "selectors";
}
function selector(rule: Rule): string {
  const value = rule.value[selectorKey(rule)];
  return Array.isArray(value) ? value.join(", ") : String(value ?? "");
}
function outputId(rule: Rule): string {
  if (rule.key === "routes") return "proxy";
  if (typeof rule.value.endpointKey === "string") return `node:${rule.value.endpointKey}`;
  if (typeof rule.value.interfaceName === "string") return `interface:${rule.value.interfaceName}`;
  return typeof rule.value.target === "string" ? rule.value.target : "";
}
function newSelectors(text: string): string[] {
  return text.split(/[\n,]/).map((value) => value.trim()).filter(Boolean).map((value) => {
    if (/^(?:domain|full|keyword|regexp|geosite|geoip|ip):/i.test(value) || /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d+)?$/.test(value) || /^(?=.*:.*:)[\da-f:.]+(?:\/\d+)?$/i.test(value)) return value;
    const url = new URL(value.includes("://") ? value : `https://${value}`);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Enter a site or network without credentials.");
    const host = url.hostname.replace(/^\[|\]$/g, "");
    return host.includes(":") || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) ? host : `domain:${host}`;
  });
}
function remainder(document: ProfileDocument): string {
  if (document.profile.backend === "xray") return tr("The connection's configured default output");
  if (document.profile.backend === "mihomo") return tr("Defined by the native Mihomo configuration");
  return tr("Other destinations follow system routing");
}

export default function ConnectionRuleEditor({ document, endpoints, interfaces, selectedPath, onSelect, onChange, disabled = false }: Props) {
  const rules = useMemo(() => getRules(document), [document]);
  const xray = document.profile.backend === "xray";
  const mihomo = document.profile.backend === "mihomo";
  const selected = rules.find((rule) => rule.path === selectedPath) ?? null;
  const [positions, setPositions] = useState<Record<string, Point>>({});
  const [drag, setDrag] = useState<Drag | null>(null);
  const [viewportWidth, setViewportWidth] = useState(0);
  const [adding, setAdding] = useState(false);
  const [draftKind, setDraftKind] = useState(xray ? "domainPolicies" : "routes");
  const [draftSelector, setDraftSelector] = useState("");
  const [draftExit, setDraftExit] = useState("proxy");
  const [draftPort, setDraftPort] = useState(443);
  const [draftNetwork, setDraftNetwork] = useState("tcp");
  const [notice, setNotice] = useState<string | null>(null);
  const [selectorDraft, setSelectorDraft] = useState<{ path: string; text: string; encoded: string } | null>(null);
  const viewportRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLDivElement>(null);
  const connectionName = typeof document.profile.name === "string" ? document.profile.name : tr("This connection");
  const subscriptionValue = document.profile.subscription;
  const subscription = subscriptionValue !== null && typeof subscriptionValue === "object" && !Array.isArray(subscriptionValue) ? subscriptionValue : null;
  const dnsValue = document.profile.xrayDns;
  const dns = dnsValue !== null && typeof dnsValue === "object" && !Array.isArray(dnsValue) ? dnsValue : null;
  const selectedList = selected ? document.profile[selected.key] : null;
  const selectedListLength = Array.isArray(selectedList) ? selectedList.length : 0;
  const activeEndpoint = endpoints.find((endpoint) => endpoint.key === subscription?.activeKey);
  const exits: Exit[] = [
    { id: "proxy", label: connectionName, detail: activeEndpoint && activeEndpoint.name !== connectionName ? activeEndpoint.name : tr("Connection default") },
    ...(xray ? [{ id: "direct", label: tr("Direct internet") }, { id: "block", label: tr("Block") },
      ...interfaces.map((iface) => ({ id: `interface:${iface.name}`, label: iface.friendlyName || iface.name, detail: iface.name })),
      ...endpoints.map((endpoint) => ({ id: `node:${endpoint.key}`, label: endpoint.name, detail: tr("Subscription server"), unavailable: endpoint.isMissing }))] : []),
  ];
  for (const rule of rules) {
    const id = outputId(rule);
    if (!id || exits.some((exit) => exit.id === id)) continue;
    exits.push({ id, label: id.startsWith("interface:") ? id.slice(10) : tr("Unavailable output"),
      detail: id.startsWith("interface:") ? tr("Interface not currently observed") : tr("The configured server or output is unavailable"),
      unavailable: !id.startsWith("interface:") });
  }
  const usedIds = new Set(["proxy", ...rules.map(outputId)]);
  const usedExits = exits.filter((exit) => usedIds.has(exit.id));
  const optionLabel = (exit: Exit) => {
    const kind = exit.id === "proxy" ? tr("Connection") : exit.id.startsWith("node:") ? tr("Subscription server") : exit.id.startsWith("interface:") ? tr("Interface") : null;
    return kind ? `${kind}: ${exit.label}` : exit.label;
  };
  const availableKinds = xray ? [["domainPolicies", "Site or network"], ["xrayTrafficRules", "IP and port"]] : mihomo ? [] : [["routes", "IP network"]];
  const pointFor = (id: string, index: number, output = false): Point => positions[id] ?? { x: output ? Math.max(520, viewportWidth - 272) : 16, y: 48 + index * (output ? 88 : 144) };
  const wires: Record<string, Wire> = {};
  rules.forEach((rule, index) => {
    const outputIndex = usedExits.findIndex((exit) => exit.id === outputId(rule));
    if (outputIndex < 0) return;
    const from = pointFor(`condition:${rule.path}`, index);
    const to = pointFor(`output:${outputId(rule)}`, outputIndex, true);
    wires[rule.path] = { x1: from.x + CONDITION_SIZE.width, y1: from.y + CONDITION_SIZE.height / 2,
      x2: to.x, y2: to.y + OUTPUT_SIZE.height / 2 };
  });
  const updateField = (rule: Rule, key: string, value: JsonValue) => onChange(setDocumentValue(document, `${rule.path}/${key}`, value));
  const canRewire = (rule: Rule) => xray && rule.key !== "routes";
  const choicesFor = (rule: Rule) => exits.filter((exit) => rule.key !== "xrayTrafficRules" || !exit.id.includes(":"));
  const convertExit = (rule: Rule, id: string) => {
    if (disabled || !canRewire(rule)) return;
    const exit = exits.find((item) => item.id === id);
    if (!exit || exit.unavailable) return;
    if (rule.key === "xrayTrafficRules") {
      if (id.includes(":")) { setNotice(tr("IP and port rules can only use the connection, direct internet, or block without losing their port condition.")); return; }
      updateField(rule, "target", id); return;
    }
    const key = id.startsWith("node:") ? "pinnedPolicies" : id.startsWith("interface:") ? "xrayInterfaceRoutes" : "domainPolicies";
    const targetField = key === "pinnedPolicies" ? "endpointKey" : key === "xrayInterfaceRoutes" ? "interfaceName" : "target";
    const target = id.startsWith("node:") ? id.slice(5) : id.startsWith("interface:") ? id.slice(10) : id;
    if (key === rule.key) { updateField(rule, targetField, target); return; }
    if (rule.key === "xrayInterfaceRoutes" && rule.value.domainStrategy != null && rule.value.domainStrategy !== document.profile.xrayDomainStrategy) {
      setNotice(tr("This rule has its own domain resolution strategy. Change it in JSON before moving it to another output type.")); return;
    }
    const value: Record<string, JsonValue> = { ...rule.value };
    const selectors = value[selectorKey(rule)] ?? [];
    for (const field of ["domains", "selectors", "ips", "target", "endpointKey", "interfaceName"]) delete value[field];
    value[key === "domainPolicies" ? "domains" : "selectors"] = selectors;
    value[targetField] = target;
    const destination = document.profile[key];
    const list = Array.isArray(destination) ? [...destination, value] : [value];
    const source = document.profile[rule.key];
    let next = setDocumentValue(document, `/profile/${key}`, list);
    if (Array.isArray(source)) next = setDocumentValue(next, `/profile/${rule.key}`, source.filter((_, index) => index !== rule.index));
    onChange(next); onSelect(`/profile/${key}/${list.length - 1}`); setPositions({});
    setNotice(tr("The output changed this rule's backend priority group. Check its order before applying."));
  };
  const addRule = () => {
    if (disabled || !availableKinds.some(([key]) => key === draftKind)) return;
    try {
      const selectors = newSelectors(draftSelector);
      const exit = exits.find((item) => item.id === draftExit);
      if (!selectors.length || !exit || exit.unavailable) return;
      const key = draftKind === "routes" ? "routes" : draftKind === "xrayTrafficRules" ? draftKind : draftExit.startsWith("node:") ? "pinnedPolicies" : draftExit.startsWith("interface:") ? "xrayInterfaceRoutes" : "domainPolicies";
      if (key === "xrayTrafficRules" && (draftExit.includes(":") || draftPort < 1 || draftPort > 65535 || !Number.isInteger(draftPort))) return;
      const current = document.profile[key];
      const list = Array.isArray(current) ? current : [];
      const values: JsonValue[] = key === "routes" ? selectors.map((destination) => ({ destination, metric: 0 }))
        : [key === "pinnedPolicies" ? { selectors, endpointKey: draftExit.slice(5) }
          : key === "xrayInterfaceRoutes" ? { selectors, interfaceName: draftExit.slice(10) }
          : key === "xrayTrafficRules" ? { ips: selectors, port: draftPort, network: draftNetwork, target: draftExit }
          : { domains: selectors, target: draftExit }];
      onChange(setDocumentValue(document, `/profile/${key}`, [...list, ...values]));
      onSelect(`/profile/${key}/${list.length}`); setAdding(false); setDraftSelector(""); setNotice(null);
    } catch { setNotice(tr("Enter a site or network without credentials.")); }
  };
  const reorder = (rule: Rule, offset: number) => {
    const values = document.profile[rule.key];
    if (disabled || rule.key === "routes" || !Array.isArray(values) || rule.index + offset < 0 || rule.index + offset >= values.length) return;
    const next = [...values];
    [next[rule.index], next[rule.index + offset]] = [next[rule.index + offset], next[rule.index]];
    onChange(setDocumentValue(document, `/profile/${rule.key}`, next));
    onSelect(`/profile/${rule.key}/${rule.index + offset}`); setPositions({});
  };
  useLayoutEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const resize = () => setViewportWidth(viewport.clientWidth);
    resize();
    const observer = new ResizeObserver(resize); observer.observe(viewport);
    return () => observer.disconnect();
  }, []);
  const beginDrag = (event: React.PointerEvent<HTMLElement>, kind: Drag["kind"], id: string, point: Point) => {
    if (disabled || !event.isPrimary || event.button !== 0) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    setDrag({ kind, id, pointerId: event.pointerId, x: event.clientX, y: event.clientY, start: point,
      scroll: { x: viewportRef.current?.scrollLeft ?? 0, y: viewportRef.current?.scrollTop ?? 0 } });
  };
  const pointerUp = (event: React.PointerEvent<HTMLDivElement>) => {
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (drag.kind === "wire") {
      const hit = globalThis.document.elementFromPoint(event.clientX, event.clientY)?.closest<HTMLElement>("[data-output-id]");
      const rule = rules.find((item) => item.path === drag.id);
      if (rule && hit?.dataset.outputId) convertExit(rule, hit.dataset.outputId);
    }
    setDrag(null);
  };
  const moveWithKeyboard = (event: React.KeyboardEvent<HTMLElement>, id: string, point: Point) => {
    const delta = ({ ArrowLeft: [-20, 0], ArrowRight: [20, 0], ArrowUp: [0, -20], ArrowDown: [0, 20] } as Record<string, number[]>)[event.key];
    if (disabled || !event.altKey || !delta) return;
    event.preventDefault(); setPositions((current) => ({ ...current, [id]: { x: Math.max(16, point.x + delta[0]), y: Math.max(48, point.y + delta[1]) } }));
  };
  const extent = Object.values(positions).reduce((size, point) => ({ x: Math.max(size.x, point.x + 312), y: Math.max(size.y, point.y + 160) }), { x: Math.max(800, viewportWidth), y: Math.max(360, rules.length * 144 + 64, usedExits.length * 88 + 64) });
  const selectedText = selected && selectorDraft?.path === selected.path && selectorDraft.encoded === JSON.stringify(selected.value[selectorKey(selected)]) ? selectorDraft.text : selected ? selector(selected) : "";
  return <section className="connection-rule-editor">
    <header><div><h2>{tr("Connection rules")}</h2><p>{tr(xray ? "Rules use fixed backend priority groups. Moving cards only changes the layout." : "IP routes use kernel prefix and metric precedence, not card order.")}</p></div>
      <button type="button" className="btn-sm" disabled={disabled || !availableKinds.length} onClick={() => setAdding((value) => !value)}>{tr("Add rule")}</button></header>
    {mihomo && <p className="runtime-notice">{tr("Mihomo routing remains in its native configuration; Xray rules are not added here.")}</p>}
    {notice && <p className="save-notice" role="status">{notice}</p>}
    {adding && <div className="connection-rule-add">
      <label>{tr("Condition type")}<select disabled={disabled} value={draftKind} onChange={(event) => { setDraftKind(event.target.value); setDraftExit("proxy"); }}>{availableKinds.map(([key, label]) => <option key={key} value={key}>{tr(label)}</option>)}</select></label>
      <label>{tr("Site or network")}<textarea disabled={disabled} value={draftSelector} onChange={(event) => setDraftSelector(event.target.value)} placeholder={draftKind === "domainPolicies" ? tr("example.com or 10.10.0.0/16") : tr("10.10.0.0/16")}/></label>
      {draftKind !== "routes" && <label>{tr("Output")}<select disabled={disabled} value={draftExit} onChange={(event) => setDraftExit(event.target.value)}>{exits.filter((exit) => draftKind !== "xrayTrafficRules" || !exit.id.includes(":")).map((exit) => <option key={exit.id} value={exit.id} disabled={exit.unavailable}>{optionLabel(exit)}</option>)}</select></label>}
      {draftKind === "xrayTrafficRules" && <><label>{tr("Port")}<input type="number" min="1" max="65535" disabled={disabled} value={draftPort} onChange={(event) => setDraftPort(Number(event.target.value))}/></label><label>{tr("Network")}<select disabled={disabled} value={draftNetwork} onChange={(event) => setDraftNetwork(event.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label></>}
      <button type="button" className="btn-sm" disabled={disabled || !draftSelector.trim()} onClick={addRule}>{tr("Create rule")}</button>
    </div>}
    <div className={`connection-rule-workspace${selected ? " with-inspector" : ""}`}>
    <div className="connection-rule-viewport" ref={viewportRef}><div className="connection-rule-canvas" ref={canvasRef} style={{ width: extent.x, height: extent.y }}
      onPointerMove={(event) => {
        if (!drag || drag.pointerId !== event.pointerId) return;
        if (drag.kind === "card") setPositions((current) => ({ ...current, [drag.id]: {
          x: Math.max(16, drag.start.x + event.clientX - drag.x + (viewportRef.current?.scrollLeft ?? 0) - drag.scroll.x),
          y: Math.max(48, drag.start.y + event.clientY - drag.y + (viewportRef.current?.scrollTop ?? 0) - drag.scroll.y),
        } })); else setDrag({ ...drag, x: event.clientX, y: event.clientY });
      }} onPointerUp={pointerUp} onPointerCancel={() => setDrag(null)} onLostPointerCapture={() => setDrag(null)}>
      <div className="connection-rule-lane-label condition-label">{tr("Conditions")}</div><div className="connection-rule-lane-label output-label">{tr("Outputs")}</div>
      <svg className="connection-rule-wires" aria-hidden="true">{Object.entries(wires).map(([path, line]) => <line key={path} className={path === selectedPath ? "selected" : undefined} x1={line.x1} y1={line.y1} x2={line.x2} y2={line.y2}/>)}
        {drag?.kind === "wire" && wires[drag.id] && canvasRef.current && <line className="connection-rule-wiring" x1={wires[drag.id].x1} y1={wires[drag.id].y1} x2={drag.x - canvasRef.current.getBoundingClientRect().left} y2={drag.y - canvasRef.current.getBoundingClientRect().top}/>}</svg>
      {rules.map((rule, index) => {
        const id = `condition:${rule.path}`; const point = pointFor(id, index);
        return <article key={rule.path} className={`connection-rule-card${selected?.path === rule.path ? " selected" : ""}`} style={{ left: point.x, top: point.y, ...CONDITION_SIZE }} data-condition-path={rule.path} tabIndex={0}
          onClick={() => onSelect(rule.path)} onPointerDown={(event) => { if ((event.target as HTMLElement).closest("button")) return; beginDrag(event, "card", id, point); onSelect(rule.path); }}
          onKeyDown={(event) => { moveWithKeyboard(event, id, point); if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(rule.path); } }}>
          <strong title={selector(rule)}>{selector(rule) || tr("Empty condition")}</strong><small>{tr(rule.kind)} · {rule.index + 1}</small>
          {rule.key === "xrayTrafficRules" && <small>{tr("Port {port}; {network}", { port: String(rule.value.port ?? 0), network: String(rule.value.network ?? "tcp") })}</small>}
          {rule.key === "routes" && <small>{tr("Metric {metric}", { metric: Number(rule.value.metric ?? 0) })}</small>}
          <button type="button" className="connection-rule-wire" data-condition-port={rule.path} disabled={disabled || !canRewire(rule)} aria-label={tr("Drag to rewire output")} onPointerDown={(event) => { if (canRewire(rule)) beginDrag(event, "wire", rule.path, point); }}/>
        </article>;
      })}
      {usedExits.map((exit, index) => {
        const id = `output:${exit.id}`; const point = pointFor(id, index, true);
        return <article key={exit.id} className={`connection-rule-output${exit.unavailable ? " unavailable" : ""}`} data-output-id={exit.id} style={{ left: point.x, top: point.y, ...OUTPUT_SIZE }} tabIndex={0}
          onPointerDown={(event) => beginDrag(event, "card", id, point)} onKeyDown={(event) => moveWithKeyboard(event, id, point)}>
          <strong>{exit.label}</strong>{exit.detail && <small>{exit.detail}</small>}
        </article>;
      })}
    </div></div>
    <p className="connection-rule-default">{tr("Default remainder")}: {remainder(document)}</p>
    {selected && <div className="connection-rule-inspector"><h3>{tr(selected.kind)}</h3>
      <label>{tr("Selector")}<textarea disabled={disabled} value={selectedText} onChange={(event) => {
        const text = event.target.value; const key = selectorKey(selected);
        const value = key === "destination" ? text : text.split(/[\n,]/).map((part) => part.trim()).filter(Boolean);
        setSelectorDraft({ path: selected.path, text, encoded: JSON.stringify(value) }); updateField(selected, key, value);
      }}/></label>
      {selected.key !== "routes" && <label>{tr("Output")}<select disabled={disabled || !canRewire(selected)} value={outputId(selected)} onChange={(event) => convertExit(selected, event.target.value)}>{choicesFor(selected).map((exit) => <option key={exit.id} value={exit.id} disabled={exit.unavailable}>{optionLabel(exit)}</option>)}</select></label>}
      {selected.key === "xrayTrafficRules" && <><label>{tr("Port")}<input type="number" min="1" max="65535" disabled={disabled} value={Number(selected.value.port ?? 0)} onChange={(event) => updateField(selected, "port", Number(event.target.value))}/></label><label>{tr("Network")}<select disabled={disabled} value={String(selected.value.network ?? "tcp")} onChange={(event) => updateField(selected, "network", event.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label></>}
      {selected.key === "routes" && <><label>{tr("Metric")}<input type="number" min="0" disabled={disabled} value={Number(selected.value.metric ?? 0)} onChange={(event) => updateField(selected, "metric", Number(event.target.value))}/></label><label>{tr("Gateway")}<input disabled={disabled} value={String(selected.value.via ?? "")} onChange={(event) => updateField(selected, "via", event.target.value || null)}/></label></>}
      <div className="connection-rule-actions">
        {selected.key !== "routes" && <><button type="button" className="btn-sm" disabled={disabled || selected.index === 0} onClick={() => reorder(selected, -1)}>{tr("Move up")}</button><button type="button" className="btn-sm" disabled={disabled || selected.index + 1 >= selectedListLength} onClick={() => reorder(selected, 1)}>{tr("Move down")}</button></>}
        <button type="button" className="btn-sm" disabled={disabled} onClick={() => { onChange(removeDocumentValue(document, selected.path)); onSelect(""); setPositions({}); }}>{tr("Remove rule")}</button>
      </div>
    </div>}
    </div>
    {xray && <details className="connection-rule-dns"><summary>{tr("DNS service settings")}</summary><p>{tr("DNS is separate from packet routing. Secret values are not shown here.")}</p>
      <label className="connection-rule-check"><input type="checkbox" disabled={disabled} checked={dns?.fakeDns === true} onChange={(event) => {
        onChange(setDocumentValue(document, "/profile/xrayDns", { ...dns, fakeDns: event.target.checked }));
      }}/>{tr("Enable fake DNS")}</label>
      <label>{tr("DNS query strategy")}<select disabled={disabled} value={typeof dns?.queryStrategy === "string" ? dns.queryStrategy : ""} onChange={(event) => {
        onChange(setDocumentValue(document, "/profile/xrayDns", { ...dns, queryStrategy: event.target.value || null }));
      }}><option value="">{tr("Backend default")}</option><option value="useIp">{tr("Use IP")}</option><option value="useIpv4">{tr("IPv4 only")}</option><option value="useIpv6">{tr("IPv6 only")}</option></select></label>
    </details>}
  </section>;
}
