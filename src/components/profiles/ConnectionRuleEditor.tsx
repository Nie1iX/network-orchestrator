import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { tr } from "../../i18n";
import type { NetworkInterface, SubscriptionEndpointInfo } from "../../types";
import { type JsonValue, type ProfileDocument, changeRoutingRuleLayer, connectDocumentNode, moveRoutingRule, removeDocumentValue, setDocumentValue } from "../../profileDocument";
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
const categories = [["routes", "Policy route"]] as const;
function getRules(document: ProfileDocument): Rule[] {
  const routing = document.profile.routing;
  if (routing === null || typeof routing !== "object" || Array.isArray(routing)) return [];
  return (["user", "base"] as const).flatMap((layer) => {
    const values = routing[layer];
    return Array.isArray(values) ? values.flatMap((value, index) => value !== null && typeof value === "object" && !Array.isArray(value)
      ? [{ path: `/profile/routing/${layer}/${index}`, key: "routing", index, kind: layer === "user" ? "User rule" : "Base rule", value: value as Record<string, JsonValue> }] : []) : [];
  }).concat(categories.flatMap(([key, kind]) => {
    const values = document.profile[key];
    return Array.isArray(values) ? values.flatMap((value, index) => value !== null && typeof value === "object" && !Array.isArray(value)
      ? [{ path: `/profile/${key}/${index}`, key, index, kind, value: value as Record<string, JsonValue> }] : []) : [];
  }));
}
function selectorKey(rule: Rule): string { return rule.key === "routes" ? "destination" : "selectors"; }
function selector(rule: Rule): string {
  const value = rule.value[selectorKey(rule)];
  return Array.isArray(value) ? value.join(", ") : String(value ?? rule.value.destination ?? "");
}
function outputId(rule: Rule): string {
  const target = rule.value.target;
  if (target !== null && typeof target === "object" && !Array.isArray(target)) {
    if (target.kind === "node") return `node:${target.endpointKey}`;
    if (target.kind === "interface") return `interface:${target.interfaceName}`;
    if (typeof target.kind === "string") return target.kind;
  }
  return rule.key === "routes" ? "proxy" : "";
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
  const [draftKind, setDraftKind] = useState(xray ? "routing" : "routes");
  const [draftSelector, setDraftSelector] = useState("");
  const [draftExit, setDraftExit] = useState("proxy");
  const [notice, setNotice] = useState<string | null>(null);
  const [selectorDraft, setSelectorDraft] = useState<{ path: string; text: string; encoded: string } | null>(null);
  const viewportRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLDivElement>(null);
  const connectionName = typeof document.profile.name === "string" ? document.profile.name : tr("This connection");
  const subscriptionValue = document.profile.subscription;
  const subscription = subscriptionValue !== null && typeof subscriptionValue === "object" && !Array.isArray(subscriptionValue) ? subscriptionValue : null;
  const dnsValue = document.profile.xrayDns;
  const dns = dnsValue !== null && typeof dnsValue === "object" && !Array.isArray(dnsValue) ? dnsValue : null;
  const selectedLayer = selected?.path.match(/^\/profile\/routing\/(base|user)\//)?.[1] as "base" | "user" | undefined;
  const selectedList = selectedLayer && document.profile.routing !== null && typeof document.profile.routing === "object" && !Array.isArray(document.profile.routing)
    ? document.profile.routing[selectedLayer] : selected ? document.profile[selected.key] : null;
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
  const availableKinds = xray ? [["routing", "Site or network"]] : mihomo ? [] : [["routes", "IP network"]];
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
  const canRewire = (rule: Rule) => xray && rule.key === "routing";
  const choicesFor = (_rule: Rule) => exits;
  const convertExit = (rule: Rule, id: string) => {
    if (disabled || !canRewire(rule) || !exits.some((exit) => exit.id === id && !exit.unavailable)) return;
    onChange(connectDocumentNode(document, rule.path, id));
  };
  const addRule = () => {
    if (disabled || !availableKinds.length) return;
    try {
      const selectors = newSelectors(draftSelector);
      const exit = exits.find((item) => item.id === draftExit);
      if (!selectors.length || !exit || exit.unavailable) return;
      if (draftKind === "routes") {
        const current = document.profile.routes;
        const list = Array.isArray(current) ? current : [];
        onChange(setDocumentValue(document, "/profile/routes", [...list, ...selectors.map((destination) => ({ destination, metric: 0 }))]));
        onSelect(`/profile/routes/${list.length}`);
      } else {
        const target: Record<string, JsonValue> = draftExit.startsWith("node:") ? { kind: "node", endpointKey: draftExit.slice(5) }
          : draftExit.startsWith("interface:") ? { kind: "interface", interfaceName: draftExit.slice(10) } : { kind: draftExit };
        const routing = document.profile.routing;
        const hasRouting = routing !== null && typeof routing === "object" && !Array.isArray(routing);
        const user = hasRouting && Array.isArray(routing.user) ? routing.user : [];
        const withRouting = hasRouting ? document : setDocumentValue(document, "/profile/routing", { base: [], user: [] });
        onChange(setDocumentValue(withRouting, "/profile/routing/user", [...user, { selectors, target }]));
        onSelect(`/profile/routing/user/${user.length}`);
      }
      setAdding(false); setDraftSelector(""); setNotice(null);
    } catch { setNotice(tr("Enter a site or network without credentials.")); }
  };
  const reorder = (rule: Rule, offset: number) => {
    if (disabled || rule.key !== "routing" || !selectedLayer) {
      if (disabled || rule.key !== "routes" || !Array.isArray(document.profile.routes)) return;
      const list = document.profile.routes;
      if (rule.index + offset < 0 || rule.index + offset >= list.length) return;
      const next = [...list]; [next[rule.index], next[rule.index + offset]] = [next[rule.index + offset], next[rule.index]];
      onChange(setDocumentValue(document, "/profile/routes", next)); onSelect(`/profile/routes/${rule.index + offset}`); return;
    }
    onChange(moveRoutingRule(document, selectedLayer, rule.index, offset));
    onSelect(`${rule.path.replace(/\/\d+$/, `/${rule.index + offset}`)}`); setPositions({});
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
    <header><div><h2>{tr("Connection rules")}</h2><p>{tr(xray ? "User rules run before Base, in the listed order. Moving cards only changes the layout." : "IP routes use kernel prefix and metric precedence, not card order.")}</p></div>
      <button type="button" className="btn-sm" disabled={disabled || !availableKinds.length} onClick={() => setAdding((value) => !value)}>{tr("Add rule")}</button></header>
    {mihomo && <p className="runtime-notice">{tr("Mihomo routing remains in its native configuration; Xray rules are not added here.")}</p>}
    {xray && <p className="runtime-notice">{tr("IP selectors use IPOnDemand. Required User IP checks fail closed when DNS is unavailable. Proxy overrides and explicit server rules protect application DNS through the proxy, even when resolver settings request direct.")}</p>}
    {notice && <p className="save-notice" role="status">{notice}</p>}
    {adding && <div className="connection-rule-add">
      <label>{tr("Condition type")}<select disabled={disabled} value={draftKind} onChange={(event) => { setDraftKind(event.target.value); setDraftExit("proxy"); }}>{availableKinds.map(([key, label]) => <option key={key} value={key}>{tr(label)}</option>)}</select></label>
      <label>{tr("Site or network")}<textarea disabled={disabled} value={draftSelector} onChange={(event) => setDraftSelector(event.target.value)} placeholder={draftKind === "routing" ? tr("example.com or 10.10.0.0/16") : tr("10.10.0.0/16")}/></label>
      {draftKind === "routing" && <label>{tr("Output")}<select disabled={disabled} value={draftExit} onChange={(event) => setDraftExit(event.target.value)}>{exits.map((exit) => <option key={exit.id} value={exit.id} disabled={exit.unavailable}>{optionLabel(exit)}</option>)}</select></label>}
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
      {selected.key === "routes" && <><label>{tr("Metric")}<input type="number" min="0" disabled={disabled} value={Number(selected.value.metric ?? 0)} onChange={(event) => updateField(selected, "metric", Number(event.target.value))}/></label><label>{tr("Gateway")}<input disabled={disabled} value={String(selected.value.via ?? "")} onChange={(event) => updateField(selected, "via", event.target.value || null)}/></label></>}
      <div className="connection-rule-actions">
        {selected.key === "routing" && selectedLayer && <label>{tr("Layer")}<select disabled={disabled} value={selectedLayer} onChange={(event) => {
          const destination = event.target.value as "base" | "user";
          const next = changeRoutingRuleLayer(document, selectedLayer, selected.index, destination);
          const nextRouting = next.profile.routing;
          const nextRows = nextRouting !== null && typeof nextRouting === "object" && !Array.isArray(nextRouting) ? nextRouting[destination] : null;
          onChange(next); onSelect(`/profile/routing/${destination}/${Array.isArray(nextRows) ? nextRows.length - 1 : 0}`); setPositions({});
        }}><option value="user">{tr("User layer")}</option><option value="base">{tr("Base layer")}</option></select></label>}
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
