import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { tr } from "../../i18n";
import type { SubscriptionEndpointInfo } from "../../types";
import {
  buildProfileGraph,
  connectDocumentNode,
  removeDocumentValue,
  setDocumentValue,
  type DocumentIssue,
  type DocumentNode,
  type JsonValue,
  type ProfileDocument,
} from "../../profileDocument";
import "./ProfileGraph.css";

interface Props {
  document: ProfileDocument;
  endpoints: SubscriptionEndpointInfo[];
  issues: DocumentIssue[];
  selectedPath: string | null;
  onSelect: (path: string) => void;
  onChange: (document: ProfileDocument) => void;
  disabled?: boolean;
}

type EdgePoint = { x1: number; y1: number; x2: number; y2: number };

const hiddenKey = /(?:password|passwd|secret|token|credential|private.?key|uuid|share.?link|(?:config)?path|(?:endpoint|outbound|active)?key)$/i;
const parts = (path: string) => path.split("/").slice(1).map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"));
function isProtectedField(key: string): boolean {
  return hiddenKey.test(key) || key === "id" || /Id$/.test(key);
}

function getAt(document: ProfileDocument, path: string): unknown {
  return parts(path).reduce<unknown>((value, key) =>
    value !== null && typeof value === "object" ? (value as Record<string, unknown>)[key] : undefined, document);
}

function displayValue(value: unknown, path: string): string {
  const pathParts = parts(path);
  const key = pathParts.length ? pathParts[pathParts.length - 1] : "";
  if (isProtectedField(key) || typeof value === "string" && value.startsWith("vault:")) return tr("Protected value");
  if (typeof value === "string") return value.length > 120 ? `${value.slice(0, 117)}…` : value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value === null || value === undefined) return tr("Not set");
  if (Array.isArray(value)) return `${value.length} ${tr("items")}`;
  return tr("Read-only details");
}

function nodeTitle(node: DocumentNode): string {
  const byKind: Record<string, string> = {
    source: tr("Profile source"), "source-setting": tr("Source setting"), endpoint: tr("Endpoint"),
    pool: tr("Endpoint pool"), selector: tr("Routing selector"), routing: tr("Routing"),
    dns: tr("DNS"), interface: tr("Interface route"), exit: tr("Named exit"),
    target: tr("Routing target"), opaque: tr("Read-only settings"), profile: tr("Profile"),
  };
  return tr(safeUserLabel(node.label, byKind[node.kind] ?? tr("Profile item")));
}
function safeUserLabel(label: string, fallback: string): string {
  const clean = label.replace(/[\r\n\t]/g, " ").trim().slice(0, 100);
  return !clean || /^[a-z][a-z\d+.-]*:\/\//i.test(clean) || /^[0-9a-f]{32,}$/i.test(clean) ? fallback : clean;
}

function nodeDetail(document: ProfileDocument, node: DocumentNode): string {
  if (node.kind === "opaque") return tr("Read-only details");
  if (node.kind === "source" || node.kind === "source-setting") return node.detail;
  if (node.kind === "endpoint" || node.kind === "interface") return node.detail || tr(node.kind === "endpoint" ? "Endpoint" : "Interface");
  if (node.kind === "target" && node.path.startsWith("/targets/")) return tr("Routing target");
  const value = getAt(document, node.path);
  if (node.editable && value && typeof value === "object" && !Array.isArray(value)) return "";
  return displayValue(value, node.path);
}

function reorder(document: ProfileDocument, firstPath: string, secondPath: string, onChange: Props["onChange"]): void {
  const first = parts(firstPath), second = parts(secondPath);
  if (first.length !== second.length || first.slice(0, -1).join("/") !== second.slice(0, -1).join("/")) return;
  const parentPath = `/${first.slice(0, -1).join("/")}`;
  const list = getAt(document, parentPath);
  const from = Number(first[first.length - 1]), to = Number(second[second.length - 1]);
  if (!Array.isArray(list) || !Number.isInteger(from) || !Number.isInteger(to)) return;
  const next = [...list];
  next.splice(to, 0, next.splice(from, 1)[0]);
  onChange(setDocumentValue(document, parentPath, next as JsonValue));
}

export function ProfileGraph({ document, endpoints, issues, selectedPath, onSelect, onChange, disabled = false }: Props) {
  const graph = useMemo(() => buildProfileGraph(document, endpoints), [document, endpoints]);
  const { nodes } = graph;
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [dragging, setDragging] = useState<string | null>(null);
  const [connectionError, setConnectionError] = useState(false);
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [catalogSearch, setCatalogSearch] = useState("");
  const [edgePoints, setEdgePoints] = useState<Record<string, EdgePoint>>({});
  const [canvasSize, setCanvasSize] = useState({ width: 900, height: 600 });
  const canvasRef = useRef<HTMLDivElement>(null);
  const catalogTriggerRef = useRef<HTMLButtonElement>(null);
  const nodeElements = useRef(new Map<string, HTMLDivElement>());
  const dragOrigin = useRef<{ x: number; y: number } | null>(null);
  const allIssues = [...graph.issues, ...issues];
  const selected = nodes.find((node) => node.path === selectedPath) ?? nodes[0];
  const value = selected ? getAt(document, selected.path) : undefined;
  const writable = Boolean(selected?.editable && !["profile", "source", "opaque"].includes(selected.kind) && !disabled);
  const nodeIssues = (path: string) => allIssues.filter((issue) => issue.path === path || issue.path.startsWith(`${path}/`));
  const selectedIssues = selected ? nodeIssues(selected.path) : [];
  const change = (path: string, next: JsonValue) => onChange(setDocumentValue(document, path, next));
  const endpointMatches = (key: unknown) => endpoints.filter((endpoint) => endpoint.key === key);
  const referenceTarget = Boolean(selected && (
    /\/subscription\/(?:activeKey|backupKeys\/\d+)$/.test(selected.path) ||
    /\/(?:pinnedPolicies|xrayServiceChecks)\/\d+$/.test(selected.path) ||
    selected.path === "/profile/xrayDns" ||
    /\/xrayProxyExits\/\d+\/target$/.test(selected.path)
  ));
  const exitTarget = selected && /\/xrayProxyExits\/\d+\/target$/.test(selected.path) && value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, JsonValue> : null;
  const sections = [
    ["/profile/routes", "Policy route"], ["/profile/domainPolicies", "Domain policy"],
    ["/profile/pinnedPolicies", "Pinned selector"], ["/profile/xrayTrafficRules", "Traffic rule"],
    ["/profile/xrayDns/servers", "DNS server"], ["/profile/xrayInterfaceRoutes", "Interface route"],
    ["/profile/xrayProxyExits", "Named exit"], ["/profile/subscription/nodePool/filters", "Pool filter"],
    ["/profile/subscription/backupKeys", "Backup endpoint"],
    ["/profile/xrayServiceChecks", "Service check"],
  ] as const;
  const matchingSections = sections.filter(([, label]) => tr(label).toLocaleLowerCase().includes(catalogSearch.toLocaleLowerCase()));
  const newItem = (path: string): JsonValue => {
    if (path === "/profile/routes") return { destination: "", metric: 0 };
    if (path === "/profile/domainPolicies") return { domains: [], target: "proxy" };
    if (path === "/profile/pinnedPolicies") return { selectors: [], endpointKey: "" };
    if (path === "/profile/xrayTrafficRules") return { ips: [], port: 0, network: "tcp", target: "proxy" };
    if (path === "/profile/xrayDns/servers") return { address: "", port: null, domains: [], skipFallback: false, route: "none" };
    if (path === "/profile/xrayInterfaceRoutes") return { selectors: [], interfaceName: "" };
    if (path === "/profile/xrayProxyExits") return { name: "", target: { kind: "rules" } };
    if (path === "/profile/subscription/backupKeys") return { key: "", name: "" };
    if (path === "/profile/subscription/nodePool/filters") return { nameContains: [], exitCountry: null };
    if (path === "/profile/xrayServiceChecks") return { id: crypto.randomUUID(), name: "", url: "", endpointKey: "", background: false };
    return {};
  };
  const addItem = (path: string) => {
    const current = getAt(document, path);
    if (Array.isArray(current)) {
      change(path, [...current, newItem(path)] as JsonValue);
      onSelect(`${path}/${current.length}`);
      return;
    }
    if (path === "/profile/xrayDns/servers") {
      const dns = document.profile.xrayDns;
      onChange({ ...document, profile: { ...document.profile, xrayDns: { ...(dns && typeof dns === "object" && !Array.isArray(dns) ? dns : { fakeDns: false, queryStrategy: null }), servers: [newItem(path)] } } });
      onSelect(`${path}/0`);
      return;
    }
    if (path === "/profile/subscription/nodePool/filters") {
      const subscription = getAt(document, "/profile/subscription");
      if (!subscription || typeof subscription !== "object" || Array.isArray(subscription)) return;
      const record = subscription as Record<string, JsonValue>;
      const pool = record.nodePool;
      const currentPool = pool && typeof pool === "object" && !Array.isArray(pool) ? pool as Record<string, JsonValue> : null;
      const filters: JsonValue[] = currentPool && Array.isArray(currentPool.filters) ? currentPool.filters : [];
      const nextPool: JsonValue = currentPool
        ? { ...currentPool, filters: [...filters, newItem(path)] }
        : { filters: [newItem(path)], verifyExitCountry: false };
      onChange({ ...document, profile: { ...document.profile, subscription: { ...record, nodePool: nextPool } } });
      onSelect(`${path}/${filters.length}`);
      return;
    }
    const keys = parts(path);
    if (keys[0] !== "profile") return;
    if (keys.length === 2) {
      onChange({ ...document, profile: { ...document.profile, [keys[1]]: [newItem(path)] } });
      onSelect(`${path}/0`);
      return;
    }
    const parentPath = `/${keys.slice(0, -1).join("/")}`;
    const parent = getAt(document, parentPath);
    if (parent && typeof parent === "object" && !Array.isArray(parent)) {
      change(parentPath, { ...(parent as Record<string, JsonValue>), [keys[keys.length - 1]]: [newItem(path)] });
      onSelect(`${path}/0`);
    }
  };

  const reorderSelected = (direction: -1 | 1) => {
    if (!selected) return;
    const selectedParts = parts(selected.path);
    const index = Number(selectedParts[selectedParts.length - 1]);
    if (!Number.isInteger(index)) return;
    const parentPath = `/${selectedParts.slice(0, -1).join("/")}`;
    const list = getAt(document, parentPath);
    const destination = index + direction;
    if (!Array.isArray(list) || destination < 0 || destination >= list.length) return;
    reorder(document, selected.path, `${parentPath}/${destination}`, onChange);
    onSelect(`${parentPath}/${destination}`);
  };

  const moveNode = (path: string, dx: number, dy: number) => setPositions((current) => {
    const point = current[path] ?? { x: 0, y: 0 };
    return { ...current, [path]: { x: point.x + dx, y: point.y + dy } };
  });
  const connect = (target: string) => {
    if (!selected) return;
    if (target.startsWith("node:")) {
      const matches = endpointMatches(target.slice(5));
      if (matches.length !== 1 || matches[0].isMissing) {
        setConnectionError(true);
        return;
      }
    }
    setConnectionError(false);
    try {
      let next = connectDocumentNode(document, selected.path, target);
      if (/\/subscription\/backupKeys\/\d+$/.test(selected.path) && target.startsWith("node:")) {
        next = setDocumentValue(next, `${selected.path}/name`, endpointMatches(target.slice(5))[0]!.name);
      }
      onChange(next);
    }
    catch { setConnectionError(true); }
  };

  const renderNode = (node: DocumentNode) => {
    const position = positions[node.path] ?? { x: 0, y: 0 };
    return <div key={node.id} className="profile-graph-node-wrap"
      ref={(element) => { if (element) nodeElements.current.set(node.path, element); else nodeElements.current.delete(node.path); }}
      draggable={!disabled}
      onKeyDown={(event) => {
        const moves: Record<string, [number, number]> = { ArrowLeft: [-20, 0], ArrowRight: [20, 0], ArrowUp: [0, -20], ArrowDown: [0, 20] };
        if (!disabled && event.altKey && moves[event.key]) {
          event.preventDefault();
          moveNode(node.path, ...moves[event.key]);
        }
      }}
      style={{ transform: `translate(${position.x}px, ${position.y}px)` }}
      onDragStart={(event) => {
        setDragging(node.path);
        dragOrigin.current = { x: event.clientX, y: event.clientY };
        event.dataTransfer.setData("text/plain", node.path);
      }}
      onDragEnd={() => setDragging(null)}>
      <GraphNode node={node} detail={nodeDetail(document, node)} issues={nodeIssues(node.path)} active={selected?.path === node.path} onSelect={onSelect} />
    </div>;
  };

  const sources = nodes.filter((node) => node.column === 0);
  const middle = nodes.filter((node) => node.column === 1 || node.column === 2);
  const targets = nodes.filter((node) => node.column === 3);

  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const measure = () => {
      const bounds = canvas.getBoundingClientRect();
      if (!bounds.width || !bounds.height) return;
      setCanvasSize((size) => size.width === bounds.width && size.height === bounds.height ? size : { width: bounds.width, height: bounds.height });
      const points: Record<string, EdgePoint> = {};
      for (const edge of graph.edges) {
        const source = nodeElements.current.get(edge.from)?.getBoundingClientRect();
        const target = nodeElements.current.get(edge.to)?.getBoundingClientRect();
        if (!source || !target) continue;
        points[edge.id] = {
          x1: source.right - bounds.left, y1: source.top + source.height / 2 - bounds.top,
          x2: target.left - bounds.left, y2: target.top + target.height / 2 - bounds.top,
        };
      }
      setEdgePoints(points);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(canvas);
    nodeElements.current.forEach((element) => observer.observe(element));
    return () => observer.disconnect();
  }, [graph, positions]);

  return <section className="profile-graph" aria-label={tr("Editable profile graph")}>
    <div className="profile-graph-toolbar">
      <button ref={catalogTriggerRef} type="button" className="btn-sm" disabled={disabled} aria-expanded={catalogOpen} aria-controls="profile-block-catalog" onClick={() => { setCatalogOpen(!catalogOpen); setCatalogSearch(""); }}>{tr("Add block")}</button>
      {catalogOpen && <div id="profile-block-catalog" className="profile-graph-catalog" role="region" aria-label={tr("Block catalog")} onKeyDown={(event) => {
        if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); setCatalogOpen(false); catalogTriggerRef.current?.focus(); }
      }}>
        <label>{tr("Search blocks")}<input autoFocus value={catalogSearch} onChange={(event) => setCatalogSearch(event.target.value)} /></label>
        {matchingSections.length === 0 && <p className="profile-graph-muted" role="status">{tr("No matching blocks")}</p>}
        {matchingSections.map(([path, label]) => {
          const needsSubscription = path.startsWith("/profile/subscription/") && (!document.profile.subscription || typeof document.profile.subscription !== "object" || Array.isArray(document.profile.subscription));
          const needsXray = document.profile.backend !== "xray" && path !== "/profile/routes";
          const reason = needsSubscription ? tr("Requires a subscription") : needsXray ? tr("Requires an Xray profile") : "";
          return <button key={path} type="button" className="btn-sm" disabled={Boolean(reason)} title={reason || undefined} onClick={() => { addItem(path); setCatalogOpen(false); }}>
            {tr(label)}{reason && <small> — {reason}</small>}
          </button>;
        })}
      </div>}
    </div>
    <div className="profile-graph-layout">
      <div className="profile-graph-canvas" ref={canvasRef}
        onDragOver={(event) => { if (dragging) event.preventDefault(); }}
        onDrop={(event) => {
          event.preventDefault();
          const origin = dragOrigin.current;
          if (dragging && origin) moveNode(dragging, event.clientX - origin.x, event.clientY - origin.y);
          setDragging(null);
        }}>
        <div className="profile-graph-column">{sources.length > 0 && <h3>{tr("Sources")}</h3>}{sources.map(renderNode)}</div>
        <svg className="profile-graph-edges" viewBox={`0 0 ${canvasSize.width} ${canvasSize.height}`} preserveAspectRatio="none" aria-hidden="true">
          <defs><marker id="profile-document-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M 0 0 L 7 3.5 L 0 7 Z" fill="var(--accent)" /></marker></defs>
          {graph.edges.map((edge) => <GraphEdge key={edge.id} point={edgePoints[edge.id]} />)}
        </svg>
        <div className="profile-graph-column">{middle.length > 0 && <h3>{tr("Routing and DNS")}</h3>}{middle.map(renderNode)}</div>
        <div className="profile-graph-column">{targets.length > 0 && <h3>{tr("Endpoints and pools")}</h3>}{targets.map(renderNode)}</div>
      </div>
      <aside className="profile-graph-inspector" aria-label={tr("Node inspector")}>
        {selected ? <>
          <h3>{nodeTitle(selected)}</h3><code className="profile-graph-path">{selected.path}</code>
          <p className="profile-graph-muted">{nodeDetail(document, selected)}</p>
          {selectedIssues.map((issue, index) => <div className={`profile-graph-issue ${issue.severity}`} key={`${issue.path}-${index}`}>
            <code>{issue.path}</code><span>{tr(issue.message)}</span>
          </div>)}
          {typeof value === "string" && writable && ["target", "route"].includes(parts(selected.path).slice(-1)[0]) &&
            <label>{selected.label}<select value={value} onChange={(event) => change(selected.path, event.target.value)}>
              {(parts(selected.path).slice(-1)[0] === "route" ? ["none", "proxy", "direct"] : ["proxy", "direct", "block"])
                .map((choice) => <option key={choice} value={choice}>{tr(choice[0].toUpperCase() + choice.slice(1))}</option>)}
            </select></label>}
          {typeof value === "string" && writable && !referenceTarget && !["target", "route"].includes(parts(selected.path).slice(-1)[0]) &&
            <label>{selected.label}<input value={value} onChange={(event) => change(selected.path, event.target.value)} /></label>}
          {typeof value === "number" && writable && <label>{selected.label}<input type="number" value={value} onChange={(event) => change(selected.path, Number(event.target.value))} /></label>}
          {typeof value === "boolean" && writable && <label className="profile-graph-check"><input type="checkbox" checked={value} onChange={(event) => change(selected.path, event.target.checked)} />{selected.label}</label>}
          {selected.path.endsWith("/refreshIntervalMinutes") && writable && <label>{tr("Refresh interval")}<select value={value == null ? "" : String(value)} onChange={(event) => change(selected.path, event.target.value === "" ? null : Number(event.target.value))}>
            <option value="">{tr("Off")}</option>{[15, 60, 360].map((minutes) => <option key={minutes} value={minutes}>{tr("{minutes} minutes", { minutes })}</option>)}
          </select></label>}
          {exitTarget && writable && <label>{tr("Exit mode")}<select value={String(exitTarget.kind)} onChange={(event) => {
            const { endpointKey: _key, endpointKeys: _keys, kind: _kind, ...rest } = exitTarget;
            change(selected.path, { ...rest, kind: event.target.value, ...(event.target.value === "node" ? { endpointKey: "" } : event.target.value === "pool" ? { endpointKeys: [] } : {}) });
          }}>
            {["rules", "direct", "node", "pool"].map((kind) => <option key={kind} value={kind}>{tr(kind)}</option>)}
          </select></label>}
          {exitTarget?.kind === "pool" && Array.isArray(exitTarget.endpointKeys) && <ol>{exitTarget.endpointKeys.map((key, index) => <li key={index}>
            {endpointMatches(key).length === 1 ? safeUserLabel(endpointMatches(key)[0].name, tr("Endpoint")) : tr("unresolved")}
            <button type="button" className="btn-sm" disabled={!writable} aria-label={tr("Remove item")} onClick={() => change(`${selected.path}/endpointKeys`, (exitTarget.endpointKeys as JsonValue[]).filter((_, member) => member !== index))}>{tr("Remove")}</button>
          </li>)}</ol>}
          {referenceTarget && writable && <label>{tr("Connection target")}<select value="" onChange={(event) => { if (event.target.value) connect(event.target.value); }}>
            <option value="">{tr("Choose target")}</option>
            {endpoints.map((endpoint, index) => {
              const unresolved = endpointMatches(endpoint.key).length !== 1 || endpoint.isMissing;
              return <option key={`${endpoint.key}-${index}`} value={`node:${endpoint.key}`} disabled={unresolved}>
                {safeUserLabel(endpoint.name, tr("Endpoint"))}{unresolved ? ` — ${tr("unresolved")}` : ""}
              </option>;
            })}
          </select></label>}
          {connectionError && <p className="profile-graph-connection-error" role="alert">{tr("Unable to connect this reference. Choose a unique available endpoint.")}</p>}
          {value && typeof value === "object" && !exitTarget && !["opaque", "source", "source-setting"].includes(selected.kind) &&
            <ObjectFields value={value as Record<string, unknown>} path={selected.path} document={document} onChange={onChange} disabled={!writable} />}
          {selected.path !== "/profile" && selected.kind !== "profile" && selected.kind !== "endpoint" && selected.kind !== "source" && selected.kind !== "source-setting" && selected.kind !== "opaque" && selected.kind !== "target" &&
            <button type="button" className="btn-danger btn-sm" disabled={!writable} onClick={() => { onChange(removeDocumentValue(document, selected.path)); onSelect("/profile"); }}>{tr("Remove node")}</button>}
          {selected.path !== "/profile" && /^\d+$/.test(parts(selected.path).slice(-1)[0] ?? "") &&
            <div className="profile-graph-order">
              <button type="button" className="btn-sm" disabled={!writable || Number(parts(selected.path).slice(-1)[0]) === 0} onClick={() => reorderSelected(-1)}>{tr("Move up")}</button>
              <button type="button" className="btn-sm" disabled={!writable} onClick={() => reorderSelected(1)}>{tr("Move down")}</button>
            </div>}
        </> : <p>{tr("Select a node to inspect it.")}</p>}
      </aside>
    </div>
  </section>;
}

function GraphNode({ node, detail, active, issues, onSelect }: {
  node: DocumentNode; detail: string; active: boolean; issues: DocumentIssue[]; onSelect: (path: string) => void;
}) {
  return <button type="button" className={`profile-graph-node${active ? " selected" : ""}${issues.length ? " has-issue" : ""}`}
    onClick={() => onSelect(node.path)} aria-pressed={active} aria-keyshortcuts="Alt+ArrowLeft Alt+ArrowRight Alt+ArrowUp Alt+ArrowDown" title={tr("Alt + arrow keys move nodes without changing rule order.")}>
    <strong>{nodeTitle(node)}</strong><span>{detail}</span><code>{node.path}</code>
    {issues.map((issue, index) => <small key={index}>{tr(issue.message)}</small>)}
  </button>;
}

function GraphEdge({ point }: { point?: EdgePoint }) {
  if (!point) return null;
  return <path className="profile-graph-edge" markerEnd="url(#profile-document-arrow)" d={`M ${point.x1} ${point.y1} C ${(point.x1 + point.x2) / 2} ${point.y1}, ${(point.x1 + point.x2) / 2} ${point.y2}, ${point.x2} ${point.y2}`} />;
}

function ObjectFields({ value, path, document, onChange, disabled }: {
  value: Record<string, unknown>; path: string; document: ProfileDocument; onChange: Props["onChange"]; disabled: boolean;
}) {
  const scalar = (item: unknown) => item === null || typeof item === "string" || typeof item === "number" || typeof item === "boolean";
  const profileFields: Record<string, true> = {
    name: true, interfaceName: true, autoConnect: true, privateLanDirect: true,
    xraySocksPort: true, xrayHttpPort: true, useSystemProxy: true, proxyBypass: true,
    xrayMode: true, xrayTunInterface: true, xrayTunIp: true, xrayTunMtu: true,
    waitForInterface: true, xrayDomainStrategy: true, xrayDomainMatcher: true,
    xrayDirectDomainStrategy: true, xraySplitDefault: true, xrayQuicReject: true,
    xrayConnectionIdleSecs: true, xrayTunDnsServers: true, xraySockopts: true,
    tunnelRole: true, tunnelNetworks: true, tunnelDnsDomains: true, endpointBypasses: true,
  };
  const entries = Object.entries(value).filter(([key, item]) =>
    !isProtectedField(key) && (path !== "/profile" || profileFields[key] === true) &&
    !(path === "/profile" && document.profile.backend === "mihomo" && key.startsWith("xray")) &&
    (scalar(item) || Array.isArray(item) || key === "xraySockopts" && item !== null && typeof item === "object"));
  return <div className="profile-graph-fields">{entries.map(([key, item]) => {
    const fieldPath = `${path}/${key.replace(/~/g, "~0").replace(/\//g, "~1")}`;
    if (typeof item === "string" && item.startsWith("vault:")) return <label key={key}>{key}<span>{tr("Protected value")}</span></label>;
    if (typeof item === "boolean") return <label key={key} className="profile-graph-check"><input type="checkbox" disabled={disabled} checked={item} onChange={(event) => onChange(setDocumentValue(document, fieldPath, event.target.checked))} />{key.replace(/([A-Z])/g, " $1")}</label>;
    if (key === "xraySockopts" && item && typeof item === "object" && !Array.isArray(item)) return <fieldset className="profile-graph-list" key={key}>
      <legend>{tr("Socket options")}</legend>
      <ObjectFields value={item as Record<string, unknown>} path={fieldPath} document={document} onChange={onChange} disabled={disabled} />
    </fieldset>;
    if (Array.isArray(item) && item.every(scalar)) return <fieldset className="profile-graph-list" key={key} disabled={disabled}>
      <legend>{key.replace(/([A-Z])/g, " $1")}</legend>
      {item.map((entry, index) => <div className="profile-graph-list-row" key={index}>
        <input aria-label={`${key} ${index + 1}`} value={String(entry)}
          onChange={(event) => onChange(setDocumentValue(document, `${fieldPath}/${index}`, typeof entry === "number" ? Number(event.target.value) : event.target.value))} />
        <button type="button" className="btn-sm" aria-label={tr("Remove item")}
          onClick={() => onChange(removeDocumentValue(document, `${fieldPath}/${index}`))}>{tr("Remove")}</button>
      </div>)}
      <button type="button" className="btn-sm" onClick={() => onChange(setDocumentValue(document, fieldPath, [...item, ""]))}>{tr("Add item")}</button>
    </fieldset>;
    if (typeof item === "string" && (key === "target" || key === "route")) {
      const options = key === "route" ? ["none", "proxy", "direct"] : ["proxy", "direct", "block"];
      return <label key={key}>{key.replace(/([A-Z])/g, " $1")}<select disabled={disabled} value={item}
        onChange={(event) => onChange(setDocumentValue(document, fieldPath, event.target.value))}>
        {options.map((option) => <option key={option} value={option}>{tr(option[0].toUpperCase() + option.slice(1))}</option>)}
      </select></label>;
    }
    if (!scalar(item)) return null;
    return <label key={key}>{key.replace(/([A-Z])/g, " $1")}
      <input disabled={disabled} type={typeof item === "number" || item === null && /port|secs|mtu|interval|timeout|idle/i.test(key) ? "number" : "text"} value={item == null ? "" : String(item)}
        onChange={(event) => onChange(setDocumentValue(document, fieldPath, item === null && event.target.value === "" ? null : typeof item === "number" || item === null && /port|secs|mtu|interval|timeout|idle/i.test(key) ? Number(event.target.value) : event.target.value))} />
    </label>;
  })}</div>;
}
