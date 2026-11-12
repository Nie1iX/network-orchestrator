import type { SubscriptionEndpointInfo } from "./types.ts";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type ProfileDocument = { version: 1; profile: { [key: string]: JsonValue } };
export type DocumentIssue = { path: string; message: string; severity: "error" | "warning" };
export type DocumentNode = { id: string; path: string; kind: string; label: string; detail: string; editable: boolean; column: number; order: number };
export type DocumentEdge = { id: string; from: string; to: string; path: string; label: string };
export type DocumentGraph = { nodes: DocumentNode[]; edges: DocumentEdge[]; issues: DocumentIssue[] };

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const isJson = (value: unknown): value is JsonValue => {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJson);
  return isObject(value) && Object.values(value).every(isJson);
};
const escape = (part: string): string => part.replace(/~/g, "~0").replace(/\//g, "~1");
const parts = (path: string): string[] => {
  if (path === "") return [];
  if (!path.startsWith("/")) throw new Error("Path must be a JSON pointer");
  return path.slice(1).split("/").map((part) => {
    if (/~(?![01])/.test(part)) throw new Error("Malformed JSON pointer");
    return part.replace(/~1/g, "/").replace(/~0/g, "~");
  });
};

export function parseProfileDocument(text: string): { document: ProfileDocument | null; issues: DocumentIssue[] } {
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { return { document: null, issues: [{ path: "", message: "Invalid JSON", severity: "error" }] }; }
  if (!isObject(parsed) || parsed.version !== 1 || !isObject(parsed.profile) || !isJson(parsed.profile)) {
    return { document: null, issues: [{ path: "", message: "Expected a version 1 profile document", severity: "error" }] };
  }
  return { document: parsed as ProfileDocument, issues: [] };
}

export function buildProfileGraph(document: ProfileDocument, endpoints: SubscriptionEndpointInfo[]): DocumentGraph {
  const nodes: DocumentNode[] = [];
  const edges: DocumentEdge[] = [];
  const issues: DocumentIssue[] = [];
  const matches = new Map<string, { endpoint: SubscriptionEndpointInfo; id: string }[]>();
  const add = (path: string, kind: string, label: string, editable: boolean, column: number, order = 0, detail = "") => {
    nodes.push({ id: path, path, kind, label: safeLabel(label), detail, editable, column, order });
  };
  const edge = (from: string, to: string, path: string, label: string) => edges.push({ id: `${from}:${path}->${to}`, from, to, path, label });
  const reference = (from: string, key: unknown, path: string, label: string) => {
    const candidates = typeof key === "string" ? matches.get(key) ?? [] : [];
    if (candidates.length !== 1 || candidates[0]?.endpoint.isMissing) {
      issues.push({ path, message: candidates.length > 1 ? "Endpoint reference is ambiguous" : "Endpoint reference is missing", severity: "error" });
      const id = `/unresolved${path}`;
      add(id, "endpoint", "Unresolved endpoint", false, 3);
      edge(from, id, path, label);
    } else edge(from, candidates[0]!.id, path, label);
  };
  endpoints.forEach((endpoint, index) => {
    const id = `/endpoints/${encodeURIComponent(endpoint.key)}:${index}`;
    add(id, "endpoint", endpoint.name, false, 3, index, endpoint.protocol ?? "Endpoint");
    matches.set(endpoint.key, [...(matches.get(endpoint.key) ?? []), { endpoint, id }]);
  });
  add("/profile", "setting", "Profile settings", true, 0);
  const target = (name: string) => {
    const id = `/targets/${name}`;
    if (!nodes.some((node) => node.id === id)) add(id, "target", name, false, 3);
    return id;
  };
  const opaque = (value: JsonValue, path: string, label: string) => {
    add(path, "opaque", /password|secret|token|url|key|credential|path/i.test(label) ? "Protected setting" : label, false, 0, 0, "Unsupported settings (read-only)");
    if (isObject(value)) for (const [key, child] of Object.entries(value)) opaque(child as JsonValue, `${path}/${escape(key)}`, key);
    else if (Array.isArray(value)) value.forEach((child, index) => { if (isObject(child)) opaque(child, `${path}/${index}`, String(index + 1)); });
  };
  const routing = (value: JsonValue, path: string, label: string, kind = "selector", editable = true) => {
    if (Array.isArray(value) && value.length === 0) return;
    add(path, kind, label, editable, 1);
    if (!Array.isArray(value)) return;
    value.forEach((entry, index) => {
      const item = `${path}/${index}`;
      add(item, kind, label, editable && isObject(entry), 1, index, String(index + 1));
      if (!isObject(entry)) return;
      if (entry.target === "proxy" || entry.target === "direct" || entry.target === "block") edge(item, target(entry.target), `${item}/target`, entry.target);
      if ("endpointKey" in entry) reference(item, entry.endpointKey, `${item}/endpointKey`, "endpoint");
      if (typeof entry.interfaceName === "string") {
        const target = `/interfaces/${encodeURIComponent(entry.interfaceName)}`;
        if (!nodes.some((node) => node.id === target)) add(target, "interface", entry.interfaceName, false, 3);
        edge(item, target, `${item}/interfaceName`, "interface");
      }
    });
  };
  const settings: Record<string, true> = { name: true, interfaceName: true, autoConnect: true, privateLanDirect: true, xraySocksPort: true, xrayHttpPort: true, useSystemProxy: true, proxyBypass: true, xrayMode: true, xrayTunInterface: true, xrayTunIp: true, xrayTunMtu: true, waitForInterface: true, endpointBypasses: true, xrayDomainStrategy: true, xrayDomainMatcher: true, xrayDirectDomainStrategy: true, xraySplitDefault: true, xrayQuicReject: true, xraySockopts: true, xrayConnectionIdleSecs: true, xrayTunDnsServers: true, tunnelRole: true, tunnelNetworks: true, tunnelDnsDomains: true };
  for (const [key, value] of Object.entries(document.profile)) {
    const path = `/profile/${escape(key)}`;
    if (value === null) continue;
    if (key === "routing" && isObject(value) && Object.entries(value).every(([field, item]) => field === "rules" && Array.isArray(item) && item.length === 0)) continue;
    if (key === "mihomo" && isObject(value)) {
      add(path, "setting", "Mihomo", true, 0);
      if (typeof value.entryGroup === "string" && value.entryGroup) {
        add(`${path}/entryGroup`, "reference", value.entryGroup, true, 1);
      }
      if (isObject(value.groupSelections)) {
        for (const [group, member] of Object.entries(value.groupSelections)) {
          if (typeof member !== "string") continue;
          const item = `${path}/groupSelections/${escape(group)}`;
          add(item, "reference", group, true, 1);
          const destination = `/mihomo-members/${encodeURIComponent(group)}`;
          add(destination, "target", member, false, 3);
          edge(item, destination, item, "selection");
        }
      }
    } else if (key === "subscription" && document.profile.backend === "mihomo") {
      add(path, "source", "Subscription", false, 0);
    } else if (key === "subscription" && isObject(value)) {
      add(path, "source", "Subscription", false, 0);
      add(`${path}/activeKey`, "reference", "Primary endpoint", true, 1);
      const primary = value.activeKey ?? endpoints.find((endpoint) => endpoint.active)?.key;
      reference(`${path}/activeKey`, primary, `${path}/activeKey`, "primary");
      for (const category of ["backupKeys", "poolKeys"]) {
        const entries = value[category];
        const listPath = `${path}/${category}`;
        if (Array.isArray(entries) && entries.length === 0 || entries == null) continue;
        add(listPath, "pool", category === "backupKeys" ? "Ordered backups" : "Verified pool members", category === "backupKeys", 1);
        if (Array.isArray(entries)) entries.forEach((entry, index) => {
          const item = `${listPath}/${index}`;
          add(item, "reference", category === "backupKeys" ? "Backup endpoint" : "Pool member", category === "backupKeys", 1, index, String(index + 1));
          if (isObject(entry)) reference(item, entry.key, `${item}/key`, category);
        });
      }
      const pool = value.nodePool;
      if (pool != null && (!isObject(pool) || Object.entries(pool).some(([key, item]) =>
        key === "filters" ? !Array.isArray(item) || item.length > 0 : key === "verifyExitCountry" ? item !== false : true))) {
        add(`${path}/nodePool`, "pool", "Endpoint pool", true, 1);
        if (isObject(pool) && Array.isArray(pool.filters)) pool.filters.forEach((filter, index) => add(`${path}/nodePool/filters/${index}`, "pool", "Pool filter", isObject(filter), 1, index));
      }
      for (const field of ["autoReturnPrimary", "refreshIntervalMinutes"]) if (value[field] != null) add(`${path}/${field}`, "setting", field, true, 0);
    } else if (key === "domainPolicies") routing(value, path, "Domain policy");
    else if (key === "pinnedPolicies") routing(value, path, "Pinned selector");
    else if (key === "xrayTrafficRules") routing(value, path, "Traffic rule");
    else if (key === "xrayInterfaceRoutes") routing(value, path, "Interface route", "interface");
    else if (key === "routes") routing(value, path, "Policy route", "routing");
    else if (key === "xrayServiceChecks") routing(value, path, "Service check", "selector");
    else if (key === "xrayDns" && isObject(value)) {
      const configured = Object.entries(value).some(([field, item]) => {
        if (field === "servers") return !Array.isArray(item) || item.length > 0;
        if (field === "hosts") return !isObject(item) || Object.keys(item).length > 0;
        if (field === "fakeDns") return item !== false;
        if (["queryStrategy", "enableParallelQuery", "outboundKey", "outbound"].includes(field)) return item != null;
        return true;
      });
      if (!configured) continue;
      add(path, "dns", "DNS", true, 1);
      if (value.outboundKey !== undefined && value.outboundKey !== null) reference(path, value.outboundKey, `${path}/outboundKey`, "DNS outbound");
      if (Array.isArray(value.servers)) value.servers.forEach((server, index) => {
        const item = `${path}/servers/${index}`;
        add(item, "dns", "DNS server", isObject(server), 1, index);
        if (isObject(server) && (server.route === "proxy" || server.route === "direct")) edge(item, target(server.route), `${item}/route`, server.route);
      });
    } else if (key === "xrayProxyExits" && Array.isArray(value)) {
      if (value.length === 0) continue;
      add(path, "exit", "Named exits", true, 1);
      value.forEach((entry, index) => {
        const item = `${path}/${index}`;
        add(item, "exit", isObject(entry) && typeof entry.name === "string" ? entry.name : "Named exit", isObject(entry), 1, index);
        if (!isObject(entry) || !isObject(entry.target)) return;
        add(`${item}/target`, "target", "Connection target", true, 1, index);
        if (entry.target.kind === "node") reference(item, entry.target.endpointKey, `${item}/target/endpointKey`, "exit endpoint");
        else if (entry.target.kind === "pool" && Array.isArray(entry.target.endpointKeys)) entry.target.endpointKeys.forEach((ref, member) => reference(item, ref, `${item}/target/endpointKeys/${member}`, "pool member"));
        else if (entry.target.kind === "direct" || entry.target.kind === "rules") edge(item, target(entry.target.kind === "direct" ? "direct" : "proxy"), `${item}/target/kind`, "exit");
      });
    } else if (settings[key] === true || key === "id" || key === "backend") continue;
    else if (key === "configPath") add(path, "source", "Managed source", false, 0);
    else if (!Array.isArray(value) || value.length > 0) {
      if (!isObject(value) || Object.keys(value).length > 0) opaque(value, path, key);
    }
  }
  const referencedEndpoints = new Set(edges.map((connection) => connection.to));
  return { nodes: nodes.filter((node) => node.kind !== "endpoint" || referencedEndpoints.has(node.id)), edges, issues };
}
function safeLabel(value: string): string {
  return value.replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, "[link]").replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "[id]").replace(/[\r\n\t]/g, " ").slice(0, 100);
}

function patch(document: ProfileDocument, path: string, value: JsonValue | undefined): ProfileDocument {
  const keys = parts(path);
  if (keys.length < 2 || keys[0] !== "profile") throw new Error("Document paths must address the profile");
  const root = structuredClone(document);
  let current: unknown = root;
  for (const key of keys.slice(0, -1)) {
    if (current === null || typeof current !== "object" || !Object.prototype.hasOwnProperty.call(current, key)) throw new Error("Path does not exist");
    current = (current as Record<string, unknown>)[key];
  }
  const last = keys[keys.length - 1]!;
  if (Array.isArray(current)) {
    if (!/^(0|[1-9]\d*)$/.test(last)) throw new Error("Invalid array index");
    const index = Number(last);
    if (!Number.isSafeInteger(index) || index >= current.length) throw new Error("Path does not exist");
    if (value === undefined) current.splice(index, 1); else current[index] = value;
  } else if (isObject(current)) {
    if (value === undefined) {
      if (!Object.prototype.hasOwnProperty.call(current, last)) throw new Error("Path does not exist");
      delete current[last];
    } else Object.defineProperty(current, last, { value, enumerable: true, configurable: true, writable: true });
  } else throw new Error("Path does not exist");
  return root;
}
export function setDocumentValue(document: ProfileDocument, path: string, value: JsonValue): ProfileDocument { return patch(document, path, value); }
export function removeDocumentValue(document: ProfileDocument, path: string): ProfileDocument { return patch(document, path, undefined); }
export function connectDocumentNode(document: ProfileDocument, path: string, target: string): ProfileDocument {
  const keys = parts(path);
  const node = getAt(document, keys);
  const endpointKey = target.startsWith("node:") ? target.slice(5) : null;
  const unsupported = () => new Error("Unsupported connection target");
  if (endpointKey !== null && !endpointKey) throw new Error("Endpoint reference is missing");
  if (path === "/profile/subscription/activeKey") {
    if (endpointKey === null) throw unsupported();
    return setDocumentValue(document, path, endpointKey);
  }
  if (/^\/profile\/subscription\/backupKeys\/\d+$/.test(path) && isObject(node)) {
    if (endpointKey === null) throw unsupported();
    return setDocumentValue(document, `${path}/key`, endpointKey);
  }
  if (/^\/profile\/(?:pinnedPolicies|xrayServiceChecks)\/\d+$/.test(path) && isObject(node)) {
    if (endpointKey === null) throw unsupported();
    return setDocumentValue(document, `${path}/endpointKey`, endpointKey);
  }
  if (/^\/profile\/(?:domainPolicies|xrayTrafficRules)\/\d+$/.test(path) && isObject(node)) {
    if (!["proxy", "direct", "block"].includes(target)) throw unsupported();
    return setDocumentValue(document, `${path}/target`, target);
  }
  if (path === "/profile/xrayDns" && isObject(node)) {
    if (endpointKey === null) throw unsupported();
    return setDocumentValue(document, `${path}/outboundKey`, endpointKey);
  }
  if (/^\/profile\/xrayDns\/servers\/\d+$/.test(path) && isObject(node)) {
    if (!["proxy", "direct", "none"].includes(target)) throw unsupported();
    return setDocumentValue(document, `${path}/route`, target);
  }
  if (/^\/profile\/xrayProxyExits\/\d+\/target$/.test(path) && isObject(node)) {
    if (endpointKey !== null && node.kind === "pool" && Array.isArray(node.endpointKeys)) {
      return setDocumentValue(document, `${path}/endpointKeys`, node.endpointKeys.includes(endpointKey) ? node.endpointKeys : [...node.endpointKeys, endpointKey]);
    }
    const { endpointKey: _oldKey, endpointKeys: _oldKeys, ...rest } = node;
    if (endpointKey !== null) return setDocumentValue(document, path, { ...rest, kind: "node", endpointKey } as JsonValue);
    if (target !== "proxy" && target !== "direct") throw unsupported();
    return setDocumentValue(document, path, { ...rest, kind: target === "proxy" ? "rules" : "direct" } as JsonValue);
  }
  if (target.startsWith("interface:") && /^\/profile\/xrayInterfaceRoutes\/\d+$/.test(path) && isObject(node)) {
    const name = target.slice(10);
    if (!name) throw new Error("Interface name is required");
    return setDocumentValue(document, `${path}/interfaceName`, name);
  }
  throw unsupported();
}
function getAt(document: ProfileDocument, keys: string[]): unknown {
  let current: unknown = document;
  for (const key of keys) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}
export function documentDiff(before: ProfileDocument, after: ProfileDocument): string[] {
  const changed = new Set<string>();
  const compare = (a: unknown, b: unknown, path: string) => {
    if (Object.is(a, b)) return;
    if (Array.isArray(a) && Array.isArray(b)) { for (let i = 0; i < Math.max(a.length, b.length); i++) compare(a[i], b[i], `${path}/${i}`); return; }
    if (isObject(a) && isObject(b)) { for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) compare(a[key], b[key], `${path}/${escape(key)}`); return; }
    changed.add(path || "");
  };
  compare(before, after, "");
  return [...changed].sort();
}
