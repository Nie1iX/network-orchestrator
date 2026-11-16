import type { ProfileDocument } from "../profileDocument.ts";
import type { RouteCheckResult } from "../types.ts";

type Match = "match" | "miss" | "unknown";
const record = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;

function ipBytes(text: string): number[] | null {
  if (text.includes(":")) {
    const halves = text.split("::");
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    const tail = halves.length === 2 ? right : left;
    const last = tail[tail.length - 1];
    if (last?.includes(".")) {
      const bytes = ipBytes(last);
      if (!bytes || bytes.length !== 4) return null;
      tail.pop();
      tail.push(((bytes[0] << 8) | bytes[1]).toString(16), ((bytes[2] << 8) | bytes[3]).toString(16));
    }
    const missing = 8 - left.length - right.length;
    if (missing < 0 || (halves.length === 1 ? missing !== 0 : missing === 0)) return null;
    const words = [...left, ...Array(missing).fill("0"), ...right];
    if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
    return words.flatMap((word) => { const value = Number.parseInt(word, 16); return [value >> 8, value & 255]; });
  }
  const parts = text.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)) return null;
  return parts.map(Number);
}

function ipMatch(selector: string, target: string): Match {
  const [address, bitsText] = selector.split("/");
  const source = ipBytes(address);
  const destination = ipBytes(target);
  if (!source) return "unknown";
  if (!destination) return "miss";
  if (source.length !== destination.length) return "miss";
  const bits = bitsText === undefined ? source.length * 8 : Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > source.length * 8) return "unknown";
  const full = Math.floor(bits / 8);
  const remainder = bits % 8;
  for (let i = 0; i < full; i++) if (source[i] !== destination[i]) return "miss";
  if (remainder && (source[full] >> (8 - remainder)) !== (destination[full] >> (8 - remainder))) return "miss";
  return "match";
}

function selectorMatch(selector: string, target: string): Match {
  const index = selector.indexOf(":");
  const literalIp = ipBytes(selector.split("/")[0]) !== null;
  const kind = literalIp ? "ip" : index < 0 ? "keyword" : selector.slice(0, index);
  const value = (literalIp || index < 0 ? selector : selector.slice(index + 1)).toLowerCase().replace(/\.$/, "");
  const host = target.toLowerCase().replace(/\.$/, "");
  const targetIp = ipBytes(host) !== null;
  // IP selectors derive IPOnDemand, independently of the saved preference.
  if (kind === "ip") return targetIp ? ipMatch(value, host) : "unknown";
  if (kind === "geoip") return "unknown";
  if (kind === "geosite" || kind === "regexp") return targetIp ? "miss" : "unknown";
  if (targetIp) return "miss";
  if (kind === "full") return host === value ? "match" : "miss";
  if (kind === "domain") return host === value || host.endsWith(`.${value}`) ? "match" : "miss";
  if (kind === "keyword") return host.includes(value) ? "match" : "miss";
  return "unknown";
}


function parseTarget(value: string): { host: string; port?: number } {
  const input = value.trim();
  const scheme = input.indexOf("://");
  const authority = (scheme < 0 ? input : input.slice(scheme + 3)).split(/[/?#]/, 1)[0].split("@").pop()!.trim();
  let host = authority;
  let portText: string | undefined;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) throw new Error("Route check target has a malformed bracket");
    host = authority.slice(1, end);
    const tail = authority.slice(end + 1);
    if (tail.startsWith(":")) portText = tail.slice(1).trim();
    else if (tail) throw new Error("Route check target has a malformed bracket");
  } else if (authority.split(":").length === 2) {
    const separator = authority.indexOf(":");
    host = authority.slice(0, separator).trim();
    portText = authority.slice(separator + 1).trim();
  }
  host = host.toLowerCase().replace(/\.+$/, "");
  if (!host || (!ipBytes(host) && (host.length > 253 || !/^[a-z0-9._*-]+$/.test(host)))) {
    throw new Error("Route check target has an invalid host");
  }
  if (portText !== undefined && (!/^\+?\d+$/.test(portText) || Number(portText) > 65535)) {
    throw new Error("Route check target has an invalid port");
  }
  return { host, ...(portText === undefined ? {} : { port: Number(portText) }) };
}
export function explainProfileDocument(document: ProfileDocument, target: string): RouteCheckResult {
  const parsedTarget = parseTarget(target);
  const host = parsedTarget.host;
  const profile = document.profile;
  const routing = record(profile.routing);
  if (profile.routing !== undefined && !routing) throw new Error("Invalid routing policy");
  const layers = ["user", "base"] as const;
  const rulesFor = (layer: typeof layers[number]): unknown[] => {
    const rules = routing?.[layer];
    if (rules === undefined) return [];
    if (!Array.isArray(rules)) throw new Error("Invalid routing layer");
    return rules;
  };
  const protectsDns = layers.some((layer) => rulesFor(layer).some((value) => {
    const rule = record(value);
    const output = record(rule?.target);
    const selectors = Array.isArray(rule?.selectors) ? rule.selectors : [];
    const effective = selectors.some((selector) => typeof selector === "string" && selector.trim() && !selector.trim().startsWith("#"));
    return effective && (output?.kind === "node" || layer === "user" && (
      output?.kind === "proxy" || selectors.some((selector) => typeof selector === "string" && (
        selector.trim().startsWith("geoip:") || ipBytes(selector.trim().split("/")[0]) !== null
      ))
    ));
  }));
  const steps: RouteCheckResult["steps"] = [];
  const targetKind = ipBytes(host) ? "ip" : "domain";
  const result = (
    outbound: RouteCheckResult["outbound"],
    source: RouteCheckResult["source"],
    certainty: RouteCheckResult["certainty"],
    extras: Partial<RouteCheckResult> = {},
  ): RouteCheckResult => ({
    target: host,
    ...(parsedTarget.port === undefined ? {} : { port: parsedTarget.port }),
    targetKind, outbound, source, certainty, steps,
    notes: certainty === "probable"
      ? ["An earlier selector could not be evaluated; no route is claimed as certain."]
      : [],
    ...extras,
  });
  if (profile.backend !== "xray") throw new Error("Offline route explanation is unavailable for this profile backend");

  const dns = record(profile.xrayDns);
  const dnsActive = protectsDns || !!dns && (
    (Array.isArray(dns.servers) && dns.servers.length > 0) ||
    (record(dns.hosts) !== null && Object.keys(record(dns.hosts) ?? {}).length > 0) ||
    dns.fakeDns === true || typeof dns.queryStrategy === "string" ||
    typeof dns.enableParallelQuery === "boolean" ||
    (typeof dns.outboundKey === "string" && dns.outboundKey.length > 0) ||
    (record(dns.outbound) !== null && Object.keys(record(dns.outbound) ?? {}).length > 0)
  );
  if (dnsActive) {
    const hit = parsedTarget.port === 53;
    steps.push({ label: "dns capture (port 53)", selector: "port:53", outcome: hit ? "match" : "miss" });
    if (hit) return result("dns", "dnsCapture", "certain");
  }

  for (const layer of layers) {
    const rules = rulesFor(layer);
    for (let index = 0; index < rules.length; index++) {
      const rule = record(rules[index]);
      if (!rule) throw new Error("Invalid routing rule");
      const label = `${layer} rule #${index + 1}`;
      if (typeof rule.port === "number" && parsedTarget.port !== undefined && parsedTarget.port !== rule.port) {
        steps.push({ label, outcome: "miss" });
        continue;
      }
      const selectors = Array.isArray(rule.selectors)
        ? rule.selectors.filter((item): item is string => typeof item === "string") : [];
      let matched: string | undefined;
      let unknown: string | undefined;
      for (const selector of selectors) {
        const value = selector.trim();
        if (!value || value.startsWith("#")) continue;
        const match = selectorMatch(value, host);
        if (match === "unknown") unknown ??= selector;
        if (match === "match") { matched = selector; break; }
      }
      const selector = matched ?? unknown;
      if (selector === undefined) {
        steps.push({ label, outcome: "miss" });
        continue;
      }
      const location = { layer, ruleIndex: index, matchedSelector: selector, policyPath: `/profile/routing/${layer}/${index}` };
      const conditionsUnknown = typeof rule.network === "string" || typeof rule.port === "number" && parsedTarget.port === undefined;
      if (matched === undefined || conditionsUnknown) {
        steps.push({ label, selector, outcome: "unknown" });
        return result("unknown", "policy", "probable", location);
      }
      const routeTarget = record(rule.target);
      const kind = routeTarget?.kind;
      if (typeof kind !== "string" || !["proxy", "direct", "block", "node", "interface"].includes(kind)) {
        throw new Error("Unsupported routing target");
      }
      steps.push({ label, selector, outcome: "match" });
      const missingNode = kind === "node" && routeTarget?.missing === true;
      const outbound = missingNode || kind === "block" ? "block" : kind === "direct" || kind === "interface" ? "direct" : "proxy";
      return result(outbound, "policy", "certain", {
        ...location,
        ...(kind === "node" && typeof routeTarget?.endpointKey === "string"
          ? { endpointKey: routeTarget.endpointKey } : {}),
        ...(kind === "interface" && typeof routeTarget?.interfaceName === "string"
          ? { interfaceName: routeTarget.interfaceName } : {}),
      });
    }
  }
  if (!protectsDns && Array.isArray(dns?.servers)) {
    for (let index = 0; index < dns.servers.length; index++) {
      const server = record(dns.servers[index]);
      if (!server || (server.route !== "proxy" && server.route !== "direct") || typeof server.address !== "string") continue;
      if (["localhost", "fakedns"].includes(server.address)) continue;
      const address = parseTarget(server.address).host;
      const literalIp = ipBytes(address) !== null;
      const resolveIp = profile.xrayDomainStrategy === "ipIfNonMatch" || profile.xrayDomainStrategy === "ipOnDemand";
      const match = literalIp
        ? targetKind === "ip" ? ipMatch(address, host) : resolveIp ? "unknown" : "miss"
        : selectorMatch(`domain:${address}`, host);
      steps.push({ label: `resolver pin #${index + 1}`, selector: address, outcome: match });
      if (match !== "miss") return result(match === "unknown" ? "unknown" : server.route, "resolverPin", match === "unknown" ? "probable" : "certain", {
        matchedSelector: address, policyPath: `/profile/xrayDns/servers/${index}`,
      });
    }
  }
  const hasRouting = layers.some((layer) => Array.isArray(routing?.[layer]) && (routing[layer] as unknown[]).length > 0);
  if (hasRouting || dnsActive || profile.privateLanDirect === true) {
    const multicast = ["224.0.0.0/4", "ff00::/8"];
    if (multicast.some((network) => ipMatch(network, host) === "match")) {
      steps.push({ label: "multicast", selector: multicast.join(", "), outcome: "match" });
      return result("block", "multicast", "certain", { matchedSelector: "multicast" });
    }
    steps.push({ label: "multicast", selector: multicast.join(", "), outcome: "miss" });
  }
  if (profile.privateLanDirect === true) {
    const privateNetworks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"];
    if (privateNetworks.some((network) => ipMatch(network, host) === "match")) {
      steps.push({ label: "private LAN", selector: "private ranges", outcome: "match" });
      return result("direct", "privateLan", "certain", { matchedSelector: "privateLanDirect" });
    }
    steps.push({ label: "private LAN", selector: "private ranges", outcome: "miss" });
  }
  steps.push({ label: "default", outcome: "match" });
  return result("proxy", "default", "certain");
}

