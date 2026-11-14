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
    const words = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
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

function selectorMatch(selector: string, target: string, resolveIp: boolean): Match {
  const index = selector.indexOf(":");
  const value = (index < 0 ? selector : selector.slice(index + 1)).toLowerCase().replace(/\.$/, "");
  const kind = index < 0 ? (ipBytes(value.split("/")[0]) ? "ip" : "domain") : selector.slice(0, index);
  const host = target.toLowerCase().replace(/\.$/, "");
  const targetIp = ipBytes(host) !== null;
  if (kind === "ip") return targetIp ? ipMatch(value, host) : resolveIp ? "unknown" : "miss";
  if (kind === "geoip") return targetIp ? "unknown" : resolveIp ? "unknown" : "miss";
  if (kind === "geosite" || kind === "regexp") return targetIp ? "miss" : "unknown";
  if (targetIp) return "miss";
  if (kind === "full") return host === value ? "match" : "miss";
  if (kind === "domain") return host === value || host.endsWith(`.${value}`) ? "match" : "miss";
  if (kind === "keyword") return host.includes(value) ? "match" : "miss";
  return "unknown";
}


function parseTarget(value: string): { host: string; port?: number } {
  const bracketed = value.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) return { host: bracketed[1], ...(bracketed[2] ? { port: Number(bracketed[2]) } : {}) };
  const ordinary = value.match(/^([^:]+)(?::(\d+))?$/);
  return ordinary ? { host: ordinary[1], ...(ordinary[2] ? { port: Number(ordinary[2]) } : {}) } : { host: value };
}
export function explainProfileDocument(document: ProfileDocument, target: string): RouteCheckResult {
  const parsedTarget = parseTarget(target);
  const host = parsedTarget.host;
  const profile = document.profile;
  const strategy = profile.xrayDomainStrategy;
  const resolveIp = strategy === "ipIfNonMatch" || strategy === "ipOnDemand";
  const steps: RouteCheckResult["steps"] = [];
  let unknownBefore = false;
  const targetKind = ipBytes(host) ? "ip" : "domain";
  const result = (
    outbound: RouteCheckResult["outbound"],
    source: RouteCheckResult["source"],
    certainty: RouteCheckResult["certainty"],
    extras: Partial<RouteCheckResult> = {},
  ): RouteCheckResult => ({
    target: host,
    ...(parsedTarget.port === undefined ? {} : { port: parsedTarget.port }),
    targetKind,
    outbound,
    source,
    certainty,
    steps,
    notes: certainty === "probable"
      ? ["An earlier selector could not be evaluated; no route is claimed as certain."]
      : [],
    ...extras,
  });
  if (profile.backend !== "xray") throw new Error("Offline route explanation is unavailable for this profile backend");

  const pins = Array.isArray(profile.pinnedPolicies) ? profile.pinnedPolicies : [];

  const trafficRules = Array.isArray(profile.xrayTrafficRules) ? profile.xrayTrafficRules : [];
  for (const ruleValue of trafficRules) {
    const rule = record(ruleValue);
    if (typeof rule?.port !== "number" || (parsedTarget.port !== undefined && parsedTarget.port !== rule.port)) continue;
    const selectors = Array.isArray(rule?.ips) ? rule.ips.filter((item): item is string => typeof item === "string") : [];
    let candidate = false;
    for (const selector of selectors) {
      const match = selectorMatch(selector, host, resolveIp);
      if (match !== "miss") candidate = true;
    }
    if (candidate) {
      unknownBefore = true;
      steps.push({ label: "traffic rule (transport unavailable)", outcome: "unknown" });
    }
  }

  const dns = record(profile.xrayDns);
  const dnsActive = !!dns && (
    (Array.isArray(dns.servers) && dns.servers.length > 0) ||
    (record(dns.hosts) !== null && Object.keys(record(dns.hosts) ?? {}).length > 0) ||
    dns.fakeDns === true ||
    typeof dns.queryStrategy === "string" ||
    typeof dns.enableParallelQuery === "boolean" ||
    (typeof dns.outboundKey === "string" && dns.outboundKey.length > 0) ||
    (record(dns.outbound) !== null && Object.keys(record(dns.outbound) ?? {}).length > 0)
  );
  if (dnsActive) {
    const hit = parsedTarget.port === 53;
    steps.push({ label: "dns capture (port 53)", selector: "port:53", outcome: hit ? "match" : "miss" });
    if (hit) return result("dns", "dnsCapture", unknownBefore ? "probable" : "certain");
  }
  const policies = Array.isArray(profile.domainPolicies) ? profile.domainPolicies : [];
  if (pins.length > 0) {
    for (let index = 0; index < policies.length; index++) {
      const policy = record(policies[index]);
      const selectors = Array.isArray(policy?.domains) ? policy.domains.filter((item): item is string =>
        typeof item === "string" && /^(domain|full):/.test(item.trim()),
      ) : [];
      for (const selector of selectors) {
        const match = selectorMatch(selector.trim(), host, resolveIp);
        if (match !== "match") continue;
        steps.push({ label: `policy #${index + 1}`, selector, outcome: "match" });
        return result(policy?.target === "direct" ? "direct" : policy?.target === "block" ? "block" : "proxy", "policy", unknownBefore ? "probable" : "certain", {
          policyIndex: index,
          matchedSelector: selector,
          policyPath: `/profile/domainPolicies/${index}`,
        });
      }
    }
  }
  for (let index = 0; index < pins.length; index++) {
    const pin = record(pins[index]);
    const selectors = Array.isArray(pin?.selectors) ? pin.selectors.filter((item): item is string => typeof item === "string") : [];
    let unknown = false;
    for (const selector of selectors) {
      if (!selector.trim() || selector.trim().startsWith("#")) continue;
      const match = selectorMatch(selector.trim(), host, resolveIp);
      if (match === "match") {
        steps.push({ label: `pinned route #${index + 1}`, selector, outcome: "match" });
        if (unknownBefore) return result("proxy", "default", "probable");
        return result("proxy", "policy", "certain", {
          policyPath: `/profile/pinnedPolicies/${index}`,
          ...(typeof pin?.endpointKey === "string" ? { endpointKey: pin.endpointKey } : {}),
          matchedSelector: selector,
        });
      }
      if (match === "unknown") unknown = true;
    }
    unknownBefore ||= unknown;
    steps.push({ label: `pinned route #${index + 1}`, outcome: unknown ? "unknown" : "miss" });
  }

  const interfaces = Array.isArray(profile.xrayInterfaceRoutes) ? profile.xrayInterfaceRoutes : [];
  for (let index = 0; index < interfaces.length; index++) {
    const route = record(interfaces[index]);
    const selectors = Array.isArray(route?.selectors) ? route.selectors.filter((item): item is string => typeof item === "string") : [];
    const routeStrategy = route?.domainStrategy;
    const routeResolveIp = routeStrategy === "ipIfNonMatch" || routeStrategy === "ipOnDemand" || (routeStrategy == null && resolveIp);
    let unknown = false;
    for (const selector of selectors) {
      const match = selectorMatch(selector, host, routeResolveIp);
      if (match === "match") {
        steps.push({ label: `interface route #${index + 1}`, selector, outcome: "match" });
        return result("direct", "policy", unknownBefore ? "probable" : "certain", {
          policyPath: `/profile/xrayInterfaceRoutes/${index}`,
          ...(typeof route?.interfaceName === "string" ? { interfaceName: route.interfaceName } : {}),
          matchedSelector: selector,
        });
      }
      if (match === "unknown") unknown = true;
    }
    unknownBefore ||= unknown;
    steps.push({ label: `interface route #${index + 1}`, outcome: unknown ? "unknown" : "miss" });
  }

  for (let index = 0; index < policies.length; index++) {
    const policy = record(policies[index]);
    const selectors = Array.isArray(policy?.domains) ? policy.domains.filter((item): item is string => typeof item === "string") : [];
    let unknown = false;
    for (const selector of selectors) {
      if (!selector.trim() || selector.trim().startsWith("#")) continue;
      const match = selectorMatch(selector.trim(), host, resolveIp);
      if (match === "match") {
        steps.push({ label: `policy #${index + 1}`, selector, outcome: "match" });
        return result(policy?.target === "direct" ? "direct" : policy?.target === "block" ? "block" : "proxy", "policy", unknownBefore ? "probable" : "certain", {
          policyIndex: index,
          matchedSelector: selector,
          policyPath: `/profile/domainPolicies/${index}`,
        });
      }
      if (match === "unknown") unknown = true;
    }
    unknownBefore ||= unknown;
    steps.push({ label: `policy #${index + 1}`, outcome: unknown ? "unknown" : "miss" });
  }

  const dnsServers = Array.isArray(dns?.servers) ? dns.servers : [];
  for (let index = 0; index < dnsServers.length; index++) {
    const server = record(dnsServers[index]);
    if (server?.route !== "proxy" && server?.route !== "direct") continue;
    const address = typeof server.address === "string" ? server.address.trim() : "";
    if (!address || /^(localhost|fakedns)(?::|$)/i.test(address)) continue;
    const authority = (address.includes("://") ? address.slice(address.indexOf("://") + 3) : address)
      .split(/[/?#]/, 1)[0]!
      .split("@").pop()!;
    const resolver = authority.startsWith("[")
      ? authority.slice(1, authority.indexOf("]"))
      : authority.replace(/:\d+$/, "");
    if (!resolver) continue;
    const resolverIp = ipBytes(resolver) !== null;
    const match = resolverIp
      ? selectorMatch(`ip:${resolver}`, host, resolveIp)
      : selectorMatch(`domain:${resolver}`, host, resolveIp);
    if (match === "match") {
      steps.push({ label: `resolver pin #${index + 1}`, selector: resolver, outcome: "match" });
      return result(server.route, "resolverPin", unknownBefore ? "probable" : "certain", {
        policyPath: `/profile/xrayDns/servers/${index}`,
        matchedSelector: resolver,
      });
    }
    if (match === "unknown") unknownBefore = true;
    steps.push({ label: `resolver pin #${index + 1}`, selector: resolver, outcome: match });
  }
  const rulesEmitted = policies.length > 0 || interfaces.length > 0 || trafficRules.length > 0 || dnsActive || profile.privateLanDirect === true;
  if (rulesEmitted) {
    const multicast = ["224.0.0.0/4", "ff00::/8"];
    if (multicast.some((network) => ipMatch(network, host) === "match")) {
      steps.push({ label: "multicast", selector: multicast.join(", "), outcome: "match" });
      return result("block", "multicast", unknownBefore ? "probable" : "certain", { matchedSelector: "multicast" });
    }
    steps.push({ label: "multicast", selector: multicast.join(", "), outcome: "miss" });
  }
  if (profile.privateLanDirect === true) {
    const privateNetworks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"];
    if (privateNetworks.some((network) => ipMatch(network, host) === "match")) {
      steps.push({ label: "private LAN", selector: "private ranges", outcome: "match" });
      return result("direct", "privateLan", unknownBefore ? "probable" : "certain", { matchedSelector: "privateLanDirect" });
    }
    steps.push({ label: "private LAN", selector: "private ranges", outcome: "miss" });
  }

  const unknown = unknownBefore;
  steps.push({ label: "default", outcome: unknown ? "unknown" : "match" });
  return result("proxy", "default", unknown ? "probable" : "certain");
}

