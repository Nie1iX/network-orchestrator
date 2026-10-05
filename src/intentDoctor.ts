import type {
  NetIntentSetParams,
  NetIntentView,
  NetworkInterface,
  Profile,
  SystemRoute,
} from "./types.ts";

/**
 * Read-only "doctor" for routing intents: looks at the live kernel
 * tables, stored intents, interfaces, and known profile endpoints and
 * turns recognizable breakage into one-click fixes. The user's mental
 * model is "connect the clients; the app resolves who goes where" —
 * this is the part that detects what needs a rule before the user has
 * to think in CIDRs.
 */

export type SuggestionKind =
  /** A VPN endpoint resolves out a tunnel — the handshake never
   *  reaches the server (the classic TLS-timeout incident). */
  | "endpointViaTunnel"
  /** A default-capturing intent through a tunnel will swallow other
   *  clients' endpoints that are not pinned to the uplink yet. */
  | "uncoveredEndpoints"
  /** A foreign route occupies an intent's destination. */
  | "conflict";

export interface IntentSuggestion {
  /** Dedup key — also used for dismissing a card for the session. */
  key: string;
  kind: SuggestionKind;
  /** Tunnel interface involved (endpoint kinds). */
  viaInterface?: string;
  /** Owning intent id (conflict kind). */
  intentId?: string;
  /** Intent destination a foreign route occupies (conflict kind). */
  destination?: string;
  /** Endpoint IPs the fix pins to the physical uplink. */
  endpoints: string[];
  /** The foreign route occupying the destination (conflict kind). */
  foreignRoute?: SystemRoute;
  /** Ready-to-apply intents — empty for conflict (fixed via route del). */
  fixes: NetIntentSetParams[];
}

/** Default-capturing destinations, including the def1-style halves a
 *  lot of clients prefer over a plain `0.0.0.0/0`. */
const DEFAULTISH = new Set([
  "0.0.0.0/0",
  "0.0.0.0/1",
  "128.0.0.0/1",
  "::/0",
  "::/1",
  "8000::/1",
]);

const MAIN_TABLE = 254;
const BYPASS_METRIC = 50;

function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

/** `10.20.0.0/16` covers `10.20.9.9`? IPv4 only — endpoints and
 *  doctor-worthy prefixes are v4 in practice; v6 input simply misses. */
export function cidrCovers(cidr: string, ip: string): boolean {
  const [base, lenText] = cidr.split("/");
  const ipInt = ipToInt(ip);
  const baseInt = ipToInt(base ?? "");
  const len = Number(lenText);
  if (ipInt === null || baseInt === null || !Number.isInteger(len))
    return false;
  if (len < 0 || len > 32) return false;
  if (len === 0) return true;
  const mask = len === 32 ? 0xffffffff : (0xffffffff << (32 - len)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/** Longest-prefix match inside the main table — what the kernel would
 *  actually pick for this destination. */
function lpmMain(routes: SystemRoute[], ip: string): SystemRoute | null {
  let best: SystemRoute | null = null;
  let bestLen = -1;
  for (const route of routes) {
    if (route.table !== MAIN_TABLE || route.routeType !== "unicast") continue;
    if (!cidrCovers(route.destination, ip)) continue;
    const len = Number(route.destination.split("/")[1] ?? 0);
    if (len > bestLen) {
      best = route;
      bestLen = len;
    }
  }
  return best;
}

/** Interfaces traffic should not take unless a rule says so: tunnels,
 *  VPN adapters, and the usual `tun*`/`wg*` names when the inventory
 *  does not classify the link. */
function tunnelish(name: string, ifaces: NetworkInterface[]): boolean {
  const known = ifaces.find((iface) => iface.name === name);
  if (known) return known.category === "vpn" || known.category === "tunnel";
  return /^(tun|wg|utun|vpn|ppp|tailscale)/i.test(name);
}

/** Literal IPv4 endpoints every profile wants pinned to the uplink. */
function knownEndpoints(
  profiles: Profile[],
): { ip: string; profile: string }[] {
  const seen = new Map<string, string>();
  for (const profile of profiles) {
    for (const raw of profile.endpointBypasses ?? []) {
      const ip = raw.trim();
      if (ipToInt(ip) === null) continue;
      if (!seen.has(ip)) seen.set(ip, profile.name || profile.id);
    }
  }
  return [...seen.entries()].map(([ip, profile]) => ({ ip, profile }));
}

/** True when an enabled `direct` intent already pins `ip` to the
 *  physical uplink — the endpoint does not need another bypass. */
function coveredByDirectIntent(ip: string, intents: NetIntentView[]): boolean {
  return intents.some(
    (intent) =>
      intent.enabled &&
      intent.path.kind === "direct" &&
      intent.destinations.some((dest) => cidrCovers(dest, ip)),
  );
}

/** A free `bypass-…` id that does not collide with stored intents — also
 *  avoids clashing with an id about to be created by the caller. */
function bypassId(
  base: string,
  intents: NetIntentView[],
  takenExtra: string[] = [],
): string {
  const slug =
    base
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "uplink";
  let id = `bypass-${slug}`;
  const taken = new Set([...intents.map((intent) => intent.id), ...takenExtra]);
  let n = 2;
  while (taken.has(id)) id = `bypass-${slug}-${n++}`;
  return id;
}

/** Intent params pinning every known endpoint that is not yet covered by
 *  a `direct` rule to the physical uplink. Created alongside an
 *  "all traffic → tunnel" rule so the rule does not swallow the very
 *  endpoints its own clients need to reach. */
export function uncoveredEndpointIntents(
  profiles: Profile[],
  intents: NetIntentView[],
  via: string,
  takenExtra: string[] = [],
): NetIntentSetParams[] {
  const endpoints = knownEndpoints(profiles)
    .map(({ ip }) => ip)
    .filter((ip) => !coveredByDirectIntent(ip, intents))
    .sort();
  if (endpoints.length === 0) return [];
  return [
    {
      id: bypassId(via, intents, takenExtra),
      destinations: endpoints.map((ip) => `${ip}/32`),
      path: { kind: "direct" },
      metric: BYPASS_METRIC,
    },
  ];
}

export function analyzeIntents(input: {
  intents: NetIntentView[];
  routes: SystemRoute[];
  interfaces: NetworkInterface[];
  profiles: Profile[];
}): IntentSuggestion[] {
  const { intents, routes, interfaces, profiles } = input;
  const suggestions: IntentSuggestion[] = [];
  const endpoints = knownEndpoints(profiles);
  const claimed = new Set<string>();

  // 1. An endpoint currently resolves out a tunnel — the fix is a
  //    /32 → direct intent per tunnel interface.
  const swallowed = new Map<string, string[]>();
  for (const { ip } of endpoints) {
    if (coveredByDirectIntent(ip, intents)) continue;
    const route = lpmMain(routes, ip);
    const via = route?.interfaceName;
    if (!via || !tunnelish(via, interfaces)) continue;
    swallowed.set(via, [...(swallowed.get(via) ?? []), ip]);
    claimed.add(ip);
  }
  for (const [via, ips] of [...swallowed.entries()].sort()) {
    suggestions.push({
      key: `endpoint-via-tunnel:${via}:${ips.join(",")}`,
      kind: "endpointViaTunnel",
      viaInterface: via,
      endpoints: ips.sort(),
      fixes: [
        {
          id: bypassId(via, intents),
          destinations: ips.sort().map((ip) => `${ip}/32`),
          path: { kind: "direct" },
          metric: BYPASS_METRIC,
        },
      ],
    });
  }

  // 2. A default-capturing intent through a tunnel: every known
  //    endpoint not pinned to the uplink will break the moment the
  //    intent lands — offer the bypasses up front.
  const broad = intents.filter(
    (intent) =>
      intent.enabled &&
      intent.path.kind === "interface" &&
      intent.destinations.some((dest) => DEFAULTISH.has(dest)),
  );
  if (broad.length > 0) {
    const uncovered = endpoints
      .map(({ ip }) => ip)
      .filter((ip) => !claimed.has(ip) && !coveredByDirectIntent(ip, intents))
      .sort();
    if (uncovered.length > 0) {
      const via = broad[0].path.interface ?? "?";
      suggestions.push({
        key: `uncovered-endpoints:${via}:${uncovered.join(",")}`,
        kind: "uncoveredEndpoints",
        viaInterface: via,
        endpoints: uncovered,
        fixes: [
          {
            id: bypassId(via, intents),
            destinations: uncovered.map((ip) => `${ip}/32`),
            path: { kind: "direct" },
            metric: BYPASS_METRIC,
          },
        ],
      });
    }
  }

  // 3. Conflicted intents: a foreign route occupies the destination —
  //    the honest fix is suppressing it (journaled, restored when the
  //    override goes away), offered as a separate action.
  for (const intent of intents) {
    if (intent.status !== "conflicted") continue;
    for (const dest of intent.destinations) {
      const foreign = routes.find(
        (route) =>
          !route.managed &&
          route.table === MAIN_TABLE &&
          route.routeType === "unicast" &&
          route.destination === dest,
      );
      if (!foreign) continue;
      suggestions.push({
        key: `conflict:${intent.id}:${dest}`,
        kind: "conflict",
        intentId: intent.id,
        destination: dest,
        foreignRoute: foreign,
        endpoints: [],
        fixes: [],
      });
      break;
    }
  }

  return suggestions;
}
