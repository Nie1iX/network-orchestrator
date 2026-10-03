import assert from "node:assert/strict";
import test from "node:test";
import { analyzeIntents, cidrCovers } from "../src/intentDoctor.ts";
import type {
  NetIntentView,
  NetworkInterface,
  Profile,
  SystemRoute,
} from "../src/types.ts";

function iface(name: string, category: NetworkInterface["category"]): NetworkInterface {
  return {
    name,
    friendlyName: name,
    kind: "ethernet",
    state: "up",
    addresses: [],
    dnsServers: [],
    dnsSuffix: null,
    mtu: 1500,
    ifIndex: 1,
    physical: category === "physical",
    mac: null,
    gateway: null,
    ipv6Gateway: null,
    rxBytes: null,
    txBytes: null,
    linkSpeedMbps: null,
    category,
    description: "",
    ifType: 6,
    tunnelType: null,
  };
}

function route(destination: string, interfaceName: string, managed = false): SystemRoute {
  return {
    family: "ipv4",
    destination,
    table: 254,
    routeType: "unicast",
    scope: "universe",
    protocol: managed ? 79 : 3,
    managed,
    gateway: "192.168.1.1",
    interfaceIndex: 1,
    interfaceName,
    metric: 100,
    prefSource: null,
    nexthops: [],
  };
}

function intent(partial: Partial<NetIntentView>): NetIntentView {
  return {
    id: "i1",
    destinations: [],
    path: { kind: "direct" },
    metric: 100,
    enabled: true,
    status: "effective",
    detail: "",
    installed: 1,
    wanted: 1,
    ...partial,
  };
}

function profile(id: string, bypasses: string[]): Profile {
  return {
    id,
    name: id,
    backend: "openVpn",
    configPath: "",
    interfaceName: `tun-${id}`,
    routes: [],
    autoConnect: false,
    domainPolicies: [],
    privateLanDirect: false,
    xraySocksPort: null,
    xrayHttpPort: null,
    useSystemProxy: false,
    proxyBypass: [],
    subscription: null,
    xrayMode: "socks",
    xrayTunInterface: null,
    xrayTunIp: null,
    endpointBypasses: bypasses,
  };
}

test("cidrCovers matches prefixes and rejects junk", () => {
  assert.equal(cidrCovers("10.20.0.0/16", "10.20.9.9"), true);
  assert.equal(cidrCovers("10.20.0.0/16", "10.21.9.9"), false);
  assert.equal(cidrCovers("0.0.0.0/0", "8.8.8.8"), true);
  assert.equal(cidrCovers("91.245.41.31/32", "91.245.41.31"), true);
  assert.equal(cidrCovers("91.245.41.31/32", "91.245.41.30"), false);
  assert.equal(cidrCovers("not-a-cidr", "1.2.3.4"), false);
  assert.equal(cidrCovers("10.0.0.0/8", "fe80::1"), false);
});

test("endpoint routed via a tunnel produces a direct bypass fix", () => {
  const suggestions = analyzeIntents({
    intents: [],
    routes: [
      route("0.0.0.0/0", "enp1s0"),
      route("0.0.0.0/1", "Mihomo"),
      route("128.0.0.0/1", "Mihomo"),
    ],
    interfaces: [iface("enp1s0", "physical"), iface("Mihomo", "vpn")],
    profiles: [profile("office", ["91.245.41.31"])],
  });
  assert.equal(suggestions.length, 1);
  const s = suggestions[0];
  assert.equal(s.kind, "endpointViaTunnel");
  assert.equal(s.viaInterface, "Mihomo");
  assert.deepEqual(s.endpoints, ["91.245.41.31"]);
  assert.deepEqual(s.fixes[0].destinations, ["91.245.41.31/32"]);
  assert.equal(s.fixes[0].path.kind, "direct");
  assert.equal(s.fixes[0].metric, 50);
});

test("endpoint already pinned by a direct intent stays quiet", () => {
  const suggestions = analyzeIntents({
    intents: [
      intent({
        id: "ep",
        destinations: ["91.245.41.31/32"],
        path: { kind: "direct" },
      }),
    ],
    routes: [route("0.0.0.0/1", "Mihomo")],
    interfaces: [iface("Mihomo", "vpn")],
    profiles: [profile("office", ["91.245.41.31"])],
  });
  assert.deepEqual(suggestions, []);
});

test("a disabled direct intent does not count as coverage", () => {
  const suggestions = analyzeIntents({
    intents: [
      intent({
        id: "ep",
        destinations: ["91.245.41.31/32"],
        path: { kind: "direct" },
        enabled: false,
      }),
    ],
    routes: [route("0.0.0.0/1", "Mihomo")],
    interfaces: [iface("Mihomo", "vpn")],
    profiles: [profile("office", ["91.245.41.31"])],
  });
  assert.equal(suggestions.length, 1);
  assert.equal(suggestions[0].kind, "endpointViaTunnel");
});

test("a broad intent through a tunnel surfaces uncovered endpoints early", () => {
  const suggestions = analyzeIntents({
    intents: [
      intent({
        id: "all",
        destinations: ["0.0.0.0/1", "128.0.0.0/1"],
        path: { kind: "interface", interface: "tun9" },
      }),
    ],
    routes: [route("0.0.0.0/0", "enp1s0")],
    interfaces: [iface("enp1s0", "physical")],
    profiles: [profile("office", ["91.245.41.31"]), profile("media", ["203.0.113.7"])],
  });
  assert.equal(suggestions.length, 1);
  const s = suggestions[0];
  assert.equal(s.kind, "uncoveredEndpoints");
  assert.deepEqual(s.endpoints, ["203.0.113.7", "91.245.41.31"]);
  assert.equal(s.fixes[0].path.kind, "direct");
});

test("a conflicted intent points at the occupying foreign route", () => {
  const foreign = route("203.0.113.0/24", "enp1s0", false);
  const suggestions = analyzeIntents({
    intents: [
      intent({
        id: "media",
        destinations: ["203.0.113.0/24"],
        path: { kind: "interface", interface: "tun9" },
        status: "conflicted",
      }),
    ],
    routes: [foreign],
    interfaces: [],
    profiles: [],
  });
  assert.equal(suggestions.length, 1);
  const s = suggestions[0];
  assert.equal(s.kind, "conflict");
  assert.equal(s.intentId, "media");
  assert.equal(s.foreignRoute, foreign);
  assert.equal(s.fixes.length, 0);
});
