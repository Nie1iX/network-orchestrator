import assert from "node:assert/strict";
import test from "node:test";
import {
  buildProfileGraph,
  connectDocumentNode,
  documentDiff,
  parseProfileDocument,
  removeDocumentValue,
  setDocumentValue,
  type ProfileDocument,
} from "../src/profileDocument.ts";

const document = (profile: Record<string, unknown>): ProfileDocument =>
  ({ version: 1, profile }) as ProfileDocument;
const endpoints = [
  { key: "aabb001122334455", name: "Alpha", active: true, protocol: "vless", isBackup: false, isMissing: false },
  { key: "aabb001122334455", name: "Alias", active: false, protocol: "vmess", isBackup: false, isMissing: false },
];

test("invalid JSON is retained as a safe parse issue, not thrown", () => {
  const parsed = parseProfileDocument('{"secret":"never echo this"');
  assert.equal(parsed.document, null);
  assert.equal(parsed.issues[0]?.severity, "error");
  assert.equal(JSON.stringify(parsed.issues).includes("never echo this"), false);
});

test("non-finite JSON numbers are rejected instead of silently normalizing", () => {
  const parsed = parseProfileDocument('{"version":1,"profile":{"port":1e999}}');
  assert.equal(parsed.document, null);
});

test("graph marks duplicate endpoint keys ambiguous without exposing credentials", () => {
  const graph = buildProfileGraph(document({ pinnedPolicies: [{ selectors: ["domain:bank.test"], endpointKey: endpoints[0]!.key, password: "secret" }] }), endpoints);
  assert.ok(graph.issues.some((issue) => issue.path === "/profile/pinnedPolicies/0/endpointKey" && /ambiguous/i.test(issue.message)));
  assert.equal(graph.nodes.some((node) => node.label.includes("secret") || node.detail.includes("secret")), false);
});

test("graph preserves routing rule order and opaque source settings", () => {
  const source = document({ routing: { rules: [{ outboundTag: "proxy" }, { outboundTag: "block" }] }, customSource: { nested: [1, { keep: true }] } });
  const graph = buildProfileGraph(source, []);
  const opaque = graph.nodes.find((node) => node.path === "/profile/customSource");
  assert.ok(opaque);
  assert.equal(opaque.editable, false);
  const edited = setDocumentValue(source, "/profile/customSource/nested/1/keep", false);
  assert.deepEqual((edited.profile.routing as { rules: unknown[] }).rules, (source.profile.routing as { rules: unknown[] }).rules);
  assert.deepEqual(edited.profile.customSource, { nested: [1, { keep: false }] });
});

test("patches use JSON pointers and diff reports paths only", () => {
  const before = document({ nested: { value: "private" }, list: [1, 2, 3] });
  const after = setDocumentValue(before, "/profile/nested/value", "changed");
  assert.deepEqual(documentDiff(before, after), ["/profile/nested/value"]);
  assert.equal(JSON.stringify(documentDiff(before, after)).includes("private"), false);
  assert.deepEqual(removeDocumentValue(after, "/profile/list/1").profile.list, [1, 3]);
});

test("patch rejects inherited prototype paths without polluting objects", () => {
  try {
    assert.throws(() => setDocumentValue(document({}), "/profile/__proto__/polluted", true), /exist/i);
  } finally {
    delete (Object.prototype as Record<string, unknown>).polluted;
  }
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test("domain policies update their target field without changing other values", () => {
  const source = document({ domainPolicies: [{ domains: ["a.test"], target: "direct", extra: { keep: 1 } }] });
  const edited = connectDocumentNode(source, "/profile/domainPolicies/0", "block");
  assert.deepEqual(edited.profile.domainPolicies, [{ domains: ["a.test"], target: "block", extra: { keep: 1 } }]);
});

test("missing endpoint references are reported", () => {
  const graph = buildProfileGraph(document({ pinnedPolicies: [{ selectors: ["domain:bank.test"], endpointKey: "deadbeefdeadbeef" }] }), endpoints);
  assert.ok(graph.issues.some((issue) => issue.path === "/profile/pinnedPolicies/0/endpointKey" && issue.severity === "error"));
});

test("minimal defaults do not create empty feature or target nodes", () => {
  const graph = buildProfileGraph(document({
    backend: "xray", routes: [], domainPolicies: [], xrayProxyExits: [], xrayServiceChecks: [],
    xrayDns: { servers: [], fakeDns: false, queryStrategy: null },
    subscription: { activeKey: endpoints[0]!.key, backupKeys: [], poolKeys: [], nodePool: null },
  }), [endpoints[0]!, { ...endpoints[1]!, key: "unused" }]);
  assert.deepEqual(graph.nodes.filter((node) => node.kind === "endpoint").map((node) => node.label), ["Alpha"]);
  assert.equal(graph.nodes.some((node) => ["/profile/routes", "/profile/xrayDns", "/profile/subscription/nodePool", "/targets/direct"].includes(node.path)), false);
});

test("referenced pool endpoints are connected while unused endpoints stay hidden", () => {
  const catalog = [endpoints[0]!, { ...endpoints[1]!, key: "second" }, { ...endpoints[1]!, key: "unused" }];
  const graph = buildProfileGraph(document({ xrayProxyExits: [{ name: "Pool", target: { kind: "pool", endpointKeys: [catalog[0]!.key, "second"] } }] }), catalog);
  assert.equal(graph.nodes.filter((node) => node.kind === "endpoint").length, 2);
  assert.equal(graph.edges.filter((edge) => edge.label === "pool member").length, 2);
});

test("missing used endpoint remains visible with an issue", () => {
  const graph = buildProfileGraph(document({ pinnedPolicies: [{ selectors: [], endpointKey: "missing" }] }), []);
  assert.ok(graph.issues.some((issue) => issue.path === "/profile/pinnedPolicies/0/endpointKey"));
  assert.ok(graph.nodes.some((node) => node.path === "/profile/pinnedPolicies/0"));
});

test("custom DNS and incomplete added entries remain visible", () => {
  const graph = buildProfileGraph(document({
    xrayDns: { servers: [], fakeDns: true, queryStrategy: null },
    domainPolicies: [{ domains: [], target: "proxy" }],
    xrayServiceChecks: [{ name: "", endpointKey: "" }],
  }), []);
  assert.ok(graph.nodes.some((node) => node.path === "/profile/xrayDns"));
  assert.ok(graph.nodes.some((node) => node.path === "/profile/domainPolicies/0"));
  assert.ok(graph.nodes.some((node) => node.path === "/profile/xrayServiceChecks/0"));
});

test("backup and verified pool references include only their members", () => {
  const catalog = [endpoints[0]!, { ...endpoints[1]!, key: "second" }, { ...endpoints[1]!, key: "unused" }];
  const graph = buildProfileGraph(document({ subscription: {
    activeKey: catalog[0]!.key, backupKeys: [{ key: "second", name: "Backup" }],
    poolKeys: [{ key: "missing", name: "Missing" }],
  } }), catalog);
  assert.equal(graph.nodes.filter((node) => node.kind === "endpoint" && node.path.startsWith("/endpoints/")).length, 2);
  assert.ok(graph.issues.some((issue) => issue.path === "/profile/subscription/poolKeys/0/key"));
  assert.ok(graph.edges.some((edge) => edge.path === "/profile/subscription/poolKeys/0/key"));
});

test("unknown nonempty DNS configuration is retained", () => {
  const graph = buildProfileGraph(document({ xrayDns: { servers: [], fakeDns: false, custom: { enabled: true } } }), []);
  assert.ok(graph.nodes.some((node) => node.path === "/profile/xrayDns"));
});

test("serialized null optional sections and empty routing do not create placeholders", () => {
  const graph = buildProfileGraph(document({
    backend: "xray", subscription: null, xrayDns: null, xrayProxyExits: null,
    xrayServiceChecks: [], routes: [], domainPolicies: [], pinnedPolicies: [],
    xrayTrafficRules: [], xrayInterfaceRoutes: [], routing: { rules: [] },
  }), []);
  assert.deepEqual(graph.nodes.map((node) => node.path), ["/profile"]);
});

test("unset subscription options do not become functional blocks", () => {
  const graph = buildProfileGraph(document({
    subscription: { activeKey: endpoints[0]!.key, refreshIntervalMinutes: null, autoReturnPrimary: true },
  }), [endpoints[0]!]);
  assert.ok(graph.nodes.some((node) => node.path === "/profile/subscription"));
  assert.equal(graph.nodes.some((node) => node.path === "/profile/subscription/refreshIntervalMinutes"), false);
});

test("Mihomo graph shows configured selections without exposing unused groups or secrets", () => {
  const graph = buildProfileGraph(document({
    backend: "mihomo",
    mihomo: { mode: "proxy", mixedPort: 7890, entryGroup: "Auto", groupSelections: { Auto: "Netherlands" } },
  }), []);
  const labels = graph.nodes.map((node) => node.label);
  assert.ok(labels.includes("Auto"));
  assert.ok(labels.includes("Netherlands"));
  assert.ok(!labels.includes("Unused"));
  assert.ok(!JSON.stringify(graph).includes("password"));
});
