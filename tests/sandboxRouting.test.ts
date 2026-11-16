import assert from "node:assert/strict";
import test from "node:test";
import type { JsonValue, ProfileDocument } from "../src/profileDocument.ts";
import { explainProfileDocument } from "../src/sandbox/routeExplanation.ts";

const document = (routing: JsonValue): ProfileDocument => ({
  version: 1,
  profile: { backend: "xray", xrayDomainStrategy: "asIs", routing },
});

test("an unresolved User IP override cannot claim a later Base direct route", () => {
  const result = explainProfileDocument(document({
    user: [{ selectors: ["203.0.113.0/24"], target: { kind: "proxy" } }],
    base: [{ selectors: ["full:site.test"], target: { kind: "direct" } }],
  }), "site.test");
  assert.equal(result.outbound, "unknown");
  assert.equal(result.layer, "user");
  assert.equal(result.policyPath, "/profile/routing/user/0");
});

test("known missing explicit servers explain a definite block", () => {
  const key = "1111111111111111";
  const result = explainProfileDocument(document({
    user: [{ selectors: ["full:site.test"], target: { kind: "node", endpointKey: key, missing: true } }],
    base: [],
  }), "site.test");
  assert.equal(result.outbound, "block");
  assert.equal(result.certainty, "certain");
  assert.equal(result.endpointKey, key);
});

test("protected DNS is a service decision even without explicit DNS options", () => {
  for (const routing of [
    { user: [{ selectors: ["full:site.test"], target: { kind: "proxy" } }], base: [] },
    { user: [], base: [{ selectors: ["full:site.test"], target: { kind: "node", endpointKey: "1111111111111111" } }] },
  ]) {
    const result = explainProfileDocument(document(routing), "1.1.1.1:53");
    assert.equal(result.outbound, "dns");
    assert.equal(result.source, "dnsCapture");
    assert.equal(result.layer, undefined);
  }
});

test("protected DNS preferences do not become ordinary direct routing exceptions", () => {
  const value = document({
    user: [{ selectors: ["full:private.test"], target: { kind: "proxy" } }], base: [],
  });
  value.profile.xrayDns = { servers: [{ address: "9.9.9.9", route: "direct" }] };
  const result = explainProfileDocument(value, "9.9.9.9:443");
  assert.equal(result.outbound, "proxy");
  assert.equal(result.source, "default");
});

test("IPv6 targets preserve User CIDR and exact-address overrides", () => {
  for (const [selector, target] of [
    ["fd00::/8", "[fd12::42]:443"],
    ["::ffff:192.0.2.42", "[::ffff:192.0.2.42]:443"],
  ]) {
    const result = explainProfileDocument(document({
      user: [{ selectors: [selector], target: { kind: "direct" } }],
      base: [{ selectors: ["::/0"], target: { kind: "proxy" } }],
    }), target);
    assert.equal(result.outbound, "direct");
    assert.equal(result.policyPath, "/profile/routing/user/0");
  }
});

test("destination URLs are normalized without returning userinfo or query secrets", () => {
  const result = explainProfileDocument(document({
    user: [{ selectors: ["full:site.test"], target: { kind: "direct" } }], base: [],
  }), "https://private-user:private-secret@site.test:8443/private?token=private-token");
  assert.equal(result.outbound, "direct");
  assert.equal(result.target, "site.test");
  assert.equal(result.port, 8443);
  assert.equal(JSON.stringify(result).includes("private-"), false);
});

test("a known selector in the same OR row wins without DNS evidence", () => {
  const result = explainProfileDocument(document({
    user: [{ selectors: ["203.0.113.0/24", "full:site.test"], target: { kind: "direct" } }],
    base: [],
  }), "site.test");
  assert.equal(result.outbound, "direct");
  assert.equal(result.certainty, "certain");
});
