import assert from "node:assert/strict";
import test from "node:test";
import { providerPrefix } from "../src/subscriptions.ts";

test("common provider prefix is split from endpoint names", () => {
  const { provider, names } = providerPrefix([
    "Geodema - ⚡ Нидерланды",
    "Geodema - 🇩🇪 Германия",
    "Geodema - 🇫🇮 Финляндия",
  ]);
  assert.equal(provider, "Geodema");
  assert.deepEqual(names, ["⚡ Нидерланды", "🇩🇪 Германия", "🇫🇮 Финляндия"]);
});

test("mixed names keep the raw list untouched", () => {
  const input = ["Geodema - NL", "Other - DE"];
  const { provider, names } = providerPrefix(input);
  assert.equal(provider, null);
  assert.deepEqual(names, input);
});

test("prefix must end at a separator boundary, not mid-word", () => {
  const { provider, names } = providerPrefix(["Alpha-NL1", "Alpha-NL2"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Alpha-NL1", "Alpha-NL2"]);
});

test("supports en/em dashes and pipes as separators", () => {
  for (const sep of [" - ", " – ", " — ", " | "]) {
    const { provider, names } = providerPrefix([
      `Prov${sep}A`,
      `Prov${sep}B`,
    ]);
    assert.equal(provider, "Prov", `separator ${sep}`);
    assert.deepEqual(names, ["A", "B"]);
  }
});

test("single endpoint yields no provider", () => {
  const { provider, names } = providerPrefix(["Geodema - NL"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Geodema - NL"]);
});

test("identical names are not treated as a provider prefix", () => {
  const { provider, names } = providerPrefix(["Same", "Same"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Same", "Same"]);
});

test("empty remainder after stripping rejects the split", () => {
  const { provider, names } = providerPrefix(["Prov - ", "Prov - X"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Prov - ", "Prov - X"]);
});
