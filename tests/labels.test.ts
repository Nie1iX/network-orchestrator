import assert from "node:assert/strict";
import test from "node:test";
import { catalogs } from "../src/i18n/catalog.generated.ts";
import {
  BACKEND_LABEL_KEYS,
  CATEGORY_DESC_KEYS,
  CATEGORY_LABEL_KEYS,
  SOURCE_LABEL_KEYS,
} from "../src/i18n/labels.ts";

const MAPS = {
  BACKEND_LABEL_KEYS,
  SOURCE_LABEL_KEYS,
  CATEGORY_LABEL_KEYS,
  CATEGORY_DESC_KEYS,
};

test("label maps cover every enum value exactly once", () => {
  assert.deepEqual(Object.keys(BACKEND_LABEL_KEYS).sort(), [
    "none",
    "openVpn",
    "wireGuard",
    "xray",
  ]);
  assert.deepEqual(Object.keys(SOURCE_LABEL_KEYS).sort(), [
    "autoDetected",
    "configured",
    "managed",
  ]);
  const cats = ["filter", "physical", "system", "tunnel", "virtual", "vpn"];
  assert.deepEqual(Object.keys(CATEGORY_LABEL_KEYS).sort(), cats);
  assert.deepEqual(Object.keys(CATEGORY_DESC_KEYS).sort(), cats);
});

test("every label key exists in the generated catalog for all locales", () => {
  for (const [name, map] of Object.entries(MAPS)) {
    for (const [variant, key] of Object.entries(map)) {
      for (const [lang, catalog] of Object.entries(catalogs)) {
        assert.ok(
          Object.prototype.hasOwnProperty.call(catalog.messages, key),
          `${name}.${variant} -> ${key} missing in ${lang}`,
        );
      }
    }
  }
});

test("label keys are distinct between label and description maps", () => {
  const labels = new Set(Object.values(CATEGORY_LABEL_KEYS));
  for (const key of Object.values(CATEGORY_DESC_KEYS)) {
    assert.ok(!labels.has(key), `${key} collides with a label key`);
  }
});
