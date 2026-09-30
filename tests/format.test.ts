import assert from "node:assert/strict";
import test from "node:test";
import { formatBytes, formatRate } from "../src/format.ts";

test("formatBytes: bytes below 1 KB stay integral", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1), "1 B");
  assert.equal(formatBytes(1023), "1023 B");
});

test("formatBytes: KB and MB use one decimal", () => {
  assert.equal(formatBytes(1024), "1.0 KB");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(1024 * 1024), "1.0 MB");
  assert.equal(formatBytes(1024 * 1024 - 1), "1024.0 KB");
  assert.equal(formatBytes(1024 * 1024 * 1024 - 1), "1024.0 MB");
});

test("formatBytes: GB uses two decimals", () => {
  assert.equal(formatBytes(1024 * 1024 * 1024), "1.00 GB");
  assert.equal(formatBytes(5.5 * 1024 * 1024 * 1024), "5.50 GB");
});

test("formatRate: integer B/s, fractional KB/s and MB/s", () => {
  assert.equal(formatRate(0), "0 B/s");
  assert.equal(formatRate(512), "512 B/s");
  assert.equal(formatRate(1023.6), "1024 B/s");
  assert.equal(formatRate(1024), "1.0 KB/s");
  assert.equal(formatRate(2048), "2.0 KB/s");
  assert.equal(formatRate(1024 * 1024), "1.0 MB/s");
  assert.equal(formatRate(2.25 * 1024 * 1024), "2.3 MB/s");
});
