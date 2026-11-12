import assert from "node:assert/strict";
import test from "node:test";
import { locateDocumentPointer } from "../src/profileDocumentLocation.ts";

test("JSON path navigation locates the correct repeated field and escaped pointer", () => {
  const text = '{ "profile": { "xrayDns": { "servers": [{"route":"direct"}, {"route": "proxy"}] }, "a/b~c": ["brace } and \\\"quote\\\"", 42] } }';
  const route = locateDocumentPointer(text, "/profile/xrayDns/servers/1/route");
  assert.ok(route);
  assert.equal(text.slice(route.start, route.end), '"proxy"');
  const escaped = locateDocumentPointer(text, "/profile/a~1b~0c/1");
  assert.ok(escaped);
  assert.equal(text.slice(escaped.start, escaped.end), "42");
});

test("JSON path navigation never jumps to a different path on invalid or missing input", () => {
  assert.equal(locateDocumentPointer('{"profile":', "/profile"), null);
  assert.equal(locateDocumentPointer('{"profile":{"route":"direct"}}', "/profile/missing/route"), null);
  assert.equal(locateDocumentPointer('{"profile":{"list":[1]}}', "/profile/list/01"), null);
});
