import assert from "node:assert/strict";
import test from "node:test";
import { clearMocks, mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { popupNativeMenu } from "../src/nativeMenu.ts";

test("browser menus use the DOM menu", async () => {
  assert.equal(await popupNativeMenu([], 10, 20), false);
});

test("overlapping Linux menus remain available through the DOM fallback", async () => {
  Object.assign(globalThis, { window: globalThis, isTauri: true });
  let resourceId = 0;
  mockIPC((command) => {
    if (command === "get_platform_capabilities") return { os: "linux" };
    if (command === "plugin:menu|new") return [++resourceId, `menu-${resourceId}`];
    if (command === "plugin:menu|popup") return;
    throw new Error(`Unexpected IPC command: ${command}`);
  });
  mockWindows("main");
  try {
    const results = await Promise.all([
      popupNativeMenu([{ label: "Refresh subscription", onClick() {} }], 10, 20),
      popupNativeMenu([{ label: "Edit", onClick() {} }], 30, 40),
    ]);
    assert.deepEqual(results, [false, false], "both callers must render responsive DOM menus on Linux");
  } finally {
    clearMocks();
    Reflect.deleteProperty(globalThis, "window");
    Reflect.deleteProperty(globalThis, "isTauri");
  }
});
