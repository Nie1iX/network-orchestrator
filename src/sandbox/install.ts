import { emit } from "@tauri-apps/api/event";
import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { isTauri } from "@tauri-apps/api/core";
import { SandboxBackend } from "./backend";

export function installSandbox() {
  if (isTauri()) throw new Error("Run the sandbox in a browser using npm run dev:sandbox");
  const backend = new SandboxBackend();
  mockIPC((command, args) => {
    if (Array.isArray(args) || args instanceof ArrayBuffer || ArrayBuffer.isView(args)) {
      throw new Error("Binary IPC is disabled in sandbox");
    }
    const result = backend.invoke(command, args);
    if (/^(connect_|disconnect_|save_|delete_|switch_|refresh_|import_)/.test(command)) {
      queueMicrotask(() => void emit("route-changed"));
    }
    return result;
  }, { shouldMockEvents: true });
  mockWindows("main");
  // Components gate IPC behind isTauri() (browser preview must stay inert);
  // the mock provides __TAURI_INTERNALS__ but not the isTauri flag itself.
  (window as unknown as { isTauri: boolean }).isTauri = true;
  const banner = document.createElement("div");
  banner.textContent = "SANDBOX · Synthetic VPN data · No changes to your network · Reload resets VPN state";
  banner.setAttribute("role", "status");
  banner.style.cssText = "position:fixed;top:0;left:0;right:0;height:34px;display:grid;place-items:center;background:#153e35;color:#fff;text-align:center;z-index:9999;font:13px system-ui";
  const layout = document.createElement("style");
  layout.textContent = "#root{padding-top:34px}.app-layout{height:calc(100vh - 34px)}";
  document.head.append(layout);
  document.body.append(banner);
}
