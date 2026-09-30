import { tr } from "./i18n";
import { invoke } from "@tauri-apps/api/core";
import { confirm, message } from "@tauri-apps/plugin-dialog";
import type { DaemonStatus } from "./types";

export async function ensureElevation(action: string): Promise<boolean> {
  const daemon = await invoke<DaemonStatus>("daemon_status");
  if (daemon.state === "ready") return true;
  if (daemon.state !== "notRequired") {
    await message(tr("{action} requires the network daemon. {message}", { action: String(action), message: String(daemon.message) }), {
      title: tr("Network daemon unavailable"),
      kind: "warning",
    });
    return false;
  }
  const elevated = await invoke<boolean>("is_elevated");
  if (elevated) return true;
  const approved = await confirm(
    tr("{action} requires administrator privileges. Restart the application as administrator?", { action: String(action) }),
    {
      title: tr("Administrator privileges required"),
      kind: "warning",
      okLabel: tr("Restart as administrator"),
      cancelLabel: tr("Cancel"),
    }
  );
  if (!approved) return false;
  await invoke("restart_elevated");
  return false;
}
