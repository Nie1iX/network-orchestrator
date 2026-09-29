import { invoke } from "@tauri-apps/api/core";
import { confirm, message } from "@tauri-apps/plugin-dialog";
import type { DaemonStatus, Profile } from "./types";

export function requiresElevation(profile: Profile): boolean {
  return (
    profile.backend === "wireGuard" ||
    profile.backend === "openVpn" ||
    profile.routes.length > 0
  );
}

export async function ensureElevation(action: string): Promise<boolean> {
  const daemon = await invoke<DaemonStatus>("daemon_status");
  if (daemon.state === "ready") return true;
  if (daemon.state !== "notRequired") {
    await message(`${action} requires the network daemon. ${daemon.message}`, {
      title: "Network daemon unavailable",
      kind: "warning",
    });
    return false;
  }
  const elevated = await invoke<boolean>("is_elevated");
  if (elevated) return true;
  const approved = await confirm(
    `${action} requires administrator privileges. Restart the application as administrator?`,
    {
      title: "Administrator privileges required",
      kind: "warning",
      okLabel: "Restart as administrator",
      cancelLabel: "Cancel",
    }
  );
  if (!approved) return false;
  await invoke("restart_elevated");
  return false;
}
