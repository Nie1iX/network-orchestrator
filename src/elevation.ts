import { invoke } from "@tauri-apps/api/core";
import { confirm, message } from "@tauri-apps/plugin-dialog";
import { t } from "./i18n";
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
    await message(t("elev.daemonUnavailable", { action, msg: daemon.message }), {
      title: t("elev.daemonUnavailableTitle"),
      kind: "warning",
    });
    return false;
  }
  const elevated = await invoke<boolean>("is_elevated");
  if (elevated) return true;
  const approved = await confirm(
    t("elev.adminRequired", { action }),
    {
      title: t("elev.adminRequiredTitle"),
      kind: "warning",
      okLabel: t("elev.restartAdmin"),
      cancelLabel: t("common.cancel"),
    }
  );
  if (!approved) return false;
  await invoke("restart_elevated");
  return false;
}
