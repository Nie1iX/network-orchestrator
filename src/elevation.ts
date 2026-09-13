import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";

export async function ensureElevation(action: string): Promise<boolean> {
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
