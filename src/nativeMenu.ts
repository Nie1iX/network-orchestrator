import { isTauri } from "@tauri-apps/api/core";
import { LogicalPosition } from "@tauri-apps/api/dpi";
import { Menu } from "@tauri-apps/api/menu";
import type { OverflowMenuItem } from "./components/ui/OverflowMenu";

export type MenuEntry = OverflowMenuItem | "separator";

/** Popup the OS-native context menu at logical window coordinates.
 * Returns false outside Tauri so callers can fall back to the DOM menu
 * (browser sandbox, tests). */
export async function popupNativeMenu(
  items: MenuEntry[],
  x: number,
  y: number,
): Promise<boolean> {
  if (!isTauri()) return false;
  const menu = await Menu.new({
    items: items.map((item, i) =>
      item === "separator"
        ? { item: "Separator" as const }
        : {
            id: `item-${i}`,
            text: item.label,
            enabled: item.disabled !== true,
            action: () => item.onClick(),
          },
    ),
  });
  await menu.popup(new LogicalPosition(x, y));
  return true;
}
