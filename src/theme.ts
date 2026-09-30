export type Appearance = "system" | "light" | "dark";

export function readAppearance(): Appearance {
  try {
    const value = localStorage.getItem("appearance");
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

export function applyAppearance(value: Appearance): void {
  document.documentElement.dataset.theme = value;
}

export function saveAppearance(value: Appearance): void {
  try { localStorage.setItem("appearance", value); } catch { /* Current-session theme still works. */ }
  applyAppearance(value);
}
