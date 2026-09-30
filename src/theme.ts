import { useSyncExternalStore } from "react";

export type Appearance = "system" | "light" | "dark";
export type ResolvedTheme = "dark" | "light";

const KEY = "appearance";
const EVENT = "appearance-changed";
const MEDIA = "(prefers-color-scheme: light)";

export function readAppearance(): Appearance {
  try {
    const value = localStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

export function applyAppearance(value: Appearance): void {
  document.documentElement.dataset.theme = value;
  window.dispatchEvent(new Event(EVENT));
}

export function saveAppearance(value: Appearance): void {
  try { localStorage.setItem(KEY, value); } catch { /* Current-session theme still works. */ }
  applyAppearance(value);
}

/** Effective theme — resolves "system" through the OS media query. */
export function resolvedAppearance(): ResolvedTheme {
  const pref = readAppearance();
  if (pref !== "system") return pref;
  try {
    return window.matchMedia(MEDIA).matches ? "light" : "dark";
  } catch {
    return "dark";
  }
}

function subscribe(listener: () => void): () => void {
  window.addEventListener(EVENT, listener);
  const media = window.matchMedia(MEDIA);
  media.addEventListener("change", listener);
  return () => {
    window.removeEventListener(EVENT, listener);
    media.removeEventListener("change", listener);
  };
}

/** Resolved theme that re-renders on preference or OS changes. */
export function useTheme(): ResolvedTheme {
  return useSyncExternalStore(subscribe, resolvedAppearance);
}
