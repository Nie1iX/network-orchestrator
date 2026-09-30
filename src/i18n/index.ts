import { useSyncExternalStore } from "react";
import { catalogs, type TranslationKey } from "./catalog.generated.ts";
import { resolveLanguage, translateMessage, type Arguments } from "./engine.ts";

export type { TranslationKey };

const STORAGE_KEY = "netmanager.language";
const LEGACY_STORAGE_KEY = "netmanager.ui.language";
const listeners = new Set<() => void>();
function readPreference(): string {
  try {
    let saved = localStorage.getItem(STORAGE_KEY);
    if (!saved) {
      saved = localStorage.getItem(LEGACY_STORAGE_KEY);
      if (saved) {
        localStorage.setItem(STORAGE_KEY, saved);
        localStorage.removeItem(LEGACY_STORAGE_KEY);
      }
    }
    return saved && (saved === "system" || Object.prototype.hasOwnProperty.call(catalogs, saved)) ? saved : "system";
  } catch { return "system"; }
}
let preference = readPreference();
export const availableLanguages = Object.entries(catalogs).map(([code, catalog]) => ({ code, name: catalog.name }));
export function currentLanguage(): string {
  return resolveLanguage(preference, typeof navigator === "undefined" ? ["en"] : navigator.languages, catalogs);
}
export function tr(key: string, args?: Arguments): string {
  return translateMessage(catalogs, currentLanguage(), key, args);
}
function notify(): void {
  if (typeof document !== "undefined") {
    const language = currentLanguage();
    document.documentElement.lang = language;
    document.documentElement.dir = catalogs[language].direction;
  }
  listeners.forEach((listener) => listener());
}
export function setLanguage(value: string): void {
  if (value !== "system" && !Object.prototype.hasOwnProperty.call(catalogs, value)) return;
  preference = value;
  try { localStorage.setItem(STORAGE_KEY, value); } catch { /* Session selection still works. */ }
  notify();
}
function storageChanged(event: StorageEvent): void {
  if (event.key === STORAGE_KEY || event.key === null) { preference = readPreference(); notify(); }
}
function subscribe(listener: () => void): () => void {
  if (listeners.size === 0) {
    window.addEventListener("storage", storageChanged);
    window.addEventListener("languagechange", notify);
    notify();
  }
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      window.removeEventListener("storage", storageChanged);
      window.removeEventListener("languagechange", notify);
    }
  };
}
const snapshot = () => `${preference}:${currentLanguage()}`;
export function useLanguage() {
  useSyncExternalStore(subscribe, snapshot);
  return { preference, language: currentLanguage(), setLanguage };
}

// Compatibility layer for the dotted-key t()/useT() call sites; the same
// strings live in locales/*.json under their dotted keys.

export function t(key: TranslationKey, params?: Arguments): string {
  return tr(key, params);
}

export function useT() {
  useLanguage();
  return t;
}
