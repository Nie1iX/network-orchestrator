import { useSyncExternalStore } from "react";
import { catalogs } from "./catalog.generated.ts";
import { resolveLanguage, translateMessage, type Arguments } from "./engine.ts";

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

export type Language = string;
export type Lang = Language;
export type TranslationKey = string;

/** Languages shown in Settings → General. `label` stays native on purpose. */
export const LANGS: { id: Language; label: string }[] = availableLanguages.map(
  ({ code, name }) => ({ id: code, label: name }),
);

export function getLanguage(): Language {
  return currentLanguage();
}

export const getLang = getLanguage;
export const setLang = setLanguage;

export function useLang(): Language {
  return useLanguage().language;
}

export function t(key: TranslationKey, params?: Arguments): string {
  return tr(key, params);
}

export function useT() {
  useLanguage();
  return t;
}

/** Russian plurals: [singular, paucal (2–4), plural]. */
export function pluralRu(n: number, forms: [string, string, string]): string {
  const a = Math.abs(n) % 10;
  const b = Math.abs(n) % 100;
  if (a === 1 && b !== 11) return forms[0];
  if (a >= 2 && a <= 4 && (b < 12 || b > 14)) return forms[1];
  return forms[2];
}

/**
 * Pick a count noun form for the active language.
 * ruForms: [singular, paucal, plural] — enForms: [singular, plural].
 */
export function pluralize(
  n: number,
  ruForms: [string, string, string],
  enForms: [string, string],
): string {
  return currentLanguage() === "ru"
    ? pluralRu(n, ruForms)
    : n === 1
      ? enForms[0]
      : enForms[1];
}
