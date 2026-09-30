import { useSyncExternalStore } from "react";
import en from "./en";
import ru from "./ru";

export type Language = "en" | "ru";
export type Lang = Language;
export type TranslationKey = keyof typeof en;

/** Languages shown in Settings → General. `label` stays native on purpose. */
export const LANGS: { id: Language; label: string }[] = [
  { id: "en", label: "English" },
  { id: "ru", label: "Русский" },
];

const LANG_KEY = "netmanager.ui.language";
const EVENT = "language-changed";

const dicts: Record<Language, Partial<Record<TranslationKey, string>>> = {
  en,
  ru,
};

function detect(): Language {
  try {
    const stored = localStorage.getItem(LANG_KEY);
    if (stored === "en" || stored === "ru") return stored;
  } catch {
    // private mode — fall through to navigator
  }
  return navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
}

let current: Language = detect();

export function getLanguage(): Language {
  return current;
}

export const getLang = getLanguage;
export const setLang = setLanguage;
export const useLang = useLanguage;

export function setLanguage(lang: Language) {
  if (lang === current) return;
  current = lang;
  try {
    localStorage.setItem(LANG_KEY, lang);
  } catch {
    // private mode — keep the in-memory choice
  }
  window.dispatchEvent(new Event(EVENT));
}

export function useLanguage(): Language {
  return useSyncExternalStore(
    (callback) => {
      window.addEventListener(EVENT, callback);
      return () => window.removeEventListener(EVENT, callback);
    },
    () => current,
  );
}

export function t(
  key: TranslationKey,
  params?: Record<string, string | number>,
): string {
  let text: string = dicts[current][key] ?? en[key] ?? key;
  if (params) {
    for (const [name, value] of Object.entries(params)) {
      text = text.split(`{${name}}`).join(String(value));
    }
  }
  return text;
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
  return current === "ru"
    ? pluralRu(n, ruForms)
    : n === 1
      ? enForms[0]
      : enForms[1];
}
