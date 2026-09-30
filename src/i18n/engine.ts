export type Message = string | Record<string, string>;
export interface PluralCondition {
  all?: PluralCondition[];
  any?: PluralCondition[];
  integer?: boolean;
  mod?: number;
  range?: [number, number];
  notRange?: [number, number];
}
export interface Catalog {
  name: string;
  direction: "ltr" | "rtl";
  pluralRules: { category: string; when: PluralCondition }[];
  messages: Record<string, Message>;
}
export type Catalogs = Record<string, Catalog>;
export type Arguments = Record<string, string | number>;

export function resolveLanguage(preference: string, systemLanguages: readonly string[], catalogs: Catalogs): string {
  const candidates = preference === "system" ? systemLanguages : [preference];
  const supported = Object.keys(catalogs);
  for (const candidate of candidates) {
    const tag = candidate.replace(/_/g, "-").toLowerCase();
    const exact = supported.find((code) => code.toLowerCase() === tag);
    if (exact) return exact;
    const base = tag.split("-")[0];
    const match = supported.find((code) => code.toLowerCase() === base)
      ?? supported.find((code) => code.toLowerCase().split("-")[0] === base);
    if (match) return match;
  }
  return "en";
}

function matches(condition: PluralCondition, number: number): boolean {
  if (condition.all && !condition.all.every((rule) => matches(rule, number))) return false;
  if (condition.any && !condition.any.some((rule) => matches(rule, number))) return false;
  if (condition.integer !== undefined && Number.isInteger(number) !== condition.integer) return false;
  const value = condition.mod ? number % condition.mod : number;
  if (condition.range && !(value >= condition.range[0] && value <= condition.range[1])) return false;
  if (condition.notRange && value >= condition.notRange[0] && value <= condition.notRange[1]) return false;
  return true;
}

export function translateMessage(catalogs: Catalogs, language: string, key: string, args: Arguments = {}): string {
  const owns = (value: object, name: string) => Object.prototype.hasOwnProperty.call(value, name);
  const selected = owns(catalogs, language) ? catalogs[language] : undefined;
  const translated = selected && owns(selected.messages, key) ? selected.messages[key] : undefined;
  const catalog = translated !== undefined ? selected : catalogs.en;
  const fallback = catalogs.en && owns(catalogs.en.messages, key) ? catalogs.en.messages[key] : key;
  const message = translated ?? fallback;
  const count = Math.abs(Number(args.count));
  const category = Number.isFinite(count)
    ? catalog?.pluralRules.find((rule) => matches(rule.when, count))?.category ?? "other"
    : "other";
  const template = typeof message === "string" ? message : message[category] ?? message.other;
  // Replace only the original template's placeholders. Argument values are never parsed as markup.
  return template.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (placeholder, name: string) =>
    Object.prototype.hasOwnProperty.call(args, name) ? String(args[name]) : placeholder);
}
