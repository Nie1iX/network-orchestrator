export interface ConnectionSnippet {
  id: string;
  name: string;
  profileIds: string[];
}

const SNIPPETS_KEY = "netmanager.connections.snippets";

export function loadSnippets(): ConnectionSnippet[] {
  try {
    const raw = localStorage.getItem(SNIPPETS_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as ConnectionSnippet[];
  } catch {
    return [];
  }
}

export function storeSnippets(snippets: ConnectionSnippet[]): void {
  try {
    localStorage.setItem(SNIPPETS_KEY, JSON.stringify(snippets));
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
}

export function newSnippetId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function sameIds(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const setA = new Set(a);
  return b.every((id) => setA.has(id));
}
