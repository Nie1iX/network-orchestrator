const SEPARATOR = /[\s\-–—|·•]+$/;

/**
 * Subscription endpoints frequently embed the provider name as a shared
 * prefix ("Geodema - NL 🇳🇱"). When every name carries the same
 * separator-terminated prefix, split it out so the list can show just the
 * endpoint part and the provider can be surfaced once elsewhere.
 */
export function providerPrefix(names: string[]): {
  provider: string | null;
  names: string[];
} {
  if (names.length < 2) return { provider: null, names };

  let prefix = names[0];
  for (const name of names.slice(1)) {
    while (prefix !== "" && !name.startsWith(prefix)) {
      prefix = prefix.slice(0, -1);
    }
    if (prefix === "") return { provider: null, names };
  }

  // A provider prefix ends at a separator boundary — "Geodema - " qualifies,
  // a mid-word overlap like "Geodema-NL" does not.
  if (!SEPARATOR.test(prefix)) return { provider: null, names };
  const provider = prefix.replace(SEPARATOR, "").trim();
  if (provider === "") return { provider: null, names };

  const stripped = names.map((n) => n.slice(prefix.length).trim());
  if (stripped.some((s) => s === "")) return { provider: null, names };

  return { provider, names: stripped };
}
