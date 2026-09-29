// Categorical color palette (OKLCH).
// All entries share one lightness/chroma so no owner/category reads
// brighter than another — equal visual weight by construction.
// Keep hues in sync with the --cat-* tokens in App.css.

export const OWNER_COLORS = [
  "oklch(0.72 0.16 277)", // indigo — matches --accent
  "oklch(0.76 0.17 162)", // green
  "oklch(0.76 0.15 55)",  // orange
  "oklch(0.70 0.20 22)",  // red
  "oklch(0.72 0.17 315)", // violet
  "oklch(0.78 0.12 205)", // cyan
  "oklch(0.80 0.13 120)", // chartreuse
  "oklch(0.74 0.16 350)", // pink
];

export const OWNER_FALLBACK = "oklch(0.66 0.01 280)";

export function categoricalColor(index: number): string {
  return OWNER_COLORS[index % OWNER_COLORS.length] ?? OWNER_FALLBACK;
}

export function colorForKey(key: string, keys: readonly string[]): string {
  const idx = keys.indexOf(key);
  return idx < 0 ? OWNER_FALLBACK : categoricalColor(idx);
}

// Neutral tones for Sankey nodes (mirror --text-muted / surfaces).
export const FLOW_NEUTRAL = "oklch(0.53 0.016 280)";
export const FLOW_NEUTRAL_FAINT = "oklch(0.42 0.014 280)";
export const FLOW_TEXT = "oklch(0.92 0.008 280)";
export const FLOW_TEXT_DIM = "oklch(0.92 0.008 280 / 0.62)";
