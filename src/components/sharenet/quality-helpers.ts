/**
 * ShareNet — UI styling helpers for path quality + node/event display.
 *
 * Centralises the (quality / type) → (label / Tailwind classes) mapping so
 * every screen renders quality with a consistent, accessible visual language.
 * The rule "never colour alone" is enforced by always pairing the colour with
 * both a textual label and an icon — the icon components live in
 * `glyphs.tsx` and consume these helpers for their colour palette.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import type { NetworkNode, PathQuality } from '@/lib/sharenet';

// ─── Quality → label ──────────────────────────────────────────────────────

export function qualityLabel(q: PathQuality | undefined): string {
  switch (q) {
    case 'excellent':
      return 'Excellent';
    case 'good':
      return 'Good';
    case 'fair':
      return 'Fair';
    case 'poor':
      return 'Poor';
    default:
      return 'Unknown';
  }
}

// ─── Quality → colour classes ─────────────────────────────────────────────
//
// Returned as a structured object so callers can pick text / bg / ring / dot
// independently without re-parsing a class string.

export interface QualityPalette {
  text: string;
  bg: string;
  ring: string;
  dot: string;
  /** Soft track used for connection lines + progress bars. */
  track: string;
}

export function qualityPalette(q: PathQuality | undefined): QualityPalette {
  switch (q) {
    case 'excellent':
      return {
        text: 'text-emerald-600 dark:text-emerald-400',
        bg: 'bg-emerald-50 dark:bg-emerald-950/40',
        ring: 'ring-emerald-200 dark:ring-emerald-900/60',
        dot: 'bg-emerald-500 dark:bg-emerald-400',
        track: 'bg-emerald-200 dark:bg-emerald-900/50',
      };
    case 'good':
      return {
        text: 'text-sky-600 dark:text-sky-400',
        bg: 'bg-sky-50 dark:bg-sky-950/40',
        ring: 'ring-sky-200 dark:ring-sky-900/60',
        dot: 'bg-sky-500 dark:bg-sky-400',
        track: 'bg-sky-200 dark:bg-sky-900/50',
      };
    case 'fair':
      return {
        text: 'text-amber-600 dark:text-amber-400',
        bg: 'bg-amber-50 dark:bg-amber-950/40',
        ring: 'ring-amber-200 dark:ring-amber-900/60',
        dot: 'bg-amber-500 dark:bg-amber-400',
        track: 'bg-amber-200 dark:bg-amber-900/50',
      };
    case 'poor':
      return {
        text: 'text-rose-600 dark:text-rose-400',
        bg: 'bg-rose-50 dark:bg-rose-950/40',
        ring: 'ring-rose-200 dark:ring-rose-900/60',
        dot: 'bg-rose-500 dark:bg-rose-400',
        track: 'bg-rose-200 dark:bg-rose-900/50',
      };
    default:
      return {
        text: 'text-muted-foreground',
        bg: 'bg-muted/60',
        ring: 'ring-border',
        dot: 'bg-muted-foreground',
        track: 'bg-border',
      };
  }
}

// ─── Node status → human label ─────────────────────────────────────────────

export function nodeStatusLabel(node: NetworkNode): string {
  switch (node.status) {
    case 'connected':
      return 'Connected';
    case 'available':
      return 'Available';
    case 'degraded':
      return 'Degraded';
    case 'offline':
      return 'Offline';
  }
}

// ─── Formatters ────────────────────────────────────────────────────────────

/** Formats a latency in ms as "42 ms" (or "—" if missing). */
export function formatLatency(ms: number | undefined): string {
  if (ms === undefined || Number.isNaN(ms)) return '—';
  return `${Math.round(ms)} ms`;
}

/** Formats a 0–1 reliability as a percentage with one decimal, e.g. "99.8%". */
export function formatReliability(r: number | undefined): string {
  if (r === undefined || Number.isNaN(r)) return '—';
  return `${(r * 100).toFixed(1)}%`;
}

/** Formats a Date as "HH:MM" (24h, locale-independent). */
export function formatClock(d: Date): string {
  const h = d.getHours().toString().padStart(2, '0');
  const m = d.getMinutes().toString().padStart(2, '0');
  return `${h}:${m}`;
}

/** Day bucket label for a given Date relative to "now" (Today / Yesterday / weekday). */
export function formatDayBucket(d: Date): string {
  const now = new Date();
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const startOfDay = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const dayMs = 86_400_000;
  const diffDays = Math.round((startOfToday.getTime() - startOfDay.getTime()) / dayMs);
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays > 1 && diffDays < 7) {
    return d.toLocaleDateString(undefined, { weekday: 'long' });
  }
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
