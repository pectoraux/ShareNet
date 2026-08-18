'use client';

/**
 * ShareNet Home — the consumer landing page.
 *
 * This is the most important surface in the app. It has to answer two
 * questions at a glance:
 *
 *   1. Am I online through ShareNet?
 *   2. Is my connection safe?
 *
 * The page is intentionally spare: an animated connection ring + state label,
 * a one-sentence explanation, a primary action button, a compact summary of
 * four facts (Connection / Path / Internet / Privacy), and nothing else.
 * Whitespace and typography carry the hierarchy — no cards, no chrome.
 *
 * The page fetches `getConnectionSummary()` from the adapter on mount and
 * shows a skeleton while loading. The primary action button calls the
 * adapter's `connect()` / `disconnect()` based on the current state, then
 * refetches and notifies the AppShell (via a custom event) so the sidebar
 * indicator updates in lockstep.
 *
 * When `IS_MOCK` is true, a discreet "Preview state" row appears at the top
 * so reviewers can see how the hero renders for each connection state. The
 * selector is purely visual — it overrides the displayed state but does not
 * touch the adapter. Clicking any primary action clears the override and
 * returns the hero to the real adapter state.
 *
 * Task ID: UI-SHELL-HOME
 */

import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';

import { cn } from '@/lib/utils';
import {
  IS_MOCK,
  connect,
  disconnect,
  getConnectionSummary,
  type ConnectionSummary,
  type ConnectionState,
} from '@/lib/sharenet';
import { ConnectionHero } from '@/components/sharenet/connection-hero';
import { ConnectionSummaryGrid } from '@/components/sharenet/connection-summary';
import {
  connectionStateLabel,
} from '@/components/sharenet/connection-state-indicator';
import {
  dispatchConnectionStateChange,
} from '@/components/sharenet/app-shell';
import { Skeleton } from '@/components/ui/skeleton';

// ─── Demo-only: preview state override ────────────────────────────────────
//
// When IS_MOCK is true, the home page exposes a small row of buttons that
// lets a reviewer preview how the hero renders for each connection state.
// The real adapter only cycles between `connected` and `disconnected` (via
// the connect()/disconnect() mock mutations), so without this selector the
// `connecting` / `recovering` / `offline` states would never be visible.

const PREVIEW_STATES: ConnectionState[] = [
  'connected',
  'connecting',
  'recovering',
  'offline',
];

// ─── Loading skeleton ──────────────────────────────────────────────────────

function HomeLoadingSkeleton() {
  return (
    <div className="flex flex-col items-center">
      {/* Ring skeleton */}
      <div className="mb-12 size-44 rounded-full" aria-hidden>
        <Skeleton className="size-full rounded-full" />
      </div>
      {/* Headline skeleton */}
      <Skeleton className="mb-4 h-9 w-72" />
      <Skeleton className="mb-2 h-9 w-56" />
      {/* Subtext skeleton */}
      <Skeleton className="mb-9 h-5 w-80" />
      <Skeleton className="mb-2 h-5 w-64" />
      {/* Button skeleton */}
      <Skeleton className="mt-9 h-12 w-44 rounded-full" />

      {/* Summary skeleton */}
      <div className="mt-20 grid w-full grid-cols-2 gap-x-10 gap-y-10 sm:grid-cols-4 sm:gap-x-12">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="flex flex-col gap-2">
            <Skeleton className="h-3 w-16" />
            <Skeleton className="h-6 w-24" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Preview state selector (demo-only) ────────────────────────────────────

function PreviewStateSelector({
  current,
  onSelect,
}: {
  current: ConnectionState | null;
  onSelect: (state: ConnectionState | null) => void;
}) {
  return (
    <div
      className="mb-10 flex flex-wrap items-center justify-center gap-2 text-xs"
      role="group"
      aria-label="Preview connection state (demo only)"
    >
      <span
        className="text-[0.7rem] font-semibold uppercase tracking-[0.12em]"
        style={{ color: 'var(--muted-foreground)' }}
      >
        Preview state
      </span>
      {PREVIEW_STATES.map((s) => {
        const active = current === s;
        return (
          <button
            key={s}
            type="button"
            onClick={() => onSelect(active ? null : s)}
            aria-pressed={active}
            className={cn(
              'rounded-full border px-3 py-1 text-xs font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--ring)]',
            )}
            style={{
              borderColor: active ? 'var(--foreground)' : 'var(--border)',
              backgroundColor: active ? 'var(--foreground)' : 'transparent',
              color: active
                ? 'var(--background)'
                : 'var(--muted-foreground)',
            }}
          >
            {connectionStateLabel(s)}
          </button>
        );
      })}
      {current !== null && (
        <button
          type="button"
          onClick={() => onSelect(null)}
          className="text-[0.7rem] underline underline-offset-2"
          style={{ color: 'var(--muted-foreground)' }}
        >
          Reset to live
        </button>
      )}
    </div>
  );
}

// ─── Error state ───────────────────────────────────────────────────────────

function HomeErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center text-center" role="alert">
      <div
        className="mb-6 flex size-14 items-center justify-center rounded-full"
        style={{
          backgroundColor: 'var(--sn-error-soft)',
          color: 'var(--sn-error-text)',
        }}
        aria-hidden
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.75}
          strokeLinecap="round"
          strokeLinejoin="round"
          className="size-6"
        >
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
          <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        </svg>
      </div>
      <h1
        className="text-2xl font-semibold tracking-tight"
        style={{ color: 'var(--foreground)' }}
      >
        Couldn't load your connection.
      </h1>
      <p
        className="mt-3 max-w-sm text-base leading-relaxed"
        style={{ color: 'var(--muted-foreground)' }}
      >
        Something went wrong talking to the ShareNet adapter. Please try again.
      </p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-8 h-11 rounded-full px-6 text-sm font-medium text-white transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--ring)] focus-visible:ring-offset-2"
        style={{ backgroundColor: 'var(--primary)' }}
      >
        Try again
      </button>
    </div>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────

export default function HomePage() {
  const [summary, setSummary] = useState<ConnectionSummary | null>(null);
  const [loadError, setLoadError] = useState<Error | null>(null);
  const [isPending, setIsPending] = useState(false);
  const [previewState, setPreviewState] = useState<ConnectionState | null>(null);

  const fetchSummary = useCallback(async () => {
    setLoadError(null);
    try {
      const s = await getConnectionSummary();
      setSummary(s);
    } catch (e) {
      setLoadError(e instanceof Error ? e : new Error(String(e)));
    }
  }, []);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  const handlePrimaryAction = useCallback(async () => {
    if (!summary) return;
    setIsPending(true);
    try {
      // The action depends on the REAL adapter state, not the preview
      // override — so we read from `summary.state`, not `displaySummary.state`.
      switch (summary.state) {
        case 'connected':
        case 'degraded':
        case 'recovering':
        case 'connecting':
          // For any "online-ish" state, the primary action disconnects.
          await disconnect();
          break;
        case 'disconnected':
        case 'disabled':
        case 'offline':
          // For any "offline-ish" state, the primary action connects.
          await connect();
          break;
      }
      // Clear any preview override so the hero reflects the real new state.
      setPreviewState(null);
      await fetchSummary();
      // Notify the AppShell sidebar to refetch its indicator.
      dispatchConnectionStateChange();
    } catch (e) {
      setLoadError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setIsPending(false);
    }
  }, [summary, fetchSummary]);

  // Apply the demo-only preview override on top of the real summary.
  const displaySummary: ConnectionSummary | null =
    summary && previewState ? { ...summary, state: previewState } : summary;

  return (
    <div className="flex flex-col">
      {/* Demo-only: preview state selector. Hidden in production. */}
      {IS_MOCK && summary && (
        <PreviewStateSelector
          current={previewState}
          onSelect={setPreviewState}
        />
      )}

      {/* Main content: hero + summary, or skeleton, or error */}
      {loadError ? (
        <HomeErrorState onRetry={fetchSummary} />
      ) : !displaySummary ? (
        <HomeLoadingSkeleton />
      ) : (
        <>
          <ConnectionHero
            summary={displaySummary}
            onPrimaryAction={handlePrimaryAction}
            isPending={isPending}
          />

          {/* Whitespace gap between hero and summary — generous on purpose. */}
          <div className="mt-20 sm:mt-24">
            <ConnectionSummaryGrid summary={displaySummary} />
          </div>
        </>
      )}
    </div>
  );
}
