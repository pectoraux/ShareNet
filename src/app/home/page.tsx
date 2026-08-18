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
import {
  ErrorState,
  LoadingSkeleton,
} from '@/components/sharenet/state-blocks';

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
        <ErrorState
          title="Couldn't load your connection"
          message="Something went wrong while reading ShareNet status."
          onRetry={fetchSummary}
        />
      ) : !displaySummary ? (
        <LoadingSkeleton variant="home" />
      ) : (
        <>
          <ConnectionHero
            summary={displaySummary}
            onPrimaryAction={handlePrimaryAction}
            onShowDetails={() => {
              // Scroll to the connection summary section below.
              document.getElementById('connection-summary')?.scrollIntoView({
                behavior: 'smooth',
                block: 'start',
              });
            }}
            isPending={isPending}
          />

          {/* Whitespace gap between hero and summary — generous on purpose. */}
          <div id="connection-summary" className="mt-20 scroll-mt-20 sm:mt-24">
            <ConnectionSummaryGrid summary={displaySummary} />
          </div>
        </>
      )}
    </div>
  );
}
