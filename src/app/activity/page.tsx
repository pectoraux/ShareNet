'use client';

/**
 * ShareNet — Activity screen
 *
 * A calm, Apple-system-style activity timeline. NOT a developer log.
 *
 *   Today
 *   ─────────────────────────────────────────
 *   ✓  10:42  Connected through ShareNet
 *      Circuit established via Amsterdam Relay 01 → …
 *
 *   ↗  10:31  Path improved
 *      Round-trip latency dropped from 71ms to 42ms.
 *   …
 *
 * Each item can expand into technical detail (event id, full timestamp,
 * severity, event-type slug) inside a Collapsible — but there are NO raw
 * stack traces and NO protocol-frame dumps anywhere in the main view.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import * as React from 'react';
import { RefreshCw } from 'lucide-react';

import { cn } from '@/lib/utils';
import {
  IS_MOCK,
  getActivityEvents,
  type ActivityEvent,
} from '@/lib/sharenet';
import { AppShell } from '@/components/sharenet/app-shell';
import { ActivityTimeline } from '@/components/sharenet/activity-timeline';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';

export default function ActivityPage() {
  return (
    <AppShell>
      <ActivityContent />
    </AppShell>
  );
}

function ActivityContent() {
  const [events, setEvents] = React.useState<ActivityEvent[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await getActivityEvents();
      setEvents(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load activity');
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  return (
    <>
      <PageHeader onRefresh={load} refreshing={loading} />

      <p className="mb-6 text-sm text-muted-foreground">
        Recent ShareNet events on this device. Tap any item for technical detail.
      </p>

      {loading ? (
        <ActivitySkeleton />
      ) : error ? (
        <ErrorCard message={error} onRetry={load} />
      ) : (
        <ActivityTimeline events={events} />
      )}
    </>
  );
}

// ─── Page header ──────────────────────────────────────────────────────────

function PageHeader({
  onRefresh,
  refreshing,
}: {
  onRefresh: () => void;
  refreshing: boolean;
}) {
  return (
    <header className="mb-2 flex items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Activity
        </h1>
      </div>
      <div className="flex items-center gap-2">
        {IS_MOCK && (
          <span className="hidden sm:inline-flex h-6 items-center rounded-full border border-amber-200/60 bg-amber-50 px-2.5 text-[11px] font-medium text-amber-700 dark:border-amber-900/50 dark:bg-amber-950/40 dark:text-amber-300">
            Prototype
          </span>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={onRefresh}
          disabled={refreshing}
          aria-label="Refresh activity"
          className="text-muted-foreground"
        >
          <RefreshCw
            className={cn('size-4', refreshing && 'animate-spin')}
            aria-hidden
          />
          <span className="sr-only">Refresh</span>
        </Button>
      </div>
    </header>
  );
}

// ─── Skeleton ──────────────────────────────────────────────────────────────

function ActivitySkeleton() {
  return (
    <div className="flex flex-col gap-8">
      <div>
        <Skeleton className="mb-3 h-3 w-16" />
        <ol className="flex flex-col">
          {[0, 1, 2, 3, 4].map((i) => (
            <li key={i} className="flex gap-3.5 px-1 py-3">
              <Skeleton className="size-9 shrink-0 rounded-full" />
              <div className="flex flex-1 flex-col gap-2 pt-1">
                <div className="flex items-center gap-2">
                  <Skeleton className="h-3 w-10" />
                  <Skeleton className="h-4 w-44" />
                </div>
                <Skeleton className="h-4 w-72" />
                <Skeleton className="h-3 w-24" />
              </div>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

// ─── Error state ────────────────────────────────────────────────────────────

function ErrorCard({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="rounded-2xl border border-rose-200/60 bg-rose-50/60 p-5 dark:border-rose-900/40 dark:bg-rose-950/20">
      <p className="text-sm font-medium text-rose-700 dark:text-rose-300">
        Couldn't load activity
      </p>
      <p className="mt-1 text-xs text-rose-700/80 dark:text-rose-300/80">{message}</p>
      <Button variant="outline" size="sm" onClick={onRetry} className="mt-3">
        Try again
      </Button>
    </div>
  );
}
