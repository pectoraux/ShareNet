'use client';

/**
 * ShareNet — Network screen
 *
 * A clean topology view of the user's path to the Internet:
 *
 *         Internet
 *            │
 *         Gateway
 *            │
 *          Relay
 *            │
 *           You
 *
 * The page renders:
 *   1. A page header (title + a "Prototype" pill when IS_MOCK).
 *   2. A "Path quality" summary at the top — overall quality (human language,
 *      icon + colour, never colour alone) + the headline latency.
 *   3. The vertical topology (`<NetworkPath>`), with each node a button that
 *      opens a detail sheet on the right.
 *   4. The detail sheet (`<NetworkPathDetailSheet>`) for the selected node.
 *
 * The page deliberately does NOT expose NodeId, RouteHop, X25519 or
 * TransportEndpoint — those wire-level identifiers are absorbed by the
 * adapter. Only user-meaningful labels (You / Relay / Gateway / Internet +
 * Available / Connected) reach this view.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import * as React from 'react';
import { RefreshCw } from 'lucide-react';

import { cn } from '@/lib/utils';
import {
  IS_MOCK,
  getNetworkPath,
  type NetworkNode,
  type NetworkPath as NetworkPathType,
} from '@/lib/sharenet';
import { AppShell } from '@/components/sharenet/app-shell';
import { NetworkPath } from '@/components/sharenet/network-path';
import { NetworkPathDetailSheet } from '@/components/sharenet/network-path-detail-sheet';
import { QualityGlyph } from '@/components/sharenet/glyphs';
import {
  formatLatency,
  formatReliability,
  qualityLabel,
  qualityPalette,
} from '@/components/sharenet/quality-helpers';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';

export default function NetworkPage() {
  return (
    <AppShell>
      <NetworkContent />
    </AppShell>
  );
}

function NetworkContent() {
  const [path, setPath] = React.useState<NetworkPathType | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [selected, setSelected] = React.useState<NetworkNode | null>(null);
  const [sheetOpen, setSheetOpen] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await getNetworkPath();
      setPath(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load path');
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const handleSelect = React.useCallback((node: NetworkNode) => {
    setSelected(node);
    setSheetOpen(true);
  }, []);

  return (
    <>
      <PageHeader onRefresh={load} refreshing={loading} />

      {loading ? (
        <PathQualitySkeleton />
      ) : error ? (
        <ErrorCard message={error} onRetry={load} />
      ) : path ? (
        <PathQualitySummary path={path} />
      ) : null}

      <section
        aria-label="Network topology"
        className="mt-8 flex flex-col items-center"
      >
        {loading ? (
          <TopologySkeleton />
        ) : path ? (
          <NetworkPath
            path={path}
            selectedNodeId={selected?.id}
            onSelectNode={handleSelect}
          />
        ) : (
          <p className="text-sm text-muted-foreground">No active path.</p>
        )}
      </section>

      <NetworkPathDetailSheet
        node={selected}
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        totalHops={path?.totalHops}
      />
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
    <header className="mb-6 flex items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Network
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Your path to the Internet. Tap any hop for details.
        </p>
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
          aria-label="Refresh network path"
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

// ─── Path quality summary ─────────────────────────────────────────────────
//
// The headline metric: overall path quality (Excellent / Good / Fair / Poor)
// as a human label with icon + colour, plus the headline latency and the
// derived reliability. Advanced metrics (loss, availability, hop count) are
// shown as small secondary stats so they don't compete with the headline.

function PathQualitySummary({ path }: { path: NetworkPathType }) {
  const palette = qualityPalette(path.overallQuality);

  return (
    <section
      aria-label="Path quality summary"
      className={cn(
        'rounded-2xl border border-border/60 bg-card/70 p-5',
        'ring-1 ring-inset',
        palette.ring,
      )}
    >
      <div className="flex items-start gap-4">
        <span
          aria-hidden
          className={cn(
            'flex size-11 shrink-0 items-center justify-center rounded-full ring-1',
            palette.bg,
            palette.text,
            palette.ring,
          )}
        >
          <QualityGlyph
            quality={path.overallQuality}
            className="size-5"
            strokeWidth={2}
          />
        </span>

        <div className="flex min-w-0 flex-1 flex-col">
          <span className="text-xs uppercase tracking-wide text-muted-foreground">
            Path quality
          </span>
          <span className="mt-0.5 flex items-baseline gap-2">
            <span className={cn('text-xl font-semibold', palette.text)}>
              {qualityLabel(path.overallQuality)}
            </span>
            <span className="text-sm text-muted-foreground">
              · {formatLatency(path.latencyMs)} round trip
            </span>
          </span>
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
            {qualitySentence(path.overallQuality, path.reliability)}
          </p>
        </div>
      </div>

      {/* Secondary metrics — clearly demoted. */}
      <dl className="mt-5 grid grid-cols-3 gap-3 border-t border-border/60 pt-4">
        <SecondaryMetric
          label="Latency"
          value={formatLatency(path.latencyMs)}
        />
        <SecondaryMetric
          label="Reliability"
          value={formatReliability(path.reliability)}
        />
        <SecondaryMetric
          label="Hops"
          value={`${path.totalHops}`}
        />
      </dl>
    </section>
  );
}

function SecondaryMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[0.7rem] uppercase tracking-wide text-muted-foreground/80">
        {label}
      </dt>
      <dd className="text-sm font-medium tabular-nums text-foreground">
        {value}
      </dd>
    </div>
  );
}

function qualitySentence(q: NetworkPathType['overallQuality'], reliability: number): string {
  switch (q) {
    case 'excellent':
      return `Your connection is excellent — stable, fast, and ${formatReliability(
        reliability,
      )} reliable over the last 24 hours.`;
    case 'good':
      return `Your connection is good — fast enough for streaming and calls, ${formatReliability(
        reliability,
      )} reliable.`;
    case 'fair':
      return `Your connection is fair — usable, but you may notice slower loads.`;
    case 'poor':
      return `Your connection is poor — recovery is engaged, hang tight.`;
    default:
      return `We're still measuring this path.`;
  }
}

// ─── Skeletons ─────────────────────────────────────────────────────────────

function PathQualitySkeleton() {
  return (
    <div className="rounded-2xl border border-border/60 bg-card/70 p-5">
      <div className="flex items-start gap-4">
        <Skeleton className="size-11 rounded-full" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-3 w-16" />
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-4 w-72" />
        </div>
      </div>
      <div className="mt-5 grid grid-cols-3 gap-3 border-t border-border/60 pt-4">
        <Skeleton className="h-9" />
        <Skeleton className="h-9" />
        <Skeleton className="h-9" />
      </div>
    </div>
  );
}

function TopologySkeleton() {
  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-2">
      {[0, 1, 2, 3].map((i) => (
        <React.Fragment key={i}>
          <Skeleton className="h-16 w-full rounded-2xl" />
          {i < 3 && <div className="mx-auto h-8 w-px bg-border/40" />}
        </React.Fragment>
      ))}
    </div>
  );
}

// ─── Error state ────────────────────────────────────────────────────────────

function ErrorCard({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="rounded-2xl border border-rose-200/60 bg-rose-50/60 p-5 dark:border-rose-900/40 dark:bg-rose-950/20">
      <p className="text-sm font-medium text-rose-700 dark:text-rose-300">
        Couldn't load the network path
      </p>
      <p className="mt-1 text-xs text-rose-700/80 dark:text-rose-300/80">{message}</p>
      <Button variant="outline" size="sm" onClick={onRetry} className="mt-3">
        Try again
      </Button>
    </div>
  );
}
