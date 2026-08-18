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
import {
  ErrorState,
  LoadingSkeleton,
} from '@/components/sharenet/state-blocks';
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
        <LoadingSkeleton variant="network" />
      ) : error ? (
        <ErrorState
          title="Couldn't load the network path"
          message="Something went wrong while reading the ShareNet network."
          onRetry={load}
        />
      ) : path ? (
        <>
          <PathQualitySummary path={path} />
          <section
            aria-label="Network topology"
            className="mt-8 flex flex-col items-center"
          >
            <NetworkPath
              path={path}
              selectedNodeId={selected?.id}
              onSelectNode={handleSelect}
            />
          </section>
        </>
      ) : null}

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
//
// Inlined loading skeletons have moved to the shared
// `<LoadingSkeleton variant="network" />` block in
// `src/components/sharenet/state-blocks.tsx`. The block renders the
// path-quality card skeleton + the 4-node topology skeleton together, so
// the loading → content transition is seamless.
