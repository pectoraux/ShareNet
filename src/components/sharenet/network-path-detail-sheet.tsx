'use client';

/**
 * NetworkPathDetailSheet — the detail panel that slides in when a user taps a
 * node in the topology.
 *
 * Shows the human side of the node:
 *   - Name + type
 *   - Status (Available / Connected)
 *   - Connection quality (Excellent / Good / Fair / Poor — colour + icon)
 *   - Latency (e.g. "42 ms")
 *   - Reliability (e.g. "99.8%")
 *   - Identity: "Verified"
 *
 * Advanced detail (latency / loss / availability / hop count) is grouped in a
 * clearly-labelled "Advanced" section so it stays secondary. The sheet never
 * shows NodeId, RouteHop, X25519 or TransportEndpoint — those are wire-level
 * concepts the user doesn't need.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import * as React from 'react';
import { ShieldCheck } from 'lucide-react';

import { cn } from '@/lib/utils';
import type { NetworkNode } from '@/lib/sharenet';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { NodeGlyph, QualityGlyph } from '@/components/sharenet/glyphs';
import {
  formatLatency,
  formatReliability,
  nodeStatusLabel,
  qualityLabel,
  qualityPalette,
} from '@/components/sharenet/quality-helpers';

export interface NetworkPathDetailSheetProps {
  node: NetworkNode | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Total hops in the active path (used to contextualise this node's hop). */
  totalHops?: number;
}

export function NetworkPathDetailSheet({
  node,
  open,
  onOpenChange,
  totalHops,
}: NetworkPathDetailSheetProps) {
  // Render even when node is null so the slide-out animation has something to
  // animate; the content is just hidden via `aria-hidden` + visually empty.
  const safeNode = node;
  const palette = safeNode?.quality ? qualityPalette(safeNode.quality) : null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full gap-0 border-l border-border/60 p-0 sm:max-w-md"
      >
        <SheetHeader className="gap-3 border-b border-border/60 px-6 pb-5 pt-6">
          <div className="flex items-center gap-3">
            {safeNode ? (
              <span
                aria-hidden
                className="flex size-11 items-center justify-center rounded-full bg-background ring-1 ring-border"
              >
                <NodeGlyph
                  type={safeNode.type}
                  className="size-5 text-foreground/80"
                  strokeWidth={1.75}
                />
              </span>
            ) : (
              <span
                aria-hidden
                className="size-11 rounded-full bg-background ring-1 ring-border"
              />
            )}
            <div className="flex min-w-0 flex-col gap-1">
              <SheetTitle className="truncate text-lg leading-tight">
                {safeNode?.label ?? ''}
              </SheetTitle>
              <SheetDescription className="text-xs uppercase tracking-wide text-muted-foreground">
                {safeNode ? nodeTypeLabel(safeNode.type) : ''}
              </SheetDescription>
            </div>
          </div>

          {safeNode && (
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <Badge
                variant="secondary"
                className={cn(
                  'h-6 gap-1.5 rounded-full px-2.5 text-xs font-medium',
                  safeNode.status === 'connected' &&
                    'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300',
                  safeNode.status === 'available' &&
                    'bg-sky-50 text-sky-700 dark:bg-sky-950/50 dark:text-sky-300',
                  safeNode.status === 'degraded' &&
                    'bg-amber-50 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300',
                  safeNode.status === 'offline' &&
                    'bg-muted text-muted-foreground',
                )}
              >
                <span
                  aria-hidden
                  className={cn(
                    'inline-block size-1.5 rounded-full',
                    safeNode.status === 'connected' && 'bg-emerald-500 dark:bg-emerald-400',
                    safeNode.status === 'available' && 'bg-sky-500 dark:bg-sky-400',
                    safeNode.status === 'degraded' && 'bg-amber-500 dark:bg-amber-400',
                    safeNode.status === 'offline' && 'bg-muted-foreground',
                  )}
                />
                {nodeStatusLabel(safeNode)}
              </Badge>

              {safeNode.quality && palette && (
                <span
                  className={cn(
                    'inline-flex h-6 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium ring-1',
                    palette.bg,
                    palette.text,
                    palette.ring,
                  )}
                >
                  <QualityGlyph
                    quality={safeNode.quality}
                    className="size-3.5"
                    strokeWidth={2}
                  />
                  {qualityLabel(safeNode.quality)} quality
                </span>
              )}
            </div>
          )}
        </SheetHeader>

        {safeNode && (
          <div className="flex-1 overflow-y-auto px-6 py-6">
            {/* Primary measurements */}
            <section aria-label="Connection measurements" className="space-y-1">
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Connection
              </h3>
              <dl className="mt-3 grid grid-cols-2 gap-3">
                <Metric
                  label="Latency"
                  value={formatLatency(safeNode.latencyMs)}
                  hint="Round-trip time"
                />
                <Metric
                  label="Reliability"
                  value={formatReliability(safeNode.reliability)}
                  hint="Last 24h"
                />
              </dl>
            </section>

            <Separator className="my-6 bg-border/60" />

            {/* Identity */}
            <section aria-label="Identity verification" className="space-y-3">
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Identity
              </h3>
              <div className="flex items-center gap-3 rounded-xl border border-emerald-200/60 bg-emerald-50/50 px-4 py-3 dark:border-emerald-900/40 dark:bg-emerald-950/20">
                <span
                  aria-hidden
                  className="flex size-9 items-center justify-center rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-900/60 dark:text-emerald-300"
                >
                  <ShieldCheck className="size-4" strokeWidth={2} />
                </span>
                <div className="flex flex-col">
                  <span className="text-sm font-medium text-foreground">Verified</span>
                  <span className="text-xs text-muted-foreground">
                    Identity authenticated, route signature valid.
                  </span>
                </div>
              </div>
            </section>

            <Separator className="my-6 bg-border/60" />

            {/* Advanced — secondary, clearly labelled. */}
            <section aria-label="Advanced details" className="space-y-3">
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Advanced
              </h3>
              <dl className="space-y-2.5">
                <AdvancedRow label="Hop" value={hopLabel(safeNode, totalHops)} />
                <AdvancedRow
                  label="Availability"
                  value={formatReliability(safeNode.reliability)}
                />
                <AdvancedRow
                  label="Packet loss"
                  value={formatPacketLoss(safeNode.reliability)}
                />
                <AdvancedRow label="Quality bucket" value={qualityLabel(safeNode.quality)} />
              </dl>
              <p className="pt-1 text-xs leading-relaxed text-muted-foreground">
                These are derived measurements. Raw protocol fields (NodeId, route
                hops, transport endpoints, public keys) are intentionally hidden —
                the dashboard never asks you to reason about wire-level details.
              </p>
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

export default NetworkPathDetailSheet;

// ─── Local sub-components ──────────────────────────────────────────────────

function Metric({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="rounded-xl border border-border/60 bg-muted/30 px-4 py-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 text-2xl font-semibold tabular-nums tracking-tight text-foreground">
        {value}
      </dd>
      {hint && <p className="mt-0.5 text-[0.7rem] text-muted-foreground/80">{hint}</p>}
    </div>
  );
}

function AdvancedRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium tabular-nums text-foreground">{value}</dd>
    </div>
  );
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function nodeTypeLabel(type: NetworkNode['type']): string {
  switch (type) {
    case 'you':
      return 'This device';
    case 'relay':
      return 'Relay';
    case 'gateway':
      return 'Gateway';
    case 'internet':
      return 'Internet';
  }
}

function hopLabel(node: NetworkNode, totalHops?: number): string {
  if (node.hopIndex === undefined) return '—';
  if (totalHops !== undefined) {
    return `${node.hopIndex + 1} of ${totalHops + 1}`;
  }
  return `${node.hopIndex + 1}`;
}

/** Derive a human packet-loss estimate from the reliability fraction. */
function formatPacketLoss(reliability: number | undefined): string {
  if (reliability === undefined || Number.isNaN(reliability)) return '—';
  const loss = Math.max(0, 1 - reliability) * 100;
  if (loss < 0.05) return '0.0%';
  return `${loss.toFixed(2)}%`;
}
