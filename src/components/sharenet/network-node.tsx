'use client';

/**
 * NetworkNodeCard — a single node in the ShareNet topology view.
 *
 * Renders as a clean horizontal card: circular icon on the left, label + status
 * on the right. The card is a button so keyboard users can focus + activate it
 * to open the detail sheet. Hover/focus rings + selected state make the
 * interaction discoverable.
 *
 * The card does NOT show protocol-level identifiers (NodeId, RouteHop,
 * X25519, TransportEndpoint). It shows only what the user cares about:
 * the node's name, its type, its status, and (when known) a quality dot.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import * as React from 'react';

import { cn } from '@/lib/utils';
import type { NetworkNode } from '@/lib/sharenet';
import { NodeGlyph } from '@/components/sharenet/glyphs';
import {
  nodeStatusLabel,
  qualityPalette,
} from '@/components/sharenet/quality-helpers';

export interface NetworkNodeCardProps {
  node: NetworkNode;
  /** Whether this node is currently selected (opens the detail sheet). */
  selected?: boolean;
  /** Called when the user activates the node (click / keyboard). */
  onSelect?: (node: NetworkNode) => void;
  /** Visually dim nodes that aren't part of the active path. */
  muted?: boolean;
  className?: string;
}

export function NetworkNodeCard({
  node,
  selected = false,
  onSelect,
  muted = false,
  className,
}: NetworkNodeCardProps) {
  const palette = qualityPalette(node.quality);
  const statusConnected = node.status === 'connected';
  const statusAvailable = node.status === 'available';

  return (
    <button
      type="button"
      onClick={() => onSelect?.(node)}
      aria-pressed={selected}
      aria-label={`${node.label}, ${nodeStatusLabel(node)}${
        node.quality ? `, quality ${node.quality}` : ''
      }. Open details.`}
      className={cn(
        'group relative flex w-full items-center gap-4 rounded-2xl border bg-card/80 px-4 py-3 text-left transition-all',
        'border-border/70 hover:border-border hover:bg-accent/40',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        selected && 'border-foreground/30 bg-accent/50 ring-1 ring-foreground/20',
        muted && 'opacity-60',
        className,
      )}
    >
      {/* Circular icon — calm, friendly. */}
      <span
        aria-hidden
        className={cn(
          'flex size-11 shrink-0 items-center justify-center rounded-full ring-1 transition-colors',
          'bg-background ring-border group-hover:ring-foreground/30',
          selected && 'ring-foreground/40',
        )}
      >
        <NodeGlyph
          type={node.type}
          className={cn(
            'size-5 text-foreground/80',
            statusConnected && 'text-emerald-600 dark:text-emerald-400',
            statusAvailable && !statusConnected && 'text-sky-600 dark:text-sky-400',
          )}
          strokeWidth={1.75}
        />
      </span>

      {/* Label + status row */}
      <span className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className="truncate text-[0.95rem] font-medium leading-tight text-foreground">
          {node.label}
        </span>
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          {/* Status dot — colour paired with the text label below, never alone. */}
          <span
            aria-hidden
            className={cn(
              'inline-block size-1.5 rounded-full',
              statusConnected && 'bg-emerald-500 dark:bg-emerald-400',
              statusAvailable && !statusConnected && 'bg-sky-500 dark:bg-sky-400',
              node.status === 'degraded' && 'bg-amber-500 dark:bg-amber-400',
              node.status === 'offline' && 'bg-muted-foreground',
            )}
          />
          <span>{nodeStatusLabel(node)}</span>
          {node.quality && (
            <>
              <span aria-hidden className="text-muted-foreground/50">·</span>
              <span className={palette.text}>{node.quality[0].toUpperCase() + node.quality.slice(1)}</span>
            </>
          )}
        </span>
      </span>

      {/* Right affordance — small chevron hint that this is interactive. */}
      <span
        aria-hidden
        className={cn(
          'shrink-0 text-muted-foreground/40 transition-transform',
          'group-hover:translate-x-0.5 group-hover:text-muted-foreground/80',
          selected && 'text-foreground/60',
        )}
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M6 4l4 4-4 4" />
        </svg>
      </span>
    </button>
  );
}

export default NetworkNodeCard;
