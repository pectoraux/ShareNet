'use client';

/**
 * NetworkPath — the ShareNet topology view.
 *
 * Renders the user's path to the Internet as a calm vertical stack:
 *
 *         Internet
 *            │
 *         Gateway
 *            │
 *          Relay
 *            │
 *           You
 *
 * Each node is a `NetworkNodeCard`. Connection lines between nodes carry a
 * subtle animated pulse (a small dot that travels the line) — but ONLY when
 * `prefers-reduced-motion: reduce` is NOT set. When reduced motion is
 * preferred the lines are static.
 *
 * Selecting any node calls `onSelectNode`, which the parent uses to open the
 * detail sheet.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import * as React from 'react';
import { motion, useReducedMotion } from 'framer-motion';

import { cn } from '@/lib/utils';
import type { NetworkNode, NetworkPath as NetworkPathType } from '@/lib/sharenet';
import { NetworkNodeCard } from '@/components/sharenet/network-node';

export interface NetworkPathProps {
  path: NetworkPathType;
  selectedNodeId?: string;
  onSelectNode?: (node: NetworkNode) => void;
  className?: string;
}

export function NetworkPath({
  path,
  selectedNodeId,
  onSelectNode,
  className,
}: NetworkPathProps) {
  const reduceMotion = useReducedMotion();
  // The adapter returns nodes ordered `you → relay → gateway → internet`
  // (i.e. in the direction data flows *out*). For the user-facing topology we
  // display them in the opposite order — Internet at the top, You at the
  // bottom — so the visual reads as a path "up to the Internet".
  const ordered = [...path.nodes].reverse();

  return (
    <ol
      className={cn(
        'mx-auto flex w-full max-w-md flex-col items-stretch',
        className,
      )}
      aria-label="Network path from this device to the Internet"
    >
      {ordered.map((node, i) => {
        const isLast = i === ordered.length - 1;
        const selected = selectedNodeId === node.id;

        return (
          <li key={node.id} className="flex flex-col items-stretch">
            <NetworkNodeCard
              node={node}
              selected={selected}
              onSelect={onSelectNode}
              muted={node.status === 'offline'}
            />

            {!isLast && (
              <ConnectionLine
                reduceMotion={!!reduceMotion}
                // The line "carries" the quality of the hop above it; for the
                // visual pulse we use the weaker of the two adjacent nodes'
                // quality to communicate end-to-end quality.
                fromNode={node}
                toNode={ordered[i + 1]}
              />
            )}
          </li>
        );
      })}
    </ol>
  );
}

export default NetworkPath;

// ─── Connection line ──────────────────────────────────────────────────────
//
// A short vertical line with an animated travelling dot. The dot motion
// respects `prefers-reduced-motion` (caller passes the resolved flag). The
// line colour is muted by default; the dot uses a calm accent.

function ConnectionLine({
  reduceMotion,
  fromNode,
  toNode,
}: {
  reduceMotion: boolean;
  fromNode: NetworkNode;
  toNode: NetworkNode;
}) {
  // If either endpoint is offline, render a static dashed line — no pulse.
  const isLive =
    fromNode.status !== 'offline' && toNode.status !== 'offline';

  return (
    <div
      aria-hidden
      className={cn(
        'relative mx-auto h-8 w-px',
        isLive
          ? 'bg-border/70'
          : 'bg-[repeating-linear-gradient(to_bottom,transparent_0_3px,var(--border)_3px_6px)]',
      )}
    >
      {isLive && !reduceMotion && (
        <motion.span
          className="absolute left-1/2 size-1.5 -translate-x-1/2 rounded-full bg-foreground/30"
          initial={{ top: '0%' }}
          animate={{ top: ['0%', '100%'] }}
          transition={{
            duration: 2.4,
            repeat: Infinity,
            ease: 'easeInOut',
            repeatDelay: 0.4,
          }}
        />
      )}
      {isLive && reduceMotion && (
        <span className="absolute left-1/2 top-1/2 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-foreground/30" />
      )}
    </div>
  );
}
