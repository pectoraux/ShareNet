'use client';

/**
 * ActivityItem — a single event in the ShareNet activity timeline.
 *
 * Designed to feel like Apple's system activity, not a developer log:
 *
 *   ┌──────────────────────────────────────────────┐
 *   │ ✓  10:42  Connected through ShareNet         │
 *   │    Circuit established via Amsterdam Relay 01 │
 *   │    ▾ Show details                            │
 *   └──────────────────────────────────────────────┘
 *
 * The technical detail (event id, ISO timestamp, event type, severity) is
 * hidden inside a Collapsible — it's there if you need it, but it doesn't
 * crowd the main timeline. There are NO raw stack traces and NO
 * protocol-frame dumps anywhere in this view.
 *
 * The component renders an `<li>` so it can be a direct child of `<ol>`.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import * as React from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { ChevronDown } from 'lucide-react';

import { cn } from '@/lib/utils';
import type { ActivityEvent } from '@/lib/sharenet';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { ActivityGlyph } from '@/components/sharenet/glyphs';
import { formatClock } from '@/components/sharenet/quality-helpers';

export interface ActivityItemProps {
  event: ActivityEvent;
  /** Whether this item is the most-recent (gets a slightly bolder treatment). */
  isLatest?: boolean;
}

export function ActivityItem({ event, isLatest = false }: ActivityItemProps) {
  const [open, setOpen] = React.useState(false);
  const reduceMotion = useReducedMotion();
  const isWarning = event.severity === 'warning' || event.severity === 'error';

  return (
    <li className="group relative">
      <Collapsible open={open} onOpenChange={setOpen}>
        <div
          className={cn(
            'flex gap-3.5 rounded-lg px-1 py-3',
            isLatest && 'bg-accent/30',
          )}
        >
          {/* Timeline icon */}
          <div className="flex flex-col items-center">
            <span
              aria-hidden
              className={cn(
                'flex size-9 shrink-0 items-center justify-center rounded-full ring-1',
                'bg-background ring-border',
                event.severity === 'success' &&
                  'text-emerald-600 dark:text-emerald-400',
                event.severity === 'info' &&
                  'text-sky-600 dark:text-sky-400',
                isWarning &&
                  'text-amber-600 dark:text-amber-400',
              )}
            >
              <ActivityGlyph
                type={event.type}
                className="size-4"
                strokeWidth={1.75}
              />
            </span>
          </div>

          {/* Body */}
          <div className="flex min-w-0 flex-1 flex-col pt-0.5">
            <div className="flex items-baseline gap-2">
              <time
                dateTime={event.timestamp.toISOString()}
                className="shrink-0 text-xs tabular-nums text-muted-foreground"
              >
                {formatClock(event.timestamp)}
              </time>
              <h3
                className={cn(
                  'truncate text-sm leading-tight text-foreground',
                  isLatest ? 'font-semibold' : 'font-medium',
                )}
              >
                {event.title}
              </h3>
            </div>

            {event.description && (
              <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                {event.description}
              </p>
            )}

            {/* Expand affordance */}
            <CollapsibleTrigger
              className={cn(
                'mt-2 inline-flex w-fit items-center gap-1 rounded-md text-xs',
                'text-muted-foreground/80 hover:text-foreground',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
              )}
            >
              <ChevronDown
                className={cn(
                  'size-3.5 transition-transform',
                  open && 'rotate-180',
                )}
                aria-hidden
              />
              <span>{open ? 'Hide details' : 'Show details'}</span>
            </CollapsibleTrigger>
          </div>
        </div>

        <CollapsibleContent className="overflow-hidden">
          <motion.div
            initial={reduceMotion ? false : { opacity: 0, y: -4 }}
            animate={reduceMotion ? undefined : { opacity: 1, y: 0 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className={cn(
              'ml-12 mr-1 mb-2 rounded-lg border border-border/60 bg-muted/30 px-3.5 py-3',
              'text-xs leading-relaxed text-muted-foreground',
            )}
          >
            <DetailGrid event={event} />
          </motion.div>
        </CollapsibleContent>
      </Collapsible>
    </li>
  );
}

export default ActivityItem;

// ─── Detail grid (inside the collapsible) ─────────────────────────────────

function DetailGrid({ event }: { event: ActivityEvent }) {
  const rows: { label: string; value: string }[] = [
    { label: 'Event type', value: humanEventType(event.type) },
    { label: 'Severity', value: event.severity },
    {
      label: 'Time',
      value: event.timestamp.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
    },
    { label: 'Event id', value: event.id },
  ];

  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5">
      {rows.map((r) => (
        <React.Fragment key={r.label}>
          <dt className="text-muted-foreground/70">{r.label}</dt>
          <dd className="font-mono text-[0.7rem] text-foreground/80">{r.value}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

function humanEventType(t: ActivityEvent['type']): string {
  switch (t) {
    case 'connected':
      return 'connection.established';
    case 'disconnected':
      return 'connection.closed';
    case 'path_improved':
      return 'path.improved';
    case 'path_degraded':
      return 'path.degraded';
    case 'relay_discovered':
      return 'discovery.relay_found';
    case 'recovery_started':
      return 'recovery.started';
    case 'recovery_completed':
      return 'recovery.completed';
    case 'gateway_changed':
      return 'path.gateway_changed';
    case 'error':
      return 'system.error';
  }
}
