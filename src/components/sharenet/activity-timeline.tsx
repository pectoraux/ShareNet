'use client';

/**
 * ActivityTimeline — the full ShareNet activity log view.
 *
 * Groups events by day (Today / Yesterday / weekday name) and renders each
 * group with a date header followed by a vertical timeline of `ActivityItem`s.
 * Subtle separators (typography + spacing, never heavy borders) keep the
 * surface calm. The timeline rail on the left is a thin vertical line — but
 * only when there is more than one item in a group, so a single-item group
 * doesn't look stranded.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import * as React from 'react';

import { cn } from '@/lib/utils';
import type { ActivityEvent } from '@/lib/sharenet';
import { ActivityItem } from '@/components/sharenet/activity-item';
import { formatDayBucket } from '@/components/sharenet/quality-helpers';

export interface ActivityTimelineProps {
  events: ActivityEvent[];
  className?: string;
  emptyLabel?: string;
}

export function ActivityTimeline({
  events,
  className,
  emptyLabel = 'No recent activity',
}: ActivityTimelineProps) {
  // Group by day-bucket (Today / Yesterday / weekday / date) preserving order.
  const groups = React.useMemo(() => groupByDay(events), [events]);

  if (events.length === 0) {
    return (
      <div
        className={cn(
          'flex flex-col items-center justify-center rounded-2xl border border-dashed border-border/60 bg-muted/20 px-6 py-16 text-center',
          className,
        )}
      >
        <p className="text-sm text-muted-foreground">{emptyLabel}</p>
      </div>
    );
  }

  return (
    <div className={cn('flex flex-col gap-8', className)}>
      {groups.map((group) => (
        <section key={group.key} aria-label={`${group.label} activity`}>
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {group.label}
          </h2>
          <ol className="relative flex flex-col">
            {/* Vertical rail — sits behind the icons. */}
            {group.events.length > 1 && (
              <span
                aria-hidden
                className="absolute left-[18px] top-9 bottom-9 w-px bg-border/60"
              />
            )}
            {group.events.map((event, i) => (
              <ActivityItem
                key={event.id}
                event={event}
                isLatest={i === 0 && group === groups[0]}
              />
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}

export default ActivityTimeline;

// ─── Day-bucket grouping ───────────────────────────────────────────────────

interface DayGroup {
  key: string;
  label: string;
  events: ActivityEvent[];
}

function groupByDay(events: ActivityEvent[]): DayGroup[] {
  // Events are expected newest-first (as the mock returns). We bucket
  // preserving that order so each day's timeline stays newest-first too.
  const groups: DayGroup[] = [];
  const indexByKey = new Map<string, number>();

  for (const event of events) {
    const key = dayBucketKey(event.timestamp);
    let idx = indexByKey.get(key);
    if (idx === undefined) {
      idx = groups.length;
      groups.push({
        key,
        label: formatDayBucket(event.timestamp),
        events: [],
      });
      indexByKey.set(key, idx);
    }
    groups[idx].events.push(event);
  }

  return groups;
}

/** A stable per-day key for grouping (YYYY-MM-DD). */
function dayBucketKey(d: Date): string {
  return `${d.getFullYear()}-${(d.getMonth() + 1)
    .toString()
    .padStart(2, '0')}-${d.getDate().toString().padStart(2, '0')}`;
}
