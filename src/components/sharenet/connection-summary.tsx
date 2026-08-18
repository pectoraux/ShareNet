/**
 * ConnectionSummaryGrid — compact, plain-language summary of the connection.
 *
 * Renders four facts the user cares about:
 *
 *     Connection    Path         Internet     Privacy
 *     Connected     3 devices    Available    Protected
 *
 * Plain language, no jargon. Each fact is a small label + value pair, laid
 * out as a single row on desktop and a 2×2 grid on mobile. No cards, no
 * chrome — whitespace and typography carry the hierarchy.
 *
 * Server-component safe (no hooks, no state).
 *
 * Task ID: UI-SHELL-HOME
 */

import * as React from 'react';

import { cn } from '@/lib/utils';
import type { ConnectionSummary } from '@/lib/sharenet';
import { connectionStateLabel } from './connection-state-indicator';

// ─── Small inline icons (size 14) ───────────────────────────────────────────
//
// Inline SVGs (not lucide imports) so we can match the exact visual weight we
// want without pulling in extra icon dependencies. Each is aria-hidden.

function PathIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <circle cx="3" cy="4" r="1.5" />
      <circle cx="13" cy="4" r="1.5" />
      <circle cx="8" cy="12" r="1.5" />
      <path d="M4.5 4H11.5" />
      <path d="M4 5L7 10.5" />
      <path d="M12 5L9 10.5" />
    </svg>
  );
}

function GlobeIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <circle cx="8" cy="8" r="6" />
      <path d="M2 8h12" />
      <path d="M8 2c1.8 1.8 2.8 3.8 2.8 6s-1 4.2-2.8 6c-1.8-1.8-2.8-3.8-2.8-6s1-4.2 2.8-6z" />
    </svg>
  );
}

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <path d="M8 1.5l5 2v4c0 3-2 5.5-5 7-3-1.5-5-4-5-7v-4l5-2z" />
      <path d="M5.5 8l1.8 1.8L10.5 6.5" />
    </svg>
  );
}

function LinkIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <path d="M6.5 9.5a3 3 0 0 0 4.24 0l2-2a3 3 0 0 0-4.24-4.24l-1 1" />
      <path d="M9.5 6.5a3 3 0 0 0-4.24 0l-2 2a3 3 0 0 0 4.24 4.24l1-1" />
    </svg>
  );
}

// ─── Component ─────────────────────────────────────────────────────────────

export interface ConnectionSummaryGridProps {
  summary: ConnectionSummary;
  className?: string;
}

interface SummaryRow {
  label: string;
  value: string;
  ok: boolean;
  icon: (props: { className?: string }) => React.ReactElement;
}

function buildRows(summary: ConnectionSummary): SummaryRow[] {
  const isOnline =
    summary.state === 'connected' ||
    summary.state === 'connecting' ||
    summary.state === 'recovering' ||
    summary.state === 'degraded';

  return [
    {
      label: 'Connection',
      value:
        summary.state === 'connected'
          ? 'Connected'
          : summary.state === 'disconnected'
            ? 'Disconnected'
            : connectionStateLabel(summary.state),
      ok: summary.state === 'connected',
      icon: LinkIcon,
    },
    {
      label: 'Path',
      value: summary.path ? `${summary.path.totalHops} devices` : 'No path',
      ok: !!summary.path,
      icon: PathIcon,
    },
    {
      label: 'Internet',
      value: summary.internetAvailable ? 'Available' : 'Unavailable',
      ok: summary.internetAvailable,
      icon: GlobeIcon,
    },
    {
      label: 'Privacy',
      value: summary.privacy.encryptionEnabled ? 'Protected' : 'Not protected',
      ok: summary.privacy.encryptionEnabled,
      icon: ShieldIcon,
    },
  ];
  // (isOnline is currently only referenced implicitly through `ok`; kept here
  // for clarity about which states count as "online" for messaging.)
  void isOnline;
}

export function ConnectionSummaryGrid({
  summary,
  className,
}: ConnectionSummaryGridProps) {
  const rows = buildRows(summary);

  return (
    <section
      aria-label="Connection summary"
      className={cn(
        'grid grid-cols-2 gap-x-10 gap-y-10 sm:grid-cols-4 sm:gap-x-12',
        className,
      )}
    >
      {rows.map((row) => {
        const Icon = row.icon;
        return (
          <div key={row.label} className="flex flex-col gap-2">
            <div
              className="flex items-center gap-2 text-[0.7rem] font-semibold uppercase tracking-[0.12em]"
              style={{ color: 'var(--muted-foreground)' }}
            >
              <Icon className="size-3.5" />
              <span>{row.label}</span>
            </div>
            <div
              className="text-lg font-semibold tracking-tight"
              style={{
                color: row.ok
                  ? 'var(--foreground)'
                  : 'var(--muted-foreground)',
              }}
            >
              {row.value}
            </div>
          </div>
        );
      })}
    </section>
  );
}

export default ConnectionSummaryGrid;
