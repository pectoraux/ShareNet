'use client';

/**
 * ShareNet 2.0 — Privacy Overview
 *
 * A static, plain-language explanation of where ShareNet traffic goes and
 * what each participant can see. No marketing copy — just the topology and
 * the trust boundary at each hop.
 *
 * Topology:
 *
 *     Your traffic
 *         ↓
 *     Encrypted ShareNet path
 *         ↓
 *     Relay(s)
 *         ↓
 *     Gateway
 *         ↓
 *     Internet
 *
 * The component renders that vertical flow as labelled boxes with downward
 * arrows between them, followed by a "what each participant can see"
 * section with three short descriptions (Relays / Gateway / Your device).
 *
 * Optionally accepts a `privacy` object (the adapter's `PrivacyState`) so a
 * live status block can be rendered at the bottom. When `privacy` is null
 * the component is fully self-contained — useful for embedding inside the
 * Settings page or rendering standalone at `/settings/privacy`.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';
import {
  ArrowDown,
  Globe,
  Laptop,
  Lock,
  Server,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import type { PrivacyState } from '@/lib/sharenet';

// ─── Flow step model ─────────────────────────────────────────────────────────

interface FlowStep {
  key: string;
  label: string;
  icon: LucideIcon;
  /** Tailwind classes for the icon tile background. */
  accent: string;
}

const FLOW: FlowStep[] = [
  { key: 'traffic', label: 'Your traffic', icon: Laptop, accent: 'bg-muted text-foreground/70' },
  { key: 'path', label: 'Encrypted ShareNet path', icon: Lock, accent: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' },
  { key: 'relays', label: 'Relay(s)', icon: Server, accent: 'bg-muted text-foreground/70' },
  { key: 'gateway', label: 'Gateway', icon: ShieldCheck, accent: 'bg-muted text-foreground/70' },
  { key: 'internet', label: 'Internet', icon: Globe, accent: 'bg-muted text-foreground/70' },
];

// ─── Participant explanations ──────────────────────────────────────────────

interface Participant {
  key: string;
  name: string;
  canSee: string;
  icon: LucideIcon;
}

const PARTICIPANTS: Participant[] = [
  {
    key: 'relays',
    name: 'Relays',
    canSee: 'Can forward encrypted traffic. Cannot read application payloads.',
    icon: Server,
  },
  {
    key: 'gateway',
    name: 'Gateway',
    canSee: 'Connects to the Internet. Applies egress policy.',
    icon: ShieldCheck,
  },
  {
    key: 'you',
    name: 'Your device',
    canSee: 'Controls your identity and connection.',
    icon: Laptop,
  },
];

// ─── Flow diagram ───────────────────────────────────────────────────────────

function FlowDiagram() {
  return (
    <ol
      className="flex flex-col items-stretch gap-0"
      aria-label="ShareNet traffic flow"
    >
      {FLOW.map((step, i) => {
        const Icon = step.icon;
        const isLast = i === FLOW.length - 1;
        return (
          <li key={step.key} className="flex flex-col items-stretch">
            <div
              className={cn(
                'flex items-center gap-3 rounded-xl border border-border/60 bg-card px-4 py-3',
              )}
            >
              <span
                aria-hidden="true"
                className={cn(
                  'flex size-9 shrink-0 items-center justify-center rounded-lg',
                  step.accent,
                )}
              >
                <Icon className="size-[18px]" />
              </span>
              <div className="flex min-w-0 flex-1 flex-col">
                <span className="text-sm font-medium text-foreground">
                  {step.label}
                </span>
              </div>
              <span
                className="text-[10px] uppercase tracking-wide text-muted-foreground"
                aria-hidden="true"
              >
                Step {i + 1}
              </span>
            </div>
            {!isLast ? (
              <div
                className="flex justify-center py-1.5"
                aria-hidden="true"
              >
                <ArrowDown className="size-4 text-muted-foreground/70" />
              </div>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}

// ─── Participant cards ─────────────────────────────────────────────────────

function ParticipantList() {
  return (
    <section aria-labelledby="participants-heading">
      <header className="mb-2.5">
        <h2
          id="participants-heading"
          className="text-sm font-semibold tracking-tight text-foreground"
        >
          What each participant can see
        </h2>
      </header>
      <ul className="flex flex-col gap-2" role="list">
        {PARTICIPANTS.map((p) => {
          const Icon = p.icon;
          return (
            <li
              key={p.key}
              role="listitem"
              className="flex items-start gap-3 rounded-xl border border-border/60 bg-card px-4 py-3"
            >
              <span
                aria-hidden="true"
                className="flex size-7 shrink-0 items-center justify-center rounded-md bg-muted/60 text-foreground/70"
              >
                <Icon className="size-3.5" />
              </span>
              <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                <span className="text-sm font-medium text-foreground">
                  {p.name}
                </span>
                <span className="text-xs leading-relaxed text-muted-foreground">
                  {p.canSee}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

// ─── Live privacy status (optional) ────────────────────────────────────────

interface PrivacyCheck {
  label: string;
  ok: boolean;
}

function privacyChecks(p: PrivacyState): PrivacyCheck[] {
  return [
    { label: 'Private relay mode', ok: p.privateRelayMode },
    { label: 'End-to-end encryption', ok: p.encryptionEnabled },
    { label: 'Identity verified', ok: p.identityVerified },
    { label: 'Circuit authenticated', ok: p.circuitAuthenticated },
    { label: 'Gateway verified', ok: p.gatewayVerified },
    { label: 'Route signed', ok: p.routeSigned },
  ];
}

function PrivacyStatusBlock({ privacy }: { privacy: PrivacyState }) {
  const checks = privacyChecks(privacy);
  const passing = checks.filter((c) => c.ok).length;

  return (
    <section
      aria-labelledby="privacy-status-heading"
      className="rounded-xl border border-border/60 bg-muted/30 px-4 py-4"
    >
      <header className="mb-3 flex items-center justify-between">
        <h2
          id="privacy-status-heading"
          className="text-sm font-semibold tracking-tight text-foreground"
        >
          Current session
        </h2>
        <span className="text-xs text-muted-foreground tabular-nums">
          {passing}/{checks.length} guarantees active
        </span>
      </header>
      <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5" role="list">
        {checks.map((c) => (
          <li
            key={c.label}
            role="listitem"
            className="flex items-center gap-2 text-xs"
          >
            <span
              aria-hidden="true"
              className={cn(
                'flex size-4 shrink-0 items-center justify-center rounded-full',
                c.ok
                  ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                  : 'bg-muted-foreground/10 text-muted-foreground',
              )}
            >
              {c.ok ? (
                <svg
                  viewBox="0 0 12 12"
                  className="size-3"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  aria-hidden="true"
                >
                  <path d="M2.5 6.5l2 2 5-5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              ) : (
                <span className="block size-1.5 rounded-full bg-current" />
              )}
            </span>
            <span
              className={cn(
                c.ok
                  ? 'text-foreground/80'
                  : 'text-muted-foreground',
              )}
            >
              {c.label}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

// ─── Main component ─────────────────────────────────────────────────────────

export interface PrivacyOverviewProps {
  /** Optional live privacy state to show a "current session" status block. */
  privacy?: PrivacyState | null;
  className?: string;
}

export function PrivacyOverview({ privacy, className }: PrivacyOverviewProps) {
  return (
    <div className={cn('flex flex-col gap-8', className)}>
      <FlowDiagram />

      <ParticipantList />

      {privacy ? <PrivacyStatusBlock privacy={privacy} /> : null}

      <p className="text-[11px] leading-relaxed text-muted-foreground">
        ShareNet traffic is end-to-end encrypted between your device and the
        gateway. Relays forward encrypted frames without seeing their
        contents. The gateway applies egress policy (what traffic is allowed
        to reach the Internet) but does not hold your long-term identity keys.
      </p>
    </div>
  );
}

export default PrivacyOverview;
