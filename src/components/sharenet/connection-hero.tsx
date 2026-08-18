'use client';

/**
 * ConnectionHero — the centerpiece of the ShareNet Home screen.
 *
 * Visual structure (centered, generous breathing room):
 *
 *     ╭─────────────╮
 *     │   ●  ring   │   ← animated arc + soft glow (reduced-motion aware)
 *     │  Connected  │
 *     ╰─────────────╯
 *     You're online through ShareNet.        ← large headline
 *     Your connection is protected and…      ← subtext
 *     [  Disconnect  ]                       ← primary action
 *     [ Verified connection ]                ← trust badge (only when connected)
 *
 * The hero is the single most important surface in the consumer app — it has
 * to read at a glance: am I safe online, and what does this button do?
 *
 * States designed:
 *   - connected    → full ring, slow breathing glow, "Disconnect" button
 *   - connecting   → sweeping arc, neutral colour, "Cancel" button
 *   - recovering   → sweeping arc, amber colour, "Disconnect" button
 *   - degraded     → near-full amber arc, no animation, "Disconnect"
 *   - offline      → broken (partial) red arc, no animation, "Try Again"
 *   - disconnected → empty ring (track only), "Connect" button
 *
 * Task ID: UI-SHELL-HOME
 */

import * as React from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { Loader2, Power, RotateCw } from 'lucide-react';

import { cn } from '@/lib/utils';
import { type ConnectionSummary, type ConnectionState } from '@/lib/sharenet';
import { Button } from '@/components/ui/button';
import {
  ConnectionStateIndicator,
  connectionStateLabel,
} from './connection-state-indicator';
import { TrustBadge } from './trust-badge';

// ─── Per-state copy + ring visuals ─────────────────────────────────────────

interface HeroCopy {
  /** One-sentence explanation shown as the large headline below the ring. */
  headline: string;
  /** Smaller subtext below the headline. */
  subtext: string;
  /** Primary action button label. */
  action: string;
  /** Whether to show the "Verified connection" trust badge under the button. */
  showTrustBadge: boolean;
  /** Button visual variant. */
  buttonVariant: 'neutral' | 'accent' | 'danger';
}

const HERO_COPY: Record<ConnectionState, HeroCopy> = {
  connected: {
    headline: "You're online through ShareNet.",
    subtext: 'Healthy path available.',
    action: 'Disconnect',
    showTrustBadge: true,
    buttonVariant: 'neutral',
  },
  connecting: {
    headline: 'Connecting…',
    subtext: 'ShareNet is establishing a connection.',
    action: 'Cancel',
    showTrustBadge: false,
    buttonVariant: 'neutral',
  },
  disconnected: {
    headline: "You're not connected.",
    subtext: 'Connect to ShareNet to reach the Internet through your trusted network.',
    action: 'Connect',
    showTrustBadge: false,
    buttonVariant: 'accent',
  },
  degraded: {
    headline: 'Connection is slow.',
    subtext: 'A path is available but performance is reduced. ShareNet is looking for a better route.',
    action: 'Disconnect',
    showTrustBadge: false,
    buttonVariant: 'neutral',
  },
  recovering: {
    headline: 'Finding a new path…',
    subtext: 'ShareNet is moving you to a healthier route.',
    action: 'Cancel',
    showTrustBadge: false,
    buttonVariant: 'neutral',
  },
  offline: {
    headline: "You're offline.",
    subtext: "ShareNet couldn't reach any gateway. Check your nearby devices or try again.",
    action: 'Try Again',
    showTrustBadge: false,
    buttonVariant: 'danger',
  },
  disabled: {
    headline: 'ShareNet is off.',
    subtext: 'Enable ShareNet to connect through your trusted network.',
    action: 'Enable',
    showTrustBadge: false,
    buttonVariant: 'accent',
  },
};

// ─── Ring visual config per state ─────────────────────────────────────────

interface RingConfig {
  /** Stroke colour for the arc (CSS variable). */
  stroke: string;
  /** Soft glow colour (background-tinted). */
  glow: string;
  /** What proportion of the ring is drawn (0..1). */
  arcLength: number;
  /** Whether to animate the arc sweeping around the ring. */
  sweep: boolean;
  /** Whether to pulse the soft outer glow. */
  pulseGlow: boolean;
}

function ringConfigForState(state: ConnectionState): RingConfig {
  switch (state) {
    case 'connected':
      return {
        stroke: 'var(--sn-connected)',
        glow: 'var(--sn-connected-soft)',
        arcLength: 1,
        sweep: false,
        pulseGlow: true,
      };
    case 'connecting':
      return {
        stroke: 'var(--sn-neutral)',
        glow: 'var(--sn-neutral-soft)',
        arcLength: 0.7,
        sweep: true,
        pulseGlow: true,
      };
    case 'recovering':
      return {
        stroke: 'var(--sn-warning)',
        glow: 'var(--sn-warning-soft)',
        arcLength: 0.7,
        sweep: true,
        pulseGlow: true,
      };
    case 'degraded':
      return {
        stroke: 'var(--sn-warning)',
        glow: 'var(--sn-warning-soft)',
        arcLength: 0.85,
        sweep: false,
        pulseGlow: false,
      };
    case 'offline':
      return {
        stroke: 'var(--sn-error)',
        glow: 'var(--sn-error-soft)',
        arcLength: 0.55,
        sweep: false,
        pulseGlow: false,
      };
    case 'disconnected':
    case 'disabled':
      return {
        stroke: 'var(--sn-neutral)',
        glow: 'var(--sn-neutral-soft)',
        arcLength: 0,
        sweep: false,
        pulseGlow: false,
      };
  }
}

// ─── Ring geometry ─────────────────────────────────────────────────────────
//
// The SVG is rendered at RING_SIZE × RING_SIZE device pixels, with a viewBox
// of the same size. The arc is a <circle> rotated -90° so its starting point
// is at 12 o'clock. We use strokeDasharray to draw only `arcLength` fraction
// of the full circle, and animate strokeDashoffset for the "sweeping" effect.

const RING_SIZE = 184;
const RING_RADIUS = 76;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS; // ≈ 477.5

// ─── Component ─────────────────────────────────────────────────────────────

export interface ConnectionHeroProps {
  summary: ConnectionSummary;
  /** Called when the user clicks the primary action button. */
  onPrimaryAction: () => void;
  /** Called when the user clicks "Connection details". */
  onShowDetails?: () => void;
  /** When true, the button shows a spinner and is disabled. */
  isPending?: boolean;
  className?: string;
}

export function ConnectionHero({
  summary,
  onPrimaryAction,
  onShowDetails,
  isPending = false,
  className,
}: ConnectionHeroProps) {
  const reduceMotion = useReducedMotion();
  const state = summary.state;
  const copy = HERO_COPY[state];
  const ring = ringConfigForState(state);

  const drawnLength = RING_CIRCUMFERENCE * ring.arcLength;
  const gapLength = RING_CIRCUMFERENCE - drawnLength;
  const dashArray = `${drawnLength} ${gapLength}`;

  const shouldSweep = ring.sweep && !reduceMotion;
  const sweepAnimate = shouldSweep
    ? { strokeDashoffset: [0, -RING_CIRCUMFERENCE] }
    : { strokeDashoffset: 0 };
  const sweepTransition = shouldSweep
    ? { duration: 2.6, repeat: Infinity, ease: 'linear' as const }
    : { duration: 0.7, ease: 'easeOut' as const };

  return (
    <section
      className={cn('flex flex-col items-center text-center', className)}
      aria-labelledby="hero-headline"
    >
      {/* ─── Animated connection ring ──────────────────────────────────── */}
      <div
        className="relative mb-12 flex items-center justify-center"
        style={{ width: RING_SIZE, height: RING_SIZE }}
        aria-hidden
      >
        {/* Soft outer glow — pulses only when `pulseGlow` is set and motion is allowed. */}
        {ring.pulseGlow && !reduceMotion && (
          <motion.div
            className="absolute rounded-full"
            style={{
              backgroundColor: ring.glow,
              inset: 16,
            }}
            initial={{ opacity: 0.55, scale: 1 }}
            animate={{ opacity: 0, scale: 1.4 }}
            transition={{
              duration: 3.4,
              repeat: Infinity,
              ease: 'easeOut',
            }}
          />
        )}

        <svg
          width={RING_SIZE}
          height={RING_SIZE}
          viewBox={`0 0 ${RING_SIZE} ${RING_SIZE}`}
          className="relative"
        >
          {/* Track */}
          <circle
            cx={RING_SIZE / 2}
            cy={RING_SIZE / 2}
            r={RING_RADIUS}
            fill="none"
            stroke="var(--border)"
            strokeWidth={2}
          />
          {/* Arc (only rendered if arcLength > 0) */}
          {ring.arcLength > 0 && (
            <motion.circle
              cx={RING_SIZE / 2}
              cy={RING_SIZE / 2}
              r={RING_RADIUS}
              fill="none"
              stroke={ring.stroke}
              strokeWidth={3}
              strokeLinecap="round"
              strokeDasharray={dashArray}
              transform={`rotate(-90 ${RING_SIZE / 2} ${RING_SIZE / 2})`}
              initial={reduceMotion ? false : { strokeDashoffset: drawnLength }}
              animate={sweepAnimate}
              transition={sweepTransition}
            />
          )}
        </svg>

        {/* Center content — the state label, large and centered. */}
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2">
          <ConnectionStateIndicator
            state={state}
            size="md"
            hideLabel
          />
          <span
            className="text-2xl font-semibold tracking-tight"
            style={{ color: 'var(--foreground)' }}
          >
            {connectionStateLabel(state)}
          </span>
        </div>
      </div>

      {/* ─── Headline (one-sentence explanation) ───────────────────────── */}
      <h1
        id="hero-headline"
        className="max-w-2xl text-balance text-3xl font-semibold tracking-tight sm:text-4xl"
        style={{ color: 'var(--foreground)' }}
      >
        {copy.headline}
      </h1>

      {/* ─── Subtext ──────────────────────────────────────────────────── */}
      <p
        className="mt-5 max-w-md text-pretty text-base leading-relaxed sm:text-lg"
        style={{ color: 'var(--muted-foreground)' }}
      >
        {copy.subtext}
      </p>

      {/* ─── Primary action + trust badge ─────────────────────────────── */}
      <div className="mt-9 flex flex-col items-center gap-3">
        <Button
          size="lg"
          onClick={onPrimaryAction}
          disabled={isPending}
          aria-busy={isPending}
          className={cn(
            'h-12 min-w-44 rounded-full px-7 text-base font-medium',
            copy.buttonVariant === 'neutral' &&
              'bg-[color:var(--primary)] text-[color:var(--primary-foreground)] hover:opacity-90',
            copy.buttonVariant === 'accent' &&
              'text-white hover:opacity-90',
            copy.buttonVariant === 'danger' &&
              'text-white hover:opacity-90',
          )}
          style={{
            backgroundColor:
              copy.buttonVariant === 'accent'
                ? 'var(--sn-connected)'
                : copy.buttonVariant === 'danger'
                  ? 'var(--sn-error)'
                  : undefined,
          }}
        >
          {isPending ? (
            <Loader2 className="size-4 animate-spin" aria-hidden />
          ) : state === 'offline' ? (
            <RotateCw className="size-4" aria-hidden />
          ) : (
            <Power className="size-4" aria-hidden />
          )}
          {isPending ? 'Working…' : copy.action}
        </Button>

        {copy.showTrustBadge && <TrustBadge className="mt-1" />}

        {/* Secondary affordance — Connection details */}
        {onShowDetails && (
          <button
            type="button"
            onClick={onShowDetails}
            className="mt-2 text-sm font-medium text-muted-foreground underline-offset-4 transition-colors hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--ring)] focus-visible:ring-offset-2 rounded-sm"
          >
            Connection details
          </button>
        )}
      </div>
    </section>
  );
}

export default ConnectionHero;
