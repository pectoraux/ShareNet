'use client';

/**
 * ConnectionStateIndicator — the small dot + text label used across the
 * consumer UI (sidebar status, mobile header, hero center).
 *
 * Always pairs colour with a textual label (never colour alone) so it's
 * accessible to colour-blind users. The pulse animation only runs for the
 * transient states (connecting / recovering) and is disabled entirely when
 * the user has `prefers-reduced-motion: reduce`.
 *
 * Task ID: UI-SHELL-HOME
 */

import { motion, useReducedMotion } from 'framer-motion';

import { cn } from '@/lib/utils';
import type { ConnectionState } from '@/lib/sharenet';

// ─── State → human label ─────────────────────────────────────────────────

export function connectionStateLabel(state: ConnectionState): string {
  switch (state) {
    case 'connected':
      return 'Connected';
    case 'connecting':
      return 'Connecting';
    case 'disconnected':
      return 'Disconnected';
    case 'degraded':
      return 'Degraded';
    case 'recovering':
      return 'Recovering';
    case 'offline':
      return 'Offline';
    case 'disabled':
      return 'Disabled';
  }
}

// ─── State → colour tokens (defined in globals.css under .sharenet-shell) ──

interface StateVisual {
  /** Solid dot/arc colour. */
  stroke: string;
  /** Text colour (slightly darker than stroke for AA contrast). */
  text: string;
  /** Whether to animate the pulse ring around the dot. */
  pulse: boolean;
}

function stateVisual(state: ConnectionState): StateVisual {
  switch (state) {
    case 'connected':
      return {
        stroke: 'var(--sn-connected)',
        text: 'var(--sn-connected-text, oklch(0.4 0.08 165))',
        pulse: false,
      };
    case 'connecting':
      return {
        stroke: 'var(--sn-neutral)',
        text: 'var(--sn-neutral-text, oklch(0.45 0.01 90))',
        pulse: true,
      };
    case 'recovering':
      return {
        stroke: 'var(--sn-warning)',
        text: 'var(--sn-warning-text, oklch(0.45 0.1 60))',
        pulse: true,
      };
    case 'degraded':
      return {
        stroke: 'var(--sn-warning)',
        text: 'var(--sn-warning-text, oklch(0.45 0.1 60))',
        pulse: false,
      };
    case 'offline':
      return {
        stroke: 'var(--sn-error)',
        text: 'var(--sn-error-text, oklch(0.45 0.12 25))',
        pulse: false,
      };
    case 'disconnected':
    case 'disabled':
      return {
        stroke: 'var(--sn-neutral)',
        text: 'var(--sn-neutral-text, oklch(0.45 0.01 90))',
        pulse: false,
      };
  }
}

// ─── Sizes ────────────────────────────────────────────────────────────────

type IndicatorSize = 'sm' | 'md' | 'lg';

const DOT_SIZE: Record<IndicatorSize, string> = {
  sm: 'size-1.5',
  md: 'size-2.5',
  lg: 'size-3.5',
};

const TEXT_SIZE: Record<IndicatorSize, string> = {
  sm: 'text-xs',
  md: 'text-sm',
  lg: 'text-base',
};

// ─── Component ─────────────────────────────────────────────────────────────

export interface ConnectionStateIndicatorProps {
  state: ConnectionState;
  size?: IndicatorSize;
  /** Hide the text label (show only the dot). Defaults to false. */
  hideLabel?: boolean;
  /** Override the visible label. Defaults to the canonical name for the state. */
  label?: string;
  className?: string;
}

export function ConnectionStateIndicator({
  state,
  size = 'md',
  hideLabel = false,
  label,
  className,
}: ConnectionStateIndicatorProps) {
  const reduceMotion = useReducedMotion();
  const visual = stateVisual(state);
  const visibleLabel = label ?? connectionStateLabel(state);
  const shouldPulse = visual.pulse && !reduceMotion;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-2 align-middle',
        className,
      )}
      role="status"
      aria-label={`Connection state: ${visibleLabel}`}
    >
      <span className="relative inline-flex items-center justify-center">
        <span
          aria-hidden
          className={cn('rounded-full', DOT_SIZE[size])}
          style={{ backgroundColor: visual.stroke }}
        />
        {shouldPulse && (
          <motion.span
            aria-hidden
            className={cn('absolute rounded-full', DOT_SIZE[size])}
            style={{ backgroundColor: visual.stroke }}
            initial={{ opacity: 0.55, scale: 1 }}
            animate={{ opacity: 0, scale: 2.6 }}
            transition={{ duration: 1.8, repeat: Infinity, ease: 'easeOut' }}
          />
        )}
      </span>
      {!hideLabel && (
        <span
          className={cn(
            'font-medium tracking-tight',
            TEXT_SIZE[size],
          )}
          style={{ color: visual.text }}
        >
          {visibleLabel}
        </span>
      )}
    </span>
  );
}

export default ConnectionStateIndicator;
