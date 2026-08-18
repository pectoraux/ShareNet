'use client';

/**
 * ShareNet — reusable state blocks.
 *
 * Three small, calm components that every consumer page reaches for when the
 * adapter is loading, has failed, or has nothing to show. They all use the
 * scoped `.sharenet-shell` design tokens (warm whites + soft graphite + the
 * restrained teal-green / amber / red accents) so they look at home inside
 * any page wrapped in `<AppShell>`. They are deliberately quiet — no spinners,
 * no neon, no error stack dumps — those belong in /diagnostics, not the
 * consumer surface.
 *
 *   <ErrorState   title="…" message="…" onRetry={() => refetch()} />
 *   <EmptyState   title="…" message="…" action={…} />
 *   <LoadingSkeleton variant="home" | "network" | "activity" | "devices" />
 *
 * Why no spinners: skeletons that mirror the real layout make the loading →
 * content transition feel seamless, which is the ShareNet aesthetic. Spinners
 * draw attention to the wait; skeletons draw attention to the layout that is
 * about to appear.
 *
 * Task ID: UI-ONBOARDING-ERRORS
 */

import * as React from 'react';
import { AlertCircle, Inbox } from 'lucide-react';

import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';

// ─── ErrorState ──────────────────────────────────────────────────────────

export interface ErrorStateProps {
  /** Short headline — what couldn't we do? */
  title: string;
  /** Calm one-sentence explanation. */
  message: string;
  /** Called when the user taps "Try again". Omit to hide the button. */
  onRetry?: () => void;
  /** Optional button label override. Defaults to "Try again". */
  retryLabel?: string;
  /** Pass true while the retry is in-flight to disable the button. */
  retrying?: boolean;
  className?: string;
}

/**
 * Calm, centered error block. The icon is a soft rose-tinted circle (the
 * `--sn-error` accent), the headline + message stay close to the body type
 * scale, and the only affordance is a single "Try again" button. Raw error
 * text is intentionally NOT rendered here — diagnostics belong in
 * `/diagnostics`, never on the consumer surface.
 */
export function ErrorState({
  title,
  message,
  onRetry,
  retryLabel = 'Try again',
  retrying = false,
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className={cn(
        'flex flex-col items-center px-4 py-12 text-center sm:py-16',
        className,
      )}
    >
      <span
        aria-hidden
        className="mb-6 flex size-14 items-center justify-center rounded-full ring-1 ring-inset"
        style={{
          backgroundColor: 'var(--sn-error-soft)',
          color: 'var(--sn-error-text)',
          // Use the soft-error ring tint so it reads as "warning" without
          // hard rose neon.
          boxShadow: 'inset 0 0 0 1px color-mix(in oklch, var(--sn-error) 18%, transparent)',
        }}
      >
        <AlertCircle className="size-6" strokeWidth={1.75} />
      </span>

      <h2
        className="max-w-md text-balance text-xl font-semibold tracking-tight sm:text-2xl"
        style={{ color: 'var(--foreground)' }}
      >
        {title}
      </h2>

      <p
        className="mt-3 max-w-sm text-pretty text-base leading-relaxed"
        style={{ color: 'var(--muted-foreground)' }}
      >
        {message}
      </p>

      {onRetry && (
        <Button
          type="button"
          variant="default"
          onClick={onRetry}
          disabled={retrying}
          aria-busy={retrying}
          className="mt-8 h-11 min-w-36 rounded-full px-6 text-sm font-medium"
        >
          {retryLabel}
        </Button>
      )}
    </div>
  );
}

// ─── EmptyState ──────────────────────────────────────────────────────────

export interface EmptyStateProps {
  /** Short headline — what's empty? */
  title: string;
  /** Calm one-sentence explanation of what will appear here. */
  message: string;
  /** Optional action rendered as a secondary button. */
  action?: {
    label: string;
    onClick: () => void;
  };
  /** Override the default Inbox icon with another lucide icon. */
  icon?: React.ElementType;
  className?: string;
}

/**
 * Calm, centered empty-state block. Default icon is an `Inbox` outline —
 * quiet enough that it doesn't compete with the copy. The action (if any)
 * is rendered as a secondary button so it stays subordinate to the page's
 * primary CTA.
 */
export function EmptyState({
  title,
  message,
  action,
  icon: Icon = Inbox,
  className,
}: EmptyStateProps) {
  return (
    <div
      role="status"
      className={cn(
        'flex flex-col items-center rounded-2xl border border-dashed border-border/60 bg-muted/20 px-6 py-14 text-center sm:py-16',
        className,
      )}
    >
      <span
        aria-hidden
        className="mb-5 flex size-12 items-center justify-center rounded-full"
        style={{
          backgroundColor: 'var(--muted)',
          color: 'var(--muted-foreground)',
        }}
      >
        <Icon className="size-5" strokeWidth={1.5} />
      </span>

      <h2
        className="max-w-xs text-balance text-base font-semibold tracking-tight"
        style={{ color: 'var(--foreground)' }}
      >
        {title}
      </h2>

      <p
        className="mt-2 max-w-xs text-pretty text-sm leading-relaxed"
        style={{ color: 'var(--muted-foreground)' }}
      >
        {message}
      </p>

      {action && (
        <Button
          type="button"
          variant="outline"
          onClick={action.onClick}
          className="mt-6 h-10 rounded-full px-5 text-sm font-medium"
        >
          {action.label}
        </Button>
      )}
    </div>
  );
}

// ─── LoadingSkeleton ─────────────────────────────────────────────────────

export type LoadingSkeletonVariant = 'home' | 'network' | 'activity' | 'devices';

export interface LoadingSkeletonProps {
  variant: LoadingSkeletonVariant;
  className?: string;
}

/**
 * Variant-aware skeleton. Each variant mirrors the layout of one consumer
 * page so the loading → content transition is visually seamless — there's no
 * "now you see a spinner, now you see a different layout" jump.
 *
 *   home     → hero ring + headline + subtext + button + 4 summary tiles
 *   network  → path-quality card + 4-node vertical topology
 *   activity → "Today" group header + 5 timeline items
 *   devices  → two sections ("Your devices" + "Nearby ShareNet devices"),
 *              each with a heading and 2 device-card skeletons
 *
 * Skeletons use shadcn's `<Skeleton>` (a `bg-accent animate-pulse rounded-md`
 * div) — no spinners, no shimmer.
 */
export function LoadingSkeleton({ variant, className }: LoadingSkeletonProps) {
  return (
    <div
      aria-busy="true"
      aria-live="polite"
      aria-label="Loading"
      className={cn(className)}
    >
      {variant === 'home' && <HomeSkeleton />}
      {variant === 'network' && <NetworkSkeleton />}
      {variant === 'activity' && <ActivitySkeleton />}
      {variant === 'devices' && <DevicesSkeleton />}
    </div>
  );
}

// ─── Variants ────────────────────────────────────────────────────────────

function HomeSkeleton() {
  return (
    <div className="flex flex-col items-center">
      {/* Ring skeleton (184px to match the real hero ring) */}
      <Skeleton className="mb-12 size-44 rounded-full" />
      {/* Headline skeleton */}
      <Skeleton className="mb-3 h-9 w-72" />
      <Skeleton className="mb-5 h-9 w-56" />
      {/* Subtext skeleton */}
      <Skeleton className="mb-9 h-5 w-80" />
      <Skeleton className="mb-2 h-5 w-64" />
      {/* Button skeleton */}
      <Skeleton className="mt-9 h-12 w-44 rounded-full" />

      {/* Summary grid skeleton */}
      <div className="mt-20 grid w-full grid-cols-2 gap-x-10 gap-y-10 sm:grid-cols-4 sm:gap-x-12">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="flex flex-col gap-2">
            <Skeleton className="h-3 w-16" />
            <Skeleton className="h-6 w-24" />
          </div>
        ))}
      </div>
    </div>
  );
}

function NetworkSkeleton() {
  return (
    <div className="flex flex-col gap-8">
      {/* Path quality summary skeleton */}
      <div className="rounded-2xl border border-border/60 bg-card/70 p-5">
        <div className="flex items-start gap-4">
          <Skeleton className="size-11 rounded-full" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-3 w-16" />
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-4 w-72" />
          </div>
        </div>
        <div className="mt-5 grid grid-cols-3 gap-3 border-t border-border/60 pt-4">
          <Skeleton className="h-9" />
          <Skeleton className="h-9" />
          <Skeleton className="h-9" />
        </div>
      </div>

      {/* Topology skeleton — 4 nodes with connecting lines */}
      <section
        aria-label="Network topology"
        className="flex flex-col items-center"
      >
        <div className="mx-auto flex w-full max-w-md flex-col gap-2">
          {[0, 1, 2, 3].map((i) => (
            <React.Fragment key={i}>
              <Skeleton className="h-16 w-full rounded-2xl" />
              {i < 3 && (
                <div
                  aria-hidden
                  className="mx-auto h-8 w-px bg-border/40"
                />
              )}
            </React.Fragment>
          ))}
        </div>
      </section>
    </div>
  );
}

function ActivitySkeleton() {
  return (
    <div className="flex flex-col gap-8">
      <div>
        <Skeleton className="mb-3 h-3 w-16" />
        <ol className="flex flex-col">
          {[0, 1, 2, 3, 4].map((i) => (
            <li key={i} className="flex gap-3.5 px-1 py-3">
              <Skeleton className="size-9 shrink-0 rounded-full" />
              <div className="flex flex-1 flex-col gap-2 pt-1">
                <div className="flex items-center gap-2">
                  <Skeleton className="h-3 w-10" />
                  <Skeleton className="h-4 w-44" />
                </div>
                <Skeleton className="h-4 w-72" />
                <Skeleton className="h-3 w-24" />
              </div>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function DevicesSkeleton() {
  return (
    <div className="flex flex-col gap-8">
      <DeviceSectionSkeleton title="Your devices" />
      <DeviceSectionSkeleton title="Nearby ShareNet devices" />
    </div>
  );
}

function DeviceSectionSkeleton({ title }: { title: string }) {
  return (
    <section aria-busy="true" aria-label={title}>
      <h2 className="mb-2.5 text-sm font-semibold tracking-tight text-foreground">
        {title}
      </h2>
      <ul className="flex flex-col gap-2">
        {[0, 1].map((i) => (
          <li
            key={i}
            className="flex items-center gap-3 rounded-xl border border-border/60 bg-card px-4 py-3"
          >
            <Skeleton className="size-9 rounded-lg" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3 w-32" />
              <Skeleton className="h-2.5 w-20" />
            </div>
            <Skeleton className="h-3 w-16" />
          </li>
        ))}
      </ul>
    </section>
  );
}

export default LoadingSkeleton;
