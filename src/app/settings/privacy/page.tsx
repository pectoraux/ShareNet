'use client';

/**
 * ShareNet 2.0 — Privacy overview page (/settings/privacy)
 *
 * A dedicated page explaining where ShareNet traffic goes and what each
 * participant can see. Renders the `<PrivacyOverview>` component (vertical
 * flow diagram + per-participant explanation), optionally augmented with a
 * live "current session" status block fed by the adapter's
 * `getPrivacyState()`.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, ShieldCheck } from 'lucide-react';

import { AppShell } from '@/components/sharenet/app-shell';
import { PrivacyOverview } from '@/components/sharenet/privacy-overview';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { getPrivacyState, IS_MOCK, type PrivacyState } from '@/lib/sharenet';

export default function PrivacyPage() {
  return (
    <AppShell>
      <PrivacyContent />
    </AppShell>
  );
}

function PrivacyContent() {
  const [privacy, setPrivacy] = useState<PrivacyState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPrivacy = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getPrivacyState();
      setPrivacy(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Could not load privacy state.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPrivacy();
  }, [fetchPrivacy]);

  return (
    <div className="flex flex-col gap-6">
      {/* ─── Header ───────────────────────────────────────────────────── */}
      <header className="flex flex-col gap-3">
        <Link
          href="/settings"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 rounded-md w-fit"
        >
          <ArrowLeft className="size-3.5" aria-hidden="true" />
          Back to settings
        </Link>

        <div className="flex items-center gap-2.5">
          <span
            className="flex size-9 items-center justify-center rounded-lg bg-muted/60 text-foreground/70"
            aria-hidden="true"
          >
            <ShieldCheck className="size-5" />
          </span>
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                Privacy overview
              </h1>
              {IS_MOCK ? (
                <Badge
                  variant="outline"
                  className="px-1.5 py-0 text-[10px] font-medium border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                >
                  Prototype
                </Badge>
              ) : null}
            </div>
            <p className="text-xs text-muted-foreground">
              Where your traffic goes and what each participant can see.
            </p>
          </div>
        </div>
      </header>

      {/* ─── Body ────────────────────────────────────────────────────── */}
      {error ? (
        <div
          role="alert"
          className="rounded-xl border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive"
        >
          {error}
        </div>
      ) : null}

      {loading && !privacy ? (
        <PrivacySkeleton />
      ) : (
        <PrivacyOverview privacy={privacy} />
      )}
    </div>
  );
}

// ─── Loading skeleton ──────────────────────────────────────────────────────

function PrivacySkeleton() {
  return (
    <div className="flex flex-col gap-6" aria-busy="true">
      {/* Flow skeleton */}
      <div className="flex flex-col">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="flex flex-col">
            <div className="flex items-center gap-3 rounded-xl border border-border/60 bg-card px-4 py-3">
              <Skeleton className="size-9 rounded-lg" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-3.5 w-40 rounded" />
              </div>
              <Skeleton className="h-2.5 w-10 rounded" />
            </div>
            {i < 4 ? (
              <div className="flex justify-center py-1.5">
                <Skeleton className="size-4 rounded" />
              </div>
            ) : null}
          </div>
        ))}
      </div>

      {/* Participants skeleton */}
      <div className="flex flex-col gap-2.5">
        <Skeleton className="h-3.5 w-44 rounded" />
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="flex items-start gap-3 rounded-xl border border-border/60 bg-card px-4 py-3"
          >
            <Skeleton className="size-7 rounded-md" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3 w-20 rounded" />
              <Skeleton className="h-2.5 w-full rounded" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

