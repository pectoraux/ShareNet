'use client';

/**
 * ShareNet 2.0 — Network settings detail page (/settings/network)
 *
 * The dedicated surface for the three behavioural toggles that govern how
 * this device participates in the ShareNet network:
 *
 *   - Connect automatically — establish a circuit when networks appear.
 *   - Prefer reliable paths  — trade latency for end-to-end reliability.
 *   - Allow this device to relay — forward traffic for other peers.
 *
 * Each row persists optimistically through the adapter (`updateSettings`)
 * with a roll-back on failure, mirroring the pattern established on the
 * root /settings page.
 *
 * Task ID: UI-SETTINGS-DETAIL
 */

import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ArrowLeft,
  Share2,
  ShieldCheck,
  Wifi,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { AppShell } from '@/components/sharenet/app-shell';
import {
  SettingsSection,
  SettingsSwitchRow,
} from '@/components/sharenet/settings-section';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import {
  getSettings,
  updateSettings,
  IS_MOCK,
  type SettingsState,
} from '@/lib/sharenet';

export default function NetworkSettingsPage() {
  return (
    <AppShell>
      <NetworkSettingsContent />
    </AppShell>
  );
}

function NetworkSettingsContent() {
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getSettings();
      setSettings(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Could not load settings.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  /**
   * Optimistic toggle: update local state immediately, then persist via
   * the adapter. Roll back on failure so the UI never lies about state.
   */
  const toggle = useCallback(
    async <K extends keyof SettingsState>(
      key: K,
      value: SettingsState[K],
    ) => {
      if (!settings) return;
      const next = { ...settings, [key]: value };
      setSettings(next);
      setPendingKey(String(key));
      try {
        await updateSettings({ [key]: value } as Partial<SettingsState>);
      } catch (err) {
        setSettings(settings);
        setError(
          err instanceof Error ? err.message : 'Could not update setting.',
        );
      } finally {
        setPendingKey(null);
      }
    },
    [settings],
  );

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
            <Wifi className="size-5" />
          </span>
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                Network
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
              How your device reaches the ShareNet network.
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

      {loading && !settings ? (
        <NetworkSettingsSkeleton />
      ) : settings ? (
        <SettingsSection
          title="Behaviour"
          description="Tune how and when your device participates in ShareNet."
        >
          <SettingsSwitchRow
            icon={Wifi}
            label="Connect automatically"
            description="Establish a ShareNet circuit when networks become available."
            checked={settings.connectAutomatically}
            onCheckedChange={(v) => void toggle('connectAutomatically', v)}
            disabled={pendingKey === 'connectAutomatically'}
          />
          <SettingsSwitchRow
            icon={ShieldCheck}
            label="Prefer reliable paths"
            description="Trade latency for higher end-to-end reliability."
            checked={settings.preferReliablePaths}
            onCheckedChange={(v) => void toggle('preferReliablePaths', v)}
            disabled={pendingKey === 'preferReliablePaths'}
          />
          <SettingsSwitchRow
            icon={Share2}
            label="Allow this device to relay"
            description="Let your device forward traffic for other ShareNet peers."
            checked={settings.allowRelaying}
            onCheckedChange={(v) => void toggle('allowRelaying', v)}
            disabled={pendingKey === 'allowRelaying'}
          />
        </SettingsSection>
      ) : null}
    </div>
  );
}

// ─── Loading skeleton ──────────────────────────────────────────────────────

function NetworkSettingsSkeleton() {
  return (
    <div className="flex flex-col gap-2.5" aria-busy="true">
      <div className="flex items-baseline justify-between gap-3 px-1">
        <div className="flex flex-col gap-1">
          <Skeleton className="h-3 w-20 rounded" />
          <Skeleton className="h-2.5 w-56 rounded" />
        </div>
      </div>
      <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className={cn(
              'flex items-center gap-3 px-4 py-3',
              i > 0 ? 'border-t border-border/50' : null,
            )}
          >
            <Skeleton className="size-7 rounded-md" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3.5 w-40 rounded" />
              <Skeleton className="h-2.5 w-64 rounded" />
            </div>
            <Skeleton className="h-4 w-8 rounded-full" />
          </div>
        ))}
      </div>
    </div>
  );
}
