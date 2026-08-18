'use client';

/**
 * ShareNet 2.0 — Appearance settings detail page (/settings/appearance)
 *
 * The dedicated surface for the theme selector. Changes apply immediately
 * via `next-themes` (so the preview is live) and are persisted through the
 * adapter (`updateSettings`) so the choice survives a reload.
 *
 * Three options, rendered as a segmented control (radiogroup semantics):
 *
 *   Light · Dark · System
 *
 * `System` follows the device's `prefers-color-scheme` — the same default
 * the rest of the consumer UI inherits from `next-themes`'s `enableSystem`.
 *
 * Task ID: UI-SETTINGS-DETAIL
 */

import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useTheme } from 'next-themes';
import {
  ArrowLeft,
  Monitor,
  Moon,
  Palette,
  Sun,
  type LucideIcon,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { AppShell } from '@/components/sharenet/app-shell';
import {
  SettingsSection,
  SettingsRow,
} from '@/components/sharenet/settings-section';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import {
  getSettings,
  updateSettings,
  IS_MOCK,
  type SettingsState,
} from '@/lib/sharenet';

export default function AppearanceSettingsPage() {
  return (
    <AppShell>
      <AppearanceSettingsContent />
    </AppShell>
  );
}

function AppearanceSettingsContent() {
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingTheme, setPendingTheme] = useState(false);

  const { setTheme } = useTheme();

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getSettings();
      setSettings(result);
      // Apply persisted theme to next-themes on first load so the
      // rendered preview matches what the user last chose.
      if (result.theme) {
        setTheme(result.theme);
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Could not load settings.',
      );
    } finally {
      setLoading(false);
    }
  }, [setTheme]);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  /**
   * Apply the new theme immediately to next-themes for a live preview,
   * then persist it via the adapter so it survives a reload.
   */
  const onThemeChange = useCallback(
    (theme: SettingsState['theme']) => {
      if (!settings) return;
      setTheme(theme);
      setSettings({ ...settings, theme });
      setPendingTheme(true);
      updateSettings({ theme })
        .catch((err) => {
          // Roll back local state on failure.
          setSettings(settings);
          setError(
            err instanceof Error ? err.message : 'Could not update theme.',
          );
        })
        .finally(() => setPendingTheme(false));
    },
    [settings, setTheme],
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
            <Palette className="size-5" />
          </span>
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                Appearance
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
              Choose how ShareNet looks. Changes apply immediately.
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
        <AppearanceSkeleton />
      ) : settings ? (
        <>
          <SettingsSection
            title="Theme"
            description="System follows your device's appearance setting."
          >
            <SettingsRow icon={getThemeIcon(settings.theme)} label="Color scheme">
              <ThemeSegmentedControl
                value={settings.theme}
                onChange={onThemeChange}
                disabled={pendingTheme}
              />
            </SettingsRow>
          </SettingsSection>

          <p className="px-1 text-xs leading-relaxed text-muted-foreground">
            The consumer interface prefers a warm-light aesthetic. Switching
            to <span className="font-medium text-foreground">Dark</span> tints
            the chrome without changing the calm accent palette.{' '}
            <span className="font-medium text-foreground">System</span>{' '}
            follows your operating system's light/dark preference.
          </p>
        </>
      ) : null}
    </div>
  );
}

// ─── Theme segmented control ──────────────────────────────────────────────

interface ThemeSegmentedControlProps {
  value: SettingsState['theme'];
  onChange: (value: SettingsState['theme']) => void;
  disabled?: boolean;
}

function ThemeSegmentedControl({
  value,
  onChange,
  disabled,
}: ThemeSegmentedControlProps) {
  const options: Array<{
    value: SettingsState['theme'];
    label: string;
    icon: LucideIcon;
  }> = [
    { value: 'light', label: 'Light', icon: Sun },
    { value: 'dark', label: 'Dark', icon: Moon },
    { value: 'system', label: 'System', icon: Monitor },
  ];

  return (
    <div
      role="radiogroup"
      aria-label="Color scheme"
      className="inline-flex items-center rounded-md border border-border/60 bg-muted/40 p-0.5"
    >
      {options.map((opt) => {
        const Icon = opt.icon;
        const active = value === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={disabled}
            onClick={() => onChange(opt.value)}
            className={cn(
              'inline-flex h-7 items-center gap-1.5 rounded-[5px] px-2.5 text-xs font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60',
              active
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground',
              disabled ? 'opacity-50 pointer-events-none' : null,
            )}
          >
            <Icon className="size-3.5" aria-hidden="true" />
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

function getThemeIcon(theme: SettingsState['theme']): LucideIcon {
  if (theme === 'dark') return Moon;
  if (theme === 'light') return Sun;
  return Monitor;
}

// ─── Loading skeleton ──────────────────────────────────────────────────────

function AppearanceSkeleton() {
  return (
    <div className="flex flex-col gap-2.5" aria-busy="true">
      <div className="flex items-baseline justify-between gap-3 px-1">
        <div className="flex flex-col gap-1">
          <Skeleton className="h-3 w-16 rounded" />
          <Skeleton className="h-2.5 w-48 rounded" />
        </div>
      </div>
      <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3">
          <Skeleton className="size-7 rounded-md" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-3.5 w-24 rounded" />
          </div>
          <Skeleton className="h-7 w-44 rounded-md" />
        </div>
      </div>
      <Skeleton className="h-10 w-full rounded" />
    </div>
  );
}
