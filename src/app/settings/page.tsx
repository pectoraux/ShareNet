'use client';

/**
 * ShareNet 2.0 — Settings page (/settings)
 *
 * Native-looking grouped settings, modelled on the iOS/macOS Settings app:
 *
 *   Network       — Connect automatically / Prefer reliable paths / Allow relaying
 *   Privacy       — Private relay mode / Share diagnostics / Privacy overview link
 *   Appearance    — Theme selector (Light / Dark / System)
 *   Advanced      — Engineering diagnostics link
 *   About         — version + external links
 *
 * Switches persist via `updateSettings()`; the theme selector additionally
 * applies the change to next-themes immediately so the user sees the
 * preview without a reload.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';
import { useTheme } from 'next-themes';
import {
  BookOpen,
  FlaskConical,
  Globe,
  Lock,
  Moon,
  Settings as SettingsIcon,
  Share2,
  ShieldCheck,
  Sun,
  Wifi,
  type LucideIcon,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { AppShell } from '@/components/sharenet/app-shell';
import {
  SettingsSection,
  SettingsRow,
  SettingsSwitchRow,
  SettingsLinkRow,
} from '@/components/sharenet/settings-section';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  getSettings,
  updateSettings,
  IS_MOCK,
  type SettingsState,
} from '@/lib/sharenet';

const SHARENET_VERSION = '2.0.0';

export default function SettingsPage() {
  return (
    <AppShell>
      <SettingsContent />
    </AppShell>
  );
}

function SettingsContent() {
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  const { resolvedTheme, setTheme } = useTheme();

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getSettings();
      setSettings(result);
      // Apply persisted theme to next-themes on first load.
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
   * Generic switch toggle: optimistic local update + persisted update via
   * the adapter. The `pendingKey` is used to show a tiny spinner / dim the
   * control while the write is in flight, without blocking subsequent toggles.
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
        // Roll back on failure.
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

  const onTheme = useCallback(
    (theme: SettingsState['theme']) => {
      // Apply immediately to next-themes for a live preview, then persist.
      setTheme(theme);
      void toggle('theme', theme);
    },
    [setTheme, toggle],
  );

  if (loading && !settings) {
    return <SettingsSkeleton />;
  }

  if (error && !settings) {
    return (
      <div
        role="alert"
        className="rounded-xl border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive"
      >
        {error}
      </div>
    );
  }

  if (!settings) return null;

  return (
    <div className="flex flex-col gap-8">
      {/* ─── Page header ─────────────────────────────────────────────── */}
      <header className="flex items-center gap-2.5">
        <span
          className="flex size-9 items-center justify-center rounded-lg bg-muted/60 text-foreground/70"
          aria-hidden="true"
        >
          <SettingsIcon className="size-5" />
        </span>
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              Settings
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
            Configure how your device connects to ShareNet.
          </p>
        </div>
      </header>

      {/* ─── Network ─────────────────────────────────────────────────── */}
      <SettingsSection
        title="Network"
        description="How your device reaches the ShareNet network."
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
          label="Allow relaying"
          description="Let your device forward traffic for other ShareNet peers."
          checked={settings.allowRelaying}
          onCheckedChange={(v) => void toggle('allowRelaying', v)}
          disabled={pendingKey === 'allowRelaying'}
        />
      </SettingsSection>

      {/* ─── Privacy ─────────────────────────────────────────────────── */}
      <SettingsSection
        title="Privacy"
        description="What your device reveals and to whom."
      >
        <SettingsSwitchRow
          icon={Lock}
          label="Private relay mode"
          description="Route through relays without exposing your device address."
          checked={settings.privateRelayMode}
          onCheckedChange={(v) => void toggle('privateRelayMode', v)}
          disabled={pendingKey === 'privateRelayMode'}
        />
        <SettingsSwitchRow
          icon={ShieldCheck}
          label="Share diagnostics"
          description="Send anonymous performance + reliability metrics."
          checked={settings.shareDiagnostics}
          onCheckedChange={(v) => void toggle('shareDiagnostics', v)}
          disabled={pendingKey === 'shareDiagnostics'}
        />
        <SettingsLinkRow
          icon={BookOpen}
          label="Privacy overview"
          description="See where your traffic goes and who can see what."
          href="/settings/privacy"
        />
      </SettingsSection>

      {/* ─── Appearance ──────────────────────────────────────────────── */}
      <SettingsSection
        title="Appearance"
        description="Theme follows your system preference by default."
      >
        <SettingsRow icon={getColorThemeIcon(resolvedTheme)} label="Theme">
          <ThemeSegmentedControl
            value={settings.theme}
            onChange={onTheme}
            disabled={pendingKey === 'theme'}
          />
        </SettingsRow>
      </SettingsSection>

      {/* ─── Advanced ─────────────────────────────────────────────────── */}
      <SettingsSection
        title="Advanced"
        description="Engineering surfaces. Use only if you know what you're doing."
      >
        <SettingsLinkRow
          icon={FlaskConical}
          label="Engineering diagnostics"
          description="Conformance suites, integration tests, mesh simulator."
          href="/diagnostics"
        />
      </SettingsSection>

      {/* ─── About ───────────────────────────────────────────────────── */}
      <SettingsSection title="About ShareNet">
        <SettingsRow icon={SettingsIcon} label="Version">
          <span className="text-xs font-mono text-muted-foreground tabular-nums">
            v{SHARENET_VERSION}
          </span>
        </SettingsRow>
        <SettingsLinkRow
          icon={BookOpen}
          label="Specification"
          href="/spec/README.md"
        />
        <SettingsLinkRow
          icon={ShieldCheck}
          label="Security policy"
          href="/docs/SECURITY.md"
        />
        <SettingsLinkRow
          icon={Globe}
          label="Architecture"
          href="/docs/SN2_ARCHITECTURE.md"
        />
      </SettingsSection>

      {error ? (
        <p
          role="alert"
          className="text-xs text-destructive"
        >
          {error}
        </p>
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
    { value: 'system', label: 'System', icon: SettingsIcon },
  ];

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
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

function getColorThemeIcon(resolvedTheme: string | undefined): LucideIcon {
  if (resolvedTheme === 'dark') return Moon;
  if (resolvedTheme === 'light') return Sun;
  return SettingsIcon;
}

// ─── Loading skeleton ───────────────────────────────────────────────────────

function SettingsSkeleton() {
  return (
    <div className="flex flex-col gap-8" aria-busy="true">
      <div className="flex items-center gap-2.5">
        <div className="size-9 rounded-lg bg-muted/60 animate-pulse" />
        <div className="flex flex-col gap-1.5">
          <div className="h-4 w-20 rounded bg-muted animate-pulse" />
          <div className="h-3 w-40 rounded bg-muted animate-pulse" />
        </div>
      </div>
      {[0, 1, 2, 3].map((i) => (
        <div key={i} className="flex flex-col gap-2">
          <div className="h-3 w-24 rounded bg-muted animate-pulse" />
          <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
            {[0, 1].map((j) => (
              <div
                key={j}
                className={cn(
                  'flex items-center gap-3 px-4 py-3',
                  j === 0 ? null : 'border-t border-border/50',
                )}
              >
                <div className="size-7 rounded-md bg-muted animate-pulse" />
                <div className="flex-1 space-y-1.5">
                  <div className="h-3 w-32 rounded bg-muted animate-pulse" />
                  <div className="h-2.5 w-48 rounded bg-muted/70 animate-pulse" />
                </div>
                <div className="h-4 w-8 rounded-full bg-muted animate-pulse" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

