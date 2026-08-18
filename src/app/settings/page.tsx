'use client';

/**
 * ShareNet 2.0 — Settings page (/settings)
 *
 * The settings root is a navigation hub: each section surfaces a short
 * summary and a chevron that opens a dedicated detail page where the
 * actual controls live.
 *
 *   Network          → /settings/network      (3 behavioural switches)
 *   Privacy          → /settings/privacy      (overview + 2 inline toggles)
 *   Appearance       → /settings/appearance   (theme selector)
 *   Notifications    → (inline placeholder toggles, UI-only for now)
 *   Advanced        → /diagnostics            (engineering surfaces)
 *   About           → /settings/about        (version + protocol + resources)
 *
 * The two privacy switches and the two notification toggles stay inline
 * because they are single-purpose and don't justify a dedicated route.
 * Everything else gets a `SettingsLinkRow` so the root stays scannable.
 *
 * Task ID: UI-DEVICES-SETTINGS · updated UI-SETTINGS-DETAIL
 */

import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';
import {
  Bell,
  BellRing,
  BookOpen,
  FlaskConical,
  Lock,
  Palette,
  Settings as SettingsIcon,
  ShieldCheck,
  Wifi,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { AppShell } from '@/components/sharenet/app-shell';
import {
  SettingsSection,
  SettingsSwitchRow,
  SettingsLinkRow,
} from '@/components/sharenet/settings-section';
import { Badge } from '@/components/ui/badge';
import {
  getSettings,
  updateSettings,
  IS_MOCK,
  type SettingsState,
} from '@/lib/sharenet';

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

  // UI-only placeholder toggles. The adapter can be extended later to
  // persist these once the notification subsystem exists.
  const [pushNotifications, setPushNotifications] = useState(false);
  const [connectionAlerts, setConnectionAlerts] = useState(true);

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
   * Generic switch toggle: optimistic local update + persisted update via
   * the adapter. The `pendingKey` is used to dim the control while the
   * write is in flight, without blocking subsequent toggles.
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
        <SettingsLinkRow
          icon={Wifi}
          label="Network behaviour"
          description="Connect automatically, prefer reliable paths, allow relaying."
          href="/settings/network"
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
        <SettingsLinkRow
          icon={Palette}
          label="Theme"
          description="Light, dark, or follow your system."
          href="/settings/appearance"
          meta={capitalizeTheme(settings.theme)}
        />
      </SettingsSection>

      {/* ─── Notifications ───────────────────────────────────────────── */}
      <SettingsSection
        title="Notifications"
        description="Placeholders — the notification subsystem is coming soon."
      >
        <SettingsSwitchRow
          icon={Bell}
          label="Push notifications"
          description="Receive notifications for important ShareNet events."
          checked={pushNotifications}
          onCheckedChange={setPushNotifications}
        />
        <SettingsSwitchRow
          icon={BellRing}
          label="Connection alerts"
          description="Get notified when your connection state changes."
          checked={connectionAlerts}
          onCheckedChange={setConnectionAlerts}
        />
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
        <SettingsLinkRow
          icon={SettingsIcon}
          label="About"
          description="Version, protocol, and engineering resources."
          href="/settings/about"
          meta="v0.1"
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

// ─── Helpers ───────────────────────────────────────────────────────────────

function capitalizeTheme(theme: SettingsState['theme']): string {
  if (theme === 'system') return 'System';
  if (theme === 'dark') return 'Dark';
  return 'Light';
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
      {[0, 1, 2, 3, 4, 5].map((i) => (
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
