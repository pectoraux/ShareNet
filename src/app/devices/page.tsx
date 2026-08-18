'use client';

/**
 * ShareNet 2.0 — Devices page (/devices)
 *
 * Shows participating devices in the user's ecosystem in two sections:
 *   1. "Your devices"           — the user's laptop/phone/tablet
 *   2. "Nearby ShareNet devices" — community ShareNet nodes in radio range
 *
 * Tapping a device opens a detail sheet (right side) with the full record
 * including the public key fingerprint — which is NEVER shown in the list
 * view. See `device-card.tsx` and `device-detail-sheet.tsx` for the
 * privacy boundary.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';
import { useCallback, useEffect, useState } from 'react';
import { MonitorSmartphone, RefreshCw } from 'lucide-react';

import { AppShell } from '@/components/sharenet/app-shell';
import { DeviceList } from '@/components/sharenet/device-list';
import { DeviceDetailSheet } from '@/components/sharenet/device-detail-sheet';
import {
  EmptyState,
  ErrorState,
  LoadingSkeleton,
} from '@/components/sharenet/state-blocks';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { getDevices, IS_MOCK, type Device } from '@/lib/sharenet';

export default function DevicesPage() {
  return (
    <AppShell>
      <DevicesContent />
    </AppShell>
  );
}

function DevicesContent() {
  const [devices, setDevices] = useState<{
    local: Device[];
    nearby: Device[];
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selected, setSelected] = useState<Device | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);

  const fetchDevices = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getDevices();
      setDevices(result);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Could not load devices.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  const onSelect = useCallback((device: Device) => {
    setSelected(device);
    setSheetOpen(true);
  }, []);

  const onOpenChange = useCallback((open: boolean) => {
    setSheetOpen(open);
    // Don't clear `selected` until after the close animation — otherwise the
    // sheet tears through stale content. We clear on the next tick instead.
    if (!open) {
      window.setTimeout(() => setSelected(null), 300);
    }
  }, []);

  const connectedCount = devices
    ? [...devices.local, ...devices.nearby].filter(
        (d) => d.status === 'connected',
      ).length
    : 0;

  // The page is the single source of truth for loading / error / empty
  // states, using the shared state blocks. `DeviceList` is only rendered
  // when there's actual data to show — so it no longer needs its internal
  // loading/error/empty fallbacks.
  const isEmpty =
    !loading &&
    !error &&
    !!devices &&
    devices.local.length === 0 &&
    devices.nearby.length === 0;

  return (
    <>
      <div className="flex flex-col gap-6">
        {/* ─── Page header ─────────────────────────────────────────── */}
        <header className="flex flex-col gap-3">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span
                className="flex size-9 items-center justify-center rounded-lg bg-muted/60 text-foreground/70"
                aria-hidden="true"
              >
                <MonitorSmartphone className="size-5" />
              </span>
              <div className="flex flex-col gap-0.5">
                <div className="flex items-center gap-2">
                  <h1 className="text-xl font-semibold tracking-tight text-foreground">
                    Devices
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
                  Devices paired with your ShareNet identity, and nearby
                  community nodes.
                </p>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchDevices}
              disabled={loading}
              aria-label="Refresh device list"
              className="shrink-0"
            >
              <RefreshCw
                className={loading ? 'size-3.5 animate-spin' : 'size-3.5'}
                aria-hidden="true"
              />
              Refresh
            </Button>
          </div>

          {!loading && !error && devices && !isEmpty ? (
            <p className="text-xs text-muted-foreground">
              <span className="font-medium text-foreground tabular-nums">
                {connectedCount}
              </span>{' '}
              connected
            </p>
          ) : null}
        </header>

        {/* ─── Body: loading / error / empty / list ─────────────────── */}
        {loading ? (
          <LoadingSkeleton variant="devices" />
        ) : error ? (
          <ErrorState
            title="Couldn't load devices"
            message="Something went wrong while reading your paired devices."
            onRetry={fetchDevices}
          />
        ) : isEmpty ? (
          <EmptyState
            title="No devices found"
            message="Devices you pair with ShareNet will appear here."
          />
        ) : devices ? (
          <DeviceList devices={devices} onSelect={onSelect} />
        ) : null}
      </div>

      <DeviceDetailSheet
        device={selected}
        open={sheetOpen}
        onOpenChange={onOpenChange}
      />
    </>
  );
}

