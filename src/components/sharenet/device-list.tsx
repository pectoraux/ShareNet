'use client';

/**
 * ShareNet 2.0 — Device List
 *
 * Renders the devices grouped into two sections:
 *
 *   1. "Your devices"          — the user's own laptop/phone/tablet.
 *   2. "Nearby ShareNet devices" — community ShareNet nodes within radio
 *                                  range that could act as relays.
 *
 * The split is computed here, not in the adapter, because it's a UI concern:
 * the adapter returns `{ local, nearby }` to express protocol-level facts
 * (which device is *running this UI* vs which are *peers*), and "nearby" is
 * a peer relationship. The user's mental model, however, is "the devices I
 * own vs the ShareNet nodes around me" — so we re-bucket:
 *
 *   yourDevices     = local  + nearby.filter(isPersonalDevice)
 *   communityDevices = nearby.filter(isCommunityDevice)
 *
 * Where "community" means a device whose name is prefixed with "ShareNet"
 * (the fixture convention for ShareNet-branded community nodes). A future
 * adapter improvement should add a proper `community: boolean` field; until
 * then this heuristic is good enough and lives entirely in the UI layer.
 *
 * PRIVACY: this component does NOT render public key fingerprints. Cards
 * render only name + status + verified badge. Tapping a card calls
 * `onSelect(device)`, which the page wires up to the detail sheet — the
 * only place the fingerprint is shown.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';

import { cn } from '@/lib/utils';
import { Skeleton } from '@/components/ui/skeleton';
import type { Device } from '@/lib/sharenet';

import { DeviceCard } from './device-card';

// ─── Sectioning helpers ────────────────────────────────────────────────────

/** True for community ShareNet-branded nodes (Café Node, Raspberry Pi, …). */
function isCommunityDevice(device: Device): boolean {
  return (
    device.name.startsWith('ShareNet ·') ||
    device.name.startsWith('ShareNet ')
  );
}

export interface DeviceGroups {
  yourDevices: Device[];
  communityDevices: Device[];
}

/**
 * Split the adapter's `{local, nearby}` shape into the two user-facing
 * sections. Pure function — exported so the page (and tests) can verify the
 * bucketing.
 */
export function groupDevices(devices: {
  local: Device[];
  nearby: Device[];
}): DeviceGroups {
  const yourDevices: Device[] = [...devices.local];
  const communityDevices: Device[] = [];

  for (const d of devices.nearby) {
    if (isCommunityDevice(d)) {
      communityDevices.push(d);
    } else {
      yourDevices.push(d);
    }
  }

  return { yourDevices, communityDevices };
}

// ─── Section wrapper ────────────────────────────────────────────────────────

interface SectionProps {
  title: string;
  description?: string;
  devices: Device[];
  onSelect: (device: Device) => void;
}

function DeviceSection({ title, description, devices, onSelect }: SectionProps) {
  return (
    <section aria-labelledby={`${title.replace(/\s+/g, '-')}-heading`}>
      <header className="mb-2.5 flex flex-col gap-0.5">
        <h2
          id={`${title.replace(/\s+/g, '-')}-heading`}
          className="text-sm font-semibold tracking-tight text-foreground"
        >
          {title}
        </h2>
        {description ? (
          <p className="text-xs text-muted-foreground">{description}</p>
        ) : null}
      </header>

      <ul className="flex flex-col gap-2" role="list">
        {devices.map((device) => (
          <li key={device.id} role="listitem">
            <DeviceCard device={device} onOpen={onSelect} />
          </li>
        ))}
      </ul>
    </section>
  );
}

// ─── Loading skeleton ──────────────────────────────────────────────────────

function LoadingSection({ title }: { title: string }) {
  return (
    <section aria-busy="true" aria-label={title}>
      <h2 className="mb-2.5 text-sm font-semibold tracking-tight text-foreground">
        {title}
      </h2>
      <ul className="flex flex-col gap-2">
        {[0, 1].map((i) => (
          <li
            key={i}
            className={cn(
              'flex items-center gap-3 rounded-xl border border-border/60 bg-card px-4 py-3',
            )}
          >
            <Skeleton className="size-9 rounded-lg" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3 w-32 rounded" />
              <Skeleton className="h-2.5 w-20 rounded" />
            </div>
            <Skeleton className="h-3 w-16 rounded" />
          </li>
        ))}
      </ul>
    </section>
  );
}

// ─── Main component ─────────────────────────────────────────────────────────

export interface DeviceListProps {
  /**
   * The raw adapter result. Will be split into "Your devices" and
   * "Nearby ShareNet devices" by `groupDevices`.
   */
  devices?: { local: Device[]; nearby: Device[] };
  /** True while the adapter is fetching. Renders skeletons. */
  loading?: boolean;
  /** Called when the user selects a device card. */
  onSelect: (device: Device) => void;
  /** Optional error message. Renders an inline alert when non-null. */
  error?: string | null;
  className?: string;
}

export function DeviceList({
  devices,
  loading = false,
  onSelect,
  error = null,
  className,
}: DeviceListProps) {
  if (loading && !devices) {
    return (
      <div className={cn('flex flex-col gap-8', className)}>
        <LoadingSection title="Your devices" />
        <LoadingSection title="Nearby ShareNet devices" />
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        className={cn(
          'rounded-xl border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive',
          className,
        )}
      >
        {error}
      </div>
    );
  }

  if (!devices) return null;

  const { yourDevices, communityDevices } = groupDevices(devices);

  const empty =
    yourDevices.length === 0 && communityDevices.length === 0;

  if (empty) {
    return (
      <div
        className={cn(
          'rounded-xl border border-dashed border-border/70 bg-muted/30 px-6 py-10 text-center',
          className,
        )}
      >
        <p className="text-sm font-medium text-foreground">No devices found</p>
        <p className="mt-1 text-xs text-muted-foreground">
          Devices you pair with ShareNet will appear here.
        </p>
      </div>
    );
  }

  return (
    <div className={cn('flex flex-col gap-8', className)}>
      {yourDevices.length > 0 ? (
        <DeviceSection
          title="Your devices"
          description="Paired to your ShareNet identity."
          devices={yourDevices}
          onSelect={onSelect}
        />
      ) : null}

      {communityDevices.length > 0 ? (
        <DeviceSection
          title="Nearby ShareNet devices"
          description="Community nodes in radio range. Can act as relays."
          devices={communityDevices}
          onSelect={onSelect}
        />
      ) : null}
    </div>
  );
}

export default DeviceList;
