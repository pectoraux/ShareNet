'use client';

/**
 * ShareNet 2.0 — Device Card
 *
 * A single row in the devices list. Renders the device's type icon, name,
 * status, and — if `identityVerified` is true — a subtle "Verified" badge.
 *
 * PRIVACY RULE: this component MUST NOT render `publicKeyFingerprint` or any
 * other cryptographic identifier. The fingerprint is reserved for the
 * detail sheet (`device-detail-sheet.tsx`) so it can only be seen after an
 * explicit, deliberate interaction. (See `Device.publicKeyFingerprint`
 * doc-comment in `src/lib/sharenet/types.ts`.)
 *
 * The card is rendered as a `<button>` so it's keyboard-focusable and
 * announces itself as an interactive control. Activating it (click or
 * Enter/Space) calls `onOpen(device)`.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';
import {
  Laptop,
  Loader2,
  Monitor,
  MonitorSmartphone,
  ShieldCheck,
  Smartphone,
  Tablet,
  type LucideIcon,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import type { Device } from '@/lib/sharenet';

// ─── Status model ─────────────────────────────────────────────────────────

export type DeviceStatus = Device['status'];

interface StatusVisual {
  label: string;
  /** Tailwind classes for the status dot + label color. */
  textClass: string;
  /** Tailwind classes for the small status dot background. */
  dotClass: string;
}

const STATUS_VISUALS: Record<DeviceStatus, StatusVisual> = {
  connected: {
    label: 'Connected',
    textClass: 'text-emerald-600 dark:text-emerald-400',
    dotClass: 'bg-emerald-500 dark:bg-emerald-400',
  },
  offline: {
    label: 'Offline',
    textClass: 'text-muted-foreground',
    dotClass: 'bg-muted-foreground/40',
  },
  syncing: {
    label: 'Syncing',
    textClass: 'text-amber-600 dark:text-amber-400',
    dotClass: 'bg-amber-500 dark:bg-amber-400',
  },
};

export function getStatusVisual(status: DeviceStatus): StatusVisual {
  return STATUS_VISUALS[status] ?? STATUS_VISUALS.offline;
}

// ─── Device type → icon ───────────────────────────────────────────────────

const DEVICE_TYPE_ICON: Record<Device['type'], LucideIcon> = {
  laptop: Laptop,
  phone: Smartphone,
  tablet: Tablet,
  desktop: Monitor,
  other: MonitorSmartphone,
};

export function getDeviceTypeIcon(type: Device['type']): LucideIcon {
  return DEVICE_TYPE_ICON[type] ?? MonitorSmartphone;
}

/**
 * Render a device-type icon inline (avoids the "components created during
 * render" ESLint rule that fires when you do `const Icon = ...; <Icon />`).
 */
export function renderDeviceTypeIcon(
  type: Device['type'],
  className?: string,
) {
  const Icon = getDeviceTypeIcon(type);
  return <Icon className={className} />;
}

// ─── Props ─────────────────────────────────────────────────────────────────

export interface DeviceCardProps {
  device: Device;
  /** Called when the user activates the card (click / Enter / Space). */
  onOpen?: (device: Device) => void;
  /** Optional className override for the row. */
  className?: string;
}

// ─── Component ─────────────────────────────────────────────────────────────

export function DeviceCard({ device, onOpen, className }: DeviceCardProps) {
  const Icon = getDeviceTypeIcon(device.type);
  const status = getStatusVisual(device.status);
  const isInteractive = Boolean(onOpen);
  const syncing = device.status === 'syncing';

  const Comp = isInteractive ? 'button' : 'div';
  const compProps = isInteractive
    ? {
        type: 'button' as const,
        onClick: () => onOpen?.(device),
        'aria-label': `View details for ${device.name}`,
      }
    : {};

  return (
    <Comp
      data-slot="device-card"
      className={cn(
        'group flex w-full items-center gap-3 rounded-xl border border-border/60 bg-card px-4 py-3 text-left transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60',
        isInteractive && 'hover:bg-accent/40 hover:border-border',
        className,
      )}
      {...compProps}
    >
      {/* Device type icon — a soft rounded tile */}
      <span
        className={cn(
          'flex size-9 shrink-0 items-center justify-center rounded-lg',
          'bg-muted/60 text-foreground/70',
          'transition-colors group-hover:bg-muted',
        )}
        aria-hidden="true"
      >
        {renderDeviceTypeIcon(device.type, 'size-[18px]')}
      </span>

      {/* Name + meta (last seen) */}
      <span className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className="flex items-center gap-2">
          <span className="truncate text-sm font-medium text-foreground">
            {device.name}
          </span>
          {device.identityVerified ? (
            <Badge
              variant="outline"
              className={cn(
                'gap-1 px-1.5 py-0 text-[10px] font-medium',
                'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
              )}
            >
              <ShieldCheck className="size-3" aria-hidden="true" />
              Verified
            </Badge>
          ) : null}
        </span>
        {device.isLocal ? (
          <span className="text-[11px] text-muted-foreground">This device</span>
        ) : null}
      </span>

      {/* Status pill */}
      <span
        className={cn(
          'flex items-center gap-1.5 text-xs font-medium',
          status.textClass,
        )}
        aria-label={`Status: ${status.label}`}
      >
        {syncing ? (
          <Loader2 className="size-3 animate-spin" aria-hidden="true" />
        ) : (
          <span
            className={cn('size-1.5 rounded-full', status.dotClass)}
            aria-hidden="true"
          />
        )}
        {status.label}
      </span>
    </Comp>
  );
}

export default DeviceCard;
