'use client';

/**
 * ShareNet 2.0 — Device Detail Sheet
 *
 * The detail sheet that opens when a user taps a `DeviceCard`. Renders the
 * full device record including the public key fingerprint, capabilities and
 * last-seen timestamp.
 *
 * This is the ONLY place the public key fingerprint may be shown. The list
 * view (`device-card.tsx`) deliberately omits it — see the doc-comment on
 * `Device.publicKeyFingerprint` in `src/lib/sharenet/types.ts`.
 *
 * The sheet is *controlled*: parent passes `device` (or null) plus
 * `open`/`onOpenChange`. Radix Sheet handles animation + ESC-to-close +
 * focus trap. We add a copy-to-clipboard affordance for the fingerprint
 * because that's the realistic reason a user would open this sheet.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';
import { formatDistanceToNow, format } from 'date-fns';
import {
  Check,
  Copy,
  Fingerprint,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Activity as ActivityIcon,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Button } from '@/components/ui/button';
import type { Device } from '@/lib/sharenet';

import { getDeviceTypeIcon, getStatusVisual, renderDeviceTypeIcon } from './device-card';

// ─── Helpers ──────────────────────────────────────────────────────────────

/** "relay" → "Relay", "content-source" → "Content source" */
function humanizeCapability(cap: string): string {
  return cap
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

// ─── Sub-rows ──────────────────────────────────────────────────────────────

interface RowProps {
  label: string;
  icon?: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  /** Hint for screen readers describing the row value. */
  valueLabel?: string;
}

function DetailRow({ label, icon: Icon, children, valueLabel }: RowProps) {
  return (
    <div className="flex items-start gap-3 py-3">
      {Icon ? (
        <span
          className="flex size-7 shrink-0 items-center justify-center rounded-md bg-muted/60 text-muted-foreground"
          aria-hidden="true"
        >
          <Icon className="size-3.5" />
        </span>
      ) : (
        <span className="size-7 shrink-0" aria-hidden="true" />
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <dt className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </dt>
        <dd
          className="text-sm text-foreground break-words"
          aria-label={valueLabel}
        >
          {children}
        </dd>
      </div>
    </div>
  );
}

// ─── Fingerprint block (with copy button) ──────────────────────────────────

function FingerprintBlock({ fingerprint }: { fingerprint: string }) {
  const [copied, setCopied] = React.useState(false);

  const onCopy = React.useCallback(async () => {
    try {
      await navigator.clipboard.writeText(fingerprint);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard API may be unavailable (permission denied, insecure
      // context). Fail silently — the user can still read + select the text.
    }
  }, [fingerprint]);

  return (
    <div className="flex items-stretch gap-2">
      <code
        className="flex-1 min-w-0 overflow-x-auto rounded-md bg-muted/60 px-3 py-2 font-mono text-[11px] leading-relaxed text-foreground/90 break-all selection:bg-primary/20"
        // The fingerprint is intentionally selectable so it can be copied
        // without depending on the clipboard API.
        aria-label="Public key fingerprint"
      >
        {fingerprint}
      </code>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onCopy}
        className="h-auto shrink-0 px-2.5"
        aria-label="Copy public key fingerprint"
      >
        {copied ? (
          <Check className="size-3.5 text-emerald-600 dark:text-emerald-400" />
        ) : (
          <Copy className="size-3.5" />
        )}
      </Button>
    </div>
  );
}

// ─── Identity row ──────────────────────────────────────────────────────────

function IdentityValue({ verified }: { verified: boolean }) {
  if (verified) {
    return (
      <span className="inline-flex items-center gap-1.5 text-sm font-medium text-emerald-700 dark:text-emerald-300">
        <ShieldCheck className="size-4" aria-hidden="true" />
        Verified
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-sm font-medium text-amber-700 dark:text-amber-400">
      <ShieldAlert className="size-4" aria-hidden="true" />
      Not verified
    </span>
  );
}

// ─── Main component ────────────────────────────────────────────────────────

export interface DeviceDetailSheetProps {
  device: Device | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function DeviceDetailSheet({
  device,
  open,
  onOpenChange,
}: DeviceDetailSheetProps) {
  // Render a stable placeholder sheet body when there's no device so the
  // close animation doesn't tear through stale content. We still keep the
  // real content mounted by keying on device.id when one exists.
  const hasDevice = Boolean(device);
  const status = device ? getStatusVisual(device.status) : null;
  const syncing = device?.status === 'syncing';

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-md gap-0 p-0"
        aria-describedby={undefined}
      >
        <SheetHeader className="gap-2 px-6 pt-6 pb-4 border-b border-border/60">
          <div className="flex items-center gap-3">
            {device ? (
              <span
                className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-muted/60 text-foreground/70"
                aria-hidden="true"
              >
                {renderDeviceTypeIcon(device.type, 'size-5')}
              </span>
            ) : null}
            <div className="flex min-w-0 flex-col gap-0.5">
              <SheetTitle className="truncate text-base font-semibold">
                {device?.name ?? 'Device'}
              </SheetTitle>
              {device?.isLocal ? (
                <span className="text-[11px] text-muted-foreground">
                  This device
                </span>
              ) : null}
            </div>
          </div>
          {device && status ? (
            <SheetDescription asChild>
              <span
                className={cn(
                  'inline-flex items-center gap-1.5 text-xs font-medium',
                  status.textClass,
                )}
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
            </SheetDescription>
          ) : null}
        </SheetHeader>

        {hasDevice && device ? (
          <div className="flex-1 overflow-y-auto px-6 pb-8">
            <dl className="divide-y divide-border/60">
              <DetailRow label="Status" icon={ActivityIcon}>
                {getStatusVisual(device.status).label}
                {device.isLocal ? (
                  <span className="ml-2 text-muted-foreground">
                    · running this UI
                  </span>
                ) : null}
              </DetailRow>

              <DetailRow
                label="Identity"
                icon={device.identityVerified ? ShieldCheck : ShieldAlert}
                valueLabel={
                  device.identityVerified ? 'Identity verified' : 'Identity not verified'
                }
              >
                <IdentityValue verified={Boolean(device.identityVerified)} />
                {!device.identityVerified ? (
                  <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">
                    The fingerprint below has not been authenticated. Treat
                    this device as untrusted until verification completes.
                  </p>
                ) : null}
              </DetailRow>

              <DetailRow
                label="Public key fingerprint"
                icon={Fingerprint}
                valueLabel={
                  device.publicKeyFingerprint
                    ? 'Public key fingerprint, ' + device.publicKeyFingerprint
                    : 'No fingerprint available'
                }
              >
                {device.publicKeyFingerprint ? (
                  <FingerprintBlock fingerprint={device.publicKeyFingerprint} />
                ) : (
                  <span className="text-xs text-muted-foreground">
                    Not available
                  </span>
                )}
              </DetailRow>

              <DetailRow label="Capabilities">
                {device.capabilities && device.capabilities.length > 0 ? (
                  <ul className="flex flex-wrap gap-1.5">
                    {device.capabilities.map((cap) => (
                      <li key={cap}>
                        <Badge
                          variant="secondary"
                          className="px-2 py-0.5 text-[11px] font-medium"
                        >
                          {humanizeCapability(cap)}
                        </Badge>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-xs text-muted-foreground">None</span>
                )}
              </DetailRow>

              <DetailRow label="Last seen">
                <span className="text-sm text-foreground">
                  {formatDistanceToNow(device.lastSeen, { addSuffix: true })}
                </span>
                <span className="block text-[11px] text-muted-foreground">
                  {format(device.lastSeen, "d MMM yyyy 'at' HH:mm:ss")}
                </span>
              </DetailRow>
            </dl>

            <Separator className="my-4" />

            <p className="text-[11px] leading-relaxed text-muted-foreground">
              This fingerprint is the device&rsquo;s Ed25519 public key. Anyone
              with this fingerprint can verify the device&rsquo;s signature on a
              future message — they cannot use it to impersonate the device.
            </p>
          </div>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

export default DeviceDetailSheet;
