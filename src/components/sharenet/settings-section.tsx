'use client';

/**
 * ShareNet 2.0 — Settings Section
 *
 * Native-looking grouped settings, modelled on the iOS / macOS Settings app:
 *
 *   ┌────────────────────────────────────────┐
 *   │ Network                                │  ← section header (title + desc)
 *   │ ┌──────────────────────────────────┐   │
 *   │ │ [icon] Connect automatically  [⬤] │   │  ← SettingsRow w/ Switch
 *   │ │ ─────────────────────────────── │   │
 *   │ │ [icon] Prefer reliable paths  [⬤] │   │
 *   │ │ ─────────────────────────────── │   │
 *   │ │ [icon] Allow relaying          [⬤] │   │
 *   │ └──────────────────────────────────┘   │
 *   └────────────────────────────────────────┘
 *
 * Each `SettingsSection` is a labelled Card with rows separated by
 * `Separator`s. Rows take a label + optional description + an arbitrary
 * control on the right (Switch, segmented control, link, etc.).
 *
 * Accessibility:
 *   - The section title is a real `<h3>` (heading level 3 — under the
 *     page `<h1>`).
 *   - Rows are `<div role="group">` so screen readers announce them as a
 *     semantic group of controls.
 *   - Interactive controls (Switch, Link) inside the row are tabbable
 *     themselves; the row itself is not a tab-stop so you don't get two
 *     stops for the same action.
 *
 * Task ID: UI-DEVICES-SETTINGS
 */

import * as React from 'react';
import Link from 'next/link';
import { ChevronRight } from 'lucide-react';

import { cn } from '@/lib/utils';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';

// ─── Section ───────────────────────────────────────────────────────────────

export interface SettingsSectionProps {
  title: string;
  description?: string;
  /** Optional element rendered to the right of the title (count, badge). */
  titleAdornment?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export function SettingsSection({
  title,
  description,
  titleAdornment,
  children,
  className,
}: SettingsSectionProps) {
  return (
    <section className={cn('flex flex-col gap-2.5', className)}>
      <header className="flex items-baseline justify-between gap-3 px-1">
        <div className="flex flex-col gap-0.5">
          <h3 className="text-[13px] font-semibold tracking-wide text-foreground uppercase">
            {title}
          </h3>
          {description ? (
            <p className="text-xs text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {titleAdornment}
      </header>

      <Card className="gap-0 p-0 shadow-none overflow-hidden">
        <CardHeader className="sr-only">
          <CardTitle>{title}</CardTitle>
          {description ? <CardDescription>{description}</CardDescription> : null}
        </CardHeader>
        <CardContent className="p-0">
          {/*
            We render rows as direct children. The caller MUST wrap each row
            in <SettingsRow> (or <SettingsLinkRow>), which handles the
            in-between separators via :not(:last-child) styling.
          */}
          <div className="flex flex-col">{children}</div>
        </CardContent>
      </Card>
    </section>
  );
}

// ─── Row ────────────────────────────────────────────────────────────────────

export interface SettingsRowProps {
  /** Leading icon. Rendered inside a soft rounded tile. */
  icon?: React.ComponentType<{ className?: string }>;
  /** Optional accent class for the icon tile background. */
  iconAccentClassName?: string;
  label: string;
  description?: string;
  /** Right-side control: a <Switch>, segmented control, etc. */
  children?: React.ReactNode;
  className?: string;
}

export function SettingsRow({
  icon: Icon,
  iconAccentClassName,
  label,
  description,
  children,
  className,
}: SettingsRowProps) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn(
        'flex items-center gap-3 px-4 py-3',
        // Subtle separator between rows — only between, not after the last.
        '[&:not(:last-child)]:border-b [&:not(:last-child)]:border-border/50',
        className,
      )}
    >
      {Icon ? (
        <span
          aria-hidden="true"
          className={cn(
            'flex size-7 shrink-0 items-center justify-center rounded-md',
            'bg-muted/70 text-foreground/70',
            iconAccentClassName,
          )}
        >
          <Icon className="size-3.5" />
        </span>
      ) : null}

      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className="text-sm font-medium text-foreground">{label}</span>
        {description ? (
          <span className="text-xs text-muted-foreground">{description}</span>
        ) : null}
      </div>

      {children ? (
        <div className="flex shrink-0 items-center gap-2">{children}</div>
      ) : null}
    </div>
  );
}

// ─── Switch row (common case, kept ergonomic) ──────────────────────────────

export interface SettingsSwitchRowProps
  extends Omit<SettingsRowProps, 'children'> {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  /** Accessible label override; defaults to the row label. */
  ariaLabel?: string;
}

export function SettingsSwitchRow({
  checked,
  onCheckedChange,
  disabled,
  ariaLabel,
  ...rowProps
}: SettingsSwitchRowProps) {
  return (
    <SettingsRow {...rowProps}>
      <Switch
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-label={ariaLabel ?? rowProps.label}
      />
    </SettingsRow>
  );
}

// ─── Link row ───────────────────────────────────────────────────────────────

export interface SettingsLinkRowProps
  extends Omit<SettingsRowProps, 'children'> {
  href: string;
  /** Optional right-side meta text shown before the chevron. */
  meta?: React.ReactNode;
  /** External link? Adds target/rel. */
  external?: boolean;
}

export function SettingsLinkRow({
  href,
  meta,
  external,
  ...rowProps
}: SettingsLinkRowProps) {
  return (
    <SettingsRow {...rowProps}>
      {meta ? (
        <span className="text-xs text-muted-foreground">{meta}</span>
      ) : null}
      <Link
        href={href}
        className={cn(
          'flex items-center gap-1 rounded-md text-muted-foreground transition-colors',
          'hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60',
        )}
        aria-label={`Open ${rowProps.label}`}
        {...(external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
      >
        <ChevronRight className="size-4" aria-hidden="true" />
        <span className="sr-only">Open</span>
      </Link>
    </SettingsRow>
  );
}

export { Separator };
export default SettingsSection;
