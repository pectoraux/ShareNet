'use client';

/**
 * ShareNet 2.0 — About page (/settings/about)
 *
 * A clean, centered surface that surfaces the minimum identifying
 * information a user might need: the product name + tagline, the version,
 * the on-the-wire protocol identifier, and a single forward link to the
 * engineering diagnostics surface. Legal / technical references
 * (Specification, Security policy, Architecture) are demoted to a
 * secondary group at the bottom — present, but never the visual focus.
 *
 * Marked `'use client'` so we can pass lucide icon components (e.g.
 * `FlaskConical`) as props to the client-side `SettingsLinkRow`. Component
 * references are not serialisable across the RSC boundary, so the page
 * itself must live on the client side.
 *
 * Task ID: UI-SETTINGS-DETAIL
 */

import * as React from 'react';
import Link from 'next/link';
import {
  ArrowLeft,
  BookOpen,
  FlaskConical,
  Globe,
  ShieldCheck,
  Wifi,
} from 'lucide-react';

import { AppShell } from '@/components/sharenet/app-shell';
import {
  SettingsSection,
  SettingsRow,
  SettingsLinkRow,
} from '@/components/sharenet/settings-section';

const SHARENET_VERSION = '0.1 prototype';
const SHARENET_PROTOCOL = 'SNP/0.1';

export default function AboutPage() {
  return (
    <AppShell>
      <div className="mx-auto flex w-full max-w-md flex-col gap-8">
        {/* ─── Header ─────────────────────────────────────────────────── */}
        <Link
          href="/settings"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 rounded-md w-fit"
        >
          <ArrowLeft className="size-3.5" aria-hidden="true" />
          Back to settings
        </Link>

        {/* ─── Hero ───────────────────────────────────────────────────── */}
        <header className="flex flex-col items-center gap-4 pt-2 text-center">
          <span
            aria-hidden="true"
            className="flex size-14 items-center justify-center rounded-2xl bg-muted/60 text-foreground/70"
          >
            <Wifi className="size-7" />
          </span>
          <div className="flex flex-col gap-2">
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">
              ShareNet
            </h1>
            <p className="text-sm leading-relaxed text-muted-foreground">
              Decentralized connectivity,
              <br />
              designed to keep you connected.
            </p>
          </div>
        </header>

        {/* ─── Build ──────────────────────────────────────────────────── */}
        <SettingsSection title="Build">
          <SettingsRow label="Version">
            <span className="text-xs font-mono tabular-nums text-muted-foreground">
              {SHARENET_VERSION}
            </span>
          </SettingsRow>
          <SettingsRow label="Protocol">
            <span className="text-xs font-mono tabular-nums text-muted-foreground">
              {SHARENET_PROTOCOL}
            </span>
          </SettingsRow>
        </SettingsSection>

        {/* ─── Engineering ────────────────────────────────────────────── */}
        <SettingsSection title="Engineering">
          <SettingsLinkRow
            icon={FlaskConical}
            label="Diagnostics"
            description="Conformance suites, integration tests, mesh simulator."
            href="/diagnostics"
          />
        </SettingsSection>

        {/* ─── Resources (secondary) ─────────────────────────────────── */}
        <SettingsSection
          title="Resources"
          description="Technical references, kept secondary."
        >
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

        {/* ─── Footer ─────────────────────────────────────────────────── */}
        <footer className="pt-2 text-center text-[0.7rem] leading-relaxed text-muted-foreground/70">
          © {new Date().getFullYear()} ShareNet · Prototype build
        </footer>
      </div>
    </AppShell>
  );
}
