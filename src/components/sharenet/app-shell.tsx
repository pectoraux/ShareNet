'use client';

/**
 * AppShell — the chrome that wraps every ShareNet consumer page.
 *
 * Desktop (≥ md):
 *
 *     ┌──────────────────────────────────────────────┐
 *     │ ╭──────╮                                       │
 *     │ │ logo │  Home                                 │
 *     │ │      │  Network                              │
 *     │ │ nav  │  Activity                             │
 *     │ │      │  Devices                              │
 *     │ │      │  Settings                             │
 *     │ │      │                                       │
 *     │ │ ●  Connected ← status at bottom              │
 *     │ ╰──────╯                                       │
 *     └──────────────────────────────────────────────┘
 *
 * Mobile (< md):
 *
 *     ┌──────────────────────────────┐
 *     │ ▣ ShareNet          ● Connected │  ← compact header
 *     ├──────────────────────────────┤
 *     │                                │
 *     │          page content          │
 *     │                                │
 *     ├──────────────────────────────┤
 *     │  Home  Net  Act  Dev  Set     │  ← bottom nav (44px+ targets)
 *     └──────────────────────────────┘
 *
 * Active nav state is computed via `usePathname()`. The active item gets a
 * sliding pill background animated by Framer Motion's `layoutId` (skipped
 * entirely when `prefers-reduced-motion: reduce`).
 *
 * The shell wraps its content in a `.sharenet-shell` div, which scopes the
 * warm-light design tokens defined in `globals.css`. The engineering
 * `/diagnostics` route is NOT inside this shell, so it keeps the default
 * dark theme.
 *
 * Backward-compat: the placeholder `AppShell` exported `nav` and `className`
 * props. The real shell accepts the same `className` prop (applied to the
 * inner content wrapper) and silently ignores `nav` (the connection status
 * is now built into the shell itself). Downstream pages using
 * `<AppShell>{children}</AppShell>` require no edits.
 *
 * Task ID: UI-SHELL-HOME
 */

import * as React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, useReducedMotion } from 'framer-motion';
import {
  Activity,
  Home as HomeIcon,
  Network,
  Settings,
  Smartphone,
  Wifi,
  type LucideIcon,
} from 'lucide-react';

import { cn } from '@/lib/utils';
import {
  IS_MOCK,
  MOCK_LABEL,
  getConnectionSummary,
  type ConnectionState,
} from '@/lib/sharenet';
import { ConnectionStateIndicator } from './connection-state-indicator';

// ─── Nav model ─────────────────────────────────────────────────────────────

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Short label used in the mobile bottom nav (kept to ≤ 5 chars). */
  shortLabel: string;
}

const NAV_ITEMS: NavItem[] = [
  { href: '/home', label: 'Home', icon: HomeIcon, shortLabel: 'Home' },
  { href: '/network', label: 'Network', icon: Network, shortLabel: 'Net' },
  { href: '/activity', label: 'Activity', icon: Activity, shortLabel: 'Activity' },
  { href: '/devices', label: 'Devices', icon: Smartphone, shortLabel: 'Devices' },
  { href: '/settings', label: 'Settings', icon: Settings, shortLabel: 'Set' },
];

function isActive(pathname: string | null, href: string): boolean {
  if (!pathname) return false;
  if (href === '/home') {
    return pathname === '/home' || pathname === '/';
  }
  return pathname === href || pathname.startsWith(href + '/');
}

// ─── Connection state hook ────────────────────────────────────────────────
//
// Fetches the connection state on mount and listens for the
// `sharenet:state-change` custom event so the sidebar indicator updates the
// instant any consumer page calls connect()/disconnect() on the adapter.

const STATE_CHANGE_EVENT = 'sharenet:state-change';

function useConnectionState(): ConnectionState | 'loading' {
  const [state, setState] = React.useState<ConnectionState | 'loading'>('loading');

  React.useEffect(() => {
    let active = true;

    const fetchState = () => {
      getConnectionSummary()
        .then((s) => {
          if (active) setState(s.state);
        })
        .catch(() => {
          if (active) setState('offline');
        });
    };

    fetchState();

    const onChange = () => fetchState();
    window.addEventListener(STATE_CHANGE_EVENT, onChange);
    return () => {
      active = false;
      window.removeEventListener(STATE_CHANGE_EVENT, onChange);
    };
  }, []);

  return state;
}

/** Dispatch the global state-change event so the AppShell can refetch. */
export function dispatchConnectionStateChange(): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent(STATE_CHANGE_EVENT));
}

// ─── Logo ──────────────────────────────────────────────────────────────────

function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <Link
      href="/home"
      className="inline-flex items-center gap-2.5 font-semibold tracking-tight transition-opacity hover:opacity-80"
      aria-label="ShareNet home"
    >
      <span
        aria-hidden
        className="flex size-8 items-center justify-center rounded-lg"
        style={{
          backgroundColor: 'var(--primary)',
          color: 'var(--primary-foreground)',
        }}
      >
        <Wifi className="size-4" strokeWidth={2} />
      </span>
      {!compact && (
        <span className="text-base" style={{ color: 'var(--foreground)' }}>
          ShareNet
        </span>
      )}
    </Link>
  );
}

// ─── Desktop sidebar ──────────────────────────────────────────────────────

function DesktopSidebar({ state }: { state: ConnectionState | 'loading' }) {
  const pathname = usePathname();
  const reduceMotion = useReducedMotion();

  return (
    <aside
      className="hidden md:flex md:fixed md:inset-y-0 md:left-0 md:w-64 md:flex-col md:shrink-0 z-30"
      aria-label="Primary navigation"
      style={{
        backgroundColor: 'var(--sidebar)',
        borderRight: '1px solid var(--sidebar-border)',
      }}
    >
      {/* Logo */}
      <div className="flex h-16 items-center px-6">
        <Logo />
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-6" aria-label="Primary">
        <ul className="space-y-1">
          {NAV_ITEMS.map((item) => {
            const active = isActive(pathname, item.href);
            const Icon = item.icon;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={active ? 'page' : undefined}
                  className={cn(
                    'relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--ring)]',
                    !active && 'hover:bg-[color:var(--sidebar-accent)]/60',
                  )}
                  style={{
                    color: active
                      ? 'var(--sidebar-accent-foreground)'
                      : 'var(--muted-foreground)',
                  }}
                >
                  {/* Active pill — slides between items via layoutId */}
                  {active && (
                    <motion.div
                      layoutId={reduceMotion ? undefined : 'desktop-active-pill'}
                      className="absolute inset-0 rounded-lg"
                      style={{
                        backgroundColor: 'var(--sidebar-accent)',
                      }}
                      transition={
                        reduceMotion
                          ? { duration: 0 }
                          : { type: 'spring', stiffness: 380, damping: 32 }
                      }
                    />
                  )}
                  <Icon
                    className="relative z-10 size-4 shrink-0"
                    strokeWidth={active ? 2.25 : 1.75}
                    aria-hidden
                  />
                  <span className="relative z-10">{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Connection status at bottom */}
      <div
        className="px-4 py-5"
        style={{ borderTop: '1px solid var(--sidebar-border)' }}
      >
        <div
          className="rounded-lg px-3 py-3"
          style={{ backgroundColor: 'var(--muted)' }}
        >
          <div
            className="text-[0.65rem] font-semibold uppercase tracking-[0.14em]"
            style={{ color: 'var(--muted-foreground)' }}
          >
            Connection
          </div>
          <div className="mt-1.5">
            {state === 'loading' ? (
              <span
                className="inline-block h-4 w-24 animate-pulse rounded"
                style={{ backgroundColor: 'var(--muted-foreground)', opacity: 0.4 }}
                aria-label="Loading connection state"
              />
            ) : (
              <ConnectionStateIndicator state={state} size="md" />
            )}
          </div>
        </div>

        {IS_MOCK && (
          <div
            className="mt-3 px-1 text-[0.7rem] leading-relaxed"
            style={{ color: 'var(--muted-foreground)' }}
            aria-label={MOCK_LABEL}
          >
            {MOCK_LABEL}
          </div>
        )}
      </div>
    </aside>
  );
}

// ─── Mobile header ────────────────────────────────────────────────────────

function MobileHeader({ state }: { state: ConnectionState | 'loading' }) {
  return (
    <header
      className="md:hidden sticky top-0 z-30 flex h-14 items-center justify-between px-4"
      style={{
        backgroundColor: 'var(--background)',
        borderBottom: '1px solid var(--border)',
      }}
      aria-label="Primary"
    >
      <Logo compact={false} />
      <div className="flex items-center gap-2">
        {state === 'loading' ? (
          <span
            className="inline-block h-4 w-20 animate-pulse rounded"
            style={{ backgroundColor: 'var(--muted-foreground)', opacity: 0.4 }}
            aria-label="Loading connection state"
          />
        ) : (
          <ConnectionStateIndicator state={state} size="sm" />
        )}
      </div>
    </header>
  );
}

// ─── Mobile bottom nav ────────────────────────────────────────────────────

function MobileBottomNav() {
  const pathname = usePathname();
  const reduceMotion = useReducedMotion();

  return (
    <nav
      className="md:hidden fixed bottom-0 left-0 right-0 z-30"
      style={{
        backgroundColor: 'var(--background)',
        borderTop: '1px solid var(--border)',
        paddingBottom: 'env(safe-area-inset-bottom, 0px)',
      }}
      aria-label="Primary navigation"
    >
      <ul className="grid grid-cols-5">
        {NAV_ITEMS.map((item) => {
          const active = isActive(pathname, item.href);
          const Icon = item.icon;
          return (
            <li key={item.href} className="contents">
              <Link
                href={item.href}
                aria-current={active ? 'page' : undefined}
                aria-label={item.label}
                className={cn(
                  'relative flex min-h-[56px] flex-col items-center justify-center gap-0.5 py-2 text-[0.65rem] font-medium transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--ring)]',
                )}
                style={{
                  color: active
                    ? 'var(--sidebar-accent-foreground)'
                    : 'var(--muted-foreground)',
                }}
              >
                {/* Active pill — slides between items via layoutId */}
                {active && (
                  <motion.span
                    layoutId={reduceMotion ? undefined : 'mobile-active-pill'}
                    className="absolute top-1 left-1/2 h-1 w-8 -translate-x-1/2 rounded-full"
                    style={{ backgroundColor: 'var(--sn-connected)' }}
                    transition={
                      reduceMotion
                        ? { duration: 0 }
                        : { type: 'spring', stiffness: 420, damping: 32 }
                    }
                    aria-hidden
                  />
                )}
                <Icon
                  className="relative z-10 size-5"
                  strokeWidth={active ? 2.25 : 1.75}
                  aria-hidden
                />
                <span className="relative z-10">{item.shortLabel}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

// ─── AppShell ──────────────────────────────────────────────────────────────

export interface AppShellProps {
  children: React.ReactNode;
  /**
   * Optional element rendered above the main content area (kept for
   * backward-compat with the placeholder AppShell; the real shell ignores it
   * since the connection control is built into the sidebar footer).
   */
  nav?: React.ReactNode;
  /** Additional className applied to the inner content wrapper. */
  className?: string;
}

export function AppShell({ children, nav, className }: AppShellProps) {
  const state = useConnectionState();

  return (
    <div className="sharenet-shell min-h-screen">
      <DesktopSidebar state={state} />
      <MobileHeader state={state} />

      {/* Main content area — padded left on desktop to clear the sidebar,
          padded bottom on mobile to clear the bottom nav. */}
      <main
        className="md:pl-64 pb-24 md:pb-0"
        style={{ backgroundColor: 'var(--background)' }}
      >
        <div className={cn('mx-auto w-full max-w-5xl px-5 py-10 sm:px-8 md:py-16', className)}>
          {nav}
          {children}
        </div>
      </main>

      <MobileBottomNav />
    </div>
  );
}

export default AppShell;
