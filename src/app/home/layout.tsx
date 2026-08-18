import type { Metadata } from 'next';

/**
 * Home route layout — wraps the Home page (and any future sub-routes under
 * /home/*) in the ShareNet AppShell.
 *
 * This is the layout pattern future consumer routes (Network, Activity,
 * Devices, Settings) should follow: each top-level consumer route has its
 * own `layout.tsx` that wraps its content in `<AppShell>`. The shell provides
 * the sidebar + mobile header + bottom nav; the page provides its own
 * content. If you'd rather share one shell across all consumer pages,
 * promote this layout to a route group at `src/app/(consumer)/layout.tsx`.
 *
 * Task ID: UI-SHELL-HOME
 */

import { AppShell } from '@/components/sharenet/app-shell';

export const metadata: Metadata = {
  title: 'Home · ShareNet',
  description:
    'Your ShareNet connection. See your current state, the path your traffic takes, and your privacy posture at a glance.',
};

export default function HomeLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppShell>{children}</AppShell>;
}
