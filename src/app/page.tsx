'use client';

/**
 * ShareNet — root route (/)
 *
 * First-run gatekeeper: decides whether the user lands on the onboarding
 * flow or straight on Home.
 *
 *   - If the user has completed onboarding (localStorage flag
 *     `sharenet_onboarded = "true"`), redirect to `/home`.
 *   - Otherwise, redirect to `/onboarding`.
 *
 * The check is done client-side in a `useEffect` (NOT during render) because
 * `localStorage` is browser-only — and the redirect itself uses Next.js's
 * client router (`router.replace`) so there's no extra round-trip. While the
 * check is in flight we render an essentially blank page so there's no flash
 * of onboarding or home content.
 *
 * The engineering conformance dashboard that previously lived here has been
 * moved to `/diagnostics` (see `src/app/diagnostics/page.tsx`).
 *
 * Task ID: UI-ONBOARDING-ERRORS
 * Agent: frontend-styling-expert
 */

import * as React from 'react';
import { useRouter } from 'next/navigation';

// ─── Onboarding localStorage contract ────────────────────────────────────
//
// Mirrored (intentionally, not re-exported) from `src/app/onboarding/page.tsx`
// so this root route doesn't have to import a page module just for two
// string constants. Keep them in sync if you rename the flag.

const ONBOARDED_KEY = 'sharenet_onboarded';
const ONBOARDED_VALUE = 'true';

export default function RootPage() {
  const router = useRouter();

  React.useEffect(() => {
    let onboarded = false;
    try {
      onboarded =
        window.localStorage.getItem(ONBOARDED_KEY) === ONBOARDED_VALUE;
    } catch {
      // localStorage may throw in private-mode / disabled-storage contexts.
      // Treat as not-onboarded so the user at least sees onboarding once.
      onboarded = false;
    }
    router.replace(onboarded ? '/home' : '/onboarding');
  }, [router]);

  // Render nothing visible — the router is about to navigate away. We avoid
  // any skeleton here because the destination route will paint its own
  // loading state and we don't want a layout flash between this blank page
  // and that one.
  return null;
}
