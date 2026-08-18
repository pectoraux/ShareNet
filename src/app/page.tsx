import { redirect } from 'next/navigation'

/**
 * ShareNet — root route
 *
 * The engineering conformance dashboard that previously lived here has been
 * moved to /diagnostics (see src/app/diagnostics/page.tsx) so that this root
 * route is free to host the consumer-facing ShareNet experience.
 *
 * Another subagent owns building the real consumer Home at /home. Until that
 * lands, the root route simply redirects to /home so the route map stays
 * consistent.
 *
 * Task ID: UI-DIAGNOSTICS
 * Agent: general-purpose
 */
export default function RootPage() {
  redirect('/home')
}
