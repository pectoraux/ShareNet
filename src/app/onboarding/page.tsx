'use client';

/**
 * ShareNet — first-run onboarding (/onboarding)
 *
 * A 3-step lightweight first-run experience:
 *
 *   Step 1 — "Welcome to ShareNet"
 *   Step 2 — "How it works"
 *   Step 3 — "You're ready"
 *
 * Design rules (from task spec):
 *   - Extremely lightweight — no protocol terminology, no crypto details,
 *     no giant illustrations.
 *   - Same typography + spacing system as the main app (warm whites, soft
 *     graphite, calm accent). Achieved by wrapping the page in
 *     `.sharenet-shell` so the scoped design tokens apply — even though
 *     there's no AppShell chrome (this is a full-screen flow before the app).
 *   - Framer Motion for subtle step transitions (fade + slight slide),
 *     skipped entirely under `prefers-reduced-motion: reduce`.
 *   - Completion stored in localStorage (`sharenet_onboarded = true`).
 *   - "Get Started" → redirect to `/home`.
 *   - If already onboarded → redirect to `/home` immediately.
 *   - 3-dot progress indicator at the bottom.
 *   - ShareNet logo / connection glyph at the top.
 *   - Centered both axes.
 *
 * Task ID: UI-ONBOARDING-ERRORS
 */

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, Wifi } from 'lucide-react';

import { Button } from '@/components/ui/button';

// ─── Onboarding localStorage contract ────────────────────────────────────

export const ONBOARDED_KEY = 'sharenet_onboarded';
export const ONBOARDED_VALUE = 'true';

function hasOnboarded(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.localStorage.getItem(ONBOARDED_KEY) === ONBOARDED_VALUE;
  } catch {
    // localStorage can throw in private-mode browsers; treat as not onboarded.
    return false;
  }
}

function markOnboarded(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(ONBOARDED_KEY, ONBOARDED_VALUE);
  } catch {
    // Best-effort — if storage fails, we still navigate to /home so the user
    // isn't stuck. They'll see onboarding again next time, which is fine.
  }
}

// ─── Step model ──────────────────────────────────────────────────────────

interface Step {
  /** Short eyebrow / label shown above the headline. */
  eyebrow: string;
  /** The large headline — one short sentence. */
  headline: string;
  /** The supporting copy — one short sentence, plain language only. */
  body: string;
  /** The button label for this step. */
  cta: string;
  /** Whether this is the final step (uses the accent colour). */
  final?: boolean;
}

const STEPS: Step[] = [
  {
    eyebrow: 'Welcome',
    headline: 'Welcome to ShareNet',
    body: 'Use ShareNet when your normal connection is unavailable or unreliable.',
    cta: 'Continue',
  },
  {
    eyebrow: 'How it works',
    headline: 'How it works',
    body: 'Your device can use encrypted paths through other ShareNet participants.',
    cta: 'Continue',
  },
  {
    eyebrow: "You're ready",
    headline: "You're ready",
    body: 'ShareNet can connect automatically when enabled.',
    cta: 'Get Started',
    final: true,
  },
];

// ─── Page ────────────────────────────────────────────────────────────────

export default function OnboardingPage() {
  const router = useRouter();
  const reduceMotion = useReducedMotion();

  const [step, setStep] = React.useState(0);
  const [checked, setChecked] = React.useState(false);

  // If the user has already onboarded, redirect to /home immediately.
  // Done in an effect (not during render) so we don't try to touch
  // localStorage during SSR.
  React.useEffect(() => {
    if (hasOnboarded()) {
      router.replace('/home');
      return;
    }
    setChecked(true);
  }, [router]);

  const handleNext = React.useCallback(() => {
    if (step < STEPS.length - 1) {
      setStep((s) => s + 1);
      return;
    }
    // Final step — mark onboarding complete and leave.
    markOnboarded();
    router.replace('/home');
  }, [step, router]);

  // Until we've checked localStorage, render nothing visible (the page is
  // about to redirect). This avoids a flash of onboarding content for
  // returning users.
  if (!checked) {
    return null;
  }

  const current = STEPS[step];

  return (
    <div
      className="sharenet-shell relative flex min-h-screen flex-col items-center justify-center px-6 py-12"
      // Surface a clear top-level label for screen readers.
      aria-label="ShareNet onboarding"
    >
      {/* ─── Logo / connection glyph ──────────────────────────────────── */}
      <div className="absolute top-10 left-1/2 -translate-x-1/2">
        <span
          aria-hidden
          className="flex size-10 items-center justify-center rounded-xl ring-1 ring-inset"
          style={{
            backgroundColor: 'var(--sn-connected-soft)',
            color: 'var(--sn-connected-text)',
            boxShadow:
              'inset 0 0 0 1px color-mix(in oklch, var(--sn-connected) 22%, transparent)',
          }}
        >
          <Wifi className="size-5" strokeWidth={2} />
        </span>
      </div>

      {/* ─── Step content ────────────────────────────────────────────── */}
      <div className="w-full max-w-md text-center">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={step}
            initial={reduceMotion ? { opacity: 1 } : { opacity: 0, x: 12 }}
            animate={{ opacity: 1, x: 0 }}
            exit={reduceMotion ? { opacity: 1 } : { opacity: 0, x: -12 }}
            transition={
              reduceMotion
                ? { duration: 0 }
                : { duration: 0.32, ease: [0.22, 1, 0.36, 1] }
            }
            className="flex flex-col items-center"
          >
            {/* Eyebrow */}
            <span
              className="mb-4 text-[0.7rem] font-semibold uppercase tracking-[0.16em]"
              style={{ color: 'var(--muted-foreground)' }}
            >
              {current.eyebrow}
            </span>

            {/* Headline */}
            <h1
              className="text-balance text-3xl font-semibold tracking-tight sm:text-4xl"
              style={{ color: 'var(--foreground)' }}
            >
              {current.headline}
            </h1>

            {/* Body */}
            <p
              className="mt-5 text-pretty text-base leading-relaxed sm:text-lg"
              style={{ color: 'var(--muted-foreground)' }}
            >
              {current.body}
            </p>

            {/* CTA */}
            <Button
              type="button"
              onClick={handleNext}
              className="mt-9 h-12 min-w-44 rounded-full px-7 text-base font-medium text-white hover:opacity-90"
              style={{
                backgroundColor: current.final
                  ? 'var(--sn-connected)'
                  : 'var(--primary)',
              }}
              // The final CTA ("Get Started") is the page's primary action —
              // give it the accent colour so it feels like a "completion".
              aria-label={current.cta}
            >
              {current.cta}
              <ArrowRight className="size-4" aria-hidden />
            </Button>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* ─── Progress dots ────────────────────────────────────────────── */}
      <ProgressDots
        count={STEPS.length}
        current={step}
        className="absolute bottom-10 left-1/2 -translate-x-1/2"
      />
    </div>
  );
}

// ─── Progress dots ───────────────────────────────────────────────────────

interface ProgressDotsProps {
  count: number;
  current: number;
  className?: string;
}

function ProgressDots({ count, current, className }: ProgressDotsProps) {
  return (
    <div
      role="group"
      aria-label={`Step ${current + 1} of ${count}`}
      className={className}
    >
      <div className="flex items-center gap-2">
        {Array.from({ length: count }).map((_, i) => {
          const active = i === current;
          return (
            <span
              key={i}
              aria-hidden
              className="rounded-full transition-all duration-300"
              style={{
                width: active ? 24 : 6,
                height: 6,
                backgroundColor: active
                  ? 'var(--sn-connected)'
                  : 'var(--border)',
              }}
            />
          );
        })}
      </div>
    </div>
  );
}
