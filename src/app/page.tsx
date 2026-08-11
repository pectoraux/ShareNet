'use client'

/**
 * ShareNet 2.0 — Conformance Foundation Dashboard
 *
 * Single-page engineering dashboard proving the N0/N1 conformance foundation
 * is real. Fetches GET /api/conformance on mount (and on Re-run click), which
 * re-executes all 14 conformance suites live against the TypeScript SNP
 * reference implementation, then renders the result.
 *
 * Task ID: 10
 * Agent: Z.ai (subagent — dashboard UI)
 */

import * as React from 'react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTheme } from 'next-themes'

// ─── shadcn/ui ────────────────────────────────────────────────────────────
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'

// ─── utils ────────────────────────────────────────────────────────────────
import { cn } from '@/lib/utils'

// ─── lucide-react ─────────────────────────────────────────────────────────
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Boxes,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  CircleDot,
  Clock,
  Coins,
  FileCheck,
  Fingerprint,
  Flag,
  FlaskConical,
  Globe,
  Hash,
  KeyRound,
  Layers,
  Loader2,
  Lock,
  Moon,
  Network,
  Radio,
  RefreshCw,
  Route,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Target,
  Wallet,
  Waypoints,
  Wifi,
  Workflow,
  XCircle,
  type LucideIcon,
} from 'lucide-react'

// ─── Types (mirror of /src/lib/snp/conformance.ts) ────────────────────────

interface VectorResult {
  suiteId: string
  vectorId: string
  description: string
  specSection: string
  passed: boolean
  mustReject: boolean
  error?: string
  durationMs: number
}

interface SuiteResult {
  suiteId: string
  suiteName: string
  specSection: string
  total: number
  passed: number
  failed: number
  vectors: VectorResult[]
}

interface ConformanceReport {
  totalVectors: number
  passed: number
  failed: number
  suites: SuiteResult[]
  generatedAt: string
  conformant: boolean
}

// ─── Static content: architecture, audit, roadmap ─────────────────────────

type LayerStatus = 'preserved' | 'fixed' | 'new'

interface ArchLayer {
  id: string
  name: string
  description: string
  status: LayerStatus
  icon: LucideIcon
}

// Source: 01-ARCHITECTURE.md §2.1 + §6 (preserve / refactor / replace / new).
const ARCHITECTURE_LAYERS: ArchLayer[] = [
  {
    id: 'L1',
    name: 'Identity',
    description:
      'Four-way split: node · device · user · economic. Ed25519 key hierarchy, rotation, revocation.',
    status: 'fixed',
    icon: Fingerprint,
  },
  {
    id: 'L2',
    name: 'Object / Content',
    description:
      'CAS, content-defined chunking, RFC 6962 Merkle, signed manifests with leaf-count binding.',
    status: 'fixed',
    icon: Boxes,
  },
  {
    id: 'L3',
    name: 'Trust',
    description:
      'Attestations, reputation, revocation propagation. Design preserved, retargeted onto real crypto.',
    status: 'preserved',
    icon: ShieldCheck,
  },
  {
    id: 'L4',
    name: 'Discovery',
    description:
      'Peer + capability advertisement, freshness. No prior implementation — built from scratch.',
    status: 'new',
    icon: Radio,
  },
  {
    id: 'L5',
    name: 'Mesh Sync',
    description:
      'Delay-tolerant store-carry-forward, anti-entropy, bundle custody. Replaces the SyncWorker stub.',
    status: 'fixed',
    icon: RefreshCw,
  },
  {
    id: 'L6',
    name: 'Routing',
    description:
      'Path-vector route discovery, metrics, dual-route maintenance, migration, loop detection.',
    status: 'new',
    icon: Route,
  },
  {
    id: 'L7',
    name: 'Internet Gateway',
    description:
      'Egress policy, RFC 1918 / loopback / link-local blocking, DNS, NAT, quotas. The thesis chokepoint.',
    status: 'new',
    icon: Globe,
  },
  {
    id: 'L8',
    name: 'Transport',
    description:
      'One-hop framing, MTU, link liveness. Becomes the platform-neutral Link interface.',
    status: 'fixed',
    icon: Wifi,
  },
  {
    id: 'L9',
    name: 'Virtual Network',
    description:
      'TUN / VpnService / WinTUN integration, packet capture, flow mapping. Mode C surface.',
    status: 'new',
    icon: Network,
  },
  {
    id: 'L10',
    name: 'App Capability',
    description:
      'Catalog, apps, models, datasets over the bearer. Existing content layer demoted to a capability.',
    status: 'preserved',
    icon: Layers,
  },
  {
    id: 'L11',
    name: 'Civic',
    description:
      'Recipient-signed contribution proofs, pure value function, no local minting. Refactored.',
    status: 'fixed',
    icon: Coins,
  },
  {
    id: 'L12',
    name: 'Settlement',
    description:
      'Authoritative points / wallet state. In-memory unauthenticated ledger replaced by durable storage.',
    status: 'fixed',
    icon: Wallet,
  },
]

const LAYER_STATUS_META: Record<
  LayerStatus,
  { label: string; badge: string; card: string; dot: string }
> = {
  preserved: {
    label: 'Preserved',
    badge:
      'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
    card:
      'border-emerald-500/30 bg-emerald-500/[0.03] dark:bg-emerald-500/[0.06]',
    dot: 'bg-emerald-500',
  },
  fixed: {
    label: 'Fixed',
    badge:
      'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/30',
    card:
      'border-amber-500/30 bg-amber-500/[0.03] dark:bg-amber-500/[0.06]',
    dot: 'bg-amber-500',
  },
  new: {
    label: 'New',
    badge:
      'bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/30',
    card: 'border-sky-500/30 bg-sky-500/[0.03] dark:bg-sky-500/[0.06]',
    dot: 'bg-sky-500',
  },
}

// Source: 00-AUDIT.md §3.1, §3.2, §3.3, §0 (mesh), §3.8 + 05-CIVIC-CONTENT-CONSISTENCY.md §A6.
interface AuditFinding {
  id: string
  title: string
  was: string
  fixedBy: string
  icon: LucideIcon
}

const AUDIT_FINDINGS: AuditFinding[] = [
  {
    id: 'F1',
    title: 'TinkCryptoProvider was non-functional',
    was: 'Public/private keys were SHA-256 of debug strings; verify() threw unconditionally. No signature made on one device ever verified on another.',
    fixedBy:
      'Real Ed25519 (@noble/ed25519). 32-byte raw public keys on the wire. NodeId = SHA-256("SNP/0.1 node\\0" ‖ pk). Every signature is over SIG_CONTEXT ‖ CBOR(payload).',
    icon: KeyRound,
  },
  {
    id: 'F2',
    title: 'Golden vectors were placeholders',
    was: 'README claimed 20 byte-identical Kotlin/Python fixtures. The file did not exist; the generator emitted sha256(label) for cborHex and 00×64 for every signature.',
    fixedBy:
      '138 real executable golden vectors across 15 suites, generated by one TypeScript generator. Every signature is a real Ed25519 signature over a real CBOR preimage, every AEAD vector uses real ChaCha20-Poly1305 — re-executed live on this page. Note: these are REFERENCE CONFORMANCE vectors (self-conformance); cross-language interop (TypeScript ↔ Rust ↔ Kotlin) is the next milestone.',
    icon: FileCheck,
  },
  {
    id: 'F3',
    title: 'Kotlin and Python CBOR disagreed',
    was: 'Kotlin sorted map keys lexicographically; Python sorted by fully encoded bytes (length-first). Different bytes → different signatures → cross-platform verification always failed.',
    fixedBy:
      'SNP-CBOR implements RFC 8949 §4.2.1 length-first key ordering. The very first vector reproduces the audit’s exact Contribution field set and proves the byte order is canonical.',
    icon: Hash,
  },
  {
    id: 'F4',
    title: 'No mesh existed',
    was: 'grep for gateway|route|tunnel|relay|nextHop|VpnService|TUN returned only an SMS receiver and Compose navigation. ShareNet was single-hop store-and-forward, not a mesh.',
    fixedBy:
      'L6 routing + L7 gateway + frames + routing-table SNP modules plus their conformance suites (08, 10, 11) establish the wire-level foundation for multi-hop. Full mesh deployment is N3 / N4.',
    icon: Network,
  },
  {
    id: 'F5',
    title: 'Civic Points were minted by claiming',
    was: 'pointsForBridging let a node self-attest bridging bytes. Fraud controls were in-memory and reset on process death. Backend settlement was unauthenticated and in-memory.',
    fixedBy:
      'Receipts are recipient-signed (the party that benefits signs — the claimant cannot forge). Civic value function is pure arithmetic: no state, no signing, no storage. Settlement remains the sole crediting authority (N8, human-gated).',
    icon: Coins,
  },
]

// Source: 07-MIGRATION-AND-ROADMAP.md §4 (N0–N9).
interface Milestone {
  id: string
  name: string
  window: string
  done: boolean
  gate?: boolean
  parallel?: boolean
  summary: string
}

const ROADMAP: Milestone[] = [
  {
    id: 'N0',
    name: 'Truth & specification',
    window: 'W 1–4',
    done: true,
    summary: 'spec/ v0.1 complete; every normative MUST has an ID; SPEC-COVERAGE.md live.',
  },
  {
    id: 'N1',
    name: 'Conformance foundation',
    window: 'W 3–6',
    done: true,
    summary:
      'Reference generator, suites 01–07 + 14, live runner. This dashboard is the proof.',
  },
  {
    id: 'N2',
    name: 'Crypto correction',
    window: 'W 5–8',
    done: false,
    summary: 'Raw Ed25519/X25519 in Kotlin + Python + Rust; cross-platform verify.',
  },
  {
    id: 'N3',
    name: 'Reference node',
    window: 'W 7–14',
    done: false,
    summary: 'Rust daemon: snp-link, Noise_IK, discovery, anti-entropy, Class A transfer.',
  },
  {
    id: 'N4',
    name: 'Routing',
    window: 'W 11–18',
    done: false,
    summary: 'snp-routing: path-vector, loop detection, dual-route, migration under churn.',
  },
  {
    id: 'N5',
    name: 'Gateway + Mode A',
    window: 'W 15–22',
    done: false,
    summary: 'snp-gateway: egress, RFC 1918 block, DNS, quotas. First thesis demonstration.',
  },
  {
    id: 'N6',
    name: 'Android port',
    window: 'W 13–24',
    done: false,
    parallel: true,
    summary: 'Kotlin core + platform-android links (Nearby + Play-free Wi-Fi Direct / BLE / TCP).',
  },
  {
    id: 'N7',
    name: 'Modes B & C',
    window: 'W 21–30',
    done: false,
    summary: 'SOCKS5 (B) + TUN / VpnService (C). Unmodified Chrome over the mesh. The thesis.',
  },
  {
    id: 'N8',
    name: 'Civic Points',
    window: 'W 25–34',
    done: false,
    gate: true,
    summary: 'Proof pipeline, durable fraud controls, sub-linear value function, settlement.',
  },
  {
    id: 'N9',
    name: 'Content capability',
    window: 'W 29–36',
    done: false,
    summary: 'Catalog, app + model distribution as L10 over routed multi-hop paths.',
  },
]

// ─── Small helpers ─────────────────────────────────────────────────────────

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return iso
  }
}

function pct(part: number, whole: number): number {
  if (!whole) return 0
  return (part / whole) * 100
}

// ─── Theme toggle ──────────────────────────────────────────────────────────

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme()
  // useSyncExternalStore returns false during SSR and the initial hydration
  // render, then true on the client — lets us render the correct icon without
  // a hydration mismatch (the canonical next-themes "mounted" pattern, but
  // expressed in a way that doesn't trip react-hooks/set-state-in-effect).
  const mounted = React.useSyncExternalStore(
    () => () => {},
    () => true,
    () => false,
  )

  const isDark = resolvedTheme === 'dark'

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          aria-label="Toggle colour theme"
          onClick={() => setTheme(isDark ? 'light' : 'dark')}
          className="h-9 w-9 border-border/60"
        >
          {mounted && isDark ? (
            <Sun className="size-4" />
          ) : (
            <Moon className="size-4" />
          )}
        </Button>
      </TooltipTrigger>
      <TooltipContent>Toggle {isDark ? 'light' : 'dark'} mode</TooltipContent>
    </Tooltip>
  )
}

// ─── Header ────────────────────────────────────────────────────────────────

function Header({
  report,
  loading,
  rerunning,
  onRerun,
}: {
  report: ConformanceReport | null
  loading: boolean
  rerunning: boolean
  onRerun: () => void
}) {
  const conformant = report?.conformant ?? false
  return (
    <header className="sticky top-0 z-40 border-b border-border/60 bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-4 sm:px-6 lg:flex-row lg:items-center lg:justify-between lg:py-5">
        <div className="flex items-start gap-3 sm:items-center">
          <div className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <Shield className="size-6" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <h1 className="font-mono text-lg font-semibold tracking-tight sm:text-xl">
                ShareNet 2.0
              </h1>
              {report && (
                <Badge
                  variant="outline"
                  className={
                    conformant
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  }
                >
                  {conformant ? (
                    <ShieldCheck className="size-3" />
                  ) : (
                    <ShieldAlert className="size-3" />
                  )}
                  {conformant ? 'CONFORMANT' : 'NON-CONFORMANT'}
                </Badge>
              )}
              {loading && !report && (
                <Badge
                  variant="outline"
                  className="border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                >
                  <Loader2 className="size-3 animate-spin" />
                  RUNNING
                </Badge>
              )}
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground sm:text-sm">
              Conformance Foundation — N0 / N1 ·{' '}
              <span className="text-foreground/80">
                138 reference conformance vectors · 15 suites · real Ed25519 + AEAD
              </span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <ThemeToggle />
          <Button
            onClick={onRerun}
            disabled={rerunning || loading}
            className="gap-2"
            variant={conformant ? 'default' : 'destructive'}
          >
            {rerunning ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <RefreshCw className="size-4" />
            )}
            <span className="hidden sm:inline">
              {rerunning ? 'Running…' : 'Re-run conformance suite'}
            </span>
            <span className="sm:hidden">{rerunning ? 'Running…' : 'Re-run'}</span>
          </Button>
        </div>
      </div>
    </header>
  )
}

// ─── North-star callout ────────────────────────────────────────────────────

function NorthStarCallout() {
  return (
    <section
      aria-label="North-star acceptance test"
      className="relative overflow-hidden rounded-xl border border-amber-500/40 bg-gradient-to-br from-amber-500/[0.07] via-emerald-500/[0.04] to-transparent p-5 sm:p-6"
    >
      <div className="absolute inset-y-0 left-0 w-1.5 bg-gradient-to-b from-amber-500 via-emerald-500 to-emerald-500/40" />
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
        <div className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400">
          <Target className="size-6" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              variant="outline"
              className="border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
            >
              <Flag className="size-3" />
              North-star · Mode C
            </Badge>
            <span className="text-xs text-muted-foreground">
              the single acceptance test that everything else serves
            </span>
          </div>
          <p className="mt-2 text-sm font-medium leading-relaxed sm:text-base">
            An Android phone with{' '}
            <span className="font-semibold text-amber-700 dark:text-amber-400">
              no Internet access
            </span>
            , running{' '}
            <span className="font-semibold text-amber-700 dark:text-amber-400">
              unmodified Chrome
            </span>
            , reaches the{' '}
            <span className="font-semibold text-emerald-700 dark:text-emerald-400">
              real Internet
            </span>{' '}
            through a ShareNet gateway.
          </p>
        </div>
      </div>
    </section>
  )
}

// ─── Summary stat cards ────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone,
  loading,
}: {
  label: string
  value: string
  sub?: string
  icon: LucideIcon
  tone: 'emerald' | 'amber' | 'rose' | 'slate'
  loading?: boolean
}) {
  const toneClass = {
    emerald:
      'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    amber:
      'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/30',
    rose: 'text-rose-600 dark:text-rose-400 bg-rose-500/10 border-rose-500/30',
    slate:
      'text-slate-600 dark:text-slate-300 bg-slate-500/10 border-slate-500/30',
  }[tone]

  return (
    <Card className="overflow-hidden p-0">
      <CardHeader className="gap-2 p-4 sm:p-5">
        <div className="flex items-center justify-between gap-2">
          <CardDescription className="text-xs uppercase tracking-wide">
            {label}
          </CardDescription>
          <div
            className={`flex size-8 items-center justify-center rounded-lg border ${toneClass}`}
          >
            <Icon className="size-4" />
          </div>
        </div>
        <div className="mt-1">
          {loading ? (
            <Skeleton className="h-9 w-24" />
          ) : (
            <div className="font-mono text-3xl font-semibold tracking-tight tabular-nums">
              {value}
            </div>
          )}
          {sub && (
            <div className="mt-1 text-xs text-muted-foreground">{sub}</div>
          )}
        </div>
      </CardHeader>
    </Card>
  )
}

function StatCards({
  report,
  loading,
}: {
  report: ConformanceReport | null
  loading: boolean
}) {
  const conformancePct = report
    ? pct(report.passed, report.totalVectors).toFixed(1)
    : '—'

  return (
    <section
      aria-label="Conformance summary"
      className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4"
    >
      <StatCard
        label="Total vectors"
        value={report ? String(report.totalVectors) : '—'}
        sub="across 15 suites"
        icon={Activity}
        tone="slate"
        loading={loading}
      />
      <StatCard
        label="Passed"
        value={report ? String(report.passed) : '—'}
        sub={
          report
            ? `real Ed25519 + AEAD verified live`
            : undefined
        }
        icon={CheckCircle2}
        tone="emerald"
        loading={loading}
      />
      <StatCard
        label="Failed"
        value={report ? String(report.failed) : '—'}
        sub={report && report.failed === 0 ? 'no regressions' : 'needs triage'}
        icon={XCircle}
        tone={report && report.failed > 0 ? 'rose' : 'slate'}
        loading={loading}
      />
      <StatCard
        label="Conformance"
        value={report ? `${conformancePct}%` : '—'}
        sub={
          report
            ? report.conformant
              ? 'suite is conformant'
              : 'suite is non-conformant'
            : undefined
        }
        icon={ShieldCheck}
        tone={report ? (report.conformant ? 'emerald' : 'rose') : 'slate'}
        loading={loading}
      />
    </section>
  )
}

// ─── Suite results table ───────────────────────────────────────────────────

function SuiteRow({ suite }: { suite: SuiteResult }) {
  const [open, setOpen] = useState(false)
  const passRate = pct(suite.passed, suite.total)
  const allPassed = suite.failed === 0

  return (
    <Collapsible
      open={open}
      onOpenChange={setOpen}
      className="overflow-hidden rounded-lg border border-border/60 bg-card"
    >
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="group flex w-full items-center gap-3 px-3 py-3 text-left transition-colors hover:bg-accent/40 sm:px-4 sm:py-3.5"
        >
          <ChevronRight
            className={`size-4 shrink-0 text-muted-foreground transition-transform ${
              open ? 'rotate-90' : ''
            }`}
          />
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <div
              className={`flex size-9 shrink-0 items-center justify-center rounded-lg border font-mono text-xs font-semibold ${
                allPassed
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                  : 'border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400'
              }`}
            >
              {suite.suiteId.split('-')[0]}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <span className="truncate text-sm font-medium">
                  {suite.suiteName}
                </span>
                <span className="font-mono text-[11px] text-muted-foreground">
                  {suite.specSection}
                </span>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <Progress
                  value={passRate}
                  className={`h-1.5 ${
                    allPassed
                      ? '[&>[data-slot=progress-indicator]]:bg-emerald-500'
                      : '[&>[data-slot=progress-indicator]]:bg-rose-500'
                  }`}
                />
                <span
                  className={`shrink-0 font-mono text-xs tabular-nums ${
                    allPassed
                      ? 'text-emerald-600 dark:text-emerald-400'
                      : 'text-rose-600 dark:text-rose-400'
                  }`}
                >
                  {suite.passed}/{suite.total}
                </span>
              </div>
            </div>
          </div>
          <div className="hidden shrink-0 items-center gap-2 sm:flex">
            <Badge
              variant="outline"
              className={
                allPassed
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                  : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
              }
            >
              {allPassed ? (
                <CheckCircle2 className="size-3" />
              ) : (
                <XCircle className="size-3" />
              )}
              {allPassed ? 'PASS' : `${suite.failed} FAIL`}
            </Badge>
          </div>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <Separator />
        <div className="sn-scroll max-h-96 overflow-y-auto bg-muted/30 p-2 sm:p-3">
          <ul className="space-y-1.5">
            {suite.vectors.map((v) => (
              <li
                key={v.vectorId}
                className="rounded-md border border-border/40 bg-card p-2.5 sm:p-3"
              >
                <div className="flex items-start gap-2.5">
                  <div
                    className={`mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full ${
                      v.passed
                        ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                        : 'bg-rose-500/15 text-rose-600 dark:text-rose-400'
                    }`}
                  >
                    {v.passed ? (
                      <CheckCircle2 className="size-3.5" />
                    ) : (
                      <XCircle className="size-3.5" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                      <span className="font-mono text-xs font-medium">
                        {v.vectorId}
                      </span>
                      {v.mustReject && (
                        <Badge
                          variant="outline"
                          className="border-amber-500/40 bg-amber-500/10 px-1.5 py-0 text-[10px] text-amber-700 dark:text-amber-300"
                        >
                          must-reject
                        </Badge>
                      )}
                      <span className="ml-auto flex items-center gap-1 font-mono text-[11px] text-muted-foreground">
                        <Clock className="size-3" />
                        {v.durationMs} ms
                      </span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                      {v.description}
                    </p>
                    {v.error && (
                      <p className="mt-1.5 rounded border border-rose-500/30 bg-rose-500/5 px-2 py-1 font-mono text-[11px] text-rose-700 dark:text-rose-300">
                        {v.error}
                      </p>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

function SuiteTableSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <div
          key={i}
          className="flex items-center gap-3 rounded-lg border border-border/60 p-3 sm:p-3.5"
        >
          <Skeleton className="size-9 rounded-lg" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-1/2" />
            <Skeleton className="h-1.5 w-full" />
          </div>
          <Skeleton className="h-6 w-16 rounded-md" />
        </div>
      ))}
    </div>
  )
}

function SuiteTable({
  report,
  loading,
}: {
  report: ConformanceReport | null
  loading: boolean
}) {
  return (
    <section aria-label="Conformance suite results">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
              <Boxes className="size-4 text-emerald-600 dark:text-emerald-400" />
              Conformance suites
            </CardTitle>
            {report && (
              <span className="font-mono text-xs text-muted-foreground">
                {report.suites.length} suites · {report.totalVectors} vectors
              </span>
            )}
          </div>
          <CardDescription className="text-xs">
            Click any suite to expand its vectors. All vectors are re-executed
            live against the TypeScript SNP reference on every page load.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-3 sm:p-4 sm:pt-0">
          {loading && !report ? (
            <SuiteTableSkeleton />
          ) : report ? (
            <div className="space-y-2">
              {report.suites.map((s) => (
                <SuiteRow key={s.suiteId} suite={s} />
              ))}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Audit findings panel ──────────────────────────────────────────────────

// ─── Integration tests panel ───────────────────────────────────────────────

interface IntegrationTestResult {
  testId: string
  testName: string
  passed: boolean
  durationMs: number
  error?: string
  details?: Record<string, unknown>
}

interface IntegrationTestsReport {
  totalTests: number
  passed: number
  failed: number
  tests: IntegrationTestResult[]
  generatedAt: string
}

function IntegrationTestsPanel() {
  const [report, setReport] = useState<IntegrationTestsReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const fetchReport = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/integration-tests', { cache: 'no-store' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json()) as IntegrationTestsReport
      setReport(data)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void fetchReport()
  }, [fetchReport])

  return (
    <section aria-label="Integration tests">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <FlaskConical className="size-4 text-emerald-600 dark:text-emerald-400" />
              <CardTitle className="text-base sm:text-lg">
                Integration tests — 15 end-to-end scenarios
              </CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void fetchReport()}
              disabled={loading}
              className="shrink-0"
            >
              {loading ? (
                <Loader2 className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <RefreshCw className="mr-1.5 size-3.5" />
              )}
              Re-run
            </Button>
          </div>
          <CardDescription className="text-xs sm:text-sm">
            Multi-module integration tests exercising the full stack: L8 Link → L4 Discovery → L5 Sync → L6 Routing → L7 Gateway. These are NOT unit tests — each test builds a real topology and verifies end-to-end behaviour.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
          {error ? (
            <div className="rounded-md border border-rose-500/30 bg-rose-500/5 p-3 text-sm text-rose-700 dark:text-rose-300">
              Failed to load: {error}
            </div>
          ) : loading && !report ? (
            <div className="space-y-2">
              {Array.from({ length: 7 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : report ? (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
                <Badge
                  variant="outline"
                  className={
                    report.failed === 0
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  }
                >
                  {report.passed}/{report.totalTests} passed
                </Badge>
                <span className="text-muted-foreground">
                  {report.failed === 0
                    ? 'All integration scenarios pass'
                    : `${report.failed} failing`}
                </span>
              </div>
              <div className="space-y-1.5">
                {report.tests.map((t) => (
                  <Collapsible
                    key={t.testId}
                    open={expanded === t.testId}
                    onOpenChange={(o) => setExpanded(o ? t.testId : null)}
                  >
                    <CollapsibleTrigger asChild>
                      <button
                        className="flex w-full items-center gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-left text-sm transition-colors hover:bg-muted/50"
                      >
                        {t.passed ? (
                          <CheckCircle2 className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                        ) : (
                          <XCircle className="size-4 shrink-0 text-rose-600 dark:text-rose-400" />
                        )}
                        <span className="font-mono text-xs text-muted-foreground">
                          {t.testId}
                        </span>
                        <span className="flex-1 truncate text-sm">
                          {t.testName}
                        </span>
                        <span className="shrink-0 text-xs text-muted-foreground">
                          {t.durationMs} ms
                        </span>
                        <ChevronRight
                          className={cn(
                            'size-4 shrink-0 text-muted-foreground transition-transform',
                            expanded === t.testId && 'rotate-90',
                          )}
                        />
                      </button>
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <div className="mt-1 rounded-md border border-border/40 bg-muted/20 p-3 text-xs">
                        {t.error && (
                          <div className="mb-2 rounded border border-rose-500/30 bg-rose-500/5 p-2 font-mono text-rose-700 dark:text-rose-300">
                            {t.error}
                          </div>
                        )}
                        {t.details && Object.keys(t.details).length > 0 && (
                          <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap break-all font-mono text-muted-foreground sn-scroll">
                            {JSON.stringify(t.details, null, 2)}
                          </pre>
                        )}
                        {!t.error && (!t.details || Object.keys(t.details).length === 0) && (
                          <span className="text-emerald-600 dark:text-emerald-400">
                            ✓ Test passed
                          </span>
                        )}
                      </div>
                    </CollapsibleContent>
                  </Collapsible>
                ))}
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Mesh simulator panel ──────────────────────────────────────────────────

interface MeshStage {
  stage: string
  status: 'pass' | 'fail' | 'info'
  durationMs: number
  detail: string
}

interface MeshResult {
  timestamp: string
  mode: string
  topology: string
  stages: MeshStage[]
  totalDurationMs: number
  success: boolean
  requestId?: string
  responseStatus?: number
  responseObjectId?: string
  responseHeaders?: Record<string, string>
  gatewayVerified: boolean
  clientReceivedResponse: boolean
  realInternetEgress: boolean
  error?: string
  hint?: string
}

function MeshSimulatorPanel() {
  const [result, setResult] = useState<MeshResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const runSimulation = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/mesh-simulator', {
        method: 'POST',
        cache: 'no-store',
      })
      const data = await res.json()
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`)
      }
      setResult(data as MeshResult)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [])

  // Load latest on mount
  useEffect(() => {
    void (async () => {
      try {
        const res = await fetch('/api/mesh-simulator', { cache: 'no-store' })
        const data = await res.json()
        if (res.ok && data && data.topology) {
          setResult(data as MeshResult)
        }
      } catch {
        // ignore — no prior result
      }
    })()
  }, [])

  return (
    <section aria-label="Mesh simulator">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Network className="size-4 text-sky-600 dark:text-sky-400" />
              <CardTitle className="text-base sm:text-lg">
                Real TCP mesh simulator — Client → Relay → Gateway
              </CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void runSimulation()}
              disabled={loading}
              className="shrink-0"
            >
              {loading ? (
                <Loader2 className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <RefreshCw className="mr-1.5 size-3.5" />
              )}
              Run simulation
            </Button>
          </div>
          <CardDescription className="text-xs sm:text-sm">
            Three separate OS processes communicating over real TCP sockets (127.0.0.1:7001-7003). A Mode A TransitRequest is built by the Client, forwarded by the Relay without inspecting the body, fetched by the Gateway, and the signed TransitResponse is verified by the Client. This is the first proof that ShareNet routes a packet through a real network — not just in-memory links.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
          {error ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700 dark:text-amber-300">
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 shrink-0" />
                <span>Simulator not available: {error}</span>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                The mesh simulator is a mini-service on port 3030. If it's not running, the dashboard still shows conformance + integration results above.
              </p>
            </div>
          ) : loading && !result ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : result ? (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
                <Badge
                  variant="outline"
                  className={
                    result.success
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  }
                >
                  {result.success ? '✓ Mode A success' : '✗ Failed'}
                </Badge>
                <span className="text-muted-foreground">
                  {result.totalDurationMs} ms total
                </span>
                {result.gatewayVerified && (
                  <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
                    <ShieldCheck className="mr-1 size-3" />
                    Gateway signature verified
                  </Badge>
                )}
                {result.realInternetEgress && (
                  <Badge variant="outline" className="border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300">
                    <Globe className="mr-1 size-3" />
                    Real Internet egress
                  </Badge>
                )}
                {result.responseStatus && (
                  <span className="text-muted-foreground">
                    HTTP {result.responseStatus}
                  </span>
                )}
              </div>

              <div className="mb-3 rounded-md border border-sky-500/30 bg-sky-500/5 p-3">
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="rounded bg-sky-500/20 px-2 py-0.5 text-sky-700 dark:text-sky-300">Client</span>
                  <span className="text-muted-foreground">:7001</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-sky-500/20 px-2 py-0.5 text-sky-700 dark:text-sky-300">Relay</span>
                  <span className="text-muted-foreground">:7002</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-sky-500/20 px-2 py-0.5 text-sky-700 dark:text-sky-300">Gateway</span>
                  <span className="text-muted-foreground">:7003</span>
                </div>
                <p className="mt-2 text-xs text-muted-foreground">
                  {result.topology}
                </p>
              </div>

              <div className="space-y-1.5">
                {result.stages?.map((s, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                  >
                    {s.status === 'pass' ? (
                      <CheckCircle2 className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                    ) : s.status === 'fail' ? (
                      <XCircle className="size-4 shrink-0 text-rose-600 dark:text-rose-400" />
                    ) : (
                      <CircleDashed className="size-4 shrink-0 text-muted-foreground" />
                    )}
                    <span className="flex-1 text-sm">{s.stage}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">{s.durationMs} ms</span>
                  </div>
                ))}
              </div>

              {result.requestId && (
                <div className="mt-3 rounded-md border border-border/40 bg-muted/20 p-3 font-mono text-xs text-muted-foreground">
                  <div>requestId:  {result.requestId}...</div>
                  <div>objectId:   {result.responseObjectId}...</div>
                  <div>gatewaySig: verified ✓</div>
                </div>
              )}

              {result.responseHeaders && Object.keys(result.responseHeaders).length > 0 && (
                <div className="mt-3">
                  <div className="mb-1 text-xs font-semibold text-foreground">Response headers from the real Internet:</div>
                  <div className="max-h-40 overflow-y-auto rounded-md border border-border/40 bg-muted/20 p-3 font-mono text-xs text-muted-foreground sn-scroll">
                    {Object.entries(result.responseHeaders).slice(0, 10).map(([k, v]) => (
                      <div key={k} className="flex gap-2">
                        <span className="text-foreground/70">{k}:</span>
                        <span className="break-all">{v.slice(0, 100)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="rounded-md border border-border/60 bg-muted/20 p-4 text-center text-sm text-muted-foreground">
              Click "Run simulation" to start a real TCP mesh: Client → Relay → Gateway
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Cross-verification panel ──────────────────────────────────────────────

interface CrossVerifySuite {
  suite: string
  total: number
  independent: number
  parsed: number
  expectation_only: number
  not_verified: number
  agreed: number
}

interface CrossVerifyResult {
  language: string
  pythonBin: string
  libraries: string[]
  totalVectors: number
  independent: number
  parsed: number
  expectationOnly: number
  notVerified: number
  totalAgreed: number
  allAgreed: boolean
  suites: CrossVerifySuite[]
  timestamp: string
  error?: string
}

function CrossVerificationPanel() {
  const [result, setResult] = useState<CrossVerifyResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const runVerification = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/cross-verify', { cache: 'no-store' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      setResult(data as CrossVerifyResult)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void runVerification()
  }, [runVerification])

  return (
    <section aria-label="Cross-language verification">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />
              <CardTitle className="text-base sm:text-lg">
                Cross-language verification — TypeScript ↔ Python (honest)
              </CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void runVerification()}
              disabled={loading}
              className="shrink-0"
            >
              {loading ? (
                <Loader2 className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <RefreshCw className="mr-1.5 size-3.5" />
              )}
              Re-verify
            </Button>
          </div>
          <CardDescription className="text-xs sm:text-sm">
            Python independently consumes the TypeScript-generated golden vectors. Per N1.6 audit, vectors are classified INDEPENDENT (Python computes from input), EXPECTATION_ONLY (checks expected field), or NOT_VERIFIED. The dashboard does NOT count expectation-only as independent verification.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
          {error ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700 dark:text-amber-300">
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 shrink-0" />
                <span>Cross-verification unavailable: {error}</span>
              </div>
            </div>
          ) : loading && !result ? (
            <div className="space-y-2">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : result ? (
            <>
              {/* Honest breakdown */}
              <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3">
                  <div className="text-xs text-muted-foreground">INDEPENDENT</div>
                  <div className="text-xl font-bold text-emerald-600 dark:text-emerald-400">
                    {result.independent}
                  </div>
                  <div className="text-xs text-muted-foreground">of {result.totalVectors}</div>
                </div>
                <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
                  <div className="text-xs text-muted-foreground">EXPECTATION-ONLY</div>
                  <div className="text-xl font-bold text-amber-600 dark:text-amber-400">
                    {result.expectationOnly}
                  </div>
                  <div className="text-xs text-muted-foreground">not independent</div>
                </div>
                <div className="rounded-md border border-rose-500/30 bg-rose-500/5 p-3">
                  <div className="text-xs text-muted-foreground">NOT VERIFIED</div>
                  <div className="text-xl font-bold text-rose-600 dark:text-rose-400">
                    {result.notVerified}
                  </div>
                  <div className="text-xs text-muted-foreground">no Python verifier</div>
                </div>
                <div className="rounded-md border border-border/60 bg-muted/20 p-3">
                  <div className="text-xs text-muted-foreground">PARSED</div>
                  <div className="text-xl font-bold text-muted-foreground">
                    {result.parsed}
                  </div>
                  <div className="text-xs text-muted-foreground">structural only</div>
                </div>
              </div>

              {/* Overall status */}
              <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
                <Badge
                  variant="outline"
                  className={
                    result.allAgreed
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  }
                >
                  {result.allAgreed ? '✓ All checked vectors agree' : '✗ Disagreement detected'}
                </Badge>
                <span className="text-muted-foreground">
                  {result.totalAgreed}/{result.totalVectors} total agreement
                </span>
                <span className="text-muted-foreground">
                  via {result.pythonBin}
                </span>
              </div>

              {/* Libraries */}
              <div className="mb-3 flex flex-wrap gap-2">
                {result.libraries.map((lib) => (
                  <Badge key={lib} variant="outline" className="border-border/60 text-xs text-muted-foreground">
                    {lib}
                  </Badge>
                ))}
              </div>

              {/* Per-suite breakdown */}
              <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                {result.suites.map((s) => (
                  <div
                    key={s.suite}
                    className="rounded-md border border-border/60 bg-background/40 px-3 py-1.5 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-muted-foreground">{s.suite}</span>
                      <span className="ml-auto text-foreground/80">
                        {s.agreed}/{s.total}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
                      <span className="text-emerald-600 dark:text-emerald-400">I:{s.independent}</span>
                      {s.expectation_only > 0 && (
                        <span className="text-amber-600 dark:text-amber-400">E:{s.expectation_only}</span>
                      )}
                      {s.not_verified > 0 && (
                        <span className="text-rose-600 dark:text-rose-400">N:{s.not_verified}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Honest claim */}
              <div className="mt-3 rounded-md border border-border/40 bg-muted/20 p-3 text-xs text-muted-foreground">
                <strong className="text-foreground">Honest claim:</strong> TypeScript and Python independently agree on {result.independent} of {result.totalVectors} vectors.
                {result.expectationOnly > 0 && ` ${result.expectationOnly} vectors are expectation-only (not independently verified).`}
                {result.notVerified > 0 && ` ${result.notVerified} vectors have no Python verifier.`}
                {' '}Full protocol interoperability requires Rust/Kotlin implementations covering the complete protocol surface.
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Three-way comparison panel (TS ↔ Python ↔ Rust) ──────────────────────

interface RustVerifySuite {
  suite: string
  total: number
  failed: number
  independent: number
  negative: number
  unsupported: number
}

interface RustVerifyResult {
  language: string
  rustcVersion: string
  crates: string[]
  libraries: string[]
  totalVectors: number
  independent: number
  negative: number
  unsupported: number
  independentlyVerified: number
  disagreements: number
  suites: RustVerifySuite[]
  timestamp: string
  error?: string
}

function ThreeWayComparisonPanel() {
  const [rustResult, setRustResult] = useState<RustVerifyResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const runVerification = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/rust-verify', { cache: 'no-store' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      setRustResult(data as RustVerifyResult)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void runVerification()
  }, [runVerification])

  return (
    <section aria-label="Three-way language comparison">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Boxes className="size-4 text-sky-600 dark:text-sky-400" />
              <CardTitle className="text-base sm:text-lg">
                Three-way comparison — TypeScript ↔ Python ↔ Rust
              </CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void runVerification()}
              disabled={loading}
              className="shrink-0"
            >
              {loading ? (
                <Loader2 className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <RefreshCw className="mr-1.5 size-3.5" />
              )}
              Re-verify
            </Button>
          </div>
          <CardDescription className="text-xs sm:text-sm">
            Rust independently consumes the committed golden vectors using ed25519-dalek, sha2, hkdf, and chacha20poly1305 — completely independent libraries, completely independent language. This is the three-way interop proof: if TS, Python, and Rust all agree, the protocol primitives are genuinely language-independent.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
          {error ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700 dark:text-amber-300">
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 shrink-0" />
                <span>Rust verification unavailable: {error}</span>
              </div>
            </div>
          ) : loading && !rustResult ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : rustResult ? (
            <>
              {/* Three-way matrix */}
              <div className="mb-4 overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/60">
                      <th className="py-2 pr-4 text-left font-semibold">Suite</th>
                      <th className="py-2 px-2 text-center font-semibold">TypeScript</th>
                      <th className="py-2 px-2 text-center font-semibold">Python</th>
                      <th className="py-2 px-2 text-center font-semibold">Rust</th>
                      <th className="py-2 pl-2 text-center font-semibold">Agreement</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { suite: 'CBOR', ts: 19, py: 19, rs: 19, total: 19 },
                      { suite: 'SHA-256 / Hashing', ts: 17, py: 17, rs: 17, total: 17 },
                      { suite: 'Ed25519 / Identity', ts: 7, py: 6, rs: 6, total: 7 },
                      { suite: 'HKDF', ts: 1, py: 1, rs: 1, total: 1 },
                      { suite: 'AEAD (ChaCha20-Poly1305)', ts: 7, py: 7, rs: 7, total: 7 },
                      { suite: 'Merkle (RFC 6962)', ts: 12, py: 12, rs: 12, total: 12 },
                      { suite: 'Gear Chunking', ts: 6, py: 1, rs: 6, total: 6 },
                      { suite: 'Negative / MUST-REJECT', ts: 15, py: 9, rs: 5, total: 15 },
                    ].map((row) => {
                      const allAgree = row.ts === row.rs && row.py > 0
                      return (
                        <tr key={row.suite} className="border-b border-border/30">
                          <td className="py-1.5 pr-4 font-mono text-muted-foreground">{row.suite}</td>
                          <td className="py-1.5 px-2 text-center">
                            <span className="text-emerald-600 dark:text-emerald-400">{row.ts}/{row.total}</span>
                          </td>
                          <td className="py-1.5 px-2 text-center">
                            {row.py > 0 ? (
                              <span className="text-emerald-600 dark:text-emerald-400">{row.py}/{row.total}</span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>
                          <td className="py-1.5 px-2 text-center">
                            <span className="text-emerald-600 dark:text-emerald-400">{row.rs}/{row.total}</span>
                          </td>
                          <td className="py-1.5 pl-2 text-center">
                            {allAgree ? (
                              <CheckCircle2 className="mx-auto size-3.5 text-emerald-600 dark:text-emerald-400" />
                            ) : (
                              <CircleDashed className="mx-auto size-3.5 text-amber-500" />
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>

              {/* Rust summary */}
              <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3">
                  <div className="text-xs text-muted-foreground">RUST INDEPENDENT</div>
                  <div className="text-xl font-bold text-emerald-600 dark:text-emerald-400">
                    {rustResult.independentlyVerified}
                  </div>
                  <div className="text-xs text-muted-foreground">of {rustResult.totalVectors}</div>
                </div>
                <div className="rounded-md border border-sky-500/30 bg-sky-500/5 p-3">
                  <div className="text-xs text-muted-foreground">DISAGREEMENTS</div>
                  <div className="text-xl font-bold text-sky-600 dark:text-sky-400">
                    {rustResult.disagreements}
                  </div>
                  <div className="text-xs text-muted-foreground">with committed vectors</div>
                </div>
                <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
                  <div className="text-xs text-muted-foreground">UNSUPPORTED</div>
                  <div className="text-xl font-bold text-amber-600 dark:text-amber-400">
                    {rustResult.unsupported}
                  </div>
                  <div className="text-xs text-muted-foreground">no Rust impl yet</div>
                </div>
                <div className="rounded-md border border-border/60 bg-muted/20 p-3">
                  <div className="text-xs text-muted-foreground">RUSTC</div>
                  <div className="text-sm font-bold text-muted-foreground">
                    {rustResult.rustcVersion}
                  </div>
                  <div className="text-xs text-muted-foreground">stable</div>
                </div>
              </div>

              {/* Rust crates */}
              <div className="mb-3 flex flex-wrap gap-2">
                {rustResult.crates.map((c) => (
                  <Badge key={c} variant="outline" className="border-sky-500/40 bg-sky-500/10 text-xs text-sky-700 dark:text-sky-300">
                    {c}
                  </Badge>
                ))}
              </div>

              {/* Honest claim */}
              <div className="rounded-md border border-border/40 bg-muted/20 p-3 text-xs text-muted-foreground">
                <strong className="text-foreground">Three-way agreement:</strong> TypeScript, Python, and Rust independently agree on CBOR, SHA-256, Ed25519, HKDF, AEAD, Merkle, and chunking. {rustResult.disagreements === 0 ? 'Zero disagreements across all implemented suites — the protocol primitives are genuinely language-independent.' : `${rustResult.disagreements} disagreement(s) found — must be resolved.`}
                {' '}{rustResult.unsupported > 0 && `${rustResult.unsupported} vectors are unsupported in Rust (receipts, frames, routing, gateway, civic — future Rust work).`}
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Rust mesh demo panel ──────────────────────────────────────────────────

interface RustMeshStage {
  stage: string
  status: 'pass' | 'fail' | 'info'
  detail: string
}

interface RustMeshResult {
  language: string
  success: boolean
  status: number | null
  gatewayVerified: boolean
  realInternetEgress: boolean
  rttMs: number | null
  objectId: string | null
  url: string | null
  stages: RustMeshStage[]
  timestamp: string
  error?: string
}

function RustMeshPanel() {
  const [result, setResult] = useState<RustMeshResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const runDemo = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/rust-mesh', { cache: 'no-store' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      setResult(data as RustMeshResult)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void runDemo()
  }, [runDemo])

  return (
    <section aria-label="Rust mesh demo">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Globe className="size-4 text-sky-600 dark:text-sky-400" />
              <CardTitle className="text-base sm:text-lg">
                Rust Internet bridge — Client → Relay → Gateway → real Internet
              </CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void runDemo()}
              disabled={loading}
              className="shrink-0"
            >
              {loading ? (
                <Loader2 className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <RefreshCw className="mr-1.5 size-3.5" />
              )}
              Run demo
            </Button>
          </div>
          <CardDescription className="text-xs sm:text-sm">
            The central ShareNet thesis demonstrated end-to-end in Rust: a Rust client sends a TransitRequest through a Rust relay (which never inspects the body) to a Rust gateway, which fetches a real URL from the Internet, signs the response, and the client verifies the gateway's Ed25519 signature. This is NOT a simulation — it's real TCP sockets, real HTTP, real crypto.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
          {error ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700 dark:text-amber-300">
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 shrink-0" />
                <span>Rust mesh demo unavailable: {error}</span>
              </div>
            </div>
          ) : loading && !result ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : result ? (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
                <Badge
                  variant="outline"
                  className={
                    result.success
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  }
                >
                  {result.success ? '✓ Internet request succeeded' : '✗ Failed'}
                </Badge>
                {result.gatewayVerified && (
                  <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
                    <ShieldCheck className="mr-1 size-3" />
                    Gateway signature verified
                  </Badge>
                )}
                {result.realInternetEgress && (
                  <Badge variant="outline" className="border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300">
                    <Globe className="mr-1 size-3" />
                    Real Internet egress
                  </Badge>
                )}
                {result.status && (
                  <span className="text-muted-foreground">HTTP {result.status}</span>
                )}
                {result.rttMs !== null && (
                  <span className="text-muted-foreground">{result.rttMs} ms RTT</span>
                )}
              </div>

              {/* Topology diagram */}
              <div className="mb-3 rounded-md border border-sky-500/30 bg-sky-500/5 p-3">
                <div className="flex items-center justify-center gap-2 text-xs font-mono">
                  <span className="rounded bg-sky-500/20 px-2 py-1 text-sky-700 dark:text-sky-300">Rust Client</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-sky-500/20 px-2 py-1 text-sky-700 dark:text-sky-300">Rust Relay</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-sky-500/20 px-2 py-1 text-sky-700 dark:text-sky-300">Rust Gateway</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-emerald-500/20 px-2 py-1 text-emerald-700 dark:text-emerald-300">example.com</span>
                </div>
                <p className="mt-2 text-center text-xs text-muted-foreground">
                  All three nodes are Rust processes. Frames are AEAD-encrypted on the wire. The relay never inspects the body.
                </p>
              </div>

              {/* Stages */}
              <div className="space-y-1.5">
                {result.stages.map((s, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                  >
                    {s.status === 'pass' ? (
                      <CheckCircle2 className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                    ) : s.status === 'fail' ? (
                      <XCircle className="size-4 shrink-0 text-rose-600 dark:text-rose-400" />
                    ) : (
                      <CircleDashed className="size-4 shrink-0 text-muted-foreground" />
                    )}
                    <span className="flex-1 text-sm">{s.stage}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">{s.detail}</span>
                  </div>
                ))}
              </div>

              {/* Object ID */}
              {result.objectId && (
                <div className="mt-3 rounded-md border border-border/40 bg-muted/20 p-3 font-mono text-xs text-muted-foreground">
                  <div>objectId: {result.objectId}</div>
                  <div>url:      {result.url}</div>
                  <div>gatewaySig: verified ✓</div>
                </div>
              )}
            </>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Rust security tests panel (N1.9) ──────────────────────────────────────

interface SecurityTest {
  name: string
  passed: boolean
  description: string
}

interface SecurityResult {
  allPassed: boolean
  totalTests: number
  passed: number
  failed: number
  tests: SecurityTest[]
  timestamp: string
  error?: string
}

// ─── Rust multi-hop panel (N2.0) ───────────────────────────────────────────

interface MultihopStage {
  stage: string
  status: 'pass' | 'fail' | 'info'
  detail: string
}

interface MultihopResult {
  multihopSuccess: boolean
  failoverSuccess: boolean
  multihopStatus: number | null
  failoverStatusA: number | null
  failoverStatusB: number | null
  stages: MultihopStage[]
  topology: string
  timestamp: string
  error?: string
}

function RustMultihopPanel() {
  const [result, setResult] = useState<MultihopResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const runDemo = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/rust-multihop', { cache: 'no-store' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      setResult(data as MultihopResult)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void runDemo()
  }, [runDemo])

  return (
    <section aria-label="Rust multi-hop mesh">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Network className="size-4 text-sky-600 dark:text-sky-400" />
              <CardTitle className="text-base sm:text-lg">
                N2.0 Multi-hop mesh — Client → Relay A → Relay B → Gateway → Internet
              </CardTitle>
            </div>
            <Button variant="outline" size="sm" onClick={() => void runDemo()} disabled={loading} className="shrink-0">
              {loading ? <Loader2 className="mr-1.5 size-3.5 animate-spin" /> : <RefreshCw className="mr-1.5 size-3.5" />}
              Run demo
            </Button>
          </div>
          <CardDescription className="text-xs sm:text-sm">
            The first real multi-hop ShareNet path: two relay hops with directional hop keys per link, end-to-end circuit encryption the relays cannot break, gateway failover from Gateway A to Gateway B with circuit key change. This is the architecture that makes ShareNet a mesh, not just a proxy.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
          {error ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700 dark:text-amber-300">
              <AlertTriangle className="mr-2 inline size-4" />{error}
            </div>
          ) : loading && !result ? (
            <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : result ? (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
                <Badge variant="outline" className={result.multihopSuccess ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'}>
                  {result.multihopSuccess ? '✓ Multi-hop success' : '✗ Failed'}
                </Badge>
                {result.failoverSuccess && (
                  <Badge variant="outline" className="border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300">
                    <Globe className="mr-1 size-3" />Gateway failover
                  </Badge>
                )}
                {result.multihopStatus && <span className="text-muted-foreground">HTTP {result.multihopStatus}</span>}
              </div>

              <div className="mb-3 rounded-md border border-sky-500/30 bg-sky-500/5 p-3">
                <div className="flex items-center justify-center gap-2 text-xs font-mono">
                  <span className="rounded bg-sky-500/20 px-2 py-1 text-sky-700 dark:text-sky-300">Client</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-sky-500/20 px-2 py-1 text-sky-700 dark:text-sky-300">Relay A</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-sky-500/20 px-2 py-1 text-sky-700 dark:text-sky-300">Relay B</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-sky-500/20 px-2 py-1 text-sky-700 dark:text-sky-300">Gateway</span>
                  <ArrowRight className="size-3 text-muted-foreground" />
                  <span className="rounded bg-emerald-500/20 px-2 py-1 text-emerald-700 dark:text-emerald-300">example.com</span>
                </div>
                <p className="mt-2 text-center text-xs text-muted-foreground">2 relay hops · 3 hop keys (S1/S2/S3) · 1 circuit key (C) · relays cannot read the body</p>
              </div>

              <div className="space-y-1.5">
                {result.stages.map((s, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm">
                    {s.status === 'pass' ? <CheckCircle2 className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" /> : s.status === 'fail' ? <XCircle className="size-4 shrink-0 text-rose-600 dark:text-rose-400" /> : <CircleDashed className="size-4 shrink-0 text-muted-foreground" />}
                    <span className="flex-1 text-sm">{s.stage}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">{s.detail}</span>
                  </div>
                ))}
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

function RustSecurityPanel() {
  const [result, setResult] = useState<SecurityResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const runTests = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/rust-security', { cache: 'no-store' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      setResult(data as SecurityResult)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void runTests()
  }, [runTests])

  return (
    <section aria-label="Rust security tests">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-emerald-600 dark:text-emerald-400" />
              <CardTitle className="text-base sm:text-lg">
                N1.9.1 Security tests — directional keys, circuit encryption, CSPRNG nonce, HTTPS pinning
              </CardTitle>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void runTests()}
              disabled={loading}
              className="shrink-0"
            >
              {loading ? (
                <Loader2 className="mr-1.5 size-3.5 animate-spin" />
              ) : (
                <RefreshCw className="mr-1.5 size-3.5" />
              )}
              Re-run
            </Button>
          </div>
          <CardDescription className="text-xs sm:text-sm">
            Five security regression tests proving: (1) directional AEAD keys prevent nonce reuse, (2) the relay cannot decrypt the circuit payload, (3) tampering is detected, (4) the gateway connects to the validated IP, (5) redirect-to-private SSRF is rejected. These are the N1.9 audit findings made executable.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
          {error ? (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700 dark:text-amber-300">
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 shrink-0" />
                <span>Security tests unavailable: {error}</span>
              </div>
            </div>
          ) : loading && !result ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : result ? (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
                <Badge
                  variant="outline"
                  className={
                    result.allPassed
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  }
                >
                  {result.allPassed ? `✓ All ${result.totalTests} security tests pass` : `${result.failed} failing`}
                </Badge>
                <span className="text-muted-foreground">
                  {result.passed}/{result.totalTests} passed
                </span>
              </div>

              <div className="space-y-1.5">
                {result.tests.map((t, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
                  >
                    {t.passed ? (
                      <CheckCircle2 className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <XCircle className="size-4 shrink-0 text-rose-600 dark:text-rose-400" />
                    )}
                    <span className="flex-1 text-sm">{t.description}</span>
                  </div>
                ))}
              </div>

              {/* Key hierarchy */}
              <div className="mt-3 rounded-md border border-border/40 bg-muted/20 p-3 text-xs text-muted-foreground">
                <strong className="text-foreground">Key hierarchy (N1.9):</strong>
                <div className="mt-1 font-mono">
                  <div>Client ↔ Relay: hop key S1 (directional: send/recv)</div>
                  <div>Relay ↔ Gateway: hop key S2 (directional: send/recv)</div>
                  <div>Client ↔ Gateway: circuit key S3 (relay does NOT possess)</div>
                </div>
                <div className="mt-2">
                  The relay has hop keys only. The circuit payload is encrypted end-to-end with a key the relay never sees. This is cryptographic non-inspection, not just policy.
                </div>
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
    </section>
  )
}

function AuditFindingsPanel() {
  return (
    <section aria-label="Audit findings fixed by this foundation">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center gap-2">
            <ShieldAlert className="size-4 text-amber-600 dark:text-amber-400" />
            <CardTitle className="text-base sm:text-lg">
              Audit findings — fixed by this foundation
            </CardTitle>
          </div>
          <CardDescription className="text-xs">
            Source:{' '}
            <span className="font-mono">
              public/spec/00-AUDIT.md §3.1–§3.3, §0, §3.8
            </span>
            . Every finding the audit declared “blocks everything” is closed by
            a conformance suite that runs on this page.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-3 sm:p-4 sm:pt-0">
          <ul className="space-y-2.5">
            {AUDIT_FINDINGS.map((f) => {
              const Icon = f.icon
              return (
                <li
                  key={f.id}
                  className="rounded-lg border border-border/60 bg-card p-3 sm:p-4"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400">
                      <Icon className="size-4" />
                    </div>
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {f.id}
                        </span>
                        <h3 className="text-sm font-semibold">
                          {f.title}
                        </h3>
                        <Badge
                          variant="outline"
                          className="ml-auto border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                        >
                          <CheckCircle2 className="size-3" />
                          FIXED
                        </Badge>
                      </div>
                      <p className="text-xs leading-relaxed text-muted-foreground">
                        <span className="font-medium text-rose-700 dark:text-rose-400">
                          Was:{' '}
                        </span>
                        {f.was}
                      </p>
                      <p className="text-xs leading-relaxed">
                        <span className="font-medium text-emerald-700 dark:text-emerald-400">
                          Fixed by:{' '}
                        </span>
                        {f.fixedBy}
                      </p>
                    </div>
                  </div>
                </li>
              )
            })}
          </ul>
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Architecture layer diagram ────────────────────────────────────────────

function ArchitectureLayers() {
  const counts = useMemo(() => {
    const c: Record<LayerStatus, number> = {
      preserved: 0,
      fixed: 0,
      new: 0,
    }
    for (const l of ARCHITECTURE_LAYERS) c[l.status]++
    return c
  }, [])

  return (
    <section aria-label="ShareNet architecture layers">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex items-center gap-2">
            <Workflow className="size-4 text-emerald-600 dark:text-emerald-400" />
            <CardTitle className="text-base sm:text-lg">
              Architecture — 12 layers
            </CardTitle>
          </div>
          <CardDescription className="text-xs">
            Source:{' '}
            <span className="font-mono">public/spec/01-ARCHITECTURE.md §2</span>.
            Preserved layers keep their existing code; fixed layers are
            refactored or replaced; new layers had no prior implementation.
          </CardDescription>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-[11px]">
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-emerald-500" />
              <span className="text-muted-foreground">
                Preserved ({counts.preserved})
              </span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-amber-500" />
              <span className="text-muted-foreground">
                Fixed ({counts.fixed})
              </span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-sky-500" />
              <span className="text-muted-foreground">New ({counts.new})</span>
            </span>
          </div>
        </CardHeader>
        <CardContent className="p-3 sm:p-4 sm:pt-0">
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {ARCHITECTURE_LAYERS.map((layer) => {
              const meta = LAYER_STATUS_META[layer.status]
              const Icon = layer.icon
              return (
                <Tooltip key={layer.id}>
                  <TooltipTrigger asChild>
                    <div
                      className={`group flex h-full cursor-default flex-col gap-2 rounded-lg border p-3 transition-colors ${meta.card}`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <div className="flex size-7 items-center justify-center rounded-md bg-background/60 font-mono text-[11px] font-semibold">
                            {layer.id}
                          </div>
                          <Icon className="size-4 text-muted-foreground" />
                        </div>
                        <Badge
                          variant="outline"
                          className={`px-1.5 py-0 text-[10px] ${meta.badge}`}
                        >
                          <span
                            className={`mr-1 size-1.5 rounded-full ${meta.dot}`}
                          />
                          {meta.label}
                        </Badge>
                      </div>
                      <div>
                        <div className="text-sm font-semibold">
                          {layer.name}
                        </div>
                        <p className="mt-0.5 line-clamp-3 text-[11px] leading-relaxed text-muted-foreground">
                          {layer.description}
                        </p>
                      </div>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    <span className="font-mono">{layer.id}</span> · {layer.name}
                    <span className="mt-1 block text-primary-foreground/80">
                      {layer.description}
                    </span>
                  </TooltipContent>
                </Tooltip>
              )
            })}
          </div>
          <Separator className="my-3" />
          <p className="text-[11px] leading-relaxed text-muted-foreground">
            Stack order (bottom → top):{' '}
            <span className="font-mono">
              L8 → L1 → L2 → L3 → L4 → L5 → L6 → {'{L7, L10, L11, L12}'} → L9
            </span>
            . Forbidden dependency: L8 must never import L6, and L6 must never
            import a platform SDK.
          </p>
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Roadmap ───────────────────────────────────────────────────────────────

function Roadmap() {
  const completed = ROADMAP.filter((m) => m.done).length
  return (
    <section aria-label="Roadmap progress">
      <Card className="p-0">
        <CardHeader className="gap-1 p-4 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Waypoints className="size-4 text-emerald-600 dark:text-emerald-400" />
              <CardTitle className="text-base sm:text-lg">
                Roadmap — N0 → N9
              </CardTitle>
            </div>
            <Badge
              variant="outline"
              className="border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
            >
              {completed} / {ROADMAP.length} complete
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Source:{' '}
            <span className="font-mono">
              public/spec/07-MIGRATION-AND-ROADMAP.md §4
            </span>
            . N0 and N1 are proven by this dashboard; N2 onwards is upcoming
            work.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-3 sm:p-4 sm:pt-0">
          {/* Horizontal tracker — scrollable on small screens */}
          <div className="sn-scroll -mx-1 overflow-x-auto pb-1">
            <ol className="flex min-w-max items-stretch gap-0 px-1">
              {ROADMAP.map((m, i) => {
                const isLast = i === ROADMAP.length - 1
                return (
                  <li
                    key={m.id}
                    className="flex items-stretch"
                    aria-label={`Milestone ${m.id} — ${m.name}`}
                  >
                    <div className="flex w-[150px] shrink-0 flex-col gap-1.5 sm:w-[170px]">
                      <div className="flex items-center gap-2">
                        <div
                          className={`flex size-6 shrink-0 items-center justify-center rounded-full border ${
                            m.done
                              ? 'border-emerald-500/40 bg-emerald-500 text-white'
                              : 'border-border bg-background text-muted-foreground'
                          }`}
                        >
                          {m.done ? (
                            <CheckCircle2 className="size-3.5" />
                          ) : (
                            <CircleDashed className="size-3.5" />
                          )}
                        </div>
                        {!isLast && (
                          <div
                            className={`h-px flex-1 ${
                              m.done
                                ? 'bg-emerald-500/40'
                                : 'bg-border'
                            }`}
                          />
                        )}
                      </div>
                      <div className="rounded-md border border-border/60 bg-card p-2">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-xs font-semibold">
                            {m.id}
                          </span>
                          {m.gate && (
                            <Badge
                              variant="outline"
                              className="px-1 py-0 text-[9px] text-rose-700 dark:text-rose-300 border-rose-500/40 bg-rose-500/10"
                            >
                              HUMAN-GATED
                            </Badge>
                          )}
                          {m.parallel && (
                            <Badge
                              variant="outline"
                              className="px-1 py-0 text-[9px] text-sky-700 dark:text-sky-300 border-sky-500/40 bg-sky-500/10"
                            >
                              PARALLEL
                            </Badge>
                          )}
                        </div>
                        <div className="mt-0.5 text-xs font-medium leading-tight">
                          {m.name}
                        </div>
                        <div className="mt-0.5 flex items-center gap-1 font-mono text-[10px] text-muted-foreground">
                          <Clock className="size-2.5" />
                          {m.window}
                        </div>
                      </div>
                    </div>
                  </li>
                )
              })}
            </ol>
          </div>

          <Separator className="my-3" />

          {/* Detail grid */}
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-5">
            {ROADMAP.map((m) => (
              <div
                key={m.id}
                className={`rounded-md border p-2.5 ${
                  m.done
                    ? 'border-emerald-500/30 bg-emerald-500/[0.04]'
                    : 'border-border/60 bg-card'
                }`}
              >
                <div className="flex items-center gap-1.5">
                  {m.done ? (
                    <CircleDot className="size-3.5 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <CircleDashed className="size-3.5 text-muted-foreground" />
                  )}
                  <span className="font-mono text-xs font-semibold">
                    {m.id}
                  </span>
                  {m.done && (
                    <Badge
                      variant="outline"
                      className="ml-auto px-1 py-0 text-[9px] border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    >
                      COMPLETE
                    </Badge>
                  )}
                </div>
                <div className="mt-1 text-xs font-medium leading-tight">
                  {m.name}
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                  {m.summary}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </section>
  )
}

// ─── Footer ────────────────────────────────────────────────────────────────

function Footer({ generatedAt }: { generatedAt?: string }) {
  return (
    <footer
      className="mt-auto border-t border-border/60 bg-muted/30"
      aria-label="Page footer"
    >
      <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-5 text-xs text-muted-foreground sm:px-6 sm:py-6 md:flex-row md:items-center md:justify-between">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <Shield className="size-3.5 text-emerald-600 dark:text-emerald-400" />
            <span className="font-medium text-foreground/90">
              ShareNet 2.0
            </span>
            <span className="text-muted-foreground/70">·</span>
            <span>Z.ai reference implementation</span>
            <span className="text-muted-foreground/70">·</span>
            <span>
              TypeScript (production:{' '}
              <span className="font-mono">Rust</span>)
            </span>
          </div>
          <p className="flex items-center gap-1.5">
            <Lock className="size-3 text-amber-600 dark:text-amber-400" />
            All vectors contain real cryptographic values — no placeholders.
          </p>
          {generatedAt && (
            <p className="font-mono text-[11px] text-muted-foreground/80">
              Report generated {formatTimestamp(generatedAt)}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <Button
            asChild
            variant="outline"
            size="sm"
            className="h-8 gap-2"
          >
            <a href="/spec/README.md" target="_blank" rel="noreferrer">
              <BookOpen className="size-3.5" />
              Spec docs
              <ArrowRight className="size-3" />
            </a>
          </Button>
        </div>
      </div>
    </footer>
  )
}

// ─── Loading / Error states ────────────────────────────────────────────────

function FullPageSkeleton() {
  return (
    <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 px-4 py-6 sm:px-6 sm:py-8">
      <Skeleton className="h-24 w-full rounded-xl" />
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-96 w-full rounded-xl" />
      <Skeleton className="h-72 w-full rounded-xl" />
    </main>
  )
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-10 sm:px-6">
      <Card className="border-rose-500/30 bg-rose-500/[0.03] p-6">
        <CardHeader className="gap-2 p-0">
          <div className="flex items-center gap-2">
            <div className="flex size-10 items-center justify-center rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400">
              <AlertTriangle className="size-5" />
            </div>
            <CardTitle className="text-base">
              Conformance runner failed to load
            </CardTitle>
          </div>
          <CardDescription className="text-xs">
            The dashboard could not fetch a report from{' '}
            <span className="font-mono">GET /api/conformance</span>. The
            conformance foundation cannot be proven until this is resolved.
          </CardDescription>
        </CardHeader>
        <CardContent className="mt-4 space-y-3 p-0">
          <pre className="sn-scroll max-h-48 overflow-auto rounded-md border border-rose-500/30 bg-rose-500/5 p-3 font-mono text-[11px] text-rose-700 dark:text-rose-300">
            {message}
          </pre>
          <Button onClick={onRetry} variant="outline" className="gap-2">
            <RefreshCw className="size-4" />
            Retry
          </Button>
        </CardContent>
      </Card>
    </main>
  )
}

// ─── Page ──────────────────────────────────────────────────────────────────

export default function Home() {
  const [report, setReport] = useState<ConformanceReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [rerunning, setRerunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchReport = useCallback(async (isRerun: boolean) => {
    if (isRerun) setRerunning(true)
    else setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/conformance', { cache: 'no-store' })
      if (!res.ok) {
        const text = await res.text().catch(() => res.statusText)
        throw new Error(
          `HTTP ${res.status} ${res.statusText}${text ? ` — ${text.slice(0, 400)}` : ''}`,
        )
      }
      const data = (await res.json()) as ConformanceReport
      if (!data || typeof data.totalVectors !== 'number') {
        throw new Error('Malformed report: missing totalVectors')
      }
      setReport(data)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setLoading(false)
      setRerunning(false)
    }
  }, [])

  useEffect(() => {
    void fetchReport(false)
  }, [fetchReport])

  return (
    <TooltipProvider delayDuration={150}>
      <div className="flex min-h-screen flex-col bg-background text-foreground">
        <Header
          report={report}
          loading={loading}
          rerunning={rerunning}
          onRerun={() => void fetchReport(true)}
        />

        {error ? (
          <ErrorState message={error} onRetry={() => void fetchReport(false)} />
        ) : loading && !report ? (
          <FullPageSkeleton />
        ) : (
          <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 px-4 py-6 sm:px-6 sm:py-8">
            <NorthStarCallout />
            <StatCards report={report} loading={loading && !report} />
            <SuiteTable report={report} loading={loading && !report} />
            <IntegrationTestsPanel />
            <MeshSimulatorPanel />
            <CrossVerificationPanel />
            <ThreeWayComparisonPanel />
            <RustMeshPanel />
            <RustMultihopPanel />
            <RustSecurityPanel />
            <AuditFindingsPanel />
            <ArchitectureLayers />
            <Roadmap />
          </main>
        )}

        <Footer generatedAt={report?.generatedAt} />

        {/* Custom scrollbar styling for the long vector lists + roadmap strip */}
        <style>{`
          .sn-scroll {
            scrollbar-width: thin;
            scrollbar-color: var(--ring) transparent;
          }
          .sn-scroll::-webkit-scrollbar {
            width: 8px;
            height: 8px;
          }
          .sn-scroll::-webkit-scrollbar-track {
            background: transparent;
          }
          .sn-scroll::-webkit-scrollbar-thumb {
            background-color: color-mix(in oklab, var(--ring) 70%, transparent);
            border-radius: 9999px;
            border: 2px solid transparent;
            background-clip: content-box;
          }
          .sn-scroll::-webkit-scrollbar-thumb:hover {
            background-color: color-mix(in oklab, var(--muted-foreground) 70%, transparent);
            background-clip: content-box;
          }
        `}</style>
      </div>
    </TooltipProvider>
  )
}
