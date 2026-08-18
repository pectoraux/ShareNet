'use client';

/**
 * ShareNet — icon glyph components.
 *
 * Tiny components that render the right lucide icon for a given node type,
 * path quality, or activity event type. They are switch-based (each branch
 * returns a *static* JSX element referencing a statically-imported lucide
 * component) so the `react-hooks/static-components` ESLint rule never fires —
 * we never create a component during render.
 *
 * Always pair with the colour + label helpers from `quality-helpers.ts` so
 * that quality is never communicated by colour alone.
 *
 * Task ID: UI-NETWORK-ACTIVITY
 */

import type { LucideProps } from 'lucide-react';
import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle2,
  CircleDashed,
  Compass,
  Globe,
  Laptop,
  LogOut,
  MinusCircle,
  RefreshCw,
  Server,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
  Waypoints,
} from 'lucide-react';

import type { ActivityEvent, NetworkNode, PathQuality } from '@/lib/sharenet';

// ─── Node glyph ────────────────────────────────────────────────────────────

export function NodeGlyph({
  type,
  ...props
}: { type: NetworkNode['type'] } & LucideProps) {
  switch (type) {
    case 'you':
      return <Laptop {...props} />;
    case 'relay':
      return <Waypoints {...props} />;
    case 'gateway':
      return <Server {...props} />;
    case 'internet':
      return <Globe {...props} />;
  }
}

// ─── Quality glyph ────────────────────────────────────────────────────────

export function QualityGlyph({
  quality,
  ...props
}: { quality: PathQuality | undefined } & LucideProps) {
  switch (quality) {
    case 'excellent':
      return <CheckCircle2 {...props} />;
    case 'good':
      return <ShieldCheck {...props} />;
    case 'fair':
      return <MinusCircle {...props} />;
    case 'poor':
      return <AlertTriangle {...props} />;
    default:
      return <CircleDashed {...props} />;
  }
}

// ─── Activity glyph ───────────────────────────────────────────────────────

export function ActivityGlyph({
  type,
  ...props
}: { type: ActivityEvent['type'] } & LucideProps) {
  switch (type) {
    case 'connected':
      return <CheckCircle2 {...props} />;
    case 'disconnected':
      return <LogOut {...props} />;
    case 'path_improved':
      return <TrendingUp {...props} />;
    case 'path_degraded':
      return <TrendingDown {...props} />;
    case 'relay_discovered':
      return <Compass {...props} />;
    case 'recovery_started':
      return <RefreshCw {...props} />;
    case 'recovery_completed':
      return <ShieldCheck {...props} />;
    case 'gateway_changed':
      return <ArrowRightLeft {...props} />;
    case 'error':
      return <AlertTriangle {...props} />;
  }
}

export default NodeGlyph;
