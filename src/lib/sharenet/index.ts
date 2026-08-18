/**
 * ShareNet 2.0 — UI Adapter Layer (barrel)
 *
 * Single import surface for the UI:
 *
 *   import {
 *     IS_MOCK,
 *     getConnectionSummary,
 *     type ConnectionSummary,
 *     type NetworkPath,
 *     ...
 *   } from '@/lib/sharenet';
 *
 * Re-exports the UI-facing types from `types.ts` and the mock adapter API
 * from `mock-adapter.ts`. When a real protocol-backed adapter lands, the
 * only change required is to swap the implementation re-exported here (and
 * flip `IS_MOCK` to `false` in that new adapter). UI code stays untouched.
 *
 * NOTE: under `isolatedModules: true`, type-only re-exports MUST use
 * `export type { ... }` so a downstream bundler can erase them safely.
 *
 * Task ID: UI-ADAPTER
 */

// ─── Types (UI-facing domain model) ───────────────────────────────────────
export type {
  ConnectionState,
  PathQuality,
  NetworkNode,
  NetworkPath,
  ActivityEvent,
  Device,
  PrivacyState,
  ConnectionSummary,
  SettingsState,
} from './types';

// ─── Mock adapter API ─────────────────────────────────────────────────────
export {
  IS_MOCK,
  MOCK_LABEL,
  getConnectionSummary,
  getNetworkPath,
  getActivityEvents,
  getDevices,
  getPrivacyState,
  getSettings,
  updateSettings,
  connect,
  disconnect,
} from './mock-adapter';
