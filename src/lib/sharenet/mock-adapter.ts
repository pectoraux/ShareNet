/**
 * ShareNet 2.0 — UI Adapter Layer: Mock Adapter (PROTOTYPE / SIMULATION)
 *
 * ╔════════════════════════════════════════════════════════════════════════╗
 * ║  ⚠️  THIS IS NOT REAL PROTOCOL DATA.                                    ║
 * ║                                                                        ║
 * ║  Every value returned by the functions in this file is hand-crafted    ║
 * ║  fixture data. The `IS_MOCK` export is `true` and the UI MUST use it   ║
 * ║  to label the dashboard as "Prototype" / "Demo data" / "Simulation"    ║
 * ║  so that no one mistakes these numbers for live measurements.           ║
 * ║                                                                        ║
 * ║  The adapter exists so the UI can be built and reviewed before the     ║
 * ║  protocol integration (see `src/lib/snp/*`) is wired up. When the     ║
 * ║  real adapter lands it will export the same surface from this same     ║
 * ║  file path (or a sibling file the barrel re-exports) and flip         ║
 * ║  `IS_MOCK` to `false`.                                                 ║
 * ╚════════════════════════════════════════════════════════════════════════╝
 *
 * Task ID: UI-ADAPTER
 */

import type {
  ActivityEvent,
  ConnectionSummary,
  ConnectionState,
  Device,
  NetworkPath,
  PathQuality,
  PrivacyState,
  SettingsState,
} from './types';

// ─── Mock identity ────────────────────────────────────────────────────────

/**
 * `true` when this adapter is the prototype/simulation adapter.
 *
 * The UI reads this flag (rather than sniffing values out of the data) to
 * decide whether to render the "Prototype" banner / "Demo data" badges.
 * The real adapter will export the same constant set to `false`.
 */
export const IS_MOCK = true;

/**
 * A human-readable label the UI can show next to mock data, e.g. a small
 * "Prototype — simulated telemetry" pill in the header.
 */
export const MOCK_LABEL = 'Prototype · simulated telemetry';

/**
 * Simulated per-call latency for the async getters, in ms. Tuned so the
 * skeleton loaders are visible but the UI doesn't feel sluggish. The
 * actual variance (±40%) makes it look less robotic.
 */
const MOCK_LATENCY_MS = 220;

// ─── In-memory mutable mock state ────────────────────────────────────────
//
// connect()/disconnect()/updateSettings() mutate this object so the UI can
// demo the full lifecycle. It is reset on a full page reload, which is fine
// for a prototype.

const mockState: {
  connectionState: ConnectionState;
  connectedSince: Date | undefined;
  settings: SettingsState;
} = {
  connectionState: 'connected',
  connectedSince: minutesAgo(12),
  settings: {
    connectAutomatically: true,
    preferReliablePaths: true,
    allowRelaying: true,
    privateRelayMode: true,
    shareDiagnostics: true,
    theme: 'system',
  },
};

// ─── Helpers ───────────────────────────────────────────────────────────────

/** Resolve after `ms` milliseconds (capped to a sane minimum). */
function delay(ms: number): Promise<void> {
  const bounded = Math.max(0, Math.min(ms, 1500));
  return new Promise((resolve) => setTimeout(resolve, bounded));
}

/** Adds jitter so mock latency doesn't look like a metronome. */
function jitter(base: number): number {
  return Math.round(base * (0.6 + Math.random() * 0.8));
}

/** A `Date` `n` minutes in the past. */
function minutesAgo(n: number): Date {
  return new Date(Date.now() - n * 60_000);
}

/** A `Date` `n` seconds in the past. */
function secondsAgo(n: number): Date {
  return new Date(Date.now() - n * 1_000);
}

/** A `Date` `n` hours in the past. */
function hoursAgo(n: number): Date {
  return new Date(Date.now() - n * 3_600_000);
}

// ─── Fixture: privacy state ───────────────────────────────────────────────

const MOCK_PRIVACY: PrivacyState = {
  privateRelayMode: true,
  shareDiagnostics: true,
  encryptionEnabled: true,
  identityVerified: true,
  circuitAuthenticated: true,
  gatewayVerified: true,
  routeSigned: true,
};

// ─── Fixture: network path ─────────────────────────────────────────────────
//
// You (MacBook Pro) → Relay (Amsterdam Relay 01) → Gateway (Frankfurt
// Gateway 03) → Internet. 3 hops, ~42ms, 99.8% reliability.
//
// Per-hop numbers are summed into the path-level totals below. The values
// are deliberately a bit asymmetric (relay hop slightly cheaper than the
// gateway hop) so the UI's per-node bars look realistic.

function buildMockPath(): NetworkPath {
  const youLatency = 1; // localhost — negligible
  const relayLatency = 14; // encrypted link to first relay
  const gatewayLatency = 19; // relay → gateway hop
  const egressLatency = 8; // gateway → first-hop Internet RTT

  const youReliability = 1.0;
  const relayReliability = 0.998; // weakest hop — bounds path reliability to 99.8%
  const gatewayReliability = 0.9994;
  const egressReliability = 0.9999;

  const totalLatency = youLatency + relayLatency + gatewayLatency + egressLatency; // 42
  const totalReliability = Math.min(
    youReliability,
    relayReliability,
    gatewayReliability,
    egressReliability,
  ); // bounded by the weakest hop

  return {
    nodes: [
      {
        id: 'node-you',
        type: 'you',
        label: 'This MacBook Pro',
        status: 'connected',
        quality: 'excellent',
        latencyMs: youLatency,
        reliability: youReliability,
        hopIndex: 0,
      },
      {
        id: 'relay-ams-01',
        type: 'relay',
        label: 'Amsterdam Relay 01',
        status: 'connected',
        quality: 'excellent',
        latencyMs: relayLatency,
        reliability: relayReliability,
        hopIndex: 1,
      },
      {
        id: 'gateway-fra-03',
        type: 'gateway',
        label: 'Frankfurt Gateway 03',
        status: 'connected',
        quality: 'good',
        latencyMs: gatewayLatency,
        reliability: gatewayReliability,
        hopIndex: 2,
      },
      {
        id: 'internet',
        type: 'internet',
        label: 'Internet',
        status: 'connected',
        quality: 'good',
        latencyMs: egressLatency,
        reliability: egressReliability,
        hopIndex: 3,
      },
    ],
    totalHops: 3,
    overallQuality: qualityFromLatencyAndReliability(totalLatency, totalReliability),
    latencyMs: totalLatency,
    reliability: totalReliability,
  };
}

/**
 * Bucket the (latency, reliability) pair into a PathQuality. Mirrors the
 * heuristic the real adapter will use, but with hardcoded thresholds so the
 * mock numbers always land in `excellent`/`good` for the demo.
 */
function qualityFromLatencyAndReliability(latencyMs: number, reliability: number): PathQuality {
  if (reliability < 0.95) return 'poor';
  if (latencyMs > 200) return 'poor';
  if (latencyMs > 120 || reliability < 0.98) return 'fair';
  if (latencyMs > 60 || reliability < 0.99) return 'good';
  return 'excellent';
}

// ─── Fixture: activity timeline ───────────────────────────────────────────
//
// Five events spanning the last ~47 minutes, newest first. The UI renders
// these in a vertical timeline; icons and severity drive the colour.

function buildMockActivity(): ActivityEvent[] {
  return [
    {
      id: 'evt-connected',
      timestamp: minutesAgo(12),
      type: 'connected',
      title: 'Connected to ShareNet',
      description:
        'Connected via Amsterdam Relay 01 → Frankfurt Gateway 03. ' +
        'Identity verified, route signature valid.',
      severity: 'success',
    },
    {
      id: 'evt-path-improved',
      timestamp: minutesAgo(8),
      type: 'path_improved',
      title: 'Path upgraded',
      description:
        'Path switched from Berlin Relay 02 to Amsterdam Relay 01. ' +
        'Latency improved from 71ms to 42ms.',
      severity: 'success',
    },
    {
      id: 'evt-relay-discovered',
      timestamp: minutesAgo(18),
      type: 'relay_discovered',
      title: 'New relay discovered',
      description:
        'Peer "Amsterdam Relay 01" advertised a new route. ' +
        'Identity verified against its public key.',
      severity: 'info',
    },
    {
      id: 'evt-recovery-completed',
      timestamp: minutesAgo(34),
      type: 'recovery_completed',
      title: 'Recovery completed',
      description:
        'ShareNet restored a healthy path in 1.4s. ' +
        'New connections can use the recovered path.',
      severity: 'success',
    },
    {
      id: 'evt-path-degraded',
      timestamp: minutesAgo(47),
      type: 'path_degraded',
      title: 'Latency spike detected',
      description:
        'Berlin Relay 02 reported 312ms latency with 4% packet loss. ' +
        'Path marked degraded; looking for a healthier route.',
      severity: 'warning',
    },
  ];
}

// ─── Fixture: devices ──────────────────────────────────────────────────────
//
// 1 local device (the user's own machine, running this UI) + 2 nearby user
// devices + 2 nearby ShareNet community devices that could act as relays.

function buildMockDevices(): { local: Device[]; nearby: Device[] } {
  const localMacBook: Device = {
    id: 'dev-mbp-local',
    name: 'MacBook Pro',
    type: 'laptop',
    status: 'connected',
    lastSeen: secondsAgo(2),
    isLocal: true,
    identityVerified: true,
    capabilities: ['relay', 'content-source', 'gateway-client'],
    publicKeyFingerprint: 'SHA-256: 7F:3A:1C:9E:B4:2D:55:8A:0E:F1:6C:33:90:1B:A4:7D',
  };

  const nearbyIPhone: Device = {
    id: 'dev-iphone-15',
    name: 'iPhone 15 Pro',
    type: 'phone',
    status: 'connected',
    lastSeen: secondsAgo(45),
    isLocal: false,
    identityVerified: true,
    capabilities: ['relay', 'content-source'],
    publicKeyFingerprint: 'SHA-256: 4C:E2:90:1A:7B:5F:33:DC:8E:02:6A:9B:F4:71:0C:88',
  };

  const nearbyIPad: Device = {
    id: 'dev-ipad-air',
    name: 'iPad Air',
    type: 'tablet',
    status: 'offline',
    lastSeen: hoursAgo(2),
    isLocal: false,
    identityVerified: true,
    capabilities: ['content-source'],
    publicKeyFingerprint: 'SHA-256: A1:5D:22:7E:F0:09:CC:64:3B:8E:1A:7F:25:E4:D9:36',
  };

  // Two community ShareNet devices in radio range — could become relays.
  const nearbyCommunity1: Device = {
    id: 'dev-sharenet-cafe',
    name: 'ShareNet · Café Node',
    type: 'other',
    status: 'connected',
    lastSeen: secondsAgo(10),
    isLocal: false,
    identityVerified: true,
    capabilities: ['relay'],
    publicKeyFingerprint: 'SHA-256: B2:9F:17:C4:60:8A:3E:DB:71:55:0F:14:9C:22:8E:3A',
  };

  const nearbyCommunity2: Device = {
    id: 'dev-sharenet-pi',
    name: 'ShareNet · Raspberry Pi',
    type: 'desktop',
    status: 'syncing',
    lastSeen: secondsAgo(30),
    isLocal: false,
    identityVerified: false, // not yet verified — UI shows a warning badge
    capabilities: ['relay', 'content-source'],
    // Note: this device's identity is NOT yet verified, so the fingerprint
    // is shown in the detail sheet under a "Pending verification" label —
    // the UI should treat it as untrusted until identityVerified flips to true.
    publicKeyFingerprint: 'SHA-256: 0E:44:71:9D:8F:2C:B6:55:3A:90:F1:7C:0D:E2:11:98',
  };

  return {
    local: [localMacBook],
    nearby: [nearbyIPhone, nearbyIPad, nearbyCommunity1, nearbyCommunity2],
  };
}

// ─── Public API ────────────────────────────────────────────────────────────
//
// Every function returns a Promise that resolves after a small simulated
// latency, so the UI exercises its loading skeletons. The data is fixed at
// module load (deterministic) except where connect()/disconnect() mutate
// `mockState` — this lets the dashboard demo the full connection lifecycle.

export async function getConnectionSummary(): Promise<ConnectionSummary> {
  await delay(jitter(MOCK_LATENCY_MS));
  const path = mockState.connectionState === 'connected' ? buildMockPath() : null;
  return {
    state: mockState.connectionState,
    path,
    internetAvailable: mockState.connectionState === 'connected',
    privacy: MOCK_PRIVACY,
    connectedSince: mockState.connectedSince,
  };
}

export async function getNetworkPath(): Promise<NetworkPath> {
  await delay(jitter(MOCK_LATENCY_MS));
  return buildMockPath();
}

export async function getActivityEvents(): Promise<ActivityEvent[]> {
  await delay(jitter(MOCK_LATENCY_MS));
  // Return a shallow-cloned array so callers can't mutate the fixture.
  return buildMockActivity().map((e) => ({ ...e }));
}

export async function getDevices(): Promise<{ local: Device[]; nearby: Device[] }> {
  await delay(jitter(MOCK_LATENCY_MS));
  const { local, nearby } = buildMockDevices();
  return {
    local: local.map((d) => ({ ...d })),
    nearby: nearby.map((d) => ({ ...d })),
  };
}

export async function getPrivacyState(): Promise<PrivacyState> {
  await delay(jitter(MOCK_LATENCY_MS));
  return { ...MOCK_PRIVACY };
}

export async function getSettings(): Promise<SettingsState> {
  await delay(jitter(MOCK_LATENCY_MS));
  return { ...mockState.settings };
}

export async function updateSettings(updates: Partial<SettingsState>): Promise<void> {
  await delay(jitter(MOCK_LATENCY_MS));
  mockState.settings = { ...mockState.settings, ...updates };
}

export async function connect(): Promise<void> {
  await delay(jitter(MOCK_LATENCY_MS + 600)); // simulate handshake cost
  mockState.connectionState = 'connected';
  mockState.connectedSince = new Date();
}

export async function disconnect(): Promise<void> {
  await delay(jitter(MOCK_LATENCY_MS));
  mockState.connectionState = 'disconnected';
  mockState.connectedSince = undefined;
}
