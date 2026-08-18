/**
 * ShareNet 2.0 — UI Adapter Layer: Type Definitions
 *
 * This file is the *only* surface area the UI components may import directly
 * for type information. It deliberately mirrors the protocol concepts from
 * the ShareNet architecture (00-ARCHITECTURE .. 07-MIGRATION-AND-ROADMAP) but
 * re-expresses them in UI-friendly shapes:
 *
 *   - No CBOR, no Ed25519 byte arrays, no SIG_CONTEXT constants leak here.
 *   - All timestamps are JS `Date` objects (never raw u64 epoch millis).
 *   - Latencies are human-meaningful `number`s in milliseconds.
 *   - Reliability is a 0-1 float the UI can format as a percentage.
 *
 * The actual protocol layer (`src/lib/snp/*`) is the source of truth for the
 * on-the-wire representation. An adapter (see `mock-adapter.ts`) is responsible
 * for translating between protocol reality and these UI shapes. Swapping the
 * mock adapter for a real protocol-backed adapter MUST NOT require any change
 * to the UI components, because they only depend on the types in this file.
 *
 * Task ID: UI-ADAPTER
 */

// ─── Connection lifecycle ─────────────────────────────────────────────────

/**
 * The high-level connection state of the ShareNet session, as seen by the UI.
 *
 * - `disconnected` — idle, no session established.
 * - `connecting`   — a session is being established (handshake / discovery).
 * - `connected`    — a usable circuit exists; user traffic is flowing.
 * - `degraded`     — connected, but reliability/latency below threshold.
 * - `recovering`  — a recovery controller is migrating the path.
 * - `offline`      — no usable path to any gateway; local-only operation.
 * - `disabled`     — the user (or admin policy) has disabled ShareNet.
 */
export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'degraded'
  | 'recovering'
  | 'offline'
  | 'disabled';

// ─── Path quality ─────────────────────────────────────────────────────────

/**
 * A coarse bucketing of the measured quality of a network path segment.
 * The adapter computes this from observed latency, loss and reliability.
 *
 * `unknown` is used when no measurement has been taken yet (e.g. the path
 * has been computed by the route engine but not yet probed).
 */
export type PathQuality = 'excellent' | 'good' | 'fair' | 'poor' | 'unknown';

// ─── Topology ─────────────────────────────────────────────────────────────

/**
 * A single node in the network path between the user and the Internet.
 *
 * The `type` discriminator tells the UI which icon/label to render. The
 * `status` field is the node's current operational state. `quality`,
 * `latencyMs` and `reliability` are populated when measurements exist.
 *
 * `hopIndex` is 0-indexed from the user's device: the `you` node is hop 0,
 * the first relay is hop 1, the gateway is the final hop before `internet`.
 */
export interface NetworkNode {
  id: string;
  type: 'you' | 'relay' | 'gateway' | 'internet';
  label: string;
  status: 'available' | 'connected' | 'degraded' | 'offline';
  quality?: PathQuality;
  latencyMs?: number;
  reliability?: number; // 0-1
  hopIndex?: number;
}

/**
 * The full end-to-end path from the user to the Internet, including all
 * intermediate relays and the gateway hop.
 *
 * `nodes` is ordered from `you` → relays → gateway → `internet`.
 * `totalHops` excludes the user device but includes the internet egress,
 * i.e. it equals `nodes.length - 1`.
 */
export interface NetworkPath {
  nodes: NetworkNode[];
  totalHops: number;
  overallQuality: PathQuality;
  latencyMs: number;
  reliability: number;
}

// ─── Activity timeline ────────────────────────────────────────────────────

/**
 * A single event in the ShareNet activity timeline shown in the UI sidebar.
 *
 * `type` drives the icon and colour. `severity` is independent of `type`:
 * a `recovery_started` event might be `info` while a `recovery_completed`
 * after a long outage is `success`.
 */
export interface ActivityEvent {
  id: string;
  timestamp: Date;
  type:
    | 'connected'
    | 'disconnected'
    | 'path_improved'
    | 'path_degraded'
    | 'relay_discovered'
    | 'recovery_started'
    | 'recovery_completed'
    | 'gateway_changed'
    | 'error';
  title: string;
  description: string;
  severity: 'info' | 'success' | 'warning' | 'error';
}

// ─── Devices ──────────────────────────────────────────────────────────────

/**
 * A device in the user's ecosystem. `isLocal` marks the device the user is
 * currently using; nearby devices can be used as relays (Mode A) or as
 * content sources. `identityVerified` reflects whether the device's
 * ShareNet identity has been authenticated against its Ed25519 public key.
 *
 * `publicKeyFingerprint` is the device's Ed25519 public key, formatted for
 * human inspection (e.g. `SHA-256: AB:CD:EF:…`). It is exposed on the
 * Device object so a detail sheet can display it — but the LIST view must
 * NOT render it. Showing full cryptographic identifiers in a list view
 * is both a privacy hazard (shoulder-surfing) and a UX hazard (visual
 * noise). Components that render lists of devices are expected to omit
 * this field from their list rows.
 *
 * Per `06-CONFORMANCE-AND-AI-MODEL.md` §B3 I3/I4, on the wire the public
 * key is a raw 32-byte Ed25519 key and the NodeId is
 * SHA-256("SNP/0.1 node\0" ‖ pk). The fingerprint here is a UI-friendly
 * rendering of the same key material — the adapter is responsible for
 * deriving it from the protocol-backed key bytes.
 *
 * Task ID: UI-ADAPTER · extended UI-DEVICES-SETTINGS
 */
export interface Device {
  id: string;
  name: string;
  type: 'laptop' | 'phone' | 'tablet' | 'desktop' | 'other';
  status: 'connected' | 'offline' | 'syncing';
  lastSeen: Date;
  isLocal?: boolean;
  identityVerified?: boolean;
  capabilities?: string[];
  publicKeyFingerprint?: string;
}

// ─── Privacy & integrity ──────────────────────────────────────────────────

/**
 * The user-visible privacy posture of the current ShareNet session.
 *
 * The four `*Verified` / `*Authenticated` / `*Signed` booleans correspond
 * to the integrity invariants from `06-CONFORMANCE-AND-AI-MODEL.md` §B3
 * (I2 signature context, I3 raw Ed25519 keys, I4 NodeId = SHA-256(domain ‖ pk))
 * — but expressed as a simple yes/no the UI can show as a checklist, rather
 * than as a wire-level signature blob.
 */
export interface PrivacyState {
  privateRelayMode: boolean;
  shareDiagnostics: boolean;
  encryptionEnabled: boolean;
  identityVerified: boolean;
  circuitAuthenticated: boolean;
  gatewayVerified: boolean;
  routeSigned: boolean;
}

// ─── Aggregates ───────────────────────────────────────────────────────────

/**
 * The single object the home screen needs to render its initial state.
 * Combines connection state, the current path, internet reachability and
 * the privacy posture in one fetch.
 */
export interface ConnectionSummary {
  state: ConnectionState;
  path: NetworkPath | null;
  internetAvailable: boolean;
  privacy: PrivacyState;
  connectedSince?: Date;
}

/**
 * User-facing settings. Persisted by the adapter (mock: in-memory only;
 * real adapter: backed by the platform settings store).
 */
export interface SettingsState {
  connectAutomatically: boolean;
  preferReliablePaths: boolean;
  allowRelaying: boolean;
  privateRelayMode: boolean;
  shareDiagnostics: boolean;
  theme: 'light' | 'dark' | 'system';
}
