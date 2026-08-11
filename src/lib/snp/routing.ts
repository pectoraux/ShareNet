/**
 * SNP Routing — Gateway-anchored mesh routing (L6)
 *
 * Source: 02-PROTOCOL-SPEC.md §6 "Routing (L6)"
 * Source: 00-AUDIT.md §4 (audit finding #4 — the existing repository has NO
 *         routing at all; this module is the heart of the new thesis)
 *
 * The audit (00-AUDIT.md §4) found that the existing repository ships no
 * routing module whatsoever: no distance-vector, no path-vector, no loop
 * defence, no gateway migration. The old `core-transport/Governor.kt` only
 * gated local sends by battery threshold — it had no concept of a route table,
 * no concept of alternate gateways, and no concept of path-vector loop
 * freedom. This file is the direct replacement.
 *
 * ## Model (spec §6.2): gateway-anchored, source-hinted, hop-by-hop
 *
 * Traffic is overwhelmingly directed at a small number of Internet gateways,
 * which is a much easier problem than general any-to-any routing. Gateways
 * originate `RouteAdvert`s that propagate outward with accumulating metrics,
 * building a distance-vector gradient. Every node therefore knows a path to
 * a gateway without asking. Node-to-node paths (rare; mostly Class A) use
 * on-demand route request/reply (NOT implemented in this file).
 *
 * ## Loop freedom (spec §6.3)
 *
 * Each RouteAdvert carries a `pathVector` of NodeIds traversed. A node MUST
 * discard an advert whose pathVector contains its own NodeId — this is the
 * loop-freedom invariant. Combined with monotonic per-destination `seq`
 * numbers (a node MUST discard adverts whose seq is lower than the best
 * known for that destination), this gives loop-free distance-vector routing
 * without counting-to-infinity.
 *
 * ## Metric integrity (spec §6.3 "Metric integrity")
 *
 * `originSig` covers ONLY `{destination, destType, seq, expiresAt}` — the
 * fields the destination owns. Per-hop metrics are NOT signed by the origin
 * (they cannot be — the origin doesn't know the path a particular advert
 * will take). Therefore **the metric is untrusted input.** Metric
 * manipulation is the primary routing attack; mitigation is
 * reputation-weighting and end-to-end verification, not signatures on
 * metrics. See the Threat Model document.
 *
 * ## Platform independence (Invariant I9)
 *
 * L8 transport never imports L6 routing. This routing module is
 * platform-independent: it has no knowledge of BLE, Wi-Fi, mDNS, or any
 * link layer. It consumes and produces pure data structures (RouteAdvert,
 * RouteTable). A platform shim (L8) is responsible for actually moving
 * bytes between peers and for advertising/receiving routes over the
 * appropriate link layer. This file MUST NOT import any platform-specific
 * module, and platform code MUST NOT reach into the route table to make
 * forwarding decisions on its own — it goes through the API exported here.
 *
 * @ invariant I9  — L8 transport never imports L6 routing. This module is
 *                   platform-independent: no link-layer imports, no platform-
 *                   specific code. Forwarding decisions go through this API.
 *                   (Enforced by architecture and code review; not statically
 *                   checkable from inside this file.)
 * @ invariant I16 — Reputation is locally computed; NEVER accepted as
 *                   authoritative from a peer. The `reputation` field in
 *                   RouteMetric is LOCAL observation only. See §6.4 + JSDoc
 *                   on the field.
 * @ invariant I20 — verify* returns false on a bad signature; never throws.
 *                   validate* throws CborError(MALFORMED) on structural
 *                   problems. sign* validates first (fail-fast on bad input).
 */

import {
  DEST_TYPES,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  POWER_STATES,
  SIG_CONTEXTS,
  type DestType,
  type PowerState,
} from "./constants";
import { type CborValue, CborError, cborMap } from "./cbor";
import { sign, verify } from "./crypto";

// ─── Frozen sizes ──────────────────────────────────────────────────────────

/** NodeId byte length (matches SHA-256 output, I4). */
const NODE_ID_BYTES = 32;

// ─── RouteMetric (spec §6.4) ───────────────────────────────────────────────

/**
 * Normative routing metric inputs (spec §6.4 table).
 *
 * Every field is an INTEGER — SNP-CBOR forbids floats (I1 / cbor.ts §3).
 * Quantities that are conceptually fractional are encoded as integer
 * parts-per-thousand so they round-trip byte-exactly across implementations:
 *
 *   - `loss`            — packet loss in parts-per-thousand (0..1000).
 *                         5% loss = 50. NOT a float.
 *   - `congestion`      — relay queue depth, normalised 0..1000.
 *   - `reliability`     — historical route uptime, 0..1000 (local obs only).
 *   - `reputation`      — locally-computed reputation, 0..1000. SEE I16 WARNING.
 *   - `stability`       — route age / flap count damped, 0..1000.
 *
 * Other fields (`latency`, `bandwidthBps`, `gatewayCapacity`, `costHint`,
 * `scarcity`, `hopCount`) are plain unsigned integers with their natural units.
 *
 * These inputs are NORMATIVE — the Conformance Suite tests them. The cost
 * WEIGHTING (see DEFAULT_ROUTE_WEIGHTS) is LOCAL POLICY: different
 * implementations can weight differently without breaking interop, because
 * only the inputs are exchanged on the wire (spec §6.4 "different
 * implementations can weight differently without breaking interop — but the
 * inputs are normative").
 */
export interface RouteMetric {
  /** One-way or round-trip latency in milliseconds (EWMA, α = 0.2 per spec). */
  readonly latency: number;

  /**
   * Packet loss in parts-per-thousand (0..1000). 5% loss = 50.
   * Encoded as an integer because SNP-CBOR forbids floats.
   */
  readonly loss: number;

  /** Hop count for this path. Equals pathVector.length in a well-formed advert. */
  readonly hopCount: number;

  /** Relay queue depth, normalised 0..1000. UNTRUSTED — advertised by relay. */
  readonly congestion: number;

  /** Historical route uptime, 0..1000. LOCAL OBSERVATION ONLY. */
  readonly reliability: number;

  /** Available bandwidth in bits per second. Prefer measured over advertised. */
  readonly bandwidthBps: number;

  /** Relay power state — one of POWER_STATES (spec §6.5). */
  readonly batteryState: PowerState;

  /** GatewayAdvert.capacity. UNTRUSTED — advertised by gateway. */
  readonly gatewayCapacity: number;

  /**
   * Reputation, 0..1000.
   *
   * ⚠️  INVARIANT I16 — Reputation is LOCALLY COMPUTED. It MUST NEVER be
   * accepted as authoritative from a peer. The `reputation` field in a
   * RouteMetric received from a peer is UNTRUSTED INPUT — the local node
   * MUST overwrite it with its own locally-computed reputation before using
   * the metric for routing decisions. Accepting a peer's reputation claim
   * creates a trivially gameable channel (spec §6.4: "Reputation MUST be
   * locally computed. Accepting a peer's reputation claim creates a
   * trivially gameable channel. Attested reputation (signed receipts) is
   * *evidence* the local node evaluates.").
   *
   * This field exists in the wire structure so that a relay can carry its
   * own reputation hint forward, but every recipient MUST treat it as a
   * hint and recompute locally.
   */
  readonly reputation: number;

  /** GatewayAdvert.costHint. Policy input (Civic Points cost). */
  readonly costHint: number;

  /** Count of distinct known gateways. Raises willingness to use poor routes. */
  readonly scarcity: number;

  /** Route age / flap count damped, 0..1000. Damps oscillation. */
  readonly stability: number;
}

// ─── RouteAdvert (spec §6.3) ───────────────────────────────────────────────

/**
 * Fields of a RouteAdvert, excluding the origin signature.
 *
 * CDDL (02-PROTOCOL-SPEC.md §6.3):
 *   RouteAdvert = {
 *     destination:  bstr .size 32,    ; NodeId of the destination (gateway or node)
 *     destType:     "gateway" / "node",
 *     seq:          uint,             ; per-destination, monotonic — anti-loop
 *     pathVector:   [* bstr .size 32],; NodeIds traversed — loop detection
 *     hopCount:     uint,
 *     metric:       RouteMetric,
 *     originSig:    bstr .size 64,    ; destination signs {destination, destType, seq, expiresAt}
 *     expiresAt:    uint
 *   }
 *
 * `pathVector` grows as the advert propagates: the gateway originates it with
 * `pathVector = [gatewayNodeId]`, and each relay appends its own NodeId before
 * re-broadcasting. Order is origin-first: `[origin, hop1, hop2, ..., lastHop]`.
 */
export interface RouteAdvertFields {
  /** NodeId (32 bytes) of the destination — a gateway or a node. */
  readonly destination: Uint8Array;

  /** Whether the destination is a gateway or a regular node. */
  readonly destType: DestType;

  /**
   * Per-destination monotonic sequence number — anti-loop / anti-replay.
   * A node MUST discard adverts whose seq is lower than the best known
   * for that destination (see isSeqRegression).
   */
  readonly seq: number;

  /**
   * NodeIds traversed by this advert, origin-first. Each entry is 32 bytes.
   * A node MUST discard an advert containing its own NodeId (see containsLoop).
   */
  readonly pathVector: Uint8Array[];

  /** Hop count. SHOULD equal pathVector.length for a well-formed advert. */
  readonly hopCount: number;

  /** Aggregate route metric for this path. UNTRUSTED — see "Metric integrity". */
  readonly metric: RouteMetric;

  /** Expiry (unix seconds). Routes whose expiresAt < now MUST be discarded. */
  readonly expiresAt: number;
}

/**
 * A complete RouteAdvert, including the 64-byte origin signature.
 *
 * `originSig` is the destination's Ed25519 signature over
 * `SIG_CONTEXTS.routeAdvert ‖ CBOR({destination, destType, seq, expiresAt})`
 * — the four origin-owned fields. Per-hop fields (pathVector, hopCount,
 * metric) are NOT signed by the origin because the origin cannot know what
 * path a particular advert will take (spec §6.3 "Metric integrity").
 */
export interface RouteAdvert extends RouteAdvertFields {
  /** 64-byte Ed25519 signature by the destination over the origin-owned fields. */
  readonly originSig: Uint8Array;
}

// ─── Route cost weights (spec §6.4) ────────────────────────────────────────

/**
 * Local-policy weights for the route cost formula. These are NOT normative —
 * different implementations can weight differently without breaking interop
 * (spec §6.4). The NORMATIVE part is the set of metric INPUTS (RouteMetric
 * fields); the weights are local policy.
 */
export interface RouteWeights {
  /** Weight for latency (ms). Default 1. */
  readonly w_lat: number;
  /** Weight for loss (parts-per-thousand). Default 1000 — loss is very disruptive. */
  readonly w_loss: number;
  /** Per-hop weight. Default 10 — applied once per hop (× metric.hopCount). */
  readonly w_hop: number;
  /** Weight for congestion (0..1000). Default 0.01. */
  readonly w_cong: number;
  /** Weight for reputation (0..1000). Default 0.1. Subtracted from cost. */
  readonly w_rep: number;
  /** Constant gateway term added to cost. Default 0. */
  readonly gateway_term: number;
}

/**
 * Default route-cost weights (spec §6.4).
 *
 * These are LOCAL POLICY — exported so that downstream code (the conformance
 * suite, the routing daemon, the gateway selector) all reference the same
 * defaults. A deployment MAY override them by passing a custom RouteWeights
 * to `computeRouteCost`. The wire-protocol inputs (RouteMetric fields) are
 * normative; the weights are not.
 *
 *   - `w_lat = 1`        latency in ms contributes 1:1
 *   - `w_loss = 1000`    loss is parts-per-thousand; 5% loss (50) contributes
 *                        50,000 — loss is severely disruptive to interactive
 *                        traffic, so it dominates the cost when present
 *   - `w_hop = 10`       per-hop penalty; a 5-hop path costs 50 more than a
 *                        direct route (× metric.hopCount, see computeRouteCost)
 *   - `w_cong = 0.01`    congestion 0..1000 contributes 0..10 (minor)
 *   - `w_rep = 0.1`      reputation 0..1000 subtracts 0..100 (high-rep routes
 *                        are cheaper; LOCALLY COMPUTED ONLY — I16)
 *   - `gateway_term = 0` no default gateway penalty
 */
export const DEFAULT_ROUTE_WEIGHTS: RouteWeights = {
  w_lat: 1,
  w_loss: 1000,
  w_hop: 10,
  w_cong: 0.01,
  w_rep: 0.1,
  gateway_term: 0,
} as const;

// ─── CBOR map builders ─────────────────────────────────────────────────────

/**
 * Build the canonical CBOR preimage map for a RouteMetric.
 *
 * All keys are strings; canonical (length-first) key ordering is applied at
 * encode time by the SNP-CBOR encoder. All values are integers or strings —
 * NEVER floats (I1 / SNP-CBOR §3).
 */
export function routeMetricToCborMap(
  metric: RouteMetric,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["latency", metric.latency],
    ["loss", metric.loss],
    ["hopCount", metric.hopCount],
    ["congestion", metric.congestion],
    ["reliability", metric.reliability],
    ["bandwidthBps", metric.bandwidthBps],
    ["batteryState", metric.batteryState],
    ["gatewayCapacity", metric.gatewayCapacity],
    ["reputation", metric.reputation],
    ["costHint", metric.costHint],
    ["scarcity", metric.scarcity],
    ["stability", metric.stability],
  ]);
}

/**
 * Build the canonical CBOR preimage map for the ORIGIN-OWNED fields of a
 * RouteAdvert: `{destination, destType, seq, expiresAt}`.
 *
 * This is the structure that `originSig` covers (spec §6.3 "Metric
 * integrity": "originSig covers {destination, destType, seq, expiresAt} —
 * the fields the origin owns"). Per-hop fields (pathVector, hopCount,
 * metric) are deliberately NOT included — they cannot be signed by the
 * origin because the origin does not know what path a particular advert
 * will take.
 *
 * Both `signRouteAdvert` and `verifyRouteAdvert` use this exact preimage,
 * so a signature made by one implementation verifies on another (I1, I2).
 */
export function routeAdvertOriginToCborMap(
  fields: RouteAdvertFields,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["destination", fields.destination],
    ["destType", fields.destType],
    ["seq", fields.seq],
    ["expiresAt", fields.expiresAt],
  ]);
}

/**
 * Build the canonical CBOR map for a COMPLETE RouteAdvert (all 8 fields,
 * including originSig). Used for wire-encoding the advert for transmission.
 *
 * Note: the `metric` sub-field is encoded as a nested CBOR map (via
 * routeMetricToCborMap). The `pathVector` is encoded as a CBOR array of
 * byte strings.
 */
export function routeAdvertToCborMap(
  advert: RouteAdvert,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["destination", advert.destination],
    ["destType", advert.destType],
    ["seq", advert.seq],
    ["pathVector", advert.pathVector as CborValue[]],
    ["hopCount", advert.hopCount],
    ["metric", routeMetricToCborMap(advert.metric)],
    ["originSig", advert.originSig],
    ["expiresAt", advert.expiresAt],
  ]);
}

// ─── Structural validation ─────────────────────────────────────────────────

/**
 * Validate a RouteMetric against the CDDL constraints.
 * Throws CborError(MALFORMED) on any violation.
 *
 * Per spec §6.4, the inputs are NORMATIVE — the Conformance Suite tests
 * them. Range checks (0..1000 for parts-per-thousand fields) catch
 * accidentally-malformed metrics; they are not a security boundary (the
 * metric is untrusted input regardless — see "Metric integrity").
 */
function assertRouteMetric(metric: RouteMetric): void {
  if (typeof metric !== "object" || metric === null) {
    throw new CborError("RouteMetric must be an object", "MALFORMED");
  }
  if (!Number.isInteger(metric.latency) || metric.latency < 0) {
    throw new CborError(
      "RouteMetric.latency must be a non-negative integer (ms)",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(metric.loss) || metric.loss < 0 || metric.loss > 1000) {
    throw new CborError(
      "RouteMetric.loss must be an integer in [0, 1000] (parts-per-thousand; 5% = 50)",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(metric.hopCount) || metric.hopCount < 0) {
    throw new CborError(
      "RouteMetric.hopCount must be a non-negative integer",
      "MALFORMED",
    );
  }
  if (
    !Number.isInteger(metric.congestion) ||
    metric.congestion < 0 ||
    metric.congestion > 1000
  ) {
    throw new CborError(
      "RouteMetric.congestion must be an integer in [0, 1000]",
      "MALFORMED",
    );
  }
  if (
    !Number.isInteger(metric.reliability) ||
    metric.reliability < 0 ||
    metric.reliability > 1000
  ) {
    throw new CborError(
      "RouteMetric.reliability must be an integer in [0, 1000]",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(metric.bandwidthBps) || metric.bandwidthBps < 0) {
    throw new CborError(
      "RouteMetric.bandwidthBps must be a non-negative integer",
      "MALFORMED",
    );
  }
  if (
    typeof metric.batteryState !== "string" ||
    !POWER_STATES.includes(metric.batteryState as PowerState)
  ) {
    throw new CborError(
      `RouteMetric.batteryState must be one of [${POWER_STATES.join(", ")}]`,
      "MALFORMED",
    );
  }
  if (
    !Number.isInteger(metric.gatewayCapacity) ||
    metric.gatewayCapacity < 0
  ) {
    throw new CborError(
      "RouteMetric.gatewayCapacity must be a non-negative integer",
      "MALFORMED",
    );
  }
  if (
    !Number.isInteger(metric.reputation) ||
    metric.reputation < 0 ||
    metric.reputation > 1000
  ) {
    throw new CborError(
      "RouteMetric.reputation must be an integer in [0, 1000] (LOCAL observation only — I16)",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(metric.costHint) || metric.costHint < 0) {
    throw new CborError(
      "RouteMetric.costHint must be a non-negative integer",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(metric.scarcity) || metric.scarcity < 0) {
    throw new CborError(
      "RouteMetric.scarcity must be a non-negative integer",
      "MALFORMED",
    );
  }
  if (
    !Number.isInteger(metric.stability) ||
    metric.stability < 0 ||
    metric.stability > 1000
  ) {
    throw new CborError(
      "RouteMetric.stability must be an integer in [0, 1000]",
      "MALFORMED",
    );
  }
}

/**
 * Validate a RouteAdvert against the CDDL constraints (spec §6.3).
 * Throws CborError(MALFORMED) on any structural violation.
 *
 * Checks:
 *   - `destination` is a 32-byte Uint8Array (NodeId)
 *   - `destType` is "gateway" or "node" (one of DEST_TYPES)
 *   - `seq` is a non-negative integer (uint)
 *   - `pathVector` is an array; each entry is a 32-byte Uint8Array
 *   - `hopCount` is a non-negative integer (uint)
 *   - `metric` is a structurally valid RouteMetric (delegates to assertRouteMetric)
 *   - `originSig` is a 64-byte Uint8Array (Ed25519 signature)
 *   - `expiresAt` is a non-negative integer (uint)
 *
 * This function does NOT check for loops within the pathVector (that is a
 * routing-policy check, not a structural one — use `containsLoop` or
 * `RouteTable.addRoute` for that). It does NOT verify the signature (use
 * `verifyRouteAdvert` for that). It only enforces CDDL structural shape.
 */
export function validateRouteAdvert(advert: RouteAdvert): void {
  if (typeof advert !== "object" || advert === null) {
    throw new CborError("RouteAdvert must be an object", "MALFORMED");
  }
  if (
    !(advert.destination instanceof Uint8Array) ||
    advert.destination.length !== NODE_ID_BYTES
  ) {
    throw new CborError(
      "RouteAdvert.destination must be a 32-byte Uint8Array (NodeId)",
      "MALFORMED",
    );
  }
  if (
    typeof advert.destType !== "string" ||
    !DEST_TYPES.includes(advert.destType as DestType)
  ) {
    throw new CborError(
      `RouteAdvert.destType must be one of [${DEST_TYPES.join(", ")}]`,
      "MALFORMED",
    );
  }
  if (!Number.isInteger(advert.seq) || advert.seq < 0) {
    throw new CborError(
      "RouteAdvert.seq must be a non-negative integer (uint)",
      "MALFORMED",
    );
  }
  if (!Array.isArray(advert.pathVector)) {
    throw new CborError(
      "RouteAdvert.pathVector must be an array of Uint8Array",
      "MALFORMED",
    );
  }
  for (let i = 0; i < advert.pathVector.length; i++) {
    const id = advert.pathVector[i];
    if (!(id instanceof Uint8Array) || id.length !== NODE_ID_BYTES) {
      throw new CborError(
        `RouteAdvert.pathVector[${i}] must be a 32-byte Uint8Array (NodeId)`,
        "MALFORMED",
      );
    }
  }
  if (!Number.isInteger(advert.hopCount) || advert.hopCount < 0) {
    throw new CborError(
      "RouteAdvert.hopCount must be a non-negative integer (uint)",
      "MALFORMED",
    );
  }
  if (typeof advert.metric !== "object" || advert.metric === null) {
    throw new CborError(
      "RouteAdvert.metric must be a RouteMetric object",
      "MALFORMED",
    );
  }
  assertRouteMetric(advert.metric);
  if (
    !(advert.originSig instanceof Uint8Array) ||
    advert.originSig.length !== ED25519_SIGNATURE_BYTES
  ) {
    throw new CborError(
      "RouteAdvert.originSig must be a 64-byte Uint8Array (Ed25519 signature)",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(advert.expiresAt) || advert.expiresAt < 0) {
    throw new CborError(
      "RouteAdvert.expiresAt must be a non-negative integer (unix seconds)",
      "MALFORMED",
    );
  }
}

// ─── Sign / Verify ─────────────────────────────────────────────────────────

/**
 * Sign the origin-owned fields of a RouteAdvert using the destination's
 * Ed25519 secret key.
 *
 * The signature is over `SIG_CONTEXTS.routeAdvert ‖ CBOR({destination, destType, seq, expiresAt})`
 * — the four fields the destination owns (spec §6.3 "Metric integrity").
 * Per-hop fields (pathVector, hopCount, metric) are NOT signed by the origin
 * because the origin cannot know what path a particular advert will take.
 *
 * The full advert fields are validated first (fail-fast on bad input — we
 * never sign malformed data). The returned signature is 64 raw bytes; the
 * caller assembles the complete RouteAdvert by attaching it as `originSig`.
 *
 * @param destinationSecretKey  32-byte Ed25519 secret key of the destination
 *                              (the gateway or node that the route leads to)
 * @param fields                the full RouteAdvert fields (without originSig)
 * @returns                     64-byte Ed25519 signature over the origin-owned
 *                              fields, under SIG_CONTEXTS.routeAdvert
 */
export function signRouteAdvert(
  destinationSecretKey: Uint8Array,
  fields: RouteAdvertFields,
): Uint8Array {
  // Validate the full advert with a zero-filled placeholder signature so we
  // never sign malformed input. Matches the pattern in receipts.ts / identity.ts.
  validateRouteAdvert({
    ...fields,
    originSig: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = routeAdvertOriginToCborMap(fields);
  return sign(destinationSecretKey, "routeAdvert", preimage);
}

/**
 * Verify a RouteAdvert's origin signature against the destination's Ed25519
 * public key.
 *
 * Re-derives the origin-owned preimage `{destination, destType, seq, expiresAt}`
 * and calls `verify(destinationPublicKey, "routeAdvert", preimage, originSig)`.
 *
 * Returns `false` on ANY failure — bad signature, wrong key length, malformed
 * fields, malformed signature. NEVER throws for a bad signature (I20 — the
 * direct fix for the audit's "FakeCryptoProvider.verify => signature.size == 64"
 * pattern).
 *
 * Note: takes the destination's Ed25519 PUBLIC KEY (32 bytes), NOT a NodeId.
 * The advert carries the destination's NodeId for identification, but NodeId
 * is a SHA-256 hash (I4) and cannot verify a signature. Callers obtain the
 * destination's public key out-of-band (e.g. from a NodeDescriptor).
 *
 * Verifying the origin signature does NOT verify the metric — the metric is
 * untrusted input by design (spec §6.3 "Metric integrity"). Mitigation for
 * metric manipulation is reputation-weighting (locally computed — I16) and
 * end-to-end verification, NOT signatures on metrics.
 *
 * @param advert                  the RouteAdvert to verify
 * @param destinationPublicKey    32-byte Ed25519 public key of the destination
 * @returns                       true iff originSig is valid for the
 *                                origin-owned fields; false on any failure
 */
export function verifyRouteAdvert(
  advert: RouteAdvert,
  destinationPublicKey: Uint8Array,
): boolean {
  if (destinationPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (
    !(advert.originSig instanceof Uint8Array) ||
    advert.originSig.length !== ED25519_SIGNATURE_BYTES
  ) {
    return false;
  }
  try {
    validateRouteAdvert(advert);
  } catch {
    return false;
  }
  const preimage = routeAdvertOriginToCborMap(advert);
  return verify(destinationPublicKey, "routeAdvert", preimage, advert.originSig);
}

// ─── Loop detection (spec §6.3) ────────────────────────────────────────────

/**
 * Constant-time-ish byte equality check for two Uint8Arrays.
 * (Not strictly constant-time — fine for NodeIds, which are public.)
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Hex-encode a Uint8Array for use as a Map key (structural equality). */
function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

/**
 * Does `pathVector` already contain `nodeId`?
 *
 * Per spec §6.3: "a node MUST discard an advert containing its own NodeId."
 * This is the loop-freedom check: when a relay receives an advert, it calls
 * `containsLoop(advert.pathVector, myNodeId)`. If true, the relay discards
 * the advert instead of forwarding it (which would create a routing loop).
 *
 * @param pathVector  the advert's pathVector (NodeIds traversed so far)
 * @param nodeId      the NodeId to look for (typically the local node's own)
 * @returns           true if `nodeId` appears in `pathVector`
 */
export function containsLoop(
  pathVector: Uint8Array[],
  nodeId: Uint8Array,
): boolean {
  for (const id of pathVector) {
    if (bytesEqual(id, nodeId)) return true;
  }
  return false;
}

/**
 * Would appending `nextHopId` to `pathVector` create a loop?
 *
 * Equivalent to `containsLoop(pathVector, nextHopId)` — if nextHopId is
 * already in the pathVector, appending it would create a cycle. Exposed as
 * a separate function because the intent is clearer at the call site: a
 * relay about to forward an advert asks "would adding myself create a loop?"
 *
 * @param pathVector  the advert's pathVector BEFORE appending
 * @param nextHopId   the NodeId about to be appended (typically the local
 *                    node's own)
 * @returns           true if appending nextHopId would create a loop
 */
export function wouldCreateLoop(
  pathVector: Uint8Array[],
  nextHopId: Uint8Array,
): boolean {
  return containsLoop(pathVector, nextHopId);
}

/**
 * Does `newSeq` regress below `bestKnownSeq`?
 *
 * Per spec §6.3: "a node MUST discard adverts whose seq is lower than the
 * best known for that destination." This is the anti-replay / anti-loop
 * sequence-number regression check. Combined with the pathVector loop check,
 * it gives loop-free distance-vector routing without counting-to-infinity.
 *
 * Equal seq is NOT a regression — a node may accept an advert with seq equal
 * to the best known (e.g. an alternate path to the same destination, fresh
 * from the origin). Only strictly-lower seq is a regression.
 *
 * @param newSeq         the seq of the incoming advert
 * @param bestKnownSeq   the highest seq previously seen for this destination
 * @returns              true iff `newSeq < bestKnownSeq`
 */
export function isSeqRegression(
  newSeq: number,
  bestKnownSeq: number,
): boolean {
  return newSeq < bestKnownSeq;
}

// ─── Route metric computation (spec §6.4) ──────────────────────────────────

/**
 * Compute a single scalar cost for a route, per the spec §6.4 formula:
 *
 *   cost = Σ_hops [ w_lat·latency + w_loss·loss + w_hop·1 + w_cong·congestion ]
 *          + gateway_term
 *          − w_rep·reputation
 *
 * The spec's Σ_hops notation iterates over per-hop contributions. Because
 * the RouteMetric contains AGGREGATE values for the whole path (latency is
 * EWMA RTT for the whole path, loss is aggregate delivery ratio, etc.), the
 * Σ_hops expands naturally to:
 *
 *   cost = w_lat·latency + w_loss·loss + w_hop·hopCount + w_cong·congestion
 *          + gateway_term − w_rep·reputation
 *
 * The `w_hop·1` term in the spec sums per hop to `w_hop · hopCount`, which
 * is the per-hop penalty scaled by path length. (Without multiplying by
 * hopCount, the per-hop weight would be a useless constant offset.)
 *
 * This is pure arithmetic for the LOCAL routing decision. It does NOT
 * encode/decode — the inputs are taken from the RouteMetric structure
 * (which was decoded elsewhere). The output is a JS number used to compare
 * routes; lower cost = better route.
 *
 * Weights are LOCAL POLICY (spec §6.4: "different implementations can
 * weight differently without breaking interop — but the inputs are
 * normative"). Callers MAY pass a custom RouteWeights; otherwise
 * DEFAULT_ROUTE_WEIGHTS is used.
 *
 * ⚠️  INVARIANT I16: `metric.reputation` MUST be the LOCAL node's own
 * computed reputation for the relevant peer, NOT the value received in the
 * advert (which is untrusted). The caller is responsible for overwriting
 * `metric.reputation` with the local value before calling this function.
 *
 * @param metric    the route metric (with LOCAL reputation — see I16)
 * @param weights   optional custom weights (defaults to DEFAULT_ROUTE_WEIGHTS)
 * @returns         a single scalar cost; lower = better route
 */
export function computeRouteCost(
  metric: RouteMetric,
  weights: RouteWeights = DEFAULT_ROUTE_WEIGHTS,
): number {
  return (
    weights.w_lat * metric.latency +
    weights.w_loss * metric.loss +
    weights.w_hop * metric.hopCount +
    weights.w_cong * metric.congestion +
    weights.gateway_term -
    weights.w_rep * metric.reputation
  );
}

// ─── RouteTable (spec §6.6) ────────────────────────────────────────────────

/**
 * Internal equality check for two path vectors (same NodeIds in same order).
 * Used by `RouteTable.addRoute` to decide whether an incoming advert is a
 * refresh of an existing route (same path) or a new alternative route.
 */
function samePathVector(a: Uint8Array[], b: Uint8Array[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (!bytesEqual(a[i], b[i])) return false;
  }
  return true;
}

/**
 * Does `pathVector` contain ANY duplicate NodeId? (Structural loop check.)
 *
 * This is the structural loop invariant enforced by `RouteTable.addRoute`:
 * a well-formed pathVector has no duplicates. It catches both loops back to
 * the origin (destination appearing more than once) and loops in the middle
 * (any intermediate appearing more than once). The local-node-specific loop
 * check ("does this contain MY NodeId?") is a separate concern, performed
 * by the relay BEFORE calling addRoute (see `containsLoop`).
 */
function hasDuplicateNodeId(pathVector: Uint8Array[]): boolean {
  const seen = new Set<string>();
  for (const id of pathVector) {
    const hex = bytesToHex(id);
    if (seen.has(hex)) return true;
    seen.add(hex);
  }
  return false;
}

/**
 * The local route table — gateway-anchored distance-vector with path-vector
 * loop freedom (spec §6.6).
 *
 * Maintains multiple alternative routes per destination (so that
 * `disjointRoutes` can satisfy the "at least 2 disjoint routes per active
 * destination where available" requirement of spec §6.6). The table is
 * keyed by destination NodeId; each destination maps to a list of routes
 * (different pathVectors to the same destination).
 *
 * Internal storage uses hex-encoded NodeId strings as Map keys because JS
 * Maps use reference equality on Uint8Array keys, which would break lookups
 * (the same NodeId decoded twice produces two non-identical Uint8Array
 * references). Externally, all API methods take/return Uint8Array; the
 * hex-encoding is an internal implementation detail.
 *
 * Thread safety: NOT thread-safe. The routing daemon is single-threaded
 * per node; concurrent access from multiple async tasks must be serialised
 * by the caller.
 */
export class RouteTable {
  /**
   * Internal storage: hex(destination NodeId) → list of routes to that
   * destination. Semantically equivalent to `Map<Uint8Array, RouteAdvert[]>`
   * (per spec §6.6) but uses string keys for structural equality.
   */
  private readonly routes = new Map<string, RouteAdvert[]>();

  /**
   * Best (highest) seq seen per destination, hex(NodeId) → seq.
   *
   * This is the DURABLE SEQUENCE FLOOR — it survives route expiry.
   *
   * Per the hardening audit (Blocker C): "If route state expires or is
   * garbage-collected and a lower sequence becomes acceptable again, you
   * have a stale-advertisement problem. Gateway A seq=100 could disappear.
   * Then later: old Gateway A advert seq=42 must NOT suddenly become valid
   * just because local state forgot that 100 existed."
   *
   * `removeStale()` does NOT clear this map. The seq floor is only cleared
   * by explicit `clearSequenceFloor()` (operator action, e.g. node restart
   * with a fresh identity) or `clear()` (full table reset).
   */
  private readonly bestSeq = new Map<string, number>();

  /**
   * Optional TTL for the sequence floor (unix seconds). If set, a seq floor
   * older than this is considered stale and MAY be cleared. Defaults to
   * Infinity (never auto-clear). Production SHOULD set a conservative TTL
   * (e.g. 7 days) so that a gateway that genuinely restarts with seq=0
   * after a long outage can re-establish — but only after a long period,
   * not a brief route expiry.
   */
  private readonly seqFloorTtlSeconds: number;

  /**
   * @param options.seqFloorTtlSeconds  Optional TTL for the durable sequence
   *   floor. A seq floor older than this MAY be cleared by `removeStale()`.
   *   Defaults to Infinity (never auto-clear). Production SHOULD set a
   *   conservative value (e.g. 604800 = 7 days).
   */
  constructor(options?: { seqFloorTtlSeconds?: number }) {
    this.seqFloorTtlSeconds = options?.seqFloorTtlSeconds ?? Number.POSITIVE_INFINITY;
  }

  /**
   * Add or update a route for `advert.destination`.
   *
   * Per spec §6.3 + §6.6:
   *   - Rejects (throws CborError MALFORMED) if the advert's seq regresses
   *     below the best known seq for that destination (anti-replay).
   *   - Rejects (throws CborError MALFORMED) if the advert's pathVector
   *     contains a structural loop (any duplicate NodeId).
   *   - Otherwise: if a route with the same pathVector already exists, it
   *     is REPLACED (refresh with updated metric/expiresAt/seq). If not,
   *     the advert is added as a NEW alternative route.
   *   - Updates the best-known seq for the destination if advert.seq is
   *     higher than the previously-recorded best.
   *
   * This function does NOT verify the originSig — that is the caller's
   * responsibility (call `verifyRouteAdvert` before `addRoute`). The
   * metric is stored as-is (UNTRUSTED — spec §6.3 "Metric integrity").
   *
   * ⚠️  The caller SHOULD overwrite `advert.metric.reputation` with the
   * local node's own computed reputation before adding the route (I16).
   * This function does not enforce that — it cannot, since "locally
   * computed" is a policy decision, not a structural property.
   *
   * @param advert  the route advert to add (must be structurally valid)
   * @throws CborError(MALFORMED) if the advert is structurally invalid,
   *         if its seq regresses, or if its pathVector contains a loop.
   */
  addRoute(advert: RouteAdvert): void {
    // Structural validation first — never accept malformed adverts.
    validateRouteAdvert(advert);

    const destHex = bytesToHex(advert.destination);

    // Seq regression check (spec §6.3).
    const bestKnown = this.bestSeq.get(destHex) ?? 0;
    if (isSeqRegression(advert.seq, bestKnown)) {
      throw new CborError(
        `RouteAdvert seq ${advert.seq} regresses below best known ${bestKnown} for destination`,
        "MALFORMED",
      );
    }

    // Structural loop check — pathVector must have no duplicates.
    if (hasDuplicateNodeId(advert.pathVector)) {
      throw new CborError(
        "RouteAdvert.pathVector contains a duplicate NodeId (structural loop)",
        "MALFORMED",
      );
    }

    // Update best-known seq for this destination (durable sequence floor).
    if (advert.seq > bestKnown) {
      this.bestSeq.set(destHex, advert.seq);
      // Track when we saw this floor, for TTL-based expiry.
      this.seqFloorSeen.set(destHex, { seq: advert.seq, seenAt: Date.now() / 1000 });
    }

    // Add or update: replace if same pathVector exists, else append.
    const routes = this.routes.get(destHex) ?? [];
    const existingIdx = routes.findIndex((r) =>
      samePathVector(r.pathVector, advert.pathVector),
    );
    if (existingIdx >= 0) {
      routes[existingIdx] = advert;
    } else {
      routes.push(advert);
    }
    this.routes.set(destHex, routes);
  }

  /**
   * Return the route to `destination` with the lowest computed cost
   * (using DEFAULT_ROUTE_WEIGHTS), or null if no route is known.
   *
   * Ties are broken by insertion order (the first-inserted of the
   * equal-cost routes wins). This is deliberate — it makes the selection
   * deterministic and reproducible for the conformance suite.
   *
   * Does NOT filter by expiry — the caller is responsible for calling
   * `removeStale(now)` periodically. A stale route MAY be returned if the
   * caller hasn't garbage-collected yet.
   *
   * @param destination  32-byte NodeId of the destination
   * @returns            the cheapest RouteAdvert, or null if none known
   */
  bestRoute(destination: Uint8Array): RouteAdvert | null {
    const destHex = bytesToHex(destination);
    const routes = this.routes.get(destHex);
    if (!routes || routes.length === 0) return null;
    let best: RouteAdvert | null = null;
    let bestCost = Infinity;
    for (const r of routes) {
      const cost = computeRouteCost(r.metric);
      if (cost < bestCost) {
        bestCost = cost;
        best = r;
      }
    }
    return best;
  }

  /**
   * Return up to `n` routes to `destination` whose pathVectors share no
   * intermediate nodes. Implements the "at least 2 disjoint routes per
   * active destination where available" requirement of spec §6.6.
   *
   * "Intermediate" means every NodeId in the pathVector EXCEPT the
   * destination itself (which is shared by all routes to that destination
   * by definition, and is not considered an intermediate relay).
   *
   * Selection is greedy: candidates are sorted by ascending cost (cheapest
   * first), then iterated; each candidate whose intermediate-node set is
   * disjoint from the union of all already-selected routes' intermediate
   * sets is added. Stops when `n` routes are selected or candidates are
   * exhausted.
   *
   * The greedy approach is not guaranteed to find the maximum disjoint
   * set, but it is O(n²) and gives the operationally-desirable property
   * that the primary route is the absolute cheapest, the secondary is the
   * cheapest that doesn't share intermediates with the primary, etc.
   *
   * @param destination  32-byte NodeId of the destination
   * @param n            maximum number of disjoint routes to return
   * @returns            up to `n` disjoint routes, cheapest first
   */
  disjointRoutes(destination: Uint8Array, n: number): RouteAdvert[] {
    if (n <= 0) return [];
    const destHex = bytesToHex(destination);
    const routes = this.routes.get(destHex);
    if (!routes || routes.length === 0) return [];

    // Sort candidates by ascending cost (cheapest first).
    const sorted = routes
      .map((r) => ({ route: r, cost: computeRouteCost(r.metric) }))
      .sort((a, b) => a.cost - b.cost);

    const selected: RouteAdvert[] = [];
    const usedIntermediates = new Set<string>();

    for (const { route } of sorted) {
      if (selected.length >= n) break;

      // Intermediate nodes = pathVector minus the destination itself.
      // (All routes to `destination` share the destination by definition.)
      const intermediates: string[] = [];
      let conflict = false;
      for (const id of route.pathVector) {
        if (bytesEqual(id, destination)) continue; // skip destination
        const hex = bytesToHex(id);
        if (usedIntermediates.has(hex)) {
          conflict = true;
          break;
        }
        intermediates.push(hex);
      }
      if (conflict) continue;

      selected.push(route);
      for (const hex of intermediates) usedIntermediates.add(hex);
    }

    return selected;
  }

  /**
   * Remove all routes whose `expiresAt < now`. Per spec §6.3 + §4.4: a
   * descriptor/advert older than its `expiresAt` MUST NOT be used for
   * routing and MUST NOT be forwarded. This function enforces the local
   * half of that requirement by garbage-collecting expired entries.
   *
   * Routes with `expiresAt === now` are kept (the spec says "older than",
   * i.e. strictly less than). When all routes for a destination are
   * removed, the destination entry is deleted — but the DURABLE SEQUENCE
   * FLOOR is NOT cleared (hardening audit Blocker C). A stale advert with
   * a lower seq will still be rejected even after all routes have expired.
   *
   * The seq floor MAY be cleared by `clearSequenceFloor()` (operator action)
   * or auto-cleared if `seqFloorTtlSeconds` is set and the floor is older
   * than that TTL.
   *
   * @param now  current time in unix seconds (passed in for testability)
   */
  removeStale(now: number): void {
    for (const [destHex, routes] of this.routes.entries()) {
      const fresh = routes.filter((r) => r.expiresAt >= now);
      if (fresh.length === 0) {
        this.routes.delete(destHex);
        // NOTE: We do NOT clear this.bestSeq here. The sequence floor is
        // durable — it survives route expiry. This is the fix for the
        // hardening audit's stale-advertisement finding.
        // (Only clear if the seqFloorTtl has elapsed, which we track
        // separately via the last-seen timestamp on the floor.)
      } else if (fresh.length !== routes.length) {
        this.routes.set(destHex, fresh);
      }
    }
    // Auto-clear seq floors that have exceeded their TTL (if configured).
    // This is separate from route expiry — the TTL is much longer (days,
    // not minutes) so that a gateway restart after a genuine long outage
    // can re-establish, but a brief route expiry cannot.
    if (this.seqFloorTtlSeconds !== Number.POSITIVE_INFINITY) {
      for (const [destHex, floor] of this.seqFloorSeen.entries()) {
        if (now - floor.seenAt > this.seqFloorTtlSeconds) {
          this.bestSeq.delete(destHex);
          this.seqFloorSeen.delete(destHex);
        }
      }
    }
  }

  /**
   * The durable sequence floor per destination. Maps hex(NodeId) → {seq, seenAt}.
   * `seenAt` is the unix time we last saw a advert with this seq — used for
   * TTL-based expiry (only if `seqFloorTtlSeconds` is configured).
   */
  private readonly seqFloorSeen = new Map<string, { seq: number; seenAt: number }>();

  /**
   * Explicitly clear the durable sequence floor for a destination (operator
   * action — e.g. after confirming a gateway has genuinely restarted with a
   * fresh identity). Use sparingly; the floor exists to prevent stale adverts.
   */
  clearSequenceFloor(destination: Uint8Array): void {
    const key = bytesToHex(destination);
    this.bestSeq.delete(key);
    this.seqFloorSeen.delete(key);
  }

  /**
   * Get the current durable sequence floor for a destination, or 0 if none.
   * Useful for diagnostics and tests.
   */
  getSequenceFloor(destination: Uint8Array): number {
    return this.bestSeq.get(bytesToHex(destination)) ?? 0;
  }

  /**
   * Return a SNAPSHOT array of all routes currently in the table.
   *
   * The returned array is a new array (mutations to it do not affect the
   * table). The RouteAdvert objects inside are shallow copies (the
   * pathVector array is copied, but the underlying Uint8Array NodeIds are
   * shared — they are treated as immutable throughout the SNP codebase).
   * Mutating the snapshot's RouteAdvert objects does not affect the table.
   *
   * @returns  a new array containing shallow copies of all routes
   */
  allRoutes(): RouteAdvert[] {
    const result: RouteAdvert[] = [];
    for (const routes of this.routes.values()) {
      for (const r of routes) {
        // Shallow copy: advert object + pathVector array. Uint8Arrays are
        // treated as immutable (never mutated in place by SNP code).
        result.push({
          ...r,
          pathVector: [...r.pathVector],
          metric: { ...r.metric },
        });
      }
    }
    return result;
  }

  /**
   * Return the number of routes currently in the table (across all
   * destinations). Useful for diagnostics and conformance testing.
   */
  size(): number {
    let n = 0;
    for (const routes of this.routes.values()) n += routes.length;
    return n;
  }

  /**
   * Return the list of distinct destination NodeIds the table has routes
   * for. Useful for diagnostics (e.g. listing all known gateways).
   */
  destinations(): Uint8Array[] {
    const result: Uint8Array[] = [];
    for (const routes of this.routes.values()) {
      if (routes.length > 0) result.push(routes[0].destination);
    }
    return result;
  }
}

// ─── Gateway migration detection (spec §6.7) ───────────────────────────────

/**
 * Select the best route to a DIFFERENT gateway than `failedGatewayId`.
 *
 * Implements the "Gateway A disappears, traffic continues via Gateway B"
 * logic of spec §6.7. Iterates through all known gateway routes in the
 * table, excludes:
 *   - the failed gateway (by destination NodeId)
 *   - routes whose destType is not "gateway"
 *   - routes whose expiresAt < now (stale)
 * and returns the one with the lowest computed cost (using
 * DEFAULT_ROUTE_WEIGHTS), or null if no alternate gateway is available.
 *
 * This is the route-selection half of gateway migration. The other half
 * (preserving the circuit ID across the switch, keeping the virtual
 * interface up, etc.) is implemented by the circuit manager, not here.
 *
 * Per spec §6.7 "Honesty about the limit": this function cannot preserve a
 * live TCP connection through the migration — the origin-side socket lived
 * on the failed gateway's kernel and died with it. What this function
 * enables is: NEW connections succeed immediately via Gateway B, the
 * virtual interface stays up, and the client's virtual IP is stable.
 *
 * @param table             the route table to search
 * @param failedGatewayId   32-byte NodeId of the failed gateway to avoid
 * @param now               current time in unix seconds (for stale filtering)
 * @returns                 the best RouteAdvert to a different gateway, or
 *                          null if none is available
 */
export function selectAlternateGateway(
  table: RouteTable,
  failedGatewayId: Uint8Array,
  now: number,
): RouteAdvert | null {
  const all = table.allRoutes();
  let best: RouteAdvert | null = null;
  let bestCost = Infinity;

  for (const r of all) {
    if (r.destType !== "gateway") continue;
    if (bytesEqual(r.destination, failedGatewayId)) continue;
    if (r.expiresAt < now) continue; // stale

    const cost = computeRouteCost(r.metric);
    if (cost < bestCost) {
      bestCost = cost;
      best = r;
    }
  }

  return best;
}
