/**
 * SNP Gateway Protocol (L7) — Internet egress on behalf of offline nodes
 *
 * Source: 02-PROTOCOL-SPEC.md §8 "Gateway protocol (L7)"
 *         §5.1 "GatewayAdvert"
 *         §6.7 "Gateway migration"
 * Source: 05-CIVIC-CONTENT-CONSISTENCY.md §A3 (gateway contribution proof)
 * Source: 04-THREAT-MODEL.md T9 (SSRF)
 * Source: 00-AUDIT.md (R7 — the receipt-farming bug the gateway receipts close)
 *
 * This module is what makes ShareNet a "bearer" rather than just a content
 * store. A node with no Internet egress of its own can ask a gateway to fetch
 * a URL on its behalf (Mode A — TransitRequest/TransitResponse, content-
 * addressed body reuses the Class A CAS) or open a raw TCP/UDP circuit to the
 * real Internet (Mode B/C — CircuitOpen). The gateway enforces an explicit
 * egress policy: which ports, how many bytes, what TLS termination, and
 * critically, which destinations — RFC 1918 / loopback / link-local /
 * multicast egress is REJECTED BY DEFAULT. Without that check an open gateway
 * is an SSRF pivot into its operator's LAN (T9).
 *
 * Structures defined here:
 *
 *   - GatewayAdvert    — capacity + egress policy + cost hint, signed by the
 *                        gateway's NodeIdentity under SIG_CONTEXTS.gatewayAdvert.
 *                        Separate from NodeDescriptor because it changes minute
 *                        to minute (capacity, quota) while identity does not.
 *                        Spec §5.1.
 *   - TransitRequest   — a Mode A "please fetch this URL for me" bundle,
 *                        signed by the client under SIG_CONTEXTS.transitRequest.
 *                        The body of the response is a content-addressed Class A
 *                        object, so it inherits chunking, Merkle verification,
 *                        and resumable transfer for free (§8.2).
 *   - TransitResponse  — the gateway's attestation that it performed a fetch,
 *                        signed by the gateway under SIG_CONTEXTS.transitResponse.
 *                        `gatewaySig` is what makes GATEWAY_PLAINTEXT accountable
 *                        (§8.2): the client knows exactly which gateway saw the
 *                        plaintext.
 *   - CircuitOpen      — a Mode B/C "open a TCP/UDP circuit to host:port"
 *                        frame payload. Not signed at this layer — it is
 *                        authenticated at the frame layer (Noise_IK + AEAD).
 *
 * Egress policy enforcement is THE security-critical surface. `isPrivateDestination`
 * implements invariant I18 (SSRF defence, T9). `enforceEgressPolicy` is the
 * single chokepoint that combines all checks; gateways MUST call it before
 * acting on a TransitRequest. The check is fail-closed (I17): a TransitRequest
 * whose `tlsTermination` is not supported by the gateway is rejected, never
 * silently downgraded to plaintext.
 *
 * @ invariant I1  — All signed structures use SNP-CBOR with length-first key ordering
 * @ invariant I2  — Every signature is over SIG_CONTEXT ‖ CBOR(payload)
 * @ invariant I3  — Ed25519 uses raw 32-byte public keys on the wire
 * @ invariant I4  — NodeId = SHA-256("SNP/0.1 node\0" ‖ pk), never the bare key
 * @ invariant I13 — Civic Points are never minted by the claimant. TransitRequest
 *                   is signed by the client (the beneficiary); TransitResponse is
 *                   signed by the gateway (the party that bore the real egress cost).
 *                   Neither party can forge the other's attestation.
 * @ invariant I17 — Mode/tlsTermination downgrade is fail-closed. A gateway that
 *                   does not support the requested tlsTermination rejects the
 *                   request; it MUST NOT silently fall back to a weaker mode.
 * @ invariant I18 — Gateways reject RFC 1918 / loopback / link-local / multicast
 *                   egress by default. `isPrivateDestination` is the implementation.
 * @ invariant I20 — verify returns false on a bad signature; never throws.
 *                   validate throws CborError(MALFORMED) on structural problems.
 */

import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  INTERNET_MODES,
  TLS_TERMINATIONS,
  type InternetMode,
  type TlsTermination,
} from "./constants";
import {
  type CborValue,
  CborError,
  cborMap,
  encode as cborEncode,
  decode as cborDecode,
} from "./cbor";
import { sign, verify } from "./crypto";

// ─── Frozen sizes ──────────────────────────────────────────────────────────

/** NodeId / ObjectId / RendezvousIdentity byte length (32 bytes). */
const NODE_ID_BYTES = 32;

/** TransitRequest.reqId byte length (16 bytes — replay defence). */
const REQ_ID_BYTES = 16;

/** Minimum valid TCP/UDP port (port 0 is reserved and rejected). */
const MIN_PORT = 1;

/** Maximum valid TCP/UDP port. */
const MAX_PORT = 65535;

// ─── Internal validation primitives ────────────────────────────────────────
//
// These throw `CborError(MALFORMED)` on any structural violation. They are
// called from the public `validateXxx` functions, which are in turn called
// from signers (fail-fast on bad input) and verifiers (wrapped in try/catch
// so a malformed structure returns false rather than throwing — I20).

/** Assert that `v` is a Uint8Array of exactly `expected` bytes. */
function assertBytes(
  v: unknown,
  expected: number,
  field: string,
): asserts v is Uint8Array {
  if (!(v instanceof Uint8Array) || v.length !== expected) {
    const got =
      v instanceof Uint8Array ? `${v.length} bytes` : typeof v;
    throw new CborError(
      `${field} must be a ${expected}-byte Uint8Array; got ${got}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a Uint8Array of exactly `expected` bytes, OR null. */
function assertBytesOrNull(
  v: unknown,
  expected: number,
  field: string,
): asserts v is Uint8Array | null {
  if (v === null) return;
  if (!(v instanceof Uint8Array) || v.length !== expected) {
    const got =
      v instanceof Uint8Array ? `${v.length} bytes` : typeof v;
    throw new CborError(
      `${field} must be null or a ${expected}-byte Uint8Array; got ${got}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a Uint8Array (any length) or null. */
function assertBytesOrNullAny(
  v: unknown,
  field: string,
): asserts v is Uint8Array | null {
  if (v === null) return;
  if (!(v instanceof Uint8Array)) {
    throw new CborError(
      `${field} must be null or a Uint8Array; got ${typeof v}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a non-negative safe integer (unix seconds or byte count). */
function assertUint(v: unknown, field: string): asserts v is number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new CborError(
      `${field} must be a non-negative integer; got ${v}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a non-negative safe integer or null. */
function assertUintOrNull(
  v: unknown,
  field: string,
): asserts v is number | null {
  if (v === null) return;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new CborError(
      `${field} must be null or a non-negative integer; got ${v}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a positive safe integer (> 0). */
function assertPositiveUint(v: unknown, field: string): asserts v is number {
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
    throw new CborError(
      `${field} must be a positive integer; got ${v}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a boolean. */
function assertBool(v: unknown, field: string): asserts v is boolean {
  if (typeof v !== "boolean") {
    throw new CborError(
      `${field} must be a boolean; got ${typeof v}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a non-empty string. */
function assertNonEmptyString(v: unknown, field: string): asserts v is string {
  if (typeof v !== "string" || v.length === 0) {
    throw new CborError(
      `${field} must be a non-empty string; got ${typeof v === "string" ? "empty" : typeof v}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a string (may be empty). */
function assertString(v: unknown, field: string): asserts v is string {
  if (typeof v !== "string") {
    throw new CborError(
      `${field} must be a string; got ${typeof v}`,
      "MALFORMED",
    );
  }
}

/** Assert that `v` is a Map<string, string> (CBOR map of tstr => tstr). */
function assertStringMap(
  v: unknown,
  field: string,
): asserts v is Map<string, string> {
  if (!(v instanceof Map)) {
    throw new CborError(
      `${field} must be a Map<string, string>; got ${v === null ? "null" : typeof v}`,
      "MALFORMED",
    );
  }
  for (const [k, val] of v.entries()) {
    if (typeof k !== "string" || typeof val !== "string") {
      throw new CborError(
        `${field} must have string keys and string values; got key=${typeof k}, value=${typeof val}`,
        "MALFORMED",
      );
    }
  }
}

// ─── GatewayAdvert (spec §5.1) ─────────────────────────────────────────────

/**
 * Egress policy advertised by a gateway. This is the contract a client accepts
 * when it routes a TransitRequest through the gateway.
 *
 * CDDL (02-PROTOCOL-SPEC.md §5.1):
 *   egressPolicy = {
 *     allowedPorts:   [* uint] / "any",
 *     blockedPorts:   [* uint],
 *     dnsAvailable:   bool,
 *     tlsTermination: [* "GATEWAY_PLAINTEXT" / "PAYLOAD_E2E"],
 *     maxBytesPerReq: uint,
 *     contentPolicy:  tstr          ; operator-declared, e.g. "open" / "http-only"
 *   }
 */
export interface EgressPolicy {
  /** Allowed TCP/UDP ports, or "any" for no allowlist. */
  readonly allowedPorts: "any" | number[];
  /** Ports always rejected, even if in allowedPorts. Takes precedence. */
  readonly blockedPorts: number[];
  /** Whether the gateway will resolve DNS on behalf of clients. */
  readonly dnsAvailable: boolean;
  /** TLS termination modes the gateway supports (I17 — checked at request time). */
  readonly tlsTermination: TlsTermination[];
  /** Hard cap on response bytes per request. */
  readonly maxBytesPerReq: number;
  /** Operator-declared content policy (advisory, human-readable). */
  readonly contentPolicy: string;
}

/**
 * Live capacity snapshot. Changes minute to minute (unlike identity).
 *
 * CDDL (02-PROTOCOL-SPEC.md §5.1):
 *   capacity = {
 *     maxCircuits:      uint,
 *     availableBps:     uint,
 *     queueDepth:       uint,
 *     remainingQuota:   uint / null
 *   }
 *
 * `remainingQuota` is essential: a gateway on a metered SIM must be able to
 * say "I have 200 MB left this month" so the network stops routing to it
 * rather than bankrupting a volunteer (spec §5.1).
 */
export interface GatewayCapacity {
  readonly maxCircuits: number;
  readonly availableBps: number;
  readonly queueDepth: number;
  /** Remaining monthly/data quota in bytes, or null if unmetered. */
  readonly remainingQuota: number | null;
}

/**
 * Fields of a GatewayAdvert, excluding the signature.
 *
 * CDDL (02-PROTOCOL-SPEC.md §5.1):
 *   GatewayAdvert = {
 *     nodeId:         bstr .size 32,
 *     modes:          [+ "A" / "B" / "C"],
 *     egressPolicy:   { ... },
 *     capacity:       { ... },
 *     costHint:       uint,
 *     observedRtt:    uint / null,
 *     validFrom:      uint,
 *     expiresAt:      uint,
 *     signature:      bstr .size 64
 *   }
 *
 * Adverts SHOULD expire ≤ 300s (spec §5.1) — capacity fluctuates minute to
 * minute, so a stale advert misleads routing. This is a SHOULD, not MUST,
 * so validateGatewayAdvert does not enforce the bound; callers MAY.
 */
export interface GatewayAdvertFields {
  /** NodeId (32 bytes) of the gateway — SHA-256("SNP/0.1 node\0" ‖ gatewayPubKey). */
  readonly nodeId: Uint8Array;
  /** Internet modes the gateway offers. Non-empty subset of {A, B, C}. */
  readonly modes: InternetMode[];
  /** Egress policy — what the gateway will and will not fetch. */
  readonly egressPolicy: EgressPolicy;
  /** Live capacity snapshot. */
  readonly capacity: GatewayCapacity;
  /** Cost hint (spec §6.4 — input to route cost; higher = more expensive). */
  readonly costHint: number;
  /** Gateway's last observed RTT to the origin Internet (ms), or null if unknown. */
  readonly observedRtt: number | null;
  /** Advert validity start, unix seconds. */
  readonly validFrom: number;
  /** Advert expiry, unix seconds. SHOULD be ≤ validFrom + 300. */
  readonly expiresAt: number;
}

/** A complete GatewayAdvert, including the 64-byte Ed25519 signature. */
export interface GatewayAdvert extends GatewayAdvertFields {
  /** 64-byte Ed25519 signature by the gateway's NodeIdentity under SIG_CONTEXTS.gatewayAdvert. */
  readonly signature: Uint8Array;
}

/** GatewayAdvert without the signature field — what gets signed. */
export type GatewayAdvertUnsigned = Omit<GatewayAdvert, "signature">;

// ─── GatewayAdvert CBOR preimage ───────────────────────────────────────────

/** Build the canonical CBOR preimage map for an EgressPolicy. */
function egressPolicyToCborMap(
  p: EgressPolicy,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["allowedPorts", p.allowedPorts === "any" ? ("any" as CborValue) : (p.allowedPorts as CborValue[])],
    ["blockedPorts", p.blockedPorts as CborValue[]],
    ["dnsAvailable", p.dnsAvailable],
    ["tlsTermination", p.tlsTermination as CborValue[]],
    ["maxBytesPerReq", p.maxBytesPerReq],
    ["contentPolicy", p.contentPolicy],
  ]);
}

/** Build the canonical CBOR preimage map for a GatewayCapacity. */
function capacityToCborMap(
  c: GatewayCapacity,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["maxCircuits", c.maxCircuits],
    ["availableBps", c.availableBps],
    ["queueDepth", c.queueDepth],
    ["remainingQuota", c.remainingQuota as CborValue],
  ]);
}

/**
 * Build the canonical CBOR preimage map for a GatewayAdvert, EXCLUDING the
 * `signature` field. This is the structure fed to `sign` / `verify` under
 * SIG_CONTEXT `"gatewayAdvert"`.
 *
 * The map uses STRING keys; canonical ordering (length-first on the fully-
 * encoded key) is applied at encode time by the SNP-CBOR encoder.
 */
export function gatewayAdvertToCborMap(
  advert: GatewayAdvert | GatewayAdvertUnsigned,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["nodeId", advert.nodeId],
    ["modes", advert.modes as CborValue[]],
    ["egressPolicy", egressPolicyToCborMap(advert.egressPolicy)],
    ["capacity", capacityToCborMap(advert.capacity)],
    ["costHint", advert.costHint],
    ["observedRtt", advert.observedRtt as CborValue],
    ["validFrom", advert.validFrom],
    ["expiresAt", advert.expiresAt],
  ]);
}

// ─── GatewayAdvert validation ──────────────────────────────────────────────

function assertEgressPolicy(p: unknown, field: string): asserts p is EgressPolicy {
  if (typeof p !== "object" || p === null || Array.isArray(p)) {
    throw new CborError(`${field} must be an EgressPolicy object`, "MALFORMED");
  }
  const obj = p as Record<string, unknown>;
  // allowedPorts: [* uint] / "any"
  if (obj.allowedPorts !== "any") {
    if (!Array.isArray(obj.allowedPorts)) {
      throw new CborError(
        `${field}.allowedPorts must be "any" or an array of uint`,
        "MALFORMED",
      );
    }
    for (const port of obj.allowedPorts) {
      if (typeof port !== "number" || !Number.isInteger(port) || port < 0) {
        throw new CborError(
          `${field}.allowedPorts entries must be non-negative integers`,
          "MALFORMED",
        );
      }
    }
  }
  // blockedPorts: [* uint]
  if (!Array.isArray(obj.blockedPorts)) {
    throw new CborError(`${field}.blockedPorts must be an array of uint`, "MALFORMED");
  }
  for (const port of obj.blockedPorts) {
    if (typeof port !== "number" || !Number.isInteger(port) || port < 0) {
      throw new CborError(
        `${field}.blockedPorts entries must be non-negative integers`,
        "MALFORMED",
      );
    }
  }
  assertBool(obj.dnsAvailable, `${field}.dnsAvailable`);
  if (!Array.isArray(obj.tlsTermination)) {
    throw new CborError(`${field}.tlsTermination must be an array`, "MALFORMED");
  }
  for (const t of obj.tlsTermination) {
    if (typeof t !== "string" || !TLS_TERMINATIONS.includes(t as TlsTermination)) {
      throw new CborError(
        `${field}.tlsTermination entries must be one of [${TLS_TERMINATIONS.join(", ")}]; got "${t}"`,
        "MALFORMED",
      );
    }
  }
  assertUint(obj.maxBytesPerReq, `${field}.maxBytesPerReq`);
  assertString(obj.contentPolicy, `${field}.contentPolicy`);
}

function assertGatewayCapacity(c: unknown, field: string): asserts c is GatewayCapacity {
  if (typeof c !== "object" || c === null || Array.isArray(c)) {
    throw new CborError(`${field} must be a GatewayCapacity object`, "MALFORMED");
  }
  const obj = c as Record<string, unknown>;
  assertUint(obj.maxCircuits, `${field}.maxCircuits`);
  assertUint(obj.availableBps, `${field}.availableBps`);
  assertUint(obj.queueDepth, `${field}.queueDepth`);
  assertUintOrNull(obj.remainingQuota, `${field}.remainingQuota`);
}

/**
 * Validate the STRUCTURE of a GatewayAdvert against the CDDL constraints.
 * Throws `CborError(MALFORMED)` on any violation.
 *
 * Does NOT check signature validity (that is `verifyGatewayAdvert`'s job) and
 * does NOT enforce the SHOULD expiry bound (≤ 300s) — that is a policy check.
 */
export function validateGatewayAdvert(advert: GatewayAdvert): void {
  assertBytes(advert.nodeId, NODE_ID_BYTES, "GatewayAdvert.nodeId");
  if (!Array.isArray(advert.modes) || advert.modes.length === 0) {
    throw new CborError(
      "GatewayAdvert.modes must be a non-empty array",
      "MALFORMED",
    );
  }
  for (const m of advert.modes) {
    if (typeof m !== "string" || !INTERNET_MODES.includes(m as InternetMode)) {
      throw new CborError(
        `GatewayAdvert.modes entries must be one of [${INTERNET_MODES.join(", ")}]; got "${m}"`,
        "MALFORMED",
      );
    }
  }
  assertEgressPolicy(advert.egressPolicy, "GatewayAdvert.egressPolicy");
  assertGatewayCapacity(advert.capacity, "GatewayAdvert.capacity");
  assertUint(advert.costHint, "GatewayAdvert.costHint");
  assertUintOrNull(advert.observedRtt, "GatewayAdvert.observedRtt");
  assertUint(advert.validFrom, "GatewayAdvert.validFrom");
  assertUint(advert.expiresAt, "GatewayAdvert.expiresAt");
  if (advert.expiresAt <= advert.validFrom) {
    throw new CborError(
      `GatewayAdvert.expiresAt (${advert.expiresAt}) must be strictly greater than validFrom (${advert.validFrom})`,
      "MALFORMED",
    );
  }
  assertBytes(advert.signature, ED25519_SIGNATURE_BYTES, "GatewayAdvert.signature");
}

// ─── GatewayAdvert sign / verify ───────────────────────────────────────────

/**
 * Sign a GatewayAdvert using the gateway's NodeIdentity secret key.
 *
 * The signature is over `SIG_CONTEXTS.gatewayAdvert ‖ CBOR(advert without signature)`,
 * per invariant I2. The gateway is attesting its own capacity and policy; this
 * is NOT a contribution proof (the contribution proof for gateway egress is
 * the GatewayReceipt in receipts.ts, counter-signed by the client).
 *
 * @param gatewaySecretKey  32-byte Ed25519 secret key of the gateway's NodeIdentity
 * @param fields            the GatewayAdvert fields (without signature)
 * @returns                 a complete GatewayAdvert including the 64-byte signature
 */
export function signGatewayAdvert(
  gatewaySecretKey: Uint8Array,
  fields: GatewayAdvertFields,
): GatewayAdvert {
  if (gatewaySecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${gatewaySecretKey.length}`,
    );
  }
  // Validate structure before signing so we never produce a signature over
  // malformed input. Use a zero-filled placeholder signature to satisfy the
  // validator's length check; the real signature is produced below.
  validateGatewayAdvert({
    ...fields,
    signature: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = gatewayAdvertToCborMap(fields);
  const signature = sign(gatewaySecretKey, "gatewayAdvert", preimage);
  return { ...fields, signature };
}

/**
 * Verify a GatewayAdvert's signature against the gateway's public key.
 *
 * Returns `false` on any failure — bad signature, wrong key length, malformed
 * fields. NEVER throws for a bad signature (I20).
 *
 * @param advert              the GatewayAdvert to verify
 * @param gatewayPublicKey    32-byte Ed25519 public key of the gateway's NodeIdentity
 *                            (NOT a NodeId — NodeId is a SHA-256 hash, I4. Obtain
 *                            the public key out-of-band, e.g. from a NodeDescriptor.)
 * @returns                   true iff the signature is valid for the advert fields
 */
export function verifyGatewayAdvert(
  advert: GatewayAdvert,
  gatewayPublicKey: Uint8Array,
): boolean {
  if (gatewayPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (advert.signature.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateGatewayAdvert(advert);
  } catch {
    return false;
  }
  const preimage = gatewayAdvertToCborMap(advert);
  return verify(gatewayPublicKey, "gatewayAdvert", preimage, advert.signature);
}

// ─── GatewayAdvert predicates ──────────────────────────────────────────────

/**
 * Check whether a GatewayAdvert has expired.
 *
 * Per spec §5.1: "a descriptor older than `expiresAt` MUST NOT be used for
 * routing." Adverts SHOULD expire ≤ 300s. Returns true iff `now >= expiresAt`.
 *
 * @param advert  the advert to check
 * @param now     current time in unix seconds (passed in for testability)
 */
export function isAdvertExpired(advert: GatewayAdvert, now: number): boolean {
  return now >= advert.expiresAt;
}

/**
 * Check whether the gateway offers a given Internet mode (A, B, or C).
 */
export function hasMode(advert: GatewayAdvert, mode: InternetMode): boolean {
  return advert.modes.includes(mode);
}

/**
 * Check whether the gateway supports a given TLS termination mode.
 *
 * This is the I17 chokepoint for TransitRequest: a request whose
 * `tlsTermination` is not in this list MUST be rejected, never silently
 * downgraded. `enforceEgressPolicy` calls this; callers constructing a
 * TransitRequest SHOULD also call it client-side to fail fast.
 */
export function supportsTlsTermination(
  advert: GatewayAdvert,
  term: TlsTermination,
): boolean {
  return advert.egressPolicy.tlsTermination.includes(term);
}

// ─── TransitRequest (Mode A bundle, spec §8.2) ─────────────────────────────

/**
 * Fields of a TransitRequest, excluding the clientSig.
 *
 * CDDL (02-PROTOCOL-SPEC.md §8.2):
 *   TransitRequest = {
 *     reqId:           bstr .size 16,
 *     method:          tstr,
 *     url:             tstr,
 *     headers:         { * tstr => tstr },
 *     body:            bstr / null,
 *     tlsTermination:  "GATEWAY_PLAINTEXT" / "PAYLOAD_E2E",   ; MANDATORY
 *     maxResponseBytes: uint,                                  ; MANDATORY
 *     deadline:        uint,                                   ; MANDATORY
 *     replyTo:         bstr .size 32,   ; rendezvous identity, not NodeId
 *     acceptGateways:  [* bstr .size 32] / "any",
 *     clientSig:       bstr .size 64
 *   }
 *
 * `tlsTermination` is MANDATORY. A Mode A request without it is a negative
 * vector (audit I17 — silent plaintext is forbidden); `validateTransitRequest`
 * rejects it. The gateway does not get to pick a default.
 *
 * `replyTo` is a 32-byte RendezvousIdentity (X25519 public key), NOT a NodeId.
 * The gateway uses it to address the response back to the client without
 * linking the request to the client's persistent identity.
 *
 * `acceptGateways` is either "any" or an explicit allowlist of gateway NodeIds.
 * A client that wants a specific gateway's `gatewaySig` (e.g. because it
 * trusts that gateway with plaintext) lists only that gateway.
 */
export interface TransitRequestFields {
  /** 16-byte random request identifier (replay defence, response correlation). */
  readonly reqId: Uint8Array;
  /** HTTP method (e.g. "GET", "POST"). */
  readonly method: string;
  /** Absolute URL to fetch. */
  readonly url: string;
  /** HTTP request headers. Map of header name → value. */
  readonly headers: Map<string, string>;
  /** Request body, or null for bodyless requests. */
  readonly body: Uint8Array | null;
  /** TLS termination mode — MANDATORY. GATEWAY_PLAINTEXT or PAYLOAD_E2E. */
  readonly tlsTermination: TlsTermination;
  /** Max response bytes the client will accept. MANDATORY, must be > 0. */
  readonly maxResponseBytes: number;
  /** Request deadline, unix seconds. Past this, the gateway rejects. MANDATORY. */
  readonly deadline: number;
  /** 32-byte X25519 rendezvous public key for response delivery. NOT a NodeId. */
  readonly replyTo: Uint8Array;
  /** "any" or an array of acceptable gateway NodeIds (32 bytes each). */
  readonly acceptGateways: "any" | Uint8Array[];
}

/** A complete TransitRequest, including the 64-byte clientSig. */
export interface TransitRequest extends TransitRequestFields {
  /** 64-byte Ed25519 signature by the client under SIG_CONTEXTS.transitRequest. */
  readonly clientSig: Uint8Array;
}

/** TransitRequest without the clientSig field — what gets signed. */
export type TransitRequestUnsigned = Omit<TransitRequest, "clientSig">;

/**
 * Build the canonical CBOR preimage map for a TransitRequest, EXCLUDING the
 * `clientSig` field. This is the structure fed to `sign` / `verify` under
 * SIG_CONTEXT `"transitRequest"`.
 *
 * `headers` is encoded as a nested CBOR map (tstr => tstr). `acceptGateways`
 * is encoded as either the string "any" or an array of 32-byte bstrs.
 */
export function transitRequestToCborMap(
  request: TransitRequest | TransitRequestUnsigned,
): Map<string | Uint8Array, CborValue> {
  // Convert headers (Map<string, string>) to a CborValue map.
  const headersCbor: Map<string | Uint8Array, CborValue> = new Map();
  for (const [k, v] of request.headers.entries()) {
    headersCbor.set(k, v);
  }
  // acceptGateways: "any" or array of bstr
  const acceptGatewaysCbor: CborValue =
    request.acceptGateways === "any"
      ? "any"
      : (request.acceptGateways as CborValue[]);

  return cborMap([
    ["reqId", request.reqId],
    ["method", request.method],
    ["url", request.url],
    ["headers", headersCbor],
    ["body", request.body as CborValue],
    ["tlsTermination", request.tlsTermination],
    ["maxResponseBytes", request.maxResponseBytes],
    ["deadline", request.deadline],
    ["replyTo", request.replyTo],
    ["acceptGateways", acceptGatewaysCbor],
  ]);
}

/**
 * Validate the STRUCTURE of a TransitRequest against the CDDL constraints.
 * Throws `CborError(MALFORMED)` on any violation.
 *
 * CRITICAL: this enforces the I17 negative vector — a TransitRequest WITHOUT
 * a valid `tlsTermination` field is rejected. Silent plaintext is forbidden.
 * The audit (06-CONFORMANCE-AND-AI-MODEL.md §A5) lists "Mode A request without
 * tlsTermination" as a MUST-REJECT conformance vector.
 *
 * Checks:
 *   1. `reqId` is a 16-byte Uint8Array.
 *   2. `method` is a non-empty string.
 *   3. `url` is a non-empty string.
 *   4. `headers` is a Map<string, string>.
 *   5. `body` is null or a Uint8Array.
 *   6. `tlsTermination` is one of TLS_TERMINATIONS (MANDATORY — I17).
 *   7. `maxResponseBytes` is a positive integer (> 0).
 *   8. `deadline` is a positive integer (> 0).
 *   9. `replyTo` is a 32-byte Uint8Array (rendezvous identity, not NodeId).
 *  10. `acceptGateways` is "any" or an array of 32-byte Uint8Arrays.
 *  11. `clientSig` is a 64-byte Uint8Array.
 */
export function validateTransitRequest(request: TransitRequest): void {
  assertBytes(request.reqId, REQ_ID_BYTES, "TransitRequest.reqId");
  assertNonEmptyString(request.method, "TransitRequest.method");
  assertNonEmptyString(request.url, "TransitRequest.url");
  assertStringMap(request.headers, "TransitRequest.headers");
  assertBytesOrNullAny(request.body, "TransitRequest.body");
  if (
    typeof request.tlsTermination !== "string" ||
    !TLS_TERMINATIONS.includes(request.tlsTermination as TlsTermination)
  ) {
    throw new CborError(
      `TransitRequest.tlsTermination must be one of [${TLS_TERMINATIONS.join(", ")}]; got "${request.tlsTermination}" (I17: mandatory, no silent downgrade)`,
      "MALFORMED",
    );
  }
  assertPositiveUint(request.maxResponseBytes, "TransitRequest.maxResponseBytes");
  assertPositiveUint(request.deadline, "TransitRequest.deadline");
  assertBytes(request.replyTo, NODE_ID_BYTES, "TransitRequest.replyTo");
  if (request.acceptGateways !== "any") {
    if (!Array.isArray(request.acceptGateways)) {
      throw new CborError(
        'TransitRequest.acceptGateways must be "any" or an array of 32-byte Uint8Arrays',
        "MALFORMED",
      );
    }
    for (const g of request.acceptGateways) {
      if (!(g instanceof Uint8Array) || g.length !== NODE_ID_BYTES) {
        throw new CborError(
          "TransitRequest.acceptGateways entries must be 32-byte Uint8Arrays",
          "MALFORMED",
        );
      }
    }
  }
  assertBytes(request.clientSig, ED25519_SIGNATURE_BYTES, "TransitRequest.clientSig");
}

/**
 * Sign a TransitRequest using the client's Ed25519 secret key, producing the
 * `clientSig`.
 *
 * The signature is over `SIG_CONTEXTS.transitRequest ‖ CBOR(request without clientSig)`,
 * per invariant I2. The client is the beneficiary of the gateway's fetch, so
 * its signature binds its economic identity to the request (I13). The gateway
 * cannot forge a request it did not receive.
 *
 * @param clientSecretKey  32-byte Ed25519 secret key of the client
 * @param fields           the TransitRequest fields (without clientSig)
 * @returns                a complete TransitRequest including the 64-byte clientSig
 */
export function signTransitRequest(
  clientSecretKey: Uint8Array,
  fields: TransitRequestFields,
): TransitRequest {
  if (clientSecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${clientSecretKey.length}`,
    );
  }
  validateTransitRequest({
    ...fields,
    clientSig: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = transitRequestToCborMap(fields);
  const clientSig = sign(clientSecretKey, "transitRequest", preimage);
  return { ...fields, clientSig };
}

/**
 * Verify a TransitRequest's `clientSig` against the client's public key.
 *
 * Returns `false` on any failure — bad signature, wrong key length, malformed
 * fields (including a missing/invalid tlsTermination — I17). NEVER throws (I20).
 *
 * @param request           the TransitRequest to verify
 * @param clientPublicKey   32-byte Ed25519 public key of the client
 *                          (NOT a NodeId — NodeId is a hash, I4.)
 * @returns                 true iff clientSig is valid
 */
export function verifyTransitRequest(
  request: TransitRequest,
  clientPublicKey: Uint8Array,
): boolean {
  if (clientPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (request.clientSig.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateTransitRequest(request);
  } catch {
    return false;
  }
  const preimage = transitRequestToCborMap(request);
  return verify(clientPublicKey, "transitRequest", preimage, request.clientSig);
}

/**
 * Check whether a TransitRequest has passed its deadline.
 *
 * Per spec §8.2: a request past `deadline` MUST be rejected. Returns true iff
 * `now >= deadline`.
 *
 * @param request  the request to check
 * @param now      current time in unix seconds (passed in for testability)
 */
export function isRequestExpired(request: TransitRequest, now: number): boolean {
  return now >= request.deadline;
}

// ─── TransitResponse (spec §8.2) ───────────────────────────────────────────

/**
 * Fields of a TransitResponse, excluding the gatewaySig.
 *
 * CDDL (02-PROTOCOL-SPEC.md §8.2):
 *   TransitResponse = {
 *     reqId:      bstr .size 16,
 *     status:     uint,
 *     headers:    { * tstr => tstr },
 *     objectId:   bstr .size 32,     ; body is a Class A object — reuses CAS
 *     fetchedAt:  uint,
 *     gatewayId:  bstr .size 32,
 *     gatewaySig: bstr .size 64      ; gateway attests it performed this fetch
 *   }
 *
 * THE KEY REUSE: the response body is NOT inlined as a bstr. It is stored as
 * a Class A content-addressed object (ObjectId = 32-byte Merkle root), and
 * the TransitResponse carries only the ObjectId. This means the body inherits
 * all of the Class A machinery for free:
 *
 *   - Chunking (gear content-defined chunking, 256 KiB – 4 MiB chunks)
 *   - Merkle verification (RFC 6962, root = SHA-256 over leaf hashes)
 *   - Resumable transfer (a chunk that fails to transfer is re-fetched
 *     without restarting the whole body)
 *   - Deduplication (two clients fetching the same URL get the same ObjectId
 *     and can share chunks)
 *   - Custody receipts (the body can traverse the mesh via the Mode A custody
 *     chain, with each hop attested by the next — see receipts.ts)
 *
 * A gateway fetching content from the origin Internet on the mesh's behalf
 * performs a Class B transit that YIELDS a Class A object. This is the
 * correct, explicit form of what `pointsForBridging` was gesturing at
 * (05-CIVIC-CONTENT-CONSISTENCY.md §B1).
 *
 * `gatewaySig` is what makes GATEWAY_PLAINTEXT accountable — the client knows
 * exactly which gateway saw the plaintext (spec §8.2). Without it, a gateway
 * could deny having performed a fetch it billed for, or could substitute a
 * different response.
 */
export interface TransitResponseFields {
  /** 16-byte request identifier — MUST match the TransitRequest.reqId. */
  readonly reqId: Uint8Array;
  /** HTTP status code (e.g. 200, 404). */
  readonly status: number;
  /** HTTP response headers. Map of header name → value. */
  readonly headers: Map<string, string>;
  /** 32-byte ObjectId (Merkle root) of the response body in the Class A CAS. */
  readonly objectId: Uint8Array;
  /** Time the gateway performed the fetch, unix seconds. */
  readonly fetchedAt: number;
  /** NodeId (32 bytes) of the gateway that performed the fetch. */
  readonly gatewayId: Uint8Array;
}

/** A complete TransitResponse, including the 64-byte gatewaySig. */
export interface TransitResponse extends TransitResponseFields {
  /** 64-byte Ed25519 signature by the gateway under SIG_CONTEXTS.transitResponse. */
  readonly gatewaySig: Uint8Array;
}

/** TransitResponse without the gatewaySig field — what gets signed. */
export type TransitResponseUnsigned = Omit<TransitResponse, "gatewaySig">;

/**
 * Build the canonical CBOR preimage map for a TransitResponse, EXCLUDING the
 * `gatewaySig` field. This is the structure fed to `sign` / `verify` under
 * SIG_CONTEXT `"transitResponse"`.
 */
export function transitResponseToCborMap(
  response: TransitResponse | TransitResponseUnsigned,
): Map<string | Uint8Array, CborValue> {
  const headersCbor: Map<string | Uint8Array, CborValue> = new Map();
  for (const [k, v] of response.headers.entries()) {
    headersCbor.set(k, v);
  }
  return cborMap([
    ["reqId", response.reqId],
    ["status", response.status],
    ["headers", headersCbor],
    ["objectId", response.objectId],
    ["fetchedAt", response.fetchedAt],
    ["gatewayId", response.gatewayId],
  ]);
}

/**
 * Validate the STRUCTURE of a TransitResponse against the CDDL constraints.
 * Throws `CborError(MALFORMED)` on any violation.
 *
 * Checks:
 *   1. `reqId` is a 16-byte Uint8Array.
 *   2. `status` is a non-negative integer (HTTP status code).
 *   3. `headers` is a Map<string, string>.
 *   4. `objectId` is a 32-byte Uint8Array (Merkle root of the body).
 *   5. `fetchedAt` is a non-negative integer.
 *   6. `gatewayId` is a 32-byte Uint8Array (NodeId).
 *   7. `gatewaySig` is a 64-byte Uint8Array.
 */
export function validateTransitResponse(response: TransitResponse): void {
  assertBytes(response.reqId, REQ_ID_BYTES, "TransitResponse.reqId");
  assertUint(response.status, "TransitResponse.status");
  assertStringMap(response.headers, "TransitResponse.headers");
  assertBytes(response.objectId, NODE_ID_BYTES, "TransitResponse.objectId");
  assertUint(response.fetchedAt, "TransitResponse.fetchedAt");
  assertBytes(response.gatewayId, NODE_ID_BYTES, "TransitResponse.gatewayId");
  assertBytes(response.gatewaySig, ED25519_SIGNATURE_BYTES, "TransitResponse.gatewaySig");
}

/**
 * Sign a TransitResponse using the gateway's Ed25519 secret key, producing the
 * `gatewaySig`.
 *
 * The signature is over `SIG_CONTEXTS.transitResponse ‖ CBOR(response without gatewaySig)`,
 * per invariant I2. The gateway is attesting that IT performed this fetch and
 * that the ObjectId is the Merkle root of the body it received from the origin.
 * This is the accountability primitive for GATEWAY_PLAINTEXT mode (§8.2): the
 * client knows exactly which gateway saw the plaintext.
 *
 * @param gatewaySecretKey  32-byte Ed25519 secret key of the gateway
 * @param fields            the TransitResponse fields (without gatewaySig)
 * @returns                 a complete TransitResponse including the 64-byte gatewaySig
 */
export function signTransitResponse(
  gatewaySecretKey: Uint8Array,
  fields: TransitResponseFields,
): TransitResponse {
  if (gatewaySecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${gatewaySecretKey.length}`,
    );
  }
  validateTransitResponse({
    ...fields,
    gatewaySig: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = transitResponseToCborMap(fields);
  const gatewaySig = sign(gatewaySecretKey, "transitResponse", preimage);
  return { ...fields, gatewaySig };
}

/**
 * Verify a TransitResponse's `gatewaySig` against the gateway's public key.
 *
 * Returns `false` on any failure. NEVER throws (I20).
 *
 * @param response           the TransitResponse to verify
 * @param gatewayPublicKey   32-byte Ed25519 public key of the gateway
 *                           (NOT a NodeId — NodeId is a hash, I4.)
 * @returns                  true iff gatewaySig is valid
 */
export function verifyTransitResponse(
  response: TransitResponse,
  gatewayPublicKey: Uint8Array,
): boolean {
  if (gatewayPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (response.gatewaySig.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateTransitResponse(response);
  } catch {
    return false;
  }
  const preimage = transitResponseToCborMap(response);
  return verify(gatewayPublicKey, "transitResponse", preimage, response.gatewaySig);
}

// ─── Egress policy enforcement (spec §8.1) — CRITICAL SECURITY ─────────────

/**
 * Parse a dotted-quad IPv4 address into a 4-byte Uint8Array, or null if the
 * input is not a valid IPv4 address.
 *
 * Strict parsing: exactly 4 octets, each 0–255, no leading zeros (rejects
 * "0177.0.0.1" which some legacy resolvers interpret as octal 127.0.0.1).
 * Single-digit "0" is allowed (e.g. "10.0.0.0").
 */
function parseIPv4(s: string): Uint8Array | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i];
    if (!/^\d{1,3}$/.test(p)) return null;
    // Reject multi-digit leading zeros ("012") — SSRF defence against octal.
    if (p.length > 1 && p[0] === "0") return null;
    const n = parseInt(p, 10);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

/**
 * Parse an IPv6 address (including "::" compression and embedded IPv4 forms
 * like "::ffff:192.168.0.1") into a 16-byte Uint8Array, or null if invalid.
 */
function parseIPv6(s: string): Uint8Array | null {
  // Split on "::" — at most one occurrence.
  const parts = s.split("::");
  if (parts.length > 2) return null;

  let leftGroups: string[];
  let rightGroups: string[];

  if (parts.length === 2) {
    leftGroups = parts[0] === "" ? [] : parts[0].split(":");
    rightGroups = parts[1] === "" ? [] : parts[1].split(":");
  } else {
    leftGroups = parts[0].split(":");
    rightGroups = [];
  }

  const parseGroup = (g: string): number | null => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    return parseInt(g, 16);
  };

  // An embedded IPv4 dotted-quad may appear as the last group of either side
  // (e.g. "::ffff:192.168.0.1" or "0:0:0:0:0:0:10.0.0.1"). It occupies the
  // last 2 groups of the 16-byte address.
  let embeddedV4: Uint8Array | null = null;
  const tryExtractV4 = (groups: string[]): { groups: string[]; v4: Uint8Array | null } => {
    if (groups.length === 0) return { groups, v4: null };
    const last = groups[groups.length - 1];
    if (last.includes(".")) {
      const v4 = parseIPv4(last);
      if (v4 === null) return { groups, v4: null };
      return { groups: groups.slice(0, -1), v4 };
    }
    return { groups, v4: null };
  };

  // Try the right side first (most common: "::ffff:1.2.3.4").
  if (rightGroups.length > 0) {
    const extracted = tryExtractV4(rightGroups);
    rightGroups = extracted.groups;
    embeddedV4 = extracted.v4;
  }
  // If no embedded v4 on the right, try the left (e.g. "1.2.3.4::").
  if (embeddedV4 === null && leftGroups.length > 0) {
    const extracted = tryExtractV4(leftGroups);
    leftGroups = extracted.groups;
    embeddedV4 = extracted.v4;
  }

  const leftVals: number[] = [];
  for (const g of leftGroups) {
    const v = parseGroup(g);
    if (v === null) return null;
    leftVals.push(v);
  }
  const rightVals: number[] = [];
  for (const g of rightGroups) {
    const v = parseGroup(g);
    if (v === null) return null;
    rightVals.push(v);
  }

  const totalGroups = leftVals.length + rightVals.length + (embeddedV4 ? 2 : 0);
  if (parts.length === 2) {
    if (totalGroups > 8) return null;
  } else {
    if (totalGroups !== 8) return null;
  }

  const out = new Uint8Array(16);
  let pos = 0;
  for (const v of leftVals) {
    out[pos++] = (v >> 8) & 0xff;
    out[pos++] = v & 0xff;
  }
  // Zero-filled gap (out is already zero-initialised; just advance pos).
  const gapGroups = 8 - totalGroups;
  pos += gapGroups * 2;
  for (const v of rightVals) {
    out[pos++] = (v >> 8) & 0xff;
    out[pos++] = v & 0xff;
  }
  if (embeddedV4 !== null) {
    out[pos++] = embeddedV4[0];
    out[pos++] = embeddedV4[1];
    out[pos++] = embeddedV4[2];
    out[pos++] = embeddedV4[3];
  }

  return out;
}

/** Check whether a 4-byte IPv4 address is in a private/restricted range. */
function isPrivateIPv4(b: Uint8Array): boolean {
  // 0.0.0.0/8 — "this network" / unspecified
  if (b[0] === 0) return true;
  // 10.0.0.0/8 — RFC 1918 private
  if (b[0] === 10) return true;
  // 127.0.0.0/8 — loopback
  if (b[0] === 127) return true;
  // 169.254.0.0/16 — link-local
  if (b[0] === 169 && b[1] === 254) return true;
  // 172.16.0.0/12 — RFC 1918 private (172.16.0.0 – 172.31.255.255)
  if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return true;
  // 192.168.0.0/16 — RFC 1918 private
  if (b[0] === 192 && b[1] === 168) return true;
  // 224.0.0.0/4 — multicast (224–239)
  if (b[0] >= 224 && b[0] <= 239) return true;
  // 240.0.0.0/4 — reserved (240–255)
  if (b[0] >= 240) return true;
  return false;
}

/** Check whether a 16-byte IPv6 address is in a private/restricted range. */
function isPrivateIPv6(b: Uint8Array): boolean {
  // ::1 — loopback (first 15 bytes zero, last byte 1)
  if (
    b[0] === 0 && b[1] === 0 && b[2] === 0 && b[3] === 0 &&
    b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0 &&
    b[8] === 0 && b[9] === 0 && b[10] === 0 && b[11] === 0 &&
    b[12] === 0 && b[13] === 0 && b[14] === 0 && b[15] === 1
  ) {
    return true;
  }
  // :: — unspecified (all zero)
  let allZero = true;
  for (let i = 0; i < 16; i++) {
    if (b[i] !== 0) { allZero = false; break; }
  }
  if (allZero) return true;
  // fe80::/10 — link-local (first 10 bits = 1111111010)
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;
  // fc00::/7 — unique local addresses (first 7 bits = 1111110 → 0xfc or 0xfd)
  if (b[0] === 0xfc || b[0] === 0xfd) return true;
  // ff00::/8 — multicast
  if (b[0] === 0xff) return true;
  // ::ffff:a.b.c.d — IPv4-mapped IPv6 (first 10 bytes zero, bytes 10–11 = 0xff 0xff)
  if (
    b[0] === 0 && b[1] === 0 && b[2] === 0 && b[3] === 0 &&
    b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0 &&
    b[8] === 0 && b[9] === 0 && b[10] === 0xff && b[11] === 0xff
  ) {
    return isPrivateIPv4(b.subarray(12, 16));
  }
  // ::a.b.c.d — IPv4-compatible IPv6 (deprecated, first 12 bytes zero, not :: or ::1)
  if (
    b[0] === 0 && b[1] === 0 && b[2] === 0 && b[3] === 0 &&
    b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0 &&
    b[8] === 0 && b[9] === 0 && b[10] === 0 && b[11] === 0 &&
    !(b[12] === 0 && b[13] === 0 && b[14] === 0 && b[15] === 0) &&
    !(b[12] === 0 && b[13] === 0 && b[14] === 0 && b[15] === 1)
  ) {
    return isPrivateIPv4(b.subarray(12, 16));
  }
  return false;
}

/**
 * Determine whether a destination host is private/restricted and MUST be
 * rejected by a gateway egress (invariant I18, threat T9 — SSRF defence).
 *
 * Returns true for:
 *   - RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 *   - Loopback: 127.0.0.0/8 (IPv4), ::1 (IPv6)
 *   - Link-local: 169.254.0.0/16 (IPv4), fe80::/10 (IPv6)
 *   - Multicast: 224.0.0.0/4 (IPv4), ff00::/8 (IPv6)
 *   - Unique local: fc00::/7 (IPv6)
 *   - Unspecified: 0.0.0.0/8 (IPv4), :: (IPv6)
 *   - Reserved: 240.0.0.0/4 (IPv4)
 *   - IPv4-mapped IPv6 (::ffff:a.b.c.d) and IPv4-compatible IPv6 (::a.b.c.d):
 *     the embedded IPv4 address is re-checked against the IPv4 private ranges.
 *   - ".local" mDNS hostname suffix
 *   - "localhost" hostname
 *
 * This is the SSRF defence. A gateway MUST reject CircuitOpen / TransitRequest
 * to these destinations unless explicitly configured (I18). Without this check,
 * an open gateway is a pivot into its operator's LAN — an attacker could ask
 * the gateway to fetch http://192.168.1.1/admin and read the response.
 *
 * NOTE: this function checks the LITERAL host string. It does NOT resolve DNS.
 * A hostname like "attacker.com" that resolves to 127.0.0.1 (DNS rebinding)
 * is NOT caught here. Gateways MUST re-check `isPrivateDestination` against
 * the resolved IP address immediately before connecting (TOCTOU defence).
 * Documenting this gap here so callers know the second check is required.
 *
 * @param host  the hostname or IP literal (URL.hostname form — no brackets, no port)
 * @returns     true iff the host is private/loopback/link-local/multicast/reserved
 */
export function isPrivateDestination(host: string): boolean {
  if (typeof host !== "string") return false;
  const h = host.toLowerCase().trim();
  if (h === "") return true; // empty host — treat as invalid/private

  // Hostname checks (case-insensitive).
  if (h === "localhost") return true;
  if (h.endsWith(".local")) return true;

  // IPv4 literal.
  const v4 = parseIPv4(h);
  if (v4 !== null) {
    return isPrivateIPv4(v4);
  }

  // IPv6 literal (the URL parser strips the brackets, so h is bare).
  const v6 = parseIPv6(h);
  if (v6 !== null) {
    return isPrivateIPv6(v6);
  }

  // Not an IP literal, not localhost, not .local — treat as a public hostname.
  // The DNS-rebinding caveat in the JSDoc above applies: the gateway MUST
  // re-check the resolved IP.
  return false;
}

/**
 * Check whether a TCP/UDP port is permitted by a gateway's egress policy.
 *
 * `blockedPorts` takes precedence over `allowedPorts`. If `allowedPorts` is
 * "any", all non-blocked ports are allowed. If it is an array, only the listed
 * ports are allowed (subject to the blocked list).
 *
 * @param advert  the gateway's advert (carrying the egress policy)
 * @param port    the TCP/UDP port to check (1–65535)
 * @returns       true iff the port is permitted
 */
export function isPortAllowed(advert: GatewayAdvert, port: number): boolean {
  if (typeof port !== "number" || !Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    return false;
  }
  const { allowedPorts, blockedPorts } = advert.egressPolicy;
  // Blocked list takes precedence.
  if (Array.isArray(blockedPorts) && blockedPorts.includes(port)) return false;
  // Allowed list.
  if (allowedPorts === "any") return true;
  if (Array.isArray(allowedPorts)) return allowedPorts.includes(port);
  // Malformed policy — fail closed.
  return false;
}

/**
 * Extract the host and port from a URL string.
 *
 * Returns null if the URL is unparseable or uses an unknown protocol (no
 * default port). For http: the default port is 80; for https: it is 443.
 * The returned `host` is the URL.hostname form (lowercase, no brackets, no
 * port) — suitable for direct use with `isPrivateDestination`.
 */
function extractHostAndPort(urlStr: string): { host: string; port: number } | null {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.hostname === "") return null;
  let port: number;
  if (u.port !== "") {
    const n = parseInt(u.port, 10);
    if (!Number.isInteger(n) || n < MIN_PORT || n > MAX_PORT) return null;
    port = n;
  } else if (u.protocol === "https:") {
    port = 443;
  } else if (u.protocol === "http:") {
    port = 80;
  } else {
    // Unknown protocol — no default port. Reject.
    return null;
  }
  return { host: u.hostname, port };
}

/**
 * The single chokepoint for egress policy enforcement.
 *
 * A gateway MUST call this before acting on a TransitRequest. It combines
 * every check that could cause a rejection:
 *
 *   1. Request not expired (deadline in the future).
 *   2. TLS termination supported by the gateway (I17 — fail-closed on
 *      downgrade; never silently fall back to a weaker mode).
 *   3. URL parseable to a host + port.
 *   4. Destination not private (I18 — SSRF defence).
 *   5. Port permitted by egress policy.
 *   6. Response size within the gateway's maxBytesPerReq.
 *
 * Returns `{ allowed: true, reason: "ok" }` iff all checks pass. Otherwise
 * returns `{ allowed: false, reason: "<human-readable explanation>" }`.
 *
 * The reason string is for gateway operator logs and client error messages.
 * It MUST NOT be used as a programmatic signal (the `allowed` boolean is the
 * only authoritative output).
 *
 * @param advert    the gateway's signed advert (carrying the egress policy)
 * @param request   the TransitRequest to check
 * @param now       current time in unix seconds (optional; defaults to
 *                  `Math.floor(Date.now() / 1000)` for production use, but
 *                  SHOULD be passed explicitly for testability)
 */
export function enforceEgressPolicy(
  advert: GatewayAdvert,
  request: TransitRequest,
  now: number = Math.floor(Date.now() / 1000),
): { allowed: boolean; reason: string } {
  // 1. Request not expired.
  if (isRequestExpired(request, now)) {
    return {
      allowed: false,
      reason: `request deadline (${request.deadline}) has passed (now=${now})`,
    };
  }

  // 2. TLS termination supported — I17 fail-closed.
  if (!supportsTlsTermination(advert, request.tlsTermination)) {
    return {
      allowed: false,
      reason: `gateway does not support tlsTermination "${request.tlsTermination}" (I17: no silent downgrade)`,
    };
  }

  // 3. Parse URL.
  const hp = extractHostAndPort(request.url);
  if (hp === null) {
    return {
      allowed: false,
      reason: `could not parse host/port from URL "${request.url}"`,
    };
  }

  // 4. SSRF defence — I18.
  if (isPrivateDestination(hp.host)) {
    return {
      allowed: false,
      reason: `destination "${hp.host}" is private/loopback/link-local/multicast (I18 SSRF defence)`,
    };
  }

  // 5. Port policy.
  if (!isPortAllowed(advert, hp.port)) {
    return {
      allowed: false,
      reason: `port ${hp.port} not permitted by egress policy`,
    };
  }

  // 6. Response size within maxBytesPerReq.
  if (request.maxResponseBytes > advert.egressPolicy.maxBytesPerReq) {
    return {
      allowed: false,
      reason: `maxResponseBytes (${request.maxResponseBytes}) exceeds gateway maxBytesPerReq (${advert.egressPolicy.maxBytesPerReq})`,
    };
  }

  return { allowed: true, reason: "ok" };
}

// ─── CircuitOpen (Mode B/C, spec §8.1) ─────────────────────────────────────

/**
 * A Mode B/C circuit-open frame payload.
 *
 * CDDL (02-PROTOCOL-SPEC.md §8.1):
 *   CircuitOpen = { op: "open", proto: "tcp"/"udp", host: tstr, port: uint,
 *                   mode: "B"/"C", deadline: uint }
 *
 * This is a FRAME PAYLOAD, not a standalone signed structure. It is
 * authenticated at the frame layer (Noise_IK handshake + ChaCha20-Poly1305
 * AEAD — spec §7). The gateway enforces its egress policy on the parsed
 * `host` and `port`: `isPrivateDestination(circuit.host)` MUST return false
 * before the gateway opens the socket (I18).
 */
export interface CircuitOpen {
  readonly op: "open";
  readonly proto: "tcp" | "udp";
  readonly host: string;
  readonly port: number;
  readonly mode: "B" | "C";
  readonly deadline: number;
}

/** Build the canonical CBOR map for a CircuitOpen. */
function circuitOpenToCborMap(co: CircuitOpen): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["op", co.op],
    ["proto", co.proto],
    ["host", co.host],
    ["port", co.port],
    ["mode", co.mode],
    ["deadline", co.deadline],
  ]);
}

/**
 * Validate the STRUCTURE of a CircuitOpen against the CDDL constraints.
 * Throws `CborError(MALFORMED)` on any violation.
 *
 * Checks:
 *   1. `op` is the literal string "open".
 *   2. `proto` is "tcp" or "udp".
 *   3. `host` is a non-empty string.
 *   4. `port` is an integer in [1, 65535].
 *   5. `mode` is "B" or "C".
 *   6. `deadline` is a non-negative integer.
 *
 * This does NOT check whether the destination is private — that is the
 * gateway's responsibility at call time via `isPrivateDestination(co.host)`.
 */
export function validateCircuitOpen(co: CircuitOpen): void {
  if (co.op !== "open") {
    throw new CborError(
      `CircuitOpen.op must be "open"; got "${co.op}"`,
      "MALFORMED",
    );
  }
  if (co.proto !== "tcp" && co.proto !== "udp") {
    throw new CborError(
      `CircuitOpen.proto must be "tcp" or "udp"; got "${co.proto}"`,
      "MALFORMED",
    );
  }
  if (typeof co.host !== "string" || co.host.length === 0) {
    throw new CborError(
      "CircuitOpen.host must be a non-empty string",
      "MALFORMED",
    );
  }
  if (
    typeof co.port !== "number" ||
    !Number.isInteger(co.port) ||
    co.port < MIN_PORT ||
    co.port > MAX_PORT
  ) {
    throw new CborError(
      `CircuitOpen.port must be an integer in [1, 65535]; got ${co.port}`,
      "MALFORMED",
    );
  }
  if (co.mode !== "B" && co.mode !== "C") {
    throw new CborError(
      `CircuitOpen.mode must be "B" or "C"; got "${co.mode}"`,
      "MALFORMED",
    );
  }
  if (typeof co.deadline !== "number" || !Number.isInteger(co.deadline) || co.deadline < 0) {
    throw new CborError(
      "CircuitOpen.deadline must be a non-negative integer",
      "MALFORMED",
    );
  }
}

/**
 * Encode a CircuitOpen to canonical CBOR bytes. Validates first (fail-fast on
 * bad input — never encode malformed data).
 */
export function encodeCircuitOpen(co: CircuitOpen): Uint8Array {
  validateCircuitOpen(co);
  return cborEncode(circuitOpenToCborMap(co));
}

/**
 * Decode a CircuitOpen from canonical CBOR bytes. Throws `CborError` on any
 * decode or structural error (non-canonical encoding, missing fields, invalid
 * enum values, port out of range).
 */
export function decodeCircuitOpen(bytes: Uint8Array): CircuitOpen {
  const value = cborDecode(bytes);
  if (!(value instanceof Map)) {
    throw new CborError("CircuitOpen must be a CBOR map", "MALFORMED");
  }
  const get = (k: string): CborValue => {
    const v = value.get(k);
    if (v === undefined) {
      throw new CborError(`CircuitOpen missing field "${k}"`, "MALFORMED");
    }
    return v;
  };
  const op = get("op");
  const proto = get("proto");
  const host = get("host");
  const port = get("port");
  const mode = get("mode");
  const deadline = get("deadline");
  if (op !== "open") {
    throw new CborError(`CircuitOpen.op must be "open"; got "${op}"`, "MALFORMED");
  }
  if (proto !== "tcp" && proto !== "udp") {
    throw new CborError(`CircuitOpen.proto must be "tcp" or "udp"; got "${proto}"`, "MALFORMED");
  }
  if (typeof host !== "string") {
    throw new CborError("CircuitOpen.host must be a string", "MALFORMED");
  }
  if (typeof port !== "number" || !Number.isInteger(port)) {
    throw new CborError("CircuitOpen.port must be an integer", "MALFORMED");
  }
  if (mode !== "B" && mode !== "C") {
    throw new CborError(`CircuitOpen.mode must be "B" or "C"; got "${mode}"`, "MALFORMED");
  }
  if (typeof deadline !== "number" || !Number.isInteger(deadline)) {
    throw new CborError("CircuitOpen.deadline must be an integer", "MALFORMED");
  }
  const co: CircuitOpen = { op: "open", proto, host, port, mode, deadline };
  validateCircuitOpen(co); // also enforces port range + deadline non-negative
  return co;
}
