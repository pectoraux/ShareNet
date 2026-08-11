/**
 * SNP L4 Discovery — link-local beacons, descriptor store, anti-entropy HAVE vectors
 *
 * Source: 02-PROTOCOL-SPEC.md §5 "Discovery (L4)"
 * Source: 03-PLATFORM-MATRIX.md §2 (capability profiles — feeds I12)
 * Source: 06-CONFORMANCE-AND-AI-MODEL.md §A4 (required anti-entropy suites)
 * Source: 00-AUDIT.md §7 (missing primitive #1: "Node capability advertisement —
 *         no node can say 'I am an INTERNET_GATEWAY.'") — this module fixes that.
 * Source: 00-AUDIT.md §3.7 (the bug the HAVE-vector format replaces: the audit's
 *         `SyncWorker.kt` sent the literal ASCII string `"HAVE:"` to every peer
 *         and `getHaveVector()` returned `emptyList()`. There was no gossip
 *         protocol. This module defines the structured CBOR replacement.)
 *
 * The audit's headline L4 finding (00-AUDIT.md §7, item 1): the existing
 * codebase has NO node-capability advertisement. No node can say "I am an
 * INTERNET_GATEWAY" or "I am a MESH_RELAY." Without that, every other layer
 * (routing, gateway migration, custody) is building on sand. This module is
 * the fix: three discovery tiers, used together, per spec §5:
 *
 *   1. Link-local beacons (`DiscoveryAdvertisement`) — BLE advertisement,
 *      mDNS, Wi-Fi Direct service records. Carries a TRUNCATED NodeId (8
 *      bytes) and a capability bitmask only. MUST NOT carry the full
 *      descriptor (too large, and it leaks). The truncated NodeId is a HINT;
 *      the full descriptor is fetched separately (tier 2) and verified by
 *      signature before use.
 *
 *   2. Gossiped descriptors (`NodeDescriptor` / `GatewayAdvert`) — full
 *      descriptors propagate as Class A objects via anti-entropy, subject to
 *      expiry. The `DescriptorStore` is the local cache; `buildHaveVector` /
 *      `parseHaveVector` are the anti-entropy exchange.
 *
 *   3. Rendezvous — for `COMMUNITY_RELAY` and `INTERNET_GATEWAY` nodes with
 *      stable identities, descriptors MAY be published to a well-known store
 *      reachable when any Internet is available. (Tier 3 is not implemented
 *      in this module — it is a deployment-time concern; the descriptor store
 *      itself is the in-memory backing for tier 2 and the local cache for
 *      tier 3 fetches.)
 *
 * Freshness rule (spec §5, normative): "a descriptor older than `expiresAt`
 * MUST NOT be used for routing and MUST NOT be forwarded. Relays MUST NOT
 * extend expiry." `DescriptorStore.activeNodeDescriptors(now)` enforces this
 * — expired descriptors are excluded from the active set even if they remain
 * in the store (the store keeps them so `getNodeDescriptor` can return them
 * for inspection; only `pruneExpired` removes them).
 *
 * Sybil defence at the discovery layer: the store verifies every descriptor's
 * signature before accepting it. A descriptor with a bad signature is silently
 * dropped (return false, never throw — I20). This is the chokepoint that
 * prevents a peer from injecting forged descriptors for NodeIds they do not
 * control. Additionally, the store enforces I4 (NodeId = SHA-256(context ‖ pk))
 * by re-deriving the NodeId from the embedded public key and rejecting
 * mismatches. Without the I4 check, a peer could advertise a descriptor whose
 * `nodeId` field is someone else's NodeId while signing with their own key —
 * a name-squatting attack that signature verification alone does not catch.
 *
 * Platform-capability matrix (I12): the store rejects NodeDescriptors that
 * advertise capabilities their platform cannot sustain. `validatePlatformCapabilities`
 * encodes the normative matrix from 03-PLATFORM-MATRIX.md §2 (e.g. iOS +
 * INTERNET_GATEWAY is forbidden; iOS is a consumer of mesh connectivity, not
 * a provider — see spec §4 of the platform matrix). This prevents a
 * misconfigured or compromised iOS device from advertising itself as a
 * gateway and attracting traffic it cannot egress.
 *
 * @ invariant I4  — NodeId = SHA-256("SNP/0.1 node\0" ‖ pk), never the bare key.
 *                   The DescriptorStore re-derives and rejects mismatches.
 * @ invariant I9  — This module imports from identity, gateway, link, constants,
 *                   cbor, hashing — NOT from routing (L6). Discovery is below
 *                   routing in the layer cake; importing L6 would invert the
 *                   dependency.
 * @ invariant I12 — The store rejects descriptors advertising capabilities their
 *                   platform cannot sustain (03-PLATFORM-MATRIX.md §2).
 * @ invariant I20 — `add*` methods return false on bad sig / expired / invalid;
 *                   never throw for verification failures. `validate*` throws
 *                   CborError(MALFORMED) on structural problems. The scanner
 *                   silently drops malformed advertisements (never throws for
 *                   peer-supplied bytes).
 */

import {
  CAPABILITIES,
  type Capability,
  type Platform,
  PLATFORMS,
} from "./constants";
import {
  type NodeDescriptor,
  isExpired,
  verifyNodeDescriptor,
} from "./identity";
import {
  type GatewayAdvert,
  isAdvertExpired,
  verifyGatewayAdvert,
} from "./gateway";
import { type LinkTransportKind } from "./link";
import {
  type CborValue,
  CborError,
  cborMap,
  encode as cborEncode,
  decode as cborDecode,
} from "./cbor";
import { deriveNodeId } from "./hashing";

// ─── Frozen sizes & defaults ───────────────────────────────────────────────

/** Full NodeId byte length (32 bytes — SHA-256 output). */
const NODE_ID_BYTES = 32;

/** Truncated NodeId prefix length carried in `DiscoveryAdvertisement` (8 bytes).
 *  Per spec §5 tier 1: "Carries a truncated NodeId and a capability bitmask only."
 *  8 bytes (64 bits) gives ample collision resistance for the link-local hint
 *  role — the prefix is NOT an identifier, only a hint to dedup adverts and
 *  trigger a descriptor fetch. */
const NODE_ID_PREFIX_BYTES = 8;

/** Default advert TTL for `DiscoveryBeacon` (60s — spec §5 tier 1: "SHOULD be
 *  ≤ 60s for mobile"). Mobile nodes churn fast; a stale link-local beacon
 *  misleads peers into attempting to connect to a gone peer. */
const DEFAULT_ADVERT_TTL_SECONDS = 60;

/** Default broadcast interval for `DiscoveryBeacon` (15s). Roughly a quarter
 *  of the default TTL, so peers observe ~4 beacons per TTL window — enough
 *  to ride out a single missed packet without losing the peer from the cache. */
const DEFAULT_BEACON_INTERVAL_SECONDS = 15;

/** Max advert TTL enforced by `DiscoveryBeacon` (300s — same SHOULD bound as
 *  `GatewayAdvert` per spec §5.1). A longer TTL is a deployment error. */
const MAX_ADVERT_TTL_SECONDS = 300;

/** Max `capabilityMask` value (uint32 — fits in a single CBOR unsigned int
 *  head). CAPABILITIES has 10 entries so the practical max is 0x3FF, but we
 *  accept any uint32 so future capability additions do not require a format
 *  change. */
const MAX_CAPABILITY_MASK = 0xffffffff;

/** All valid `LinkTransportKind` string values (mirror of `link.ts`). Used
 *  for runtime validation in `validateDiscoveryAdvertisement`. The type alias
 *  in `link.ts` is compile-time only; we need a runtime check here. */
const VALID_TRANSPORTS: ReadonlySet<string> = new Set([
  "ble", // Bluetooth Low Energy
  "wifi-direct", // Wi-Fi Direct (Wi-Fi P2P)
  "tcp", // TCP/IP
  "quic", // QUIC
  "wifi-lan", // Wi-Fi LAN (infrastructure BSS)
  "lora", // LoRaWAN
]);

// ─── Internal helpers ──────────────────────────────────────────────────────

/** Convert a Uint8Array to a lowercase hex string. Used as Map keys in the
 *  DescriptorStore (JS Map uses reference equality on objects, so NodeIds
 *  must be normalised to a primitive string before lookup). */
function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0");
  }
  return s;
}

/** Constant-time-ish byte equality. Used for NodeId comparisons in the
 *  DescriptorStore so the comparison does not leak which NodeId is being
 *  queried via timing. (NodeId lookups are not secret in SNP — they rotate
 *  per epoch — but uniform timing is cheap and avoids leaking the access
 *  pattern to a timing observer.) */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Type guard: true iff `s` is a valid `LinkTransportKind`. */
function isLinkTransportKind(s: string): s is LinkTransportKind {
  return VALID_TRANSPORTS.has(s);
}

/** Extract a byte string from a decoded CBOR value, throwing CborError(MALFORMED)
 *  if the value is missing or not a Uint8Array. */
function extractBstr(v: CborValue | undefined, field: string): Uint8Array {
  if (!(v instanceof Uint8Array)) {
    throw new CborError(
      `${field} must be a byte string; got ${v === undefined ? "missing" : typeof v}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a text string from a decoded CBOR value, throwing CborError(MALFORMED)
 *  if the value is missing or not a string. */
function extractString(v: CborValue | undefined, field: string): string {
  if (typeof v !== "string") {
    throw new CborError(
      `${field} must be a text string; got ${v === undefined ? "missing" : typeof v}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a non-negative integer from a decoded CBOR value. Accepts both
 *  `number` and `bigint` (CBOR may decode large uints as bigint); the value
 *  must be a non-negative safe integer. Throws CborError(MALFORMED) otherwise. */
function extractUint(v: CborValue | undefined, field: string): number {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) {
    return v;
  }
  if (typeof v === "bigint" && v >= 0n && v <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(v);
  }
  throw new CborError(
    `${field} must be a non-negative integer; got ${v === undefined ? "missing" : typeof v === "bigint" ? `${v}n` : String(v)}`,
    "MALFORMED",
  );
}

// ─── 1. DiscoveryAdvertisement (spec §5 tier 1) ────────────────────────────

/**
 * The link-local discovery beacon. Carried in BLE advertisement payloads,
 * mDNS TXT records, Wi-Fi Direct service discovery records, etc.
 *
 * Per spec §5 tier 1: "Carries a truncated NodeId and a capability bitmask
 * only. MUST NOT carry the full descriptor (too large, and it leaks)."
 *
 * The `nodeIdPrefix` is the first 8 bytes of the NodeId (NOT the public key —
 * I4 still holds: the prefix is a hash prefix, not a key prefix). It is a HINT
 * — observers use it to deduplicate adverts and to decide whether to fetch the
 * full descriptor (tier 2). It MUST NOT be used as an identifier for routing
 * or authorization; only the full NodeId (recovered from the signed descriptor)
 * has that authority.
 *
 * The `capabilityMask` is a uint32 bitmask with bit positions per the
 * `CAPABILITIES` array in `constants.ts` (index 0 = MESH_CLIENT = bit 0,
 * index 1 = MESH_RELAY = bit 1, etc.). This is the audit's missing primitive
 * #1 made concrete: a node can finally say "I am an INTERNET_GATEWAY" (bit 2)
 * in a compact, link-layer-friendly form.
 *
 * The `transport` and `linkAddress` fields tell observers HOW to reach the
 * advertiser (e.g. transport="ble" + 6-byte MAC, or transport="tcp" +
 * UTF-8 "host:port"). These are opaque to L1–L7 (per the Link abstraction
 * in `link.ts`); only the platform adapter (L8/L9) interprets them.
 *
 * The advert is NOT signed. There is no key material in it (the prefix is a
 * hash, the mask is a few bits, the address is link-local). Authentication
 * happens later, when the observer fetches the full descriptor (tier 2) and
 * verifies its signature. A forged advert can attract a connection attempt,
 * but the connection's Noise_IK handshake (`link.ts`) will fail closed
 * against a forged NodeId. This is defense in depth: the advert is a hint,
 * the descriptor is a claim, the handshake is proof.
 */
export interface DiscoveryAdvertisement {
  /** First 8 bytes of the NodeId — truncated for compactness. Truncated NodeId
   *  is a HINT, not an identifier; the full descriptor is fetched separately. */
  readonly nodeIdPrefix: Uint8Array; // 8 bytes
  /** Bitmask of capabilities (bit positions per CAPABILITIES array in constants.ts). */
  readonly capabilityMask: number; // uint32
  /** Transport kind that the advertiser is reachable on. */
  readonly transport: LinkTransportKind;
  /** Link-layer address to connect on (e.g. BLE MAC bytes, or "host:port" for TCP).
   *  Opaque to L1–L7 — only the L8 adapter interprets it. */
  readonly linkAddress: Uint8Array;
  /** When this advert was generated (unix seconds). */
  readonly generatedAt: number;
  /** When this advert expires (unix seconds, SHOULD be ≤ 60s for mobile). */
  readonly expiresAt: number;
}

/**
 * Encode a `DiscoveryAdvertisement` to canonical SNP-CBOR bytes.
 *
 * The structure is a CBOR map with STRING keys:
 *   { "nodeIdPrefix": bstr .size 8, "capabilityMask": uint, "transport": tstr,
 *     "linkAddress": bstr, "generatedAt": uint, "expiresAt": uint }
 *
 * Canonical ordering (length-first on the fully-encoded key — I1) is applied
 * by the SNP-CBOR encoder in `cbor.ts`.
 *
 * The encoded form is small (typically ≤ 60 bytes including CBOR heads),
 * suitable for BLE advertisement payloads (which have ~31 bytes by default,
 * extendable to ~255 with scan response) and mDNS TXT records.
 */
export function encodeDiscoveryAdvertisement(
  adv: DiscoveryAdvertisement,
): Uint8Array {
  return cborEncode(
    cborMap([
      ["nodeIdPrefix", adv.nodeIdPrefix],
      ["capabilityMask", adv.capabilityMask],
      ["transport", adv.transport],
      ["linkAddress", adv.linkAddress],
      ["generatedAt", adv.generatedAt],
      ["expiresAt", adv.expiresAt],
    ]),
  );
}

/**
 * Decode a `DiscoveryAdvertisement` from canonical SNP-CBOR bytes.
 *
 * Throws `CborError` (any code) on malformed input — non-CBOR bytes, wrong
 * major types, missing fields, structural violations. After a successful
 * decode the returned advertisement is guaranteed to pass
 * `validateDiscoveryAdvertisement`.
 */
export function decodeDiscoveryAdvertisement(
  bytes: Uint8Array,
): DiscoveryAdvertisement {
  let value: CborValue;
  try {
    value = cborDecode(bytes);
  } catch (e) {
    if (e instanceof CborError) throw e;
    throw new CborError(
      `Failed to decode DiscoveryAdvertisement: ${e instanceof Error ? e.message : String(e)}`,
      "DECODE_ERROR",
    );
  }
  if (!(value instanceof Map)) {
    throw new CborError(
      "DiscoveryAdvertisement must be a CBOR map",
      "MALFORMED",
    );
  }
  const nodeIdPrefix = extractBstr(
    value.get("nodeIdPrefix"),
    "DiscoveryAdvertisement.nodeIdPrefix",
  );
  const capabilityMask = extractUint(
    value.get("capabilityMask"),
    "DiscoveryAdvertisement.capabilityMask",
  );
  const transport = extractString(
    value.get("transport"),
    "DiscoveryAdvertisement.transport",
  );
  const linkAddress = extractBstr(
    value.get("linkAddress"),
    "DiscoveryAdvertisement.linkAddress",
  );
  const generatedAt = extractUint(
    value.get("generatedAt"),
    "DiscoveryAdvertisement.generatedAt",
  );
  const expiresAt = extractUint(
    value.get("expiresAt"),
    "DiscoveryAdvertisement.expiresAt",
  );
  const adv: DiscoveryAdvertisement = {
    nodeIdPrefix,
    capabilityMask,
    // Cast is safe — validateDiscoveryAdvertisement checks the value is a
    // valid LinkTransportKind before this object is returned to the caller.
    transport: transport as LinkTransportKind,
    linkAddress,
    generatedAt,
    expiresAt,
  };
  // Structural validation (incl. transport enum + expiresAt > generatedAt).
  // Throws CborError(MALFORMED) on any violation — decode never returns a
  // structurally-invalid advertisement.
  validateDiscoveryAdvertisement(adv);
  return adv;
}

/**
 * Validate the STRUCTURE of a `DiscoveryAdvertisement` against the spec.
 *
 * Throws `CborError(MALFORMED)` on any violation:
 *   - `nodeIdPrefix` must be a Uint8Array of exactly 8 bytes.
 *   - `capabilityMask` must be a non-negative integer ≤ 0xFFFFFFFF.
 *   - `transport` must be a valid `LinkTransportKind`.
 *   - `linkAddress` must be a Uint8Array (any length, including empty).
 *   - `generatedAt` and `expiresAt` must be non-negative integers.
 *   - `expiresAt` must be strictly greater than `generatedAt`.
 *
 * Does NOT check signature validity (the advert is unsigned — see the
 * interface JSDoc) and does NOT enforce the SHOULD TTL bound (≤ 60s for
 * mobile). The TTL bound is a policy decision enforced by `DiscoveryBeacon`
 * at construction time.
 */
export function validateDiscoveryAdvertisement(
  adv: DiscoveryAdvertisement,
): void {
  if (!(adv.nodeIdPrefix instanceof Uint8Array) || adv.nodeIdPrefix.length !== NODE_ID_PREFIX_BYTES) {
    throw new CborError(
      `DiscoveryAdvertisement.nodeIdPrefix must be a ${NODE_ID_PREFIX_BYTES}-byte Uint8Array; got ${adv.nodeIdPrefix instanceof Uint8Array ? `${adv.nodeIdPrefix.length} bytes` : typeof adv.nodeIdPrefix}`,
      "MALFORMED",
    );
  }
  if (
    typeof adv.capabilityMask !== "number" ||
    !Number.isInteger(adv.capabilityMask) ||
    adv.capabilityMask < 0 ||
    adv.capabilityMask > MAX_CAPABILITY_MASK
  ) {
    throw new CborError(
      `DiscoveryAdvertisement.capabilityMask must be a uint32 (0..${MAX_CAPABILITY_MASK}); got ${String(adv.capabilityMask)}`,
      "MALFORMED",
    );
  }
  if (typeof adv.transport !== "string" || !isLinkTransportKind(adv.transport)) {
    throw new CborError(
      `DiscoveryAdvertisement.transport must be one of [${[...VALID_TRANSPORTS].join(", ")}]; got "${adv.transport}"`,
      "MALFORMED",
    );
  }
  if (!(adv.linkAddress instanceof Uint8Array)) {
    throw new CborError(
      `DiscoveryAdvertisement.linkAddress must be a Uint8Array; got ${adv.linkAddress === null ? "null" : typeof adv.linkAddress}`,
      "MALFORMED",
    );
  }
  if (typeof adv.generatedAt !== "number" || !Number.isInteger(adv.generatedAt) || adv.generatedAt < 0) {
    throw new CborError(
      `DiscoveryAdvertisement.generatedAt must be a non-negative integer (unix seconds); got ${String(adv.generatedAt)}`,
      "MALFORMED",
    );
  }
  if (typeof adv.expiresAt !== "number" || !Number.isInteger(adv.expiresAt) || adv.expiresAt < 0) {
    throw new CborError(
      `DiscoveryAdvertisement.expiresAt must be a non-negative integer (unix seconds); got ${String(adv.expiresAt)}`,
      "MALFORMED",
    );
  }
  if (adv.expiresAt <= adv.generatedAt) {
    throw new CborError(
      `DiscoveryAdvertisement.expiresAt (${adv.expiresAt}) must be strictly greater than generatedAt (${adv.generatedAt})`,
      "MALFORMED",
    );
  }
}

/**
 * Check whether a `DiscoveryAdvertisement` has expired.
 *
 * Per spec §5 tier 1: link-local adverts SHOULD be ≤ 60s for mobile. An
 * expired advert MUST be dropped by the scanner — the advertiser may have
 * moved on, and connecting to a stale address wastes battery.
 *
 * @param adv  the advertisement to check
 * @param now  current time in unix seconds (passed in for testability)
 * @returns    true iff `now` is at or past `adv.expiresAt`
 */
export function isAdvExpired(adv: DiscoveryAdvertisement, now: number): boolean {
  return now >= adv.expiresAt;
}

/**
 * Return the bit position for a capability name, per the `CAPABILITIES` array
 * in `constants.ts`. Index 0 (MESH_CLIENT) = bit 0; index 1 (MESH_RELAY) =
 * bit 1; index 2 (INTERNET_GATEWAY) = bit 2; etc.
 *
 * Throws `Error` if `capability` is not a known capability name. This is a
 * programming error (the caller passed an invalid Capability value), not a
 * peer-input error, so it throws rather than returning a sentinel.
 */
export function capabilityBit(capability: Capability): number {
  const idx = CAPABILITIES.indexOf(capability);
  if (idx < 0) {
    throw new Error(
      `Unknown capability: "${String(capability)}". Must be one of [${CAPABILITIES.join(", ")}]`,
    );
  }
  return idx;
}

/**
 * Check whether a capability bitmask has a given capability set.
 *
 * Bit positions are per the `CAPABILITIES` array (see `capabilityBit`).
 *
 * @param mask        the bitmask to test (uint32)
 * @param capability  the capability name to check
 * @returns           true iff the bit for `capability` is set in `mask`
 */
export function hasCapability(
  mask: number,
  capability: Capability,
): boolean {
  const bit = capabilityBit(capability);
  // `>>> 0` coerces to uint32 so bit 31 is treated as unsigned. For the
  // current CAPABILITIES array (10 entries) this is a no-op, but it future-
  // proofs against capability additions.
  return ((mask >>> 0) & (1 << bit)) !== 0;
}

/**
 * Build a capability bitmask by OR-ing the bits for each capability in the
 * input array. Duplicate capabilities are idempotent (OR is idempotent).
 *
 * @param capabilities  array of capability names (may be empty — returns 0)
 * @returns             uint32 bitmask with the corresponding bits set
 */
export function buildCapabilityMask(capabilities: Capability[]): number {
  let mask = 0;
  for (const c of capabilities) {
    mask |= 1 << capabilityBit(c);
  }
  return mask >>> 0;
}

// ─── 2. DescriptorStore (spec §5 tier 2 — gossiped descriptors) ───────────

/** Options for constructing a `DescriptorStore`. */
export interface DescriptorStoreOptions {
  /**
   * Wall-clock provider, returning the current time in unix seconds.
   * Defaults to `() => Math.floor(Date.now() / 1000)`. Override in tests
   * for deterministic expiry behaviour.
   */
  now?: () => number;
}

/**
 * Local cache of gossiped `NodeDescriptor`s and `GatewayAdvert`s (spec §5
 * tier 2). This is the structured replacement for the audit's
 * `core-transport/SyncWorker.kt` which had no descriptor cache at all (00-AUDIT.md
 * §3.7 — `getHaveVector()` returned `emptyList()` and the literal bytes sent
 * to every peer were `"HAVE:"`).
 *
 * The store is the Sybil-defence chokepoint at the discovery layer. EVERY
 * descriptor added is signature-verified (`verifyNodeDescriptor` /
 * `verifyGatewayAdvert`) and NodeId↔public-key bound (I4: re-derive the
 * NodeId from the embedded public key and reject mismatches). A descriptor
 * with a bad signature OR a mismatched NodeId is silently dropped (return
 * false, never throw — I20).
 *
 * Freshness policy (spec §5, normative): "a descriptor older than `expiresAt`
 * MUST NOT be used for routing and MUST NOT be forwarded. Relays MUST NOT
 * extend expiry." The store enforces this by:
 *   - Rejecting already-expired descriptors at add time.
 *   - Excluding expired descriptors from `activeNodeDescriptors(now)` /
 *     `activeGatewayAdverts(now)` even if they remain in the cache.
 *   - Never bumping an existing descriptor's `expiresAt` field. When a new
 *     descriptor arrives for an existing NodeId, the store keeps the FRESHER
 *     one (higher `epoch` for NodeDescriptor, higher `validFrom` for
 *     GatewayAdvert; ties broken by `expiresAt`). It does not extend the
 *     expiry of a stored descriptor without a fresh signature.
 *
 * The store is NOT thread-safe. Callers using it from multiple async contexts
 * MUST serialise access (e.g. via a per-store mutex). In practice the store
 * is owned by a single async task (the discovery loop) so this is rarely an
 * issue.
 */
export class DescriptorStore {
  /** NodeId (hex) → freshest known NodeDescriptor. */
  private readonly nodeDescriptors: Map<string, NodeDescriptor> = new Map();
  /** NodeId (hex) → freshest known GatewayAdvert. */
  private readonly gatewayAdverts: Map<string, GatewayAdvert> = new Map();
  /** Wall-clock provider (unix seconds). */
  private readonly now: () => number;

  constructor(options?: DescriptorStoreOptions) {
    this.now = options?.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Add or update a `NodeDescriptor`.
   *
   * Verification chain (ALL must pass; any failure → return false, never throw):
   *   1. `peerPublicKey` is a 32-byte Uint8Array (defensive — it is not used
   *      to verify the descriptor; the descriptor is self-attesting via its
   *      own `nodePubKey`. The parameter is required by the API for symmetry
   *      with `addGatewayAdvert` and to support future relay-attestation
   *      extensions).
   *   2. I4: `deriveNodeId(desc.nodePubKey)` equals `desc.nodeId`. Prevents
   *      name-squatting (a peer signing a descriptor whose `nodeId` field
   *      names someone else's NodeId).
   *   3. Signature: `verifyNodeDescriptor(desc)` returns true.
   *   4. Platform: `validatePlatformCapabilities(desc.platform, desc.capabilities)`
   *      returns true (I12 — rejects e.g. iOS + INTERNET_GATEWAY).
   *   5. Expiry: `!isExpired(desc, now())`.
   *
   * If a descriptor for the same NodeId is already in the store, the FRESHER
   * one wins (higher `epoch`, ties broken by `expiresAt`). If the existing
   * is fresher or equal, the new one is dropped (return true — the new
   * descriptor was valid, just stale).
   *
   * @returns true iff the descriptor was valid (and either stored or
   *          superseded by an equal/fresher one); false iff rejected.
   */
  addNodeDescriptor(
    desc: NodeDescriptor,
    peerPublicKey: Uint8Array,
  ): boolean {
    // (1) Defensive: peerPublicKey must be a 32-byte Ed25519 public key.
    if (!(peerPublicKey instanceof Uint8Array) || peerPublicKey.length !== 32) {
      return false;
    }

    // (2) I4: NodeId = SHA-256("SNP/0.1 node\0" ‖ nodePubKey). The signature
    // check below verifies that desc was signed by desc.nodePubKey, but it
    // does NOT verify that desc.nodeId is the correct hash of that key. A
    // malicious peer could sign a descriptor with their own key while setting
    // `nodeId` to someone else's NodeId — a name-squatting attack. Re-deriving
    // the NodeId and comparing closes that gap.
    let derivedNodeId: Uint8Array;
    try {
      derivedNodeId = deriveNodeId(desc.nodePubKey);
    } catch {
      return false;
    }
    if (!bytesEqual(derivedNodeId, desc.nodeId)) {
      return false;
    }

    // (3) Signature check (I20: verifyNodeDescriptor returns false, never throws).
    if (!verifyNodeDescriptor(desc)) {
      return false;
    }

    // (4) Platform-capability matrix (I12).
    if (!validatePlatformCapabilities(desc.platform, desc.capabilities)) {
      return false;
    }

    // (5) Expiry check.
    if (isExpired(desc, this.now())) {
      return false;
    }

    // Freshness check: keep the freshest descriptor per NodeId.
    const key = bytesToHex(desc.nodeId);
    const existing = this.nodeDescriptors.get(key);
    if (existing !== undefined && !this.fresherNodeDescriptor(existing, desc)) {
      // Existing is fresher or equal — keep it. Return true (the new desc was
      // valid, just not the freshest we have).
      return true;
    }
    this.nodeDescriptors.set(key, desc);
    return true;
  }

  /**
   * Add or update a `GatewayAdvert`.
   *
   * Verification chain (ALL must pass; any failure → return false, never throw):
   *   1. `peerPublicKey` is a 32-byte Uint8Array (the gateway's Ed25519 public
   *      key — caller obtains it from the gateway's NodeDescriptor, which the
   *      store already holds via `addNodeDescriptor`).
   *   2. I4: `deriveNodeId(peerPublicKey)` equals `advert.nodeId`.
   *   3. Signature: `verifyGatewayAdvert(advert, peerPublicKey)` returns true.
   *   4. Expiry: `!isAdvertExpired(advert, now())`.
   *
   * Unlike `addNodeDescriptor`, this method does NOT do a platform-capability
   * check, because `GatewayAdvert` does not carry a `platform` field (it is
   * a capacity+policy snapshot, separate from identity — spec §5.1). The
   * platform check was done when the gateway's NodeDescriptor was added.
   *
   * If an advert for the same NodeId is already in the store, the FRESHER
   * one wins (higher `validFrom`, ties broken by `expiresAt`).
   *
   * @returns true iff the advert was valid (and either stored or superseded
   *          by an equal/fresher one); false iff rejected.
   */
  addGatewayAdvert(
    advert: GatewayAdvert,
    peerPublicKey: Uint8Array,
  ): boolean {
    // (1) peerPublicKey must be a 32-byte Ed25519 public key.
    if (!(peerPublicKey instanceof Uint8Array) || peerPublicKey.length !== 32) {
      return false;
    }

    // (2) I4: the gateway's NodeId must be the hash of the supplied public key.
    let derivedNodeId: Uint8Array;
    try {
      derivedNodeId = deriveNodeId(peerPublicKey);
    } catch {
      return false;
    }
    if (!bytesEqual(derivedNodeId, advert.nodeId)) {
      return false;
    }

    // (3) Signature check (I20: verifyGatewayAdvert returns false, never throws).
    if (!verifyGatewayAdvert(advert, peerPublicKey)) {
      return false;
    }

    // (4) Expiry check.
    if (isAdvertExpired(advert, this.now())) {
      return false;
    }

    // Freshness check: keep the freshest advert per gateway NodeId.
    const key = bytesToHex(advert.nodeId);
    const existing = this.gatewayAdverts.get(key);
    if (existing !== undefined && !this.fresherGatewayAdvert(existing, advert)) {
      return true;
    }
    this.gatewayAdverts.set(key, advert);
    return true;
  }

  /**
   * Get the freshest `NodeDescriptor` for a NodeId, or null if unknown.
   *
   * Returns the stored descriptor regardless of expiry — callers needing a
   * routing-usable descriptor MUST call `activeNodeDescriptors(now)` instead,
   * which filters out expired entries. This method is for inspection (e.g.
   * looking up a peer's public key from a recently-stored descriptor).
   */
  getNodeDescriptor(nodeId: Uint8Array): NodeDescriptor | null {
    if (!(nodeId instanceof Uint8Array) || nodeId.length !== NODE_ID_BYTES) {
      return null;
    }
    return this.nodeDescriptors.get(bytesToHex(nodeId)) ?? null;
  }

  /**
   * Get the freshest `GatewayAdvert` for a gateway NodeId, or null if unknown.
   *
   * Returns the stored advert regardless of expiry — callers needing a
   * routing-usable advert MUST call `activeGatewayAdverts(now)` instead.
   */
  getGatewayAdvert(nodeId: Uint8Array): GatewayAdvert | null {
    if (!(nodeId instanceof Uint8Array) || nodeId.length !== NODE_ID_BYTES) {
      return null;
    }
    return this.gatewayAdverts.get(bytesToHex(nodeId)) ?? null;
  }

  /**
   * All non-expired `NodeDescriptor`s, for routing decisions.
   *
   * Per spec §5 freshness rule: "a descriptor older than `expiresAt` MUST NOT
   * be used for routing." This method is the chokepoint that enforces it —
   * callers MUST NOT route on `getNodeDescriptor` results without re-checking
   * expiry; they should use this method instead.
   *
   * @param now  current time in unix seconds
   */
  activeNodeDescriptors(now: number): NodeDescriptor[] {
    const out: NodeDescriptor[] = [];
    for (const desc of this.nodeDescriptors.values()) {
      if (!isExpired(desc, now)) {
        out.push(desc);
      }
    }
    return out;
  }

  /**
   * All non-expired `GatewayAdvert`s.
   *
   * @param now  current time in unix seconds
   */
  activeGatewayAdverts(now: number): GatewayAdvert[] {
    const out: GatewayAdvert[] = [];
    for (const advert of this.gatewayAdverts.values()) {
      if (!isAdvertExpired(advert, now)) {
        out.push(advert);
      }
    }
    return out;
  }

  /**
   * Remove all expired entries (both NodeDescriptors and GatewayAdverts).
   * Returns the total count removed.
   *
   * Per spec §5: "MUST NOT be forwarded" — expired descriptors are useless
   * to peers, so the store drops them on prune. The store does NOT auto-prune
   * on every add (amortised cost is lower with explicit prune calls from the
   * discovery loop).
   *
   * @param now  current time in unix seconds
   * @returns    number of entries removed
   */
  pruneExpired(now: number): number {
    let removed = 0;
    for (const [key, desc] of this.nodeDescriptors) {
      if (isExpired(desc, now)) {
        this.nodeDescriptors.delete(key);
        removed++;
      }
    }
    for (const [key, advert] of this.gatewayAdverts) {
      if (isAdvertExpired(advert, now)) {
        this.gatewayAdverts.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /**
   * All known gateway NodeIds — i.e. the NodeIds of all non-expired
   * `GatewayAdvert`s in the store. Used by the routing layer (L6) to know
   * which gateways are currently reachable.
   *
   * @param now  current time in unix seconds
   */
  knownGateways(now: number): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const advert of this.gatewayAdverts.values()) {
      if (!isAdvertExpired(advert, now)) {
        out.push(advert.nodeId);
      }
    }
    return out;
  }

  // ─── Private freshness helpers ──────────────────────────────────────────

  /**
   * Returns true iff `candidate` is FRESHER than `existing`.
   *
   * Freshness ordering for NodeDescriptors (spec §4.4):
   *   - Higher `epoch` wins (epoch is per-node monotonic — a higher epoch
   *     means the node rotated its identity).
   *   - Same epoch: later `expiresAt` wins (a re-sign without an epoch bump
   *     is a routine refresh; the new descriptor has a later expiry).
   *
   * The store keeps the freshest; the older one is dropped. Per spec §5,
   * "Relays MUST NOT extend expiry" — this is enforced by the fact that we
   * only replace when (epoch, expiresAt) is strictly greater, never by
   * mutating an existing descriptor's fields.
   */
  private fresherNodeDescriptor(
    existing: NodeDescriptor,
    candidate: NodeDescriptor,
  ): boolean {
    if (candidate.epoch > existing.epoch) return true;
    if (candidate.epoch < existing.epoch) return false;
    return candidate.expiresAt > existing.expiresAt;
  }

  /**
   * Returns true iff `candidate` is FRESHER than `existing`.
   *
   * Freshness ordering for GatewayAdverts (spec §5.1):
   *   - Higher `validFrom` wins (validFrom is the advert's "this supersedes
   *     prior adverts" timestamp).
   *   - Same validFrom: later `expiresAt` wins.
   */
  private fresherGatewayAdvert(
    existing: GatewayAdvert,
    candidate: GatewayAdvert,
  ): boolean {
    if (candidate.validFrom > existing.validFrom) return true;
    if (candidate.validFrom < existing.validFrom) return false;
    return candidate.expiresAt > existing.expiresAt;
  }
}

// ─── 3. DiscoveryBeacon (spec §5 tier 1 — emit) ───────────────────────────

/** Callbacks invoked by `DiscoveryBeacon` to broadcast an advertisement. */
export interface DiscoveryBeaconCallbacks {
  /**
   * Called when a new advertisement should be broadcast on a transport.
   *
   * The callback receives the transport kind (the beacon is configured for
   * one transport at construction time; see `DiscoveryBeacon` options) and
   * the encoded `DiscoveryAdvertisement` bytes. The actual BLE/mDNS/TCP
   * advertising is a platform concern (the L8 adapter) — this module just
   * produces the bytes.
   *
   * Implementations MUST NOT throw. If the platform adapter is unable to
   * broadcast (e.g. BLE radio off), it should swallow the error; the beacon
   * will retry on the next tick.
   */
  broadcast: (transport: LinkTransportKind, bytes: Uint8Array) => void;
}

/** Constructor options for `DiscoveryBeacon`. */
export interface DiscoveryBeaconOptions {
  /** Advert TTL in seconds (default: 60; max: 300). Spec §5 tier 1: "SHOULD
   *  be ≤ 60s for mobile." A longer TTL is a deployment error. */
  advertTtlSeconds?: number;
  /** Broadcast interval in seconds (default: 15). Roughly a quarter of the
   *  default TTL, so peers observe ~4 beacons per TTL window. */
  intervalSeconds?: number;
  /** Transport the beacon advertises reachability on (default: "ble").
   *  Production code MUST set this to the transport the node is actually
   *  reachable on. */
  transport?: LinkTransportKind;
  /** Link-layer address bytes to advertise (default: empty Uint8Array).
   *  For BLE: 6-byte MAC. For TCP: UTF-8 "host:port". Production code MUST
   *  set this — an empty address is only useful for tests. */
  linkAddress?: Uint8Array;
  /** Wall-clock provider (unix seconds). Defaults to `Date.now() / 1000`.
   *  Override in tests for deterministic advert timestamps. */
  now?: () => number;
}

/**
 * Emits periodic link-local `DiscoveryAdvertisement`s on a transport.
 *
 * This is the audit's missing primitive #1 (00-AUDIT.md §7) in operational
 * form: a node uses `DiscoveryBeacon` to broadcast its presence and
 * capabilities to nearby peers via BLE advertisement, mDNS, Wi-Fi Direct
 * service discovery, etc. The beacon produces the CBOR bytes; the actual
 * link-layer advertising is delegated to a platform adapter via the
 * `broadcast` callback.
 *
 * Lifecycle:
 *   const beacon = new DiscoveryBeacon(nodeId, caps, callbacks, opts);
 *   const stop = beacon.start();
 *   // ... later, when capabilities change (e.g. battery drops, shed INTERNET_GATEWAY):
 *   beacon.updateCapabilities(newCaps);
 *   // ... later, when the node is going offline:
 *   stop();
 *
 * The beacon is single-transport. A node that wants to advertise on multiple
 * transports (e.g. BLE + Wi-Fi Direct) constructs one `DiscoveryBeacon` per
 * transport. This keeps each beacon simple and lets the platform adapter
 * handle transport-specific advertising quirks (e.g. BLE's 31-byte payload
 * limit, which may require splitting the advert across advertisement + scan
 * response).
 */
export class DiscoveryBeacon {
  private readonly nodeId: Uint8Array;
  private capabilities: Capability[];
  private readonly callbacks: DiscoveryBeaconCallbacks;
  private readonly advertTtlSeconds: number;
  private readonly intervalSeconds: number;
  private readonly transport: LinkTransportKind;
  private readonly linkAddress: Uint8Array;
  private readonly now: () => number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running: boolean = false;

  constructor(
    nodeId: Uint8Array,
    capabilities: Capability[],
    callbacks: DiscoveryBeaconCallbacks,
    options?: DiscoveryBeaconOptions,
  ) {
    if (!(nodeId instanceof Uint8Array) || nodeId.length !== NODE_ID_BYTES) {
      throw new Error(
        `DiscoveryBeacon.nodeId must be a ${NODE_ID_BYTES}-byte Uint8Array; got ${nodeId instanceof Uint8Array ? `${nodeId.length} bytes` : typeof nodeId}`,
      );
    }
    // Validate capabilities eagerly so buildAdvertisement can't fail later.
    if (!Array.isArray(capabilities)) {
      throw new Error("DiscoveryBeacon.capabilities must be an array");
    }
    for (const c of capabilities) {
      // `capabilityBit` throws on unknown capability names; we let it.
      capabilityBit(c);
    }
    this.nodeId = nodeId;
    this.capabilities = [...capabilities];
    this.callbacks = callbacks;

    const ttl = options?.advertTtlSeconds ?? DEFAULT_ADVERT_TTL_SECONDS;
    if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_ADVERT_TTL_SECONDS) {
      throw new Error(
        `DiscoveryBeacon.advertTtlSeconds must be an integer in (0, ${MAX_ADVERT_TTL_SECONDS}]; got ${ttl}`,
      );
    }
    this.advertTtlSeconds = ttl;

    const interval = options?.intervalSeconds ?? DEFAULT_BEACON_INTERVAL_SECONDS;
    if (!Number.isInteger(interval) || interval <= 0) {
      throw new Error(
        `DiscoveryBeacon.intervalSeconds must be a positive integer; got ${interval}`,
      );
    }
    // The interval SHOULD be ≤ advertTtlSeconds / 2 so peers observe at least
    // 2 adverts per TTL window (one missed packet doesn't lose the peer).
    if (interval * 2 > this.advertTtlSeconds) {
      throw new Error(
        `DiscoveryBeacon.intervalSeconds (${interval}) is too large relative to advertTtlSeconds (${this.advertTtlSeconds}); use an interval ≤ TTL/2 so peers observe multiple adverts per window`,
      );
    }
    this.intervalSeconds = interval;

    const transport = options?.transport ?? "ble";
    if (!isLinkTransportKind(transport)) {
      throw new Error(
        `DiscoveryBeacon.transport must be a valid LinkTransportKind; got "${transport}"`,
      );
    }
    this.transport = transport;

    const linkAddress = options?.linkAddress ?? new Uint8Array(0);
    if (!(linkAddress instanceof Uint8Array)) {
      throw new Error(
        `DiscoveryBeacon.linkAddress must be a Uint8Array; got ${linkAddress === null ? "null" : typeof linkAddress}`,
      );
    }
    this.linkAddress = linkAddress;

    this.now = options?.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Start broadcasting. Returns a `stop()` function.
   *
   * The beacon emits an advertisement immediately on start (so callers don't
   * have to wait for the first tick), then on every `intervalSeconds` tick.
   * The `stop()` function clears the timer; calling it is idempotent.
   *
   * If `start()` is called when already running, the second call returns a
   * no-op `stop()` function (the first `start()`'s `stop()` is the one that
   * actually stops the timer). This avoids double-timer bugs.
   */
  start(): () => void {
    if (this.timer !== null) {
      // Already running. Return a no-op stop function — calling it does
      // nothing; the original stop() (from the first start() call) is the
      // one that stops the timer.
      return () => {};
    }
    this.running = true;
    const tick = (): void => {
      if (!this.running) return;
      const adv = this.buildAdvertisement(this.now());
      const bytes = encodeDiscoveryAdvertisement(adv);
      try {
        this.callbacks.broadcast(this.transport, bytes);
      } catch {
        // Broadcast callback threw — swallow and retry on next tick. The
        // platform adapter is responsible for its own error handling; we
        // don't want a transient BLE error to crash the discovery loop.
      }
    };
    // Emit immediately so a freshly-started beacon advertises without waiting
    // for the first interval tick.
    tick();
    this.timer = setInterval(tick, this.intervalSeconds * 1000);
    return () => {
      this.running = false;
      if (this.timer !== null) {
        clearInterval(this.timer);
        this.timer = null;
      }
    };
  }

  /**
   * Update the capabilities the beacon advertises. Takes effect on the next
   * tick (within `intervalSeconds` seconds).
   *
   * Typical use: when battery drops to BATTERY_LOW, shed INTERNET_GATEWAY;
   * when the device goes on mains power, add it back. This is the runtime
   * knob that keeps the advert honest with the platform's actual capacity
   * (I12 — the platform-capability matrix is enforced at add-time by the
   * DescriptorStore, but capacity fluctuates at runtime and the beacon must
   * reflect that).
   */
  updateCapabilities(caps: Capability[]): void {
    if (!Array.isArray(caps)) {
      throw new Error("DiscoveryBeacon.updateCapabilities: caps must be an array");
    }
    for (const c of caps) {
      capabilityBit(c); // throws on unknown capability name
    }
    this.capabilities = [...caps];
  }

  /**
   * Build a `DiscoveryAdvertisement` for the current state, at a given time.
   *
   * Exposed publicly so tests can verify the advert format without running
   * the timer. Production callers should use `start()` to actually broadcast.
   */
  buildAdvertisement(now: number): DiscoveryAdvertisement {
    return {
      // First 8 bytes of the NodeId — the truncated hint. slice() returns a
      // copy so the caller cannot mutate our nodeId via the advert.
      nodeIdPrefix: this.nodeId.slice(0, NODE_ID_PREFIX_BYTES),
      capabilityMask: buildCapabilityMask(this.capabilities),
      transport: this.transport,
      // Copy the link address too (defensive — though platform adapters
      // typically don't mutate the bytes they're given).
      linkAddress: this.linkAddress.slice(),
      generatedAt: now,
      expiresAt: now + this.advertTtlSeconds,
    };
  }
}

// ─── 4. DiscoveryScanner (spec §5 tier 1 — receive) ───────────────────────

/** Callbacks invoked by `DiscoveryScanner` when an advertisement is observed. */
export interface DiscoveryScannerCallbacks {
  /**
   * Called when a new advertisement is observed (after successful decode +
   * structural validation). Expired advertisements ARE surfaced — the
   * callback decides whether to act on them (e.g. a recently-expired advert
   * might still be worth a connection attempt; a long-expired one is not).
   *
   * The callback receives the decoded `DiscoveryAdvertisement`. The `transport`
   * parameter to `observe()` is NOT passed to the callback — the advertisement
   * itself carries the transport the advertiser is reachable on, which is
   * what the callback needs to initiate a connection.
   */
  onAdvertisement: (adv: DiscoveryAdvertisement) => void;
}

/**
 * Receives link-local `DiscoveryAdvertisement`s from a platform scanner
 * (BLE scan, mDNS browser, Wi-Fi Direct service discovery).
 *
 * The scanner is the receive-side counterpart to `DiscoveryBeacon`. Platform
 * adapters feed observed advertisement bytes via `observe()`; the scanner
 * decodes them, structurally validates them, and surfaces the result via the
 * `onAdvertisement` callback.
 *
 * Per I20: malformed bytes are silently dropped (the scanner never throws for
 * peer-supplied input). The audit (00-AUDIT.md §3.9) found that the existing
 * codebase's `FakeCryptoProvider.verify => signature.size == 64` pattern
 * accepted any 64 bytes as a valid signature; the symmetric failure mode
 * here would be accepting any bytes as a valid advertisement. We avoid that
 * by structural validation in `decodeDiscoveryAdvertisement` (which throws
 * CborError on malformed input) wrapped in a try/catch that drops on failure.
 */
export class DiscoveryScanner {
  constructor(private readonly callbacks: DiscoveryScannerCallbacks) {}

  /**
   * Feed an observed advertisement byte blob (from a BLE scan, mDNS, etc.).
   *
   * @param transport  the link-layer transport the bytes were received on.
   *                   This is INFORMATIONAL — it does NOT need to match
   *                   `adv.transport` (the advertiser may advertise TCP
   *                   reachability via an mDNS packet, for example). The
   *                   scanner does not enforce a match; the callback decides.
   * @param bytes      the raw advertisement bytes (CBOR-encoded
   *                   `DiscoveryAdvertisement`).
   */
  observe(transport: LinkTransportKind, bytes: Uint8Array): void {
    // Defensive: ignore non-bytes input (a misbehaving platform adapter
    // shouldn't crash the scanner).
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      return;
    }
    // `transport` is informational; we don't validate it against
    // VALID_TRANSPORTS here (the type system enforces it at compile time,
    // and runtime enforcement is the platform adapter's responsibility).

    let adv: DiscoveryAdvertisement;
    try {
      adv = decodeDiscoveryAdvertisement(bytes);
    } catch {
      // Malformed — drop silently (I20: never throw for peer-supplied input).
      return;
    }
    try {
      this.callbacks.onAdvertisement(adv);
    } catch {
      // Callback threw — swallow. A misbehaving callback must not crash the
      // scanner (which would silently drop all subsequent advertisements).
    }
  }
}

// ─── 5. Anti-entropy HAVE vectors (spec §5 tier 2 + 06-CONFORMANCE §A4) ───

/**
 * Build a "HAVE" vector — a CBOR array of NodeIds whose descriptors we hold —
 * for the anti-entropy exchange.
 *
 * This is the structured replacement for the audit's literal `"HAVE:"` ASCII
 * string (00-AUDIT.md §3.7: "`RealSyncDependencies.getHaveVector()` returns
 * `emptyList()`. The literal bytes sent to every peer are `HAVE:`."). The
 * wire format is a canonical CBOR array of 32-byte NodeId byte strings:
 *
 *   HAVE = [* bstr .size 32]   ; array of NodeIds
 *
 * Only NodeIds whose descriptors are currently non-expired are included
 * (spec §5 freshness rule — "MUST NOT be forwarded" applies to the advert
 * itself, and by extension to its presence in a HAVE vector: advertising
 * that we have an expired descriptor would mislead the peer into requesting
 * it).
 *
 * @param store  the descriptor store to enumerate
 * @param now    current time in unix seconds (for expiry filtering)
 * @returns      canonical CBOR bytes encoding the array of NodeIds
 */
export function buildHaveVector(
  store: DescriptorStore,
  now: number,
): Uint8Array {
  const activeDescs = store.activeNodeDescriptors(now);
  // Deduplicate by NodeId (activeNodeDescriptors already returns one entry
  // per NodeId since the store keys by NodeId, but dedup is cheap insurance).
  const seen = new Set<string>();
  const nodeIds: CborValue[] = [];
  for (const desc of activeDescs) {
    const key = bytesToHex(desc.nodeId);
    if (seen.has(key)) continue;
    seen.add(key);
    nodeIds.push(desc.nodeId);
  }
  return cborEncode(nodeIds);
}

/**
 * Parse a peer's HAVE vector and return the NodeIds it claims to hold.
 *
 * The caller diffs this list against its own store to determine which
 * descriptors to send the peer (descriptors the peer is missing) and which
 * to request (descriptors the peer has that the caller is missing).
 *
 * Throws `CborError(MALFORMED)` on:
 *   - Non-CBOR bytes.
 *   - Top-level value is not a CBOR array.
 *   - Any entry is not a 32-byte byte string.
 *
 * This is a parser — it throws on malformed input. Callers wrapping it in
 * an anti-entropy loop should catch CborError and drop the peer's HAVE
 * vector on failure (treat as if the peer sent an empty vector).
 *
 * @param bytes  the CBOR-encoded HAVE vector
 * @returns      array of 32-byte NodeIds
 */
export function parseHaveVector(bytes: Uint8Array): Uint8Array[] {
  let value: CborValue;
  try {
    value = cborDecode(bytes);
  } catch (e) {
    if (e instanceof CborError) throw e;
    throw new CborError(
      `Failed to decode HAVE vector: ${e instanceof Error ? e.message : String(e)}`,
      "DECODE_ERROR",
    );
  }
  if (!Array.isArray(value)) {
    throw new CborError(
      `HAVE vector must be a CBOR array; got ${value === null ? "null" : typeof value === "object" ? (value instanceof Map ? "map" : Array.isArray(value) ? "array" : "object") : typeof value}`,
      "MALFORMED",
    );
  }
  const out: Uint8Array[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (!(item instanceof Uint8Array) || item.length !== NODE_ID_BYTES) {
      throw new CborError(
        `HAVE vector entry ${i} must be a ${NODE_ID_BYTES}-byte byte string; got ${item instanceof Uint8Array ? `${item.length} bytes` : item === null ? "null" : typeof item}`,
        "MALFORMED",
      );
    }
    out.push(item);
  }
  return out;
}

// ─── 6. Platform-capability validation (I12) ──────────────────────────────

/**
 * Forbidden capability combinations per platform, from
 * 03-PLATFORM-MATRIX.md §2.
 *
 * ❌ entries in the matrix are forbidden (the platform cannot sustain them).
 * ⚠️ entries are allowed-with-caveats (the platform can sustain them with
 *    restrictions like foreground-only, or with caveats like "laptops sleep");
 *    we treat ⚠️ as ALLOWED — the matrix's caveats are advisory and enforced
 *    by the platform adapter, not by the protocol.
 *
 * Concretely:
 *   - iOS: MESH_RELAY ❌, INTERNET_GATEWAY ❌, CUSTODY ❌, COMMUNITY_RELAY ❌
 *     (spec §4 of the platform matrix: "iPhone as INTERNET_GATEWAY: ❌
 *     NEPacketTunnelProvider is architected to send THIS DEVICE'S traffic
 *     to a remote server. It is not a mechanism for accepting and egressing
 *     others' traffic. ... iPhone as reliable MESH_RELAY: ❌ No foreground-
 *     service equivalent.")
 *   - Android: COMMUNITY_RELAY ❌ (spec §2: "Android ... COMMUNITY_RELAY ❌").
 *   - Windows/macOS: COMMUNITY_RELAY ❌ (spec §2: "Windows/macOS — all except
 *     COMMUNITY_RELAY (⚠️ — laptops sleep)").
 *   - Linux: all ✅ (the reference COMMUNITY_RELAY-capable desktop platform).
 *   - embedded (RPi): all ✅ ("the reference COMMUNITY_RELAY platform").
 *
 * The forbidden set for each platform is a ReadonlySet<Capability>; lookup
 * is O(1).
 */
const FORBIDDEN_CAPABILITIES: ReadonlyMap<Platform, ReadonlySet<Capability>> =
  new Map<Platform, ReadonlySet<Capability>>([
    ["android", new Set<Capability>(["COMMUNITY_RELAY"])],
    [
      "ios",
      new Set<Capability>([
        "MESH_RELAY",
        "INTERNET_GATEWAY",
        "CUSTODY",
        "COMMUNITY_RELAY",
      ]),
    ],
    ["linux", new Set<Capability>()],
    ["macos", new Set<Capability>(["COMMUNITY_RELAY"])],
    ["windows", new Set<Capability>(["COMMUNITY_RELAY"])],
    ["embedded", new Set<Capability>()],
  ]);

/**
 * Validate that a platform is allowed to advertise a set of capabilities,
 * per the normative capability matrix in 03-PLATFORM-MATRIX.md §2.
 *
 * This is the I12 enforcement at the discovery layer. The `DescriptorStore`
 * calls this before accepting a `NodeDescriptor`, so a descriptor advertising
 * e.g. iOS + INTERNET_GATEWAY is rejected before it can mislead the routing
 * layer. This is the structured fix for the audit's missing primitive #1
 * — without this check, a misconfigured or compromised iOS device could
 * advertise itself as a gateway and attract traffic it cannot egress.
 *
 * @param platform      the platform string (one of PLATFORMS)
 * @param capabilities  the capabilities the descriptor claims
 * @returns             true iff the platform is known AND none of the
 *                      capabilities are forbidden for that platform.
 *                      Returns false (fail-closed) for an unknown platform
 *                      or an unknown capability name.
 */
export function validatePlatformCapabilities(
  platform: Platform,
  capabilities: Capability[],
): boolean {
  // Fail-closed on unknown platform (defensive — TypeScript prevents this at
  // compile time, but a runtime `as Platform` cast could smuggle in a bad value).
  if (!PLATFORMS.includes(platform)) return false;
  const forbidden = FORBIDDEN_CAPABILITIES.get(platform);
  if (forbidden === undefined) return false;
  if (!Array.isArray(capabilities)) return false;
  for (const c of capabilities) {
    // Fail-closed on unknown capability name.
    if (!CAPABILITIES.includes(c)) return false;
    if (forbidden.has(c)) return false;
  }
  return true;
}
