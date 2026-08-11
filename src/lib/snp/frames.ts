/**
 * SNP Frame — the wire unit every relay sees on every link
 *
 * Source: 02-PROTOCOL-SPEC.md §7.1 (Frame CDDL)
 * Source: 02-PROTOCOL-SPEC.md §7.4 (metadata-minimization: padding, blinded src)
 * Source: 00-AUDIT.md §3.6 (finding R5 — Class B transit was conflated with
 *         Class A content, leaking transit traffic to content-caching paths)
 * Source: 06-CONFORMANCE-AND-AI-MODEL.md §B3 (Invariants I7, I8, I20)
 *
 * The Frame is THE structural unit that crosses every SNP link. The single
 * most important design decision in the redesign is the split between:
 *
 *   - Class A (content)   — body is an object-protocol message (Manifest
 *                            request, chunk fetch, etc.). MAY be inspected,
 *                            cached, deduplicated, and sourced from any
 *                            peer that has the object.
 *   - Class B (transit)   — body is opaque AEAD ciphertext for a downstream
 *                            circuit. Relays MUST NOT inspect, cache, or
 *                            deduplicate (I8). The frame is forwarded purely
 *                            on (dst, fid, ttl).
 *   - Class C (control)   — body is a link/control message (descriptor
 *                            gossip, route adverts, revocations, receipts).
 *                            Inspected but not cached as content.
 *
 * The `cls` field is the discriminator. The Frame type itself is neutral —
 * relay policy (inspect/cache/dedup or not) is enforced elsewhere — but the
 * `cls` field is what tells the relay which policy to apply. A relay that
 * confuses Class B for Class A reintroduces the audit's R5 leak.
 *
 * The CDDL (02-PROTOCOL-SPEC.md §7.1) is:
 *
 *   Frame = {
 *     v:     uint,              ; protocol version = 1
 *     cls:   "A" / "B" / "C",   ; A=content, B=transit, C=control
 *     dst:   bstr .size 32,     ; destination NodeId
 *     src:   bstr .size 32,     ; source NodeId (or blinded per §7.4)
 *     ttl:   uint,              ; decrement per hop, drop at 0. Max 16.
 *     fid:   bstr .size 8,      ; flow/circuit id — opaque to relays
 *     seq:   uint,
 *     body:  bstr               ; Class A: object protocol. Class B: ciphertext.
 *   }
 *
 * Invariants enforced here:
 *
 *   I7  — Frame TTL ≤ 16, decremented every hop.
 *         `validateFrame` enforces the upper bound (ttl in [0, 16]).
 *         `forwardFrame` enforces the lower bound (throws at ttl === 0).
 *         `shouldDrop` is the relay-side check (ttl <= 0 ⇒ drop).
 *   I8  — Class B payloads are never inspected, cached, or duplicated by
 *         relays. The Frame type itself is neutral — the relay policy is
 *         enforced elsewhere — but the `cls` field is the discriminator.
 *         The JSDoc on `body` spells out the contract.
 *   I20 — `decodeFrame` and `validateFrame` throw on structural problems;
 *         they never silently accept malformed input.
 *
 * @ invariant I7  — Frame TTL ≤ 16, decremented every hop
 * @ invariant I8  — Class B body is opaque to relays; never inspected/cached/dedup'd
 * @ invariant I20 — decode/validate throw on malformed input; never permissive
 */

import { randomBytes } from "@noble/hashes/utils.js";
import {
  FRAME_VERSION,
  FRAME_TTL_MAX,
  FRAME_FLOW_ID_BYTES,
  FRAME_PADDING_BUCKETS,
  TRAFFIC_CLASSES,
  type TrafficClass,
} from "./constants";
import { type CborValue, CborError, cborMap, encode, decode } from "./cbor";

// ─── Local constants ───────────────────────────────────────────────────────

/** Byte length of a NodeId (matches SHA-256 output, I4). */
const NODE_ID_BYTES = 32;

/** Required Frame map keys (closed CDDL map — extras MUST be rejected). */
const FRAME_KEYS = ["v", "cls", "dst", "src", "ttl", "fid", "seq", "body"] as const;

// ─── Frame interface ───────────────────────────────────────────────────────

/**
 * A SNP Frame — the wire unit every relay sees on every link.
 *
 * Field semantics (02-PROTOCOL-SPEC.md §7.1):
 *
 *   - `v`    — protocol version. MUST equal FRAME_VERSION (1).
 *   - `cls`  — traffic class discriminator: "A"=content, "B"=transit,
 *              "C"=control. Determines relay policy on `body`.
 *   - `dst`  — destination NodeId (32 bytes). For Class B transit the relay
 *              forwards toward `dst` without inspecting `body`.
 *   - `src`  — source NodeId (32 bytes). May be blinded/rotated per §7.4
 *              for metadata minimisation, but the wire field is always a
 *              32-byte bstr.
 *   - `ttl`  — time-to-live in hops. Max FRAME_TTL_MAX (16). Decremented
 *              every hop by `forwardFrame`; dropped at 0 by `shouldDrop`.
 *              0 is a structurally valid value ("drop on receipt") —
 *              forwarding logic checks > 0 before forwarding.
 *   - `fid`  — flow/circuit id (8 bytes). OPAQUE to relays — used only to
 *              distinguish frames on the same (src,dst) pair. For Class B
 *              this is the circuit id; for Class A it is the object-flow id.
 *   - `seq`  — per-flow sequence number. Non-negative integer.
 *   - `body` — payload bytes. See the JSDoc on the field below.
 */
export interface Frame {
  /** Protocol version. MUST equal FRAME_VERSION (1). */
  readonly v: number;
  /** Traffic class: "A"=content, "B"=transit, "C"=control. */
  readonly cls: TrafficClass;
  /** Destination NodeId (32 bytes). */
  readonly dst: Uint8Array;
  /** Source NodeId (32 bytes), or a blinded/rotated value per §7.4. */
  readonly src: Uint8Array;
  /** Time-to-live in hops, [0, FRAME_TTL_MAX]. Decremented per hop. */
  readonly ttl: number;
  /** Flow/circuit id (8 bytes). Opaque to relays. */
  readonly fid: Uint8Array;
  /** Per-flow sequence number (non-negative integer). */
  readonly seq: number;
  /**
   * Payload bytes.
   *
   * Class A: object protocol bytes (manifest request, chunk fetch, etc.).
   * Class B: opaque AEAD ciphertext — relays MUST NOT inspect, cache, or
   *          deduplicate. The relay forwards purely on (dst, fid, ttl);
   *          it never looks inside `body` for a Class B frame (I8).
   * Class C: link/control message bytes (descriptor gossip, route advert,
   *          revocation, receipt). Inspected but not cached as content.
   *
   * The Frame type itself is neutral about how `body` is handled — relay
   * policy is enforced by the forwarding code keyed on `cls`. The contract
   * above is the spec requirement that policy must implement.
   */
  readonly body: Uint8Array;
}

// ─── Frame → CBOR map ──────────────────────────────────────────────────────

/**
 * Build the canonical CBOR map for a Frame.
 *
 * The map uses STRING keys (per the CDDL: `v`, `cls`, `dst`, `src`, `ttl`,
 * `fid`, `seq`, `body`). Canonical (length-first) key ordering is applied
 * at encode time by the SNP-CBOR encoder, so callers may pass entries in
 * any order; the emitted bytes are always canonical.
 *
 * This function does NOT validate the frame — it only assembles the map.
 * Callers that need validation (signers, encoders that must fail-fast)
 * should call `validateFrame` first.
 *
 * @param frame  the Frame to encode
 * @returns      a CborValue Map with string keys, ready for `encode()`
 */
export function frameToCborMap(
  frame: Frame,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["v", frame.v],
    ["cls", frame.cls],
    ["dst", frame.dst],
    ["src", frame.src],
    ["ttl", frame.ttl],
    ["fid", frame.fid],
    ["seq", frame.seq],
    ["body", frame.body],
  ]);
}

// ─── Encode ────────────────────────────────────────────────────────────────

/**
 * Encode a Frame to canonical SNP-CBOR bytes.
 *
 * Validates the frame first (fail-fast: never emit malformed bytes), then
 * builds the canonical map and encodes it. The output is a definite-length
 * CBOR map with keys in canonical (length-first) order, per I1.
 *
 * @param frame  the Frame to encode
 * @returns      canonical CBOR bytes for the Frame
 * @throws       CborError(MALFORMED) if the frame fails structural validation
 */
export function encodeFrame(frame: Frame): Uint8Array {
  validateFrame(frame);
  return encode(frameToCborMap(frame));
}

// ─── Decode ────────────────────────────────────────────────────────────────

/**
 * Decode canonical SNP-CBOR bytes into a Frame.
 *
 * Calls `decode(bytes)` (which rejects trailing bytes, non-canonical key
 * order, duplicate keys, and non-shortest integer encodings), then verifies
 * the decoded value is a Frame-shaped map and runs `validateFrame` on the
 * extracted fields.
 *
 * This function NEVER silently accepts malformed input (I20). Any
 * structural problem — wrong types, missing keys, extra keys, out-of-range
 * ttl, wrong-length bstr fields, non-canonical CBOR — throws CborError.
 *
 * @param bytes  canonical CBOR bytes of a Frame
 * @returns      the decoded Frame
 * @throws       CborError on any decode or validation failure
 */
export function decodeFrame(bytes: Uint8Array): Frame {
  if (!(bytes instanceof Uint8Array)) {
    throw new CborError("decodeFrame: input must be a Uint8Array", "MALFORMED");
  }
  // decode() rejects trailing bytes, non-canonical key order, duplicate keys,
  // and non-shortest integer encodings. Anything that survives this call is
  // well-formed SNP-CBOR; we then check it is Frame-shaped.
  const value = decode(bytes);
  if (!(value instanceof Map)) {
    throw new CborError(
      "Frame must decode to a CBOR map",
      "MALFORMED",
    );
  }

  // The map's keys are text strings (we encoded them that way), so they
  // decode back to JS strings. Reject any non-string keys defensively.
  for (const k of value.keys()) {
    if (typeof k !== "string") {
      throw new CborError(
        "Frame map keys must be text strings",
        "MALFORMED",
      );
    }
  }

  // Closed CDDL map: exactly the 8 known keys, no more, no less.
  if (value.size !== FRAME_KEYS.length) {
    throw new CborError(
      `Frame map must have exactly ${FRAME_KEYS.length} keys; got ${value.size}`,
      "MALFORMED",
    );
  }

  const frame: Frame = {
    v:    extractUint(value.get("v"),    "v"),
    cls:  extractClass(value.get("cls"), "cls"),
    dst:  extractBstr(value.get("dst"),  NODE_ID_BYTES,        "dst"),
    src:  extractBstr(value.get("src"),  NODE_ID_BYTES,        "src"),
    ttl:  extractUint(value.get("ttl"),  "ttl"),
    fid:  extractBstr(value.get("fid"),  FRAME_FLOW_ID_BYTES,  "fid"),
    seq:  extractUint(value.get("seq"),  "seq"),
    body: extractBstrAny(value.get("body"), "body"),
  };

  // Final structural validation (range checks on v, ttl, seq).
  validateFrame(frame);
  return frame;
}

// ─── Validate ──────────────────────────────────────────────────────────────

/**
 * Validate the structure of a Frame against the CDDL constraints.
 *
 * Throws `CborError(MALFORMED)` on any violation. This is the single
 * structural gate for frames: it is called by `encodeFrame` (fail-fast:
 * never emit malformed bytes) and `decodeFrame` (reject malformed input).
 * Callers that want a boolean instead of a throw should wrap in try/catch.
 *
 * Checks:
 *   - `v`    must equal FRAME_VERSION (1)
 *   - `cls`  must be one of "A", "B", "C" (TRAFFIC_CLASSES)
 *   - `dst`  must be a Uint8Array of exactly 32 bytes
 *   - `src`  must be a Uint8Array of exactly 32 bytes
 *   - `ttl`  must be an integer in [0, FRAME_TTL_MAX] (0..16 inclusive —
 *             0 is valid because it means "drop on receipt"; forwarding
 *             logic checks > 0 before forwarding)
 *   - `fid`  must be a Uint8Array of exactly 8 bytes
 *   - `seq`  must be a non-negative integer
 *   - `body` must be a Uint8Array (any length, including zero)
 *
 * @param frame  the Frame to validate
 * @throws       CborError(MALFORMED) on any structural violation
 */
export function validateFrame(frame: Frame): void {
  // v — must equal FRAME_VERSION
  if (typeof frame.v !== "number" || !Number.isInteger(frame.v)) {
    throw new CborError(
      `Frame.v must be an integer; got ${typeof frame.v}`,
      "MALFORMED",
    );
  }
  if (frame.v !== FRAME_VERSION) {
    throw new CborError(
      `Frame.v must equal FRAME_VERSION (${FRAME_VERSION}); got ${frame.v}`,
      "MALFORMED",
    );
  }

  // cls — one of TRAFFIC_CLASSES
  if (typeof frame.cls !== "string") {
    throw new CborError(
      `Frame.cls must be a string; got ${typeof frame.cls}`,
      "MALFORMED",
    );
  }
  if (!TRAFFIC_CLASSES.includes(frame.cls as TrafficClass)) {
    throw new CborError(
      `Frame.cls must be one of ${JSON.stringify([...TRAFFIC_CLASSES])}; got "${frame.cls}"`,
      "MALFORMED",
    );
  }

  // dst — 32-byte bstr
  if (!(frame.dst instanceof Uint8Array) || frame.dst.length !== NODE_ID_BYTES) {
    throw new CborError(
      `Frame.dst must be a ${NODE_ID_BYTES}-byte Uint8Array; got length ${byteLength(frame.dst)}`,
      "MALFORMED",
    );
  }

  // src — 32-byte bstr (may be blinded per §7.4, but still 32 bytes on wire)
  if (!(frame.src instanceof Uint8Array) || frame.src.length !== NODE_ID_BYTES) {
    throw new CborError(
      `Frame.src must be a ${NODE_ID_BYTES}-byte Uint8Array; got length ${byteLength(frame.src)}`,
      "MALFORMED",
    );
  }

  // ttl — integer in [0, FRAME_TTL_MAX]. 0 is valid (drop-on-receipt).
  if (typeof frame.ttl !== "number" || !Number.isInteger(frame.ttl)) {
    throw new CborError(
      `Frame.ttl must be an integer; got ${typeof frame.ttl}`,
      "MALFORMED",
    );
  }
  if (frame.ttl < 0 || frame.ttl > FRAME_TTL_MAX) {
    throw new CborError(
      `Frame.ttl must be in [0, ${FRAME_TTL_MAX}]; got ${frame.ttl}`,
      "MALFORMED",
    );
  }

  // fid — 8-byte bstr
  if (!(frame.fid instanceof Uint8Array) || frame.fid.length !== FRAME_FLOW_ID_BYTES) {
    throw new CborError(
      `Frame.fid must be a ${FRAME_FLOW_ID_BYTES}-byte Uint8Array; got length ${byteLength(frame.fid)}`,
      "MALFORMED",
    );
  }

  // seq — non-negative integer
  if (typeof frame.seq !== "number" || !Number.isInteger(frame.seq) || frame.seq < 0) {
    throw new CborError(
      `Frame.seq must be a non-negative integer; got ${frame.seq}`,
      "MALFORMED",
    );
  }

  // body — Uint8Array of any length (including zero)
  if (!(frame.body instanceof Uint8Array)) {
    throw new CborError(
      `Frame.body must be a Uint8Array; got ${describeType(frame.body)}`,
      "MALFORMED",
    );
  }
}

// ─── Forward ───────────────────────────────────────────────────────────────

/**
 * Produce a forwarded copy of a Frame with `ttl` decremented by 1.
 *
 * This is the per-hop TTL decrement mandated by I7. The returned frame is a
 * NEW object — the input is not mutated — with all fields identical except
 * `ttl`, which is `frame.ttl - 1`.
 *
 * Throws `CborError(MALFORMED)` if `frame.ttl` is already 0. A frame with
 * no TTL remaining cannot be forwarded — this enforces the audit's "TTL=0
 * drop" negative vector (00-AUDIT.md §3.6 / 06-CONFORMANCE-AND-AI-MODEL.md
 * §A5): relays MUST drop frames whose TTL has reached 0 rather than
 * forwarding them with a negative or wrapped TTL.
 *
 * This function does NOT re-validate the rest of the frame — it assumes the
 * caller is forwarding a frame that was already decoded/validated. If the
 * caller is unsure, call `validateFrame` first.
 *
 * @param frame  the Frame to forward (must have ttl > 0)
 * @returns      a NEW Frame with ttl decremented by 1; all other fields identical
 * @throws       CborError(MALFORMED) if frame.ttl is 0 (cannot forward)
 */
export function forwardFrame(frame: Frame): Frame {
  if (typeof frame.ttl !== "number" || !Number.isInteger(frame.ttl)) {
    throw new CborError(
      `forwardFrame: frame.ttl must be an integer; got ${frame.ttl}`,
      "MALFORMED",
    );
  }
  if (frame.ttl <= 0) {
    throw new CborError(
      `forwardFrame: cannot forward a frame with ttl ${frame.ttl} (TTL exhausted — drop)`,
      "MALFORMED",
    );
  }
  return {
    ...frame,
    ttl: frame.ttl - 1,
  };
}

// ─── Drop check ────────────────────────────────────────────────────────────

/**
 * Relay-side TTL exhaustion check.
 *
 * Returns `true` if the frame should be dropped because its TTL has been
 * exhausted (ttl <= 0). Relays call this BEFORE forwarding: a frame with
 * `ttl <= 0` is dropped on receipt rather than forwarded (I7).
 *
 * Note: a structurally valid frame may have `ttl === 0` ("drop on receipt"
 * — used for local-delivery-only frames). `validateFrame` accepts ttl=0;
 * `shouldDrop` is the relay policy that says "don't forward it."
 *
 * @param frame  the Frame to check
 * @returns      true iff the frame's TTL is exhausted (ttl <= 0)
 */
export function shouldDrop(frame: Frame): boolean {
  return frame.ttl <= 0;
}

// ─── Body padding (metadata minimization, §7.4) ────────────────────────────

/**
 * Pad a frame body to the next bucket size from `FRAME_PADDING_BUCKETS`
 * ([256, 512, 1024, 1500]).
 *
 * This implements the metadata-minimization mitigation from spec §7.4: by
 * padding every body to one of a small set of fixed sizes, a relay observing
 * the frame on the wire cannot infer the original body length (and thus
 * cannot easily fingerprint object types or circuit phases from length
 * alone). The original length is preserved out-of-band (returned here so the
 * recipient can strip the padding with `unpadBody`).
 *
 * Behavior:
 *   - If `body.length <= 256`,  padded to 256.
 *   - If `body.length <= 512`,  padded to 512.
 *   - If `body.length <= 1024`, padded to 1024.
 *   - If `body.length <= 1500`, padded to 1500.
 *   - If `body.length > 1500`,  NO padding is applied (the body is returned
 *     as-is, with originalLength === body.length). The largest bucket is
 *     1500 (a conservative MTU), so bodies larger than that are sent
 *     unpadded rather than fragmented.
 *
 * Padding is appended zero bytes. If the body is already exactly a bucket
 * size, no zero bytes are appended (the padded output equals the input,
 * but a copy is returned so the caller cannot mutate the input via the
 * returned array).
 *
 * @param body  the original body bytes
 * @returns     `{ padded, originalLength }` — `padded` is the padded body,
 *              `originalLength` is the length to pass to `unpadBody`
 * @throws      CborError(MALFORMED) if `body` is not a Uint8Array
 */
export function padBody(
  body: Uint8Array,
): { padded: Uint8Array; originalLength: number } {
  if (!(body instanceof Uint8Array)) {
    throw new CborError(
      "padBody: body must be a Uint8Array",
      "MALFORMED",
    );
  }
  const originalLength = body.length;

  // Find the smallest bucket that fits the body. FRAME_PADDING_BUCKETS is
  // sorted ascending, so the first bucket >= body.length is the target.
  let target = 0;
  for (const bucket of FRAME_PADDING_BUCKETS) {
    if (body.length <= bucket) {
      target = bucket;
      break;
    }
  }

  // Body is larger than the largest bucket — no padding applied.
  if (target === 0) {
    return { padded: body.slice(), originalLength };
  }

  // Body fits in a bucket. Allocate a zero-filled buffer of the target size
  // and copy the body in. The trailing bytes are zero by default.
  const padded = new Uint8Array(target);
  padded.set(body, 0);
  return { padded, originalLength };
}

/**
 * Strip padding from a padded body, restoring the original length.
 *
 * The caller MUST pass the `originalLength` returned by `padBody` (or known
 * out-of-band). This function does NOT verify that the stripped bytes were
 * zero — padding integrity is not authenticated at this layer (the body
 * itself is either an authenticated object-protocol message or an AEAD
 * ciphertext, both of which detect tampering).
 *
 * @param padded          the padded body bytes
 * @param originalLength  the original (pre-padding) length, from `padBody`
 * @returns               the original body bytes (a slice of `padded`)
 * @throws                CborError(MALFORMED) if `padded` is not a Uint8Array,
 *                        if `originalLength` is not a non-negative integer,
 *                        or if `originalLength > padded.length`
 */
export function unpadBody(padded: Uint8Array, originalLength: number): Uint8Array {
  if (!(padded instanceof Uint8Array)) {
    throw new CborError(
      "unpadBody: padded must be a Uint8Array",
      "MALFORMED",
    );
  }
  if (typeof originalLength !== "number" || !Number.isInteger(originalLength) || originalLength < 0) {
    throw new CborError(
      `unpadBody: originalLength must be a non-negative integer; got ${originalLength}`,
      "MALFORMED",
    );
  }
  if (originalLength > padded.length) {
    throw new CborError(
      `unpadBody: originalLength ${originalLength} exceeds padded length ${padded.length}`,
      "MALFORMED",
    );
  }
  return padded.slice(0, originalLength);
}

// ─── Flow id ───────────────────────────────────────────────────────────────

/**
 * Generate a fresh 8-byte flow/circuit id.
 *
 * Uses `randomBytes` from `@noble/hashes/utils` (which delegates to the
 * platform CSPRNG: `crypto.getRandomValues` in browsers / `crypto.randomBytes`
 * in Node). The flow id is opaque to relays — it only distinguishes frames
 * on the same (src, dst) pair. For Class B transit this is the circuit id;
 * for Class A it is the object-flow id.
 *
 * @returns 8 cryptographically-random bytes
 */
export function makeFlowId(): Uint8Array {
  return randomBytes(FRAME_FLOW_ID_BYTES);
}

// ─── Internal decode helpers ───────────────────────────────────────────────
//
// These extract typed values from a decoded CborValue, throwing CborError
// (MALFORMED) if the value is missing or has the wrong type. The CBOR
// decoder represents integers as `number` (within safe-integer range) or
// `bigint`; both are accepted for uint fields, but we require them to be
// non-negative and within the safe-integer range (CDDL uint is unbounded,
// but SNP frame fields v/ttl/seq are all small).

/**
 * Extract a CBOR uint (major type 0) as a non-negative JS number.
 * Accepts both `number` and `bigint` (CborValue's two integer forms),
 * but rejects values outside the safe-integer range.
 */
function extractUint(v: CborValue | undefined, field: string): number {
  if (v === undefined) {
    throw new CborError(`Frame.${field} is missing`, "MALFORMED");
  }
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0) {
      throw new CborError(
        `Frame.${field} must be a non-negative integer; got ${v}`,
        "MALFORMED",
      );
    }
    return v;
  }
  if (typeof v === "bigint") {
    if (v < 0n) {
      throw new CborError(
        `Frame.${field} must be a non-negative integer; got ${v}`,
        "MALFORMED",
      );
    }
    if (v > Number.MAX_SAFE_INTEGER) {
      throw new CborError(
        `Frame.${field} exceeds JavaScript safe-integer range: ${v}`,
        "MALFORMED",
      );
    }
    return Number(v);
  }
  throw new CborError(
    `Frame.${field} must be a CBOR uint; got ${describeType(v)}`,
    "MALFORMED",
  );
}

/**
 * Extract a CBOR text string and verify it is one of the TRAFFIC_CLASSES.
 */
function extractClass(v: CborValue | undefined, field: string): TrafficClass {
  if (v === undefined) {
    throw new CborError(`Frame.${field} is missing`, "MALFORMED");
  }
  if (typeof v !== "string") {
    throw new CborError(
      `Frame.${field} must be a text string; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  if (!TRAFFIC_CLASSES.includes(v as TrafficClass)) {
    throw new CborError(
      `Frame.${field} must be one of ${JSON.stringify([...TRAFFIC_CLASSES])}; got "${v}"`,
      "MALFORMED",
    );
  }
  return v as TrafficClass;
}

/**
 * Extract a CBOR bstr (major type 2) of exactly `expected` bytes.
 */
function extractBstr(
  v: CborValue | undefined,
  expected: number,
  field: string,
): Uint8Array {
  if (v === undefined) {
    throw new CborError(`Frame.${field} is missing`, "MALFORMED");
  }
  if (!(v instanceof Uint8Array)) {
    throw new CborError(
      `Frame.${field} must be a ${expected}-byte byte string; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  if (v.length !== expected) {
    throw new CborError(
      `Frame.${field} must be ${expected} bytes; got ${v.length}`,
      "MALFORMED",
    );
  }
  return v;
}

/**
 * Extract a CBOR bstr (major type 2) of any length (including zero).
 * Used for `body`, which the CDDL leaves as an unbounded bstr.
 */
function extractBstrAny(v: CborValue | undefined, field: string): Uint8Array {
  if (v === undefined) {
    throw new CborError(`Frame.${field} is missing`, "MALFORMED");
  }
  if (!(v instanceof Uint8Array)) {
    throw new CborError(
      `Frame.${field} must be a byte string; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  return v;
}

// ─── Tiny type-description helpers ─────────────────────────────────────────

/** Human-readable type name for an unknown value, for error messages. */
function describeType(v: unknown): string {
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (typeof v === "number") return `number (${v})`;
  if (typeof v === "bigint") return `bigint (${v})`;
  if (typeof v === "string") return `string ("${v}")`;
  if (typeof v === "boolean") return `boolean (${v})`;
  if (v instanceof Uint8Array) return `Uint8Array (length ${v.length})`;
  if (Array.isArray(v)) return `array (length ${v.length})`;
  if (v instanceof Map) return `map (size ${v.size})`;
  return typeof v;
}

/** Length of a value if it is a Uint8Array, else a descriptive placeholder. */
function byteLength(v: unknown): string {
  if (v instanceof Uint8Array) return String(v.length);
  return describeType(v);
}
