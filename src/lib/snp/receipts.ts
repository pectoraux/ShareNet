/**
 * SNP Contribution Receipts — Civic Points proof objects
 *
 * Source: 05-CIVIC-CONTENT-CONSISTENCY.md §A3 (contribution types & proofs),
 *         §A4 (TransitReceipt CDDL), §A6 (anti-farming)
 * Source: 02-PROTOCOL-SPEC.md §A4 (DeliveryReceipt / CustodyReceipt CDDL)
 * Source: 00-AUDIT.md §3.7 (finding R7 — the bug this module replaces)
 *
 * The audit (00-AUDIT.md §3.7, finding R7) found that the existing Kotlin
 * codebase's `pointsForBridging(bytesBridged)` had no proof object at all —
 * a relay could call it and mint Civic Points by simply claiming it bridged
 * traffic. This is precisely the anti-pattern the brief names: "Do not design
 * a system where users can generate points simply by claiming that they
 * provided service." It already existed.
 *
 * This module replaces that bare self-claim with four signed receipt types,
 * each of which is signed by a party that did NOT benefit from issuing it
 * (Invariant I13):
 *
 *   - DeliveryReceipt  — signed by the RECIPIENT (the beneficiary of delivery
 *                        attests that delivery happened).
 *   - TransitReceipt   — signed by the CLIENT (the circuit originator and
 *                        beneficiary of the relay's forwarding). The relay
 *                        (relayId) is credited but cannot forge the receipt.
 *                        THIS IS THE DIRECT REPLACEMENT FOR pointsForBridging.
 *   - GatewayReceipt   — counter-signed by BOTH the client AND the gateway.
 *                        The gateway bears the real egress cost, so it must
 *                        attest the egress volume (§A6: "Fake traffic through
 *                        a real gateway → gateway counter-signs; gateway bears
 *                        real bandwidth cost, so it will not sign fictitious
 *                        volume"). Both signatures are over the SAME preimage.
 *   - CustodyReceipt   — signed by the NEXT CUSTODIAN (or final recipient),
 *                        the party that RECEIVED the bundle from the credited
 *                        custodian. Makes the Mode A chain of custody
 *                        chain-verifiable (§A3).
 *
 * Every signature is over `SIG_CONTEXT ‖ CBOR(payload)` (I2), where SIG_CONTEXT
 * is one of:
 *   - SIG_CONTEXTS.deliveryReceipt  ("SNP/0.1 delivery-receipt\0")
 *   - SIG_CONTEXTS.transitReceipt   ("SNP/0.1 transit-receipt\0")
 *   - SIG_CONTEXTS.gatewayReceipt   ("SNP/0.1 gateway-receipt\0")
 *   - SIG_CONTEXTS.custodyReceipt   ("SNP/0.1 custody-receipt\0")
 *
 * Each receipt carries the signer's NodeId for identification, but verification
 * requires the signer's actual Ed25519 PUBLIC KEY (32 bytes), because NodeId
 * is a SHA-256 hash and cannot be used to verify (I4). Callers obtain the
 * public key out-of-band (e.g. from a NodeDescriptor).
 *
 * @ invariant I1  — All signed structures use SNP-CBOR with length-first key ordering
 * @ invariant I2  — Every signature is over SIG_CONTEXT ‖ CBOR(payload)
 * @ invariant I3  — Ed25519 uses raw 32-byte public keys on the wire
 * @ invariant I4  — NodeId = SHA-256("SNP/0.1 node\0" ‖ pk), never the bare key
 * @ invariant I13 — Civic Points are never minted by the claimant. Every proof
 *                   is signed by a party that did not benefit from issuing it.
 * @ invariant I19 — NEVER reference a Fake* class
 * @ invariant I20 — verify returns false on a bad signature; never throws.
 *                   validate throws CborError(MALFORMED) on structural problems.
 */

import { randomBytes } from "@noble/hashes/utils.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  QUALITY_CLASSES,
  type QualityClass,
} from "./constants";
import { type CborValue, CborError, cborMap } from "./cbor";
import { sign, verify } from "./crypto";

// ─── Frozen sizes & category enums ─────────────────────────────────────────

/** Number of bytes in a receipt nonce. 16 bytes — replay defence (§A6). */
export const RECEIPT_NONCE_BYTES = 16 as const;

/** Number of bytes in a circuit identifier. 8 bytes — per-epoch scope (§A4). */
export const CIRCUIT_ID_BYTES = 8 as const;

/** NodeId / ObjectId byte length (matches SHA-256 output, I4). */
const NODE_ID_BYTES = 32;

/** ObjectId (Mode A bundle) byte length — 32-byte Merkle root. */
const BUNDLE_ID_BYTES = 32;

/**
 * Allowed categories for DeliveryReceipt. Subset of MANIFEST_CLASSES —
 * "transit-response" is excluded because delivery receipts attest CONTENT
 * delivery, not transit responses (which are Mode A bundle deliveries and
 * use CustodyReceipt at the bundle layer).
 */
export const DELIVERY_CATEGORIES = ["content", "app", "model", "dataset"] as const;
export type DeliveryCategory = (typeof DELIVERY_CATEGORIES)[number];

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically-random nonce of `size` bytes (default 16).
 * Used by every receipt type as a per-receipt replay defence (§A6: "16-byte
 * nonce, durable unique index at settlement").
 *
 * @param size  number of random bytes to generate (default: RECEIPT_NONCE_BYTES)
 * @returns     `size` cryptographically-random bytes
 */
export function generateNonce(size: number = RECEIPT_NONCE_BYTES): Uint8Array {
  if (!Number.isInteger(size) || size <= 0) {
    throw new Error(`nonce size must be a positive integer; got ${size}`);
  }
  return randomBytes(size);
}

/**
 * Generate a random 8-byte circuit identifier. Convenience wrapper around
 * `generateNonce(CIRCUIT_ID_BYTES)`. Used when a new transit/gateway circuit
 * is opened for an epoch.
 */
export function generateCircuitId(): Uint8Array {
  return randomBytes(CIRCUIT_ID_BYTES);
}

// ─── Internal validation primitives ─────────────────────────────────────────
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

/** Assert that `v` is a non-negative safe integer (unix seconds or byte count). */
function assertUint(v: unknown, field: string): asserts v is number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new CborError(
      `${field} must be a non-negative integer; got ${v}`,
      "MALFORMED",
    );
  }
}

// ─── DeliveryReceipt (preserved concept, with domain separation added) ─────

/**
 * CDDL (05-CIVIC-CONTENT-CONSISTENCY.md §A4, 02-PROTOCOL-SPEC.md §A4):
 *
 *   DeliveryReceipt = {
 *     blobId:         bstr .size 32,   ; merkle root of the delivered object
 *     recipientId:    bstr .size 32,   ; NodeId of recipient (signer)
 *     bytesDelivered: uint,
 *     deliveredAt:    uint,            ; unix seconds
 *     category:       tstr,            ; "content" | "app" | "model" | "dataset"
 *     nonce:          bstr .size 16,
 *     signature:      bstr .size 64    ; by recipientId's key
 *   }
 *
 * The recipient is the BENEFICIARY of the delivery, so its signature attests
 * that the delivery actually happened. The seeder (whose NodeId is NOT in
 * this receipt) cannot forge it. (Invariant I13.)
 *
 * Per §A7: "DeliveryReceipt — Preserve wire shape; add SIG_CONTEXT". The
 * domain separation is added by signing under SIG_CONTEXTS.deliveryReceipt
 * (I2), which the pre-ShareNet-2.0 implementation did not do.
 */
export interface DeliveryReceipt {
  /** Merkle root (32 bytes) of the delivered object — Manifest.objectId. */
  readonly blobId: Uint8Array;
  /** NodeId (32 bytes) of the recipient — the signer. NOT a bare public key. */
  readonly recipientId: Uint8Array;
  /** Number of bytes delivered. */
  readonly bytesDelivered: number;
  /** Delivery time, unix seconds. */
  readonly deliveredAt: number;
  /** Object category — one of DELIVERY_CATEGORIES. */
  readonly category: DeliveryCategory;
  /** 16-byte random nonce for replay defence (§A6). */
  readonly nonce: Uint8Array;
  /** 64-byte Ed25519 signature by the recipient's key under SIG_CONTEXTS.deliveryReceipt. */
  readonly signature: Uint8Array;
}

/** DeliveryReceipt without the signature field — what gets signed. */
export type DeliveryReceiptUnsigned = Omit<DeliveryReceipt, "signature">;

/**
 * Build the canonical CBOR preimage map for a DeliveryReceipt, EXCLUDING the
 * `signature` field. This is the structure fed to `sign` / `verify` under
 * SIG_CONTEXT `"deliveryReceipt"`.
 *
 * The map uses STRING keys; canonical ordering (length-first on the fully-
 * encoded key) is applied at encode time by the CBOR encoder. Callers MUST
 * pass this map to `sign`/`verify` — never re-encode by hand.
 */
export function deliveryReceiptToCborMap(
  receipt: DeliveryReceipt | DeliveryReceiptUnsigned,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["blobId", receipt.blobId],
    ["recipientId", receipt.recipientId],
    ["bytesDelivered", receipt.bytesDelivered],
    ["deliveredAt", receipt.deliveredAt],
    ["category", receipt.category],
    ["nonce", receipt.nonce],
  ]);
}

/**
 * Validate the STRUCTURE of a DeliveryReceipt against the CDDL constraints.
 *
 * Throws `CborError` with code `"MALFORMED"` on any violation. Called by both
 * `signDeliveryReceipt` (fail-fast on bad input) and `verifyDeliveryReceipt`
 * (wrapped in try/catch so malformed input returns false rather than throwing
 * — I20).
 *
 * Checks:
 *   1. `blobId` is a 32-byte Uint8Array.
 *   2. `recipientId` is a 32-byte Uint8Array.
 *   3. `bytesDelivered` is a non-negative integer.
 *   4. `deliveredAt` is a non-negative integer.
 *   5. `category` is one of DELIVERY_CATEGORIES.
 *   6. `nonce` is a 16-byte Uint8Array.
 *   7. `signature` is a 64-byte Uint8Array.
 */
export function validateDeliveryReceipt(receipt: DeliveryReceipt): void {
  assertBytes(receipt.blobId, NODE_ID_BYTES, "DeliveryReceipt.blobId");
  assertBytes(receipt.recipientId, NODE_ID_BYTES, "DeliveryReceipt.recipientId");
  assertUint(receipt.bytesDelivered, "DeliveryReceipt.bytesDelivered");
  assertUint(receipt.deliveredAt, "DeliveryReceipt.deliveredAt");
  if (
    typeof receipt.category !== "string" ||
    !DELIVERY_CATEGORIES.includes(receipt.category as DeliveryCategory)
  ) {
    throw new CborError(
      `DeliveryReceipt.category must be one of [${DELIVERY_CATEGORIES.join(", ")}]; got "${receipt.category}"`,
      "MALFORMED",
    );
  }
  assertBytes(receipt.nonce, RECEIPT_NONCE_BYTES, "DeliveryReceipt.nonce");
  assertBytes(receipt.signature, ED25519_SIGNATURE_BYTES, "DeliveryReceipt.signature");
}

/**
 * Sign a DeliveryReceipt using the recipient's Ed25519 secret key.
 *
 * The signature is over `SIG_CONTEXTS.deliveryReceipt ‖ CBOR(receipt without signature)`,
 * per invariant I2. The recipient is the BENEFICIARY of the delivery, so its
 * signature is the proof that the delivery happened (I13). The seeder (not
 * named in this receipt) cannot forge it.
 *
 * @param unsigned             the DeliveryReceipt fields WITHOUT signature
 * @param recipientSecretKey   32-byte Ed25519 secret key of the recipient
 * @returns                    64-byte Ed25519 signature
 */
export function signDeliveryReceipt(
  unsigned: DeliveryReceiptUnsigned,
  recipientSecretKey: Uint8Array,
): Uint8Array {
  if (recipientSecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${recipientSecretKey.length}`,
    );
  }
  // Validate structure before signing so we never produce a signature over
  // malformed input. Use a zero-filled placeholder signature just to satisfy
  // the validator's length check; the real signature is produced below.
  validateDeliveryReceipt({
    ...unsigned,
    signature: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = deliveryReceiptToCborMap(unsigned);
  return sign(recipientSecretKey, "deliveryReceipt", preimage);
}

/**
 * Verify a DeliveryReceipt's signature against the recipient's public key.
 *
 * Returns `false` on any failure — bad signature, wrong key length, malformed
 * fields. NEVER throws for a bad signature (I20). This is the direct fix for
 * the audit's "FakeCryptoProvider.verify => signature.size == 64" pattern
 * (00-AUDIT.md §3.9).
 *
 * @param receipt              the DeliveryReceipt to verify
 * @param recipientPublicKey   32-byte Ed25519 public key of the recipient
 *                             (NOT a NodeId — NodeId is a hash, I4. Obtain
 *                             the public key out-of-band, e.g. from a
 *                             NodeDescriptor.)
 * @returns                    true iff the signature is valid for the receipt fields
 */
export function verifyDeliveryReceipt(
  receipt: DeliveryReceipt,
  recipientPublicKey: Uint8Array,
): boolean {
  if (recipientPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (receipt.signature.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateDeliveryReceipt(receipt);
  } catch {
    return false;
  }
  const preimage = deliveryReceiptToCborMap(receipt);
  return verify(recipientPublicKey, "deliveryReceipt", preimage, receipt.signature);
}

// ─── TransitReceipt (the new core object — replaces pointsForBridging) ─────

/**
 * CDDL (05-CIVIC-CONTENT-CONSISTENCY.md §A4):
 *
 *   TransitReceipt = {
 *     circuitId:     bstr .size 8,
 *     relayId:       bstr .size 32,   ; who is being credited
 *     clientId:      bstr .size 32,   ; economic identity of beneficiary (signer)
 *     bytesForward:  uint,
 *     bytesReturn:   uint,
 *     epochStart:    uint,
 *     epochEnd:      uint,
 *     qualityClass:  "interactive" / "bulk" / "tolerant",
 *     gatewayId:     bstr .size 32 / null,
 *     nonce:         bstr .size 16,
 *     clientSig:     bstr .size 64    ; SIGNED BY THE CLIENT — the beneficiary
 *   }
 *
 * The relay (relayId) is the party being CREDITED, but the signature is made
 * by the CLIENT (clientId) — the circuit originator and the beneficiary of
 * the relay's forwarding. The relay cannot forge its own receipt (I13).
 * This is the direct replacement for the unproven `pointsForBridging` call
 * (audit finding R7).
 *
 * Key properties (§A4):
 *   - The client signs; the relay cannot forge it. Symmetric with
 *     DeliveryReceipt, and for the same reason.
 *   - Issued per epoch (default 60 s), not per frame — bounded overhead.
 *   - A relay that stops forwarding stops receiving receipts. Payment tracks
 *     service continuously, with an epoch's granularity of loss.
 *   - `qualityClass` allows value-weighting: sustaining an interactive
 *     circuit is worth more per byte than carrying tolerant bulk.
 */
export interface TransitReceipt {
  /** 8-byte circuit identifier (per-epoch scope). */
  readonly circuitId: Uint8Array;
  /** NodeId (32 bytes) of the relay being CREDITED. NOT the signer. */
  readonly relayId: Uint8Array;
  /** NodeId (32 bytes) of the client — the economic beneficiary and SIGNER. */
  readonly clientId: Uint8Array;
  /** Bytes forwarded from client toward the gateway/origin during the epoch. */
  readonly bytesForward: number;
  /** Bytes returned from the gateway/origin back to the client during the epoch. */
  readonly bytesReturn: number;
  /** Epoch start time, unix seconds. */
  readonly epochStart: number;
  /** Epoch end time, unix seconds. MUST be > epochStart. */
  readonly epochEnd: number;
  /** Quality class — one of QUALITY_CLASSES. Drives value-weighting (§A5). */
  readonly qualityClass: QualityClass;
  /** NodeId (32 bytes) of the gateway if this circuit crossed a gateway, else null. */
  readonly gatewayId: Uint8Array | null;
  /** 16-byte random nonce for replay defence (§A6). */
  readonly nonce: Uint8Array;
  /** 64-byte Ed25519 signature by the client's key under SIG_CONTEXTS.transitReceipt. */
  readonly clientSig: Uint8Array;
}

/** TransitReceipt without the clientSig field — what gets signed. */
export type TransitReceiptUnsigned = Omit<TransitReceipt, "clientSig">;

/**
 * Build the canonical CBOR preimage map for a TransitReceipt, EXCLUDING the
 * `clientSig` field. This is the structure fed to `sign` / `verify` under
 * SIG_CONTEXT `"transitReceipt"`.
 */
export function transitReceiptToCborMap(
  receipt: TransitReceipt | TransitReceiptUnsigned,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["circuitId", receipt.circuitId],
    ["relayId", receipt.relayId],
    ["clientId", receipt.clientId],
    ["bytesForward", receipt.bytesForward],
    ["bytesReturn", receipt.bytesReturn],
    ["epochStart", receipt.epochStart],
    ["epochEnd", receipt.epochEnd],
    ["qualityClass", receipt.qualityClass],
    ["gatewayId", receipt.gatewayId as CborValue],
    ["nonce", receipt.nonce],
  ]);
}

/**
 * Validate the STRUCTURE of a TransitReceipt against the CDDL constraints.
 * Throws `CborError(MALFORMED)` on any violation.
 *
 * Checks:
 *   1. `circuitId` is an 8-byte Uint8Array.
 *   2. `relayId` is a 32-byte Uint8Array.
 *   3. `clientId` is a 32-byte Uint8Array.
 *   4. `bytesForward` / `bytesReturn` are non-negative integers.
 *   5. `epochStart` / `epochEnd` are non-negative integers with epochEnd > epochStart.
 *   6. `qualityClass` is one of QUALITY_CLASSES.
 *   7. `gatewayId` is null or a 32-byte Uint8Array.
 *   8. `nonce` is a 16-byte Uint8Array.
 *   9. `clientSig` is a 64-byte Uint8Array.
 */
export function validateTransitReceipt(receipt: TransitReceipt): void {
  assertBytes(receipt.circuitId, CIRCUIT_ID_BYTES, "TransitReceipt.circuitId");
  assertBytes(receipt.relayId, NODE_ID_BYTES, "TransitReceipt.relayId");
  assertBytes(receipt.clientId, NODE_ID_BYTES, "TransitReceipt.clientId");
  assertUint(receipt.bytesForward, "TransitReceipt.bytesForward");
  assertUint(receipt.bytesReturn, "TransitReceipt.bytesReturn");
  assertUint(receipt.epochStart, "TransitReceipt.epochStart");
  assertUint(receipt.epochEnd, "TransitReceipt.epochEnd");
  if (receipt.epochEnd <= receipt.epochStart) {
    throw new CborError(
      `TransitReceipt.epochEnd (${receipt.epochEnd}) must be strictly greater than epochStart (${receipt.epochStart})`,
      "MALFORMED",
    );
  }
  if (
    typeof receipt.qualityClass !== "string" ||
    !QUALITY_CLASSES.includes(receipt.qualityClass as QualityClass)
  ) {
    throw new CborError(
      `TransitReceipt.qualityClass must be one of [${QUALITY_CLASSES.join(", ")}]; got "${receipt.qualityClass}"`,
      "MALFORMED",
    );
  }
  assertBytesOrNull(receipt.gatewayId, NODE_ID_BYTES, "TransitReceipt.gatewayId");
  assertBytes(receipt.nonce, RECEIPT_NONCE_BYTES, "TransitReceipt.nonce");
  assertBytes(receipt.clientSig, ED25519_SIGNATURE_BYTES, "TransitReceipt.clientSig");
}

/**
 * Sign a TransitReceipt using the client's Ed25519 secret key, producing
 * the `clientSig`.
 *
 * The signature is over `SIG_CONTEXTS.transitReceipt ‖ CBOR(receipt without clientSig)`,
 * per invariant I2. The client is the BENEFICIARY of the relay's forwarding,
 * so its signature is the proof that the transit happened (I13). The relay
 * (relayId) is credited but cannot forge the receipt.
 *
 * @param unsigned         the TransitReceipt fields WITHOUT clientSig
 * @param clientSecretKey  32-byte Ed25519 secret key of the client
 * @returns                64-byte Ed25519 signature (the clientSig)
 */
export function signTransitReceipt(
  unsigned: TransitReceiptUnsigned,
  clientSecretKey: Uint8Array,
): Uint8Array {
  if (clientSecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${clientSecretKey.length}`,
    );
  }
  validateTransitReceipt({
    ...unsigned,
    clientSig: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = transitReceiptToCborMap(unsigned);
  return sign(clientSecretKey, "transitReceipt", preimage);
}

/**
 * Verify a TransitReceipt's `clientSig` against the client's public key.
 *
 * Returns `false` on any failure — bad signature, wrong key length, malformed
 * fields. NEVER throws for a bad signature (I20).
 *
 * @param receipt          the TransitReceipt to verify
 * @param clientPublicKey  32-byte Ed25519 public key of the client
 *                         (NOT a NodeId — NodeId is a hash, I4. Obtain the
 *                         public key out-of-band, e.g. from a NodeDescriptor
 *                         or EconomicIdentity record.)
 * @returns                true iff clientSig is valid
 */
export function verifyTransitReceipt(
  receipt: TransitReceipt,
  clientPublicKey: Uint8Array,
): boolean {
  if (clientPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (receipt.clientSig.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateTransitReceipt(receipt);
  } catch {
    return false;
  }
  const preimage = transitReceiptToCborMap(receipt);
  return verify(clientPublicKey, "transitReceipt", preimage, receipt.clientSig);
}

// ─── GatewayReceipt (counter-signed by BOTH client and gateway) ────────────

/**
 * CDDL (05-CIVIC-CONTENT-CONSISTENCY.md §A4, §A6):
 *
 *   GatewayReceipt = {
 *     circuitId:     bstr .size 8,
 *     gatewayId:     bstr .size 32,
 *     clientId:      bstr .size 32,
 *     bytesEgress:   uint,            ; bytes the gateway actually sent to origin
 *     bytesIngress:  uint,            ; bytes the gateway received from origin
 *     epochStart:    uint,
 *     epochEnd:      uint,
 *     gatewaySig:    bstr .size 64,   ; gateway attests the egress volume (bears real cost)
 *     clientSig:     bstr .size 64    ; client countersigns
 *   }
 *
 * The gateway (gatewayId) bears the real bandwidth cost of egress to the
 * origin Internet, so it must attest the egress volume to prevent
 * fictitious-volume farming (§A6: "Fake traffic through a real gateway →
 * gateway counter-signs; gateway bears real bandwidth cost, so it will not
 * sign fictitious volume"). The client countersigns to bind its economic
 * identity to the attested volume.
 *
 * Both signatures are over the SAME preimage — the receipt with BOTH
 * `gatewaySig` and `clientSig` removed. Each signature is verified
 * independently against the respective party's public key. Disagreement
 * between the two parties voids the receipt (§A6: "Both parties sign the
 * byte count; disagreement voids the receipt").
 *
 * Note: per the task spec, for simplicity both parties sign the SAME preimage
 * (we do not chain them — i.e. client does not sign over gatewaySig, and
 * gateway does not sign over clientSig). This means either party can produce
 * its signature independently and in any order, which simplifies the
 * protocol. The binding comes from the fact that both attest the SAME byte
 * counts in the SAME preimage.
 */
export interface GatewayReceipt {
  /** 8-byte circuit identifier (per-epoch scope). */
  readonly circuitId: Uint8Array;
  /** NodeId (32 bytes) of the gateway — co-signer, bears real egress cost. */
  readonly gatewayId: Uint8Array;
  /** NodeId (32 bytes) of the client — economic beneficiary and co-signer. */
  readonly clientId: Uint8Array;
  /** Bytes the gateway actually sent to the origin Internet (gateway bears this cost). */
  readonly bytesEgress: number;
  /** Bytes the gateway received from the origin Internet. */
  readonly bytesIngress: number;
  /** Epoch start time, unix seconds. */
  readonly epochStart: number;
  /** Epoch end time, unix seconds. MUST be > epochStart. */
  readonly epochEnd: number;
  /** 64-byte Ed25519 signature by the gateway's key under SIG_CONTEXTS.gatewayReceipt. */
  readonly gatewaySig: Uint8Array;
  /** 64-byte Ed25519 signature by the client's key under SIG_CONTEXTS.gatewayReceipt. */
  readonly clientSig: Uint8Array;
}

/** GatewayReceipt without either signature — what BOTH parties sign. */
export type GatewayReceiptUnsigned = Omit<
  GatewayReceipt,
  "gatewaySig" | "clientSig"
>;

/**
 * Build the canonical CBOR preimage map for a GatewayReceipt, EXCLUDING BOTH
 * signature fields. Both the client and the gateway sign this SAME preimage
 * under SIG_CONTEXT `"gatewayReceipt"`. Each signature is verified
 * independently against the respective party's public key.
 */
export function gatewayReceiptToCborMap(
  receipt: GatewayReceipt | GatewayReceiptUnsigned,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["circuitId", receipt.circuitId],
    ["gatewayId", receipt.gatewayId],
    ["clientId", receipt.clientId],
    ["bytesEgress", receipt.bytesEgress],
    ["bytesIngress", receipt.bytesIngress],
    ["epochStart", receipt.epochStart],
    ["epochEnd", receipt.epochEnd],
  ]);
}

/**
 * Validate the STRUCTURE of a GatewayReceipt against the CDDL constraints.
 * Throws `CborError(MALFORMED)` on any violation.
 *
 * Checks:
 *   1. `circuitId` is an 8-byte Uint8Array.
 *   2. `gatewayId` is a 32-byte Uint8Array.
 *   3. `clientId` is a 32-byte Uint8Array.
 *   4. `bytesEgress` / `bytesIngress` are non-negative integers.
 *   5. `epochStart` / `epochEnd` are non-negative integers with epochEnd > epochStart.
 *   6. `gatewaySig` is a 64-byte Uint8Array.
 *   7. `clientSig` is a 64-byte Uint8Array.
 */
export function validateGatewayReceipt(receipt: GatewayReceipt): void {
  assertBytes(receipt.circuitId, CIRCUIT_ID_BYTES, "GatewayReceipt.circuitId");
  assertBytes(receipt.gatewayId, NODE_ID_BYTES, "GatewayReceipt.gatewayId");
  assertBytes(receipt.clientId, NODE_ID_BYTES, "GatewayReceipt.clientId");
  assertUint(receipt.bytesEgress, "GatewayReceipt.bytesEgress");
  assertUint(receipt.bytesIngress, "GatewayReceipt.bytesIngress");
  assertUint(receipt.epochStart, "GatewayReceipt.epochStart");
  assertUint(receipt.epochEnd, "GatewayReceipt.epochEnd");
  if (receipt.epochEnd <= receipt.epochStart) {
    throw new CborError(
      `GatewayReceipt.epochEnd (${receipt.epochEnd}) must be strictly greater than epochStart (${receipt.epochStart})`,
      "MALFORMED",
    );
  }
  assertBytes(receipt.gatewaySig, ED25519_SIGNATURE_BYTES, "GatewayReceipt.gatewaySig");
  assertBytes(receipt.clientSig, ED25519_SIGNATURE_BYTES, "GatewayReceipt.clientSig");
}

/**
 * Sign a GatewayReceipt using the CLIENT's Ed25519 secret key, producing
 * the `clientSig`. The client is the economic beneficiary; its countersignature
 * binds its identity to the attested volume (I13, §A6).
 *
 * Both signatures (client and gateway) are over the SAME preimage (the receipt
 * with both `gatewaySig` and `clientSig` removed). Either party may sign
 * first; the order does not affect validity.
 *
 * @param unsigned         the GatewayReceipt fields WITHOUT either signature
 * @param clientSecretKey  32-byte Ed25519 secret key of the client
 * @returns                64-byte Ed25519 signature (the clientSig)
 */
export function signGatewayReceiptClient(
  unsigned: GatewayReceiptUnsigned,
  clientSecretKey: Uint8Array,
): Uint8Array {
  if (clientSecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${clientSecretKey.length}`,
    );
  }
  validateGatewayReceipt({
    ...unsigned,
    gatewaySig: new Uint8Array(ED25519_SIGNATURE_BYTES),
    clientSig: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = gatewayReceiptToCborMap(unsigned);
  return sign(clientSecretKey, "gatewayReceipt", preimage);
}

/**
 * Sign a GatewayReceipt using the GATEWAY's Ed25519 secret key, producing
 * the `gatewaySig`. The gateway bears the real egress cost, so its signature
 * attests the egress volume and prevents fictitious-volume farming (§A6).
 *
 * Both signatures (client and gateway) are over the SAME preimage (the receipt
 * with both `gatewaySig` and `clientSig` removed). Either party may sign
 * first; the order does not affect validity.
 *
 * @param unsigned           the GatewayReceipt fields WITHOUT either signature
 * @param gatewaySecretKey   32-byte Ed25519 secret key of the gateway
 * @returns                  64-byte Ed25519 signature (the gatewaySig)
 */
export function signGatewayReceiptGateway(
  unsigned: GatewayReceiptUnsigned,
  gatewaySecretKey: Uint8Array,
): Uint8Array {
  if (gatewaySecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${gatewaySecretKey.length}`,
    );
  }
  validateGatewayReceipt({
    ...unsigned,
    gatewaySig: new Uint8Array(ED25519_SIGNATURE_BYTES),
    clientSig: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = gatewayReceiptToCborMap(unsigned);
  return sign(gatewaySecretKey, "gatewayReceipt", preimage);
}

/**
 * Verify a GatewayReceipt's `clientSig` against the client's public key.
 * Returns `false` on any failure. NEVER throws (I20).
 *
 * Note: verifying ONLY the clientSig is useful for diagnostic / partial-
 * verification scenarios. The production check is `verifyGatewayReceipt`,
 * which requires BOTH signatures to be valid.
 *
 * @param receipt          the GatewayReceipt to verify
 * @param clientPublicKey  32-byte Ed25519 public key of the client
 * @returns                true iff clientSig is valid
 */
export function verifyGatewayReceiptClient(
  receipt: GatewayReceipt,
  clientPublicKey: Uint8Array,
): boolean {
  if (clientPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (receipt.clientSig.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateGatewayReceipt(receipt);
  } catch {
    return false;
  }
  const preimage = gatewayReceiptToCborMap(receipt);
  return verify(clientPublicKey, "gatewayReceipt", preimage, receipt.clientSig);
}

/**
 * Verify a GatewayReceipt's `gatewaySig` against the gateway's public key.
 * Returns `false` on any failure. NEVER throws (I20).
 *
 * Note: verifying ONLY the gatewaySig is useful for diagnostic / partial-
 * verification scenarios. The production check is `verifyGatewayReceipt`,
 * which requires BOTH signatures to be valid.
 *
 * @param receipt            the GatewayReceipt to verify
 * @param gatewayPublicKey   32-byte Ed25519 public key of the gateway
 * @returns                  true iff gatewaySig is valid
 */
export function verifyGatewayReceiptGateway(
  receipt: GatewayReceipt,
  gatewayPublicKey: Uint8Array,
): boolean {
  if (gatewayPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (receipt.gatewaySig.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateGatewayReceipt(receipt);
  } catch {
    return false;
  }
  const preimage = gatewayReceiptToCborMap(receipt);
  return verify(gatewayPublicKey, "gatewayReceipt", preimage, receipt.gatewaySig);
}

/**
 * Verify a GatewayReceipt's BOTH signatures — the client countersignature AND
 * the gateway signature. Returns `true` iff BOTH verify. This is the
 * production check: a receipt with only one valid signature is NOT a valid
 * GatewayReceipt (§A6: "Both parties sign the byte count; disagreement voids
 * the receipt").
 *
 * Returns `false` on any failure. NEVER throws (I20).
 *
 * @param receipt            the GatewayReceipt to verify
 * @param clientPublicKey    32-byte Ed25519 public key of the client
 * @param gatewayPublicKey   32-byte Ed25519 public key of the gateway
 * @returns                  true iff BOTH clientSig and gatewaySig are valid
 */
export function verifyGatewayReceipt(
  receipt: GatewayReceipt,
  clientPublicKey: Uint8Array,
  gatewayPublicKey: Uint8Array,
): boolean {
  // Each sub-verifier performs its own structural validation (wrapped in
  // try/catch, returning false on MALFORMED) AND its own signature check.
  // Both must pass for the receipt to be considered valid. The `&&`
  // short-circuits, but that's safe: if the clientSig fails (for any reason
  // — bad sig OR structural issue), the receipt is invalid regardless of the
  // gatewaySig, and vice versa.
  return (
    verifyGatewayReceiptClient(receipt, clientPublicKey) &&
    verifyGatewayReceiptGateway(receipt, gatewayPublicKey)
  );
}

// ─── CustodyReceipt (Mode A store-and-forward — chain of custody) ──────────

/**
 * CDDL (05-CIVIC-CONTENT-CONSISTENCY.md §A3, §A4):
 *
 *   CustodyReceipt = {
 *     bundleId:        bstr .size 32,   ; ObjectId of the Mode A bundle being carried
 *     custodianId:     bstr .size 32,   ; current custodian being credited
 *     nextCustodianId: bstr .size 32,   ; next custodian or final recipient (signer)
 *     receivedAt:      uint,
 *     forwardedAt:     uint,
 *     nonce:           bstr .size 16,
 *     nextSig:         bstr .size 64    ; by nextCustodianId's key
 *   }
 *
 * The current custodian (custodianId) is being CREDITED for carrying the
 * bundle, but the signature is made by the NEXT custodian (or final recipient)
 * — the party that RECEIVED the bundle from the credited custodian. This
 * makes the chain of custody chain-verifiable (I13, §A3): each hop is
 * attested by the next hop, never by the party being credited. A custodian
 * cannot forge a receipt for its own custody service.
 */
export interface CustodyReceipt {
  /** ObjectId (32-byte Merkle root) of the Mode A bundle being carried. */
  readonly bundleId: Uint8Array;
  /** NodeId (32 bytes) of the current custodian being CREDITED. NOT the signer. */
  readonly custodianId: Uint8Array;
  /** NodeId (32 bytes) of the next custodian or final recipient — the SIGNER. */
  readonly nextCustodianId: Uint8Array;
  /** Time the bundle was received by the current custodian, unix seconds. */
  readonly receivedAt: number;
  /** Time the bundle was forwarded to the next custodian, unix seconds. */
  readonly forwardedAt: number;
  /** 16-byte random nonce for replay defence (§A6). */
  readonly nonce: Uint8Array;
  /** 64-byte Ed25519 signature by the next custodian's key under SIG_CONTEXTS.custodyReceipt. */
  readonly nextSig: Uint8Array;
}

/** CustodyReceipt without the nextSig field — what gets signed. */
export type CustodyReceiptUnsigned = Omit<CustodyReceipt, "nextSig">;

/**
 * Build the canonical CBOR preimage map for a CustodyReceipt, EXCLUDING the
 * `nextSig` field. This is the structure fed to `sign` / `verify` under
 * SIG_CONTEXT `"custodyReceipt"`.
 */
export function custodyReceiptToCborMap(
  receipt: CustodyReceipt | CustodyReceiptUnsigned,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["bundleId", receipt.bundleId],
    ["custodianId", receipt.custodianId],
    ["nextCustodianId", receipt.nextCustodianId],
    ["receivedAt", receipt.receivedAt],
    ["forwardedAt", receipt.forwardedAt],
    ["nonce", receipt.nonce],
  ]);
}

/**
 * Validate the STRUCTURE of a CustodyReceipt against the CDDL constraints.
 * Throws `CborError(MALFORMED)` on any violation.
 *
 * Checks:
 *   1. `bundleId` is a 32-byte Uint8Array.
 *   2. `custodianId` is a 32-byte Uint8Array.
 *   3. `nextCustodianId` is a 32-byte Uint8Array.
 *   4. `receivedAt` / `forwardedAt` are non-negative integers with forwardedAt >= receivedAt.
 *   5. `nonce` is a 16-byte Uint8Array.
 *   6. `nextSig` is a 64-byte Uint8Array.
 */
export function validateCustodyReceipt(receipt: CustodyReceipt): void {
  assertBytes(receipt.bundleId, BUNDLE_ID_BYTES, "CustodyReceipt.bundleId");
  assertBytes(receipt.custodianId, NODE_ID_BYTES, "CustodyReceipt.custodianId");
  assertBytes(
    receipt.nextCustodianId,
    NODE_ID_BYTES,
    "CustodyReceipt.nextCustodianId",
  );
  assertUint(receipt.receivedAt, "CustodyReceipt.receivedAt");
  assertUint(receipt.forwardedAt, "CustodyReceipt.forwardedAt");
  if (receipt.forwardedAt < receipt.receivedAt) {
    throw new CborError(
      `CustodyReceipt.forwardedAt (${receipt.forwardedAt}) must be >= receivedAt (${receipt.receivedAt})`,
      "MALFORMED",
    );
  }
  assertBytes(receipt.nonce, RECEIPT_NONCE_BYTES, "CustodyReceipt.nonce");
  assertBytes(receipt.nextSig, ED25519_SIGNATURE_BYTES, "CustodyReceipt.nextSig");
}

/**
 * Sign a CustodyReceipt using the next custodian's (or final recipient's)
 * Ed25519 secret key, producing the `nextSig`.
 *
 * The current custodian (custodianId) is being CREDITED, but the signature is
 * made by the party that RECEIVED the bundle — making the chain of custody
 * chain-verifiable (I13). The credited custodian cannot forge its own receipt.
 *
 * @param unsigned                 the CustodyReceipt fields WITHOUT nextSig
 * @param nextCustodianSecretKey   32-byte Ed25519 secret key of the next
 *                                 custodian (or final recipient)
 * @returns                        64-byte Ed25519 signature (the nextSig)
 */
export function signCustodyReceipt(
  unsigned: CustodyReceiptUnsigned,
  nextCustodianSecretKey: Uint8Array,
): Uint8Array {
  if (nextCustodianSecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${nextCustodianSecretKey.length}`,
    );
  }
  validateCustodyReceipt({
    ...unsigned,
    nextSig: new Uint8Array(ED25519_SIGNATURE_BYTES),
  });
  const preimage = custodyReceiptToCborMap(unsigned);
  return sign(nextCustodianSecretKey, "custodyReceipt", preimage);
}

/**
 * Verify a CustodyReceipt's `nextSig` against the next custodian's (or final
 * recipient's) public key.
 *
 * Returns `false` on any failure — bad signature, wrong key length, malformed
 * fields. NEVER throws for a bad signature (I20).
 *
 * Chain verification: to verify an entire custody chain for a bundle, the
 * verifier assembles the ordered list of CustodyReceipts for that bundle
 * (matching `bundleId`), checks that each receipt's `nextCustodianId` equals
 * the next receipt's `custodianId`, and calls `verifyCustodyReceipt` on each
 * with the corresponding next custodian's public key. The final receipt's
 * `nextCustodianId` is the final recipient, whose key is verified against the
 * recipient's published public key.
 *
 * @param receipt                   the CustodyReceipt to verify
 * @param nextCustodianPublicKey    32-byte Ed25519 public key of the next
 *                                  custodian (or final recipient).
 *                                  NOT a NodeId — NodeId is a hash (I4).
 * @returns                         true iff nextSig is valid
 */
export function verifyCustodyReceipt(
  receipt: CustodyReceipt,
  nextCustodianPublicKey: Uint8Array,
): boolean {
  if (nextCustodianPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (receipt.nextSig.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    validateCustodyReceipt(receipt);
  } catch {
    return false;
  }
  const preimage = custodyReceiptToCborMap(receipt);
  return verify(nextCustodianPublicKey, "custodyReceipt", preimage, receipt.nextSig);
}
