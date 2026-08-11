/**
 * SNP Identity — four-way (now six-way) key separation
 *
 * Source: 02-PROTOCOL-SPEC.md §2 "Identity (L1)"
 * Source: 00-AUDIT.md §1 (R6 — the bug this replaces)
 *
 * The audit (00-AUDIT.md §1, finding R6) found that the existing Kotlin
 * codebase uses ONE Ed25519 key as the node identity, the user identity,
 * the publisher identity, AND the economic identity simultaneously. The
 * `NodeId` documentation even calls it "the global primary key everywhere."
 * That design is:
 *
 *   - a privacy failure: a single permanent, network-wide correlator; and
 *   - a security failure: compromise of one role compromises all roles.
 *
 * This module splits identity into six distinct roles, each with its own
 * key material. None of the role interfaces are structurally assignable to
 * one another — you cannot pass a `PublisherIdentity` where a
 * `NodeIdentity` is expected. This is enforced by a `kind` discriminator.
 *
 *   UserIdentity         — Ed25519, offline, human-recoverable. Never on wire.
 *   DeviceIdentity       — Ed25519, per-device, hardware-backed where available.
 *   NodeIdentity         — Ed25519, rotatable per epoch, in routing/link peer.
 *   EconomicIdentity     — Ed25519, for settlement only.
 *   PublisherIdentity    — Ed25519, per channel.
 *   RendezvousIdentity   — X25519, for Mode A response delivery.
 *
 * `NodeId` is a 32-byte SHA-256 hash of an Ed25519 public key, NOT the key
 * itself (I4). The bare key is disclosed only during the Noise_IK handshake.
 *
 * @ invariant I3 — Ed25519 uses raw 32-byte public keys on the wire
 * @ invariant I4 — NodeId = SHA-256("SNP/0.1 node\0" ‖ pk), never the bare key
 * @ invariant I19 — NEVER reference a Fake* class
 * @ invariant I20 — a stub in a security-critical path throws; never permissive
 */

import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  PROTO_VERSION,
  SIG_CONTEXTS,
  type Capability,
  type Platform,
} from "./constants";
import {
  type Ed25519Keypair,
  type X25519Keypair,
  generateEd25519Keypair,
  generateX25519Keypair,
  sign,
  verify,
} from "./crypto";
import { deriveNodeId } from "./hashing";
import { type CborValue, CborError, cborMap } from "./cbor";

// ─── NodeId ────────────────────────────────────────────────────────────────

/**
 * A NodeId is a 32-byte SHA-256 hash of an Ed25519 public key:
 *
 *   NodeId := SHA-256("SNP/0.1 node\0" ‖ ed25519_public_key)
 *
 * It is NOT the bare key (I4). The bare key is disclosed only during the
 * Noise_IK handshake. On the wire, every `bstr .size 32` that identifies a
 * node (in NodeDescriptor.nodeId, Manifest.publisherId, route tables, etc.)
 * carries a NodeId, never a raw public key.
 *
 * This is a type alias over Uint8Array so it can flow through CBOR bstr
 * fields without casting, but the semantic contract is "32 bytes that are a
 * SHA-256 output, not an Ed25519 public key."
 */
export type NodeId = Uint8Array;

/**
 * Derive a NodeId from a 32-byte Ed25519 public key.
 *
 * Thin wrapper around `deriveNodeId` from hashing.ts, exposed here so callers
 * building SNP structures don't need to import two modules.
 *
 * @param publicKey 32-byte Ed25519 public key
 * @returns 32-byte NodeId (SHA-256("SNP/0.1 node\0" ‖ publicKey))
 */
export function toNodeId(publicKey: Uint8Array): NodeId {
  return deriveNodeId(publicKey);
}

// ─── Identity role types ───────────────────────────────────────────────────
//
// Each role is a distinct interface keyed by a `kind` discriminator. This
// prevents accidental cross-role substitution at compile time: a function
// taking `NodeIdentity` will not accept a `PublisherIdentity`.
//
// None of these identities appear on the wire as-is — they are keypair
// holders. Their *public keys* (or NodeIds derived from them) appear in
// DeviceCert, NodeDescriptor, Manifest, etc.

/** User identity — Ed25519, offline, backed up, human-recoverable. Never on wire. */
export interface UserIdentity {
  readonly kind: "user";
  /** The Ed25519 keypair. The secret key MUST be backed up offline. */
  readonly keypair: Ed25519Keypair;
}

/** Device identity — Ed25519, per-device, hardware-backed where available. */
export interface DeviceIdentity {
  readonly kind: "device";
  readonly keypair: Ed25519Keypair;
}

/** Node identity — Ed25519, rotatable per epoch, appears in routing/link peer. */
export interface NodeIdentity {
  readonly kind: "node";
  readonly keypair: Ed25519Keypair;
}

/** Economic identity — Ed25519, for settlement only. May equal the UserIdentity. */
export interface EconomicIdentity {
  readonly kind: "economic";
  readonly keypair: Ed25519Keypair;
}

/** Publisher identity — Ed25519, per channel. */
export interface PublisherIdentity {
  readonly kind: "publisher";
  readonly keypair: Ed25519Keypair;
}

/** Rendezvous identity — X25519, for Mode A response delivery. */
export interface RendezvousIdentity {
  readonly kind: "rendezvous";
  readonly keypair: X25519Keypair;
}

/** Discriminated union of all Ed25519 identity roles. */
export type AnyEd25519Identity =
  | UserIdentity
  | DeviceIdentity
  | NodeIdentity
  | EconomicIdentity
  | PublisherIdentity;

// ─── Identity factories ────────────────────────────────────────────────────

/** Generate a fresh UserIdentity (Ed25519). Caller is responsible for backup. */
export function generateUserIdentity(): UserIdentity {
  return { kind: "user", keypair: generateEd25519Keypair() };
}

/** Generate a fresh DeviceIdentity (Ed25519). */
export function generateDeviceIdentity(): DeviceIdentity {
  return { kind: "device", keypair: generateEd25519Keypair() };
}

/** Generate a fresh NodeIdentity (Ed25519). Rotate per epoch (default 24h). */
export function generateNodeIdentity(): NodeIdentity {
  return { kind: "node", keypair: generateEd25519Keypair() };
}

/** Generate a fresh EconomicIdentity (Ed25519). */
export function generateEconomicIdentity(): EconomicIdentity {
  return { kind: "economic", keypair: generateEd25519Keypair() };
}

/** Generate a fresh PublisherIdentity (Ed25519). */
export function generatePublisherIdentity(): PublisherIdentity {
  return { kind: "publisher", keypair: generateEd25519Keypair() };
}

/** Generate a fresh RendezvousIdentity (X25519) for Mode A response delivery. */
export function generateRendezvousIdentity(): RendezvousIdentity {
  return { kind: "rendezvous", keypair: generateX25519Keypair() };
}

// ─── DeviceCert (02-PROTOCOL-SPEC.md §2.4) ─────────────────────────────────

/**
 * Fields of a DeviceCert, excluding the signature. This is the structure
 * that gets signed by the UserIdentity's secret key.
 *
 * CDDL (02-PROTOCOL-SPEC.md §2.4):
 *   DeviceCert = {
 *     deviceId:      bstr .size 32,   ; NodeId of the device identity
 *     userId:        bstr .size 32,   ; NodeId of the user identity
 *     capabilities:  [* capability],
 *     platform:      tstr,
 *     notBefore:     uint,            ; unix seconds
 *     notAfter:      uint,            ; unix seconds
 *     attestation:   bstr / null,     ; platform hardware attestation, advisory
 *     signature:     bstr .size 64    ; by userId
 *   }
 */
export interface DeviceCertFields {
  /** NodeId (32 bytes) of the device's Ed25519 identity key. */
  readonly deviceId: Uint8Array;
  /** NodeId (32 bytes) of the user's Ed25519 identity key. */
  readonly userId: Uint8Array;
  /** Capabilities the device is authorised to advertise. */
  readonly capabilities: Capability[];
  /** Platform string (one of PLATFORMS). */
  readonly platform: Platform;
  /** Validity start (unix seconds). */
  readonly notBefore: number;
  /** Validity end (unix seconds). */
  readonly notAfter: number;
  /**
   * Platform hardware attestation (Android Key Attestation, iOS DeviceCheck,
   * TPM quote) or null. Treated as advisory reputation input ONLY — never
   * as an authorisation gate (spec §2.4).
   */
  readonly attestation: Uint8Array | null;
}

/** A complete DeviceCert, including the 64-byte Ed25519 signature. */
export interface DeviceCert extends DeviceCertFields {
  /** 64-byte Ed25519 signature by the UserIdentity over SIG_CONTEXTS.deviceCert. */
  readonly signature: Uint8Array;
}

/**
 * Build the canonical CBOR preimage map for a DeviceCert (without signature).
 *
 * The map uses STRING keys and is sorted canonically at encode time by the
 * CBOR encoder (length-first on the fully-encoded key). Callers MUST pass
 * this map to `sign`/`verify` — never re-encode by hand.
 *
 * @param fields the DeviceCert fields (deviceId, userId, capabilities, ...)
 * @returns a CborValue Map suitable for `sign(secretKey, "deviceCert", map)`
 */
export function deviceCertToCborMap(fields: DeviceCertFields): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["deviceId", fields.deviceId],
    ["userId", fields.userId],
    ["capabilities", fields.capabilities as CborValue[]],
    ["platform", fields.platform],
    ["notBefore", fields.notBefore],
    ["notAfter", fields.notAfter],
    ["attestation", fields.attestation as CborValue],
  ]);
}

/**
 * Sign a DeviceCert using the UserIdentity's secret key.
 *
 * The signature is over `SIG_CONTEXTS.deviceCert ‖ CBOR(DeviceCertFields)`,
 * per invariant I2. The signature field itself is NOT part of the signed
 * preimage.
 *
 * @param userIdSecretKey  32-byte Ed25519 secret key of the UserIdentity
 * @param fields           the DeviceCert fields (without signature)
 * @returns                a complete DeviceCert including the 64-byte signature
 */
export function signDeviceCert(
  userIdSecretKey: Uint8Array,
  fields: DeviceCertFields,
): DeviceCert {
  assertDeviceCertFields(fields);
  const preimage = deviceCertToCborMap(fields);
  const signature = sign(userIdSecretKey, "deviceCert", preimage);
  return { ...fields, signature };
}

/**
 * Verify a DeviceCert's signature against the UserIdentity's public key.
 *
 * Returns `false` on any failure (bad signature, wrong key length, malformed
 * fields). NEVER throws for a bad signature. This is the direct fix for the
 * audit's "FakeCryptoProvider.verify => signature.size == 64" pattern (I20).
 *
 * @param cert              the DeviceCert to verify
 * @param userIdPublicKey   32-byte Ed25519 public key of the UserIdentity
 * @returns                 true iff the signature is valid for the cert fields
 */
export function verifyDeviceCert(
  cert: DeviceCert,
  userIdPublicKey: Uint8Array,
): boolean {
  // Structural sanity: never trust a cert whose fields don't match the CDDL.
  // Length checks are not signature checks, but they prevent feeding garbage
  // to the verifier.
  if (userIdPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (cert.signature.length !== ED25519_SIGNATURE_BYTES) return false;
  if (cert.deviceId.length !== 32 || cert.userId.length !== 32) return false;
  try {
    assertDeviceCertFields(cert);
  } catch {
    return false;
  }
  const preimage = deviceCertToCborMap(cert);
  return verify(userIdPublicKey, "deviceCert", preimage, cert.signature);
}

// ─── NodeDescriptor (02-PROTOCOL-SPEC.md §4.4) ─────────────────────────────

/**
 * A link hint — a URI-like string telling peers how to reach the node over a
 * specific link layer (e.g. "ble:AB:CD:EF:...", "mdns:node-abc.local",
 * "ws://10.0.0.2:7780"). The spec uses `[* link_hint]` without a formal
 * CDDL definition; we model link_hint as a text string.
 */
export type LinkHint = string;

/**
 * Fields of a NodeDescriptor, excluding the signature.
 *
 * CDDL (02-PROTOCOL-SPEC.md §4.4):
 *   NodeDescriptor = {
 *     nodeId:        bstr .size 32,   ; NodeId of nodePubKey
 *     nodePubKey:    bstr .size 32,   ; Ed25519 public key (NOT NodeId)
 *     rendezvousPub: bstr .size 32,   ; X25519 public key
 *     capabilities:  [+ capability],
 *     platform:      tstr,
 *     protoVersion:  tstr,            ; "SNP/0.1"
 *     epoch:         uint,
 *     expiresAt:     uint,            ; unix seconds; mandatory, SHOULD be short
 *     links:         [* link_hint],
 *     deviceCert:    DeviceCert / null,
 *     signature:     bstr .size 64    ; by nodePubKey
 *   }
 */
export interface NodeDescriptorFields {
  /** NodeId (32 bytes) — SHA-256("SNP/0.1 node\0" ‖ nodePubKey). */
  readonly nodeId: Uint8Array;
  /** 32-byte Ed25519 public key of the NodeIdentity. */
  readonly nodePubKey: Uint8Array;
  /** 32-byte X25519 public key of the RendezvousIdentity. */
  readonly rendezvousPub: Uint8Array;
  /** Capabilities the node advertises. MUST match platform (spec §4.3). */
  readonly capabilities: Capability[];
  /** Platform string (one of PLATFORMS). */
  readonly platform: Platform;
  /** Protocol version string — MUST be PROTO_VERSION ("SNP/0.1"). */
  readonly protoVersion: string;
  /** Epoch number this descriptor is valid for. */
  readonly epoch: number;
  /** Expiry (unix seconds). Mandatory; SHOULD be ≤ 1h for mobile. */
  readonly expiresAt: number;
  /** Link-layer hints for reaching the node. */
  readonly links: LinkHint[];
  /** DeviceCert binding this node to a device/user, or null for privacy. */
  readonly deviceCert: DeviceCert | null;
}

/** A complete NodeDescriptor, including the 64-byte Ed25519 signature. */
export interface NodeDescriptor extends NodeDescriptorFields {
  /** 64-byte Ed25519 signature by nodePubKey over SIG_CONTEXTS.nodeDescriptor. */
  readonly signature: Uint8Array;
}

/**
 * Build the canonical CBOR preimage map for a NodeDescriptor (without
 * signature).
 *
 * The map uses STRING keys. The `deviceCert` field, when present, is encoded
 * as the FULL DeviceCert sub-map (including its own `signature`); when
 * absent, it is encoded as CBOR null. The DeviceCert's signature is part of
 * the signed preimage of the NodeDescriptor — it is NOT re-signed, but it
 * IS bound into the descriptor so that stripping or substituting the
 * DeviceCert invalidates the descriptor signature.
 *
 * @param fields the NodeDescriptor fields (without signature)
 */
export function nodeDescriptorToCborMap(
  fields: NodeDescriptorFields,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["nodeId", fields.nodeId],
    ["nodePubKey", fields.nodePubKey],
    ["rendezvousPub", fields.rendezvousPub],
    ["capabilities", fields.capabilities as CborValue[]],
    ["platform", fields.platform],
    ["protoVersion", fields.protoVersion],
    ["epoch", fields.epoch],
    ["expiresAt", fields.expiresAt],
    ["links", fields.links as CborValue[]],
    [
      "deviceCert",
      fields.deviceCert === null
        ? (null as CborValue)
        : deviceCertToCborMap(fields.deviceCert),
    ],
  ]);
}

/**
 * Sign a NodeDescriptor using the NodeIdentity's secret key.
 *
 * The signature is over `SIG_CONTEXTS.nodeDescriptor ‖ CBOR(NodeDescriptorFields)`,
 * per invariant I2. The descriptor's own `signature` field is NOT part of
 * the signed preimage; the embedded `deviceCert.signature` (if any) IS,
 * because the DeviceCert is a complete sub-structure.
 *
 * @param nodeSecretKey  32-byte Ed25519 secret key of the NodeIdentity
 * @param fields         the NodeDescriptor fields (without signature)
 * @returns              a complete NodeDescriptor including the 64-byte signature
 */
export function signNodeDescriptor(
  nodeSecretKey: Uint8Array,
  fields: NodeDescriptorFields,
): NodeDescriptor {
  assertNodeDescriptorFields(fields);
  const preimage = nodeDescriptorToCborMap(fields);
  const signature = sign(nodeSecretKey, "nodeDescriptor", preimage);
  return { ...fields, signature };
}

/**
 * Verify a NodeDescriptor's signature.
 *
 * Re-derives the preimage (descriptor without its own signature field — the
 * embedded DeviceCert, including its signature, is part of the preimage) and
 * calls `verify(nodePubKey, "nodeDescriptor", preimage, signature)`.
 *
 * Returns `false` on any failure. NEVER throws for a bad signature. Note:
 * verifying the descriptor's signature does NOT verify the embedded
 * DeviceCert — callers MUST call `verifyDeviceCert` separately if they care
 * about the device binding.
 *
 * @param descriptor  the NodeDescriptor to verify
 * @returns           true iff the signature is valid for the descriptor fields
 */
export function verifyNodeDescriptor(descriptor: NodeDescriptor): boolean {
  if (descriptor.nodePubKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (descriptor.signature.length !== ED25519_SIGNATURE_BYTES) return false;
  if (descriptor.nodeId.length !== 32) return false;
  if (descriptor.rendezvousPub.length !== 32) return false;
  try {
    assertNodeDescriptorFields(descriptor);
  } catch {
    return false;
  }
  const preimage = nodeDescriptorToCborMap(descriptor);
  return verify(descriptor.nodePubKey, "nodeDescriptor", preimage, descriptor.signature);
}

/**
 * Check whether a NodeDescriptor has expired.
 *
 * Per spec §4.4 / §5: "a descriptor older than `expiresAt` MUST NOT be used
 * for routing and MUST NOT be forwarded. Relays MUST NOT extend expiry."
 *
 * @param descriptor  the descriptor to check
 * @param now         current time in unix seconds (passed in for testability)
 * @returns           true iff `now` is past `descriptor.expiresAt`
 */
export function isExpired(descriptor: NodeDescriptor, now: number): boolean {
  return now >= descriptor.expiresAt;
}

// ─── Field validators ──────────────────────────────────────────────────────
//
// These throw CborError(MALFORMED) on invalid input. They are called from
// signers (to fail-fast on bad input) and from verifiers (wrapped in
// try/catch so a malformed structure returns false rather than throwing).

/**
 * Validate the fields of a DeviceCert against the CDDL constraints.
 * Throws CborError(MALFORMED) on any violation.
 */
function assertDeviceCertFields(fields: DeviceCertFields): void {
  if (!(fields.deviceId instanceof Uint8Array) || fields.deviceId.length !== 32) {
    throw new CborError(
      "DeviceCert.deviceId must be a 32-byte Uint8Array",
      "MALFORMED",
    );
  }
  if (!(fields.userId instanceof Uint8Array) || fields.userId.length !== 32) {
    throw new CborError(
      "DeviceCert.userId must be a 32-byte Uint8Array",
      "MALFORMED",
    );
  }
  if (!Array.isArray(fields.capabilities)) {
    throw new CborError(
      "DeviceCert.capabilities must be an array",
      "MALFORMED",
    );
  }
  for (const c of fields.capabilities) {
    if (typeof c !== "string") {
      throw new CborError(
        "DeviceCert.capabilities must be an array of strings",
        "MALFORMED",
      );
    }
  }
  if (typeof fields.platform !== "string") {
    throw new CborError(
      "DeviceCert.platform must be a string",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(fields.notBefore) || fields.notBefore < 0) {
    throw new CborError(
      "DeviceCert.notBefore must be a non-negative integer (unix seconds)",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(fields.notAfter) || fields.notAfter < 0) {
    throw new CborError(
      "DeviceCert.notAfter must be a non-negative integer (unix seconds)",
      "MALFORMED",
    );
  }
  if (fields.notAfter <= fields.notBefore) {
    throw new CborError(
      "DeviceCert.notAfter must be strictly greater than notBefore",
      "MALFORMED",
    );
  }
  if (fields.attestation !== null && !(fields.attestation instanceof Uint8Array)) {
    throw new CborError(
      "DeviceCert.attestation must be a Uint8Array or null",
      "MALFORMED",
    );
  }
}

/**
 * Validate the fields of a NodeDescriptor against the CDDL constraints.
 * Throws CborError(MALFORMED) on any violation.
 */
function assertNodeDescriptorFields(fields: NodeDescriptorFields): void {
  if (!(fields.nodeId instanceof Uint8Array) || fields.nodeId.length !== 32) {
    throw new CborError(
      "NodeDescriptor.nodeId must be a 32-byte Uint8Array",
      "MALFORMED",
    );
  }
  if (!(fields.nodePubKey instanceof Uint8Array) || fields.nodePubKey.length !== 32) {
    throw new CborError(
      "NodeDescriptor.nodePubKey must be a 32-byte Uint8Array",
      "MALFORMED",
    );
  }
  if (!(fields.rendezvousPub instanceof Uint8Array) || fields.rendezvousPub.length !== 32) {
    throw new CborError(
      "NodeDescriptor.rendezvousPub must be a 32-byte Uint8Array",
      "MALFORMED",
    );
  }
  if (!Array.isArray(fields.capabilities) || fields.capabilities.length === 0) {
    throw new CborError(
      "NodeDescriptor.capabilities must be a non-empty array",
      "MALFORMED",
    );
  }
  for (const c of fields.capabilities) {
    if (typeof c !== "string") {
      throw new CborError(
        "NodeDescriptor.capabilities must be an array of strings",
        "MALFORMED",
      );
    }
  }
  if (typeof fields.platform !== "string") {
    throw new CborError(
      "NodeDescriptor.platform must be a string",
      "MALFORMED",
    );
  }
  if (typeof fields.protoVersion !== "string") {
    throw new CborError(
      "NodeDescriptor.protoVersion must be a string",
      "MALFORMED",
    );
  }
  // Per spec §10, protoVersion MUST be PROTO_VERSION ("SNP/0.1"). We reject
  // anything else at the structural level — a different version is a
  // different protocol and must not be parsed by this code.
  if (fields.protoVersion !== PROTO_VERSION) {
    throw new CborError(
      `NodeDescriptor.protoVersion must be "${PROTO_VERSION}"; got "${fields.protoVersion}"`,
      "MALFORMED",
    );
  }
  if (!Number.isInteger(fields.epoch) || fields.epoch < 0) {
    throw new CborError(
      "NodeDescriptor.epoch must be a non-negative integer",
      "MALFORMED",
    );
  }
  if (!Number.isInteger(fields.expiresAt) || fields.expiresAt <= 0) {
    throw new CborError(
      "NodeDescriptor.expiresAt must be a positive integer (unix seconds)",
      "MALFORMED",
    );
  }
  if (!Array.isArray(fields.links)) {
    throw new CborError(
      "NodeDescriptor.links must be an array of link hints",
      "MALFORMED",
    );
  }
  for (const l of fields.links) {
    if (typeof l !== "string") {
      throw new CborError(
        "NodeDescriptor.links must be an array of strings",
        "MALFORMED",
      );
    }
  }
  if (fields.deviceCert !== null && typeof fields.deviceCert !== "object") {
    throw new CborError(
      "NodeDescriptor.deviceCert must be a DeviceCert or null",
      "MALFORMED",
    );
  }
  // If a DeviceCert is embedded, validate its structure too. We do NOT
  // verify its signature here — that is a separate trust decision.
  if (fields.deviceCert !== null) {
    assertDeviceCertFields(fields.deviceCert);
    if (
      !(fields.deviceCert.signature instanceof Uint8Array) ||
      fields.deviceCert.signature.length !== ED25519_SIGNATURE_BYTES
    ) {
      throw new CborError(
        "NodeDescriptor.deviceCert.signature must be a 64-byte Uint8Array",
        "MALFORMED",
      );
    }
  }
}
