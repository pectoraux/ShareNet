/**
 * SNP L5 Mesh Sync — anti-entropy, store-carry-forward, bundle custody
 *
 * Source: 01-ARCHITECTURE.md §2.1 (L5 contract: "Anti-entropy, store-carry-
 *         forward, bundle custody. Must NOT interpret transit payloads.")
 * Source: 02-PROTOCOL-SPEC.md §5 (tier 2 anti-entropy)
 * Source: 00-AUDIT.md §3.7 (the bug this module replaces: `SyncWorker.kt`
 *         sent the literal ASCII string `"HAVE:"` to every peer and
 *         `getHaveVector()` returned `emptyList()`. There was no gossip
 *         protocol. This module is the structured CBOR replacement.)
 * Source: 06-CONFORMANCE-AND-AI-MODEL.md §A4 (required anti-entropy suites)
 *
 * The audit (00-AUDIT.md §3.7) found three coupled failures in the existing
 * codebase:
 *
 *   1. `SyncWorker.kt` sent the literal ASCII bytes `"HAVE:"` to every peer.
 *      There was no structured payload — peers had no way to say WHAT they
 *      had, only that they had "something."
 *
 *   2. `RealSyncDependencies.getHaveVector()` returned `emptyList()`. Even if
 *      the wire format had been structured, the local node advertised nothing.
 *
 *   3. Nothing consumed `transport.incoming`. The receive side of the gossip
 *      protocol did not exist. Bytes arrived and were discarded.
 *
 * This module fixes all three. The `HaveVector` is the structured CBOR
 * replacement for `"HAVE:"` — a canonical CBOR map listing the NodeIds,
 * gateway NodeIds, and ObjectIds the local node holds. `SyncSession` is the
 * stateful anti-entropy exchange: build a HAVE, diff against the peer's HAVE,
 * request the objects the peer has that we lack, and apply the peer's
 * response to our local stores.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * L5 CONTRACT — "Must NOT interpret transit payloads."
 * ════════════════════════════════════════════════════════════════════════════
 *
 * The L5 layer carries TWO kinds of cargo, and must NEVER carry a third:
 *
 *   ✅ Class A objects — content-addressed (Manifest + chunks). The ObjectId
 *      is the Merkle root of the chunks, so the object is self-verifying.
 *      Sync carries the Manifest; chunks are fetched by ObjectId through a
 *      separate exchange. Sync does NOT inspect the content type, MIME, or
 *      publisher of the object — it carries whatever the Manifest attests to.
 *
 *   ✅ NodeDescriptors & GatewayAdverts — self-signed identity/capability
 *      claims. Sync carries them so peers can learn about nodes they haven't
 *      directly observed. The DescriptorStore (L4) verifies signatures before
 *      accepting; sync just transports.
 *
 *   ✅ Mode A bundles — store-carry-forward custody objects wrapping a
 *      TransitRequest (and optionally a TransitResponse). Sync carries these
 *      so a request can traverse the mesh hop-by-hop until it reaches a
 *      gateway, and the response can traverse back. Sync does NOT act on the
 *      request (it doesn't fetch the URL); it only forwards the bundle.
 *
 *   ❌ Class B transit frames — circuit-addressed (FlowId), NOT content-
 *      addressed. These belong to L6/L7 (routing + sessions). Sync MUST NOT
 *      carry them: they are not content-addressed (no ObjectId), they are
 *      not self-verifying (the circuit's integrity comes from the Noise_IK
 *      + AEAD channel, not from a signature), and they are not store-carry-
 *      forward (they are real-time streams). Mixing them into sync would
 *      break the layer separation and create a circuit-into-content confusion
 *      attack surface.
 *
 * The rule is: if it has an ObjectId (32-byte Merkle root) OR a NodeId OR a
 * reqId (Mode A bundle), sync can carry it. If it has a FlowId, it belongs to
 * L6/L7 and sync MUST refuse it. This module enforces the rule by construction
 * — there is no API that accepts a Class B frame.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * ANTI-ENTROPY EXCHANGE (spec §5 tier 2)
 * ════════════════════════════════════════════════════════════════════════════
 *
 * When two nodes meet (after the L8 Noise_IK handshake), they run a
 * `SyncSession`:
 *
 *   1. Each side builds a `HaveVector` from its local stores (DescriptorStore
 *      + ObjectStore). The vector lists the NodeIds, gateway NodeIds, and
 *      ObjectIds the node holds.
 *
 *   2. Each side sends its HaveVector to the peer.
 *
 *   3. Each side calls `computeSyncDiff(localHave, peerHave)` to compute
 *      `localWants` (ObjectIds the peer has that local lacks) and
 *      `localOffers` (ObjectIds local has that the peer lacks).
 *
 *   4. Each side builds a `SyncRequest` with `want` (objects to fetch),
 *      `offer` (objects local can provide), and `wantDescriptors` (NodeIds
 *      whose descriptors local lacks). The request is sent to the peer.
 *
 *   5. The peer's `handleSyncRequest` produces a `SyncResponse` with the
 *      manifests of the requested objects and the requested descriptors. The
 *      response is sent back.
 *
 *   6. Each side calls `applySyncResponse` to merge the response into its
 *      local stores (descriptors go to DescriptorStore; manifests go to a
 *      pending queue; chunks need a separate fetch exchange).
 *
 * This is classic anti-entropy (Demers et al. 1987, "Epidemic Algorithms for
 * Replicated Database Maintenance"): nodes exchange summaries, diff, and
 * reconcile. The summaries (HaveVectors) are compact (lists of 32-byte
 * hashes); the actual objects are exchanged only for the diff.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * STORE-CARRY-FORWARD + BUNDLE CUSTODY
 * ════════════════════════════════════════════════════════════════════════════
 *
 * Mode A bundles (TransitRequest + optional TransitResponse) traverse the
 * mesh via store-carry-forward: a node receives a bundle, holds it in its
 * `BundleStore`, and forwards it when it next meets a peer closer to a
 * gateway (or to the requester, for responses). Each hop appends its NodeId
 * to the bundle's `custodyChain`, creating an auditable record of which nodes
 * held the bundle.
 *
 * The custody chain is APPEND-ONLY (I15). `appendCustodyHop` returns a NEW
 * `ModeABundle` with the hop appended; it never mutates the input. This
 * prevents a malicious relay from rewriting the chain to hide its involvement
 * or to frame another node.
 *
 * Bundles have a deadline (from the TransitRequest). `isBundleExpired(bundle,
 * now)` returns true past the deadline; `BundleStore.pruneExpired(now)`
 * removes expired bundles; `BundleStore.pending(now)` returns non-expired,
 * undelivered bundles for forwarding.
 *
 * @ invariant I1  — All structures use SNP-CBOR with length-first key ordering
 * @ invariant I9  — This module imports from discovery, identity, manifest,
 *                   cbor, constants, gateway — NOT from routing (L6). L5 must
 *                   not import L6.
 * @ invariant I15 — BundleStore custody chain is append-only.
 *                   `appendCustodyHop` returns a new bundle; never mutates.
 * @ invariant I20 — `validate*` throws CborError(MALFORMED) on structural
 *                   problems; decode throws on malformed input; store
 *                   operations return booleans (ObjectStore.put,
 *                   InMemoryObjectStore.put). BundleStore.add throws on
 *                   invalid input (it is a custody gate, not a verification
 *                   gate — callers wrap peer-supplied bundles in try/catch).
 */

import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  PROTO_VERSION,
} from "./constants";
import {
  type CborValue,
  CborError,
  cborMap,
  encode as cborEncode,
  decode as cborDecode,
} from "./cbor";
import {
  type NodeDescriptor,
  type DeviceCert,
  isExpired,
} from "./identity";
import {
  type Manifest,
  type ManifestClass,
  validateManifest,
} from "./manifest";
import {
  type TransitRequest,
  type TransitResponse,
  validateTransitRequest,
  validateTransitResponse,
} from "./gateway";
import { type DescriptorStore } from "./discovery";

// ─── Frozen sizes ──────────────────────────────────────────────────────────

/** NodeId / ObjectId / RendezvousIdentity byte length (32 bytes — SHA-256). */
const NODE_ID_BYTES = 32;

/** TransitRequest.reqId byte length (16 bytes — replay defence). */
const REQ_ID_BYTES = 16;

// ─── Internal helpers ──────────────────────────────────────────────────────

/** Convert a Uint8Array to a lowercase hex string. Used as Map keys (JS Map
 *  uses reference equality on objects, so NodeIds/ObjectIds must be normalised
 *  to a primitive string before lookup). */
function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0");
  }
  return s;
}

/** Inverse of bytesToHex. Used to materialise ObjectIds from Map keys. */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`hex string has odd length: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return out;
}

/** Constant-time-ish byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Human-readable type name for a CborValue, for error messages. */
function describeType(v: CborValue | undefined): string {
  if (v === undefined) return "missing";
  if (v === null) return "null";
  if (typeof v !== "object") return typeof v;
  if (v instanceof Uint8Array) return `bstr(${v.length})`;
  if (Array.isArray(v)) return `array(${v.length})`;
  if (v instanceof Map) return "map";
  return "object";
}

/** Extract a byte string (Uint8Array) from a decoded CBOR value, throwing
 *  CborError(MALFORMED) if the value is missing or not a Uint8Array. */
function extractBstr(v: CborValue | undefined, field: string): Uint8Array {
  if (!(v instanceof Uint8Array)) {
    throw new CborError(
      `${field} must be a byte string; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a byte string of any length, or null. */
function extractBstrOrNullAny(
  v: CborValue | undefined,
  field: string,
): Uint8Array | null {
  if (v === null) return null;
  if (!(v instanceof Uint8Array)) {
    throw new CborError(
      `${field} must be null or a byte string; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a text string. */
function extractString(v: CborValue | undefined, field: string): string {
  if (typeof v !== "string") {
    throw new CborError(
      `${field} must be a text string; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a non-negative integer (number or bigint → number). */
function extractUint(v: CborValue | undefined, field: string): number {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) {
    return v;
  }
  if (typeof v === "bigint" && v >= 0n && v <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(v);
  }
  throw new CborError(
    `${field} must be a non-negative integer; got ${describeType(v)}`,
    "MALFORMED",
  );
}

/** Extract a boolean. */
function extractBool(v: CborValue | undefined, field: string): boolean {
  if (typeof v !== "boolean") {
    throw new CborError(
      `${field} must be a boolean; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a CBOR array. */
function extractArray(v: CborValue | undefined, field: string): CborValue[] {
  if (!Array.isArray(v)) {
    throw new CborError(
      `${field} must be an array; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a CBOR map. */
function extractMap(
  v: CborValue | undefined,
  field: string,
): Map<string | Uint8Array, CborValue> {
  if (!(v instanceof Map)) {
    throw new CborError(
      `${field} must be a map; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  return v;
}

/** Extract a Map<string, string> (for HTTP headers). All keys and values
 *  must be text strings; bstr keys are rejected (they would collide with
 *  tstr keys under canonical encoding and are not used in SNP header maps). */
function extractStringMap(
  v: CborValue | undefined,
  field: string,
): Map<string, string> {
  const m = extractMap(v, field);
  const out = new Map<string, string>();
  for (const [k, val] of m.entries()) {
    if (typeof k !== "string") {
      throw new CborError(
        `${field} keys must be text strings; got ${describeType(k)}`,
        "MALFORMED",
      );
    }
    if (typeof val !== "string") {
      throw new CborError(
        `${field}["${k}"] must be a text string; got ${describeType(val)}`,
        "MALFORMED",
      );
    }
    out.set(k, val);
  }
  return out;
}

/** Decode the top-level CBOR value, re-throwing CborError and wrapping
 *  unknown errors as CborError(DECODE_ERROR). */
function decodeCbor(bytes: Uint8Array, what: string): CborValue {
  try {
    return cborDecode(bytes);
  } catch (e) {
    if (e instanceof CborError) throw e;
    throw new CborError(
      `Failed to decode ${what}: ${e instanceof Error ? e.message : String(e)}`,
      "DECODE_ERROR",
    );
  }
}

// ─── Wire-format (de)serialisers for embedded structures ───────────────────
//
// Manifest, NodeDescriptor (with embedded DeviceCert), TransitRequest, and
// TransitResponse are all self-signed structures whose `*ToCborMap` helpers
// in their home modules return the SIGNED PREIMAGE (without the signature
// field). For the sync wire format we need the COMPLETE structure (preimage +
// signature) so the receiver can re-verify the signature without re-signing.
// These helpers build the wire map (preimage + signature) and the inverse
// decoders that reconstruct the structure from a wire map.
//
// The decoders call the existing `validate*` functions from the home modules
// to enforce the CDDL constraints. They do NOT verify signatures — signature
// verification is a separate trust decision made by the store that receives
// the structure (DescriptorStore.addNodeDescriptor, ObjectStore.put, etc.).

// ─── Manifest wire format ──────────────────────────────────────────────────

/**
 * Build the wire CBOR map for a Manifest (preimage + signature). The map has
 * STRING keys; canonical ordering is applied at encode time.
 *
 *   ManifestWire = {
 *     "objectId":     bstr .size 32,
 *     "chunks":       [+ bstr .size 32],
 *     "chunkCount":   uint,
 *     "totalBytes":   uint,
 *     "mimeType":     tstr,
 *     "class":        tstr,
 *     "publisherId":  bstr .size 32,
 *     "publishedAt":  uint,
 *     "expiresAt":    uint / null,
 *     "signature":    bstr .size 64
 *   }
 */
function manifestToWireMap(m: Manifest): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["objectId", m.objectId],
    ["chunks", m.chunks as CborValue[]],
    ["chunkCount", m.chunkCount],
    ["totalBytes", m.totalBytes],
    ["mimeType", m.mimeType],
    ["class", m.class],
    ["publisherId", m.publisherId],
    ["publishedAt", m.publishedAt],
    ["expiresAt", m.expiresAt as CborValue],
    ["signature", m.signature],
  ]);
}

/**
 * Decode a Manifest from a wire CBOR map. Calls `validateManifest` (throws
 * CborError(MALFORMED) on structural violations). Does NOT verify the
 * signature — that is a separate trust decision.
 */
function manifestFromWireMap(map: Map<string | Uint8Array, CborValue>): Manifest {
  const objectId = extractBstr(map.get("objectId"), "Manifest.objectId");
  const chunksArr = extractArray(map.get("chunks"), "Manifest.chunks");
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < chunksArr.length; i++) {
    chunks.push(extractBstr(chunksArr[i], `Manifest.chunks[${i}]`));
  }
  const chunkCount = extractUint(map.get("chunkCount"), "Manifest.chunkCount");
  const totalBytes = extractUint(map.get("totalBytes"), "Manifest.totalBytes");
  const mimeType = extractString(map.get("mimeType"), "Manifest.mimeType");
  const classStr = extractString(map.get("class"), "Manifest.class");
  const publisherId = extractBstr(map.get("publisherId"), "Manifest.publisherId");
  const publishedAt = extractUint(map.get("publishedAt"), "Manifest.publishedAt");
  const expiresAtRaw = map.get("expiresAt");
  const expiresAt =
    expiresAtRaw === null || expiresAtRaw === undefined
      ? null
      : extractUint(expiresAtRaw, "Manifest.expiresAt");
  const signature = extractBstr(map.get("signature"), "Manifest.signature");
  const manifest: Manifest = {
    objectId,
    chunks,
    chunkCount,
    totalBytes,
    mimeType,
    class: classStr as ManifestClass,
    publisherId,
    publishedAt,
    expiresAt,
    signature,
  };
  // validateManifest checks class ∈ MANIFEST_CLASSES, chunkCount === chunks.length,
  // signature length, etc. Throws CborError(MALFORMED) on any violation.
  validateManifest(manifest);
  return manifest;
}

// ─── DeviceCert wire format ────────────────────────────────────────────────

/**
 * Build the wire CBOR map for a DeviceCert (preimage + signature). Embedded
 * inside NodeDescriptor's `deviceCert` field.
 */
function deviceCertToWireMap(c: DeviceCert): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["deviceId", c.deviceId],
    ["userId", c.userId],
    ["capabilities", c.capabilities as CborValue[]],
    ["platform", c.platform],
    ["notBefore", c.notBefore],
    ["notAfter", c.notAfter],
    ["attestation", c.attestation as CborValue],
    ["signature", c.signature],
  ]);
}

/**
 * Decode a DeviceCert from a wire CBOR map. Structural validation only — does
 * NOT verify the signature (the NodeDescriptor's signature binds the embedded
 * DeviceCert; the DeviceCert's own signature is verified separately by callers
 * who care about the user↔device binding).
 */
function deviceCertFromWireMap(map: Map<string | Uint8Array, CborValue>): DeviceCert {
  const deviceId = extractBstr(map.get("deviceId"), "DeviceCert.deviceId");
  const userId = extractBstr(map.get("userId"), "DeviceCert.userId");
  const capsArr = extractArray(map.get("capabilities"), "DeviceCert.capabilities");
  const capabilities: string[] = [];
  for (let i = 0; i < capsArr.length; i++) {
    if (typeof capsArr[i] !== "string") {
      throw new CborError(
        `DeviceCert.capabilities[${i}] must be a string; got ${describeType(capsArr[i])}`,
        "MALFORMED",
      );
    }
    capabilities.push(capsArr[i] as string);
  }
  const platform = extractString(map.get("platform"), "DeviceCert.platform");
  const notBefore = extractUint(map.get("notBefore"), "DeviceCert.notBefore");
  const notAfter = extractUint(map.get("notAfter"), "DeviceCert.notAfter");
  const attestation = extractBstrOrNullAny(
    map.get("attestation"),
    "DeviceCert.attestation",
  );
  const signature = extractBstr(map.get("signature"), "DeviceCert.signature");
  const cert: DeviceCert = {
    deviceId,
    userId,
    capabilities: capabilities as DeviceCert["capabilities"],
    platform: platform as DeviceCert["platform"],
    notBefore,
    notAfter,
    attestation,
    signature,
  };
  // Lightweight structural validation (the full assertDeviceCertFields is
  // private in identity.ts; we replicate the load-bearing checks here).
  if (deviceId.length !== NODE_ID_BYTES) {
    throw new CborError(
      `DeviceCert.deviceId must be ${NODE_ID_BYTES} bytes; got ${deviceId.length}`,
      "MALFORMED",
    );
  }
  if (userId.length !== NODE_ID_BYTES) {
    throw new CborError(
      `DeviceCert.userId must be ${NODE_ID_BYTES} bytes; got ${userId.length}`,
      "MALFORMED",
    );
  }
  if (capabilities.length === 0) {
    throw new CborError("DeviceCert.capabilities must be non-empty", "MALFORMED");
  }
  if (notAfter <= notBefore) {
    throw new CborError(
      `DeviceCert.notAfter (${notAfter}) must be > notBefore (${notBefore})`,
      "MALFORMED",
    );
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new CborError(
      `DeviceCert.signature must be ${ED25519_SIGNATURE_BYTES} bytes; got ${signature.length}`,
      "MALFORMED",
    );
  }
  return cert;
}

// ─── NodeDescriptor wire format ────────────────────────────────────────────

/**
 * Build the wire CBOR map for a NodeDescriptor (preimage + signature, with
 * the embedded DeviceCert also in wire form).
 *
 *   NodeDescriptorWire = {
 *     "nodeId":        bstr .size 32,
 *     "nodePubKey":    bstr .size 32,
 *     "rendezvousPub": bstr .size 32,
 *     "capabilities":  [+ tstr],
 *     "platform":      tstr,
 *     "protoVersion":  tstr,
 *     "epoch":         uint,
 *     "expiresAt":     uint,
 *     "links":         [* tstr],
 *     "deviceCert":    DeviceCertWire / null,
 *     "signature":     bstr .size 64
 *   }
 */
function nodeDescriptorToWireMap(
  d: NodeDescriptor,
): Map<string | Uint8Array, CborValue> {
  const deviceCertWire: CborValue =
    d.deviceCert === null ? null : deviceCertToWireMap(d.deviceCert);
  return cborMap([
    ["nodeId", d.nodeId],
    ["nodePubKey", d.nodePubKey],
    ["rendezvousPub", d.rendezvousPub],
    ["capabilities", d.capabilities as CborValue[]],
    ["platform", d.platform],
    ["protoVersion", d.protoVersion],
    ["epoch", d.epoch],
    ["expiresAt", d.expiresAt],
    ["links", d.links as CborValue[]],
    ["deviceCert", deviceCertWire],
    ["signature", d.signature],
  ]);
}

/**
 * Decode a NodeDescriptor from a wire CBOR map. Structural validation only —
 * does NOT verify the signature (DescriptorStore.addNodeDescriptor does that).
 */
function nodeDescriptorFromWireMap(
  map: Map<string | Uint8Array, CborValue>,
): NodeDescriptor {
  const nodeId = extractBstr(map.get("nodeId"), "NodeDescriptor.nodeId");
  const nodePubKey = extractBstr(map.get("nodePubKey"), "NodeDescriptor.nodePubKey");
  const rendezvousPub = extractBstr(
    map.get("rendezvousPub"),
    "NodeDescriptor.rendezvousPub",
  );
  const capsArr = extractArray(
    map.get("capabilities"),
    "NodeDescriptor.capabilities",
  );
  const capabilities: string[] = [];
  for (let i = 0; i < capsArr.length; i++) {
    if (typeof capsArr[i] !== "string") {
      throw new CborError(
        `NodeDescriptor.capabilities[${i}] must be a string; got ${describeType(capsArr[i])}`,
        "MALFORMED",
      );
    }
    capabilities.push(capsArr[i] as string);
  }
  const platform = extractString(map.get("platform"), "NodeDescriptor.platform");
  const protoVersion = extractString(
    map.get("protoVersion"),
    "NodeDescriptor.protoVersion",
  );
  const epoch = extractUint(map.get("epoch"), "NodeDescriptor.epoch");
  const expiresAt = extractUint(map.get("expiresAt"), "NodeDescriptor.expiresAt");
  const linksArr = extractArray(map.get("links"), "NodeDescriptor.links");
  const links: string[] = [];
  for (let i = 0; i < linksArr.length; i++) {
    if (typeof linksArr[i] !== "string") {
      throw new CborError(
        `NodeDescriptor.links[${i}] must be a string; got ${describeType(linksArr[i])}`,
        "MALFORMED",
      );
    }
    links.push(linksArr[i] as string);
  }
  const deviceCertRaw = map.get("deviceCert");
  const deviceCert: DeviceCert | null =
    deviceCertRaw === null || deviceCertRaw === undefined
      ? null
      : deviceCertFromWireMap(extractMap(deviceCertRaw, "NodeDescriptor.deviceCert"));
  const signature = extractBstr(map.get("signature"), "NodeDescriptor.signature");

  // Lightweight structural validation (mirrors identity.ts's private
  // assertNodeDescriptorFields — load-bearing checks only).
  if (nodeId.length !== NODE_ID_BYTES) {
    throw new CborError(
      `NodeDescriptor.nodeId must be ${NODE_ID_BYTES} bytes; got ${nodeId.length}`,
      "MALFORMED",
    );
  }
  if (nodePubKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new CborError(
      `NodeDescriptor.nodePubKey must be ${ED25519_PUBLIC_KEY_BYTES} bytes; got ${nodePubKey.length}`,
      "MALFORMED",
    );
  }
  if (rendezvousPub.length !== NODE_ID_BYTES) {
    throw new CborError(
      `NodeDescriptor.rendezvousPub must be ${NODE_ID_BYTES} bytes; got ${rendezvousPub.length}`,
      "MALFORMED",
    );
  }
  if (capabilities.length === 0) {
    throw new CborError(
      "NodeDescriptor.capabilities must be non-empty",
      "MALFORMED",
    );
  }
  if (protoVersion !== PROTO_VERSION) {
    throw new CborError(
      `NodeDescriptor.protoVersion must be "${PROTO_VERSION}"; got "${protoVersion}"`,
      "MALFORMED",
    );
  }
  if (expiresAt <= 0) {
    throw new CborError(
      `NodeDescriptor.expiresAt must be a positive integer; got ${expiresAt}`,
      "MALFORMED",
    );
  }
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new CborError(
      `NodeDescriptor.signature must be ${ED25519_SIGNATURE_BYTES} bytes; got ${signature.length}`,
      "MALFORMED",
    );
  }

  return {
    nodeId,
    nodePubKey,
    rendezvousPub,
    capabilities: capabilities as NodeDescriptor["capabilities"],
    platform: platform as NodeDescriptor["platform"],
    protoVersion,
    epoch,
    expiresAt,
    links,
    deviceCert,
    signature,
  };
}

// ─── TransitRequest wire format ────────────────────────────────────────────

/**
 * Build the wire CBOR map for a TransitRequest (preimage + clientSig).
 *
 *   TransitRequestWire = {
 *     "reqId":            bstr .size 16,
 *     "method":           tstr,
 *     "url":              tstr,
 *     "headers":          { * tstr => tstr },
 *     "body":             bstr / null,
 *     "tlsTermination":   tstr,
 *     "maxResponseBytes": uint,
 *     "deadline":         uint,
 *     "replyTo":          bstr .size 32,
 *     "acceptGateways":   "any" / [* bstr .size 32],
 *     "clientSig":        bstr .size 64
 *   }
 */
function transitRequestToWireMap(
  r: TransitRequest,
): Map<string | Uint8Array, CborValue> {
  const headersCbor: Map<string | Uint8Array, CborValue> = new Map();
  for (const [k, v] of r.headers.entries()) {
    headersCbor.set(k, v);
  }
  const acceptGatewaysCbor: CborValue =
    r.acceptGateways === "any" ? "any" : (r.acceptGateways as CborValue[]);
  return cborMap([
    ["reqId", r.reqId],
    ["method", r.method],
    ["url", r.url],
    ["headers", headersCbor],
    ["body", r.body as CborValue],
    ["tlsTermination", r.tlsTermination],
    ["maxResponseBytes", r.maxResponseBytes],
    ["deadline", r.deadline],
    ["replyTo", r.replyTo],
    ["acceptGateways", acceptGatewaysCbor],
    ["clientSig", r.clientSig],
  ]);
}

/** Decode the `acceptGateways` field — either the string "any" or an array
 *  of 32-byte bstrs. */
function extractAcceptGateways(
  v: CborValue | undefined,
  field: string,
): "any" | Uint8Array[] {
  if (typeof v === "string") {
    if (v !== "any") {
      throw new CborError(
        `${field} string value must be "any"; got "${v}"`,
        "MALFORMED",
      );
    }
    return "any";
  }
  if (!Array.isArray(v)) {
    throw new CborError(
      `${field} must be "any" or an array; got ${describeType(v)}`,
      "MALFORMED",
    );
  }
  const out: Uint8Array[] = [];
  for (let i = 0; i < v.length; i++) {
    const item = v[i];
    if (!(item instanceof Uint8Array) || item.length !== NODE_ID_BYTES) {
      throw new CborError(
        `${field}[${i}] must be a ${NODE_ID_BYTES}-byte byte string; got ${describeType(item)}`,
        "MALFORMED",
      );
    }
    out.push(item);
  }
  return out;
}

/**
 * Decode a TransitRequest from a wire CBOR map. Calls `validateTransitRequest`
 * (throws CborError(MALFORMED) on structural violations, including a missing
 * or invalid `tlsTermination` — I17). Does NOT verify the clientSig.
 */
function transitRequestFromWireMap(
  map: Map<string | Uint8Array, CborValue>,
): TransitRequest {
  const reqId = extractBstr(map.get("reqId"), "TransitRequest.reqId");
  const method = extractString(map.get("method"), "TransitRequest.method");
  const url = extractString(map.get("url"), "TransitRequest.url");
  const headers = extractStringMap(map.get("headers"), "TransitRequest.headers");
  const body = extractBstrOrNullAny(map.get("body"), "TransitRequest.body");
  const tlsTermination = extractString(
    map.get("tlsTermination"),
    "TransitRequest.tlsTermination",
  );
  const maxResponseBytes = extractUint(
    map.get("maxResponseBytes"),
    "TransitRequest.maxResponseBytes",
  );
  const deadline = extractUint(map.get("deadline"), "TransitRequest.deadline");
  const replyTo = extractBstr(map.get("replyTo"), "TransitRequest.replyTo");
  const acceptGateways = extractAcceptGateways(
    map.get("acceptGateways"),
    "TransitRequest.acceptGateways",
  );
  const clientSig = extractBstr(map.get("clientSig"), "TransitRequest.clientSig");
  const request: TransitRequest = {
    reqId,
    method,
    url,
    headers,
    body,
    tlsTermination: tlsTermination as TransitRequest["tlsTermination"],
    maxResponseBytes,
    deadline,
    replyTo,
    acceptGateways,
    clientSig,
  };
  // validateTransitRequest enforces the CDDL (incl. I17: tlsTermination is
  // mandatory and must be a known value). Throws CborError(MALFORMED).
  validateTransitRequest(request);
  return request;
}

// ─── TransitResponse wire format ───────────────────────────────────────────

/**
 * Build the wire CBOR map for a TransitResponse (preimage + gatewaySig).
 *
 *   TransitResponseWire = {
 *     "reqId":      bstr .size 16,
 *     "status":     uint,
 *     "headers":    { * tstr => tstr },
 *     "objectId":   bstr .size 32,
 *     "fetchedAt":  uint,
 *     "gatewayId":  bstr .size 32,
 *     "gatewaySig": bstr .size 64
 *   }
 */
function transitResponseToWireMap(
  r: TransitResponse,
): Map<string | Uint8Array, CborValue> {
  const headersCbor: Map<string | Uint8Array, CborValue> = new Map();
  for (const [k, v] of r.headers.entries()) {
    headersCbor.set(k, v);
  }
  return cborMap([
    ["reqId", r.reqId],
    ["status", r.status],
    ["headers", headersCbor],
    ["objectId", r.objectId],
    ["fetchedAt", r.fetchedAt],
    ["gatewayId", r.gatewayId],
    ["gatewaySig", r.gatewaySig],
  ]);
}

/**
 * Decode a TransitResponse from a wire CBOR map. Calls `validateTransitResponse`
 * (throws CborError(MALFORMED) on structural violations). Does NOT verify the
 * gatewaySig.
 */
function transitResponseFromWireMap(
  map: Map<string | Uint8Array, CborValue>,
): TransitResponse {
  const reqId = extractBstr(map.get("reqId"), "TransitResponse.reqId");
  const status = extractUint(map.get("status"), "TransitResponse.status");
  const headers = extractStringMap(
    map.get("headers"),
    "TransitResponse.headers",
  );
  const objectId = extractBstr(map.get("objectId"), "TransitResponse.objectId");
  const fetchedAt = extractUint(map.get("fetchedAt"), "TransitResponse.fetchedAt");
  const gatewayId = extractBstr(map.get("gatewayId"), "TransitResponse.gatewayId");
  const gatewaySig = extractBstr(
    map.get("gatewaySig"),
    "TransitResponse.gatewaySig",
  );
  const response: TransitResponse = {
    reqId,
    status,
    headers,
    objectId,
    fetchedAt,
    gatewayId,
    gatewaySig,
  };
  validateTransitResponse(response);
  return response;
}

// ─── 1. HaveVector — the anti-entropy summary ──────────────────────────────

/**
 * A structured CBOR payload listing the content objects and descriptors a node
 * holds. Per spec §5 tier 2, this replaces the audit's literal `"HAVE:"`
 * ASCII string (00-AUDIT.md §3.7).
 *
 * The vector is a SUMMARY — it lists hashes (NodeIds, ObjectIds), not the
 * objects themselves. The actual objects are exchanged in the SyncRequest /
 * SyncResponse phase, only for the diff (objects one side has that the other
 * lacks). This keeps the HAVE exchange compact even when the local stores
 * hold gigabytes of content.
 *
 * CDDL (02-PROTOCOL-SPEC.md §5 tier 2):
 *
 *   HaveVector = {
 *     "knownNodes":    [* bstr .size 32],   ; NodeIds whose NodeDescriptors we hold
 *     "knownGateways": [* bstr .size 32],   ; gateway NodeIds whose GatewayAdverts we hold
 *     "knownObjects":  [* bstr .size 32],   ; ObjectIds of Class A content objects we hold
 *     "generatedAt":   uint                 ; unix seconds — when this vector was generated
 *   }
 *
 * Only NON-EXPIRED descriptors are included in `knownNodes` / `knownGateways`
 * (spec §5 freshness rule — forwarding an expired descriptor's NodeId would
 * mislead the peer into requesting it). `knownObjects` lists every ObjectId
 * in the local CAS; object expiry is per-Manifest (the `expiresAt` field) and
 * is enforced at fetch time, not at HAVE-vector time.
 */
export interface HaveVector {
  /** NodeIds whose NodeDescriptors we hold (gossiped descriptors). Each 32 bytes. */
  readonly knownNodes: Uint8Array[];
  /** Gateway NodeIds whose GatewayAdverts we hold. Each 32 bytes. */
  readonly knownGateways: Uint8Array[];
  /** ObjectIds of Class A content objects we hold (manifests, blobs). Each 32 bytes. */
  readonly knownObjects: Uint8Array[];
  /** When this vector was generated (unix seconds). */
  readonly generatedAt: number;
}

/**
 * Encode a `HaveVector` to canonical SNP-CBOR bytes.
 *
 * The wire form is a CBOR map with STRING keys (see the CDDL in the
 * `HaveVector` interface JSDoc). Canonical ordering (length-first on the
 * fully-encoded key — I1) is applied by the SNP-CBOR encoder in `cbor.ts`.
 */
export function encodeHaveVector(v: HaveVector): Uint8Array {
  validateHaveVector(v);
  return cborEncode(
    cborMap([
      ["knownNodes", v.knownNodes as CborValue[]],
      ["knownGateways", v.knownGateways as CborValue[]],
      ["knownObjects", v.knownObjects as CborValue[]],
      ["generatedAt", v.generatedAt],
    ]),
  );
}

/**
 * Decode a `HaveVector` from canonical SNP-CBOR bytes.
 *
 * Throws `CborError` on malformed input — non-CBOR bytes, wrong major types,
 * missing fields, non-32-byte entries, or a non-positive `generatedAt`. After
 * a successful decode the returned vector is guaranteed to pass
 * `validateHaveVector`.
 */
export function decodeHaveVector(bytes: Uint8Array): HaveVector {
  const value = decodeCbor(bytes, "HaveVector");
  if (!(value instanceof Map)) {
    throw new CborError(
      `HaveVector must be a CBOR map; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  const map = value as Map<string | Uint8Array, CborValue>;
  const knownNodesArr = extractArray(map.get("knownNodes"), "HaveVector.knownNodes");
  const knownNodes: Uint8Array[] = [];
  for (let i = 0; i < knownNodesArr.length; i++) {
    knownNodes.push(extractBstr(knownNodesArr[i], `HaveVector.knownNodes[${i}]`));
  }
  const knownGatewaysArr = extractArray(
    map.get("knownGateways"),
    "HaveVector.knownGateways",
  );
  const knownGateways: Uint8Array[] = [];
  for (let i = 0; i < knownGatewaysArr.length; i++) {
    knownGateways.push(
      extractBstr(knownGatewaysArr[i], `HaveVector.knownGateways[${i}]`),
    );
  }
  const knownObjectsArr = extractArray(
    map.get("knownObjects"),
    "HaveVector.knownObjects",
  );
  const knownObjects: Uint8Array[] = [];
  for (let i = 0; i < knownObjectsArr.length; i++) {
    knownObjects.push(
      extractBstr(knownObjectsArr[i], `HaveVector.knownObjects[${i}]`),
    );
  }
  const generatedAt = extractUint(map.get("generatedAt"), "HaveVector.generatedAt");
  const v: HaveVector = {
    knownNodes,
    knownGateways,
    knownObjects,
    generatedAt,
  };
  validateHaveVector(v);
  return v;
}

/**
 * Validate the STRUCTURE of a `HaveVector` against the CDDL constraints.
 *
 * Throws `CborError(MALFORMED)` on any violation:
 *   - `knownNodes`, `knownGateways`, `knownObjects` must be arrays of
 *     32-byte Uint8Arrays.
 *   - `generatedAt` must be a positive integer (> 0).
 *
 * Does NOT enforce deduplication — a peer MAY send a vector with duplicate
 * NodeIds (wasteful but not a security issue; the diff logic handles it via
 * set membership).
 */
export function validateHaveVector(v: HaveVector): void {
  assertBstrArray(v.knownNodes, "HaveVector.knownNodes");
  assertBstrArray(v.knownGateways, "HaveVector.knownGateways");
  assertBstrArray(v.knownObjects, "HaveVector.knownObjects");
  if (
    typeof v.generatedAt !== "number" ||
    !Number.isInteger(v.generatedAt) ||
    v.generatedAt <= 0
  ) {
    throw new CborError(
      `HaveVector.generatedAt must be a positive integer (unix seconds); got ${String(v.generatedAt)}`,
      "MALFORMED",
    );
  }
}

/** Helper: assert that `v` is an array of 32-byte Uint8Arrays. */
function assertBstrArray(v: unknown, field: string): asserts v is Uint8Array[] {
  if (!Array.isArray(v)) {
    throw new CborError(
      `${field} must be an array; got ${v === null ? "null" : typeof v}`,
      "MALFORMED",
    );
  }
  for (let i = 0; i < v.length; i++) {
    const item = v[i];
    if (!(item instanceof Uint8Array) || item.length !== NODE_ID_BYTES) {
      throw new CborError(
        `${field}[${i}] must be a ${NODE_ID_BYTES}-byte Uint8Array; got ${item instanceof Uint8Array ? `${item.length} bytes` : typeof item}`,
        "MALFORMED",
      );
    }
  }
}

// ─── 2. ObjectStore — the local CAS contract ───────────────────────────────

/**
 * Minimal interface that the sync layer uses to access the content-addressed
 * store. The real implementation lives in L2 (content layer); this is the
 * contract L5 needs.
 *
 * An ObjectId is the 32-byte Merkle root of an object's chunks (RFC 6962).
 * The CAS stores Manifests (which bind the ObjectId to the chunk hashes,
 * totalBytes, MIME type, publisher, etc.) and the raw chunks. `put` accepts
 * both; `getManifest` / `getChunks` retrieve them separately (the manifest is
 * small and frequently accessed; the chunks may be large and are fetched
 * lazily).
 *
 * The CAS is CONTENT-ADDRESSED: the ObjectId is derived from the content
 * (Merkle root), so two puts of the same content are idempotent. There is no
 * "delete" in this interface — content expiry is a higher-level concern (the
 * Manifest's `expiresAt` field; a periodic GC pass that removes expired
 * objects is out of scope for L5).
 */
export interface ObjectStore {
  /**
   * Returns true iff an object with the given ObjectId is stored.
   * The ObjectId is the Merkle root (32 bytes); the caller must NOT pass a
   * raw chunk hash or a NodeId.
   */
  has(objectId: Uint8Array): boolean;
  /** List all stored ObjectIds. */
  list(): Uint8Array[];
  /**
   * Store an object (manifest + chunks). Returns true on success, false on
   * invalid input (I20: never throws for store operations).
   *
   * The manifest's `objectId` MUST equal `merkleRoot(manifest.chunks)`; the
   * CAS MAY verify this (the InMemoryObjectStore does, for testing fidelity).
   * The chunks are the RAW chunk bytes (not leaf hashes); the CAS stores them
   * alongside the manifest for later retrieval.
   */
  put(manifest: Manifest, chunks: Uint8Array[]): boolean;
  /** Retrieve a manifest by ObjectId, or null if not present. */
  getManifest(objectId: Uint8Array): Manifest | null;
  /** Retrieve chunks for an ObjectId, or null if not present. */
  getChunks(objectId: Uint8Array): Uint8Array[] | null;
}

// ─── 3. InMemoryObjectStore — for testing ──────────────────────────────────

/**
 * A simple Map-backed `ObjectStore` for conformance/integration tests.
 *
 * ⚠️ TESTING ONLY. Production code MUST use a real content-addressed store
 * (L2 content layer) that persists to disk and verifies Merkle roots on
 * retrieval. This implementation does NOT persist and does NOT verify that
 * `objectId === merkleRoot(chunks)` on put (it trusts the manifest's
 * `objectId` field as the key) — it is suitable for testing the sync layer's
 * logic, not for storing real content.
 *
 * The store keeps two parallel maps: `manifests` (ObjectId → Manifest) and
 * `chunks` (ObjectId → Uint8Array[]). Both are keyed by the hex encoding of
 * the ObjectId (JS Map uses reference equality on objects, so 32-byte keys
 * must be normalised to a primitive string before lookup).
 */
export class InMemoryObjectStore implements ObjectStore {
  private readonly manifests: Map<string, Manifest> = new Map();
  private readonly chunks: Map<string, Uint8Array[]> = new Map();

  has(objectId: Uint8Array): boolean {
    if (!(objectId instanceof Uint8Array) || objectId.length !== NODE_ID_BYTES) {
      return false;
    }
    return this.manifests.has(bytesToHex(objectId));
  }

  list(): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const key of this.manifests.keys()) {
      out.push(hexToBytes(key));
    }
    return out;
  }

  put(manifest: Manifest, chunks: Uint8Array[]): boolean {
    // I20: store operations return booleans; never throw. Wrap validation in
    // try/catch and return false on any structural issue.
    try {
      validateManifest(manifest);
    } catch {
      return false;
    }
    if (!Array.isArray(chunks)) return false;
    // Defensive-copy the chunks so the caller cannot mutate stored data.
    const chunkCopies: Uint8Array[] = [];
    for (const c of chunks) {
      if (!(c instanceof Uint8Array)) return false;
      chunkCopies.push(c.slice());
    }
    const key = bytesToHex(manifest.objectId);
    this.manifests.set(key, manifest);
    this.chunks.set(key, chunkCopies);
    return true;
  }

  getManifest(objectId: Uint8Array): Manifest | null {
    if (!(objectId instanceof Uint8Array) || objectId.length !== NODE_ID_BYTES) {
      return null;
    }
    return this.manifests.get(bytesToHex(objectId)) ?? null;
  }

  getChunks(objectId: Uint8Array): Uint8Array[] | null {
    if (!(objectId instanceof Uint8Array) || objectId.length !== NODE_ID_BYTES) {
      return null;
    }
    const stored = this.chunks.get(bytesToHex(objectId));
    if (stored === undefined) return null;
    // Return defensive copies so callers cannot mutate the store's chunks.
    return stored.map((c) => c.slice());
  }
}

// ─── 4. buildHaveVectorFromStores ──────────────────────────────────────────

/** Options for `buildHaveVectorFromStores`. */
export interface BuildHaveVectorFromStoresOptions {
  /** The descriptor store (from discovery.ts) — source of knownNodes/knownGateways. */
  readonly descriptorStore: DescriptorStore;
  /** The object store — source of knownObjects. */
  readonly objectStore: ObjectStore;
  /** Current time in unix seconds (for expiry filtering of descriptors). */
  readonly now: number;
}

/**
 * Build a `HaveVector` from a `DescriptorStore` and an `ObjectStore`.
 *
 * - `knownNodes`: NodeIds of all NON-EXPIRED NodeDescriptors in the store
 *   (spec §5 freshness rule — expired descriptors MUST NOT be forwarded).
 * - `knownGateways`: NodeIds of all NON-EXPIRED GatewayAdverts (from
 *   `descriptorStore.knownGateways(now)`).
 * - `knownObjects`: all ObjectIds in the object store (from `objectStore.list()`).
 *   Object expiry is per-Manifest and is NOT filtered here — the peer will
 *   request an object by ObjectId, and the responder's `handleSyncRequest`
 *   can choose to refuse expired objects at that point.
 * - `generatedAt`: the supplied `now` value.
 *
 * This is the structured replacement for the audit's `getHaveVector() →
 * emptyList()` (00-AUDIT.md §3.7). It also supersedes the simpler
 * `buildHaveVector` in discovery.ts (which only carried NodeIds, not the full
 * structured vector with gateways and objects) — the discovery.ts version is
 * retained for backward compatibility with tier-2-only exchanges; new code
 * should use this structured form.
 */
export function buildHaveVectorFromStores(
  options: BuildHaveVectorFromStoresOptions,
): HaveVector {
  const { descriptorStore, objectStore, now } = options;

  // knownNodes: active (non-expired) NodeDescriptor NodeIds, deduplicated.
  const activeDescs = descriptorStore.activeNodeDescriptors(now);
  const knownNodes: Uint8Array[] = [];
  const seenNodes = new Set<string>();
  for (const desc of activeDescs) {
    const key = bytesToHex(desc.nodeId);
    if (seenNodes.has(key)) continue;
    seenNodes.add(key);
    knownNodes.push(desc.nodeId);
  }

  // knownGateways: active (non-expired) gateway NodeIds, deduplicated.
  // `knownGateways(now)` already returns non-expired entries.
  const knownGateways: Uint8Array[] = [];
  const seenGateways = new Set<string>();
  for (const gw of descriptorStore.knownGateways(now)) {
    const key = bytesToHex(gw);
    if (seenGateways.has(key)) continue;
    seenGateways.add(key);
    knownGateways.push(gw);
  }

  // knownObjects: all ObjectIds in the CAS, deduplicated (list() should
  // already return unique IDs, but dedup is cheap insurance).
  const knownObjects: Uint8Array[] = [];
  const seenObjects = new Set<string>();
  for (const obj of objectStore.list()) {
    const key = bytesToHex(obj);
    if (seenObjects.has(key)) continue;
    seenObjects.add(key);
    knownObjects.push(obj);
  }

  return {
    knownNodes,
    knownGateways,
    knownObjects,
    generatedAt: now,
  };
}

// ─── 5. SyncRequest / SyncResponse — the anti-entropy exchange ────────────

/**
 * A request from a node to its peer for the objects/descriptors the peer has
 * that the requester lacks.
 *
 * Per spec §5, when two nodes meet they exchange HAVE vectors, then each
 * requests the objects the other has that they lack. The `SyncRequest` is the
 * "I want these, and here's what I can offer" message.
 *
 * CDDL:
 *
 *   SyncRequest = {
 *     "want":            [* bstr .size 32],   ; ObjectIds the requester wants
 *     "offer":           [* bstr .size 32],   ; ObjectIds the requester can offer
 *     "wantDescriptors": [* bstr .size 32],   ; NodeIds whose descriptors the requester wants
 *     "requesterNodeId": bstr .size 32,       ; the requester's NodeId
 *     "generatedAt":     uint
 *   }
 *
 * `want` and `offer` are computed via `computeSyncDiff(localHave, peerHave)`
 * (objects only). `wantDescriptors` is computed separately by diffing the
 * `knownNodes` fields of the two HAVE vectors (the descriptor diff is not
 * part of `computeSyncDiff` because `SyncDiff` is object-only — see its
 * JSDoc).
 *
 * The `offer` field is INFORMATIONAL on this request — it tells the responder
 * what the requester can provide, so the responder can schedule a follow-up
 * request. The responder does NOT act on `offer` in its response (it only
 * satisfies `want` and `wantDescriptors`).
 */
export interface SyncRequest {
  /** ObjectIds the requester wants (from the responder's HAVE that the requester lacks). */
  readonly want: Uint8Array[];
  /** ObjectIds the requester can offer (from the requester's HAVE that the responder lacks). */
  readonly offer: Uint8Array[];
  /** NodeIds whose descriptors the requester wants. */
  readonly wantDescriptors: Uint8Array[];
  /** The requester's NodeId (32 bytes). */
  readonly requesterNodeId: Uint8Array;
  /** When this request was generated (unix seconds). */
  readonly generatedAt: number;
}

/**
 * Encode a `SyncRequest` to canonical SNP-CBOR bytes.
 */
export function encodeSyncRequest(r: SyncRequest): Uint8Array {
  validateSyncRequest(r);
  return cborEncode(
    cborMap([
      ["want", r.want as CborValue[]],
      ["offer", r.offer as CborValue[]],
      ["wantDescriptors", r.wantDescriptors as CborValue[]],
      ["requesterNodeId", r.requesterNodeId],
      ["generatedAt", r.generatedAt],
    ]),
  );
}

/**
 * Decode a `SyncRequest` from canonical SNP-CBOR bytes.
 *
 * Throws `CborError` on malformed input. After a successful decode the
 * returned request is guaranteed to pass `validateSyncRequest`.
 */
export function decodeSyncRequest(bytes: Uint8Array): SyncRequest {
  const value = decodeCbor(bytes, "SyncRequest");
  if (!(value instanceof Map)) {
    throw new CborError(
      `SyncRequest must be a CBOR map; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  const map = value as Map<string | Uint8Array, CborValue>;
  const want = extractBstrArrayValue(map.get("want"), "SyncRequest.want");
  const offer = extractBstrArrayValue(map.get("offer"), "SyncRequest.offer");
  const wantDescriptors = extractBstrArrayValue(
    map.get("wantDescriptors"),
    "SyncRequest.wantDescriptors",
  );
  const requesterNodeId = extractBstr(
    map.get("requesterNodeId"),
    "SyncRequest.requesterNodeId",
  );
  const generatedAt = extractUint(
    map.get("generatedAt"),
    "SyncRequest.generatedAt",
  );
  const r: SyncRequest = {
    want,
    offer,
    wantDescriptors,
    requesterNodeId,
    generatedAt,
  };
  validateSyncRequest(r);
  return r;
}

/** Helper: extract a CBOR array field whose entries are all 32-byte bstrs. */
function extractBstrArrayValue(
  v: CborValue | undefined,
  field: string,
): Uint8Array[] {
  const arr = extractArray(v, field);
  const out: Uint8Array[] = [];
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];
    if (!(item instanceof Uint8Array) || item.length !== NODE_ID_BYTES) {
      throw new CborError(
        `${field}[${i}] must be a ${NODE_ID_BYTES}-byte byte string; got ${describeType(item)}`,
        "MALFORMED",
      );
    }
    out.push(item);
  }
  return out;
}

/**
 * Validate the STRUCTURE of a `SyncRequest`. Throws `CborError(MALFORMED)`
 * on any violation:
 *   - `want`, `offer`, `wantDescriptors` must be arrays of 32-byte Uint8Arrays.
 *   - `requesterNodeId` must be a 32-byte Uint8Array.
 *   - `generatedAt` must be a positive integer.
 */
export function validateSyncRequest(r: SyncRequest): void {
  assertBstrArray(r.want, "SyncRequest.want");
  assertBstrArray(r.offer, "SyncRequest.offer");
  assertBstrArray(r.wantDescriptors, "SyncRequest.wantDescriptors");
  if (
    !(r.requesterNodeId instanceof Uint8Array) ||
    r.requesterNodeId.length !== NODE_ID_BYTES
  ) {
    throw new CborError(
      `SyncRequest.requesterNodeId must be a ${NODE_ID_BYTES}-byte Uint8Array; got ${r.requesterNodeId instanceof Uint8Array ? `${r.requesterNodeId.length} bytes` : typeof r.requesterNodeId}`,
      "MALFORMED",
    );
  }
  if (
    typeof r.generatedAt !== "number" ||
    !Number.isInteger(r.generatedAt) ||
    r.generatedAt <= 0
  ) {
    throw new CborError(
      `SyncRequest.generatedAt must be a positive integer; got ${String(r.generatedAt)}`,
      "MALFORMED",
    );
  }
}

/**
 * A response to a `SyncRequest`, carrying the manifests of the requested
 * objects and the requested descriptors.
 *
 * The response carries MANIFESTS, not chunks. The chunks are fetched in a
 * separate exchange (the requester now knows the ObjectIds and has the
 * manifests, so it can fetch chunks by ObjectId through a chunk-fetch
 * protocol — out of scope for the SyncSession). This keeps the SyncResponse
 * compact even for large objects: a 1 GiB object's manifest is ~1 KiB.
 *
 * `complete` is true iff all wants and wantDescriptors were satisfied. A
 * partial response (`complete: false`) means the responder was missing some
 * of the requested objects/descriptors; the requester can try another peer.
 */
export interface SyncResponse {
  /** Objects sent (manifest + chunk count for each). */
  readonly objects: ReadonlyArray<{
    /** 32-byte ObjectId (Merkle root) — the key under which the manifest is stored. */
    readonly objectId: Uint8Array;
    /** The signed Manifest for this object. */
    readonly manifest: Manifest;
    /** Number of chunks (mirrors `manifest.chunkCount` for fast scanning). */
    readonly chunkCount: number;
  }>;
  /** Descriptors sent. */
  readonly descriptors: NodeDescriptor[];
  /** Whether the response is complete (all wants satisfied) or partial. */
  readonly complete: boolean;
}

/**
 * Encode a `SyncResponse` to canonical SNP-CBOR bytes.
 *
 * Each object in `objects` is encoded as a nested CBOR map:
 *
 *   { "objectId": bstr .size 32, "manifest": ManifestWire, "chunkCount": uint }
 *
 * Each descriptor in `descriptors` is encoded as a `NodeDescriptorWire` nested
 * map. The `complete` field is a CBOR boolean.
 */
export function encodeSyncResponse(r: SyncResponse): Uint8Array {
  validateSyncResponse(r);
  const objectsCbor: CborValue[] = r.objects.map((o) =>
    cborMap([
      ["objectId", o.objectId],
      ["manifest", manifestToWireMap(o.manifest)],
      ["chunkCount", o.chunkCount],
    ]),
  );
  const descriptorsCbor: CborValue[] = r.descriptors.map((d) =>
    nodeDescriptorToWireMap(d),
  );
  return cborEncode(
    cborMap([
      ["objects", objectsCbor],
      ["descriptors", descriptorsCbor],
      ["complete", r.complete],
    ]),
  );
}

/**
 * Decode a `SyncResponse` from canonical SNP-CBOR bytes.
 *
 * Throws `CborError` on malformed input. Each embedded Manifest is validated
 * via `validateManifest`; each embedded NodeDescriptor is structurally
 * validated. Signature verification is NOT performed (it is a separate trust
 * decision made by `applySyncResponse` → `DescriptorStore.addNodeDescriptor`
 * and by the chunk-fetch layer).
 */
export function decodeSyncResponse(bytes: Uint8Array): SyncResponse {
  const value = decodeCbor(bytes, "SyncResponse");
  if (!(value instanceof Map)) {
    throw new CborError(
      `SyncResponse must be a CBOR map; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  const map = value as Map<string | Uint8Array, CborValue>;

  const objectsArr = extractArray(map.get("objects"), "SyncResponse.objects");
  const objects: SyncResponse["objects"][number][] = [];
  for (let i = 0; i < objectsArr.length; i++) {
    const itemMap = extractMap(objectsArr[i], `SyncResponse.objects[${i}]`);
    const objectId = extractBstr(
      itemMap.get("objectId"),
      `SyncResponse.objects[${i}].objectId`,
    );
    const manifestMap = extractMap(
      itemMap.get("manifest"),
      `SyncResponse.objects[${i}].manifest`,
    );
    const manifest = manifestFromWireMap(manifestMap);
    const chunkCount = extractUint(
      itemMap.get("chunkCount"),
      `SyncResponse.objects[${i}].chunkCount`,
    );
    objects.push({ objectId, manifest, chunkCount });
  }

  const descsArr = extractArray(
    map.get("descriptors"),
    "SyncResponse.descriptors",
  );
  const descriptors: NodeDescriptor[] = [];
  for (let i = 0; i < descsArr.length; i++) {
    const descMap = extractMap(descsArr[i], `SyncResponse.descriptors[${i}]`);
    descriptors.push(nodeDescriptorFromWireMap(descMap));
  }

  const complete = extractBool(map.get("complete"), "SyncResponse.complete");
  const r: SyncResponse = { objects, descriptors, complete };
  validateSyncResponse(r);
  return r;
}

/**
 * Validate the STRUCTURE of a `SyncResponse`. Throws `CborError(MALFORMED)`
 * on any violation:
 *   - `objects` must be an array of `{ objectId: 32-byte bstr, manifest: Manifest, chunkCount: positive int }`.
 *     Each manifest is validated via `validateManifest`.
 *   - `descriptors` must be an array of NodeDescriptors. Each descriptor is
 *     structurally validated (NodeId/pubkey lengths, capabilities non-empty,
 *     protoVersion === "SNP/0.1", signature length, etc.).
 *   - `complete` must be a boolean.
 */
export function validateSyncResponse(r: SyncResponse): void {
  if (!Array.isArray(r.objects)) {
    throw new CborError(
      `SyncResponse.objects must be an array; got ${describeType(r.objects as unknown as CborValue)}`,
      "MALFORMED",
    );
  }
  for (let i = 0; i < r.objects.length; i++) {
    const o = r.objects[i];
    if (o === null || typeof o !== "object") {
      throw new CborError(
        `SyncResponse.objects[${i}] must be an object`,
        "MALFORMED",
      );
    }
    if (
      !(o.objectId instanceof Uint8Array) ||
      o.objectId.length !== NODE_ID_BYTES
    ) {
      throw new CborError(
        `SyncResponse.objects[${i}].objectId must be a ${NODE_ID_BYTES}-byte Uint8Array`,
        "MALFORMED",
      );
    }
    // validateManifest throws CborError(MALFORMED) on structural issues.
    validateManifest(o.manifest);
    if (
      typeof o.chunkCount !== "number" ||
      !Number.isInteger(o.chunkCount) ||
      o.chunkCount <= 0
    ) {
      throw new CborError(
        `SyncResponse.objects[${i}].chunkCount must be a positive integer; got ${String(o.chunkCount)}`,
        "MALFORMED",
      );
    }
    if (o.chunkCount !== o.manifest.chunkCount) {
      throw new CborError(
        `SyncResponse.objects[${i}].chunkCount (${o.chunkCount}) must equal manifest.chunkCount (${o.manifest.chunkCount})`,
        "MALFORMED",
      );
    }
  }
  if (!Array.isArray(r.descriptors)) {
    throw new CborError(
      `SyncResponse.descriptors must be an array; got ${describeType(r.descriptors as unknown as CborValue)}`,
      "MALFORMED",
    );
  }
  // Structural validation of each descriptor is performed by
  // nodeDescriptorFromWireMap during decode. For a SyncResponse constructed
  // in-memory (not decoded), we do a lightweight shape check here.
  for (let i = 0; i < r.descriptors.length; i++) {
    const d = r.descriptors[i];
    if (d === null || typeof d !== "object") {
      throw new CborError(
        `SyncResponse.descriptors[${i}] must be a NodeDescriptor`,
        "MALFORMED",
      );
    }
    if (!(d.nodeId instanceof Uint8Array) || d.nodeId.length !== NODE_ID_BYTES) {
      throw new CborError(
        `SyncResponse.descriptors[${i}].nodeId must be a ${NODE_ID_BYTES}-byte Uint8Array`,
        "MALFORMED",
      );
    }
    if (
      !(d.nodePubKey instanceof Uint8Array) ||
      d.nodePubKey.length !== ED25519_PUBLIC_KEY_BYTES
    ) {
      throw new CborError(
        `SyncResponse.descriptors[${i}].nodePubKey must be a ${ED25519_PUBLIC_KEY_BYTES}-byte Uint8Array`,
        "MALFORMED",
      );
    }
    if (
      !(d.signature instanceof Uint8Array) ||
      d.signature.length !== ED25519_SIGNATURE_BYTES
    ) {
      throw new CborError(
        `SyncResponse.descriptors[${i}].signature must be a ${ED25519_SIGNATURE_BYTES}-byte Uint8Array`,
        "MALFORMED",
      );
    }
  }
  if (typeof r.complete !== "boolean") {
    throw new CborError(
      `SyncResponse.complete must be a boolean; got ${typeof r.complete}`,
      "MALFORMED",
    );
  }
}

// ─── 6. computeSyncDiff — the anti-entropy decision ────────────────────────

/**
 * The diff between two HAVE vectors, from the LOCAL node's perspective.
 *
 * - `localWants`: ObjectIds the remote has that the local lacks — these are
 *   what the local node should REQUEST from the remote.
 * - `localOffers`: ObjectIds the local has that the remote lacks — these are
 *   what the local node can OFFER to the remote.
 *
 * The diff is OBJECT-ONLY (it diffs `knownObjects`). Descriptor diffs
 * (`knownNodes`) are handled separately in `SyncSession.buildSyncRequest`,
 * because the `SyncRequest` has a dedicated `wantDescriptors` field for
 * NodeIds. Mixing ObjectIds and NodeIds in a single diff output would be
 * ambiguous (both are 32-byte bstrs).
 */
export interface SyncDiff {
  /** What the local node should request from the remote. */
  readonly localWants: Uint8Array[];
  /** What the local node can offer to the remote. */
  readonly localOffers: Uint8Array[];
}

/**
 * Compute the anti-entropy diff between two HAVE vectors.
 *
 * Given `localHave` and `remoteHave`, returns:
 *   - `localWants`: ObjectIds in `remoteHave.knownObjects` but NOT in
 *     `localHave.knownObjects`.
 *   - `localOffers`: ObjectIds in `localHave.knownObjects` but NOT in
 *     `remoteHave.knownObjects`.
 *
 * Both outputs are deduplicated (a peer MAY send a HAVE vector with duplicate
 * ObjectIds; the diff tolerates this via set membership).
 *
 * The diff is symmetric: if A computes `computeSyncDiff(aHave, bHave)`, then
 * B computes `computeSyncDiff(bHave, aHave)`, and A's `localWants` equals B's
 * `localOffers` (and vice versa). This is the anti-entropy invariant: each
 * side's wants are the other side's offers.
 */
export function computeSyncDiff(
  localHave: HaveVector,
  remoteHave: HaveVector,
): SyncDiff {
  // Validate both inputs (throws CborError(MALFORMED) on structural issues).
  validateHaveVector(localHave);
  validateHaveVector(remoteHave);

  const localSet = new Set(localHave.knownObjects.map(bytesToHex));
  const remoteSet = new Set(remoteHave.knownObjects.map(bytesToHex));

  const localWants: Uint8Array[] = [];
  const wantSeen = new Set<string>();
  for (const obj of remoteHave.knownObjects) {
    const key = bytesToHex(obj);
    if (localSet.has(key)) continue; // local already has it
    if (wantSeen.has(key)) continue; // dedup (peer may have sent duplicates)
    wantSeen.add(key);
    localWants.push(obj);
  }

  const localOffers: Uint8Array[] = [];
  const offerSeen = new Set<string>();
  for (const obj of localHave.knownObjects) {
    const key = bytesToHex(obj);
    if (remoteSet.has(key)) continue; // remote already has it
    if (offerSeen.has(key)) continue; // dedup
    offerSeen.add(key);
    localOffers.push(obj);
  }

  return { localWants, localOffers };
}

// ─── 7. ModeABundle — store-and-forward custody object ────────────────────

/**
 * A Mode A bundle — the custody object for store-carry-forward.
 *
 * Per 01-ARCHITECTURE.md §2.1 L5: "store-carry-forward, bundle custody". Mode
 * A bundles (from gateway.ts `TransitRequest` / `TransitResponse`) are
 * carried by sync nodes across the mesh. A node receives a bundle, holds it
 * in its `BundleStore`, and forwards it when it next meets a peer closer to
 * a gateway (for requests) or closer to the requester (for responses).
 *
 * The `custodyChain` records every NodeId that has held the bundle, in order.
 * This is the audit trail for store-carry-forward: at any point, anyone can
 * inspect the chain to see which nodes carried the bundle. The chain is
 * APPEND-ONLY (I15) — `appendCustodyHop` returns a NEW bundle with the hop
 * appended; it never mutates the input. This prevents a malicious relay from
 * rewriting the chain to hide its involvement or to frame another node.
 *
 * The `deadline` is taken from the TransitRequest.deadline. Past the
 * deadline, the bundle is expired and MUST NOT be forwarded (the gateway
 * would reject the request anyway). `isBundleExpired(bundle, now)` checks
 * this; `BundleStore.pruneExpired(now)` removes expired bundles.
 *
 * `delivered` is set to true once the response has been delivered to the
 * requester (for response bundles) or once the request has been delivered to
 * a gateway (for request bundles). A delivered bundle is not forwarded again.
 *
 * CDDL:
 *
 *   ModeABundle = {
 *     "request":      TransitRequestWire,
 *     "response":     TransitResponseWire / null,
 *     "custodyChain": [* bstr .size 32],   ; NodeIds, in custody order
 *     "createdAt":    uint,
 *     "deadline":     uint,
 *     "delivered":    bool
 *   }
 */
export interface ModeABundle {
  /** The TransitRequest being carried. */
  readonly request: TransitRequest;
  /** The TransitResponse, if one has been received. Null while in transit. */
  readonly response: TransitResponse | null;
  /** Custody chain: NodeIds that have held this bundle, in order. Each 32 bytes. */
  readonly custodyChain: Uint8Array[];
  /** When the bundle was created (unix seconds). */
  readonly createdAt: number;
  /** Bundle deadline (from the TransitRequest.deadline). */
  readonly deadline: number;
  /** Whether this bundle has been delivered to the requester. */
  readonly delivered: boolean;
}

/**
 * Encode a `ModeABundle` to canonical SNP-CBOR bytes.
 */
export function encodeModeABundle(b: ModeABundle): Uint8Array {
  validateModeABundle(b);
  const responseWire: CborValue =
    b.response === null ? null : transitResponseToWireMap(b.response);
  return cborEncode(
    cborMap([
      ["request", transitRequestToWireMap(b.request)],
      ["response", responseWire],
      ["custodyChain", b.custodyChain as CborValue[]],
      ["createdAt", b.createdAt],
      ["deadline", b.deadline],
      ["delivered", b.delivered],
    ]),
  );
}

/**
 * Decode a `ModeABundle` from canonical SNP-CBOR bytes.
 *
 * Throws `CborError` on malformed input. The embedded TransitRequest (and
 * TransitResponse, if present) are validated via their respective
 * `validate*` functions. Signature verification is NOT performed (it is a
 * separate trust decision made by the gateway when it acts on the request).
 */
export function decodeModeABundle(bytes: Uint8Array): ModeABundle {
  const value = decodeCbor(bytes, "ModeABundle");
  if (!(value instanceof Map)) {
    throw new CborError(
      `ModeABundle must be a CBOR map; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  const map = value as Map<string | Uint8Array, CborValue>;
  const requestMap = extractMap(map.get("request"), "ModeABundle.request");
  const request = transitRequestFromWireMap(requestMap);
  const responseRaw = map.get("response");
  const response: TransitResponse | null =
    responseRaw === null || responseRaw === undefined
      ? null
      : transitResponseFromWireMap(
          extractMap(responseRaw, "ModeABundle.response"),
        );
  const custodyChain = extractBstrArrayValue(
    map.get("custodyChain"),
    "ModeABundle.custodyChain",
  );
  const createdAt = extractUint(map.get("createdAt"), "ModeABundle.createdAt");
  const deadline = extractUint(map.get("deadline"), "ModeABundle.deadline");
  const delivered = extractBool(map.get("delivered"), "ModeABundle.delivered");
  const b: ModeABundle = {
    request,
    response,
    custodyChain,
    createdAt,
    deadline,
    delivered,
  };
  validateModeABundle(b);
  return b;
}

/**
 * Validate the STRUCTURE of a `ModeABundle`. Throws `CborError(MALFORMED)`
 * on any violation:
 *   - `request` is a valid TransitRequest (validated via `validateTransitRequest`).
 *   - `response` is null or a valid TransitResponse (validated via `validateTransitResponse`).
 *   - `custodyChain` is an array of 32-byte Uint8Arrays.
 *   - `createdAt` is a positive integer.
 *   - `deadline` is a positive integer ≥ `createdAt` (the deadline cannot be
 *     before the bundle was created).
 *   - `delivered` is a boolean.
 *   - If `response` is non-null, `response.reqId` MUST equal `request.reqId`
 *     (a response must correspond to its request).
 */
export function validateModeABundle(b: ModeABundle): void {
  // request: validateTransitRequest throws CborError(MALFORMED) on issues.
  validateTransitRequest(b.request);
  // response: null or valid TransitResponse.
  if (b.response !== null) {
    validateTransitResponse(b.response);
    // A response must correspond to its request (same reqId).
    if (!bytesEqual(b.response.reqId, b.request.reqId)) {
      throw new CborError(
        "ModeABundle.response.reqId must equal ModeABundle.request.reqId",
        "MALFORMED",
      );
    }
  }
  assertBstrArray(b.custodyChain, "ModeABundle.custodyChain");
  if (
    typeof b.createdAt !== "number" ||
    !Number.isInteger(b.createdAt) ||
    b.createdAt <= 0
  ) {
    throw new CborError(
      `ModeABundle.createdAt must be a positive integer; got ${String(b.createdAt)}`,
      "MALFORMED",
    );
  }
  if (
    typeof b.deadline !== "number" ||
    !Number.isInteger(b.deadline) ||
    b.deadline <= 0
  ) {
    throw new CborError(
      `ModeABundle.deadline must be a positive integer; got ${String(b.deadline)}`,
      "MALFORMED",
    );
  }
  if (b.deadline < b.createdAt) {
    throw new CborError(
      `ModeABundle.deadline (${b.deadline}) must be >= createdAt (${b.createdAt})`,
      "MALFORMED",
    );
  }
  // The deadline should also be >= request.deadline, but we tolerate a bundle
  // whose deadline was clamped by an earlier custodian (defensive — the
  // request's own deadline is the authoritative one).
  if (typeof b.delivered !== "boolean") {
    throw new CborError(
      `ModeABundle.delivered must be a boolean; got ${typeof b.delivered}`,
      "MALFORMED",
    );
  }
}

/**
 * Check whether a bundle has expired (past its deadline).
 *
 * @param bundle  the bundle to check
 * @param now     current time in unix seconds
 * @returns       true iff `now >= bundle.deadline`
 */
export function isBundleExpired(bundle: ModeABundle, now: number): boolean {
  return now >= bundle.deadline;
}

/**
 * Append a custody hop to a bundle, returning a NEW bundle (immutable update).
 *
 * Per I15, the custody chain is append-only. This function does NOT mutate
 * the input `bundle`; it returns a new `ModeABundle` with the
 * `custodianNodeId` appended to `custodyChain`. All other fields are copied
 * as-is.
 *
 * @param bundle          the bundle to append to (NOT mutated)
 * @param custodianNodeId 32-byte NodeId of the node taking custody
 * @returns               a new ModeABundle with the hop appended
 * @throws CborError(MALFORMED) if `custodianNodeId` is not a 32-byte Uint8Array
 */
export function appendCustodyHop(
  bundle: ModeABundle,
  custodianNodeId: Uint8Array,
): ModeABundle {
  if (
    !(custodianNodeId instanceof Uint8Array) ||
    custodianNodeId.length !== NODE_ID_BYTES
  ) {
    throw new CborError(
      `custodianNodeId must be a ${NODE_ID_BYTES}-byte Uint8Array; got ${custodianNodeId instanceof Uint8Array ? `${custodianNodeId.length} bytes` : typeof custodianNodeId}`,
      "MALFORMED",
    );
  }
  // Immutable update: copy the custody chain and append. The original bundle
  // is unchanged (I15).
  return {
    ...bundle,
    custodyChain: [...bundle.custodyChain, custodianNodeId],
  };
}

// ─── 8. BundleStore — holds Mode A bundles for store-carry-forward ─────────

/**
 * Holds `ModeABundle`s for store-carry-forward.
 *
 * When a node receives a Mode A bundle (from a peer or from a local client),
 * it adds the bundle to its `BundleStore`. The bundle stays in the store
 * until one of:
 *   - The bundle is forwarded to another peer (the peer's BundleStore now
 *     holds it; the local store MAY keep a copy for redundancy, but typically
 *     drops it to save space — `markDelivered` + `pruneExpired` handle this).
 *   - The bundle is delivered (to a gateway for requests, or to the requester
 *     for responses) — `markDelivered` sets `delivered: true`.
 *   - The bundle expires — `pruneExpired(now)` removes it.
 *
 * `pending(now)` returns all non-expired, undelivered bundles — these are the
 * candidates for forwarding when the node next meets a peer.
 *
 * Custody-chain freshness: when `add` is called with a bundle whose `reqId`
 * already exists in the store, the store keeps the "more advanced" bundle
 * (longer custody chain, or has a response when the existing doesn't, or is
 * marked delivered). This prevents a peer from regressing a bundle by sending
 * an older copy. It also ensures that once a response is received, the
 * response-bearing bundle is not overwritten by a response-less one.
 */
export class BundleStore {
  /** reqId (hex) → bundle. Keyed by the 16-byte reqId of the TransitRequest. */
  private readonly bundles: Map<string, ModeABundle> = new Map();

  /**
   * Add a bundle to the store. If a bundle with the same `reqId` already
   * exists, the more-advanced one is kept (see class JSDoc).
   *
   * Throws `CborError(MALFORMED)` if the bundle is structurally invalid
   * (callers wrapping peer-supplied bundles in an anti-entropy loop should
   * catch and drop on failure — I20's "never throw for peer-supplied input"
   * applies at the loop boundary, not inside the store).
   */
  add(bundle: ModeABundle): void {
    validateModeABundle(bundle); // throws CborError(MALFORMED) on invalid
    const key = bytesToHex(bundle.request.reqId);
    const existing = this.bundles.get(key);
    if (existing === undefined) {
      this.bundles.set(key, bundle);
      return;
    }
    // Keep the more-advanced bundle.
    this.bundles.set(key, this.moreAdvanced(existing, bundle));
  }

  /**
   * Get the bundle for a given reqId, or null if not present.
   *
   * @param reqId  16-byte reqId of the TransitRequest
   */
  get(reqId: Uint8Array): ModeABundle | null {
    if (!(reqId instanceof Uint8Array) || reqId.length !== REQ_ID_BYTES) {
      return null;
    }
    return this.bundles.get(bytesToHex(reqId)) ?? null;
  }

  /**
   * All non-expired, undelivered bundles — the candidates for custody
   * forwarding. Callers iterate this list when they meet a peer and forward
   * each bundle to a peer closer to its destination.
   *
   * @param now  current time in unix seconds
   */
  pending(now: number): ModeABundle[] {
    const out: ModeABundle[] = [];
    for (const b of this.bundles.values()) {
      if (b.delivered) continue;
      if (isBundleExpired(b, now)) continue;
      out.push(b);
    }
    return out;
  }

  /**
   * Mark a bundle as delivered (to a gateway for requests, or to the
   * requester for responses). A delivered bundle is not forwarded again.
   *
   * If the bundle is not in the store, this is a no-op.
   *
   * @param reqId  16-byte reqId of the TransitRequest
   */
  markDelivered(reqId: Uint8Array): void {
    if (!(reqId instanceof Uint8Array) || reqId.length !== REQ_ID_BYTES) {
      return;
    }
    const key = bytesToHex(reqId);
    const existing = this.bundles.get(key);
    if (existing === undefined) return;
    // Immutable update: replace with a new bundle that has delivered=true.
    // The original bundle object is not mutated (I15).
    this.bundles.set(key, { ...existing, delivered: true });
  }

  /**
   * Remove all expired bundles from the store. Returns the count removed.
   *
   * @param now  current time in unix seconds
   * @returns    number of bundles removed
   */
  pruneExpired(now: number): number {
    let removed = 0;
    for (const [key, b] of this.bundles) {
      if (isBundleExpired(b, now)) {
        this.bundles.delete(key);
        removed++;
      }
    }
    return removed;
  }

  // ─── Private helpers ──────────────────────────────────────────────────

  /**
   * Returns the "more advanced" of two bundles (for custody-chain freshness).
   *
   * Ordering (first wins):
   *   1. A delivered bundle beats an undelivered one.
   *   2. A bundle with a response beats one without.
   *   3. A bundle with a longer custody chain beats one with a shorter chain.
   *   4. Ties broken by later `createdAt`.
   *
   * This prevents a peer from regressing a bundle (e.g. sending an older copy
   * with a shorter chain, or a response-less copy after a response was
   * received).
   */
  private moreAdvanced(a: ModeABundle, b: ModeABundle): ModeABundle {
    if (a.delivered && !b.delivered) return a;
    if (b.delivered && !a.delivered) return b;
    if (a.response !== null && b.response === null) return a;
    if (b.response !== null && a.response === null) return b;
    if (a.custodyChain.length > b.custodyChain.length) return a;
    if (b.custodyChain.length > a.custodyChain.length) return b;
    return b.createdAt >= a.createdAt ? b : a;
  }
}

// ─── 9. SyncSession — a single anti-entropy exchange with a peer ──────────

/**
 * A single anti-entropy exchange with one peer.
 *
 * Lifecycle (per peer encounter, after the L8 Noise_IK handshake):
 *
 *   const session = new SyncSession(localNodeId, objectStore, descriptorStore, bundleStore);
 *   const localHave = session.buildLocalHaveVector(now);
 *   // send localHave to peer; receive peerHave
 *   const request = session.buildSyncRequest(peerHave, now);
 *   // send request to peer; receive response
 *   session.applySyncResponse(response);
 *   // later: fetch chunks for pending objects (out of scope for SyncSession)
 *
 * The session is stateful: it tracks pending manifests (objects whose
 * manifests were received via sync but whose chunks have not yet been
 * fetched). Callers drain `pendingObjectIds()` and `getPendingManifest()` to
 * drive a chunk-fetch exchange.
 *
 * L5 contract: the session carries Class A objects (manifests) and
 * NodeDescriptors, and it forwards Mode A bundles via the `BundleStore`. It
 * does NOT interpret transit payloads — it does not fetch URLs, it does not
 * open circuits, it does not inspect the content of objects. It only moves
 * content-addressed objects between stores.
 */
export class SyncSession {
  private readonly localNodeId: Uint8Array;
  private readonly objectStore: ObjectStore;
  private readonly descriptorStore: DescriptorStore;
  private readonly bundleStore: BundleStore;

  /**
   * Manifests received via sync but whose chunks have not yet been fetched.
   * Keyed by hex(objectId). Callers drain this via `pendingObjectIds()` and
   * `getPendingManifest()` to drive a chunk-fetch exchange, then call
   * `commitPendingObject()` to move the object into the ObjectStore once
   * chunks are available.
   */
  private readonly pendingManifests: Map<string, Manifest> = new Map();

  constructor(
    localNodeId: Uint8Array,
    objectStore: ObjectStore,
    descriptorStore: DescriptorStore,
    bundleStore: BundleStore,
  ) {
    if (
      !(localNodeId instanceof Uint8Array) ||
      localNodeId.length !== NODE_ID_BYTES
    ) {
      throw new Error(
        `SyncSession.localNodeId must be a ${NODE_ID_BYTES}-byte Uint8Array; got ${localNodeId instanceof Uint8Array ? `${localNodeId.length} bytes` : typeof localNodeId}`,
      );
    }
    this.localNodeId = localNodeId;
    this.objectStore = objectStore;
    this.descriptorStore = descriptorStore;
    this.bundleStore = bundleStore;
  }

  /**
   * Generate our HAVE vector to send to the peer.
   *
   * Builds a `HaveVector` from the local DescriptorStore (active descriptors +
   * gateways) and ObjectStore (all ObjectIds). The vector is a SUMMARY — it
   * lists hashes, not the objects themselves.
   *
   * @param now  current time in unix seconds (for descriptor expiry filtering)
   */
  buildLocalHaveVector(now: number): HaveVector {
    return buildHaveVectorFromStores({
      descriptorStore: this.descriptorStore,
      objectStore: this.objectStore,
      now,
    });
  }

  /**
   * Given the peer's HAVE vector, build a SyncRequest.
   *
   * Computes:
   *   - `want`: ObjectIds the peer has that local lacks (from `computeSyncDiff`).
   *   - `offer`: ObjectIds local has that the peer lacks (from `computeSyncDiff`).
   *   - `wantDescriptors`: NodeIds the peer has descriptors for that local lacks
   *     (diff of `knownNodes`).
   *   - `requesterNodeId`: this node's NodeId.
   *   - `generatedAt`: `now`.
   *
   * @param peerHave  the peer's HAVE vector
   * @param now       current time in unix seconds
   */
  buildSyncRequest(peerHave: HaveVector, now: number): SyncRequest {
    validateHaveVector(peerHave);
    const localHave = this.buildLocalHaveVector(now);
    const diff = computeSyncDiff(localHave, peerHave);

    // Descriptor diff: NodeIds the peer has that local lacks. This is
    // separate from the object diff because `SyncDiff` is object-only.
    const localNodeSet = new Set(localHave.knownNodes.map(bytesToHex));
    const wantDescriptors: Uint8Array[] = [];
    const descSeen = new Set<string>();
    for (const nodeId of peerHave.knownNodes) {
      const key = bytesToHex(nodeId);
      if (localNodeSet.has(key)) continue; // local already has it
      if (descSeen.has(key)) continue; // dedup
      descSeen.add(key);
      wantDescriptors.push(nodeId);
    }

    return {
      want: diff.localWants,
      offer: diff.localOffers,
      wantDescriptors,
      requesterNodeId: this.localNodeId,
      generatedAt: now,
    };
  }

  /**
   * Handle a peer's SyncRequest: produce a SyncResponse with the objects they
   * want that we have, and the descriptors they want that we have.
   *
   * For each ObjectId in `request.want`:
   *   - Look up the manifest in our ObjectStore. If present, include it in
   *     the response (manifest + chunkCount).
   *   - If absent, skip (the response will be partial).
   *
   * For each NodeId in `request.wantDescriptors`:
   *   - Look up the descriptor in our DescriptorStore. If present and
   *     NON-EXPIRED, include it in the response.
   *   - If absent or expired, skip.
   *
   * `complete` is true iff all wants and wantDescriptors were satisfied.
   *
   * @param request  the peer's SyncRequest (validated; throws CborError on invalid)
   * @param now      current time in unix seconds (for descriptor expiry filtering)
   */
  handleSyncRequest(request: SyncRequest, now: number): SyncResponse {
    validateSyncRequest(request);

    const objects: SyncResponse["objects"][number][] = [];
    for (const objectId of request.want) {
      const manifest = this.objectStore.getManifest(objectId);
      if (manifest === null) continue; // we don't have it
      objects.push({
        objectId,
        manifest,
        chunkCount: manifest.chunkCount,
      });
    }

    const descriptors: NodeDescriptor[] = [];
    for (const nodeId of request.wantDescriptors) {
      const desc = this.descriptorStore.getNodeDescriptor(nodeId);
      if (desc === null) continue; // we don't have it
      if (isExpired(desc, now)) continue; // expired — don't forward (spec §5)
      descriptors.push(desc);
    }

    const complete =
      objects.length === request.want.length &&
      descriptors.length === request.wantDescriptors.length;

    return { objects, descriptors, complete };
  }

  /**
   * Apply a peer's SyncResponse to our local stores.
   *
   * For each descriptor in `response.descriptors`:
   *   - Add it to the DescriptorStore via `addNodeDescriptor(desc, desc.nodePubKey)`.
   *     The descriptor is SELF-ATTESTING (it carries its own nodePubKey and
   *     signature); the store verifies the signature and the I4 NodeId↔pubkey
   *     binding. The `peerPublicKey` parameter to addNodeDescriptor is
   *     defensive (per discovery.ts JSDoc: "it is not used to verify the
   *     descriptor; the descriptor is self-attesting via its own nodePubKey")
   *     — we pass `desc.nodePubKey` to satisfy the API and match the semantics.
   *
   * For each object in `response.objects`:
   *   - If we already have the object (objectStore.has(objectId)), skip.
   *   - Otherwise, record the manifest in `pendingManifests`. The chunks are
   *     NOT in the response — the caller must fetch them via a separate
   *     chunk-fetch exchange and then call `commitPendingObject()` to move
   *     the object into the ObjectStore.
   *
   * This method does NOT verify object signatures (the manifest's signature
   * is verified by the ObjectStore when chunks are committed via
   * `commitPendingObject` → `objectStore.put`, or by a separate verification
   * step the caller may insert). Descriptor signatures ARE verified (inside
   * `addNodeDescriptor`).
   */
  applySyncResponse(response: SyncResponse): void {
    // Apply descriptors — self-attesting, signature-verified by the store.
    for (const desc of response.descriptors) {
      // addNodeDescriptor returns false on bad sig / expired / invalid; we
      // don't propagate the failure (the descriptor was either accepted or
      // dropped for a good reason). I20: never throws.
      this.descriptorStore.addNodeDescriptor(desc, desc.nodePubKey);
    }
    // Apply objects — record manifests in pendingManifests; chunks need a
    // separate fetch.
    for (const obj of response.objects) {
      if (this.objectStore.has(obj.objectId)) continue; // already have it
      // Record the manifest for later chunk-fetch. Overwrites any prior
      // pending manifest for the same objectId (idempotent — the manifest is
      // content-addressed, so two copies are identical).
      this.pendingManifests.set(bytesToHex(obj.objectId), obj.manifest);
    }
  }

  /**
   * The ObjectIds of manifests received via sync but whose chunks have not
   * yet been fetched. Callers iterate this to drive a chunk-fetch exchange.
   */
  pendingObjectIds(): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const key of this.pendingManifests.keys()) {
      out.push(hexToBytes(key));
    }
    return out;
  }

  /**
   * Get the pending manifest for an ObjectId, or null if not pending.
   *
   * @param objectId  32-byte ObjectId
   */
  getPendingManifest(objectId: Uint8Array): Manifest | null {
    if (
      !(objectId instanceof Uint8Array) ||
      objectId.length !== NODE_ID_BYTES
    ) {
      return null;
    }
    return this.pendingManifests.get(bytesToHex(objectId)) ?? null;
  }

  /**
   * Commit a pending object: store its manifest + chunks in the ObjectStore
   * and remove it from the pending queue.
   *
   * Callers call this after fetching the chunks for a pending object. The
   * ObjectStore.put will validate the manifest structurally (via
   * validateManifest); the caller is responsible for verifying the manifest's
   * signature against the publisher's public key (out of scope for L5 — the
   * publisher's key is in their NodeDescriptor, which the DescriptorStore
   * holds after `applySyncResponse`).
   *
   * @param objectId  32-byte ObjectId of the pending object
   * @param chunks    raw chunk bytes, in order (matching manifest.chunks)
   * @returns         true iff the object was committed (pending + put succeeded);
   *                  false if the object was not pending or put failed
   */
  commitPendingObject(objectId: Uint8Array, chunks: Uint8Array[]): boolean {
    if (
      !(objectId instanceof Uint8Array) ||
      objectId.length !== NODE_ID_BYTES
    ) {
      return false;
    }
    const key = bytesToHex(objectId);
    const manifest = this.pendingManifests.get(key);
    if (manifest === undefined) return false; // not pending
    const ok = this.objectStore.put(manifest, chunks);
    if (ok) {
      this.pendingManifests.delete(key);
    }
    return ok;
  }
}
