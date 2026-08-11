/**
 * SNP Manifest — content-addressed object envelope
 *
 * Source: 02-PROTOCOL-SPEC.md §3.4 "Manifest"
 * Source: 00-AUDIT.md §3 (the bugs this structure fixes)
 *
 * A Manifest is a signed statement that binds:
 *
 *   - a content-addressed ObjectId (the Merkle root of the object's chunks),
 *   - the ordered list of chunk hashes,
 *   - a chunkCount (NEW — binds the leaf count, audit fix),
 *   - the total byte size and MIME type,
 *   - a traffic class,
 *   - the publisher's NodeId,
 *   - a publication time and optional expiry,
 *
 * under a single Ed25519 signature by the publisher's key, over the SIG_CONTEXT
 * `"SNP/0.1 manifest\0"`.
 *
 * CDDL (02-PROTOCOL-SPEC.md §3.4):
 *
 *   Manifest = {
 *     objectId:     bstr .size 32,    ; merkle_root(chunks)
 *     chunks:       [+ bstr .size 32],
 *     chunkCount:   uint,             ; NEW — binds leaf count
 *     totalBytes:   uint,
 *     mimeType:     tstr,
 *     class:        tstr,             ; "content"|"app"|"model"|"dataset"|"transit-response"
 *     publisherId:  bstr .size 32,    ; NodeId of publisher
 *     publishedAt:  uint,             ; unix seconds
 *     expiresAt:    uint / null,
 *     signature:    bstr .size 64     ; by publisher's Ed25519 key
 *   }
 *
 * The `chunkCount` field is the direct fix for the audit's "Manifest did not
 * bind leaf count" finding (00-AUDIT.md §3.4): without it, an attacker could
 * strip trailing chunks and still produce a manifest whose Merkle root
 * verified against the (now-shorter) leaf set, because the root is computed
 * recursively and a tree's root does not encode its leaf count.
 * `validateManifest` enforces `chunkCount === chunks.length` and is the
 * function that catches this attack.
 *
 * @ invariant I1 — All signed structures use SNP-CBOR with length-first key ordering
 * @ invariant I2 — Every signature is over SIG_CONTEXT ‖ CBOR(payload)
 * @ invariant I3 — Ed25519 uses raw 32-byte public keys on the wire (publisherId is a NodeId, never a bare key)
 * @ invariant I19 — NEVER reference a Fake* class
 * @ invariant I20 — a stub in a security-critical path throws; never permissive
 */

import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  SIG_CONTEXTS,
} from "./constants";
import { type CborValue, CborError, cborMap } from "./cbor";
import { sign, verify } from "./crypto";
import { merkleRoot, leafHash } from "./merkle";

// ─── Types ─────────────────────────────────────────────────────────────────

/**
 * The allowed values for `Manifest.class`. These are the traffic classes of
 * content the network carries; they determine routing priority, custody
 * policy, and replication factor (see 01-ARCHITECTURE.md §4 and
 * 05-CIVIC-CONTENT-CONSISTENCY.md).
 */
export const MANIFEST_CLASSES = [
  "content",
  "app",
  "model",
  "dataset",
  "transit-response",
] as const;
export type ManifestClass = (typeof MANIFEST_CLASSES)[number];

/**
 * A complete Manifest — the signed, content-addressed object envelope.
 *
 * All `bstr` fields are `Uint8Array` (never hex strings on the wire — I3).
 * `expiresAt` may be `null` for content with no expiry.
 */
export interface Manifest {
  /** 32-byte Merkle root of the chunks (ObjectId). */
  readonly objectId: Uint8Array;
  /** Ordered list of 32-byte chunk hashes. MUST be non-empty. */
  readonly chunks: Uint8Array[];
  /** Number of chunks. MUST equal `chunks.length` (audit fix). */
  readonly chunkCount: number;
  /** Total size of the original object in bytes. */
  readonly totalBytes: number;
  /** MIME type, e.g. "application/octet-stream". */
  readonly mimeType: string;
  /** Traffic class — one of MANIFEST_CLASSES. */
  readonly class: ManifestClass;
  /** NodeId (32 bytes) of the publisher. NOT a bare public key. */
  readonly publisherId: Uint8Array;
  /** Publication time, unix seconds. */
  readonly publishedAt: number;
  /** Expiry time, unix seconds, or null for no expiry. */
  readonly expiresAt: number | null;
  /** 64-byte Ed25519 signature by the publisher's key. */
  readonly signature: Uint8Array;
}

/**
 * Fields of a Manifest, excluding the signature. This is what gets signed.
 * Useful as the input type to `signManifest` and `buildManifest`.
 */
export type ManifestUnsigned = Omit<Manifest, "signature">;

// ─── CBOR preimage ─────────────────────────────────────────────────────────

/**
 * Build the canonical CBOR preimage map for a Manifest, EXCLUDING the
 * `signature` field. This is the structure that gets fed to `sign` /
 * `verify` under SIG_CONTEXT `"manifest"`.
 *
 * The map uses STRING keys; canonical ordering is applied at encode time
 * (length-first on the fully-encoded key — see cbor.ts). Callers MUST pass
 * this map (or the equivalent Manifest) to `sign`/`verify`; never re-encode
 * by hand.
 *
 * @param manifest  the Manifest (or unsigned Manifest fields). The
 *                  `signature` field is ignored even if present.
 */
export function manifestToCborMap(
  manifest: Manifest | ManifestUnsigned,
): Map<string | Uint8Array, CborValue> {
  return cborMap([
    ["objectId", manifest.objectId],
    ["chunks", manifest.chunks as CborValue[]],
    ["chunkCount", manifest.chunkCount],
    ["totalBytes", manifest.totalBytes],
    ["mimeType", manifest.mimeType],
    ["class", manifest.class],
    ["publisherId", manifest.publisherId],
    ["publishedAt", manifest.publishedAt],
    ["expiresAt", manifest.expiresAt as CborValue],
  ]);
}

// ─── Sign / verify ─────────────────────────────────────────────────────────

/**
 * Sign a Manifest using the publisher's Ed25519 secret key.
 *
 * The signature is over `SIG_CONTEXTS.manifest ‖ CBOR(manifest without signature)`,
 * per invariant I2. The `signature` field is NOT part of the signed preimage.
 *
 * @param manifestWithoutSig  the Manifest fields WITHOUT a signature
 * @param publisherSecretKey  32-byte Ed25519 secret key of the publisher
 * @returns                   64-byte Ed25519 signature
 */
export function signManifest(
  manifestWithoutSig: ManifestUnsigned,
  publisherSecretKey: Uint8Array,
): Uint8Array {
  if (publisherSecretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${publisherSecretKey.length}`,
    );
  }
  // Validate the structure before signing so we never produce a signature
  // over malformed input.
  validateManifest({ ...manifestWithoutSig, signature: new Uint8Array(ED25519_SIGNATURE_BYTES) });
  const preimage = manifestToCborMap(manifestWithoutSig);
  return sign(publisherSecretKey, "manifest", preimage);
}

/**
 * Verify a Manifest's signature.
 *
 * Re-derives the preimage (the manifest with the `signature` field removed)
 * and calls `verify(publisherPubKey, "manifest", preimage, signature)`.
 *
 * Returns `false` on any failure — bad signature, wrong key length,
 * malformed fields. NEVER throws for a bad signature. This is the direct
 * fix for the audit's "FakeCryptoProvider.verify => signature.size == 64"
 * pattern (00-AUDIT.md §3.9, invariant I20).
 *
 * Note: this function verifies ONLY the signature. It does NOT check that
 * `objectId === merkleRoot(chunks)` — that is a content-integrity check
 * performed by `validateManifest` and by the chunk-delivery layer. The two
 * checks are deliberately separate: signature verification is cheap and
 * can be done on gossip; content-integrity verification is done when the
 * chunks are actually fetched.
 *
 * @param manifest         the complete Manifest to verify
 * @param publisherPubKey  32-byte Ed25519 public key of the publisher
 *                         (NOT a NodeId — NodeId is a hash, see identity.ts)
 * @returns                true iff the signature is valid
 */
export function verifyManifest(
  manifest: Manifest,
  publisherPubKey: Uint8Array,
): boolean {
  if (publisherPubKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (manifest.signature.length !== ED25519_SIGNATURE_BYTES) return false;
  // Structural sanity: never feed garbage to the verifier.
  try {
    validateManifest(manifest);
  } catch {
    return false;
  }
  const preimage = manifestToCborMap(manifest);
  return verify(publisherPubKey, "manifest", preimage, manifest.signature);
}

// ─── Builder ───────────────────────────────────────────────────────────────

/**
 * Options for `buildManifest`. The caller supplies the raw chunks and the
 * metadata; `buildManifest` computes `objectId`, `chunkCount`, and
 * `totalBytes` automatically and signs the result.
 */
export interface BuildManifestOptions {
  /** Raw chunk bytes, in order. The caller is responsible for chunking. */
  readonly chunks: Uint8Array[];
  /** MIME type of the reassembled object. */
  readonly mimeType: string;
  /** Traffic class — one of MANIFEST_CLASSES. */
  readonly class: ManifestClass;
  /** 32-byte NodeId of the publisher (NOT a bare public key). */
  readonly publisherId: Uint8Array;
  /** Publication time, unix seconds. */
  readonly publishedAt: number;
  /** Expiry time, unix seconds, or null for no expiry. */
  readonly expiresAt: number | null;
  /** 32-byte Ed25519 secret key of the publisher. */
  readonly publisherSecretKey: Uint8Array;
}

/**
 * Build a complete, signed Manifest from raw chunks and metadata.
 *
 * Computes:
 *   - `objectId`  = `merkleRoot(chunks.map(leafHash))`  (RFC 6962 root)
 *   - `chunkCount` = `chunks.length`
 *   - `totalBytes` = sum of `chunks[i].length`
 *
 * Then signs the result with the publisher's secret key under SIG_CONTEXT
 * `"manifest"`. Returns the complete Manifest including the 64-byte signature.
 *
 * @param opts  chunks, metadata, and publisher secret key
 * @returns     a complete signed Manifest
 */
export function buildManifest(opts: BuildManifestOptions): Manifest {
  if (opts.chunks.length === 0) {
    throw new CborError(
      "Manifest requires at least one chunk; got empty array",
      "MALFORMED",
    );
  }
  // Compute leaf hashes and the Merkle root.
  const leafHashes = opts.chunks.map(leafHash);
  const objectId = merkleRoot(leafHashes);
  let totalBytes = 0;
  for (const c of opts.chunks) totalBytes += c.length;

  const unsigned: ManifestUnsigned = {
    objectId,
    chunks: leafHashes,
    chunkCount: opts.chunks.length,
    totalBytes,
    mimeType: opts.mimeType,
    class: opts.class,
    publisherId: opts.publisherId,
    publishedAt: opts.publishedAt,
    expiresAt: opts.expiresAt,
  };
  const signature = signManifest(unsigned, opts.publisherSecretKey);
  return { ...unsigned, signature };
}

// ─── Structural validation ─────────────────────────────────────────────────

/**
 * Validate the STRUCTURE of a Manifest against the CDDL constraints.
 *
 * This is the function that catches the audit's `chunkCount ≠ leaf count`
 * attack (00-AUDIT.md §3.4). Without `chunkCount`, an attacker who strips
 * trailing chunks from an object can still produce a manifest whose Merkle
 * root verifies against the shorter leaf set — because RFC 6962's recursive
 * split rule means the root of a prefix of a tree is sometimes equal to the
 * root of the full tree. Binding `chunkCount` and requiring
 * `chunkCount === chunks.length` defeats this attack.
 *
 * Throws `CborError` with code `"MALFORMED"` on any violation. Does NOT
 * verify the signature (use `verifyManifest` for that) and does NOT
 * re-derive the Merkle root (the chunk-delivery layer does that).
 *
 * Checks:
 *   1. `objectId` is a 32-byte Uint8Array.
 *   2. `chunks` is a non-empty array of 32-byte Uint8Arrays.
 *   3. `chunkCount === chunks.length`            ← audit fix
 *   4. `totalBytes` is a non-negative integer.
 *   5. `mimeType` is a string.
 *   6. `class` is one of MANIFEST_CLASSES.
 *   7. `publisherId` is a 32-byte Uint8Array.
 *   8. `publishedAt` is a non-negative integer.
 *   9. `expiresAt` is null or a positive integer strictly greater than `publishedAt`.
 *  10. `signature` is a 64-byte Uint8Array.
 *
 * @param manifest  the Manifest to validate
 * @throws CborError  with code "MALFORMED" on any structural violation
 */
export function validateManifest(manifest: Manifest): void {
  // 1. objectId
  if (!(manifest.objectId instanceof Uint8Array) || manifest.objectId.length !== 32) {
    throw new CborError(
      "Manifest.objectId must be a 32-byte Uint8Array (Merkle root)",
      "MALFORMED",
    );
  }

  // 2. chunks: non-empty array of 32-byte bstrs
  if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
    throw new CborError(
      "Manifest.chunks must be a non-empty array of 32-byte Uint8Arrays",
      "MALFORMED",
    );
  }
  for (let i = 0; i < manifest.chunks.length; i++) {
    const c = manifest.chunks[i];
    if (!(c instanceof Uint8Array) || c.length !== 32) {
      throw new CborError(
        `Manifest.chunks[${i}] must be a 32-byte Uint8Array; got length ${c?.length ?? "non-Uint8Array"}`,
        "MALFORMED",
      );
    }
  }

  // 3. chunkCount — THE audit fix.
  if (!Number.isInteger(manifest.chunkCount) || manifest.chunkCount < 1) {
    throw new CborError(
      "Manifest.chunkCount must be a positive integer",
      "MALFORMED",
    );
  }
  if (manifest.chunkCount !== manifest.chunks.length) {
    throw new CborError(
      `Manifest.chunkCount (${manifest.chunkCount}) must equal chunks.length (${manifest.chunks.length}) — leaf-count binding (audit fix 00-AUDIT.md §3.4)`,
      "MALFORMED",
    );
  }

  // 4. totalBytes
  if (!Number.isInteger(manifest.totalBytes) || manifest.totalBytes < 0) {
    throw new CborError(
      "Manifest.totalBytes must be a non-negative integer",
      "MALFORMED",
    );
  }

  // 5. mimeType
  if (typeof manifest.mimeType !== "string" || manifest.mimeType.length === 0) {
    throw new CborError(
      "Manifest.mimeType must be a non-empty string",
      "MALFORMED",
    );
  }

  // 6. class
  if (typeof manifest.class !== "string" || !MANIFEST_CLASSES.includes(manifest.class as ManifestClass)) {
    throw new CborError(
      `Manifest.class must be one of [${MANIFEST_CLASSES.join(", ")}]; got "${manifest.class}"`,
      "MALFORMED",
    );
  }

  // 7. publisherId
  if (!(manifest.publisherId instanceof Uint8Array) || manifest.publisherId.length !== 32) {
    throw new CborError(
      "Manifest.publisherId must be a 32-byte Uint8Array (NodeId, not a bare key)",
      "MALFORMED",
    );
  }

  // 8. publishedAt
  if (!Number.isInteger(manifest.publishedAt) || manifest.publishedAt < 0) {
    throw new CborError(
      "Manifest.publishedAt must be a non-negative integer (unix seconds)",
      "MALFORMED",
    );
  }

  // 9. expiresAt
  if (manifest.expiresAt !== null) {
    if (!Number.isInteger(manifest.expiresAt) || manifest.expiresAt <= 0) {
      throw new CborError(
        "Manifest.expiresAt must be null or a positive integer (unix seconds)",
        "MALFORMED",
      );
    }
    if (manifest.expiresAt <= manifest.publishedAt) {
      throw new CborError(
        `Manifest.expiresAt (${manifest.expiresAt}) must be strictly greater than publishedAt (${manifest.publishedAt})`,
        "MALFORMED",
      );
    }
  }

  // 10. signature
  if (
    !(manifest.signature instanceof Uint8Array) ||
    manifest.signature.length !== ED25519_SIGNATURE_BYTES
  ) {
    throw new CborError(
      `Manifest.signature must be a ${ED25519_SIGNATURE_BYTES}-byte Uint8Array`,
      "MALFORMED",
    );
  }
}
