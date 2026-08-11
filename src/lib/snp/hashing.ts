/**
 * SNP Hashing primitives
 *
 * Source: 02-PROTOCOL-SPEC.md §1.1 (domain separation) and §1.2 (SHA-256, HKDF).
 *
 * All SNP signatures are over `SIG_CONTEXT ‖ CBOR(payload)`. This module
 * centralises that construction so every signature site is forced through
 * the same domain-separated hashing path. See invariant I2.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf.js";
import { SIG_CONTEXTS, type SigContextName, NODE_ID_CONTEXT } from "./constants";
import type { CborValue } from "./cbor";
import { encode as cborEncode } from "./cbor";

export type { SigContextName };

/** Convert an ASCII string to a Uint8Array (no multi-byte surprises). */
function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) {
      throw new Error(`ASCII context string contains non-ASCII byte at index ${i}: ${s}`);
    }
    out[i] = c;
  }
  return out;
}

/** SHA-256 of arbitrary bytes. */
export function hashSha256(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * The signing pre-image for a signed SNP structure: `SIG_CONTEXT ‖ CBOR(payload)`.
 * This is THE function every signer and verifier must use. Bypassing it is a
 * conformance failure (I2).
 *
 * @param contextName  which SIG_CONTEXT to use (see constants.SIG_CONTEXTS)
 * @param payload      the CBOR-encodable payload (typically the structure with
 *                     the `signature` field omitted or set to empty bytes)
 * @returns            the bytes that get fed to Ed25519.sign / Ed25519.verify
 */
export function signingPreimage(
  contextName: SigContextName,
  payload: CborValue,
): Uint8Array {
  const context = asciiBytes(SIG_CONTEXTS[contextName]);
  const cborBytes = cborEncode(payload);
  const out = new Uint8Array(context.length + cborBytes.length);
  out.set(context, 0);
  out.set(cborBytes, context.length);
  return out;
}

/**
 * HKDF-SHA256. Used for key derivation in the Noise_IK handshake and for
 * deriving circuit AEAD keys from the Noise output.
 *
 * @param ikm    input keying material
 * @param salt   salt (may be empty)
 * @param info   context/application-specific info string
 * @param length number of bytes to derive (<= 255 * 32)
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const prk = hkdfExtract(sha256, ikm, salt);
  return hkdfExpand(sha256, prk, info, length);
}

/**
 * Derive a NodeId from an Ed25519 public key.
 *
 * `NodeId := SHA-256("SNP/0.1 node\0" ‖ ed25519_public_key)[0..32]`
 *
 * NodeId is a HASH of the key, not the key itself (I4). The bare key is
 * disclosed only during the Noise_IK handshake. This is the fix for the
 * current repository where `NodeId.bytes` *is* the public key — a
 * permanent, unrevocable, network-wide correlator.
 */
export function deriveNodeId(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes; got ${publicKey.length}`,
    );
  }
  const context = asciiBytes(NODE_ID_CONTEXT);
  const input = new Uint8Array(context.length + publicKey.length);
  input.set(context, 0);
  input.set(publicKey, context.length);
  return sha256(input);
}

/**
 * Compute the RFC 6962 empty-tree root.
 *   empty_root = SHA-256("SNP/0.1 empty\0")
 * Used by the Merkle module when the leaf set is empty.
 */
export function merkleEmptyRoot(): Uint8Array {
  return sha256(asciiBytes("SNP/0.1 empty\0"));
}
