/**
 * SNP Cryptography — Ed25519 + X25519 over RAW 32-byte keys
 *
 * Source: 02-PROTOCOL-SPEC.md §1.2 "Cryptographic primitives (locked)"
 * Source: 00-AUDIT.md §3.1 (the bug this replaces)
 *
 * The audit's headline finding: the existing `TinkCryptoProvider` derives
 * "Ed25519 public keys" as `sha256(handle.toString())`, signs with an
 * unrelated random key, and throws on every verify call — so no signature
 * made on one device has ever verified on another.
 *
 * This module uses `@noble/ed25519` and `@noble/curves` which operate on
 * raw 32-byte Ed25519 secret keys and 32-byte public keys. There is no
 * KeysetHandle, no Tink, no opaque handle. Every key is bytes that round-trip
 * byte-exactly across implementations (I3).
 *
 * @ invariant I3 — Ed25519 uses raw 32-byte public keys on the wire
 * @ invariant I20 — a stub in a security-critical path throws; never permissive
 */

import * as ed25519 from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { sha512, sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  X25519_PUBLIC_KEY_BYTES,
  AEAD_KEY_BYTES,
  AEAD_NONCE_BYTES,
} from "./constants";
import { signingPreimage, type SigContextName } from "./hashing";
import type { CborValue } from "./cbor";

// @noble/ed25519 v3 needs the user to supply a SHA-512 implementation.
// We use the one from @noble/hashes. Set both the sync (`hashes.sha512`)
// and async (`hashes.sha512Async`) slots.
ed25519.hashes.sha512 = sha512;
ed25519.hashes.sha512Async = async (message: Uint8Array) => sha512(message);

// ─── Ed25519 keypair ───────────────────────────────────────────────────────

export interface Ed25519Keypair {
  /** 32-byte Ed25519 secret key (the seed). */
  secretKey: Uint8Array;
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
}

/**
 * Generate a new Ed25519 keypair from cryptographic randomness.
 * The secret key is the 32-byte seed; the public key is derived from it
 * deterministically.
 */
export function generateEd25519Keypair(): Ed25519Keypair {
  const secretKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

/**
 * Derive the Ed25519 public key from a 32-byte secret key.
 * Deterministic — the same secret always yields the same public key.
 */
export function deriveEd25519Public(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${secretKey.length}`,
    );
  }
  return ed25519.getPublicKey(secretKey);
}

// ─── Ed25519 sign / verify ─────────────────────────────────────────────────

/**
 * Sign a SNP structure. The signature is over `SIG_CONTEXT ‖ CBOR(payload)`.
 *
 * @param secretKey     32-byte Ed25519 secret key
 * @param contextName   which SIG_CONTEXT applies (prevents cross-structure
 *                      signature confusion — see audit §1.1)
 * @param payloadCbor   the CBOR-encodable payload (signature field omitted)
 */
export function sign(
  secretKey: Uint8Array,
  contextName: SigContextName,
  payloadCbor: CborValue,
): Uint8Array {
  if (secretKey.length !== 32) {
    throw new Error(
      `Ed25519 secret key must be 32 bytes; got ${secretKey.length}`,
    );
  }
  const preimage = signingPreimage(contextName, payloadCbor);
  return ed25519.sign(preimage, secretKey);
}

/**
 * Verify a SNP signature. Returns true ONLY if the signature is valid.
 *
 * CRITICAL: this returns `false` on any failure. It NEVER throws for a bad
 * signature, and it NEVER returns `true` just because the signature is the
 * right length. This is the direct fix for audit finding 00-AUDIT.md §3.9:
 *
 *   FakeCryptoProvider.verify(...) => signature.size == 64
 *
 * which accepted any 64 bytes as a valid signature.
 *
 * @param publicKey   32-byte Ed25519 public key (NOT a NodeId — NodeId is a hash)
 * @param contextName which SIG_CONTEXT applies
 * @param payloadCbor the CBOR-encodable payload (signature field omitted)
 * @param signature   64-byte Ed25519 signature
 */
export function verify(
  publicKey: Uint8Array,
  contextName: SigContextName,
  payloadCbor: CborValue,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  const preimage = signingPreimage(contextName, payloadCbor);
  try {
    return ed25519.verify(signature, preimage, publicKey);
  } catch {
    return false;
  }
}

/**
 * Verify a signature over a RAW preimage (already-encoded SIG_CONTEXT ‖ CBOR).
 * Used by the conformance runner when we want to test that a captured preimage
 * from another implementation verifies.
 */
export function verifyPreimage(
  publicKey: Uint8Array,
  preimage: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    return ed25519.verify(signature, preimage, publicKey);
  } catch {
    return false;
  }
}

// ─── X25519 (for Noise_IK handshake and RendezvousIdentity) ────────────────

export interface X25519Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateX25519Keypair(): X25519Keypair {
  const secretKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

/**
 * X25519 scalar multiplication (DH). Used in the Noise_IK handshake.
 * Returns 32 raw shared-secret bytes; the caller passes these through HKDF.
 */
export function x25519SharedSecret(
  secretKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  if (secretKey.length !== 32 || peerPublicKey.length !== 32) {
    throw new Error("X25519 keys must be 32 bytes");
  }
  return x25519.getSharedSecret(secretKey, peerPublicKey);
}

// ─── ChaCha20-Poly1305 AEAD (RFC 8439) ─────────────────────────────────────
//
// Source: 02-PROTOCOL-SPEC.md §1.2 — "AEAD: ChaCha20-Poly1305 (RFC 8439),
// 12-byte nonce". Used for Class B transit frame encryption and link-layer
// frame encryption after the handshake establishes keys.
//
// This is the AEAD that was previously a TODO in EstablishedLink. Per the
// hardening audit (Blocker A): "No one should implement a real network
// adapter on top of EstablishedLink yet" until AEAD is wired in. This module
// provides the primitive; link.ts wires it into the frame path.

export interface AeadSealed {
  /** The ciphertext (same length as plaintext for ChaCha20). */
  ciphertext: Uint8Array;
  /** The 16-byte Poly1305 authentication tag, appended to ciphertext on the wire. */
  tag: Uint8Array;
}

/**
 * Encrypt plaintext under ChaCha20-Poly1305.
 *
 * @param key       32-byte AEAD key (from HKDF in the handshake)
 * @param nonce     12-byte nonce — MUST be unique per key. For link frames,
 *                  the nonce is `fid ‖ seq` (per spec §7.3). For circuits,
 *                  the nonce is `fid ‖ seq` with rekey every 2^20 frames.
 * @param plaintext the data to encrypt
 * @param aad       additional authenticated data (authenticated but not encrypted;
 *                  e.g. the frame header for Class B transit)
 * @returns         ciphertext + 16-byte tag
 */
export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): AeadSealed {
  if (key.length !== AEAD_KEY_BYTES) {
    throw new Error(`AEAD key must be ${AEAD_KEY_BYTES} bytes; got ${key.length}`);
  }
  if (nonce.length !== AEAD_NONCE_BYTES) {
    throw new Error(`AEAD nonce must be ${AEAD_NONCE_BYTES} bytes; got ${nonce.length}`);
  }
  // @noble/ciphers API: chacha20poly1305(key, nonce, aad?) returns a cipher
  // object with .encrypt(plaintext). The AAD is passed at cipher creation.
  const cipher = chacha20poly1305(key, nonce, aad);
  // .encrypt() returns ciphertext || tag (16 bytes appended).
  const sealed = cipher.encrypt(plaintext);
  const ciphertext = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);
  return { ciphertext, tag };
}

/**
 * Decrypt and authenticate a ChaCha20-Poly1305 ciphertext.
 *
 * Returns `null` on authentication failure (NEVER throws for a bad tag —
 * per I20, security-critical verification must not throw on failure).
 *
 * @param key        32-byte AEAD key
 * @param nonce      12-byte nonce
 * @param ciphertext the ciphertext (without tag)
 * @param tag        16-byte Poly1305 tag
 * @param aad        additional authenticated data (must match encryption AAD)
 * @returns          plaintext, or null if authentication fails
 */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): Uint8Array | null {
  if (key.length !== AEAD_KEY_BYTES) return null;
  if (nonce.length !== AEAD_NONCE_BYTES) return null;
  if (tag.length !== 16) return null;
  try {
    // @noble/ciphers API: chacha20poly1305(key, nonce, aad?) returns a cipher
    // object with .decrypt(ciphertext). The AAD is passed at cipher creation.
    const cipher = chacha20poly1305(key, nonce, aad);
    // Reconstruct ciphertext || tag for @noble/ciphers.
    const sealed = new Uint8Array(ciphertext.length + tag.length);
    sealed.set(ciphertext, 0);
    sealed.set(tag, ciphertext.length);
    return cipher.decrypt(sealed);
  } catch {
    return null;
  }
}

/**
 * Build a 12-byte AEAD nonce from a flow ID and sequence number.
 * Per spec §7.3: "Nonce = fid ‖ seq; strictly monotonic."
 *
 * The flow ID is 8 bytes; the sequence number is encoded as a 4-byte
 * big-endian unsigned integer in the low 4 bytes of the nonce. This
 * means seq can range 0..2^32-1 before rekeying is required (spec §7.3
 * says rekey every 2^20 frames, well within this range).
 */
export function aeadNonce(fid: Uint8Array, seq: number): Uint8Array {
  if (fid.length !== 8) {
    throw new Error(`Flow ID must be 8 bytes for AEAD nonce; got ${fid.length}`);
  }
  if (seq < 0 || seq > 0xffffffff) {
    throw new Error(`Sequence number must fit in uint32 for AEAD nonce; got ${seq}`);
  }
  const nonce = new Uint8Array(AEAD_NONCE_BYTES);
  nonce.set(fid, 0);
  // 4-byte big-endian seq in bytes [8..11]
  nonce[8] = (seq >>> 24) & 0xff;
  nonce[9] = (seq >>> 16) & 0xff;
  nonce[10] = (seq >>> 8) & 0xff;
  nonce[11] = seq & 0xff;
  return nonce;
}

/**
 * Constant-time comparison of two byte arrays. Used for tag comparison
 * in AEAD verification (though @noble/ciphers already does this internally;
 * this is exposed for callers that need to compare tags manually).
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

// ─── Deterministic test keypairs ───────────────────────────────────────────
//
// The conformance suite MUST use deterministic keys so that vectors are
// reproducible and stable across runs. These seed-derived keys are NOT for
// production. They exist so vectors have real Ed25519 signatures that
// verify against published public keys.

const TEST_SEEDS: Record<string, Uint8Array> = {
  alice: hexToBytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  ),
  bob: hexToBytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  ),
  gateway: hexToBytes(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
  ),
  relay: hexToBytes(
    "f5e5d7e0e8a34b8c6f2a1d9e7b3f5c8d4a6e2b8f1d3c5e7a9b0d2f4c6e8a1b3d",
  ),
  carol: hexToBytes(
    "0d4d4e0d70b8b1ff5e1c5b3e1a0f3d2c4b6a8e0d2f4c6b8a0d2e4f6a8b0c2d4e",
  ),
  dave: hexToBytes(
    "3b8a4c6e0d2f4a6b8c0e2d4f6a8b0c2e4d6f8a0b2c4e6d8f0a2b4c6e8d0f2a4b",
  ),
  publisher: hexToBytes(
    "e7b3a1c5d9e0f2b4a6c8d0e2f4b6a8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2",
  ),
};

export type TestKeyName = keyof typeof TEST_SEEDS;

/** Get a deterministic test keypair by name. For conformance vectors only. */
export function testKeypair(name: TestKeyName): Ed25519Keypair {
  const seed = TEST_SEEDS[name];
  if (!seed) throw new Error(`Unknown test key: ${name}`);
  return {
    secretKey: seed.slice(),
    publicKey: ed25519.getPublicKey(seed),
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`Hex string has odd length: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

export { AEAD_KEY_BYTES, AEAD_NONCE_BYTES };
