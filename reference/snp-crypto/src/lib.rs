//! SNP-CRYPTO — Cryptographic primitives for ShareNet 2.0
//!
//! Implements the SNP/0.1 cryptographic stack (per `02-PROTOCOL-SPEC.md` §3):
//! - **Ed25519** for signatures (raw 32-byte public keys on the wire — I3)
//! - **X25519** for ephemeral-static Diffie-Hellman in the Noise_IK handshake
//! - **SHA-256** as the universal hash (NodeIds, Merkle leaves, transcript hashes)
//! - **HKDF-SHA256** for key derivation in Noise_IK and circuit keys
//! - **ChaCha20-Poly1305** as the AEAD for L8 frames and L6/L7 circuits
//!
//! This is the Rust equivalent of `/src/lib/snp/crypto.ts` plus
//! `/src/lib/snp/hashing.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference (built on
//! @noble/ed25519, @noble/curves, @noble/hashes per ADR-0002) is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/02-hashing.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from SNP cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("signature verification failed")]
    BadSignature,
    /// AEAD decryption failed (bad tag, wrong key, truncated input, …).
    #[error("AEAD decryption failed")]
    BadAead,
    /// HKDF was called with an invalid info or length.
    #[error("invalid HKDF parameter: {0}")]
    InvalidHkdf(String),
    /// A raw byte buffer had the wrong length for its intended use.
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length supplied.
        actual: usize,
    },
}

/// Convenience `Result` alias.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// A 32-byte Ed25519 secret key.
pub type SecretKey = [u8; 32];
/// A 32-byte Ed25519 / X25519 public key (raw form on the wire, per I3).
pub type PublicKey = [u8; 32];
/// A 64-byte Ed25519 signature.
pub type Signature = [u8; 64];
/// A 32-byte symmetric key (HKDF output, ChaCha20-Poly1305 key).
pub type SymmetricKey = [u8; 32];
/// A 12-byte ChaCha20-Poly1305 nonce.
pub type Nonce = [u8; 12];

/// An Ed25519 key pair: secret key + derived public key.
///
/// A real implementation will derive `zeroize::ZeroizeOnDrop` once the
/// `zeroize` crate is added as a dependency. It is omitted from the skeleton
/// to keep the workspace dependency list focused on protocol primitives.
#[derive(Debug, Clone)]
pub struct Keypair {
    /// The 32-byte secret key.
    pub secret: SecretKey,
    /// The 32-byte public key.
    pub public: PublicKey,
}

// === Hashing (SHA-256) ===

/// Compute `SHA-256(data)`.
pub fn sha256(_data: &[u8]) -> [u8; 32] {
    todo!("Implement SHA-256 via the `sha2` crate")
}

/// Compute `SHA-256(domain_sep || data)` — the SNP domain-separated hash.
///
/// SNP/0.1 §1 mandates that every hash used in a NodeId, Merkle leaf, or
/// transcript be domain-separated by prefixing a fixed tag.
pub fn domain_hash(_domain: &[u8], _data: &[u8]) -> [u8; 32] {
    todo!("Implement domain-separated SHA-256 (domain || data)")
}

// === Ed25519 ===

/// Generate a new Ed25519 keypair using the supplied CSPRNG.
pub fn ed25519_keygen() -> Keypair {
    todo!("Generate an Ed25519 keypair using `ed25519-dalek` + `rand_core`")
}

/// Derive the 32-byte public key from a 32-byte secret key.
pub fn ed25519_derive_public(_secret: &SecretKey) -> PublicKey {
    todo!("Derive Ed25519 public key via `ed25519-dalek`")
}

/// Sign `message` with `secret`. Returns a 64-byte raw signature.
///
/// Per I2, signed structures in SNP are over `SIG_CONTEXT || CBOR(payload)`.
/// This function signs raw bytes; callers are responsible for prefixing the
/// context.
pub fn ed25519_sign(_secret: &SecretKey, _message: &[u8]) -> Signature {
    todo!("Sign with Ed25519 via `ed25519-dalek`")
}

/// Verify an Ed25519 signature.
pub fn ed25519_verify(_public: &PublicKey, _message: &[u8], _signature: &Signature) -> CryptoResult<()> {
    todo!("Verify an Ed25519 signature via `ed25519-dalek`")
}

// === X25519 ===

/// Generate a new X25519 keypair (for Noise_IK ephemeral keys).
pub fn x25519_keygen() -> Keypair {
    todo!("Generate an X25519 keypair via `x25519-dalek`")
}

/// Compute the X25519 shared secret between `our_secret` and `their_public`.
///
/// Returns a 32-byte raw shared secret. Callers MUST feed this into HKDF
/// before using it as a symmetric key.
pub fn x25519_dh(_our_secret: &SecretKey, _their_public: &PublicKey) -> [u8; 32] {
    todo!("Compute X25519 DH via `x25519-dalek`")
}

// === HKDF-SHA256 ===

/// HKDF-Extract using SHA-256.
pub fn hkdf_extract(_salt: &[u8], _ikm: &[u8]) -> [u8; 32] {
    todo!("Implement HKDF-Extract-SHA256 via the `hkdf` crate")
}

/// HKDF-Expand using SHA-256.
pub fn hkdf_expand(_prk: &[u8; 32], _info: &[u8], _length: usize) -> CryptoResult<Vec<u8>> {
    todo!("Implement HKDF-Expand-SHA256 via the `hkdf` crate")
}

// === ChaCha20-Poly1305 ===

/// Encrypt `plaintext` with ChaCha20-Poly1305. Returns ciphertext ‖ 16-byte tag.
pub fn aead_encrypt(
    _key: &SymmetricKey,
    _nonce: &Nonce,
    _aad: &[u8],
    _plaintext: &[u8],
) -> Vec<u8> {
    todo!("Encrypt with ChaCha20-Poly1305 via the `chacha20poly1305` crate")
}

/// Decrypt a ChaCha20-Poly1305 ciphertext (ciphertext ‖ 16-byte tag).
///
/// # Errors
/// Returns [`CryptoError::BadAead`] if the tag does not verify.
pub fn aead_decrypt(
    _key: &SymmetricKey,
    _nonce: &Nonce,
    _aad: &[u8],
    _ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    todo!("Decrypt with ChaCha20-Poly1305 via the `chacha20poly1305` crate")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/02-hashing.json (domain_hash, NodeId
        // derivation, HKDF outputs) and a future 02-crypto.json for
        // Ed25519/X25519/ChaCha20-Poly1305 deterministic test vectors.
        let _ = CryptoError::BadSignature;
    }
}
