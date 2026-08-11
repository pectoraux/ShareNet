//! SNP-OBJECT — Content-addressed objects for ShareNet 2.0
//!
//! Implements the SNP/0.1 content layer (per `02-PROTOCOL-SPEC.md` §4):
//! - **Gear CDC chunking** with frozen constants (target 8 KiB, min 2 KiB,
//!   max 64 KiB). Boundary logic MUST NOT change without an ADR.
//! - **RFC 6962 Merkle trees** with `\x00` (leaf) and `\x01` (intermediate)
//!   prefixes, no odd-node duplication, `chunkCount` bound into the root.
//! - **Content-addressed storage (CAS)** keyed by `SHA-256`.
//! - **Manifests** — the signed envelope that binds an object's metadata,
//!   chunk list, and Merkle root.
//!
//! This is the Rust equivalent of `/src/lib/snp/chunking.ts` +
//! `/src/lib/snp/merkle.ts` + `/src/lib/snp/manifest.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/04-chunking.json`,
//! `/public/conformance/vectors/05-merkle.json`, and
//! `/public/conformance/vectors/06-manifest.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the SNP content layer.
#[derive(Debug, Error)]
pub enum ObjectError {
    /// A chunk referenced by a manifest was not present in the CAS.
    #[error("missing chunk: {0}")]
    MissingChunk(String),
    /// A Merkle proof failed verification.
    #[error("invalid Merkle proof")]
    InvalidProof,
    /// A manifest signature failed verification.
    #[error("invalid manifest signature")]
    InvalidSignature,
    /// A CAS key did not match the stored bytes.
    #[error("CAS key mismatch: expected {expected}, got {actual}")]
    CasMismatch {
        /// Expected SHA-256 (hex).
        expected: String,
        /// Actual SHA-256 (hex).
        actual: String,
    },
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
}

/// Convenience `Result` alias.
pub type ObjectResult<T> = Result<T, ObjectError>;

/// A 32-byte content hash (SHA-256 of a chunk, leaf, or root).
pub type ContentHash = [u8; 32];

/// Frozen chunking constants — changing these breaks every ObjectId.
///
/// See `/public/spec/02-PROTOCOL-SPEC.md` §4.1 and ADRs in
/// `/public/docs/adr/` before modifying.
pub mod chunk_constants {
    /// Minimum chunk size in bytes (2 KiB).
    pub const MIN_CHUNK: usize = 2 * 1024;
    /// Target average chunk size in bytes (8 KiB).
    pub const TARGET_CHUNK: usize = 8 * 1024;
    /// Maximum chunk size in bytes (64 KiB).
    pub const MAX_CHUNK: usize = 64 * 1024;
    /// Gear CDC hash window size.
    pub const GEAR_WINDOW: usize = 64;
}

/// A chunked object's metadata.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Publisher's NodeId.
    pub publisher: [u8; 32],
    /// Content type (e.g. `"application/octet-stream"`).
    pub content_type: String,
    /// Total object size in bytes.
    pub size: u64,
    /// Chunk hashes in order.
    pub chunks: Vec<ContentHash>,
    /// RFC 6962 Merkle root with `chunkCount` bound in.
    pub merkle_root: ContentHash,
    /// Optional content encryption key (for encrypted objects).
    pub encryption_key: Option<[u8; 32]>,
}

/// Split `data` into chunks using Gear CDC with frozen constants.
///
/// Returns the chunk bytes in order. The Merkle root over these chunks is the
/// `ObjectId` of the resulting object.
pub fn chunk(_data: &[u8]) -> Vec<Vec<u8>> {
    todo!("Implement Gear CDC chunking with frozen constants")
}

/// Compute the Merkle leaf hash for a single chunk: `SHA-256(0x00 || chunk)`.
pub fn merkle_leaf(_chunk: &[u8]) -> ContentHash {
    todo!("Implement RFC 6962 leaf hash: SHA-256(0x00 || chunk)")
}

/// Compute the Merkle internal hash for two children:
/// `SHA-256(0x01 || left || right)`.
pub fn merkle_internal(_left: &ContentHash, _right: &ContentHash) -> ContentHash {
    todo!("Implement RFC 6962 internal hash: SHA-256(0x01 || left || right)")
}

/// Compute the Merkle root of a list of chunks, binding `chunkCount` per
/// SNP/0.1 §4.2 (no odd-node duplication).
pub fn merkle_root(_chunks: &[Vec<u8>]) -> ContentHash {
    todo!("Compute the RFC 6962 Merkle root with chunkCount binding")
}

/// Build a Merkle inclusion proof for the chunk at `index`.
pub fn merkle_proof(_chunks: &[Vec<u8>], _index: usize) -> ObjectResult<MerkleProof> {
    todo!("Build an RFC 6962 inclusion proof")
}

/// Verify a Merkle inclusion proof against a known root.
pub fn merkle_verify(
    _root: &ContentHash,
    _leaf: &ContentHash,
    _index: usize,
    _total: usize,
    _proof: &MerkleProof,
) -> ObjectResult<()> {
    todo!("Verify an RFC 6962 inclusion proof")
}

/// A Merkle inclusion proof (list of sibling hashes, with left/right flags).
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Sibling hashes, in order from leaf to root.
    pub siblings: Vec<(Side, ContentHash)>,
}

/// Whether a sibling sits to the left or right of the path node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is on the left.
    Left,
    /// Sibling is on the right.
    Right,
}

/// A content-addressed store: SHA-256 key → bytes.
pub trait Cas: Send + Sync {
    /// Insert `bytes` and return its SHA-256 key.
    fn put(&self, bytes: &[u8]) -> ObjectResult<ContentHash>;
    /// Fetch the bytes for `key`, if present.
    fn get(&self, key: &ContentHash) -> ObjectResult<Vec<u8>>;
    /// Returns true if `key` is present.
    fn has(&self, key: &ContentHash) -> bool;
}

/// An in-memory CAS (for tests and the daemon bootstrap).
pub struct InMemoryCas;

impl Cas for InMemoryCas {
    fn put(&self, _bytes: &[u8]) -> ObjectResult<ContentHash> {
        todo!("Implement in-memory CAS put")
    }
    fn get(&self, _key: &ContentHash) -> ObjectResult<Vec<u8>> {
        todo!("Implement in-memory CAS get")
    }
    fn has(&self, _key: &ContentHash) -> bool {
        todo!("Implement in-memory CAS has")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/04-chunking.json,
        // /public/conformance/vectors/05-merkle.json, and
        // /public/conformance/vectors/06-manifest.json.
        let _ = chunk_constants::MIN_CHUNK;
    }
}
