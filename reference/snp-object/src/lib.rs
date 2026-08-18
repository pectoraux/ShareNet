//! SNP-OBJECT — Content-addressed objects for ShareNet 2.0
//!
//! Implements the SNP/0.1 content layer (per `02-PROTOCOL-SPEC.md` §3):
//! - **Gear CDC chunking** with frozen constants (MIN 256 KiB, TARGET 1 MiB,
//!   MAX 4 MiB, 20-bit mask). Boundary logic MUST NOT change without an ADR.
//! - **RFC 6962 Merkle trees** with `\x00` (leaf) and `\x01` (intermediate)
//!   prefixes, no odd-node duplication, empty root = `SHA-256("SNP/0.1 empty\0")`.
//! - **Content-addressed storage (CAS)** keyed by `SHA-256`.
//! - **Manifests** — the signed envelope that binds an object's metadata,
//!   chunk list, and Merkle root.
//!
//! This crate is implemented independently of the TypeScript reference. The
//! normative authority is `public/spec/02-PROTOCOL-SPEC.md` §3 and RFC 6962.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use sha2::{Digest, Sha256};
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

// ─── ContentBytes (Class A body) ───────────────────────────────────────────

/// Typed content data — represents Class A content that MAY be cached,
/// replicated, Merkle-verified, and content-addressed.
///
/// This type wraps `Vec<u8>` and represents content that is semantically
/// distinct from Class B transit ciphertext.
///
/// Unlike a transit ciphertext type, `ContentBytes` exposes its inner
/// bytes for content operations (hashing, chunking, CAS storage).
///
/// ## Ownership
///
/// `ContentBytes` is owned by the content layer (L2), not the transport
/// layer (L8). The transport layer may carry content bytes, but the
/// semantic ownership of "what is content" belongs here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentBytes(Vec<u8>);

impl ContentBytes {
    /// Construct from raw content bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the content bytes (for hashing, CAS, etc.).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for ContentBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for ContentBytes {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

/// A chunked object's metadata. Skeleton stub — not exercised by the Rust
/// conformance harness. The full Manifest CBOR structure is tracked as
/// future work; the `manifest-sign-and-verify` vector is classified as
/// UNSUPPORTED until then.
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

/// A content-addressed store: SHA-256 key → content bytes.
///
/// The `put` method accepts [`ContentBytes`] (Class A), NOT raw `&[u8]`.
/// This prevents transit ciphertext from accidentally entering the
/// content cache — ciphertext types have no `as_bytes()` method.
pub trait Cas: Send + Sync {
    /// Insert content and return its SHA-256 key.
    fn put(&self, content: &ContentBytes) -> ObjectResult<ContentHash>;
    /// Fetch the bytes for `key`, if present.
    fn get(&self, key: &ContentHash) -> ObjectResult<Vec<u8>>;
    /// Returns true if `key` is present.
    fn has(&self, key: &ContentHash) -> bool;
}

/// An in-memory CAS (for tests and the daemon bootstrap). Skeleton stub.
pub struct InMemoryCas;

impl Cas for InMemoryCas {
    fn put(&self, _content: &ContentBytes) -> ObjectResult<ContentHash> {
        todo!("Implement in-memory CAS put")
    }
    fn get(&self, _key: &ContentHash) -> ObjectResult<Vec<u8>> {
        todo!("Implement in-memory CAS get")
    }
    fn has(&self, _key: &ContentHash) -> bool {
        todo!("Implement in-memory CAS has")
    }
}

/// Frozen chunking constants — changing these breaks every ObjectId.
///
/// Per `02-PROTOCOL-SPEC.md` §3.3 and §A (frozen parameters table):
/// - MIN_CHUNK = 256 KiB
/// - TARGET_CHUNK = 1 MiB (drives the 20-bit mask)
/// - MAX_CHUNK = 4 MiB
/// - Mask = 20 bits (0xFFFFF)
///
/// The original skeleton used 2/8/64 KiB which was incorrect; the committed
/// vectors (`04-chunking.json`) require the 256 KiB / 1 MiB / 4 MiB values.
pub mod chunk_constants {
    /// Minimum chunk size in bytes (256 KiB).
    pub const MIN_CHUNK: usize = 256 * 1024;
    /// Target average chunk size in bytes (1 MiB). Drives the 20-bit mask.
    pub const TARGET_CHUNK: usize = 1024 * 1024;
    /// Maximum chunk size in bytes (4 MiB). Hard ceiling — never exceeded.
    pub const MAX_CHUNK: usize = 4 * 1024 * 1024;
    /// Gear CDC boundary mask (20 bits).
    pub const MASK: u32 = 0xFFFFF;
    /// Gear CDC rolling-hash window (informational; not used by the algorithm
    /// — Gear is a one-byte rolling hash, not a windowed one).
    pub const GEAR_WINDOW: usize = 1;
}

// === RFC 6962 Merkle trees ===

/// Compute the Merkle leaf hash for a single chunk: `SHA-256(0x00 || chunk)`.
#[must_use]
pub fn leaf_hash(chunk: &[u8]) -> ContentHash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(chunk);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the Merkle internal hash for two children:
/// `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &ContentHash, right: &ContentHash) -> ContentHash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the Merkle root of an empty leaf set:
/// `SHA-256("SNP/0.1 empty\0")`.
#[must_use]
pub fn empty_root() -> ContentHash {
    snp_crypto::empty_merkle_root()
}

/// Compute the Merkle root of a list of leaf hashes using RFC 6962's split
/// rule: split at the largest power of two less than `n`, never duplicate.
///
/// - 0 leaves → [`empty_root`]
/// - 1 leaf → that leaf's hash (no node_hash wrap; the leaf IS the root)
/// - n ≥ 2 → split at `k = largest power of 2 < n`, root = node_hash(MT(left), MT(right))
#[must_use]
pub fn merkle_root(leaf_hashes: &[ContentHash]) -> ContentHash {
    match leaf_hashes.len() {
        0 => empty_root(),
        1 => leaf_hashes[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = merkle_root(&leaf_hashes[..k]);
            let right = merkle_root(&leaf_hashes[k..]);
            node_hash(&left, &right)
        }
    }
}

/// Compute the Merkle root of a list of raw chunks (convenience: hashes each
/// chunk first, then calls [`merkle_root`]).
#[must_use]
pub fn merkle_root_from_chunks(chunks: &[Vec<u8>]) -> ContentHash {
    let leaves: Vec<ContentHash> = chunks.iter().map(|c| leaf_hash(c)).collect();
    merkle_root(&leaves)
}

/// The largest power of two strictly less than `n` (for n ≥ 2).
/// For n = 2 → 1, n = 3 → 2, n = 4 → 2, n = 5 → 4, n = 8 → 4, n = 9 → 8, …
fn largest_power_of_two_less_than(n: usize) -> usize {
    assert!(n >= 2);
    // Highest set bit position of (n-1), then 2^pos.
    // e.g. n=5 → n-1=4=0b100 → pos=2 → 2^2 = 4. ✓
    // e.g. n=4 → n-1=3=0b011 → pos=1 → 2^1 = 2. ✓
    // e.g. n=8 → n-1=7=0b111 → pos=2 → 2^2 = 4. ✓
    let m = n - 1;
    1 << m.ilog2()
}

/// Whether a sibling sits to the left or right of the path node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is on the left.
    Left,
    /// Sibling is on the right.
    Right,
}

/// A Merkle inclusion proof (list of sibling hashes, leaf-to-root order).
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Sibling hashes, in order from leaf to root.
    pub siblings: Vec<(Side, ContentHash)>,
}

/// Build a Merkle inclusion proof for the leaf at `index`.
///
/// # Errors
/// Returns [`ObjectError::InvalidProof`] if `index` is out of bounds.
pub fn merkle_proof(leaf_hashes: &[ContentHash], index: usize) -> ObjectResult<MerkleProof> {
    if index >= leaf_hashes.len() {
        return Err(ObjectError::InvalidProof);
    }
    let mut siblings = Vec::new();
    build_proof(leaf_hashes, index, &mut siblings);
    Ok(MerkleProof { siblings })
}

fn build_proof(level: &[ContentHash], idx: usize, siblings: &mut Vec<(Side, ContentHash)>) {
    if level.len() <= 1 {
        return;
    }
    let k = largest_power_of_two_less_than(level.len());
    if idx < k {
        // Leaf is in the left subtree; sibling is the right subtree's root.
        // Push siblings in leaf-to-root order: recurse first, then push.
        build_proof(&level[..k], idx, siblings);
        let right = merkle_root(&level[k..]);
        siblings.push((Side::Right, right));
    } else {
        build_proof(&level[k..], idx - k, siblings);
        let left = merkle_root(&level[..k]);
        siblings.push((Side::Left, left));
    }
}

/// Verify a Merkle inclusion proof against a known root.
///
/// Walks the proof leaf-to-root, hashing the running value with each sibling
/// (using the recorded `Side` to determine hash argument order), and compares
/// the final value to `root`.
pub fn merkle_verify(
    root: &ContentHash,
    leaf: &ContentHash,
    proof: &MerkleProof,
) -> ObjectResult<()> {
    let mut running = *leaf;
    for (side, sibling) in &proof.siblings {
        running = match side {
            Side::Left => node_hash(sibling, &running),
            Side::Right => node_hash(&running, sibling),
        };
    }
    if &running == root {
        Ok(())
    } else {
        Err(ObjectError::InvalidProof)
    }
}

// === Gear CDC chunking ===

/// Build the 256-entry Gear table using `splitmix64` seeded at 0, taking the
/// low 32 bits of each output. Frozen (I6).
///
/// The first four entries are `[0x7b1dcdaf, 0xa1b965f4, 0x8009454f, 0x724c81ec]`
/// (decimal `[2065550767, 2713282036, 2148091215, 1917616620]`), matching the
/// committed `gear-table-first4` vector.
#[must_use]
pub fn build_gear_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut state: u64 = 0;
    for entry in &mut table {
        let z = splitmix64_next(&mut state);
        *entry = (z & 0xFFFF_FFFF) as u32;
    }
    table
}

/// One step of Sebastiano Vigna's splitmix64: advance `state` in place by
/// adding the golden-ratio delta, mix the new state, return the output.
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Compute Gear CDC chunk boundaries for `data`. Returns a list of byte
/// offsets (each = the cumulative end position of a chunk).
///
/// Algorithm:
/// 1. If `data` is empty, return `[]`.
/// 2. Walk the data with a Gear rolling hash `h = ((h << 1) + GEAR[byte]) & MASK_ALL`.
/// 3. After `MIN_CHUNK` bytes, if `(h & MASK) == 0`, emit a boundary.
/// 4. If a chunk reaches `MAX_CHUNK` bytes, emit a boundary unconditionally.
/// 5. At end of input, emit the final boundary (the total length).
#[must_use]
pub fn chunk_boundaries(data: &[u8]) -> Vec<usize> {
    let n = data.len();
    if n == 0 {
        return Vec::new();
    }
    let gear = build_gear_table();
    let min = chunk_constants::MIN_CHUNK;
    let max = chunk_constants::MAX_CHUNK;
    let mask = chunk_constants::MASK;
    let mask_64 = u64::from(mask);

    let mut boundaries = Vec::new();
    let mut start = 0usize;
    while start < n {
        let mut h: u64 = 0;
        let mut chunk_size: usize = 0;
        // Determine end of this chunk.
        for &b in &data[start..] {
            h = h.wrapping_shl(1).wrapping_add(u64::from(gear[b as usize]));
            chunk_size += 1;
            if chunk_size >= min && (h & mask_64) == 0 {
                break;
            }
            if chunk_size >= max {
                break;
            }
        }
        start += chunk_size;
        boundaries.push(start);
    }
    boundaries
}

/// Split `data` into chunks using Gear CDC. Returns the chunk byte vectors in
/// order. The Merkle root over `leaf_hash(chunk)` for each chunk is the
/// `ObjectId` of the resulting object.
#[must_use]
pub fn chunk(data: &[u8]) -> Vec<Vec<u8>> {
    let boundaries = chunk_boundaries(data);
    let mut out = Vec::with_capacity(boundaries.len());
    let mut prev = 0usize;
    for end in boundaries {
        out.push(data[prev..end].to_vec());
        prev = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn gear_table_first4() {
        let table = build_gear_table();
        assert_eq!(table[0], 2_065_550_767, "gear[0]");
        assert_eq!(table[1], 2_713_282_036, "gear[1]");
        assert_eq!(table[2], 2_148_091_215, "gear[2]");
        assert_eq!(table[3], 1_917_616_620, "gear[3]");
    }

    #[test]
    fn chunk_empty_input() {
        assert_eq!(chunk_boundaries(b""), Vec::<usize>::new());
    }

    #[test]
    fn chunk_single_byte() {
        assert_eq!(chunk_boundaries(&[0x41]), vec![1]);
    }

    #[test]
    fn chunk_below_min_is_one_chunk() {
        // MIN-1 bytes -> 1 chunk
        let data = vec![0u8; chunk_constants::MIN_CHUNK - 1];
        let b = chunk_boundaries(&data);
        assert_eq!(b, vec![data.len()]);
    }

    #[test]
    fn merkle_1_leaf_matches_leaf_hash() {
        let leaf = hex_to_bytes("010203");
        let lh = leaf_hash(&leaf);
        let root = merkle_root(&[lh]);
        assert_eq!(to_hex(&root), to_hex(&lh));
    }

    #[test]
    fn merkle_2_leaves() {
        let l1 = leaf_hash(&hex_to_bytes("01"));
        let l2 = leaf_hash(&hex_to_bytes("02"));
        let root = merkle_root(&[l1, l2]);
        assert_eq!(
            to_hex(&root),
            "6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965"
        );
    }

    #[test]
    fn merkle_3_leaves_no_duplication() {
        let leaves: Vec<ContentHash> = ["01", "02", "03"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        assert_eq!(
            to_hex(&root),
            "e2da0242936eb38ec996a543601b3a1da4226391ff92014ed1a7a248ace36347"
        );
    }

    #[test]
    fn merkle_5_leaves() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        assert_eq!(
            to_hex(&root),
            "b2165c86fbfb34fa51840bb6ba3d5ce0d7dc31f2e605b5ba62c98fa86ff6746d"
        );
    }

    #[test]
    fn merkle_8_leaves_balanced() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05", "06", "07", "08"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        assert_eq!(
            to_hex(&root),
            "c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071"
        );
    }

    #[test]
    fn merkle_empty_root() {
        let r = empty_root();
        assert_eq!(
            to_hex(&r),
            "8b8f6a4bed03dd03c795484fb1354b67e707ae7f4e8587b03ee10341d299cc8b"
        );
    }

    #[test]
    fn merkle_5_leaves_proof_index_0_round_trips() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0).unwrap();
        assert_eq!(proof.siblings.len(), 3);
        merkle_verify(&root, &leaves[0], &proof).unwrap();
    }

    #[test]
    fn merkle_5_leaves_proof_index_4_round_trips() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 4).unwrap();
        assert_eq!(proof.siblings.len(), 1);
        assert!(matches!(proof.siblings[0].0, Side::Left));
        merkle_verify(&root, &leaves[4], &proof).unwrap();
    }

    /// Deterministic data generator used by the committed chunking vectors.
    /// The 04-chunking.json vectors use `seed` as an integer seed for
    /// splitmix64, generating 8 bytes per call (little-endian). This was
    /// derived independently (see worklog Task 52-60) by matching the
    /// committed boundary values; the PRNG choice is part of the vector,
    /// not part of the SNP spec.
    fn deterministic_data(seed: u64, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut state = seed;
        while out.len() < n {
            let z = splitmix64_next(&mut state);
            for &b in &z.to_le_bytes() {
                if out.len() >= n {
                    break;
                }
                out.push(b);
            }
        }
        out
    }

    #[test]
    fn chunk_5mb_deterministic_seed7() {
        let data = deterministic_data(7, 5_242_880);
        let b = chunk_boundaries(&data);
        assert_eq!(b, vec![4_194_304, 4_803_239, 5_242_880]);
    }

    #[test]
    fn chunk_max_plus_1_seed99() {
        let data = deterministic_data(99, 4_195_328);
        let b = chunk_boundaries(&data);
        assert_eq!(b, vec![1_692_137, 3_593_855, 4_195_328]);
    }
}
