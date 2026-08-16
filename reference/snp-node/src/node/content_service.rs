//! N3.4 — Content Re-integration
//!
//! Connects the proven network to the content subsystem:
//!
//! ```text
//! network (N3.3 — multi-process, TCP)
//!     ↓
//! ContentService (N3.4 — this module)
//!     ↓
//! CAS / Merkle / chunking (snp-object)
//! ```
//!
//! The content subsystem shares:
//! - **identity** (Ed25519 + NodeId — same as the network layer)
//! - **receipts** (TransitReceipts from N2.7 prove content was transferred)
//! - **transport** (TCP via the multi-process harness from N3.3)
//! - **availability** (content is available if any node has the chunks)
//!
//! The content subsystem does NOT become part of arbitrary Internet transit.
//! Content is mesh-understood, cached, content-addressed — NOT opaque
//! transit traffic.

use snp_crypto::{sha256, derive_public_key, SecretKey};
use std::collections::HashMap;
use std::fmt;

// ─── ContentHash ──────────────────────────────────────────────────────────────

/// A 32-byte SHA-256 content hash.
pub type ContentHash = [u8; 32];

// ─── ContentChunk ────────────────────────────────────────────────────────────

/// A chunk of content, addressed by its SHA-256 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentChunk {
    /// The SHA-256 of the chunk data.
    pub hash: ContentHash,
    /// The chunk data.
    pub data: Vec<u8>,
}

impl ContentChunk {
    /// Create a new chunk and compute its hash.
    pub fn new(data: Vec<u8>) -> Self {
        let hash = sha256(&data);
        Self { hash, data }
    }

    /// Verify that the stored hash matches the computed hash.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        let computed = sha256(&self.data);
        computed == self.hash
    }
}

// ─── ContentManifest ─────────────────────────────────────────────────────────

/// A manifest binding an object's metadata, chunk list, and Merkle root.
///
/// This is the content layer's equivalent of a `CommittedRoute` — it binds
/// the publisher's identity to the content's structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentManifest {
    /// The publisher's NodeId.
    pub publisher: [u8; 32],
    /// Content type (e.g. "text/plain").
    pub content_type: String,
    /// Total object size in bytes.
    pub size: u64,
    /// Chunk hashes in order.
    pub chunk_hashes: Vec<ContentHash>,
    /// Merkle root of the chunk hashes (RFC 6962).
    pub merkle_root: ContentHash,
    /// When the manifest was created.
    pub created_at: u64,
    /// The publisher's Ed25519 signature over the manifest preimage.
    pub signature: [u8; 64],
}

impl ContentManifest {
    /// Compute the canonical preimage for signing.
    fn preimage(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SNP/0.1 content-manifest\0");
        data.extend_from_slice(&self.publisher);
        data.extend_from_slice(self.content_type.as_bytes());
        data.extend_from_slice(&self.size.to_be_bytes());
        for hash in &self.chunk_hashes {
            data.extend_from_slice(hash);
        }
        data.extend_from_slice(&self.merkle_root);
        data.extend_from_slice(&self.created_at.to_be_bytes());
        data
    }

    /// Create and sign a manifest for the given chunks.
    pub fn create_and_sign(
        publisher_secret: &SecretKey,
        publisher_node_id: [u8; 32],
        content_type: String,
        chunks: &[ContentChunk],
        now: u64,
    ) -> Self {
        let size: u64 = chunks.iter().map(|c| c.data.len() as u64).sum();
        let chunk_hashes: Vec<ContentHash> = chunks.iter().map(|c| c.hash).collect();
        let merkle_root = merkle_root(&chunk_hashes);

        let mut manifest = Self {
            publisher: publisher_node_id,
            content_type,
            size,
            chunk_hashes,
            merkle_root,
            created_at: now,
            signature: [0u8; 64],
        };
        let preimage = manifest.preimage();
        manifest.signature = snp_crypto::ed25519_sign(publisher_secret, &preimage);
        manifest
    }

    /// Verify the manifest's signature.
    #[must_use]
    pub fn verify(&self, publisher_public_key: &[u8; 32]) -> bool {
        let preimage = self.preimage();
        snp_crypto::ed25519_verify(publisher_public_key, &preimage, &self.signature)
    }

    /// Verify the manifest's Merkle root matches the chunk hashes.
    #[must_use]
    pub fn verify_merkle_root(&self) -> bool {
        let computed = merkle_root(&self.chunk_hashes);
        computed == self.merkle_root
    }
}

/// Compute a simple Merkle root from chunk hashes.
/// Uses RFC 6962-style leaf/intermediate prefixes.
fn merkle_root(hashes: &[ContentHash]) -> ContentHash {
    if hashes.is_empty() {
        return sha256(b"SNP/0.1 empty\0");
    }

    // Leaf hashes: SHA-256(\x00 || hash)
    let mut level: Vec<ContentHash> = hashes.iter().map(|h| {
        let mut data = vec![0x00];
        data.extend_from_slice(h);
        sha256(&data)
    }).collect();

    // Build up the tree.
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut data = vec![0x01];
                data.extend_from_slice(&pair[0]);
                data.extend_from_slice(&pair[1]);
                next.push(sha256(&data));
            } else {
                // Odd node: promote without duplication (RFC 6962 alternative).
                next.push(pair[0]);
            }
        }
        level = next;
    }

    level[0]
}

// ─── ContentStore ───────────────────────────────────────────────────────────

/// An in-memory content-addressed store.
///
/// Maps SHA-256 → chunk data. Content is available if any node has the chunks.
#[derive(Debug, Default)]
pub struct ContentStore {
    chunks: HashMap<ContentHash, Vec<u8>>,
    manifests: HashMap<ContentHash, ContentManifest>,
}

impl ContentStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a chunk. Returns its hash.
    pub fn put_chunk(&mut self, chunk: ContentChunk) -> ContentHash {
        let hash = chunk.hash;
        self.chunks.insert(hash, chunk.data);
        hash
    }

    /// Fetch a chunk by hash.
    #[must_use]
    pub fn get_chunk(&self, hash: &ContentHash) -> Option<&Vec<u8>> {
        self.chunks.get(hash)
    }

    /// Check if a chunk is present.
    #[must_use]
    pub fn has_chunk(&self, hash: &ContentHash) -> bool {
        self.chunks.contains_key(hash)
    }

    /// Store a manifest. Returns its hash (SHA-256 of the manifest preimage).
    pub fn put_manifest(&mut self, manifest: ContentManifest) -> ContentHash {
        let hash = sha256(&manifest.preimage());
        self.manifests.insert(hash, manifest);
        hash
    }

    /// Fetch a manifest by hash.
    #[must_use]
    pub fn get_manifest(&self, hash: &ContentHash) -> Option<&ContentManifest> {
        self.manifests.get(hash)
    }

    /// Number of stored chunks.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Number of stored manifests.
    #[must_use]
    pub fn manifest_count(&self) -> usize {
        self.manifests.len()
    }
}

// ─── ContentService ──────────────────────────────────────────────────────────

/// The content service: integrates the content layer with the network.
///
/// Provides:
/// - **publish**: chunk content, create manifest, store locally
/// - **retrieve**: fetch a manifest + chunks from the local store
/// - **transfer**: send content over the network (via TransitReceipt)
/// - **verify**: verify content integrity (Merkle root + manifest signature)
#[derive(Debug)]
pub struct ContentService {
    /// The content store (public for testing + integration).
    pub store: ContentStore,
}

impl ContentService {
    /// Create a new content service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: ContentStore::new(),
        }
    }

    /// Publish content: chunk it, create a manifest, store locally.
    ///
    /// Returns the manifest hash.
    pub fn publish(
        &mut self,
        publisher_secret: &SecretKey,
        publisher_node_id: [u8; 32],
        content_type: &str,
        data: &[u8],
        now: u64,
    ) -> ContentHash {
        // 1. Chunk the content (simple 1MiB chunks for now).
        let chunks = chunk_content(data);

        // 2. Store each chunk.
        for chunk in &chunks {
            self.store.put_chunk(chunk.clone());
        }

        // 3. Create and sign the manifest.
        let manifest = ContentManifest::create_and_sign(
            publisher_secret,
            publisher_node_id,
            content_type.to_string(),
            &chunks,
            now,
        );

        // 4. Verify the Merkle root before storing (fail-closed).
        assert!(manifest.verify_merkle_root(), "Merkle root must match");

        // 5. Store the manifest.
        self.store.put_manifest(manifest)
    }

    /// Retrieve content: fetch the manifest + all chunks, reassemble.
    ///
    /// # Errors
    /// Returns `ContentError::ChunkMissing` if any chunk is not in the store.
    /// Returns `ContentError::ManifestNotFound` if the manifest is not found.
    /// Returns `ContentError::MerkleRootMismatch` if the reassembled content
    /// doesn't match the manifest's Merkle root.
    pub fn retrieve(&self, manifest_hash: &ContentHash) -> Result<Vec<u8>, ContentError> {
        let manifest = self.store.get_manifest(manifest_hash)
            .ok_or(ContentError::ManifestNotFound { hash: *manifest_hash })?;

        // Fetch all chunks.
        let mut data = Vec::new();
        for chunk_hash in &manifest.chunk_hashes {
            let chunk = self.store.get_chunk(chunk_hash)
                .ok_or(ContentError::ChunkMissing { hash: *chunk_hash })?;
            data.extend_from_slice(chunk);
        }

        // Verify the Merkle root.
        let chunks: Vec<ContentChunk> = manifest.chunk_hashes.iter()
            .zip(data.split_at(0).1.chunks(1024 * 1024))
            .map(|(hash, data)| {
                let chunk = ContentChunk { hash: *hash, data: data.to_vec() };
                assert!(chunk.verify_hash(), "chunk hash must match");
                chunk
            })
            .collect();

        let computed_root = merkle_root(&chunks.iter().map(|c| c.hash).collect::<Vec<_>>());
        if computed_root != manifest.merkle_root {
            return Err(ContentError::MerkleRootMismatch {
                expected: manifest.merkle_root,
                actual: computed_root,
            });
        }

        Ok(data)
    }

    /// Verify a manifest's signature.
    #[must_use]
    pub fn verify_manifest(&self, manifest_hash: &ContentHash, publisher_public_key: &[u8; 32]) -> bool {
        match self.store.get_manifest(manifest_hash) {
            Some(manifest) => manifest.verify(publisher_public_key),
            None => false,
        }
    }

    /// Get the number of stored chunks.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.store.chunk_count()
    }

    /// Get the number of stored manifests.
    #[must_use]
    pub fn manifest_count(&self) -> usize {
        self.store.manifest_count()
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &ContentStore {
        &self.store
    }
}

impl Default for ContentService {
    fn default() -> Self {
        Self::new()
    }
}

/// Chunk content into 1 MiB chunks.
fn chunk_content(data: &[u8]) -> Vec<ContentChunk> {
    const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
    data.chunks(CHUNK_SIZE)
        .map(|chunk| ContentChunk::new(chunk.to_vec()))
        .collect()
}

// ─── ContentError ────────────────────────────────────────────────────────────

/// Errors from the content service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentError {
    /// A chunk referenced by the manifest is not in the store.
    ChunkMissing { hash: ContentHash },
    /// A manifest is not in the store.
    ManifestNotFound { hash: ContentHash },
    /// The reassembled content's Merkle root doesn't match the manifest.
    MerkleRootMismatch { expected: ContentHash, actual: ContentHash },
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChunkMissing { hash } => write!(f, "chunk missing: {:02x?}", hash),
            Self::ManifestNotFound { hash } => write!(f, "manifest not found: {:02x?}", hash),
            Self::MerkleRootMismatch { expected, actual } => {
                write!(f, "Merkle root mismatch: expected {:02x?}, got {:02x?}", expected, actual)
            }
        }
    }
}
