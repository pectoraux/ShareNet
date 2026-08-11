//! SNP-DISCOVERY — L4 link-local discovery for ShareNet 2.0
//!
//! Implements the SNP/0.1 L4 discovery layer (per `01-ARCHITECTURE.md` §2.4
//! and `02-PROTOCOL-SPEC.md` §6):
//!
//! - **Link-local beacons** — small, signed UDP/mDNS advertisements carrying
//!   a `NodeDescriptor` and a timestamp. Beacons are scoped to a single L2
//!   segment and never routed.
//! - **Descriptor store** — a local cache of every `NodeDescriptor` this node
//!   has heard, indexed by NodeId, deduplicated by `seq`.
//! - **Anti-entropy HAVE vectors** — Bloom-filter-style summaries of which
//!   objects a node has, periodically exchanged with discovered peers so that
//!   `snp-sync` knows what to request.
//!
//! This is the Rust equivalent of `/src/lib/snp/discovery.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/09-descriptors.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the L4 discovery layer.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// A beacon's signature failed verification.
    #[error("invalid beacon signature")]
    InvalidSignature,
    /// A beacon is stale (its timestamp is too far from local clock).
    #[error("stale beacon")]
    StaleBeacon,
    /// A descriptor's sequence number is older than the one we have stored.
    #[error("stale descriptor (have seq {have}, got {got})")]
    StaleDescriptor {
        /// The sequence number we already have.
        have: u64,
        /// The sequence number we received.
        got: u64,
    },
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] snp_crypto::CryptoError),
    /// Underlying identity error.
    #[error("identity error: {0}")]
    Identity(#[from] snp_identity::IdentityError),
}

/// Convenience `Result` alias.
pub type DiscoveryResult<T> = Result<T, DiscoveryError>;

/// A link-local discovery beacon: a signed, broadcastable wrapper for a
/// `NodeDescriptor` with a beacon timestamp.
#[derive(Debug, Clone)]
pub struct Beacon {
    /// The descriptor being advertised.
    pub descriptor: snp_identity::NodeDescriptor,
    /// Unix timestamp (seconds) at which the beacon was issued.
    pub beacon_time: u64,
    /// Signature by the issuer's identity key over `SIG_CONTEXT || CBOR(descriptor, beacon_time)`.
    pub signature: snp_crypto::Signature,
}

impl Beacon {
    /// Build and sign a new beacon.
    pub fn issue(
        _descriptor: snp_identity::NodeDescriptor,
        _beacon_time: u64,
        _identity_secret: &snp_crypto::SecretKey,
    ) -> DiscoveryResult<Self> {
        todo!("Build and sign a Beacon per SNP/0.1 §6.1")
    }

    /// Verify the beacon's signature and freshness.
    pub fn verify(&self, _now: u64, _max_skew_seconds: u64) -> DiscoveryResult<()> {
        todo!("Verify Beacon signature and freshness window")
    }

    /// Encode to canonical CBOR (for the wire).
    pub fn to_cbor(&self) -> DiscoveryResult<Vec<u8>> {
        todo!("Encode Beacon to canonical CBOR")
    }

    /// Decode from canonical CBOR.
    pub fn from_cbor(_bytes: &[u8]) -> DiscoveryResult<Self> {
        todo!("Decode Beacon from canonical CBOR")
    }
}

/// A descriptor store: in-memory cache of `NodeDescriptor`s by NodeId.
pub struct DescriptorStore;

impl DescriptorStore {
    /// Construct an empty descriptor store.
    pub fn new() -> Self {
        Self
    }

    /// Insert or update a descriptor. Returns `Err(StaleDescriptor)` if the
    /// incoming `seq` is older than the stored one.
    pub fn upsert(&mut self, _descriptor: snp_identity::NodeDescriptor) -> DiscoveryResult<()> {
        todo!("Insert or update a NodeDescriptor by NodeId, dedup by seq")
    }

    /// Fetch the current descriptor for `node_id`, if any.
    pub fn get(&self, _node_id: &snp_identity::NodeId) -> Option<&snp_identity::NodeDescriptor> {
        todo!("Look up a NodeDescriptor by NodeId")
    }

    /// Iterate over all known descriptors.
    pub fn iter(&self) -> impl Iterator<Item = &snp_identity::NodeDescriptor> {
        todo!("Iterate over all known descriptors")
    }
}

impl Default for DescriptorStore {
    fn default() -> Self {
        Self::new()
    }
}

/// A HAVE vector: a Bloom-filter-style summary of which object IDs a node
/// has, periodically exchanged with peers to drive `snp-sync`.
#[derive(Debug, Clone)]
pub struct HaveVector {
    /// Bloom filter bytes.
    pub filter: Vec<u8>,
    /// Number of hash functions used.
    pub k: u8,
    /// Number of bits in the filter.
    pub m: u32,
    /// Approximate number of items inserted.
    pub n: u32,
}

impl HaveVector {
    /// Build a HAVE vector from a set of object IDs.
    pub fn from_object_ids(_ids: &[[u8; 32]]) -> Self {
        todo!("Build a Bloom-filter HAVE vector from object IDs")
    }

    /// Test whether `id` might be in the vector (false positive possible).
    pub fn contains(&self, _id: &[u8; 32]) -> bool {
        todo!("Bloom-filter membership test")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/09-descriptors.json (beacon wire format,
        // descriptor store upsert/dedup, HAVE vector membership).
        let _ = DescriptorStore::new();
    }
}
