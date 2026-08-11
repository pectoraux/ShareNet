//! SNP-SYNC — L5 anti-entropy and store-carry-forward for ShareNet 2.0
//!
//! Implements the SNP/0.1 L5 sync layer (per `01-ARCHITECTURE.md` §2.4 and
//! `02-PROTOCOL-SPEC.md` §7):
//!
//! - **Anti-entropy sync** — when two nodes meet, they exchange HAVE vectors
//!   (from `snp-discovery`) and each requests the objects the other has that
//!   they lack. This is the only sync primitive: no push, no subscribe.
//! - **Store-carry-forward** — when a node receives an object destined for a
//!   NodeId it cannot currently reach, it stores the object and forwards it
//!   when a path opens. The bundle's custody chain proves delivery.
//! - **Mode A bundle custody** — for Mode A (relay-only) traffic, the bundle
//!   carries a `TransitReceipt` chain so each carrier can be credited.
//!
//! This is the Rust equivalent of `/src/lib/snp/sync.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in a
//! future `15-sync.json` suite.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the L5 sync layer.
#[derive(Debug, Error)]
pub enum SyncError {
    /// An object requested by the peer was not in local storage.
    #[error("object not found: {0}")]
    ObjectNotFound(String),
    /// A bundle's custody chain was broken (missing or out-of-order signature).
    #[error("broken custody chain at hop {0}")]
    BrokenCustodyChain(usize),
    /// A bundle has expired past its deadline.
    #[error("bundle expired at {0}")]
    Expired(u64),
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] snp_crypto::CryptoError),
    /// Underlying object layer failure.
    #[error("object error: {0}")]
    Object(#[from] snp_object::ObjectError),
}

/// Convenience `Result` alias.
pub type SyncResult<T> = Result<T, SyncError>;

/// A sync request: the list of object IDs this node wants from the peer.
#[derive(Debug, Clone)]
pub struct SyncRequest {
    /// Object IDs being requested.
    pub object_ids: Vec<[u8; 32]>,
}

/// A sync response: the requested objects, plus any newly-available object
/// IDs the peer might want.
#[derive(Debug, Clone)]
pub struct SyncResponse {
    /// Objects being delivered.
    pub objects: Vec<SyncObject>,
    /// Newly-available object IDs the requester might want.
    pub new_have: Vec<[u8; 32]>,
}

/// A single object being synced, with its manifest and chunk payloads.
#[derive(Debug, Clone)]
pub struct SyncObject {
    /// The object's manifest.
    pub manifest: snp_object::Manifest,
    /// Chunk bytes in order.
    pub chunks: Vec<Vec<u8>>,
}

/// A store-carry-forward bundle: an object payload plus a destination NodeId
/// and a deadline. Custody is transferred at each hop and proven by a chain
/// of `TransitReceipt`s.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Destination NodeId.
    pub destination: snp_identity::NodeId,
    /// Source NodeId.
    pub source: snp_identity::NodeId,
    /// Object payload (manifest + chunk references).
    pub payload: SyncObject,
    /// Unix timestamp (seconds) after which the bundle is dropped.
    pub deadline: u64,
    /// Chain of custody: one entry per hop.
    pub custody_chain: Vec<CustodyHop>,
}

/// One hop in a bundle's custody chain.
#[derive(Debug, Clone)]
pub struct CustodyHop {
    /// The NodeId of the carrier at this hop.
    pub carrier: snp_identity::NodeId,
    /// Unix timestamp (seconds) at which custody was taken.
    pub taken_at: u64,
    /// Signature by the carrier's identity key over the previous hop (or
    /// `destination || source || payload || deadline` for the first hop).
    pub signature: snp_crypto::Signature,
}

impl Bundle {
    /// Take custody of this bundle: append a new `CustodyHop` signed by `us`.
    pub fn take_custody(
        &mut self,
        _us: &snp_identity::NodeId,
        _now: u64,
        _our_secret: &snp_crypto::SecretKey,
    ) -> SyncResult<()> {
        todo!("Append a CustodyHop to the bundle's custody chain")
    }

    /// Verify the entire custody chain from source to current carrier.
    pub fn verify_custody(&self) -> SyncResult<()> {
        todo!("Verify every hop in the custody chain")
    }

    /// Encode to canonical CBOR (for the wire).
    pub fn to_cbor(&self) -> SyncResult<Vec<u8>> {
        todo!("Encode Bundle to canonical CBOR")
    }

    /// Decode from canonical CBOR.
    pub fn from_cbor(_bytes: &[u8]) -> SyncResult<Self> {
        todo!("Decode Bundle from canonical CBOR")
    }
}

/// Run a single anti-entropy exchange with a peer. Returns the objects we
/// received and the objects we sent.
pub fn exchange(
    _local_have: &snp_discovery::HaveVector,
    _peer_link: &impl snp_link::Link,
) -> SyncResult<(Vec<SyncObject>, Vec<SyncObject>)> {
    todo!("Run one anti-entropy round: request missing, send requested")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will cover:
        //   - SyncRequest/Response round-trip
        //   - Bundle custody chain append + verify
        //   - Bundle expiry rejection
        //   - Anti-entropy exchange convergence
        let _ = SyncError::ObjectNotFound("test".into());
    }
}
