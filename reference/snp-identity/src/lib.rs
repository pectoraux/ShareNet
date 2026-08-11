//! SNP-IDENTITY — The four-way identity split for ShareNet 2.0
//!
//! Implements SNP/0.1 §2 (identity). ShareNet splits identity into four
//! distinct objects to avoid the audit's finding that NodeId was a "key, a
//! hash, and a routing locator all at once":
//!
//! 1. **`IdentityKey`** — the Ed25519 secret key, never transmitted.
//! 2. **`NodeId`** — `SHA-256("SNP/0.1 node\0" || pk)` (per I4), the durable
//!    identifier. NOT the bare public key, NOT a routing locator.
//! 3. **`DeviceCert`** — a short-lived certificate binding a `NodeId` to a
//!    device public key, signed by the node's identity key.
//! 4. **`NodeDescriptor`** — the signed, broadcastable record containing the
//!    NodeId, supported link types, capabilities, and current device cert.
//!
//! This is the Rust equivalent of `/src/lib/snp/identity.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/03-identity.json` and
//! `/public/conformance/vectors/09-descriptors.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from SNP identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// A signature over a DeviceCert or NodeDescriptor failed verification.
    #[error("invalid identity signature")]
    InvalidSignature,
    /// A certificate has expired.
    #[error("certificate expired")]
    Expired,
    /// A certificate was issued for a different NodeId than the one presented.
    #[error("NodeId mismatch in certificate")]
    NodeIdMismatch,
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] snp_crypto::CryptoError),
}

/// Convenience `Result` alias.
pub type IdentityResult<T> = Result<T, IdentityError>;

/// A 32-byte NodeId: `SHA-256("SNP/0.1 node\0" || pk)`.
pub type NodeId = [u8; 32];

/// Domain-separation tag used in NodeId derivation (I4).
pub const NODE_ID_DOMAIN: &[u8] = b"SNP/0.1 node\0";

/// Derive a NodeId from an Ed25519 public key.
///
/// Per invariant I4: `NodeId = SHA-256("SNP/0.1 node\0" || pk)`. The bare key
/// is NEVER used as a NodeId.
pub fn derive_node_id(_public_key: &snp_crypto::PublicKey) -> NodeId {
    todo!("Compute SHA-256(NODE_ID_DOMAIN || pk) via snp_crypto::domain_hash")
}

/// A device certificate: binds a NodeId to a device Ed25519 public key with
/// an expiry. Signed by the node's identity key.
#[derive(Debug, Clone)]
pub struct DeviceCert {
    /// The NodeId this cert is issued to.
    pub node_id: NodeId,
    /// The device's Ed25519 public key.
    pub device_key: snp_crypto::PublicKey,
    /// Unix timestamp (seconds) at which the cert expires.
    pub expires_at: u64,
    /// Signature by the node identity key over the canonical CBOR of the
    /// three fields above, prefixed by `SIG_CONTEXT`.
    pub signature: snp_crypto::Signature,
}

impl DeviceCert {
    /// Issue a new DeviceCert by signing with `node_secret`.
    pub fn issue(
        _node_id: &NodeId,
        _device_key: &snp_crypto::PublicKey,
        _expires_at: u64,
        _node_secret: &snp_crypto::SecretKey,
    ) -> IdentityResult<Self> {
        todo!("Build and sign a DeviceCert per SNP/0.1 §2.2")
    }

    /// Verify the certificate's signature against `node_public`.
    pub fn verify(&self, _node_public: &snp_crypto::PublicKey) -> IdentityResult<()> {
        todo!("Verify DeviceCert signature via snp_crypto::ed25519_verify")
    }
}

/// Capabilities a node advertises. Subset of the platform matrix in
/// `/public/spec/03-PLATFORM-MATRIX.md`.
#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    /// Can this node act as a relay?
    pub can_relay: bool,
    /// Can this node act as a gateway (has Internet egress)?
    pub can_gateway: bool,
    /// Supported link types: "tcp", "ble", "wifi-direct", …
    pub link_types: Vec<String>,
    /// Supported modes: "A", "B", "C".
    pub modes: Vec<String>,
}

/// A NodeDescriptor: the signed, broadcastable record published by a node.
#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    /// The issuer's NodeId.
    pub node_id: NodeId,
    /// The issuer's identity public key (raw 32 bytes, per I3).
    pub identity_key: snp_crypto::PublicKey,
    /// The current device certificate.
    pub device_cert: DeviceCert,
    /// Advertised capabilities.
    pub capabilities: Capabilities,
    /// Sequence number, incremented on every change.
    pub seq: u64,
    /// Unix timestamp (seconds) at which this descriptor was issued.
    pub issued_at: u64,
    /// Signature by the identity key over canonical CBOR of all fields above.
    pub signature: snp_crypto::Signature,
}

impl NodeDescriptor {
    /// Build and sign a NodeDescriptor.
    pub fn issue(
        _node_id: &NodeId,
        _identity_key: &snp_crypto::PublicKey,
        _device_cert: DeviceCert,
        _capabilities: Capabilities,
        _seq: u64,
        _issued_at: u64,
        _identity_secret: &snp_crypto::SecretKey,
    ) -> IdentityResult<Self> {
        todo!("Build and sign a NodeDescriptor per SNP/0.1 §2.3")
    }

    /// Verify the descriptor's signature against the embedded identity key.
    pub fn verify(&self) -> IdentityResult<()> {
        todo!("Verify NodeDescriptor signature via snp_crypto::ed25519_verify")
    }

    /// Encode to canonical CBOR bytes (for the wire and for signature input).
    pub fn to_cbor(&self) -> IdentityResult<Vec<u8>> {
        todo!("Encode NodeDescriptor to canonical CBOR")
    }

    /// Decode from canonical CBOR bytes.
    pub fn from_cbor(_bytes: &[u8]) -> IdentityResult<Self> {
        todo!("Decode NodeDescriptor from canonical CBOR")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/03-identity.json (NodeId derivation,
        // DeviceCert issue/verify) and /public/conformance/vectors/09-descriptors.json
        // (NodeDescriptor wire format).
        let _ = NODE_ID_DOMAIN;
    }
}
