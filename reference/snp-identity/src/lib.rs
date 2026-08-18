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
//! This crate implements NodeId derivation and Ed25519 signature verification
//! against the committed conformance vectors in
//! `public/conformance/vectors/03-identity.json`. The full DeviceCert /
//! NodeDescriptor CBOR structures are not yet implemented; they are exercised
//! by the conformance harness as `UNSUPPORTED` where they require CBOR
//! reconstruction of complex payload shapes.

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
    Crypto(String),
}

/// Convenience `Result` alias.
pub type IdentityResult<T> = Result<T, IdentityError>;

/// A 32-byte NodeId: `SHA-256("SNP/0.1 node\0" || pk)`.
pub type NodeId = [u8; 32];

/// Domain-separation tag used in NodeId derivation (I4).
pub const NODE_ID_DOMAIN: &[u8] = snp_crypto::NODE_ID_DOMAIN;

/// Derive a NodeId from an Ed25519 public key.
///
/// Per invariant I4: `NodeId = SHA-256("SNP/0.1 node\0" || pk)`. The bare key
/// is NEVER used as a NodeId.
#[must_use]
pub fn derive_node_id(public_key: &snp_crypto::PublicKey) -> NodeId {
    snp_crypto::derive_node_id(public_key)
}

/// Verify an Ed25519 signature made under a specific SIG_CONTEXT.
///
/// Preimage = `sig_context(name) || bytes`. Returns `true` iff the signature
/// is valid under RFC 8032 verification for `public_key`.
///
/// Returns `false` if `name` is not a known SIG_CONTEXT.
#[must_use]
pub fn verify_signed(
    public_key: &snp_crypto::PublicKey,
    context_name: &str,
    payload_bytes: &[u8],
    signature: &snp_crypto::SignatureBytes,
) -> bool {
    let Some(ctx) = snp_crypto::sig_context(context_name) else {
        return false;
    };
    let mut preimage = Vec::with_capacity(ctx.len() + payload_bytes.len());
    preimage.extend_from_slice(ctx);
    preimage.extend_from_slice(payload_bytes);
    snp_crypto::ed25519_verify(public_key, &preimage, signature)
}

// === Runtime identity types (extracted from snp-node/src/node/identity.rs) ===
//
// These are the production identity types used by the runtime. They were
// previously owned by snp-node but are extracted here (R2.2) to establish
// the L1 identity layer as a real architectural boundary.
//
// The older skeleton types (DeviceCert, Capabilities struct, NodeDescriptor)
// below are retained for API compatibility but are NOT used by the runtime.

/// A node's cryptographic identity: Ed25519 secret key, public key, NodeId.
///
/// `NodeId = SHA-256("SNP/0.1 node\0" || public_key)` per invariant I4 — the
/// bare public key is NEVER used as a NodeId.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    /// Ed25519 secret key (32 bytes).
    pub secret_key: [u8; 32],
    /// Ed25519 public key (32 bytes), derived from `secret_key`.
    pub public_key: [u8; 32],
    /// NodeId = `SHA-256("SNP/0.1 node\0" || public_key)`.
    pub node_id: [u8; 32],
}

impl NodeIdentity {
    /// Construct a `NodeIdentity` from a secret key.
    #[must_use]
    pub fn from_secret(secret_key: [u8; 32]) -> Self {
        let public_key = snp_crypto::derive_public_key(&secret_key);
        let node_id = snp_crypto::derive_node_id(&public_key);
        Self {
            secret_key,
            public_key,
            node_id,
        }
    }

    /// Construct a gateway identity from an X25519 keypair in addition to
    /// the Ed25519 identity.
    ///
    /// **N2.0.5:** This is the canonical production constructor for gateway
    /// nodes. The Ed25519 keypair provides the node's signing identity; the
    /// X25519 keypair provides the static key for the SNP-IK/0.1 handshake.
    #[must_use]
    pub fn new_with_x25519(secret_key: [u8; 32]) -> Self {
        Self::from_secret(secret_key)
    }
}

/// A node's role in the network. A single node MAY hold multiple capabilities
/// (e.g. a gateway might also relay), but in N2.0.1 each node has exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Can send TransitRequests (a client node).
    Client,
    /// Can forward frames between peers (a relay node).
    Relay,
    /// Can terminate circuits and fetch from the Internet (a gateway node).
    Gateway,
}

impl Capability {
    /// String representation for advertisement serialisation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Client => "client",
            Capability::Relay => "relay",
            Capability::Gateway => "gateway",
        }
    }

    /// Parse from string (for advertisement deserialisation).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Capability::Client),
            "relay" => Some(Capability::Relay),
            "gateway" => Some(Capability::Gateway),
            _ => None,
        }
    }
}

// === Skeleton types (kept for downstream crate API compatibility) ===
//
// These types are NOT yet exercised by the Rust conformance harness. The
// full DeviceCert / NodeDescriptor CBOR structures are tracked as future
// work; the `devicecert-sign-and-verify` and `node-descriptor-sign-and-verify`
// vectors are classified as UNSUPPORTED until then.

/// A device certificate: binds a NodeId to a device Ed25519 public key with
/// an expiry. Signed by the node's identity key. Skeleton stub.
#[derive(Debug, Clone)]
pub struct DeviceCert {
    /// The NodeId this cert is issued to.
    pub node_id: NodeId,
    /// The device's Ed25519 public key.
    pub device_key: snp_crypto::PublicKey,
    /// Unix timestamp (seconds) at which the cert expires.
    pub expires_at: u64,
    /// Signature by the node identity key.
    pub signature: snp_crypto::Signature,
}

/// Capabilities a node advertises. Skeleton stub.
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
/// Skeleton stub — not yet implemented.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nodeid_deterministic_alice() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_to_bytes(pk_hex));
        let id = derive_node_id(&pk);
        let got: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            "4ae95ccb41544dccde22eca97a7cdc99101cb5aa91606c257b56cdd35b414913"
        );
        // Deterministic: same input → same output.
        let id2 = derive_node_id(&pk);
        assert_eq!(id, id2);
    }

    #[test]
    fn rfc8032_test1_verify() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_to_bytes(pk_hex));
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&hex_to_bytes(sig_hex));
        assert!(snp_crypto::ed25519_verify(&pk, b"", &sig));
    }

    #[test]
    fn unknown_context_rejects() {
        let pk = [0u8; 32];
        let sig = [0u8; 64];
        assert!(!verify_signed(&pk, "nonsense", b"", &sig));
    }
}
