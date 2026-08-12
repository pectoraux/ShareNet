//! N2.1.0 — Generic Authenticated Node Advertisement.
//!
//! This module introduces a GENERIC signed node advertisement that works for
//! ALL ShareNet node roles: relays, gateways, and multi-role nodes. It replaces
//! the N2.0.7.3 gateway-specific authentication pipeline
//! (`VerifiedGatewayAdvertisement → VerifiedNodeDescriptor`) with a model where
//! ANY node can produce a signed advertisement that, once verified, yields a
//! `VerifiedNodeDescriptor`.
//!
//! ## Architecture
//!
//! ```text
//! NodeAdvertisement (signed, covers ALL identity-critical fields)
//!     │
//!     ↓ verify_into_verified()
//!     │
//! VerifiedNodeAdvertisement (type-level proof: signature checked,
//!                            NodeId↔Ed25519 consistent, not expired)
//!     │
//!     ↓ descriptor()
//!     │
//! VerifiedNodeDescriptor (authenticated identity + capabilities + endpoints)
//! ```
//!
//! A `NodeAdvertisement` contains:
//! - `node_id` — SHA-256("SNP/0.1 node\0" || ed25519_public_key)
//! - `ed25519_public_key` — the signing key
//! - `capabilities` — Client, Relay, Gateway (any combination)
//! - `endpoints` — transport endpoints (AUTHENTICATED — covered by the signature)
//! - `x25519_circuit_public` — optional, only for gateways
//! - `timestamp` — when the advertisement was signed
//! - `expiry` — when the advertisement expires
//! - `nonce` — 16-byte freshness token (prevents replay)
//! - `signature` — Ed25519 over SIG_CONTEXTS::NODE_ADVERT ‖ CBOR(preimage)
//!
//! ## Freshness / Replay Protection
//!
//! Each advertisement carries a `timestamp`, `expiry`, and `nonce`. The
//! `verify_into_verified()` method checks that the advertisement has not
//! expired. Callers SHOULD also track seen nonces to prevent replay within
//! the validity window. The `nonce` is a 16-byte random value generated at
//! sign time — two advertisements from the same node at different times
//! will have different nonces.

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{derive_node_id, ed25519_sign, ed25519_verify, sha256, sig_contexts};

/// A generic signed node advertisement. Represents ANY ShareNet node —
/// relay, gateway, or multi-role — with a signed set of identity-critical
/// fields including capabilities, endpoints, and optional gateway X25519 key.
///
/// The signature covers ALL fields except `signature` itself, under
/// `SIG_CONTEXTS::NODE_ADVERT`. This means:
/// - The NodeId is authenticated.
/// - The Ed25519 public key is authenticated.
/// - The capabilities are authenticated.
/// - The endpoints are authenticated (endpoint tampering is detected).
/// - The gateway X25519 circuit key (if present) is authenticated.
/// - The timestamp, expiry, and nonce are authenticated (replay protection).
#[derive(Debug, Clone)]
pub struct NodeAdvertisement {
    /// The node's NodeId (`SHA-256("SNP/0.1 node\0" || ed25519_public_key)`).
    pub node_id: [u8; 32],
    /// The node's Ed25519 identity public key (32 bytes).
    pub ed25519_public_key: [u8; 32],
    /// The node's capabilities (any combination of Client, Relay, Gateway).
    pub capabilities: Vec<Capability>,
    /// The node's transport endpoints. These are AUTHENTICATED — they are
    /// inside the signed preimage, so an attacker cannot substitute
    /// different endpoints without invalidating the signature.
    pub endpoints: Vec<TransportEndpoint>,
    /// The node's STATIC X25519 circuit public key. Only present for nodes
    /// with the Gateway capability; `None` for pure relays/clients.
    pub x25519_circuit_public: Option<[u8; 32]>,
    /// When this advertisement was signed (unix seconds).
    pub timestamp: u64,
    /// When this advertisement expires (unix seconds).
    pub expiry: u64,
    /// 16-byte freshness nonce. Generated at sign time. Prevents replay
    /// within the validity window — two advertisements from the same node
    /// at different times have different nonces.
    pub nonce: [u8; 16],
    /// Ed25519 signature over `SIG_CONTEXTS::NODE_ADVERT ‖ CBOR(preimage)`.
    pub signature: [u8; 64],
}

impl NodeAdvertisement {
    /// Construct and sign a `NodeAdvertisement` for a node.
    ///
    /// The `ed25519_secret_key` is used to sign the advertisement. The
    /// `node_id` is derived from the `ed25519_public_key` (invariant I4).
    ///
    /// # Parameters
    /// - `ed25519_secret_key` — the node's Ed25519 secret key.
    /// - `ed25519_public_key` — the node's Ed25519 public key.
    /// - `capabilities` — the node's capabilities.
    /// - `endpoints` — the node's transport endpoints (authenticated).
    /// - `x25519_circuit_public` — `Some` for gateways, `None` for relays.
    /// - `expiry_secs` — how many seconds from now the advertisement expires.
    #[must_use]
    pub fn create_and_sign(
        ed25519_secret_key: &[u8; 32],
        ed25519_public_key: &[u8; 32],
        capabilities: Vec<Capability>,
        endpoints: Vec<TransportEndpoint>,
        x25519_circuit_public: Option<[u8; 32]>,
        expiry_secs: u64,
    ) -> Self {
        let now = now_unix();
        let node_id = derive_node_id(ed25519_public_key);
        let mut nonce = [0u8; 16];
        let _ = getrandom::getrandom(&mut nonce);
        let mut advert = Self {
            node_id,
            ed25519_public_key: *ed25519_public_key,
            capabilities,
            endpoints,
            x25519_circuit_public,
            timestamp: now,
            expiry: now.saturating_add(expiry_secs),
            nonce,
            signature: [0u8; 64],
        };
        advert.sign(ed25519_secret_key);
        advert
    }

    /// Build the canonical CBOR preimage (all fields EXCEPT `signature`).
    fn preimage(&self) -> CborValue {
        let caps: Vec<CborValue> = self
            .capabilities
            .iter()
            .map(|c| CborValue::TextString(c.as_str().to_string()))
            .collect();
        let endpoints: Vec<CborValue> = self
            .endpoints
            .iter()
            .map(|e| e.canonical_cbor())
            .collect();
        CborValue::Map(vec![
            (CborValue::TextString("nodeId".into()), CborValue::ByteString(self.node_id.to_vec())),
            (CborValue::TextString("publicKey".into()), CborValue::ByteString(self.ed25519_public_key.to_vec())),
            (CborValue::TextString("capabilities".into()), CborValue::Array(caps)),
            (CborValue::TextString("endpoints".into()), CborValue::Array(endpoints)),
            (
                CborValue::TextString("x25519CircuitPub".into()),
                match &self.x25519_circuit_public {
                    Some(k) => CborValue::ByteString(k.to_vec()),
                    None => CborValue::Null,
                },
            ),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(self.expiry)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.nonce.to_vec())),
        ])
    }

    /// Sign this advertisement with the given Ed25519 secret key.
    /// Mutates `self.signature` in place.
    pub fn sign(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode of NodeAdvertisement preimage never fails");
        let mut msg = Vec::with_capacity(sig_contexts::NODE_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::NODE_ADVERT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// Verify the advertisement's signature, NodeId↔Ed25519 consistency,
    /// and expiry. If ALL checks pass, returns a `VerifiedNodeAdvertisement`.
    /// Otherwise returns `None`.
    ///
    /// Checks:
    /// 1. Ed25519 signature is valid under `SIG_CONTEXTS::NODE_ADVERT`.
    /// 2. `node_id == SHA-256("SNP/0.1 node\0" || ed25519_public_key)` (I4).
    /// 3. `expiry > now` (not expired).
    ///
    /// Note: callers SHOULD also track seen nonces to prevent replay within
    /// the validity window.
    #[must_use]
    pub fn verify_into_verified(&self) -> Option<VerifiedNodeAdvertisement> {
        // 1. Verify the signature.
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return None;
        };
        let mut msg = Vec::with_capacity(sig_contexts::NODE_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::NODE_ADVERT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.ed25519_public_key, &msg, &self.signature) {
            return None;
        }
        // 2. Verify NodeId ↔ Ed25519 consistency (I4).
        let expected_node_id = derive_node_id(&self.ed25519_public_key);
        if self.node_id != expected_node_id {
            return None;
        }
        // 3. Verify not expired.
        let now = now_unix();
        if self.expiry <= now {
            return None;
        }
        Some(VerifiedNodeAdvertisement { advert: self.clone() })
    }

    /// Check if this advertisement has expired.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expiry <= now
    }
}

/// A `NodeAdvertisement` whose signature has been VERIFIED and whose
/// NodeId↔Ed25519 consistency has been checked and which has not expired.
///
/// This type can ONLY be constructed by
/// [`NodeAdvertisement::verify_into_verified`]. The type system enforces
/// that the routing layer receives authenticated node identity data.
///
/// `VerifiedNodeAdvertisement::descriptor()` produces a
/// [`VerifiedNodeDescriptor`] that carries the authenticated identity +
/// capabilities + endpoints for ANY node role (relay, gateway, multi-role).
#[derive(Debug, Clone)]
pub struct VerifiedNodeAdvertisement {
    advert: NodeAdvertisement,
}

impl VerifiedNodeAdvertisement {
    /// Derive a `VerifiedNodeDescriptor` from this verified advertisement.
    /// This is the ONLY way to obtain a `VerifiedNodeDescriptor` — the
    /// type system enforces that the identity came from a signed, verified
    /// advertisement.
    #[must_use]
    pub fn descriptor(&self) -> VerifiedNodeDescriptor {
        VerifiedNodeDescriptor::from_verified_advert_internal(&self.advert)
    }

    /// Get the NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.advert.node_id
    }

    /// Get the Ed25519 public key.
    #[must_use]
    pub fn ed25519_public_key(&self) -> &[u8; 32] {
        &self.advert.ed25519_public_key
    }

    /// Get the capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.advert.capabilities
    }

    /// Get the authenticated endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[TransportEndpoint] {
        &self.advert.endpoints
    }

    /// Get the X25519 circuit public key (for gateways), or `None`.
    #[must_use]
    pub fn circuit_x25519_pub(&self) -> Option<&[u8; 32]> {
        self.advert.x25519_circuit_public.as_ref()
    }

    /// Get the nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 16] {
        &self.advert.nonce
    }

    /// Get the expiry.
    #[must_use]
    pub fn expiry(&self) -> u64 {
        self.advert.expiry
    }

    /// Check if this node has the Gateway capability.
    #[must_use]
    pub fn is_gateway(&self) -> bool {
        self.advert.capabilities.contains(&Capability::Gateway)
    }

    /// Check if this node has the Relay capability.
    #[must_use]
    pub fn is_relay(&self) -> bool {
        self.advert.capabilities.contains(&Capability::Relay)
    }

    /// Get the inner advertisement (for CBOR serialization, etc.).
    #[must_use]
    pub fn as_ref(&self) -> &NodeAdvertisement {
        &self.advert
    }
}
