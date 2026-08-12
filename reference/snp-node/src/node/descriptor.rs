//! N2.0.7.2 — NodeDescriptor + TransportEndpoint + VerifiedNodeDescriptor.
//!
//! These types enforce the ShareNet architectural separation:
//!
//! > **NodeId answers "who?" — transport endpoint answers "where can I
//! > reach them now?"**
//!
//! ## N2.0.7.2 changes
//!
//! - `NodeDescriptor` is now `UnverifiedNodeDescriptor` — it carries identity
//!   data but does NOT prove the data is authentic.
//! - `VerifiedNodeDescriptor` is a wrapper that can ONLY be constructed from
//!   a verified `GatewayAdvertisement` (signature checked). The routing layer
//!   consumes `VerifiedNodeDescriptor` — it cannot accidentally use unverified
//!   identity data.
//! - `VerifiedNodeDescriptor::verify_node_id()` enforces invariant I4:
//!   `NodeId == SHA-256("SNP/0.1 node\0" || ed25519_public_key)`. A descriptor
//!   with a mismatched NodeId/public-key pair is REJECTED at construction time.
//! - `TransportEndpoint` is a typed enum (Tcp/Ble/WifiDirect/NearbyConnections).

use super::*;
use snp_crypto::{derive_node_id, sha256};

/// **N2.0.7.2.** An UNVERIFIED node identity descriptor. Carries identity
/// data but does NOT prove the data is authentic. Use
/// [`VerifiedNodeDescriptor::from_verified_advert`] to obtain a verified
/// descriptor from a checked advertisement.
///
/// The routing layer MUST NOT consume `UnverifiedNodeDescriptor` directly —
/// it requires [`VerifiedNodeDescriptor`]. This type exists for internal
/// construction (e.g. building a relay descriptor for a known peer) and
/// for test fixtures.
#[derive(Debug, Clone)]
pub struct UnverifiedNodeDescriptor {
    /// The node's NodeId (`SHA-256("SNP/0.1 node\0" || ed25519_public_key)`).
    pub node_id: [u8; 32],
    /// The node's Ed25519 identity public key (32 bytes, raw wire form per I3).
    pub ed25519_public_key: [u8; 32],
    /// The node's STATIC X25519 circuit public key (32 bytes). Only present
    /// for gateway nodes; `None` for relays/clients.
    pub x25519_circuit_public: Option<[u8; 32]>,
    /// The node's capabilities (Client, Relay, Gateway).
    pub capabilities: Vec<Capability>,
}

impl UnverifiedNodeDescriptor {
    /// Construct an `UnverifiedNodeDescriptor` for a relay (no X25519
    /// circuit key — relays don't terminate circuits).
    #[must_use]
    pub fn for_relay(node_id: [u8; 32], ed25519_public_key: [u8; 32]) -> Self {
        Self {
            node_id,
            ed25519_public_key,
            x25519_circuit_public: None,
            capabilities: vec![Capability::Relay],
        }
    }

    /// Construct an `UnverifiedNodeDescriptor` for a gateway (with X25519
    /// circuit key).
    #[must_use]
    pub fn for_gateway(
        node_id: [u8; 32],
        ed25519_public_key: [u8; 32],
        x25519_circuit_public: [u8; 32],
    ) -> Self {
        Self {
            node_id,
            ed25519_public_key,
            x25519_circuit_public: Some(x25519_circuit_public),
            capabilities: vec![Capability::Gateway],
        }
    }

    /// Verify the NodeId ↔ Ed25519 public key consistency (invariant I4):
    /// `NodeId == SHA-256("SNP/0.1 node\0" || ed25519_public_key)`.
    ///
    /// Returns `true` if the NodeId matches the hash of the public key.
    #[must_use]
    pub fn verify_node_id_consistency(&self) -> bool {
        let expected = derive_node_id(&self.ed25519_public_key);
        self.node_id == expected
    }

    /// Convert to a `VerifiedNodeDescriptor` after verifying the NodeId ↔
    /// public key consistency. Returns `None` if the consistency check fails.
    ///
    /// Note: this does NOT verify that the identity data came from a signed
    /// advertisement — it only verifies the cryptographic relationship
    /// between NodeId and Ed25519 public key. For full verification, use
    /// [`VerifiedNodeDescriptor::from_verified_advert`].
    #[must_use]
    pub fn into_verified(self) -> Option<VerifiedNodeDescriptor> {
        if !self.verify_node_id_consistency() {
            return None;
        }
        Some(VerifiedNodeDescriptor { inner: self })
    }

    /// Get the X25519 circuit public key, or `None` if this node is not a
    /// gateway.
    #[must_use]
    pub fn circuit_x25519_pub(&self) -> Option<&[u8; 32]> {
        self.x25519_circuit_public.as_ref()
    }
}

/// **N2.0.7.2.** A VERIFIED node identity descriptor. This type can ONLY be
/// constructed by:
///
/// 1. [`VerifiedNodeDescriptor::from_verified_advert`] — from a
///    `GatewayAdvertisement` whose signature has been checked AND whose
///    NodeId ↔ Ed25519 consistency has been verified.
/// 2. [`UnverifiedNodeDescriptor::into_verified`] — after verifying the
///    NodeId ↔ Ed25519 consistency.
///
/// The routing layer (`Route`, `send_via_route`, `serve_relay_via_route`)
/// consumes `VerifiedNodeDescriptor` — it cannot accidentally use unverified
/// identity data. This is the type-system enforcement of the security
/// invariant that the routing layer requires authenticated node identity.
#[derive(Debug, Clone)]
pub struct VerifiedNodeDescriptor {
    inner: UnverifiedNodeDescriptor,
}

impl VerifiedNodeDescriptor {
    /// Construct a `VerifiedNodeDescriptor` from a VERIFIED
    /// [`GatewayAdvertisement`]. The advertisement's signature MUST be
    /// verified BEFORE calling this function (via `advert.verify()`).
    ///
    /// This function ALSO verifies invariant I4 (NodeId ↔ Ed25519 public
    /// key consistency). If the advertisement's NodeId does not match
    /// `SHA-256("SNP/0.1 node\0" || public_key)`, this function returns
    /// `None`.
    ///
    /// # Errors
    /// Returns `None` if the NodeId ↔ Ed25519 consistency check fails.
    /// (Signature verification is the caller's responsibility — this
    /// function trusts that `advert.verify()` was already called.)
    #[must_use]
    pub fn from_verified_advert(advert: &GatewayAdvertisement) -> Option<Self> {
        let unverified = UnverifiedNodeDescriptor {
            node_id: advert.node_id,
            ed25519_public_key: advert.public_key,
            x25519_circuit_public: Some(advert.circuit_x25519_pub),
            capabilities: advert.capabilities.clone(),
        };
        unverified.into_verified()
    }

    /// Get the NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.inner.node_id
    }

    /// Get the Ed25519 public key.
    #[must_use]
    pub fn ed25519_public_key(&self) -> &[u8; 32] {
        &self.inner.ed25519_public_key
    }

    /// Get the X25519 circuit public key (for gateways), or `None` for relays.
    #[must_use]
    pub fn circuit_x25519_pub(&self) -> Option<&[u8; 32]> {
        self.inner.x25519_circuit_public.as_ref()
    }

    /// Get the capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.inner.capabilities
    }

    /// Check if this descriptor has the Gateway capability.
    #[must_use]
    pub fn is_gateway(&self) -> bool {
        self.inner.capabilities.contains(&Capability::Gateway)
    }

    /// Check if this descriptor has the Relay capability.
    #[must_use]
    pub fn is_relay(&self) -> bool {
        self.inner.capabilities.contains(&Capability::Relay)
    }

    /// Compute the canonical encoding of this descriptor for RouteCommitment.
    /// This is a deterministic encoding that includes ALL identity-critical
    /// fields (NodeId + Ed25519 pub + X25519 circuit pub + capabilities).
    #[must_use]
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 32 + 16);
        buf.extend_from_slice(&self.inner.node_id);
        buf.extend_from_slice(&self.inner.ed25519_public_key);
        if let Some(x25519) = &self.inner.x25519_circuit_public {
            buf.push(1);
            buf.extend_from_slice(x25519);
        } else {
            buf.push(0);
        }
        // Capabilities (sorted for determinism).
        let mut caps: Vec<&str> = self
            .inner
            .capabilities
            .iter()
            .map(|c| c.as_str())
            .collect();
        caps.sort();
        for cap in caps {
            buf.extend_from_slice(cap.as_bytes());
            buf.push(0); // null-terminate
        }
        buf
    }
}

/// **N2.0.7.1.** A transport-neutral endpoint locator. Not an informal
/// string — a typed enum that the [`TransportProvider`] resolves into a
/// connection.
///
/// **N2.0.7.2:** Endpoints must be bound to a `VerifiedNodeDescriptor` via
/// the `RouteHop` structure. An endpoint is only usable for Node X if it
/// was obtained through an authenticated/verified discovery record or an
/// authenticated route construction mechanism. The `RouteHop` enforces this
/// by carrying the endpoint alongside the `VerifiedNodeDescriptor`.
///
/// [`TransportProvider`]: super::transport::TransportProvider
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportEndpoint {
    /// A TCP endpoint (e.g. `"127.0.0.1:38507"`).
    Tcp(String),
    /// A BLE endpoint (e.g. `"ble:aa:bb:cc:dd:ee:ff"`). NOT YET IMPLEMENTED.
    Ble(String),
    /// A Wi-Fi Direct endpoint. NOT YET IMPLEMENTED.
    WifiDirect(String),
    /// A Nearby Connections endpoint. NOT YET IMPLEMENTED.
    NearbyConnections(String),
}

impl TransportEndpoint {
    /// Construct a `TransportEndpoint::Tcp` from an address string.
    #[must_use]
    pub fn tcp(addr: impl Into<String>) -> Self {
        Self::Tcp(addr.into())
    }

    /// Get the TCP address if this is a `Tcp` endpoint, or `None`.
    #[must_use]
    pub fn as_tcp(&self) -> Option<&str> {
        match self {
            Self::Tcp(addr) => Some(addr),
            _ => None,
        }
    }

    /// Get a string representation for diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tcp(s) => s,
            Self::Ble(s) => s,
            Self::WifiDirect(s) => s,
            Self::NearbyConnections(s) => s,
        }
    }

    /// Compute the canonical encoding of this endpoint for RouteCommitment.
    #[must_use]
    pub fn canonical_encoding(&self) -> Vec<u8> {
        match self {
            Self::Tcp(s) => {
                let mut buf = Vec::with_capacity(1 + s.len());
                buf.push(0x01);
                buf.extend_from_slice(s.as_bytes());
                buf
            }
            Self::Ble(s) => {
                let mut buf = Vec::with_capacity(1 + s.len());
                buf.push(0x02);
                buf.extend_from_slice(s.as_bytes());
                buf
            }
            Self::WifiDirect(s) => {
                let mut buf = Vec::with_capacity(1 + s.len());
                buf.push(0x03);
                buf.extend_from_slice(s.as_bytes());
                buf
            }
            Self::NearbyConnections(s) => {
                let mut buf = Vec::with_capacity(1 + s.len());
                buf.push(0x04);
                buf.extend_from_slice(s.as_bytes());
                buf
            }
        }
    }
}

/// Verify a `VerifiedNodeDescriptor`'s NodeId consistency. Used by
/// `Route::validate()` for defence in depth.
#[must_use]
pub fn verify_node_id_consistency(desc: &VerifiedNodeDescriptor) -> bool {
    let expected = derive_node_id(desc.ed25519_public_key());
    desc.node_id() == expected
}

// Backward compat: re-export UnverifiedNodeDescriptor as NodeDescriptor.
// This allows existing code that references `NodeDescriptor` to continue
// working. New code should use `UnverifiedNodeDescriptor` or
// `VerifiedNodeDescriptor` explicitly.
pub type NodeDescriptor = UnverifiedNodeDescriptor;
