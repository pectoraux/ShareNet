//! N2.1.0.1 — Node identity descriptors with verified/unverified distinction.
//!
//! ## Key distinction
//!
//! Three concepts are separated:
//!
//! 1. **`UnverifiedNodeDescriptor`** — raw identity data. No proof of anything.
//! 2. **`IdentityConsistentNodeDescriptor`** — NodeId↔Ed25519 consistency
//!    verified (invariant I4). Can be constructed from `UnverifiedNodeDescriptor`
//!    via `into_consistent()`. This proves the NodeId is the hash of the public
//!    key, but does NOT prove the identity is authentic.
//! 3. **`VerifiedNodeDescriptor`** — the identity came from a VERIFIED
//!    `NodeAdvertisement` (signature checked + NodeId↔Ed25519 consistency
//!    verified + clock validated + role/key consistency checked). This is
//!    the ONLY descriptor type the routing layer accepts. It can ONLY be
//!    constructed via `VerifiedNodeAdvertisement::descriptor()`.
//!
//! **N2.1.0:** `VerifiedNodeDescriptor` is NO LONGER gateway-specific. It
//! works for relays, gateways, and multi-role nodes. The generic
//! `NodeAdvertisement` (in `node_advert.rs`) is the canonical source.

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{derive_node_id, sha256};

// ─── UnverifiedNodeDescriptor ────────────────────────────────────────────────

/// Raw node identity data. No proof of authenticity or consistency.
/// This type exists for internal construction and test fixtures.
/// The routing layer MUST NOT consume it.
#[derive(Debug, Clone)]
pub struct UnverifiedNodeDescriptor {
    /// The node's NodeId.
    pub node_id: [u8; 32],
    /// The node's Ed25519 identity public key (32 bytes).
    pub ed25519_public_key: [u8; 32],
    /// The node's STATIC X25519 circuit public key. `None` for non-gateways.
    pub x25519_circuit_public: Option<[u8; 32]>,
    /// The node's capabilities.
    pub capabilities: Vec<Capability>,
}

impl UnverifiedNodeDescriptor {
    /// Construct for a relay (no X25519 circuit key).
    #[must_use]
    pub fn for_relay(node_id: [u8; 32], ed25519_public_key: [u8; 32]) -> Self {
        Self {
            node_id,
            ed25519_public_key,
            x25519_circuit_public: None,
            capabilities: vec![Capability::Relay],
        }
    }

    /// Construct for a gateway (with X25519 circuit key).
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

    /// Verify NodeId↔Ed25519 consistency (invariant I4):
    /// `NodeId == SHA-256("SNP/0.1 node\0" || ed25519_public_key)`.
    #[must_use]
    pub fn verify_node_id_consistency(&self) -> bool {
        let expected = derive_node_id(&self.ed25519_public_key);
        self.node_id == expected
    }

    /// Convert to an `IdentityConsistentNodeDescriptor` after verifying the
    /// NodeId↔Ed25519 consistency. Returns `None` if the check fails.
    ///
    /// **N2.0.7.3:** This is NOT `into_verified()` — it does NOT produce a
    /// `VerifiedNodeDescriptor`. It produces an
    /// `IdentityConsistentNodeDescriptor`, which proves the NodeId is the
    /// hash of the public key but does NOT prove the identity is authentic.
    /// Only `VerifiedGatewayAdvertisement::descriptor()` produces a
    /// `VerifiedNodeDescriptor`.
    #[must_use]
    pub fn into_consistent(self) -> Option<IdentityConsistentNodeDescriptor> {
        if !self.verify_node_id_consistency() {
            return None;
        }
        Some(IdentityConsistentNodeDescriptor { inner: self })
    }
}

// ─── IdentityConsistentNodeDescriptor ────────────────────────────────────────

/// A node descriptor whose NodeId↔Ed25519 consistency has been verified
/// (invariant I4: `NodeId == SHA-256("SNP/0.1 node\0" || ed25519_public_key)`).
///
/// **N2.0.7.3:** This type replaces the N2.0.7.2 `VerifiedNodeDescriptor`
/// that was produced by `into_verified()`. The old name was misleading —
/// "verified" implied authentication, but the function only proved
/// internal consistency.
///
/// This type does NOT prove the identity came from a signed advertisement.
/// For authenticated identity, use [`VerifiedNodeDescriptor`] (which can
/// only be constructed from a [`VerifiedGatewayAdvertisement`]).
#[derive(Debug, Clone)]
pub struct IdentityConsistentNodeDescriptor {
    inner: UnverifiedNodeDescriptor,
}

impl IdentityConsistentNodeDescriptor {
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

    /// Get the X25519 circuit public key (for gateways), or `None`.
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

    /// Compute the canonical CBOR encoding of this descriptor for
    /// RouteCommitment. Uses the existing `snp-cbor` canonical encoding
    /// (NOT manual concatenation).
    #[must_use]
    pub fn canonical_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("nodeId".into()), CborValue::ByteString(self.inner.node_id.to_vec())),
            (CborValue::TextString("publicKey".into()), CborValue::ByteString(self.inner.ed25519_public_key.to_vec())),
            (
                CborValue::TextString("x25519CircuitPub".into()),
                match &self.inner.x25519_circuit_public {
                    Some(k) => CborValue::ByteString(k.to_vec()),
                    None => CborValue::Null,
                },
            ),
            (
                CborValue::TextString("capabilities".into()),
                CborValue::Array(
                    self.inner.capabilities.iter().map(|c| CborValue::TextString(c.as_str().to_string())).collect(),
                ),
            ),
        ])
    }
}

// ─── VerifiedNodeDescriptor ──────────────────────────────────────────────────

/// A node descriptor whose identity has been AUTHENTICATED — it came from a
/// [`VerifiedNodeAdvertisement`] (signature checked + NodeId↔Ed25519
/// consistency verified + clock validated + role/key consistency checked).
///
/// This type can ONLY be constructed via
/// `VerifiedNodeAdvertisement::descriptor()`. There is NO
/// `into_verified()` path from `UnverifiedNodeDescriptor` or
/// `IdentityConsistentNodeDescriptor`. The type system enforces that
/// the routing layer receives authenticated identity data.
///
/// **N2.1.0:** `VerifiedNodeDescriptor` is NO LONGER gateway-specific.
/// It works for relays, gateways, and multi-role nodes. The generic
/// `NodeAdvertisement` is the canonical source.
///
/// The routing layer (`Route`, `RouteHop`, `send_via_route`) consumes
/// `VerifiedNodeDescriptor` — it cannot accidentally use unverified or
/// merely-consistent identity data.
#[derive(Debug, Clone)]
pub struct VerifiedNodeDescriptor {
    inner: IdentityConsistentNodeDescriptor,
}

impl VerifiedNodeDescriptor {
    /// Construct a `VerifiedNodeDescriptor` from a verified
    /// `NodeAdvertisement` (the generic N2.1.0 path). This is the
    /// canonical way to obtain a `VerifiedNodeDescriptor` for ANY node
    /// role (relay, gateway, multi-role).
    #[must_use]
    pub(crate) fn from_verified_advert_internal(advert: &super::node_advert::NodeAdvertisement) -> Self {
        let unverified = UnverifiedNodeDescriptor {
            node_id: advert.node_id,
            ed25519_public_key: advert.ed25519_public_key,
            x25519_circuit_public: advert.x25519_circuit_public,
            capabilities: advert.capabilities.clone(),
        };
        let consistent = unverified.into_consistent()
            .expect("NodeId consistency was already verified by verify_into_verified()");
        VerifiedNodeDescriptor { inner: consistent }
    }

    /// Get the NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.inner.node_id()
    }

    /// Get the Ed25519 public key.
    #[must_use]
    pub fn ed25519_public_key(&self) -> &[u8; 32] {
        self.inner.ed25519_public_key()
    }

    /// Get the X25519 circuit public key (for gateways), or `None`.
    #[must_use]
    pub fn circuit_x25519_pub(&self) -> Option<&[u8; 32]> {
        self.inner.circuit_x25519_pub()
    }

    /// Get the capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        self.inner.capabilities()
    }

    /// Check if this descriptor has the Gateway capability.
    #[must_use]
    pub fn is_gateway(&self) -> bool {
        self.inner.is_gateway()
    }

    /// Check if this descriptor has the Relay capability.
    #[must_use]
    pub fn is_relay(&self) -> bool {
        self.inner.is_relay()
    }

    /// Verify NodeId↔Ed25519 consistency (defence in depth — should always
    /// be true since it was checked at construction).
    #[must_use]
    pub fn verify_node_id_consistency(&self) -> bool {
        self.inner.inner.verify_node_id_consistency()
    }

    /// Compute the canonical CBOR encoding of this descriptor for
    /// RouteCommitment.
    #[must_use]
    pub fn canonical_cbor(&self) -> CborValue {
        self.inner.canonical_cbor()
    }
}

// ─── VerifiedGatewayAdvertisement ────────────────────────────────────────────

/// A `GatewayAdvertisement` whose signature has been VERIFIED.
///
/// **N2.0.7.3:** This wrapper can ONLY be constructed by calling
/// [`GatewayAdvertisement::verify_into_verified`], which checks the Ed25519
/// signature. An arbitrary `GatewayAdvertisement` CANNOT be directly
/// converted to a `VerifiedGatewayAdvertisement` — the verification step
/// is enforced by the type system.
///
/// This is the authenticated source from which `VerifiedNodeDescriptor`s
/// are derived.
#[derive(Debug, Clone)]
pub struct VerifiedGatewayAdvertisement {
    advert: GatewayAdvertisement,
}

impl VerifiedGatewayAdvertisement {
    /// Get the inner advertisement.
    #[must_use]
    pub fn as_ref(&self) -> &GatewayAdvertisement {
        &self.advert
    }

    /// Derive a `VerifiedNodeDescriptor` from this verified gateway advertisement.
    /// This is the gateway-specific path; the generic path is via
    /// `VerifiedNodeAdvertisement::descriptor()`.
    ///
    /// Also verifies NodeId↔Ed25519 consistency (invariant I4). Returns
    /// `None` if the consistency check fails.
    #[must_use]
    pub fn descriptor(&self) -> Option<VerifiedNodeDescriptor> {
        let unverified = UnverifiedNodeDescriptor {
            node_id: self.advert.node_id,
            ed25519_public_key: self.advert.public_key,
            x25519_circuit_public: Some(self.advert.circuit_x25519_pub),
            capabilities: self.advert.capabilities.clone(),
        };
        let consistent = unverified.into_consistent()?;
        Some(VerifiedNodeDescriptor { inner: consistent })
    }

    /// Get the gateway's NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.advert.node_id
    }

    /// Get the gateway's Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.advert.public_key
    }

    /// Get the gateway's X25519 circuit public key.
    #[must_use]
    pub fn circuit_x25519_pub(&self) -> &[u8; 32] {
        &self.advert.circuit_x25519_pub
    }

    /// Get the gateway's listen address.
    #[must_use]
    pub fn listen_addr(&self) -> &str {
        &self.advert.listen_addr
    }

    /// Get the gateway's discovery address.
    #[must_use]
    pub fn discovery_addr(&self) -> &str {
        &self.advert.discovery_addr
    }
}

/// Verify a `GatewayAdvertisement`'s signature and return a
/// `VerifiedGatewayAdvertisement` wrapper.
///
/// This is the ONLY way to construct a `VerifiedGatewayAdvertisement`.
/// The signature is checked against the advertisement's `public_key` under
/// `SIG_CONTEXTS::GATEWAY_ADVERT`.
impl GatewayAdvertisement {
    /// Verify the advertisement's signature. If valid, return a
    /// [`VerifiedGatewayAdvertisement`] wrapper. If invalid, return `None`.
    ///
    /// This is the entry point for authenticated identity — the resulting
    /// `VerifiedGatewayAdvertisement` can produce a `VerifiedNodeDescriptor`
    /// via `descriptor()`.
    #[must_use]
    pub fn verify_into_verified(&self) -> Option<VerifiedGatewayAdvertisement> {
        if !self.verify() {
            return None;
        }
        Some(VerifiedGatewayAdvertisement {
            advert: self.clone(),
        })
    }
}

// ─── TransportEndpoint ───────────────────────────────────────────────────────

/// A transport-neutral endpoint locator. Not an informal string — a typed
/// enum. Endpoints are bound to a `VerifiedNodeDescriptor` via the `RouteHop`
/// structure; an endpoint is only usable for Node X if it was obtained
/// through an authenticated route construction mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportEndpoint {
    /// A TCP endpoint (e.g. `"127.0.0.1:38507"`).
    Tcp(String),
    /// A BLE endpoint. NOT YET IMPLEMENTED.
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

    /// Compute the canonical CBOR encoding of this endpoint for
    /// RouteCommitment. Uses `snp-cbor` canonical encoding.
    #[must_use]
    pub fn canonical_cbor(&self) -> CborValue {
        let (type_tag, addr) = match self {
            Self::Tcp(s) => ("tcp", s),
            Self::Ble(s) => ("ble", s),
            Self::WifiDirect(s) => ("wifi-direct", s),
            Self::NearbyConnections(s) => ("nearby", s),
        };
        CborValue::Map(vec![
            (CborValue::TextString("type".into()), CborValue::TextString(type_tag.to_string())),
            (CborValue::TextString("addr".into()), CborValue::TextString(addr.to_string())),
        ])
    }
}

/// Verify a `VerifiedNodeDescriptor`'s NodeId consistency. Used by
/// `Route::validate()` for defence in depth.
#[must_use]
pub fn verify_node_id_consistency(desc: &VerifiedNodeDescriptor) -> bool {
    desc.verify_node_id_consistency()
}

// N2.1.0: The dangerous backward-compat alias that mapped `NodeDescriptor`
// to `UnverifiedNodeDescriptor` has been REMOVED. Developers must use
// explicit type names:
//   - UnverifiedNodeDescriptor (raw, no proof)
//   - IdentityConsistentNodeDescriptor (NodeId↔Ed25519 verified)
//   - VerifiedNodeDescriptor (authenticated from VerifiedNodeAdvertisement)
