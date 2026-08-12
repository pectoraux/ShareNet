//! N2.0.7.1 — NodeDescriptor + TransportEndpoint: the authenticated identity
//! and transport-neutral endpoint abstractions.
//!
//! These types enforce the ShareNet architectural separation:
//!
//! > **NodeId answers "who?" — transport endpoint answers "where can I
//! > reach them now?"**
//!
//! A [`NodeDescriptor`] carries the authenticated identity of a node (NodeId
//! + Ed25519 public key + X25519 circuit public key + capabilities). It is
//! obtained from a VERIFIED [`GatewayAdvertisement`] (or equivalent discovery
//! source) and is the cryptographic identity that a [`Route`](super::Route)
//! references.
//!
//! A [`TransportEndpoint`] is a transport-neutral locator — not an informal
//! string. Currently only TCP is implemented, but the enum is extensible to
//! BLE, Wi-Fi Direct, Nearby Connections, etc. The
//! [`TransportProvider`](super::transport) trait resolves a
//! `TransportEndpoint` into a connection.

use super::*;

/// **N2.0.7.1.** The authenticated identity descriptor of a node. Carries:
///
/// - `node_id` — the stable NodeId (`SHA-256("SNP/0.1 node\0" || ed25519_public_key)`).
/// - `ed25519_public_key` — the Ed25519 identity public key (for signature verification).
/// - `x25519_circuit_public` — the STATIC X25519 circuit public key (only
///   present for gateway nodes; `None` for relays/clients). Used for
///   fresh-ephemeral circuit key establishment via
///   `seal_circuit_payload_with_fresh_eph`.
/// - `capabilities` — the node's capabilities (Client, Relay, Gateway).
///
/// A `NodeDescriptor` is obtained from a VERIFIED discovery source (e.g. a
/// `GatewayAdvertisement` whose signature has been checked). It is the
/// cryptographic identity that a [`Route`](super::Route) references — the
/// Route does NOT duplicate `ed25519_public_key` / `x25519_circuit_public`
/// as separate parameters; they come from the `NodeDescriptor` carried in
/// the Route's `hop_details`.
#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    /// The node's NodeId (`SHA-256("SNP/0.1 node\0" || ed25519_public_key)`).
    pub node_id: [u8; 32],
    /// The node's Ed25519 identity public key (32 bytes, raw wire form per I3).
    pub ed25519_public_key: [u8; 32],
    /// The node's STATIC X25519 circuit public key (32 bytes). Only present
    /// for gateway nodes; `None` for relays/clients. Used for
    /// fresh-ephemeral circuit key establishment.
    pub x25519_circuit_public: Option<[u8; 32]>,
    /// The node's capabilities (Client, Relay, Gateway).
    pub capabilities: Vec<Capability>,
}

impl NodeDescriptor {
    /// Construct a `NodeDescriptor` from a VERIFIED [`GatewayAdvertisement`].
    ///
    /// The advertisement's signature MUST be verified BEFORE calling this
    /// function. The resulting `NodeDescriptor` carries the gateway's
    /// authenticated Ed25519 public key + X25519 circuit public key.
    #[must_use]
    pub fn from_verified_advert(advert: &GatewayAdvertisement) -> Self {
        Self {
            node_id: advert.node_id,
            ed25519_public_key: advert.public_key,
            x25519_circuit_public: Some(advert.circuit_x25519_pub),
            capabilities: advert.capabilities.clone(),
        }
    }

    /// Construct a `NodeDescriptor` for a relay (no X25519 circuit key —
    /// relays don't terminate circuits).
    #[must_use]
    pub fn for_relay(node_id: [u8; 32], ed25519_public_key: [u8; 32]) -> Self {
        Self {
            node_id,
            ed25519_public_key,
            x25519_circuit_public: None,
            capabilities: vec![Capability::Relay],
        }
    }

    /// Get the X25519 circuit public key, or `None` if this node is not a
    /// gateway (relays/clients don't have one).
    #[must_use]
    pub fn circuit_x25519_pub(&self) -> Option<&[u8; 32]> {
        self.x25519_circuit_public.as_ref()
    }
}

/// **N2.0.7.1.** A transport-neutral endpoint locator. Not an informal
/// string — a typed enum that the [`TransportProvider`] resolves into a
/// connection.
///
/// Currently only TCP is implemented, but the enum is extensible to BLE,
/// Wi-Fi Direct, Nearby Connections, etc. The important architectural
/// property is that a [`Route`](super::Route) does NOT carry raw strings
/// — it carries `TransportEndpoint` values that the runtime resolves via
/// the transport abstraction.
///
/// [`TransportProvider`]: super::transport::TransportProvider
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportEndpoint {
    /// A TCP endpoint (e.g. `"127.0.0.1:38507"`). Resolved by
    /// `AsyncTcpTransportProvider::connect`.
    Tcp(String),
    /// A BLE endpoint (e.g. `"ble:aa:bb:cc:dd:ee:ff"`). NOT YET IMPLEMENTED —
    /// the Android platform will implement a `BleTransportProvider` that
    /// resolves this. Included here to prove the enum is extensible.
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
}
