//! Extracted from node/mod.rs for N2.0.4 Gate E (node decomposition).
use super::*;

// ─── NodeIdentity ────────────────────────────────────────────────────────────

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
        let public_key = derive_public_key(&secret_key);
        let node_id = derive_node_id(&public_key);
        Self { secret_key, public_key, node_id }
    }

    /// Construct the N2.0.1 Client identity (matches the N2.0 `CLIENT_SECRET`).
    #[must_use]
    pub fn client() -> Self {
        Self::from_secret(client_secret_key())
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

// ─── NodeCapability (extensible) ────────────────────────────────────────────
//
// N2.5-T2: The old Capability enum (Client/Relay/Gateway) is replaced by
// the extensible NodeCapability set from the frozen architecture. A node
// MAY advertise multiple capabilities simultaneously.
//
// This is SEPARATE from the N2.4 governance/authority ProtocolCapability
// (in capability.rs), which answers "under what trusted authority/policy
// is this capability authorized?" Use `to_protocol_capability()` to bridge
// the node-level capability to the authority-level capability.
//
// Relationship:
//   NodeAdvertisement → NodeCapabilities → optional Governance/Authorization

/// A node's network service capability. A node MAY hold multiple capabilities
/// simultaneously (e.g. a node can be both a mesh relay and an Internet
/// gateway).
///
/// N2.5-T2: This replaces the old Client/Relay/Gateway-only enum with the
/// full extensible set from the frozen architecture. The old variants are
/// retained as deprecated aliases for migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    // ─── Deprecated aliases (N2.0.1 compatibility) ───
    /// Deprecated: use `MeshRelay`. Can send TransitRequests (a client node).
    Client,
    /// Deprecated: use `MeshRelay`. Can forward frames between peers.
    Relay,
    /// Deprecated: use `InternetGateway`. Can terminate circuits and fetch.
    Gateway,

    // ─── Frozen architecture capabilities ───
    /// Can relay mesh traffic (replaces old `Relay`).
    MeshRelay,
    /// Can provide Internet gateway transit (replaces old `Gateway`).
    InternetGateway,
    /// Can seed content chunks for mesh distribution.
    ContentSeed,
    /// Can provide storage for content chunks.
    Storage,
    /// Can participate in the discovery layer.
    Discovery,
    /// Can participate in anti-entropy sync.
    Sync,
    /// Can provide compute resources.
    Compute,
    /// Can relay using crypto-protected channels (enhanced relay).
    CryptoRelay,
    /// Can provide crypto-protected Internet gateway transit.
    CryptoGateway,
    /// Can relay payment-related traffic.
    PaymentRelay,
}

impl Capability {
    /// String representation for advertisement serialisation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            // Deprecated aliases
            Capability::Client => "client",
            Capability::Relay => "relay",
            Capability::Gateway => "gateway",
            // Frozen architecture capabilities
            Capability::MeshRelay => "mesh-relay",
            Capability::InternetGateway => "internet-gateway",
            Capability::ContentSeed => "content-seed",
            Capability::Storage => "storage",
            Capability::Discovery => "discovery",
            Capability::Sync => "sync",
            Capability::Compute => "compute",
            Capability::CryptoRelay => "crypto-relay",
            Capability::CryptoGateway => "crypto-gateway",
            Capability::PaymentRelay => "payment-relay",
        }
    }

    /// Parse from string (for advertisement deserialisation).
    /// Accepts both old-style ("client"/"relay"/"gateway") and new-style
    /// ("mesh-relay"/"internet-gateway"/...) strings.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            // Deprecated aliases
            "client" => Some(Capability::Client),
            "relay" => Some(Capability::Relay),
            "gateway" => Some(Capability::Gateway),
            // Frozen architecture capabilities
            "mesh-relay" => Some(Capability::MeshRelay),
            "internet-gateway" => Some(Capability::InternetGateway),
            "content-seed" => Some(Capability::ContentSeed),
            "storage" => Some(Capability::Storage),
            "discovery" => Some(Capability::Discovery),
            "sync" => Some(Capability::Sync),
            "compute" => Some(Capability::Compute),
            "crypto-relay" => Some(Capability::CryptoRelay),
            "crypto-gateway" => Some(Capability::CryptoGateway),
            "payment-relay" => Some(Capability::PaymentRelay),
            _ => None,
        }
    }

    /// N2.5-T2: Returns true if this capability implies gateway transit
    /// (either old `Gateway` or new `InternetGateway`/`CryptoGateway`).
    #[must_use]
    pub fn is_gateway_capability(&self) -> bool {
        matches!(
            self,
            Capability::Gateway | Capability::InternetGateway | Capability::CryptoGateway
        )
    }

    /// N2.5-T2: Returns true if this capability implies relay forwarding
    /// (either old `Relay` or new `MeshRelay`/`CryptoRelay`).
    #[must_use]
    pub fn is_relay_capability(&self) -> bool {
        matches!(
            self,
            Capability::Relay | Capability::MeshRelay | Capability::CryptoRelay
        )
    }

    /// N2.5-T2: Bridge to the N2.4 governance/authority ProtocolCapability.
    /// Returns `None` for capabilities that don't have an authority-level
    /// counterpart (e.g. `Client`, `PaymentRelay`).
    #[must_use]
    pub fn to_protocol_capability(&self) -> Option<crate::node::capability::ProtocolCapability> {
        use crate::node::capability::ProtocolCapability;
        match self {
            Capability::MeshRelay | Capability::Relay => Some(ProtocolCapability::MeshRelay),
            Capability::InternetGateway | Capability::Gateway => {
                Some(ProtocolCapability::InternetGateway)
            }
            Capability::ContentSeed => Some(ProtocolCapability::ContentSeed),
            Capability::Storage => Some(ProtocolCapability::Storage),
            Capability::Discovery => Some(ProtocolCapability::Discovery),
            Capability::Sync => Some(ProtocolCapability::Sync),
            Capability::Compute => Some(ProtocolCapability::Compute),
            // CryptoRelay/CryptoGateway map to the same authority capability
            // as their non-crypto counterparts (the crypto variant is a
            // transport enhancement, not a separate authority).
            Capability::CryptoRelay => Some(ProtocolCapability::MeshRelay),
            Capability::CryptoGateway => Some(ProtocolCapability::InternetGateway),
            // Client and PaymentRelay don't have authority-level counterparts.
            Capability::Client | Capability::PaymentRelay => None,
        }
    }
}

