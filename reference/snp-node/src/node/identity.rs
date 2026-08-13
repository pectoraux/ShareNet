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

// ─── Capability ──────────────────────────────────────────────────────────────

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

