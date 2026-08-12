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

    /// Construct a gateway identity for the given choice.
    ///
    /// **N2.0.3: DEPRECATED.** This constructor uses
    /// [`crate::legacy::GatewayChoice`], which is now confined to legacy/demo code.
    /// New production code MUST use [`NodeIdentity::from_secret`] with an
    /// arbitrary Ed25519 secret key — gateways are NOT required to be one of
    /// the two pre-N2.0.2 `GatewayChoice::A`/`GatewayChoice::B` identities.
    ///
    /// **Why not `#[cfg(test)]`?** The N2.0.3 task spec suggested marking
    /// this constructor `#[cfg(test)]` so it cannot leak into production
    /// builds. However, `#[cfg(test)]` on a `pub fn` in a library crate
    /// makes it invisible to INTEGRATION tests (in `tests/`), which are
    /// separate crates. The integration tests in `tests/n201_sessions.rs`
    /// and `tests/n202_protocol.rs` still use this constructor (they are
    /// explicitly testing the N2.0/N2.0.1 backward-compat path). The
    /// `#[deprecated]` attribute is sufficient to discourage production
    /// use; the static test `gateway_choice_not_in_production_code` at the
    /// bottom of this file enforces that `GatewayChoice` is NOT imported
    /// at the top level of `node.rs` (so production code in this module
    /// cannot construct a `GatewayChoice` value to pass to this function).
    #[deprecated(
        since = "N2.0.2",
        note = "Use NodeIdentity::from_secret(arbitrary_secret) instead. \
                The GatewayChoice-based constructor is retained for N2.0/N2.0.1 backward compat."
    )]
    #[must_use]
    pub fn gateway(gw: crate::legacy::GatewayChoice) -> Self {
        Self::from_secret(crate::legacy::gateway_secret_for(gw))
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

