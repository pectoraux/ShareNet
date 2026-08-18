//! L1 Identity — re-exported from snp-identity.
//!
//! R2.2 extraction: NodeIdentity and Capability have been moved to the
//! snp-identity crate (L1 layer). This file re-exports them so existing
//! code that imports from `snp_node::node::identity` continues to work
//! without changes.
//!
//! The dependency direction is:
//!   snp-identity (owns identity types)
//!       ↓
//!   snp-node (re-exports + uses)
//!
//! NOT the reverse.
//!
//! The `client()` method is kept here (not in snp-identity) because it
//! depends on the legacy deterministic `CLIENT_SECRET` test seed, which
//! belongs to snp-node's legacy compatibility layer, not to the identity
//! layer.

pub use snp_identity::{Capability, NodeIdentity};

/// Construct the N2.0.1 Client identity (matches the N2.0 `CLIENT_SECRET`).
///
/// This is a legacy deterministic-key constructor used by `Node::new_client()`
/// and legacy demo code. Production code should use `NodeIdentity::from_secret()`
/// with a freshly generated key.
#[must_use]
pub fn client_identity() -> NodeIdentity {
    NodeIdentity::from_secret(crate::legacy::client_secret_key())
}
