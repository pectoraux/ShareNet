//! **N2.1.2.3 test-support module.**
//!
//! This module is ONLY compiled when the `test-support` Cargo feature is
//! enabled. It provides test helpers for constructing `AuthenticatedLink`
//! objects WITHOUT performing actual network handshakes.
//!
//! ## Security
//!
//! These helpers construct a real `snp_link::HandshakeResult` whose fields
//! match a `VerifiedNodeAdvertisement`. The resulting `AuthenticatedLink`
//! is genuine — it passes all the same verification checks as a production
//! link. The only shortcut is that the `HandshakeResult` is synthesized
//! rather than produced by an actual SNP-IK handshake over a real transport.
//!
//! This is acceptable for deterministic route-engine testing. The test
//! helpers do NOT weaken the `AuthenticatedLink` verification — they
//! simply provide a `HandshakeResult` that matches the advertisement.
//!
//! **Production code MUST NOT use this module.** It is gated behind
//! `feature = "test-support"` and is not compiled in production builds.

use crate::node::{
    AuthenticatedLink, AuthenticatedLinkError, LinkKey, VerifiedNodeAdvertisement,
};

/// Construct an `AuthenticatedLink` from a `VerifiedNodeAdvertisement`
/// for testing purposes.
///
/// This synthesizes a `snp_link::HandshakeResult` whose `peer_node_id` and
/// `peer_public_key` match the advertisement. The `session_id` is derived
/// from the advertisement's NodeId (deterministic for testing).
///
/// The `LinkKey.endpoint` must appear in the advertisement's endpoints
/// (endpoint authorization is still enforced).
///
/// # Errors
/// Returns `AuthenticatedLinkError` if the endpoint is not authorized or
/// the NodeId doesn't match.
pub fn test_authenticated_link(
    key: LinkKey,
    advert: &VerifiedNodeAdvertisement,
) -> Result<AuthenticatedLink, AuthenticatedLinkError> {
    // Synthesize a HandshakeResult that matches the advertisement.
    let handshake = snp_link::HandshakeResult {
        link_keys: snp_link::LinkKeys {
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
        },
        peer_node_id: advert.node_id(),
        peer_public_key: *advert.ed25519_public_key(),
        peer_x25519_public: advert.circuit_x25519_pub().copied().unwrap_or([0u8; 32]),
        peer_ephemeral_public: [0u8; 32],
        // Derive a non-zero session_id from the NodeId (deterministic).
        session_id: derive_test_session_id(&advert.node_id()),
    };
    AuthenticatedLink::from_handshake(key, advert, &handshake)
}

/// Derive a non-zero session ID from a NodeId for testing.
fn derive_test_session_id(node_id: &[u8; 32]) -> [u8; 32] {
    let mut id = snp_crypto::sha256(node_id);
    // Ensure non-zero (sha256 of non-zero input is effectively always non-zero,
    // but we defensively set a bit).
    if id == [0u8; 32] {
        id[0] = 1;
    }
    id
}
