//! **N2.1.2.4 test-support module.**
//!
//! This module is ONLY compiled when the `test-support` Cargo feature is
//! enabled. It provides test helpers for constructing `AuthenticatedLink`
//! objects WITHOUT performing actual network handshakes.
//!
//! ## Security
//!
//! These helpers use `snp_link::test_support::verified_handshake_from_fields()`
//! to create a genuine `snp_link::VerifiedHandshake` proof. The proof is
//! real — it's minted using the private constructor inside `snp-link`.
//! The only shortcut is that no actual SNP-IK handshake over a real
//! transport is performed.
//!
//! The resulting `AuthenticatedLink` passes all the same verification checks
//! as a production link (identity, Ed25519, X25519, endpoint authorization).
//!
//! **Production code MUST NOT use this module.** It is gated behind
//! `feature = "test-support"` and is not compiled in production builds.

use crate::node::{
    AuthenticatedLink, AuthenticatedLinkError, LinkKey, VerifiedNodeAdvertisement,
};

/// Construct an `AuthenticatedLink` from a `VerifiedNodeAdvertisement`
/// for testing purposes.
///
/// This uses `snp_link::test_support::verified_handshake_from_fields()` to
/// create an unforgeable `VerifiedHandshake` proof whose fields match the
/// advertisement. The `session_id` is derived from the advertisement's
/// NodeId (deterministic for testing).
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
    // Use snp-link's test-only factory to create an unforgeable VerifiedHandshake.
    // This proof is real — it's minted using the private constructor inside snp-link.
    // The only shortcut is no actual network transport.
    let proof = snp_link::test_support::verified_handshake_from_fields(
        advert.node_id(),
        *advert.ed25519_public_key(),
        advert.circuit_x25519_pub().copied().unwrap_or([0u8; 32]),
        derive_test_session_id(&advert.node_id()),
    );
    AuthenticatedLink::from_verified_handshake(key, advert, &proof)
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
