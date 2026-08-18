//! GatewayAdvertisement — re-exported from snp-identity.
//!
//! R2.2 extraction (DESCRIPTOR-EXTRACTION): `GatewayAdvertisement` and its
//! impl methods (sign, verify, encode_cbor, decode_cbor, for_identity,
//! for_identity_with_circuit_key, is_expired, verify_into_verified) have been
//! moved to the snp-identity crate (L1 layer). This file re-exports the type
//! so existing code that imports from `snp_node::node::gateway` continues to
//! work without changes.
//!
//! The dependency direction is:
//!   snp-identity (owns GatewayAdvertisement + ADVERTISEMENT_TTL_SECS)
//!       ↓
//!   snp-node (re-exports + uses)
//!
//! NOT the reverse.
//!
//! The `VerifiedGatewayAdvertisement` wrapper (which can ONLY be constructed
//! via `GatewayAdvertisement::verify_into_verified()`) lives in
//! `snp-identity::descriptor` alongside the other descriptor types — see
//! [`snp_identity::VerifiedGatewayAdvertisement`].

pub use snp_identity::GatewayAdvertisement;
