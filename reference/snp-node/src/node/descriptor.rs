//! Node identity descriptors — re-exported from snp-identity.
//!
//! R2.2 extraction (DESCRIPTOR-EXTRACTION): the descriptor types have been
//! moved to the snp-identity crate (L1 layer). This file re-exports them so
//! existing code that imports from `snp_node::node::descriptor` continues to
//! work without changes.
//!
//! The dependency direction is:
//!   snp-identity (owns UnverifiedNodeDescriptor, IdentityConsistentNodeDescriptor,
//!                 VerifiedNodeDescriptor, VerifiedGatewayAdvertisement,
//!                 TransportEndpoint, verify_node_id_consistency)
//!       ↓
//!   snp-node (re-exports + uses)
//!
//! NOT the reverse.
//!
//! **Note on `VerifiedNodeDescriptor::from_verified_advert_internal`:** the
//! pre-extraction implementation took a `&NodeAdvertisement` directly. After
//! extraction it takes the underlying primitive fields (`node_id`,
//! `ed25519_public_key`, `x25519_circuit_public`, `capabilities`) because
//! `NodeAdvertisement` lives in `snp-node` (which depends on `snp-identity`,
//! so the reverse reference would be circular). The
//! `VerifiedNodeAdvertisement::descriptor()` method in `snp-node` is the
//! sole caller — it extracts the primitive fields from its inner advert and
//! passes them to this constructor.

pub use snp_identity::{
    IdentityConsistentNodeDescriptor, TransportEndpoint, UnverifiedNodeDescriptor,
    VerifiedGatewayAdvertisement, VerifiedNodeDescriptor, verify_node_id_consistency,
};
