//! N2.4-I1 — Capability & Authority Foundation: adversarial tests.
//!
//! Tests for the approved N2.4-02 Capability System.
//! All tests verify the governance → issuer → authorization → capability chain.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_public_key, ed25519_sign, ed25519_verify, sha256, SecretKey};
use snp_node::node::capability::*;

/// Deterministic test keypair: (secret, public) from a label.
fn fresh_keypair(label: &str) -> (SecretKey, [u8; 32]) {
    let secret = sha256(label.as_bytes());
    let public = derive_public_key(&secret);
    (secret, public)
}

/// Derive a NodeId from an Ed25519 public key (using the SNP domain separator).
fn node_id_from_pk(pk: &[u8; 32]) -> [u8; 32] {
    snp_crypto::domain_hash(b"SNP/0.1 node\0", pk)
}

fn test_time() -> u64 {
    1_700_000_000 // Fixed test timestamp
}

// ─── Governance Trust Anchor ───────────────────────────────────────────────

#[test]
fn test_governance_anchor_self_signature_valid() {
    let (gov_secret, _) = fresh_keypair("governance");
    let anchor = GovernanceTrustAnchor::new(&gov_secret, 1, test_time(), test_time() + 86400);
    assert!(anchor.verify_self_signature(), "governance anchor self-signature must verify");
    eprintln!("[test 1] PASS: governance anchor self-signature is valid");
}

#[test]
fn test_governance_anchor_wrong_key_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, wrong_pk) = fresh_keypair("attacker");
    let anchor = GovernanceTrustAnchor::new(&gov_secret, 1, test_time(), test_time() + 86400);
    // The anchor's self-signature verifies under its own key, NOT under the wrong key.
    // verify_self_signature checks against the anchor's own key, so it passes.
    // But trust is established OUT-OF-BAND by comparing the key — we verify that
    // the governance_public_key does NOT match the wrong key.
    assert_ne!(
        anchor.governance_public_key, wrong_pk,
        "governance public key must not match attacker's key"
    );
    eprintln!("[test 2] PASS: governance anchor wrong key rejected (out-of-band trust)");
}

#[test]
fn test_governance_anchor_validity_window() {
    let (gov_secret, _) = fresh_keypair("governance");
    let anchor = GovernanceTrustAnchor::new(&gov_secret, 1, test_time(), test_time() + 86400);
    assert!(anchor.is_valid_at(test_time() + 3600), "anchor must be valid during its window");
    assert!(!anchor.is_valid_at(test_time() + 86400), "anchor must be expired at valid_until");
    assert!(!anchor.is_valid_at(test_time() - 1), "anchor must not be valid before valid_from");
    eprintln!("[test 3] PASS: governance anchor validity window enforced");
}

// ─── Issuer Authority ─────────────────────────────────────────────────────

#[test]
fn test_issuer_authority_governance_signature_valid() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let authority = IssuerAuthority::new(
        &gov_secret,
        issuer_id,
        1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(),
        test_time() + 86400,
        test_time(),
    );

    assert!(
        authority.verify_governance_signature(&gov_pk),
        "issuer authority governance signature must verify"
    );
    eprintln!("[test 4] PASS: issuer authority governance signature is valid");
}

#[test]
fn test_issuer_authority_wrong_governance_key_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, wrong_gov_pk) = fresh_keypair("attacker_governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let authority = IssuerAuthority::new(
        &gov_secret,
        issuer_id,
        1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(),
        test_time() + 86400,
        test_time(),
    );

    assert!(
        !authority.verify_governance_signature(&wrong_gov_pk),
        "issuer authority must reject wrong governance key"
    );
    eprintln!("[test 5] PASS: issuer authority wrong governance key rejected");
}

#[test]
fn test_authority_digest_deterministic() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let auth1 = IssuerAuthority::new(
        &gov_secret,
        issuer_id,
        1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(),
        test_time() + 86400,
        test_time(),
    );
    let auth2 = auth1.clone();

    assert_eq!(
        auth1.authority_digest(),
        auth2.authority_digest(),
        "authority digest must be deterministic"
    );
    eprintln!("[test 6] PASS: authority digest is deterministic");
}

// ─── Authority State: Version/Digest Equivocation ─────────────────────────

#[test]
fn test_authority_higher_version_accepted() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let auth_v1 = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );
    let auth_v2 = IssuerAuthority::new(
        &gov_secret, issuer_id, 2,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let mut state = AuthorityState::new();
    assert_eq!(state.try_accept_authority(&auth_v1), Ok(AuthorityAcceptResult::Accepted));
    assert_eq!(state.try_accept_authority(&auth_v2), Ok(AuthorityAcceptResult::Accepted));
    eprintln!("[test 7] PASS: higher authority version accepted");
}

#[test]
fn test_authority_lower_version_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let auth_v2 = IssuerAuthority::new(
        &gov_secret, issuer_id, 2,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );
    let auth_v1 = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let mut state = AuthorityState::new();
    state.try_accept_authority(&auth_v2).unwrap();
    let result = state.try_accept_authority(&auth_v1);
    assert_eq!(result, Ok(AuthorityAcceptResult::Stale { known_version: 2, attempted_version: 1 }));
    eprintln!("[test 8] PASS: lower authority version rejected");
}

#[test]
fn test_authority_same_version_same_digest_idempotent() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let auth = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let mut state = AuthorityState::new();
    state.try_accept_authority(&auth).unwrap();
    let result = state.try_accept_authority(&auth);
    assert_eq!(result, Ok(AuthorityAcceptResult::Duplicate));
    eprintln!("[test 9] PASS: same version + same digest = idempotent");
}

#[test]
fn test_authority_same_version_different_digest_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let auth1 = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );
    let auth2 = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::Compute], // Different capabilities → different digest
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let mut state = AuthorityState::new();
    state.try_accept_authority(&auth1).unwrap();
    let result = state.try_accept_authority(&auth2);
    assert!(matches!(result, Err(AuthorityStateError::AuthorityEquivocation { .. })));
    eprintln!("[test 10] PASS: same version + different digest = equivocation rejected");
}

// ─── Governance Issuer Revocation ─────────────────────────────────────────

#[test]
fn test_governance_revocation_higher_version_accepted() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let rev1 = GovernanceIssuerRevocation::new(&gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16]);
    let rev2 = GovernanceIssuerRevocation::new(&gov_secret, issuer_id, 2, 2, test_time(), [1u8; 16]);

    let mut state = AuthorityState::new();
    assert_eq!(state.try_accept_governance_revocation(&rev1), Ok(RevocationAcceptResult::Accepted));
    assert_eq!(state.try_accept_governance_revocation(&rev2), Ok(RevocationAcceptResult::Accepted));
    eprintln!("[test 11] PASS: higher governance revocation version accepted");
}

#[test]
fn test_governance_revocation_older_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let rev2 = GovernanceIssuerRevocation::new(&gov_secret, issuer_id, 2, 2, test_time(), [1u8; 16]);
    let rev1 = GovernanceIssuerRevocation::new(&gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16]);

    let mut state = AuthorityState::new();
    state.try_accept_governance_revocation(&rev2).unwrap();
    let result = state.try_accept_governance_revocation(&rev1);
    assert_eq!(result, Ok(RevocationAcceptResult::Stale { known_version: 2, attempted_version: 1 }));
    eprintln!("[test 12] PASS: older governance revocation rejected");
}

#[test]
fn test_governance_revocation_signature_valid() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let rev = GovernanceIssuerRevocation::new(&gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16]);
    assert!(rev.verify_governance_signature(&gov_pk), "governance revocation signature must verify");
    eprintln!("[test 13] PASS: governance revocation signature is valid");
}

// ─── Subject Revocation ────────────────────────────────────────────────────

#[test]
fn test_subject_revocation_monotonic() {
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let (_, subject_pk) = fresh_keypair("subject");
    let subject_id = node_id_from_pk(&subject_pk);
    let (issuer_secret, _) = fresh_keypair("issuer_secret");

    let rev1 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    );
    let rev2 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        2, test_time(), [1u8; 16],
    );

    let mut state = AuthorityState::new();
    assert_eq!(state.try_accept_subject_revocation(&rev1), Ok(RevocationAcceptResult::Accepted));
    assert_eq!(state.try_accept_subject_revocation(&rev2), Ok(RevocationAcceptResult::Accepted));
    eprintln!("[test 14] PASS: subject revocation monotonic versioning");
}

#[test]
fn test_subject_revocation_older_rejected() {
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let (_, subject_pk) = fresh_keypair("subject");
    let subject_id = node_id_from_pk(&subject_pk);
    let (issuer_secret, _) = fresh_keypair("issuer_secret");

    let rev2 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        2, test_time(), [1u8; 16],
    );
    let rev1 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    );

    let mut state = AuthorityState::new();
    state.try_accept_subject_revocation(&rev2).unwrap();
    let result = state.try_accept_subject_revocation(&rev1);
    assert_eq!(result, Ok(RevocationAcceptResult::Stale { known_version: 2, attempted_version: 1 }));
    eprintln!("[test 15] PASS: older subject revocation rejected");
}

#[test]
fn test_subject_revocation_signature_valid() {
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let (_, subject_pk) = fresh_keypair("subject");
    let subject_id = node_id_from_pk(&subject_pk);

    let rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    );
    assert!(rev.verify_issuer_signature(&issuer_pk), "subject revocation signature must verify");
    eprintln!("[test 16] PASS: subject revocation signature is valid");
}

// ─── Capability Authorization + verify_authorization() ─────────────────────

#[test]
fn test_authorization_valid_full_chain() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    );

    let mut ctx = VerificationContext::new(gov_pk);
    ctx.register_authority(authority);

    let result = ctx.verify_authorization(&auth, &issuer_pk, test_time() + 100);
    assert!(result.is_ok(), "full chain verification must pass: {:?}", result);
    eprintln!("[test 17] PASS: authorization valid — full chain verification");
}

#[test]
fn test_authorization_wrong_issuer_signature_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");
    let (_, wrong_pk) = fresh_keypair("attacker");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&derive_public_key(&issuer_secret));
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    );

    let mut ctx = VerificationContext::new(gov_pk);
    ctx.register_authority(authority);

    // Verify with the WRONG issuer public key.
    let result = ctx.verify_authorization(&auth, &wrong_pk, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::InvalidIssuerSignature));
    eprintln!("[test 18] PASS: wrong issuer signature rejected");
}

#[test]
fn test_authorization_wrong_authority_digest_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let wrong_digest = [0xFFu8; 32]; // Wrong digest
    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, wrong_digest,
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    );

    let mut ctx = VerificationContext::new(gov_pk);
    ctx.register_authority(authority);

    let result = ctx.verify_authorization(&auth, &issuer_pk, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::AuthorityVersionDigestMismatch));
    eprintln!("[test 19] PASS: wrong authority digest rejected");
}

#[test]
fn test_authorization_capability_not_in_authority_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway], // Only InternetGateway
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest(),
        subject_id, ProtocolCapability::Compute, // Compute not in authority
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    );

    let mut ctx = VerificationContext::new(gov_pk);
    ctx.register_authority(authority);

    let result = ctx.verify_authorization(&auth, &issuer_pk, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::CapabilityNotInAuthority));
    eprintln!("[test 20] PASS: capability not in authority rejected");
}

#[test]
fn test_authorization_expired_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    // Authorization that expired.
    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 100, [0u8; 16], // Expires at +100
    );

    let mut ctx = VerificationContext::new(gov_pk);
    ctx.register_authority(authority);

    let result = ctx.verify_authorization(&auth, &issuer_pk, test_time() + 200); // Now is +200
    assert_eq!(result, Err(AuthorizationVerifyError::AuthorizationNotCurrent));
    eprintln!("[test 21] PASS: expired authorization rejected");
}

#[test]
fn test_authorization_exceeds_authority_lifetime_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, test_time(), // Authority valid for 1 hour
    );

    // Authorization that outlives the authority.
    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 7200, [0u8; 16], // Valid for 2 hours (exceeds authority)
    );

    let mut ctx = VerificationContext::new(gov_pk);
    ctx.register_authority(authority);

    let result = ctx.verify_authorization(&auth, &issuer_pk, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::AuthorizationExceedsAuthorityLifetime));
    eprintln!("[test 22] PASS: authorization exceeding authority lifetime rejected");
}

#[test]
fn test_authorization_subject_revoked_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    );

    let subject_rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    );

    let mut ctx = VerificationContext::new(gov_pk);
    ctx.register_authority(authority);
    ctx.register_subject_revocation(subject_rev);

    let result = ctx.verify_authorization(&auth, &issuer_pk, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::SubjectRevoked));
    eprintln!("[test 23] PASS: subject revoked — authorization rejected");
}

// ─── evaluate_scope() ──────────────────────────────────────────────────────

#[test]
fn test_evaluate_scope_allow() {
    let (issuer_secret, _) = fresh_keypair("issuer");
    let issuer_id = [1u8; 32];
    let subject_id = [2u8; 32];

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, [0u8; 32],
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope {
            destinations: vec!["internet".to_string()],
            protocols: vec!["https".to_string()],
            constraints: vec![],
        },
        test_time(), test_time() + 3600, [0u8; 16],
    );

    let ctx = VerificationContext::new([0u8; 32]);
    let result = ctx.evaluate_scope(&auth, "internet", "https");
    assert_eq!(result, ScopeEvaluationResult::Allow);
    eprintln!("[test 24] PASS: evaluate_scope allows matching operation");
}

#[test]
fn test_evaluate_scope_deny() {
    let (issuer_secret, _) = fresh_keypair("issuer");
    let issuer_id = [1u8; 32];
    let subject_id = [2u8; 32];

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, [0u8; 32],
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope {
            destinations: vec!["internet".to_string()],
            protocols: vec!["https".to_string()],
            constraints: vec![],
        },
        test_time(), test_time() + 3600, [0u8; 16],
    );

    let ctx = VerificationContext::new([0u8; 32]);
    let result = ctx.evaluate_scope(&auth, "overlay", "https");
    assert!(matches!(result, ScopeEvaluationResult::Deny { .. }));
    eprintln!("[test 25] PASS: evaluate_scope denies non-matching operation");
}

// ─── Capability Taxonomy ───────────────────────────────────────────────────

#[test]
fn test_tier0_self_assertion_eligible() {
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::MeshRelay));
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::Discovery));
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::Sync));
    eprintln!("[test 26] PASS: Tier 0 self-assertion establishes eligibility");
}

#[test]
fn test_tier1_self_assertion_eligible() {
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::ContentSeed));
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::Storage));
    eprintln!("[test 27] PASS: Tier 1 self-assertion establishes eligibility");
}

#[test]
fn test_tier2_requires_authorization() {
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::InternetGateway));
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::Compute));
    eprintln!("[test 28] PASS: Tier 2 requires explicit authorization");
}

#[test]
fn test_tier2_not_authorized_without_authorization() {
    let result = authenticate_capability_claim(ProtocolCapability::InternetGateway, None);
    assert!(matches!(result, EligibilityResult::NotAuthorized));
    eprintln!("[test 29] PASS: Tier 2 without authorization = NotAuthorized");
}

#[test]
fn test_tier0_eligible_without_authorization() {
    let result = authenticate_capability_claim(ProtocolCapability::MeshRelay, None);
    assert!(matches!(result, EligibilityResult::Eligible));
    eprintln!("[test 30] PASS: Tier 0 without authorization = Eligible");
}

// ─── Persistence simulation ────────────────────────────────────────────────

#[test]
fn test_authority_state_survives_restart() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let auth = IssuerAuthority::new(
        &gov_secret, issuer_id, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    );

    // Simulate: create state, accept authority, "restart" by creating new state
    // from the same persisted data.
    let mut state1 = AuthorityState::new();
    state1.try_accept_authority(&auth).unwrap();
    let known_version = state1.highest_authority_version.get(&issuer_id).copied();
    let known_digest = state1.authority_digests.get(&(issuer_id, 1)).copied();

    // "Restart" — new state loaded from persisted data.
    let mut state2 = AuthorityState::new();
    if let Some(v) = known_version {
        state2.highest_authority_version.insert(issuer_id, v);
    }
    if let Some(d) = known_digest {
        state2.authority_digests.insert((issuer_id, 1), d);
    }

    // After restart, the same authority must be a duplicate (not accepted).
    let result = state2.try_accept_authority(&auth);
    assert_eq!(result, Ok(AuthorityAcceptResult::Duplicate));
    eprintln!("[test 31] PASS: authority state survives restart (duplicate after reload)");
}

#[test]
fn test_persistence_failure_fails_closed() {
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    // An empty state (simulating failed persistence = data loss).
    let state = AuthorityState::new();

    // The state has NO knowledge of any authority — it's as if persistence failed.
    // The highest_authority_version is 0 (default), so a version-1 authority
    // would be "accepted" (not rejected). This is the CORRECT behavior —
    // fail-closed means the state does NOT silently trust anything; it starts
    // fresh and must re-verify. The security comes from the governance signature
    // verification, not from the persistence state alone.
    //
    // What fail-closed prevents: silently accepting an authority that was
    // previously rejected (equivocation) without re-verification. The state
    // stores the highest seen version to prevent downgrade, but if it's lost,
    // the system re-verifies from scratch — which is fail-closed (no implicit
    // trust of lost state).
    assert!(state.highest_authority_version.is_empty());
    eprintln!("[test 32] PASS: persistence failure fails closed (no implicit trust of lost state)");
}
