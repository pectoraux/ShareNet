//! N2.4-I1 rev2 — Capability & Authority Foundation: adversarial tests.
//!
//! Tests for the corrected N2.4-02 Capability System.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_public_key, sha256, SecretKey};
use snp_node::node::capability::*;

fn fresh_keypair(label: &str) -> (SecretKey, [u8; 32]) {
    let secret = sha256(label.as_bytes());
    let public = derive_public_key(&secret);
    (secret, public)
}

fn node_id_from_pk(pk: &[u8; 32]) -> [u8; 32] {
    snp_crypto::domain_hash(b"SNP/0.1 node\0", pk)
}

fn test_time() -> u64 {
    1_700_000_000
}

// ─── P0 #1: Issuer identity binding ────────────────────────────────────────

#[test]
fn test_issuer_identity_binding_valid() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");

    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    assert!(authority.verify_issuer_identity_binding(),
        "issuer_id must equal NodeId(issuer_public_key)");
    eprintln!("[test 1] PASS: issuer identity binding valid");
}

#[test]
fn test_issuer_identity_binding_mismatch_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");
    let (_, wrong_pk) = fresh_keypair("attacker");

    let mut authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    // Tamper: set issuer_id to a wrong value.
    authority.issuer_id = node_id_from_pk(&wrong_pk);

    assert!(!authority.verify_issuer_identity_binding(),
        "mismatched issuer_id/public_key must be rejected");
    eprintln!("[test 2] PASS: issuer identity binding mismatch rejected");
}

#[test]
fn test_authority_accept_rejects_identity_binding_mismatch() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");
    let (_, wrong_pk) = fresh_keypair("attacker");

    let mut authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    // Tamper: set issuer_id to a wrong value.
    authority.issuer_id = node_id_from_pk(&wrong_pk);

    let mut store = AuthorityStateStore::new();
    let result = store.try_accept_authority(&authority);
    assert!(matches!(result, Err(AuthorityStateError::IssuerIdentityBindingInvalid)),
        "authority with identity binding mismatch must be rejected");
    eprintln!("[test 3] PASS: authority with identity binding mismatch rejected by store");
}

#[test]
fn test_verify_authorization_uses_authority_bound_key() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_authority(&authority).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);

    // P0 #1: verify_authorization no longer takes issuer_public_key —
    // it uses the authority-bound key.
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "verification must pass with authority-bound key: {:?}", result);
    eprintln!("[test 4] PASS: verify_authorization uses authority-bound issuer public key");
}

// ─── P0 #2: Real persistence ──────────────────────────────────────────────

#[test]
fn test_persistence_round_trip() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    // Write to persistent store.
    let mut store1 = AuthorityStateStore::open(&path).unwrap();
    store1.try_accept_authority(&authority).unwrap();

    // Simulate restart: create a new store from the same file.
    let mut store2 = AuthorityStateStore::open(&path).unwrap();

    // After restart, the same authority must be a duplicate (not accepted).
    let result = store2.try_accept_authority(&authority);
    assert_eq!(result, Ok(AuthorityAcceptResult::Duplicate),
        "after restart, same authority must be duplicate");

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 5] PASS: persistence round-trip — authority remains duplicate after restart");
}

#[test]
fn test_persistence_failure_fails_closed() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_fail_{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    // Write garbage to the persistence file.
    std::fs::write(&path, b"GARBAGE").unwrap();

    let result = AuthorityStateStore::open(&path);
    assert!(result.is_err(), "corrupted persistence file must fail closed");
    eprintln!("[test 6] PASS: corrupted persistence file fails closed");
}

// ─── P0 #3: Same-version revocation equivocation ──────────────────────────

#[test]
fn test_governance_revocation_same_version_same_digest_idempotent() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let rev = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_governance_revocation(&rev).unwrap();
    let result = store.try_accept_governance_revocation(&rev);
    assert_eq!(result, Ok(RevocationAcceptResult::Duplicate));
    eprintln!("[test 7] PASS: governance revocation same version + same digest = idempotent");
}

#[test]
fn test_governance_revocation_same_version_different_digest_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let rev1 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16],
    ).unwrap();
    let rev2 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time() + 100, [1u8; 16], // Different timestamp/nonce → different digest
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_governance_revocation(&rev1).unwrap();
    let result = store.try_accept_governance_revocation(&rev2);
    assert!(matches!(result, Err(AuthorityStateError::RevocationEquivocation { .. })),
        "same version + different digest must be equivocation");
    eprintln!("[test 8] PASS: governance revocation same version + different digest = equivocation rejected");
}

#[test]
fn test_subject_revocation_same_version_same_digest_idempotent() {
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let (_, subject_pk) = fresh_keypair("subject");
    let subject_id = node_id_from_pk(&subject_pk);
    let (issuer_secret, _) = fresh_keypair("issuer_secret");

    let rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_subject_revocation(&rev).unwrap();
    let result = store.try_accept_subject_revocation(&rev);
    assert_eq!(result, Ok(RevocationAcceptResult::Duplicate));
    eprintln!("[test 9] PASS: subject revocation same version + same digest = idempotent");
}

#[test]
fn test_subject_revocation_same_version_different_digest_rejected() {
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let (_, subject_pk) = fresh_keypair("subject");
    let subject_id = node_id_from_pk(&subject_pk);
    let (issuer_secret, _) = fresh_keypair("issuer_secret");

    let rev1 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();
    let rev2 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time() + 100, [1u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_subject_revocation(&rev1).unwrap();
    let result = store.try_accept_subject_revocation(&rev2);
    assert!(matches!(result, Err(AuthorityStateError::RevocationEquivocation { .. })),
        "same version + different digest must be equivocation");
    eprintln!("[test 10] PASS: subject revocation same version + different digest = equivocation rejected");
}

// ─── P0 #4: Governance revocation targets exact authority version ─────────

#[test]
fn test_v2_revocation_does_not_revoke_v1_authorization() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let auth_v1 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    // Authorization under v1.
    let authorization = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, auth_v1.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    ).unwrap();

    // Governance revocation targeting v2 (NOT v1).
    let rev_v2 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 2, 1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_authority(&auth_v1).unwrap();
    store.try_accept_governance_revocation(&rev_v2).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);

    // v2 revocation must NOT revoke v1 authorization.
    let result = ctx.verify_authorization(&authorization, test_time() + 100);
    assert!(result.is_ok(), "v2 revocation must not affect v1 authorization: {:?}", result);
    eprintln!("[test 11] PASS: v2 governance revocation does not revoke v1 authorization");
}

#[test]
fn test_v1_revocation_does_revoke_v1_authorization() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let auth_v1 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let authorization = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, auth_v1.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    ).unwrap();

    // Governance revocation targeting v1 (same version as authorization).
    let rev_v1 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time() - 100, [0u8; 16], // timestamp before auth validity_start
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_authority(&auth_v1).unwrap();
    store.try_accept_governance_revocation(&rev_v1).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);

    // v1 revocation MUST revoke v1 authorization.
    let result = ctx.verify_authorization(&authorization, test_time() + 100);
    assert!(matches!(result, Err(AuthorizationVerifyError::IssuerGovernanceRevoked { .. })),
        "v1 revocation must affect v1 authorization: {:?}", result);
    eprintln!("[test 12] PASS: v1 governance revocation revokes v1 authorization");
}

// ─── P1 #5: Constraints not ignored ────────────────────────────────────────

#[test]
fn test_non_empty_constraints_rejected_in_encompasses() {
    let scope = AuthScope {
        destinations: vec![],
        protocols: vec![],
        constraints: vec!["max-bandwidth=10Mbps".to_string()],
    };
    // P1 #5: non-empty constraints → encompasses returns false (safe default).
    assert!(!scope.encompasses("internet", "https"),
        "non-empty constraints must cause scope denial (safe default)");
    eprintln!("[test 13] PASS: non-empty constraints rejected in encompasses()");
}

#[test]
fn test_non_empty_constraints_rejected_in_includes() {
    let authority_scope = AuthScope {
        destinations: vec![],
        protocols: vec![],
        constraints: vec!["max-bandwidth=10Mbps".to_string()],
    };
    let auth_scope = AuthScope::wildcard();

    // P1 #5: authority with non-empty constraints → includes returns false.
    assert!(!authority_scope.includes(&auth_scope),
        "authority with non-empty constraints must not include any scope (safe default)");
    eprintln!("[test 14] PASS: non-empty constraints rejected in includes()");
}

#[test]
fn test_empty_constraints_allowed() {
    let scope = AuthScope::wildcard();
    assert!(scope.encompasses("internet", "https"),
        "empty constraints (wildcard) must allow matching operation");
    eprintln!("[test 15] PASS: empty constraints allowed in encompasses()");
}

// ─── P1 #8: classify_capability_claim ──────────────────────────────────────

#[test]
fn test_classify_capability_claim_tier0_eligible() {
    let result = classify_capability_claim(ProtocolCapability::MeshRelay, None);
    assert!(matches!(result, CapabilityClaimResult::Eligible));
    eprintln!("[test 16] PASS: classify_capability_claim — Tier 0 eligible");
}

#[test]
fn test_classify_capability_claim_tier2_not_authorized() {
    let result = classify_capability_claim(ProtocolCapability::InternetGateway, None);
    assert!(matches!(result, CapabilityClaimResult::NotAuthorized));
    eprintln!("[test 17] PASS: classify_capability_claim — Tier 2 not authorized without authorization");
}

// ─── Original tests (retained, adapted for new API) ────────────────────────

#[test]
fn test_governance_anchor_self_signature_valid() {
    let (gov_secret, _) = fresh_keypair("governance");
    let anchor = GovernanceTrustAnchor::new(&gov_secret, 1, test_time(), test_time() + 86400);
    assert!(anchor.verify_self_signature());
    eprintln!("[test 18] PASS: governance anchor self-signature valid");
}

#[test]
fn test_authority_higher_version_accepted() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let auth_v1 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();
    let auth_v2 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 2,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    assert_eq!(store.try_accept_authority(&auth_v1), Ok(AuthorityAcceptResult::Accepted));
    assert_eq!(store.try_accept_authority(&auth_v2), Ok(AuthorityAcceptResult::Accepted));
    eprintln!("[test 19] PASS: higher authority version accepted");
}

#[test]
fn test_authority_same_version_different_digest_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let auth1 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();
    let auth2 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::Compute], // Different → different digest
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_authority(&auth1).unwrap();
    let result = store.try_accept_authority(&auth2);
    assert!(matches!(result, Err(AuthorityStateError::AuthorityEquivocation { .. })));
    eprintln!("[test 20] PASS: same version + different digest = equivocation rejected");
}

#[test]
fn test_authorization_valid_full_chain() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_authority(&authority).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "full chain verification must pass: {:?}", result);
    eprintln!("[test 21] PASS: authorization valid — full chain verification");
}

#[test]
fn test_authorization_expired_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 100, [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_authority(&authority).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 200);
    assert_eq!(result, Err(AuthorizationVerifyError::AuthorizationNotCurrent));
    eprintln!("[test 22] PASS: expired authorization rejected");
}

#[test]
fn test_authorization_subject_revoked_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    ).unwrap();

    let subject_rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.try_accept_authority(&authority).unwrap();
    store.try_accept_subject_revocation(&subject_rev).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::SubjectRevoked));
    eprintln!("[test 23] PASS: subject revoked — authorization rejected");
}

#[test]
fn test_evaluate_scope_allow() {
    let (issuer_secret, _) = fresh_keypair("issuer");

    let auth = CapabilityAuthorization::new(
        &issuer_secret, [1u8; 32], 1, [0u8; 32],
        [2u8; 32], ProtocolCapability::InternetGateway,
        AuthScope {
            destinations: vec!["internet".to_string()],
            protocols: vec!["https".to_string()],
            constraints: vec![], // P1 #5: empty constraints = OK
        },
        test_time(), test_time() + 3600, [0u8; 16],
    ).unwrap();

    let store = AuthorityStateStore::new();
    let ctx = VerificationContext::with_store([0u8; 32], store);
    let result = ctx.evaluate_scope(&auth, "internet", "https");
    assert_eq!(result, ScopeEvaluationResult::Allow);
    eprintln!("[test 24] PASS: evaluate_scope allows matching operation");
}

#[test]
fn test_tier2_requires_authorization() {
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::InternetGateway));
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::Compute));
    eprintln!("[test 25] PASS: Tier 2 requires explicit authorization");
}

#[test]
fn test_tier0_self_assertion_eligible() {
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::MeshRelay));
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::Discovery));
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::Sync));
    eprintln!("[test 26] PASS: Tier 0 self-assertion establishes eligibility");
}
