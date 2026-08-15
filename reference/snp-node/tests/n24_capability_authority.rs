//! N2.4-I1 rev3 — Capability & Authority Foundation: adversarial tests.
//!
//! Tests for the corrected N2.4-02 Capability System with:
//! - P0 #1: Signature verification before acceptance
//! - P0 #2: Complete object persistence + restart verification
//! - P0 #3: Transactional persistence mutations
//! - P0 #4: Subject revocation authority resolution
//! - P1 #5: Fail-closed on malformed entries

#![allow(clippy::pedantic)]

use snp_crypto::{derive_public_key, sha256, SecretKey};
use snp_node::node::capability::*;
use std::path::PathBuf;

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

fn make_authority(gov_secret: &SecretKey, issuer_secret: &SecretKey, version: u64) -> IssuerAuthority {
    IssuerAuthority::new(
        gov_secret, issuer_secret, version,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap()
}

fn make_authorization(
    issuer_secret: &SecretKey,
    issuer_id: [u8; 32],
    authority: &IssuerAuthority,
    subject_id: [u8; 32],
) -> CapabilityAuthorization {
    CapabilityAuthorization::new(
        issuer_secret, issuer_id, authority.authority_version,
        authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 3600, [0u8; 16],
    ).unwrap()
}

// ─── P0 #1: Signature verification before acceptance ───────────────────────

#[test]
fn test_unsigned_authority_cannot_poison_store() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let authority = make_authority(&gov_secret, &issuer_secret, 1);

    // Tamper: corrupt the governance signature.
    let mut bad_authority = authority.clone();
    bad_authority.governance_signature[0] ^= 0xFF;

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);

    let result = store.try_accept_authority(&bad_authority);
    assert!(matches!(result, Err(AuthorityStateError::AuthorityNotGovernanceSigned)),
        "unsigned/invalid-signature authority MUST be rejected before acceptance");
    eprintln!("[test 1] PASS: unsigned authority cannot poison store");
}

#[test]
fn test_invalid_governance_revocation_signature_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let rev = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16],
    ).unwrap();

    // Tamper: corrupt the signature.
    let mut bad_rev = rev.clone();
    bad_rev.governance_signature[0] ^= 0xFF;

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);

    let result = store.try_accept_governance_revocation(&bad_rev);
    assert!(matches!(result, Err(AuthorityStateError::RevocationSignatureInvalid)));
    eprintln!("[test 2] PASS: invalid governance revocation signature rejected");
}

#[test]
fn test_subject_revocation_without_authority_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);

    // No authority has been accepted → cannot resolve issuer key.
    let result = store.try_accept_subject_revocation(&rev);
    assert!(matches!(result, Err(AuthorityStateError::IssuerAuthorityNotFound { .. })));
    eprintln!("[test 3] PASS: subject revocation without authority rejected");
}

#[test]
fn test_subject_revocation_with_wrong_issuer_key_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let (_, attacker_secret) = fresh_keypair("attacker");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);

    // Subject revocation signed by WRONG key (attacker, not issuer).
    let bad_rev = SubjectCapabilityRevocation::new(
        &attacker_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();

    let result = store.try_accept_subject_revocation(&bad_rev);
    assert!(matches!(result, Err(AuthorityStateError::RevocationSignatureInvalid)));
    eprintln!("[test 4] PASS: subject revocation with wrong issuer key rejected");
}

// ─── P0 #2: Complete object persistence + restart verification ──────────────

#[test]
fn test_complete_authority_survives_restart() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_rev3_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let auth = make_authorization(&issuer_secret, issuer_id, &authority, subject_id);

    // Write to persistent store.
    let mut store1 = AuthorityStateStore::open(&path).unwrap();
    store1.set_governance_public_key(gov_pk);
    store1.try_accept_authority(&authority).unwrap();

    // Restart: open a new store from the same file.
    let mut store2 = AuthorityStateStore::open(&path).unwrap();
    store2.set_governance_public_key(gov_pk);

    // Verify the authority was restored — verify_authorization must work without reinjection.
    let ctx = VerificationContext::with_store(gov_pk, store2);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "verify_authorization must work after restart: {:?}", result);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 5] PASS: complete authority survives restart + verify_authorization works");
}

#[test]
fn test_complete_revocation_survives_restart() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_rev_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let gov_rev = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time() - 100, [0u8; 16],
    ).unwrap();

    // Write authority + governance revocation.
    let mut store1 = AuthorityStateStore::open(&path).unwrap();
    store1.set_governance_public_key(gov_pk);
    store1.try_accept_authority(&authority).unwrap();
    store1.try_accept_governance_revocation(&gov_rev).unwrap();

    // Restart.
    let mut store2 = AuthorityStateStore::open(&path).unwrap();
    store2.set_governance_public_key(gov_pk);

    // Verify governance revocation was restored.
    let restored_rev = store2.get_governance_revocation(&issuer_id, 1);
    assert!(restored_rev.is_some(), "governance revocation must survive restart");
    assert_eq!(restored_rev.unwrap().revocation_version, 1);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 6] PASS: complete governance revocation survives restart");
}

#[test]
fn test_complete_subject_revocation_survives_restart() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_subj_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let subj_rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store1 = AuthorityStateStore::open(&path).unwrap();
    store1.set_governance_public_key(gov_pk);
    store1.try_accept_authority(&authority).unwrap();
    store1.try_accept_subject_revocation(&subj_rev).unwrap();

    // Restart.
    let mut store2 = AuthorityStateStore::open(&path).unwrap();
    store2.set_governance_public_key(gov_pk);

    // Verify subject revocation was restored.
    let restored = store2.get_subject_revocation(&issuer_id, &subject_id, ProtocolCapability::InternetGateway);
    assert!(restored.is_some(), "subject revocation must survive restart");
    assert_eq!(restored.unwrap().revocation_version, 1);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 7] PASS: complete subject revocation survives restart");
}

// ─── P0 #2: Restart + verify_authorization without reinjection ─────────────

#[test]
fn test_restart_verify_authorization_succeeds() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_verify_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let auth = make_authorization(&issuer_secret, issuer_id, &authority, subject_id);

    // Accept authority in persistent store.
    let mut store = AuthorityStateStore::open(&path).unwrap();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();

    // Restart: create a new VerificationContext from the persistent file.
    let restarted_store = store.restart().unwrap();
    let ctx = VerificationContext::with_store(gov_pk, restarted_store);

    // verify_authorization must work without any re-registration.
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "verify_authorization after restart must succeed: {:?}", result);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 8] PASS: restart + verify_authorization succeeds without reinjection");
}

// ─── P0 #2: Malformed persistence record fails closed ──────────────────────

#[test]
fn test_malformed_authority_persistence_record_fails_closed() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_malformed_{:x}.bin", std::process::id()));

    // Write a valid SNCA v2 file but with a truncated authority entry.
    let mut data = Vec::new();
    data.extend_from_slice(b"SNCA");
    data.push(2); // Version 2
    // Write a truncated entry: 4-byte length prefix + garbage.
    data.extend_from_slice(&10u32.to_le_bytes());
    data.extend_from_slice(&[0xFF; 10]);

    std::fs::write(&path, &data).unwrap();

    let result = AuthorityStateStore::open(&path);
    assert!(result.is_err(), "malformed persistence record must fail closed");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 9] PASS: malformed authority persistence record fails closed");
}

#[test]
fn test_corrupted_persistence_file_fails_closed() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_corrupt_{:x}.bin", std::process::id()));

    std::fs::write(&path, b"GARBAGE").unwrap();

    let result = AuthorityStateStore::open(&path);
    assert!(result.is_err(), "corrupted persistence file must fail closed");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 10] PASS: corrupted persistence file fails closed");
}

// ─── P0 #3: Transactional persistence — failure leaves memory unchanged ────

#[test]
fn test_persistence_failure_leaves_memory_unchanged() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let authority = make_authority(&gov_secret, &issuer_secret, 1);

    // Use an in-memory store (no path) to test that in-memory mode works correctly.
    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);

    // In-memory store: no persistence, so try_accept_authority should succeed.
    let result = store.try_accept_authority(&authority);
    assert!(result.is_ok(), "in-memory store should accept authority: {:?}", result);

    // Now test persistence failure: set a non-existent path and try to accept
    // another version. The transactional_apply will try to commit and fail.
    // The memory state should be unchanged (v1 remains the highest).
    store.path = Some(PathBuf::from("/nonexistent/dir/cap_store.bin"));

    let auth_v2 = make_authority(&gov_secret, &issuer_secret, 2);
    let fail_result = store.try_accept_authority(&auth_v2);
    assert!(fail_result.is_err(), "persistence failure should reject the operation");

    // Verify that v1 is still the highest (memory unchanged).
    let auth_v1_dup = make_authority(&gov_secret, &issuer_secret, 1);
    let dup_result = store.try_accept_authority(&auth_v1_dup);
    assert_eq!(dup_result, Ok(AuthorityAcceptResult::Duplicate),
        "v1 must still be the highest (persistence failure left memory unchanged)");
    eprintln!("[test 11] PASS: persistence failure leaves memory unchanged");
    let _ = gov_secret; // suppress warning
}

// ─── Retained tests from previous revision ─────────────────────────────────

#[test]
fn test_issuer_identity_binding_valid() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    assert!(authority.verify_issuer_identity_binding());
    eprintln!("[test 12] PASS: issuer identity binding valid");
}

#[test]
fn test_issuer_identity_binding_mismatch_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");
    let (_, wrong_pk) = fresh_keypair("attacker");

    let mut authority = make_authority(&gov_secret, &issuer_secret, 1);
    authority.issuer_id = node_id_from_pk(&wrong_pk);

    assert!(!authority.verify_issuer_identity_binding());
    eprintln!("[test 13] PASS: issuer identity binding mismatch rejected");
}

#[test]
fn test_authority_higher_version_accepted() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);
    let auth_v2 = make_authority(&gov_secret, &issuer_secret, 2);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    assert_eq!(store.try_accept_authority(&auth_v1), Ok(AuthorityAcceptResult::Accepted));
    assert_eq!(store.try_accept_authority(&auth_v2), Ok(AuthorityAcceptResult::Accepted));
    eprintln!("[test 14] PASS: higher authority version accepted");
}

#[test]
fn test_authority_same_version_different_digest_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let auth1 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();
    let auth2 = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::Compute],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth1).unwrap();
    let result = store.try_accept_authority(&auth2);
    assert!(matches!(result, Err(AuthorityStateError::AuthorityEquivocation { .. })));
    eprintln!("[test 15] PASS: same version + different digest = equivocation rejected");
}

#[test]
fn test_governance_revocation_same_version_different_digest_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (_, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let rev1 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16],
    ).unwrap();
    let rev2 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time() + 100, [1u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_governance_revocation(&rev1).unwrap();
    let result = store.try_accept_governance_revocation(&rev2);
    assert!(matches!(result, Err(AuthorityStateError::RevocationEquivocation { .. })));
    eprintln!("[test 16] PASS: governance revocation same version + different digest = equivocation");
}

#[test]
fn test_subject_revocation_same_version_different_digest_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);

    let rev1 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();
    let rev2 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time() + 100, [1u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();
    store.try_accept_subject_revocation(&rev1).unwrap();
    let result = store.try_accept_subject_revocation(&rev2);
    assert!(matches!(result, Err(AuthorityStateError::RevocationEquivocation { .. })));
    eprintln!("[test 17] PASS: subject revocation same version + different digest = equivocation");
}

#[test]
fn test_v2_revocation_does_not_revoke_v1_authorization() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);
    let authorization = make_authorization(&issuer_secret, issuer_id, &auth_v1, subject_id);

    let rev_v2 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 2, 1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth_v1).unwrap();
    store.try_accept_governance_revocation(&rev_v2).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&authorization, test_time() + 100);
    assert!(result.is_ok(), "v2 revocation must not affect v1 authorization: {:?}", result);
    eprintln!("[test 18] PASS: v2 governance revocation does not revoke v1 authorization");
}

#[test]
fn test_v1_revocation_does_revoke_v1_authorization() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);
    let authorization = make_authorization(&issuer_secret, issuer_id, &auth_v1, subject_id);

    let rev_v1 = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time() - 100, [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth_v1).unwrap();
    store.try_accept_governance_revocation(&rev_v1).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&authorization, test_time() + 100);
    assert!(matches!(result, Err(AuthorizationVerifyError::IssuerGovernanceRevoked { .. })));
    eprintln!("[test 19] PASS: v1 governance revocation revokes v1 authorization");
}

#[test]
fn test_authorization_valid_full_chain() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let auth = make_authorization(&issuer_secret, issuer_id, &authority, subject_id);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "full chain verification must pass: {:?}", result);
    eprintln!("[test 20] PASS: authorization valid — full chain verification");
}

#[test]
fn test_authorization_expired_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let auth = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        test_time(), test_time() + 100, [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 200);
    assert_eq!(result, Err(AuthorizationVerifyError::AuthorizationNotCurrent));
    eprintln!("[test 21] PASS: expired authorization rejected");
}

#[test]
fn test_authorization_subject_revoked_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let auth = make_authorization(&issuer_secret, issuer_id, &authority, subject_id);

    let subj_rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();
    store.try_accept_subject_revocation(&subj_rev).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::SubjectRevoked));
    eprintln!("[test 22] PASS: subject revoked — authorization rejected");
}

#[test]
fn test_non_empty_constraints_rejected() {
    let scope = AuthScope {
        destinations: vec![],
        protocols: vec![],
        constraints: vec!["max-bandwidth=10Mbps".to_string()],
    };
    assert!(!scope.encompasses("internet", "https"));
    assert!(!scope.includes(&AuthScope::wildcard()));
    eprintln!("[test 23] PASS: non-empty constraints rejected");
}

#[test]
fn test_tier0_self_assertion_eligible() {
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::MeshRelay));
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::Discovery));
    eprintln!("[test 24] PASS: Tier 0 self-assertion establishes eligibility");
}

#[test]
fn test_tier2_requires_authorization() {
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::InternetGateway));
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::Compute));
    eprintln!("[test 25] PASS: Tier 2 requires explicit authorization");
}

#[test]
fn test_classify_capability_claim_tier2_not_authorized() {
    let result = classify_capability_claim(ProtocolCapability::InternetGateway, None);
    assert!(matches!(result, CapabilityClaimResult::NotAuthorized));
    eprintln!("[test 26] PASS: classify_capability_claim — Tier 2 not authorized");
}

#[test]
fn test_governance_anchor_self_signature_valid() {
    let (gov_secret, _) = fresh_keypair("governance");
    let anchor = GovernanceTrustAnchor::new(&gov_secret, 1, test_time(), test_time() + 86400);
    assert!(anchor.verify_self_signature());
    eprintln!("[test 27] PASS: governance anchor self-signature valid");
}
