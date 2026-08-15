//! N2.4-I1 rev4 — Capability & Authority Foundation: adversarial tests.
//!
//! Tests for the corrected N2.4-02 Capability System with:
//! - P0 #1 rev4: IssuerStatus::Active enforced in verify_authorization()
//! - P0 #2 rev4: SubjectCapabilityRevocation bound to exact authority version+digest
//! - P0 #3 rev4: Durable persistence (fsync temp + rename + fsync parent dir)
//! - P1 #4 rev4: load() validates crypto provenance + equivocation into a candidate
//! - P1 #5 rev4: decode_auth_scope_from_cbor fails closed on wrong-type known fields
//! - Retained rev3 coverage: signature verification, complete persistence,
//!   transactional mutation, exact governance-revocation version binding,
//!   same-version equivocation detection, safe constraint default.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_public_key, ed25519_sign, sha256, SecretKey};
use snp_node::node::capability::*;
use snp_cbor::{encode, CborValue};
use std::path::{Path, PathBuf};

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

/// Construct an authority with a non-default status. Because `status` is part
/// of the canonical preimage (and thus the governance signature), the
/// governance signature is re-computed after setting the status.
fn authority_with_status(
    gov_secret: &SecretKey,
    issuer_secret: &SecretKey,
    version: u64,
    status: IssuerStatus,
) -> IssuerAuthority {
    let mut auth = make_authority(gov_secret, issuer_secret, version);
    auth.status = status;
    let preimage = auth.canonical_preimage().unwrap();
    auth.governance_signature = ed25519_sign(gov_secret, &preimage);
    auth
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

/// P0 #2 rev4: subject revocation helper now binds to the exact authority
/// (version + digest) supplied.
fn make_subj_revocation(
    issuer_secret: &SecretKey,
    issuer_id: [u8; 32],
    authority: &IssuerAuthority,
    subject_id: [u8; 32],
) -> SubjectCapabilityRevocation {
    SubjectCapabilityRevocation::new(
        issuer_secret, issuer_id,
        authority.authority_version,
        authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap()
}

/// Write a synthetic SNCA store file from a list of (type, object) entries.
/// Used to craft malformed/persisted security state for fail-closed tests.
fn write_store_file(path: &Path, entries: &[(&str, CborValue)]) {
    let mut data = Vec::new();
    data.extend_from_slice(b"SNCA");
    data.push(2);
    for (etype, object) in entries {
        let entry = CborValue::Map(vec![
            (CborValue::TextString("type".into()), CborValue::TextString((*etype).to_string())),
            (CborValue::TextString("object".into()), object.clone()),
        ]);
        let encoded = encode(&entry).unwrap();
        data.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        data.extend_from_slice(&encoded);
    }
    std::fs::write(path, &data).unwrap();
}

// ─── P0 #1 rev4: IssuerStatus::Active enforcement ───────────────────────────

#[test]
fn test_revoked_authority_rejects_authorization() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let revoked_authority =
        authority_with_status(&gov_secret, &issuer_secret, 1, IssuerStatus::Revoked);
    let auth = make_authorization(&issuer_secret, issuer_id, &revoked_authority, subject_id);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    // A governance-signed authority with status=Revoked is still accepted into
    // the store (it is a valid governance statement); verification rejects it.
    store.try_accept_authority(&revoked_authority).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::AuthorityStatusNotActive),
        "authority with status=Revoked MUST be rejected even without a GovernanceIssuerRevocation");
    eprintln!("[test 1] PASS (rev4): revoked authority rejects authorization");
}

#[test]
fn test_active_authority_permits_authorization() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let active_authority =
        authority_with_status(&gov_secret, &issuer_secret, 1, IssuerStatus::Active);
    let auth = make_authorization(&issuer_secret, issuer_id, &active_authority, subject_id);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&active_authority).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "active authority must permit authorization: {:?}", result);
    eprintln!("[test 2] PASS (rev4): active authority permits authorization");
}

#[test]
fn test_revoked_authority_status_survives_restart() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_rev_status_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let revoked_authority =
        authority_with_status(&gov_secret, &issuer_secret, 1, IssuerStatus::Revoked);
    let auth = make_authorization(&issuer_secret, issuer_id, &revoked_authority, subject_id);

    let mut store1 = AuthorityStateStore::open(&path, gov_pk).unwrap();
    store1.try_accept_authority(&revoked_authority).unwrap();

    // Restart: the persisted Revoked status must be restored AND respected.
    let store2 = AuthorityStateStore::open(&path, gov_pk).unwrap();
    let ctx = VerificationContext::with_store(gov_pk, store2);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::AuthorityStatusNotActive),
        "revoked status must survive restart and be respected after reload");

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 3] PASS (rev4): revoked authority status survives restart");
}

// ─── P0 #1 rev3 (retained): Signature verification before acceptance ───────

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
    eprintln!("[test 4] PASS: unsigned authority cannot poison store");
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
    eprintln!("[test 5] PASS: invalid governance revocation signature rejected");
}

#[test]
fn test_subject_revocation_without_authority_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    // P0 #2 rev4: revocation binds to a real authority (v1) that is NOT accepted.
    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let rev = make_subj_revocation(&issuer_secret, issuer_id, &authority, subject_id);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);

    // No authority accepted → cannot resolve the exact bound authority version.
    let result = store.try_accept_subject_revocation(&rev);
    assert!(matches!(result, Err(AuthorityStateError::IssuerAuthorityNotFound { .. })));
    eprintln!("[test 6] PASS: subject revocation without authority rejected");
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

    // P0 #2 rev4: revocation correctly binds to authority v1 (version+digest),
    // but is signed by the WRONG key (attacker, not issuer).
    let bad_rev = SubjectCapabilityRevocation::new(
        &attacker_secret, issuer_id,
        authority.authority_version,
        authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();

    let result = store.try_accept_subject_revocation(&bad_rev);
    assert!(matches!(result, Err(AuthorityStateError::RevocationSignatureInvalid)));
    eprintln!("[test 7] PASS: subject revocation with wrong issuer key rejected");
}

// ─── P0 #2 rev4: Subject revocation bound to exact authority version+digest ──

#[test]
fn test_authority_v1_revocation_survives_authority_v2() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    // v1 authority + v1 authorization + v1 subject revocation (bound to v1).
    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);
    let authorization_v1 = make_authorization(&issuer_secret, issuer_id, &auth_v1, subject_id);
    let subj_rev_v1 = make_subj_revocation(&issuer_secret, issuer_id, &auth_v1, subject_id);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth_v1).unwrap();
    store.try_accept_subject_revocation(&subj_rev_v1).unwrap();

    // Accept v2 authority for the same issuer.
    let auth_v2 = make_authority(&gov_secret, &issuer_secret, 2);
    store.try_accept_authority(&auth_v2).unwrap();

    // The v1 subject revocation MUST remain retrievable via its exact version.
    let restored = store.get_subject_revocation(
        &issuer_id, &subject_id, ProtocolCapability::InternetGateway, 1,
    );
    assert!(restored.is_some(), "v1 subject revocation must survive later v2 authority");

    // The v1 subject revocation MUST still revoke the v1 authorization.
    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&authorization_v1, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::SubjectRevoked),
        "v1 revocation must still revoke v1 authorization after v2 accepted");
    eprintln!("[test 8] PASS (rev4): v1 revocation survives later v2 authority");
}

#[test]
fn test_v1_revocation_does_not_revoke_v2_authorization() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);
    let auth_v2 = make_authority(&gov_secret, &issuer_secret, 2);
    // v2 authorization (issued under v2) for the SAME subject.
    let authorization_v2 = make_authorization(&issuer_secret, issuer_id, &auth_v2, subject_id);
    // v1 subject revocation (bound to v1).
    let subj_rev_v1 = make_subj_revocation(&issuer_secret, issuer_id, &auth_v1, subject_id);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth_v1).unwrap();
    store.try_accept_authority(&auth_v2).unwrap();
    store.try_accept_subject_revocation(&subj_rev_v1).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    // The v1 revocation is bound to v1; it MUST NOT revoke the v2 authorization.
    let result = ctx.verify_authorization(&authorization_v2, test_time() + 100);
    assert!(result.is_ok(),
        "v1 subject revocation must NOT revoke v2 authorization (exact-version binding): {:?}", result);
    eprintln!("[test 9] PASS (rev4): v1 revocation does not revoke v2 authorization");
}

#[test]
fn test_v2_key_cannot_sign_v1_revocation() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, attacker_secret) = fresh_keypair("attacker-v2-key");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);

    // Attacker constructs a revocation correctly bound to v1 (version + digest)
    // — which is all public information — but signs it with their own key.
    let forged_rev = SubjectCapabilityRevocation::new(
        &attacker_secret, issuer_id,
        auth_v1.authority_version,
        auth_v1.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth_v1).unwrap();

    let result = store.try_accept_subject_revocation(&forged_rev);
    assert!(matches!(result, Err(AuthorityStateError::RevocationSignatureInvalid)),
        "a key other than the v1 authority's issuer key cannot sign a v1 revocation");
    eprintln!("[test 10] PASS (rev4): v2/foreign key cannot sign a v1 revocation");
}

#[test]
fn test_wrong_subject_revocation_authority_version_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    // Only v1 exists; the revocation falsely claims authority_version = 99.
    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);
    let bogus_digest = auth_v1.authority_digest().unwrap();
    let wrong_version_rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id,
        99, // wrong authority version
        bogus_digest,
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth_v1).unwrap();

    let result = store.try_accept_subject_revocation(&wrong_version_rev);
    assert!(matches!(result, Err(AuthorityStateError::IssuerAuthorityNotFound { .. })),
        "wrong authority version must be rejected (exact-version resolution)");
    eprintln!("[test 11] PASS (rev4): wrong subject revocation authority version rejected");
}

#[test]
fn test_wrong_subject_revocation_authority_digest_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let auth_v1 = make_authority(&gov_secret, &issuer_secret, 1);
    // Correct version, but a bogus digest.
    let wrong_digest_rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id,
        auth_v1.authority_version,
        [0xAA; 32], // wrong digest
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&auth_v1).unwrap();

    let result = store.try_accept_subject_revocation(&wrong_digest_rev);
    assert!(matches!(result, Err(AuthorityStateError::AuthorityDigestMismatch)),
        "wrong authority digest must be rejected");
    eprintln!("[test 12] PASS (rev4): wrong subject revocation authority digest rejected");
}

// ─── P0 #2 rev3 (retained): Complete object persistence + restart ───────────

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
    let mut store1 = AuthorityStateStore::open(&path, gov_pk).unwrap();
    store1.try_accept_authority(&authority).unwrap();

    // Restart: open a new store from the same file.
    let store2 = AuthorityStateStore::open(&path, gov_pk).unwrap();

    // Verify the authority was restored — verify_authorization must work without reinjection.
    let ctx = VerificationContext::with_store(gov_pk, store2);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "verify_authorization must work after restart: {:?}", result);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 13] PASS: complete authority survives restart + verify_authorization works");
}

#[test]
fn test_complete_revocation_survives_restart() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_rev_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let gov_rev = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time() - 100, [0u8; 16],
    ).unwrap();

    // Write authority + governance revocation.
    let mut store1 = AuthorityStateStore::open(&path, gov_pk).unwrap();
    store1.try_accept_authority(&authority).unwrap();
    store1.try_accept_governance_revocation(&gov_rev).unwrap();

    // Restart.
    let store2 = AuthorityStateStore::open(&path, gov_pk).unwrap();

    // Verify governance revocation was restored.
    let restored_rev = store2.get_governance_revocation(&issuer_id, 1);
    assert!(restored_rev.is_some(), "governance revocation must survive restart");
    assert_eq!(restored_rev.unwrap().revocation_version, 1);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 14] PASS: complete governance revocation survives restart");
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
    let subj_rev = make_subj_revocation(&issuer_secret, issuer_id, &authority, subject_id);

    let mut store1 = AuthorityStateStore::open(&path, gov_pk).unwrap();
    store1.try_accept_authority(&authority).unwrap();
    store1.try_accept_subject_revocation(&subj_rev).unwrap();

    // Restart.
    let store2 = AuthorityStateStore::open(&path, gov_pk).unwrap();

    // P0 #2 rev4: lookup now requires the exact authority version (1).
    let restored = store2.get_subject_revocation(
        &issuer_id, &subject_id, ProtocolCapability::InternetGateway, 1,
    );
    assert!(restored.is_some(), "subject revocation must survive restart");
    assert_eq!(restored.unwrap().revocation_version, 1);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 15] PASS: complete subject revocation survives restart");
}

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
    let mut store = AuthorityStateStore::open(&path, gov_pk).unwrap();
    store.try_accept_authority(&authority).unwrap();

    // Restart: create a new VerificationContext from the persistent file.
    let restarted_store = store.restart().unwrap();
    let ctx = VerificationContext::with_store(gov_pk, restarted_store);

    // verify_authorization must work without any re-registration.
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert!(result.is_ok(), "verify_authorization after restart must succeed: {:?}", result);

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 16] PASS: restart + verify_authorization succeeds without reinjection");
}

// ─── P0 #2 / P1 #4: Malformed persistence fails closed ──────────────────────

#[test]
fn test_malformed_authority_persistence_record_fails_closed() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_malformed_{:x}.bin", std::process::id()));
    let (gov_secret, _) = fresh_keypair("governance");
    let gov_pk = derive_public_key(&gov_secret);

    // Write a valid SNCA v2 file but with a truncated authority entry.
    let mut data = Vec::new();
    data.extend_from_slice(b"SNCA");
    data.push(2); // Version 2
    // Write a truncated entry: 4-byte length prefix + garbage.
    data.extend_from_slice(&10u32.to_le_bytes());
    data.extend_from_slice(&[0xFF; 10]);

    std::fs::write(&path, &data).unwrap();

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(), "malformed persistence record must fail closed");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 17] PASS: malformed authority persistence record fails closed");
}

#[test]
fn test_corrupted_persistence_file_fails_closed() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_cap_corrupt_{:x}.bin", std::process::id()));
    let (gov_secret, _) = fresh_keypair("governance");
    let gov_pk = derive_public_key(&gov_secret);

    std::fs::write(&path, b"GARBAGE").unwrap();

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(), "corrupted persistence file must fail closed");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 18] PASS: corrupted persistence file fails closed");
}

// ─── P0 #3 rev4: Durable persistence ─────────────────────────────────────────

#[test]
fn test_durable_commit_completes_full_sequence() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_durable_ok_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("tmp"));

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    let auth = make_authorization(&issuer_secret, issuer_id, &authority, subject_id);

    // Commit through the durable sequence (write temp → fsync temp → rename → fsync dir).
    let mut store = AuthorityStateStore::open(&path, gov_pk).unwrap();
    store.try_accept_authority(&authority).unwrap();

    // The durable commit completed: temp file is gone, target file is fully present.
    assert!(!path.with_extension("tmp").exists(), "temp file must be renamed away");
    let metadata = std::fs::metadata(&path).expect("durable file must exist");
    assert!(metadata.len() > 5, "durable file must contain full serialized state");

    // Re-open and verify the durable state round-trips.
    let store2 = AuthorityStateStore::open(&path, gov_pk).unwrap();
    let ctx = VerificationContext::with_store(gov_pk, store2);
    assert!(ctx.verify_authorization(&auth, test_time() + 100).is_ok());

    let _ = std::fs::remove_file(&path);
    eprintln!("[test 19] PASS (rev4): durable commit completes the full fsync sequence");
}

#[test]
fn test_durable_persistence_failure_fails_closed() {
    let dir = std::env::temp_dir();
    // Create a regular file and use it as the "parent" of the target path,
    // so File::create on the temp path fails with ENOTDIR. This reliably
    // triggers a commit (durability) failure regardless of the running user.
    let blocker = dir.join(format!("snp_blocker_{:x}", std::process::id()));
    let _ = std::fs::remove_file(&blocker);
    std::fs::write(&blocker, b"blocker").unwrap();
    let path = blocker.join("cap_store.bin");

    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let authority_v1 = make_authority(&gov_secret, &issuer_secret, 1);

    // In-memory accept succeeds (path not yet involved).
    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority_v1).unwrap();

    // Point the store at a path whose parent is a regular file → commit fails.
    store.path = Some(path);
    let authority_v2 = make_authority(&gov_secret, &issuer_secret, 2);
    let result = store.try_accept_authority(&authority_v2);
    assert!(result.is_err(), "durability failure must reject the operation");

    // P0 #3: live memory MUST be unchanged — v1 remains the highest version.
    let dup = store.try_accept_authority(&make_authority(&gov_secret, &issuer_secret, 1));
    assert_eq!(dup, Ok(AuthorityAcceptResult::Duplicate),
        "durable persistence failure must leave live state unchanged");

    let _ = std::fs::remove_file(&blocker);
    eprintln!("[test 20] PASS (rev4): durable persistence failure fails closed");
}

#[test]
fn test_persistence_failure_leaves_memory_unchanged() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let authority = make_authority(&gov_secret, &issuer_secret, 1);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);

    let result = store.try_accept_authority(&authority);
    assert!(result.is_ok(), "in-memory store should accept authority: {:?}", result);

    // Now point at a non-existent directory and try to accept v2: commit fails.
    store.path = Some(PathBuf::from("/nonexistent/dir/cap_store.bin"));

    let auth_v2 = make_authority(&gov_secret, &issuer_secret, 2);
    let fail_result = store.try_accept_authority(&auth_v2);
    assert!(fail_result.is_err(), "persistence failure should reject the operation");

    let auth_v1_dup = make_authority(&gov_secret, &issuer_secret, 1);
    let dup_result = store.try_accept_authority(&auth_v1_dup);
    assert_eq!(dup_result, Ok(AuthorityAcceptResult::Duplicate),
        "v1 must still be the highest (persistence failure left memory unchanged)");
    eprintln!("[test 21] PASS: persistence failure leaves memory unchanged");
    let _ = gov_secret;
}

// ─── P1 #4 rev4: load() validates crypto provenance + equivocation ──────────

#[test]
fn test_malformed_persisted_authority_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_bad_auth_{:x}.bin", std::process::id()));
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    // Valid CBOR structure, but the governance signature is corrupted.
    let mut authority = make_authority(&gov_secret, &issuer_secret, 1);
    authority.governance_signature[0] ^= 0xFF;
    write_store_file(&path, &[("authority", authority.to_cbor_value())]);

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(),
        "persisted authority with invalid governance signature must fail closed on load");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 22] PASS (rev4): malformed persisted authority rejected (crypto re-verification)");
}

#[test]
fn test_malformed_persisted_authority_identity_binding_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_bad_id_{:x}.bin", std::process::id()));
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");
    let (_, wrong_pk) = fresh_keypair("attacker");

    // Valid governance signature? No — tampering issuer_id breaks the preimage,
    // so the signature will also fail. But the FIRST check that fires in load
    // is the identity binding (issuer_id != NodeId(issuer_public_key)).
    let mut authority = make_authority(&gov_secret, &issuer_secret, 1);
    authority.issuer_id = node_id_from_pk(&wrong_pk);
    write_store_file(&path, &[("authority", authority.to_cbor_value())]);

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(),
        "persisted authority with invalid identity binding must fail closed on load");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 23] PASS (rev4): malformed persisted authority identity binding rejected");
}

#[test]
fn test_malformed_persisted_gov_revocation_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_bad_govrev_{:x}.bin", std::process::id()));
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let issuer_id = node_id_from_pk(&issuer_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    // Valid CBOR, corrupted governance-revocation signature.
    let mut gov_rev = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, test_time(), [0u8; 16],
    ).unwrap();
    gov_rev.governance_signature[0] ^= 0xFF;

    write_store_file(&path, &[
        ("authority", authority.to_cbor_value()),
        ("gov_rev", gov_rev.to_cbor_value()),
    ]);

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(),
        "persisted governance revocation with invalid signature must fail closed on load");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 24] PASS (rev4): malformed persisted governance revocation rejected");
}

#[test]
fn test_malformed_persisted_subject_revocation_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_bad_subjrev_{:x}.bin", std::process::id()));
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    // Valid CBOR + correct binding metadata, but corrupted issuer signature.
    let mut subj_rev = make_subj_revocation(&issuer_secret, issuer_id, &authority, subject_id);
    subj_rev.issuer_signature[0] ^= 0xFF;

    write_store_file(&path, &[
        ("authority", authority.to_cbor_value()),
        ("subj_rev", subj_rev.to_cbor_value()),
    ]);

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(),
        "persisted subject revocation with invalid issuer signature must fail closed on load");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 25] PASS (rev4): malformed persisted subject revocation rejected");
}

#[test]
fn test_equivocating_persisted_authorities_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_eq_auth_{:x}.bin", std::process::id()));
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    // Two authorities: same (issuer, version=1), DIFFERENT digest (different
    // capabilities). Both are individually governance-signed and decode fine,
    // but they equivocate on (issuer, version).
    let auth_a = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();
    let auth_b = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::Compute],
        AuthScope::wildcard(),
        test_time(), test_time() + 86400, test_time(),
    ).unwrap();
    write_store_file(&path, &[
        ("authority", auth_a.to_cbor_value()),
        ("authority", auth_b.to_cbor_value()),
    ]);

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(),
        "equivocating persisted authorities (same version, different digest) must fail closed");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 26] PASS (rev4): equivocating persisted authorities rejected");
}

#[test]
fn test_equivocating_persisted_subject_revocations_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_eq_subj_{:x}.bin", std::process::id()));
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    // Two subject revocations bound to the SAME (issuer, subject, cap, auth_ver=1)
    // and same rev_version=1, but different digests (different nonce/timestamp).
    let rev_a = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id,
        authority.authority_version, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();
    let rev_b = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id,
        authority.authority_version, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time() + 100, [1u8; 16],
    ).unwrap();
    write_store_file(&path, &[
        ("authority", authority.to_cbor_value()),
        ("subj_rev", rev_a.to_cbor_value()),
        ("subj_rev", rev_b.to_cbor_value()),
    ]);

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(),
        "equivocating persisted subject revocations must fail closed");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 27] PASS (rev4): equivocating persisted subject revocations rejected");
}

// ─── P1 #5 rev4: fail closed on malformed AuthScope fields ───────────────────

#[test]
fn test_malformed_auth_scope_field_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_bad_scope_{:x}.bin", std::process::id()));
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    // Rebuild the authority CBOR with a malformed AuthScope: `destinations`
    // is a TextString instead of an Array.
    let malformed_scope = CborValue::Map(vec![
        (CborValue::TextString("destinations".into()),
         CborValue::TextString("not-an-array".into())),
        (CborValue::TextString("protocols".into()), CborValue::Array(vec![])),
        (CborValue::TextString("constraints".into()), CborValue::Array(vec![])),
    ]);
    let malformed_authority = CborValue::Array(vec![
        CborValue::ByteString(authority.issuer_id.to_vec()),
        CborValue::ByteString(authority.issuer_public_key.to_vec()),
        CborValue::UnsignedInt(authority.authority_version),
        CborValue::UnsignedInt(authority.issued_at),
        CborValue::UnsignedInt(authority.valid_from),
        CborValue::UnsignedInt(authority.valid_until),
        CborValue::Array(
            authority.capabilities_authorized.iter()
                .map(|c| CborValue::UnsignedInt(u64::from(c.to_byte())))
                .collect(),
        ),
        malformed_scope,
        CborValue::UnsignedInt(u64::from(authority.status as u8)),
        CborValue::ByteString(authority.governance_signature.to_vec()),
    ]);
    write_store_file(&path, &[("authority", malformed_authority)]);

    let result = AuthorityStateStore::open(&path, gov_pk);
    assert!(result.is_err(),
        "malformed AuthScope field (destinations wrong CBOR type) must fail closed");
    let _ = std::fs::remove_file(&path);
    eprintln!("[test 28] PASS (rev4): malformed AuthScope field rejected (fail closed)");
}

// ─── Retained rev3 coverage ──────────────────────────────────────────────────

#[test]
fn test_issuer_identity_binding_valid() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");

    let authority = make_authority(&gov_secret, &issuer_secret, 1);
    assert!(authority.verify_issuer_identity_binding());
    eprintln!("[test 29] PASS: issuer identity binding valid");
    let _ = issuer_pk;
}

#[test]
fn test_issuer_identity_binding_mismatch_rejected() {
    let (gov_secret, _) = fresh_keypair("governance");
    let (issuer_secret, _) = fresh_keypair("issuer");
    let (_, wrong_pk) = fresh_keypair("attacker");

    let mut authority = make_authority(&gov_secret, &issuer_secret, 1);
    authority.issuer_id = node_id_from_pk(&wrong_pk);

    assert!(!authority.verify_issuer_identity_binding());
    eprintln!("[test 30] PASS: issuer identity binding mismatch rejected");
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
    eprintln!("[test 31] PASS: higher authority version accepted");
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
    eprintln!("[test 32] PASS: same version + different digest = equivocation rejected");
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
    eprintln!("[test 33] PASS: governance revocation same version + different digest = equivocation");
}

#[test]
fn test_subject_revocation_same_version_different_digest_rejected() {
    let (gov_secret, gov_pk) = fresh_keypair("governance");
    let (issuer_secret, issuer_pk) = fresh_keypair("issuer");
    let (_, subject_pk) = fresh_keypair("subject");
    let issuer_id = node_id_from_pk(&issuer_pk);
    let subject_id = node_id_from_pk(&subject_pk);

    let authority = make_authority(&gov_secret, &issuer_secret, 1);

    // Same (issuer, subject, cap, auth_ver=1) and rev_version=1, different digest.
    let rev1 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id,
        authority.authority_version, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time(), [0u8; 16],
    ).unwrap();
    let rev2 = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id,
        authority.authority_version, authority.authority_digest().unwrap(),
        subject_id, ProtocolCapability::InternetGateway,
        1, test_time() + 100, [1u8; 16],
    ).unwrap();

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();
    store.try_accept_subject_revocation(&rev1).unwrap();
    let result = store.try_accept_subject_revocation(&rev2);
    assert!(matches!(result, Err(AuthorityStateError::RevocationEquivocation { .. })));
    eprintln!("[test 34] PASS: subject revocation same version + different digest = equivocation");
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
    eprintln!("[test 35] PASS: v2 governance revocation does not revoke v1 authorization");
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
    eprintln!("[test 36] PASS: v1 governance revocation revokes v1 authorization");
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
    eprintln!("[test 37] PASS: authorization valid — full chain verification");
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
    eprintln!("[test 38] PASS: expired authorization rejected");
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

    let subj_rev = make_subj_revocation(&issuer_secret, issuer_id, &authority, subject_id);

    let mut store = AuthorityStateStore::new();
    store.set_governance_public_key(gov_pk);
    store.try_accept_authority(&authority).unwrap();
    store.try_accept_subject_revocation(&subj_rev).unwrap();

    let ctx = VerificationContext::with_store(gov_pk, store);
    let result = ctx.verify_authorization(&auth, test_time() + 100);
    assert_eq!(result, Err(AuthorizationVerifyError::SubjectRevoked));
    eprintln!("[test 39] PASS: subject revoked — authorization rejected");
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
    eprintln!("[test 40] PASS: non-empty constraints rejected");
}

#[test]
fn test_tier0_self_assertion_eligible() {
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::MeshRelay));
    assert!(self_assertion_establishes_eligibility(ProtocolCapability::Discovery));
    eprintln!("[test 41] PASS: Tier 0 self-assertion establishes eligibility");
}

#[test]
fn test_tier2_requires_authorization() {
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::InternetGateway));
    assert!(!self_assertion_establishes_eligibility(ProtocolCapability::Compute));
    eprintln!("[test 42] PASS: Tier 2 requires explicit authorization");
}

#[test]
fn test_classify_capability_claim_tier2_not_authorized() {
    let result = classify_capability_claim(ProtocolCapability::InternetGateway, None);
    assert!(matches!(result, CapabilityClaimResult::NotAuthorized));
    eprintln!("[test 43] PASS: classify_capability_claim — Tier 2 not authorized");
}

#[test]
fn test_governance_anchor_self_signature_valid() {
    let (gov_secret, _) = fresh_keypair("governance");
    let anchor = GovernanceTrustAnchor::new(&gov_secret, 1, test_time(), test_time() + 86400);
    assert!(anchor.verify_self_signature());
    eprintln!("[test 44] PASS: governance anchor self-signature valid");
}
