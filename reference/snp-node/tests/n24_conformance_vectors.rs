//! N2.4-I1 rev5 — Frozen Conformance Vectors
//!
//! These vectors freeze the canonical CBOR encoding, signing preimages,
//! authority digest, revocation digests, and signatures for all N2.4-02
//! capability objects. They are consumed by tests — if the implementation's
//! canonical representation changes (e.g. field order, context string, CBOR
//! encoding), these tests will fail.
//!
//! ## Fixed inputs (deterministic)
//!
//! - governance secret = SHA-256("conformance-governance-key")
//! - issuer secret     = SHA-256("conformance-issuer-key")
//! - subject key       = SHA-256("conformance-subject-key")
//! - t0                = 1_700_000_000
//! - nonce             = [0u8; 16]
//! - scope             = wildcard (all empty)
//! - capability        = InternetGateway (byte 5)
//! - authority_version = 1

#![allow(clippy::pedantic)]

use snp_crypto::{derive_public_key, sha256, SecretKey};
use snp_node::node::capability::*;
use snp_cbor::encode;

// ─── Fixed inputs ───────────────────────────────────────────────────────────

fn gov_secret() -> SecretKey { sha256(b"conformance-governance-key") }
fn issuer_secret() -> SecretKey { sha256(b"conformance-issuer-key") }
fn gov_pk() -> [u8; 32] { derive_public_key(&gov_secret()) }
fn issuer_pk() -> [u8; 32] { derive_public_key(&issuer_secret()) }
fn subject_pk() -> [u8; 32] { derive_public_key(&sha256(b"conformance-subject-key")) }
fn gov_id() -> [u8; 32] { sha256(&gov_pk()) }
fn issuer_id() -> [u8; 32] { snp_crypto::domain_hash(b"SNP/0.1 node\0", &issuer_pk()) }
fn subject_id() -> [u8; 32] { snp_crypto::domain_hash(b"SNP/0.1 node\0", &subject_pk()) }
fn t0() -> u64 { 1_700_000_000 }

// ─── Frozen vectors ──────────────────────────────────────────────────────────

/// Frozen governance public key (Ed25519 derived from SHA-256("conformance-governance-key")).
const FROZEN_GOV_PK: [u8; 32] = [
    0x30, 0x22, 0x14, 0x3a, 0x2c, 0xf9, 0xc5, 0x8a,
    0xef, 0x34, 0x5f, 0xcc, 0x16, 0x96, 0x58, 0xd1,
    0x4e, 0x9b, 0x21, 0x08, 0xec, 0x4b, 0xd6, 0x20,
    0x3a, 0xac, 0x64, 0xc1, 0xf2, 0xc2, 0x4d, 0xe2,
];

/// Frozen governance_id (SHA-256(governance_public_key)).
const FROZEN_GOV_ID: [u8; 32] = [
    0x0c, 0xe9, 0xb4, 0x5f, 0x92, 0xcd, 0x2e, 0x24,
    0x8b, 0x97, 0x78, 0x8f, 0xc2, 0xf0, 0xd5, 0x45,
    0x17, 0xbe, 0xb1, 0x5e, 0xdf, 0x1f, 0x3a, 0x66,
    0xa9, 0xea, 0x7d, 0xf4, 0xf1, 0x66, 0xe7, 0x2d,
];

/// Frozen issuer_id (NodeId(issuer_public_key) = SHA-256("SNP/0.1 node\0" || issuer_pk)).
const FROZEN_ISSUER_ID: [u8; 32] = [
    0x41, 0xe5, 0xc0, 0x03, 0x78, 0xd0, 0x93, 0x68,
    0x94, 0xe4, 0x72, 0x8a, 0x5c, 0x3f, 0xc7, 0x32,
    0xde, 0xa5, 0x35, 0xef, 0xd7, 0xbc, 0xda, 0x4e,
    0x02, 0x82, 0xc5, 0x8e, 0xb0, 0x77, 0x80, 0x04,
];

/// Frozen issuer public key.
const FROZEN_ISSUER_PK: [u8; 32] = [
    0x44, 0x12, 0x29, 0x04, 0x12, 0x86, 0xd2, 0x32,
    0x1d, 0x62, 0xba, 0x62, 0xda, 0x5b, 0xfb, 0x39,
    0x8c, 0x23, 0xc1, 0x77, 0xa6, 0x57, 0x95, 0xe8,
    0x6a, 0xc3, 0x03, 0x42, 0xfe, 0x4d, 0x29, 0xf7,
];

/// Frozen subject_id (NodeId(subject_public_key)).
const FROZEN_SUBJECT_ID: [u8; 32] = [
    0xdb, 0xf2, 0x6a, 0xf0, 0xf2, 0xe3, 0xcf, 0x31,
    0xe3, 0x82, 0x99, 0x4f, 0xa4, 0x70, 0x2e, 0xce,
    0x3a, 0x23, 0x04, 0xc0, 0x12, 0x2e, 0x7e, 0xef,
    0x81, 0xe4, 0xa3, 0x6a, 0xa9, 0x2f, 0x31, 0x15,
];

/// Frozen IssuerAuthority digest (SHA-256 of CBOR excluding signature).
const FROZEN_AUTHORITY_DIGEST: [u8; 32] = [
    0x73, 0x28, 0x36, 0x0a, 0xe0, 0x5e, 0xef, 0xf2,
    0xaa, 0x8a, 0x1e, 0x02, 0x3b, 0x68, 0x97, 0x39,
    0x0c, 0x20, 0x0a, 0x95, 0x7e, 0xc8, 0xa1, 0xb9,
    0xdf, 0x6b, 0x3c, 0xf3, 0x73, 0xec, 0x68, 0xe5,
];

/// Frozen GovernanceIssuerRevocation digest.
const FROZEN_GOV_REV_DIGEST: [u8; 32] = [
    0x8c, 0xb6, 0x4e, 0x71, 0x65, 0xc6, 0xcb, 0x06,
    0x7d, 0xc5, 0xca, 0xc3, 0x6b, 0x4e, 0x90, 0x88,
    0xe2, 0x3e, 0x00, 0x37, 0x37, 0xde, 0x84, 0x39,
    0xc0, 0xde, 0x60, 0x85, 0x9b, 0xa4, 0x80, 0xbb,
];

/// Frozen SubjectCapabilityRevocation digest.
const FROZEN_SUBJ_REV_DIGEST: [u8; 32] = [
    0xc5, 0xa0, 0x91, 0xa3, 0x9a, 0x6a, 0xbe, 0xf8,
    0xf6, 0x38, 0x7a, 0x9b, 0x76, 0x69, 0x22, 0xae,
    0xf2, 0x11, 0x83, 0x62, 0x37, 0x59, 0xcb, 0x8c,
    0x2d, 0x2d, 0xee, 0x55, 0x88, 0xff, 0xfd, 0x25,
];

/// Frozen GovernanceTrustAnchor governance signature.
const FROZEN_ANCHOR_SIG: [u8; 64] = [
    0xf2, 0x35, 0xd0, 0xd0, 0x6a, 0x35, 0xcd, 0x34,
    0x4c, 0x9e, 0xb7, 0x15, 0x0a, 0x54, 0x7e, 0x01,
    0x18, 0x5b, 0xc1, 0xf1, 0x71, 0x27, 0x14, 0xdc,
    0x77, 0xb9, 0xbc, 0x8b, 0x12, 0xe9, 0xbe, 0x1d,
    0x62, 0xef, 0x2e, 0xb7, 0x61, 0x98, 0x57, 0x80,
    0xe6, 0xcf, 0xbf, 0x6d, 0x7f, 0xdd, 0x3b, 0xfb,
    0x57, 0x61, 0x76, 0x15, 0x82, 0x23, 0x13, 0xc8,
    0xdb, 0x78, 0x41, 0x80, 0x8b, 0x3e, 0x1a, 0x05,
];

/// Frozen IssuerAuthority governance signature.
const FROZEN_AUTHORITY_GOV_SIG: [u8; 64] = [
    0x76, 0xcf, 0x13, 0x1d, 0xee, 0x2b, 0x21, 0xe6,
    0x89, 0xaf, 0x5b, 0x1b, 0x19, 0xfc, 0x84, 0xdf,
    0xac, 0xb7, 0x32, 0x05, 0xbf, 0x67, 0x85, 0x98,
    0x4f, 0x69, 0xed, 0x81, 0x82, 0x01, 0x5a, 0x41,
    0x3c, 0x20, 0x94, 0x04, 0xaa, 0x40, 0x64, 0xea,
    0x92, 0xb0, 0x46, 0x4d, 0x56, 0xc7, 0x0f, 0xe0,
    0x95, 0x71, 0x14, 0x22, 0x70, 0x5a, 0xe9, 0x99,
    0x14, 0xa9, 0xc7, 0xf4, 0xcc, 0xfd, 0xb4, 0x09,
];

/// Frozen CapabilityAuthorization issuer signature.
const FROZEN_CAPAUTH_SIG: [u8; 64] = [
    0x5b, 0x31, 0x56, 0x45, 0x7d, 0x0b, 0x39, 0xe7,
    0x35, 0xf5, 0x30, 0xdf, 0xbb, 0x7a, 0xc5, 0xba,
    0x85, 0x96, 0x47, 0x04, 0xf5, 0x3c, 0x22, 0xe6,
    0xe4, 0xbc, 0x4a, 0xf0, 0x13, 0x34, 0xc2, 0xfd,
    0x94, 0x88, 0x9d, 0x03, 0x53, 0x89, 0xf6, 0x3d,
    0xfe, 0x3b, 0xf0, 0x6e, 0x44, 0xd2, 0x38, 0xa2,
    0x02, 0x5a, 0x0c, 0x0f, 0x65, 0x12, 0x51, 0xaa,
    0x50, 0xb0, 0x69, 0xeb, 0x95, 0x6a, 0x13, 0x09,
];

/// Frozen GovernanceIssuerRevocation governance signature.
const FROZEN_GOV_REV_SIG: [u8; 64] = [
    0x1f, 0x3e, 0x77, 0x3f, 0x97, 0x36, 0x03, 0x4b,
    0x37, 0x79, 0x2c, 0x07, 0x4a, 0x72, 0xe2, 0x98,
    0x3f, 0xf5, 0xc2, 0x34, 0xd3, 0x74, 0x64, 0x34,
    0xb0, 0x53, 0xdd, 0x12, 0x47, 0xe6, 0xbd, 0xd3,
    0xf9, 0xbd, 0x40, 0x45, 0xe6, 0xd0, 0x24, 0x9e,
    0xaf, 0x12, 0x3a, 0xbe, 0x04, 0xb6, 0xa4, 0x76,
    0x4f, 0x66, 0xad, 0xfa, 0x2b, 0xb0, 0xaa, 0x71,
    0xe7, 0x31, 0xb9, 0x9f, 0xb7, 0x5f, 0x09, 0x02,
];

/// Frozen SubjectCapabilityRevocation issuer signature.
const FROZEN_SUBJ_REV_SIG: [u8; 64] = [
    0x0f, 0x6d, 0x22, 0xc8, 0x46, 0x83, 0x0d, 0x6c,
    0xd7, 0x89, 0x86, 0xc8, 0xfc, 0x85, 0xf9, 0x5d,
    0x71, 0xec, 0x02, 0x9a, 0x93, 0x6d, 0xa8, 0x72,
    0x30, 0xf1, 0xfe, 0x69, 0xab, 0x61, 0x54, 0xb8,
    0xcc, 0x23, 0xc8, 0x7a, 0x0e, 0x50, 0x22, 0x92,
    0x7c, 0x3d, 0xc3, 0x65, 0xf4, 0xcd, 0x11, 0xb7,
    0x1d, 0xa8, 0x43, 0xed, 0x6f, 0xb6, 0xcf, 0x52,
    0xec, 0xa1, 0xef, 0xdd, 0x9d, 0xfa, 0x41, 0x0e,
];

// ─── Helper: construct the canonical objects from fixed inputs ──────────────

fn build_anchor() -> GovernanceTrustAnchor {
    GovernanceTrustAnchor::new(&gov_secret(), 1, t0(), t0() + 86400).unwrap()
}

fn build_authority() -> IssuerAuthority {
    IssuerAuthority::new(
        &gov_secret(), &issuer_secret(), 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        t0(), t0() + 86400, t0(),
    ).unwrap()
}

fn build_authorization(auth_digest: [u8; 32]) -> CapabilityAuthorization {
    CapabilityAuthorization::new(
        &issuer_secret(), issuer_id(), 1, auth_digest,
        subject_id(), ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        t0(), t0() + 3600, [0u8; 16],
    ).unwrap()
}

fn build_gov_rev() -> GovernanceIssuerRevocation {
    GovernanceIssuerRevocation::new(
        &gov_secret(), issuer_id(), 1, 1, t0() - 100, [0u8; 16],
    ).unwrap()
}

fn build_subj_rev(auth_digest: [u8; 32]) -> SubjectCapabilityRevocation {
    SubjectCapabilityRevocation::new(
        &issuer_secret(), issuer_id(), 1, auth_digest,
        subject_id(), ProtocolCapability::InternetGateway,
        1, t0(), [0u8; 16],
    ).unwrap()
}

// ─── Conformance tests ──────────────────────────────────────────────────────

#[test]
fn test_frozen_governance_public_key() {
    assert_eq!(gov_pk(), FROZEN_GOV_PK, "governance public key must match frozen vector");
    assert_eq!(gov_id(), FROZEN_GOV_ID, "governance_id must match frozen vector");
    eprintln!("[conf 1] PASS: governance public key + id match frozen vector");
}

#[test]
fn test_frozen_issuer_identity() {
    assert_eq!(issuer_pk(), FROZEN_ISSUER_PK, "issuer public key must match frozen vector");
    assert_eq!(issuer_id(), FROZEN_ISSUER_ID, "issuer_id (NodeId) must match frozen vector");
    eprintln!("[conf 2] PASS: issuer public key + NodeId match frozen vector");
}

#[test]
fn test_frozen_subject_identity() {
    assert_eq!(subject_id(), FROZEN_SUBJECT_ID, "subject_id (NodeId) must match frozen vector");
    eprintln!("[conf 3] PASS: subject NodeId matches frozen vector");
}

#[test]
fn test_frozen_authority_digest() {
    let authority = build_authority();
    let digest = authority.authority_digest().unwrap();
    assert_eq!(digest, FROZEN_AUTHORITY_DIGEST, "authority digest must match frozen vector");
    eprintln!("[conf 4] PASS: authority digest matches frozen vector");
}

#[test]
fn test_frozen_governance_revocation_digest() {
    let rev = build_gov_rev();
    let digest = rev.revocation_digest().unwrap();
    assert_eq!(digest, FROZEN_GOV_REV_DIGEST, "governance revocation digest must match frozen vector");
    eprintln!("[conf 5] PASS: governance revocation digest matches frozen vector");
}

#[test]
fn test_frozen_subject_revocation_digest() {
    let auth_digest = build_authority().authority_digest().unwrap();
    let rev = build_subj_rev(auth_digest);
    let digest = rev.revocation_digest().unwrap();
    assert_eq!(digest, FROZEN_SUBJ_REV_DIGEST, "subject revocation digest must match frozen vector");
    eprintln!("[conf 6] PASS: subject revocation digest matches frozen vector");
}

#[test]
fn test_frozen_anchor_preimage_and_signature() {
    let anchor = build_anchor();
    let preimage = anchor.canonical_preimage().unwrap();

    // The preimage starts with the SIG_CONTEXT constant.
    assert!(preimage.starts_with(b"SNP/0.1 governance-anchor\0"),
        "anchor preimage must start with the governance-anchor context");

    // The signature must verify against this preimage.
    assert!(anchor.verify_self_signature(),
        "anchor self-signature must verify");

    // The signature must match the frozen vector.
    assert_eq!(anchor.governance_signature, FROZEN_ANCHOR_SIG,
        "governance anchor signature must match frozen vector");
    eprintln!("[conf 7] PASS: anchor preimage + signature match frozen vector");
}

#[test]
fn test_frozen_authority_preimage_and_signature() {
    let authority = build_authority();
    let preimage = authority.canonical_preimage().unwrap();

    assert!(preimage.starts_with(b"SNP/0.1 issuer-authority\0"),
        "authority preimage must start with the issuer-authority context");
    assert!(authority.verify_governance_signature(&gov_pk()),
        "authority governance signature must verify");
    assert_eq!(authority.governance_signature, FROZEN_AUTHORITY_GOV_SIG,
        "authority governance signature must match frozen vector");
    eprintln!("[conf 8] PASS: authority preimage + signature match frozen vector");
}

#[test]
fn test_frozen_capability_authorization_preimage_and_signature() {
    let auth_digest = build_authority().authority_digest().unwrap();
    let authorization = build_authorization(auth_digest);
    let preimage = authorization.canonical_preimage().unwrap();

    assert!(preimage.starts_with(b"SNP/0.1 capability-authorization\0"),
        "authorization preimage must start with the capability-authorization context");
    assert!(authorization.verify_issuer_signature(&issuer_pk()),
        "authorization issuer signature must verify");
    assert_eq!(authorization.issuer_signature, FROZEN_CAPAUTH_SIG,
        "capability authorization signature must match frozen vector");
    eprintln!("[conf 9] PASS: capability authorization preimage + signature match frozen vector");
}

#[test]
fn test_frozen_governance_revocation_preimage_and_signature() {
    let rev = build_gov_rev();
    let preimage = rev.canonical_preimage().unwrap();

    assert!(preimage.starts_with(b"SNP/0.1 governance-revocation\0"),
        "gov revocation preimage must start with the governance-revocation context");
    assert!(rev.verify_governance_signature(&gov_pk()),
        "gov revocation governance signature must verify");
    assert_eq!(rev.governance_signature, FROZEN_GOV_REV_SIG,
        "governance revocation signature must match frozen vector");
    eprintln!("[conf 10] PASS: governance revocation preimage + signature match frozen vector");
}

#[test]
fn test_frozen_subject_revocation_preimage_and_signature() {
    let auth_digest = build_authority().authority_digest().unwrap();
    let rev = build_subj_rev(auth_digest);
    let preimage = rev.canonical_preimage().unwrap();

    assert!(preimage.starts_with(b"SNP/0.1 subject-revocation\0"),
        "subj revocation preimage must start with the subject-revocation context");
    assert!(rev.verify_issuer_signature(&issuer_pk()),
        "subj revocation issuer signature must verify");
    assert_eq!(rev.issuer_signature, FROZEN_SUBJ_REV_SIG,
        "subject revocation signature must match frozen vector");
    eprintln!("[conf 11] PASS: subject revocation preimage + signature match frozen vector");
}

#[test]
fn test_frozen_persistence_canonical_representation() {
    // Build a store with all three object types and verify the persisted file
    // contains exactly the expected entry CBOR encodings.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snp_test_conf_{:x}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let authority = build_authority();
    let auth_digest = authority.authority_digest().unwrap();
    let gov_rev = build_gov_rev();
    let subj_rev = build_subj_rev(auth_digest);

    let mut store = AuthorityStateStore::open(&path, gov_pk()).unwrap();
    store.try_accept_authority(&authority).unwrap();
    store.try_accept_governance_revocation(&gov_rev).unwrap();
    store.try_accept_subject_revocation(&subj_rev).unwrap();

    // Read the persisted file and verify its structure.
    let file_data = std::fs::read(&path).unwrap();
    assert!(file_data.starts_with(b"SNCA"), "file must start with magic");
    assert_eq!(file_data[4], 2, "file must be version 2");

    // Parse the entries and verify each contains the expected CBOR.
    let mut cursor = 5; // skip magic + version
    let mut found_authority = false;
    let mut found_gov_rev = false;
    let mut found_subj_rev = false;

    let expected_auth_cbor = encode(&authority.to_cbor_value()).unwrap();
    let expected_gov_rev_cbor = encode(&gov_rev.to_cbor_value()).unwrap();
    let expected_subj_rev_cbor = encode(&subj_rev.to_cbor_value()).unwrap();

    while cursor < file_data.len() {
        let len = u32::from_le_bytes([
            file_data[cursor], file_data[cursor + 1], file_data[cursor + 2], file_data[cursor + 3],
        ]) as usize;
        cursor += 4;
        let entry_bytes = &file_data[cursor..cursor + len];
        cursor += len;

        let decoded = snp_cbor::decode(entry_bytes).unwrap();
        if let snp_cbor::CborValue::Map(entries) = decoded {
            let mut etype = String::new();
            let mut eobj = snp_cbor::CborValue::Null;
            for (k, v) in &entries {
                if let (snp_cbor::CborValue::TextString(t), val) = (k, v) {
                    if t == "type" {
                        if let snp_cbor::CborValue::TextString(s) = val {
                            etype = s.clone();
                        }
                    } else if t == "object" {
                        eobj = val.clone();
                    }
                }
            }
            let obj_bytes = encode(&eobj).unwrap();
            match etype.as_str() {
                "authority" => {
                    assert_eq!(obj_bytes, expected_auth_cbor,
                        "persisted authority CBOR must match frozen encoding");
                    found_authority = true;
                }
                "gov_rev" => {
                    assert_eq!(obj_bytes, expected_gov_rev_cbor,
                        "persisted gov revocation CBOR must match frozen encoding");
                    found_gov_rev = true;
                }
                "subj_rev" => {
                    assert_eq!(obj_bytes, expected_subj_rev_cbor,
                        "persisted subj revocation CBOR must match frozen encoding");
                    found_subj_rev = true;
                }
                _ => panic!("unknown entry type: {etype}"),
            }
        }
    }

    assert!(found_authority, "persisted file must contain authority entry");
    assert!(found_gov_rev, "persisted file must contain gov_rev entry");
    assert!(found_subj_rev, "persisted file must contain subj_rev entry");

    let _ = std::fs::remove_file(&path);
    eprintln!("[conf 12] PASS: persistence canonical representation matches frozen vectors");
}
