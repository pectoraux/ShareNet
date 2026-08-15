//! N2.5.1 — Golden Conformance Vector Generator
//!
//! Generates frozen CBOR artifacts + expected hashes/signatures for all
//! N2.5 protocol objects. The output is consumed by the cross-platform
//! conformance runner (Rust, Kotlin, Python, Swift) to verify byte-for-byte
//! agreement.
//!
//! Usage: cargo run -p snp-node --example gen_n25_vectors

#![allow(clippy::pedantic)]

use snp_cbor::{encode, CborValue};
use snp_crypto::{derive_public_key, sha256, ed25519_sign, SecretKey};
use snp_node::node::capability::*;
use snp_node::node::identity::Capability;
use std::fs;

fn main() {
    // ── Fixed deterministic inputs (frozen) ──
    let gov_secret: SecretKey = sha256(b"n25-gov-secret");
    let gov_pk = derive_public_key(&gov_secret);
    let issuer_secret: SecretKey = sha256(b"n25-issuer-secret");
    let issuer_pk = derive_public_key(&issuer_secret);
    let subject_pk = derive_public_key(&sha256(b"n25-subject-secret"));

    let issuer_id = snp_crypto::domain_hash(b"SNP/0.1 node\0", &issuer_pk);
    let subject_id = snp_crypto::domain_hash(b"SNP/0.1 node\0", &subject_pk);
    let t0: u64 = 1_700_000_000;

    let mut vectors = Vec::new();

    // ── Vector suite: capability-authority ──
    // IssuerAuthority
    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        t0, t0 + 86400, t0,
    ).unwrap();
    let auth_cbor = authority.to_cbor_value();
    let auth_cbor_bytes = encode(&auth_cbor).unwrap();
    let auth_preimage = authority.canonical_preimage().unwrap();
    let auth_digest = authority.authority_digest().unwrap();
    vectors.push(vector_entry(
        "issuer-authority-v1",
        "Frozen IssuerAuthority CBOR + governance signature + authority digest",
        "capability-authority",
        &auth_cbor_bytes,
        &auth_preimage,
        &auth_digest,
        &authority.governance_signature,
        &gov_pk,
        &issuer_id,
    ));

    // CapabilityAuthorization
    let authorization = CapabilityAuthorization::new(
        &issuer_secret, issuer_id, 1, auth_digest,
        subject_id, ProtocolCapability::InternetGateway,
        AuthScope::wildcard(),
        t0, t0 + 3600, [0u8; 16],
    ).unwrap();
    let authz_preimage = authorization.canonical_preimage().unwrap();
    vectors.push(vector_entry(
        "capability-authorization-v1",
        "Frozen CapabilityAuthorization signing preimage + issuer signature",
        "capability-authority",
        &authz_preimage,  // the preimage IS the canonical form for verification
        &authz_preimage,
        &sha256(&authz_preimage),
        &authorization.issuer_signature,
        &issuer_pk,
        &subject_id,
    ));

    // GovernanceIssuerRevocation
    let gov_rev = GovernanceIssuerRevocation::new(
        &gov_secret, issuer_id, 1, 1, t0 - 100, [0u8; 16],
    ).unwrap();
    let gov_rev_cbor = gov_rev.to_cbor_value();
    let gov_rev_bytes = encode(&gov_rev_cbor).unwrap();
    let gov_rev_preimage = gov_rev.canonical_preimage().unwrap();
    let gov_rev_digest = gov_rev.revocation_digest().unwrap();
    vectors.push(vector_entry(
        "governance-issuer-revocation-v1",
        "Frozen GovernanceIssuerRevocation CBOR + governance signature + revocation digest",
        "capability-authority",
        &gov_rev_bytes,
        &gov_rev_preimage,
        &gov_rev_digest,
        &gov_rev.governance_signature,
        &gov_pk,
        &issuer_id,
    ));

    // SubjectCapabilityRevocation
    let subj_rev = SubjectCapabilityRevocation::new(
        &issuer_secret, issuer_id, 1, auth_digest,
        subject_id, ProtocolCapability::InternetGateway,
        1, t0, [0u8; 16],
    ).unwrap();
    let subj_rev_cbor = subj_rev.to_cbor_value();
    let subj_rev_bytes = encode(&subj_rev_cbor).unwrap();
    let subj_rev_preimage = subj_rev.canonical_preimage().unwrap();
    let subj_rev_digest = subj_rev.revocation_digest().unwrap();
    vectors.push(vector_entry(
        "subject-capability-revocation-v1",
        "Frozen SubjectCapabilityRevocation CBOR + issuer signature + revocation digest (authority-version bound)",
        "capability-authority",
        &subj_rev_bytes,
        &subj_rev_preimage,
        &subj_rev_digest,
        &subj_rev.issuer_signature,
        &issuer_pk,
        &subject_id,
    ));

    // ── Vector suite: capability-model ──
    // NodeCapability (extensible) string mappings
    let cap_strings = vec![
        (Capability::Client, "client"),
        (Capability::Relay, "relay"),
        (Capability::Gateway, "gateway"),
        (Capability::MeshRelay, "mesh-relay"),
        (Capability::InternetGateway, "internet-gateway"),
        (Capability::ContentSeed, "content-seed"),
        (Capability::Storage, "storage"),
        (Capability::Discovery, "discovery"),
        (Capability::Sync, "sync"),
        (Capability::Compute, "compute"),
        (Capability::CryptoRelay, "crypto-relay"),
        (Capability::CryptoGateway, "crypto-gateway"),
        (Capability::PaymentRelay, "payment-relay"),
    ];
    for (cap, expected_str) in cap_strings {
        vectors.push(serde_json::json!({
            "id": format!("capability-string-{}", expected_str),
            "suite": "capability-model",
            "description": format!("Capability::{:?} serializes to \"{}\"", cap, expected_str),
            "protocol_version": "2.5",
            "input": {
                "capability_variant": format!("{:?}", cap),
            },
            "expected": {
                "string": expected_str,
                "is_gateway_capability": cap.is_gateway_capability(),
                "is_relay_capability": cap.is_relay_capability(),
                "protocol_capability_byte": cap.to_protocol_capability().map(|p| p.to_byte()),
            },
        }));
    }

    // ── Write output ──
    let output = serde_json::json!({
        "protocol_version": "2.5",
        "frozen_at_commit": "39dee10",
        "generated_by": "snp-node gen_n25_vectors",
        "suites": {
            "capability-authority": "IssuerAuthority, CapabilityAuthorization, GovernanceIssuerRevocation, SubjectCapabilityRevocation — CBOR + signatures + digests",
            "capability-model": "NodeCapability string mappings (extensible set, old + new variants)",
        },
        "vectors": vectors,
    });

    // Write to public/conformance/vectors/
    // The example runs from reference/ (the workspace root), so the path is
    // ../public/conformance/vectors
    let out_dir = "../public/conformance/vectors";
    fs::create_dir_all(out_dir).expect("create vectors dir");
    let json = serde_json::to_string_pretty(&output).unwrap();
    fs::write(format!("{out_dir}/16-capability-authority.json"), &json).unwrap();
    eprintln!("Wrote {out_dir}/16-capability-authority.json ({} vectors)", vectors.len());
}

fn vector_entry(
    id: &str,
    description: &str,
    suite: &str,
    cbor_bytes: &[u8],
    preimage: &[u8],
    digest: &[u8; 32],
    signature: &[u8; 64],
    signer_pk: &[u8; 32],
    subject_id: &[u8; 32],
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "suite": suite,
        "description": description,
        "protocol_version": "2.5",
        "input": {
            "cbor_hex": hex::encode(cbor_bytes),
            "preimage_hex": hex::encode(preimage),
        },
        "expected": {
            "digest_hex": hex::encode(digest),
            "signature_hex": hex::encode(signature),
            "signer_public_key_hex": hex::encode(signer_pk),
            "subject_node_id_hex": hex::encode(subject_id),
            "verifies": true,
        },
    })
}
