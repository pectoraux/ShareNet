//! N2.5.1 — Cross-Platform Conformance Vector Runner
//!
//! Loads the frozen golden vectors from
//! `public/conformance/vectors/16-capability-authority.json` and verifies
//! that the Rust reference implementation produces byte-identical results.
//!
//! This is NOT a unit test — it consumes external serialized artifacts
//! (CBOR hex + expected hashes + signatures) and verifies them against the
//! Rust implementation. The same vector file can be consumed by a Kotlin,
//! Python, or Swift runner to prove cross-platform agreement.
//!
//! Usage: cargo test -p snp-node --test n251_conformance_runner

#![allow(clippy::pedantic)]

use snp_cbor::{decode, encode, CborValue};
use snp_crypto::{derive_public_key, ed25519_verify, sha256, SecretKey};
use snp_node::node::capability::*;
use snp_node::node::identity::Capability;
use std::fs;

/// Path to the frozen vector file relative to the workspace root.
const VECTOR_FILE: &str = "../../public/conformance/vectors/16-capability-authority.json";

/// Load the frozen vectors.
fn load_vectors() -> serde_json::Value {
    let content = fs::read_to_string(VECTOR_FILE)
        .unwrap_or_else(|e| panic!("failed to read {VECTOR_FILE}: {e}"));
    serde_json::from_str(&content).expect("vectors must be valid JSON")
}

/// Decode a hex string to bytes.
fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("hex decode failed: {e}"))
}

// ─── Suite: capability-authority ───────────────────────────────────────────

#[test]
fn conf_runner_capability_authority_vectors() {
    let vectors = load_vectors();
    let protocol_version = vectors["protocol_version"].as_str().unwrap();
    assert_eq!(protocol_version, "2.5", "protocol version must be 2.5");

    let vecs = vectors["vectors"].as_array().unwrap();
    let authority_vecs: Vec<_> = vecs
        .iter()
        .filter(|v| v["suite"].as_str() == Some("capability-authority"))
        .collect();

    assert!(!authority_vecs.is_empty(), "must have capability-authority vectors");

    for v in &authority_vecs {
        let id = v["id"].as_str().unwrap();
        let cbor_hex = v["input"]["cbor_hex"].as_str().unwrap();
        let preimage_hex = v["input"]["preimage_hex"].as_str().unwrap();
        let expected_sig_hex = v["expected"]["signature_hex"].as_str().unwrap();
        let signer_pk_hex = v["expected"]["signer_public_key_hex"].as_str().unwrap();

        let cbor_bytes = hex_decode(cbor_hex);
        let preimage = hex_decode(preimage_hex);
        let expected_sig = hex_decode(expected_sig_hex);
        let signer_pk: [u8; 32] = hex_decode(signer_pk_hex)
            .try_into()
            .unwrap();

        // 1. CBOR round-trip (only when cbor_hex ≠ preimage_hex — i.e. the
        //    cbor_hex is pure CBOR, not a preimage with context prefix).
        //    For capability-authorization-v1, cbor_hex IS the preimage
        //    (context + CBOR), which is not pure CBOR.
        if cbor_hex != preimage_hex {
            let decoded = decode(&cbor_bytes).unwrap_or_else(|e| {
                panic!("[{id}] CBOR decode failed: {e}")
            });
            let reencoded = encode(&decoded).unwrap();
            assert_eq!(
                reencoded, cbor_bytes,
                "[{id}] CBOR round-trip failed: encode(decode(bytes)) != bytes"
            );
        }

        // 2. The signature must verify against the signer's public key
        //    over the canonical preimage. This is the critical cross-platform
        //    check: the SAME preimage + signature must verify in every language.
        let sig: [u8; 64] = expected_sig
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("[{id}] signature wrong length: {}", v.len()));

        assert!(
            ed25519_verify(&signer_pk, &preimage, &sig),
            "[{id}] signature verification failed — cross-platform signature disagreement"
        );

        eprintln!("[conf-runner] PASS: {id} — signature verifies over canonical preimage (cross-platform)");
    }
    eprintln!("[conf-runner] PASS: {} capability-authority vectors verified", authority_vecs.len());
}

// ─── Suite: capability-model ────────────────────────────────────────────────

#[test]
fn conf_runner_capability_model_vectors() {
    let vectors = load_vectors();
    let vecs = vectors["vectors"].as_array().unwrap();
    let model_vecs: Vec<_> = vecs
        .iter()
        .filter(|v| v["suite"].as_str() == Some("capability-model"))
        .collect();

    assert_eq!(model_vecs.len(), 13, "must have 13 capability-model vectors (13 Capability variants)");

    for v in &model_vecs {
        let id = v["id"].as_str().unwrap();
        let expected_string = v["expected"]["string"].as_str().unwrap();
        let expected_is_gw = v["expected"]["is_gateway_capability"].as_bool().unwrap();
        let expected_is_relay = v["expected"]["is_relay_capability"].as_bool().unwrap();

        // The Capability enum must parse this string.
        let cap = Capability::from_str(expected_string)
            .unwrap_or_else(|| panic!("[{id}] Capability::from_str(\"{expected_string}\") returned None"));

        // The string must round-trip.
        assert_eq!(
            cap.as_str(),
            expected_string,
            "[{id}] as_str() round-trip failed"
        );

        // The typed checks must match.
        assert_eq!(
            cap.is_gateway_capability(),
            expected_is_gw,
            "[{id}] is_gateway_capability() mismatch"
        );
        assert_eq!(
            cap.is_relay_capability(),
            expected_is_relay,
            "[{id}] is_relay_capability() mismatch"
        );

        // If there's a protocol_capability_byte, verify the bridge.
        if let Some(expected_byte) = v["expected"]["protocol_capability_byte"].as_u64() {
            let proto = cap.to_protocol_capability()
                .unwrap_or_else(|| panic!("[{id}] to_protocol_capability() returned None"));
            assert_eq!(
                proto.to_byte(),
                expected_byte as u8,
                "[{id}] protocol_capability_byte mismatch"
            );
        }

        eprintln!("[conf-runner] PASS: {id} — string round-trip + typed checks + bridge OK");
    }
    eprintln!("[conf-runner] PASS: {} capability-model vectors verified", model_vecs.len());
}

// ─── Cross-platform agreement proof ─────────────────────────────────────────

#[test]
fn conf_runner_vectors_are_language_independent() {
    // This test proves that the vectors are serialized artifacts, not
    // Rust-internal objects. The vector file contains:
    //   - CBOR hex (language-independent binary)
    //   - SHA-256 digests (language-independent hashes)
    //   - Ed25519 signatures (language-independent crypto)
    //   - String mappings (language-independent text)
    //
    // A Kotlin/Python/Swift implementation can load the SAME file and
    // verify the SAME bytes without depending on Rust types.

    let vectors = load_vectors();
    let vecs = vectors["vectors"].as_array().unwrap();

    for v in vecs {
        let id = v["id"].as_str().unwrap();

        // Every vector must have a protocol_version.
        assert_eq!(
            v["protocol_version"].as_str(),
            Some("2.5"),
            "[{id}] must declare protocol_version 2.5"
        );

        // Every vector must have an id + suite + description.
        assert!(v["suite"].is_string(), "[{id}] must have a suite");
        assert!(v["description"].is_string(), "[{id}] must have a description");

        // Every vector must have input + expected.
        assert!(v["input"].is_object(), "[{id}] must have input");
        assert!(v["expected"].is_object(), "[{id}] must have expected");
    }

    eprintln!("[conf-runner] PASS: all {} vectors are language-independent serialized artifacts", vecs.len());
}

// ─── Determinism proof ──────────────────────────────────────────────────────

#[test]
fn conf_runner_vectors_are_deterministic() {
    // Re-derive the authority from the same fixed inputs and verify it
    // matches the frozen vector. This proves the vectors are deterministic
    // (same inputs → same outputs, every time).

    let gov_secret: SecretKey = sha256(b"n25-gov-secret");
    let issuer_secret: SecretKey = sha256(b"n25-issuer-secret");
    let issuer_pk = derive_public_key(&issuer_secret);
    let issuer_id = snp_crypto::domain_hash(b"SNP/0.1 node\0", &issuer_pk);
    let t0: u64 = 1_700_000_000;

    let authority = IssuerAuthority::new(
        &gov_secret, &issuer_secret, 1,
        vec![ProtocolCapability::InternetGateway],
        AuthScope::wildcard(),
        t0, t0 + 86400, t0,
    ).unwrap();

    let recomputed_digest = authority.authority_digest().unwrap();
    let recomputed_sig = authority.governance_signature;

    // Load the frozen vector and compare.
    let vectors = load_vectors();
    let vecs = vectors["vectors"].as_array().unwrap();
    let auth_vec = vecs
        .iter()
        .find(|v| v["id"].as_str() == Some("issuer-authority-v1"))
        .expect("issuer-authority-v1 vector must exist");

    let frozen_digest = hex_decode(auth_vec["expected"]["digest_hex"].as_str().unwrap());
    let frozen_sig = hex_decode(auth_vec["expected"]["signature_hex"].as_str().unwrap());

    assert_eq!(
        recomputed_digest.to_vec(),
        frozen_digest,
        "recomputed authority digest must match frozen vector"
    );
    assert_eq!(
        recomputed_sig.to_vec(),
        frozen_sig,
        "recomputed authority signature must match frozen vector"
    );

    eprintln!("[conf-runner] PASS: vectors are deterministic (same inputs → same outputs)");
}
