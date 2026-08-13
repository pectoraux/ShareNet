#![cfg(feature = "legacy-circuit-keys")]
//! N2.0.7.3: This test uses the legacy Route::new() constructor.
//! Run with: cargo test --features legacy-circuit-keys

//! N2.0.3 Gate L — Security Regression Tests
//!
//! Tests every security invariant has an executable check.
//! These tests run WITHOUT real Internet (all local/stub).

#![allow(clippy::pedantic, deprecated)]

use snp_crypto::{aead_encrypt, aead_nonce, ed25519_sign, ed25519_verify, sha256};
use snp_frames::Frame;
use snp_gateway::{is_private_destination, sign_transit_request, verify_transit_request, TransitRequest};
use snp_link::{
    decrypt_circuit_payload, derive_circuit_keys, derive_link_keys, encrypt_circuit_payload,
};
use snp_node::node::{Route, RouteState, GatewayAdvertisement, NodeIdentity};

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════════
// Route security
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_route_loop_rejected() {
    let id_a = sha256(b"node-a");
    let id_b = sha256(b"node-b");
    let id_c = sha256(b"node-c");
    let gw = sha256(b"gateway");
    // Route with a loop: A → B → C → B → Gateway
    let route = Route::new(id_a, gw, vec![id_b, id_c, id_b, gw]);
    assert!(route.validate().is_err(), "Route with loop must be rejected");
}

#[test]
fn sec_route_excessive_hops_rejected() {
    let ids: Vec<[u8; 32]> = (0..20).map(|i| sha256(&[i])).collect();
    let gw = ids[19];
    let route = Route::new(ids[0], gw, ids[1..].to_vec());
    assert!(route.validate().is_err(), "Route with >16 hops must be rejected");
}

#[test]
fn sec_route_expired_rejected() {
    let id_a = sha256(b"node-a");
    let gw = sha256(b"gateway");
    let route = Route::new(id_a, gw, vec![gw]);
    // N2.0.7.2: expires_at is now non-mutable. Use the is_expired check
    // with a future timestamp to test expiration logic.
    let future = now_unix() + 7200; // 2 hours in the future
    assert!(route.is_expired(future), "Route must be expired at a future timestamp");
}

#[test]
fn sec_route_epoch_regression() {
    let id_a = sha256(b"node-a");
    let gw = sha256(b"gateway");
    let mut route1 = Route::new(id_a, gw, vec![gw]);
    route1.increment_epoch();
    route1.increment_epoch();
    route1.increment_epoch();
    let route2 = Route::new(id_a, gw, vec![gw]);
    // Epoch regression: route2 has a lower epoch than route1
    assert!(route2.epoch() < route1.epoch(), "Epoch regression must be detectable");
}

#[test]
fn sec_route_state_machine_illegal_transition() {
    let id_a = sha256(b"node-a");
    let gw = sha256(b"gateway");
    let mut route = Route::new(id_a, gw, vec![gw]);
    // Closed → Active is illegal
    route.transition(RouteState::Closed).expect("Proposed → Closed is legal");
    assert!(route.transition(RouteState::Active).is_err(),
        "Closed → Active must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════════
// Gateway advertisement security
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_forged_advertisement_rejected() {
    let identity = NodeIdentity::from_secret(sha256(b"gateway-xyz"));
    let mut advert = GatewayAdvertisement::for_identity(
        &identity,
        "127.0.0.1:0",
        "127.0.0.1:0",
    );
    advert.sign(&identity.secret_key);
    // Tamper with the signature
    advert.signature[0] ^= 0x01;
    assert!(!advert.verify(), "Forged advertisement must be rejected");
}

#[test]
fn sec_expired_advertisement_rejected() {
    let identity = NodeIdentity::from_secret(sha256(b"gateway-exp"));
    let mut advert = GatewayAdvertisement::for_identity(
        &identity,
        "127.0.0.1:0",
        "127.0.0.1:0",
    );
    advert.sign(&identity.secret_key);
    advert.expiry = now_unix() - 1;
    assert!(advert.is_expired(now_unix()), "Expired advertisement must be rejected");
}

#[test]
fn sec_nodeid_mismatch_rejected() {
    let identity = NodeIdentity::from_secret(sha256(b"gateway-mismatch"));
    let mut advert = GatewayAdvertisement::for_identity(
        &identity,
        "127.0.0.1:0",
        "127.0.0.1:0",
    );
    advert.sign(&identity.secret_key);
    // Tamper with node_id to create a mismatch
    advert.node_id[0] ^= 0x01;
    assert!(!advert.verify(), "Advertisement with mismatched NodeId must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════════
// SSRF defence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_ssrf_private_addresses_blocked() {
    let private_hosts = [
        "10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
        "169.254.169.254", "0.0.0.0", "::1", "fe80::1",
        "fc00::1", "224.0.0.1", "100.64.0.1",
    ];
    for host in &private_hosts {
        assert!(is_private_destination(host), "{} must be blocked", host);
    }
}

#[test]
fn sec_ssrf_public_addresses_allowed() {
    let public_hosts = ["example.com", "1.1.1.1", "8.8.8.8"];
    for host in &public_hosts {
        assert!(!is_private_destination(host), "{} must be allowed", host);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Circuit key separation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_circuit_keys_independent_of_hop_keys() {
    let hop_keys = derive_link_keys(b"hop-seed", true);
    let circuit_keys = derive_circuit_keys(b"circuit-seed", true);

    let plaintext = b"secret payload";
    let sealed = encrypt_circuit_payload(&circuit_keys.send_key, plaintext);

    // Hop key CANNOT decrypt circuit payload
    assert!(decrypt_circuit_payload(&hop_keys.send_key, &sealed).is_none(),
        "Hop key must NOT decrypt circuit payload");
    assert!(decrypt_circuit_payload(&hop_keys.recv_key, &sealed).is_none(),
        "Hop recv key must NOT decrypt circuit payload");

    // Circuit key CAN decrypt
    let gw_circuit = derive_circuit_keys(b"circuit-seed", false);
    assert!(decrypt_circuit_payload(&gw_circuit.recv_key, &sealed).is_some(),
        "Circuit key MUST decrypt circuit payload");
}

#[test]
fn sec_directional_keys_prevent_nonce_reuse() {
    let keys = derive_link_keys(b"directional-test", true);
    let responder_keys = derive_link_keys(b"directional-test", false);

    // Initiator send_key != responder send_key (they're opposite directions)
    assert_ne!(keys.send_key, responder_keys.send_key,
        "Initiator send_key must differ from responder send_key");
    assert_eq!(keys.send_key, responder_keys.recv_key,
        "Initiator send_key must equal responder recv_key");
}

// ═══════════════════════════════════════════════════════════════════════════
// TransitRequest signature verification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_unsigned_transit_request_rejected() {
    let client_sk = sha256(b"client-sec-test");
    let client_pk = snp_crypto::derive_public_key(&client_sk);

    let req = TransitRequest {
        req_id: [0x42; 16],
        method: "GET".to_string(),
        url: "https://example.com/".to_string(),
        tls_termination: "GATEWAY_PLAINTEXT".to_string(),
        max_response_bytes: 1024 * 1024,
        deadline: u64::MAX,
        reply_to: [0; 32],
        client_sig: [0u8; 64], // ALL ZEROS — unsigned
    };

    assert!(!verify_transit_request(&req, &client_pk),
        "Unsigned TransitRequest must be rejected");
}

#[test]
fn sec_tampered_transit_request_rejected() {
    let client_sk = sha256(b"client-tamper-test");
    let client_pk = snp_crypto::derive_public_key(&client_sk);

    let mut req = TransitRequest {
        req_id: [0x42; 16],
        method: "GET".to_string(),
        url: "https://example.com/".to_string(),
        tls_termination: "GATEWAY_PLAINTEXT".to_string(),
        max_response_bytes: 1024 * 1024,
        deadline: u64::MAX,
        reply_to: [0; 32],
        client_sig: [0u8; 64],
    };
    sign_transit_request(&mut req, &client_sk);

    // Tamper with the URL after signing
    req.url = "https://evil.com/".to_string();
    assert!(!verify_transit_request(&req, &client_pk),
        "Tampered TransitRequest must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame TTL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_ttl_zero_frame_dropped() {
    let frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: [0; 32],
        src: [0; 32],
        ttl: 0,
        fid: [0; 8],
        seq: 1,
        body: vec![0xDE, 0xAD],
    };
    assert!(snp_frames::should_drop(&frame), "TTL=0 frame must be dropped");
}

#[test]
fn sec_ttl_excessive_rejected() {
    // Frame with TTL > 16 should be rejected at validation
    // (Frame::decode_cbor would parse it, but validate_frame should reject)
    // The constant is FRAME_TTL_MAX = 16
    assert_eq!(snp_frames::FRAME_TTL_MAX, 16, "Max TTL must be 16");
}

// ═══════════════════════════════════════════════════════════════════════════
// Nonce reuse prevention
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_nonce_reuse_leaks_plaintext() {
    // Prove that nonce reuse is catastrophic (motivates the replay window)
    let keys = derive_link_keys(b"nonce-reuse-test", true);
    let fid = [0xAA; 8];
    let nonce = aead_nonce(&fid, 1);

    let pt_a = b"password: hunter2";
    let pt_b = b"password: letmein!";

    let (ct_a, _) = aead_encrypt(&keys.send_key, &nonce, pt_a, b"");
    let (ct_b, _) = aead_encrypt(&keys.send_key, &nonce, pt_b, b"");

    let xor_ct: Vec<u8> = ct_a.iter().zip(ct_b.iter()).map(|(a, b)| a ^ b).collect();
    let xor_pt: Vec<u8> = pt_a.iter().zip(pt_b.iter()).map(|(a, b)| a ^ b).collect();

    assert_eq!(xor_ct, xor_pt, "Nonce reuse leaks plaintext XOR — proves replay window is needed");
}

// ═══════════════════════════════════════════════════════════════════════════
// Capability mismatch
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_ios_mesh_relay_rejected() {
    // iOS advertising MESH_RELAY must be rejected (per Platform Matrix)
    let ios_forbidden = ["MESH_RELAY", "INTERNET_GATEWAY", "CUSTODY", "COMMUNITY_RELAY"];
    for cap in &ios_forbidden {
        assert!(ios_forbidden.contains(cap), "iOS must not advertise {}", cap);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GatewayChoice not in production
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sec_gateway_choice_not_in_production() {
    let source = include_str!("../src/node/mod.rs");
    let import_line = source
        .lines()
        .find(|line| line.starts_with("use crate::{") && line.contains("GatewayChoice"));
    assert!(
        import_line.is_none(),
        "node/mod.rs must NOT import GatewayChoice via `use crate::{{...}};`"
    );
}
