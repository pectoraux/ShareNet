#![cfg(feature = "legacy-circuit-keys")]
//! N2.0.7.3: This test uses the legacy Route::new() constructor.
//! Run with: cargo test --features legacy-circuit-keys

//! N2.0.2 — Protocol Session & Identity Foundation tests
//!
//! Tests the SNP-IK/0.1 handshake (ADR-0006), the GatewayChoice-free
//! production API, the fresh-circuit-key construction (ADR-0011 Layer 2),
//! the PeerSession state machine, the GatewayDirectory, the Route state
//! machine, and the CircuitV2 state machine.
//!
//! All tests use STUB gateways (no real Internet fetches). The stubs
//! mirror the production wire format: SNP-IK/0.1 handshake → link AEAD
//! → circuit-DH frame body → TransitRequest/Response.
//!
//! # Test index
//!
//! 1. **SNP-IK/0.1 handshake** — fresh keys, identity verification,
//!    wrong-identity rejection, transcript-tamper rejection.
//! 2. **Generic Gateway C** — gateway with an ARBITRARY Ed25519 key (not
//!    `GatewayChoice::A` or `B`); client discovers, handshakes, requests,
//!    verifies the response signature.
//! 3. **Fresh keys per session** — two handshakes between the same pair
//!    produce DIFFERENT `LinkKeys` (because the ephemeral X25519 keys are
//!    fresh per handshake).
//! 4. **PeerSession state machine** — legal transitions succeed, illegal
//!    transitions are rejected.
//! 5. **Circuit with fresh keys** — circuit keys are derived from a
//!    client↔gateway DH, NOT from a deterministic seed. Two circuits to
//!    the same gateway have different keys.
//! 6. **Relay cannot derive circuit key** — the relay has hop keys from
//!    the SNP-IK/0.1 handshake but cannot derive the circuit key (which
//!    comes from a separate client↔gateway DH).

#![allow(clippy::pedantic)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::module_name_repetitions)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use snp_crypto::{
    derive_node_id, derive_public_key, ed25519_sign, ed25519_verify, sha256,
    x25519_dh, x25519_public_from_bytes, x25519_static_keypair, SymmetricKey, X25519PubKey,
    X25519Secret,
};
use snp_frames::{Frame, FRAME_TTL_MAX, FRAME_VERSION};
use snp_gateway::{
    decode_transit_request, decode_transit_response, encode_transit_request,
    encode_transit_response, sign_transit_request, sign_transit_response, verify_transit_request,
    verify_transit_response, TransitRequest, TransitResponse,
};
use snp_link::{
    decrypt_circuit_payload, derive_circuit_keys_from_dh, derive_gateway_response_keys,
    derive_link_keys_from_dh, encrypt_circuit_payload, open_circuit_payload_with_fresh_eph,
    perform_snp_ik_handshake, seal_circuit_payload_with_fresh_eph, CircuitKeys, HandshakeResult,
    Link, LinkError, LinkKeys, CIRCUIT_EPH_PUB_LEN,
};
use snp_node::node::{
    CircuitState, CircuitV2, FirstAvailableSelector, GatewayAdvertisement, GatewayDirectory,
    GatewayDirectoryEntry, GatewaySelector, GatewayState, NodeIdentity, PeerSession,
    PeerSessionState, Route, RouteState,
};

// ═══════════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Construct a deterministic Ed25519 secret key from a seed string. The seed
/// is hashed with SHA-256 to produce the 32-byte secret. This is a TEST
/// HELPER — production code generates Ed25519 keys from the OS CSPRNG.
fn ed25519_secret_from_seed(seed: &[u8]) -> [u8; 32] {
    sha256(seed)
}

/// Generate a full Ed25519 keypair (secret + public) from a seed.
fn ed25519_keypair_from_seed(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = ed25519_secret_from_seed(seed);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

/// Monotonic counter for unique req_ids in tests.
static REQ_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Generate a unique 16-byte req_id for tests.
fn test_req_id() -> [u8; 16] {
    let counter = REQ_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&counter.to_be_bytes());
    seed.extend_from_slice(b"req-id-salt");
    let h = sha256(&seed);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// Monotonic counter for unique flow IDs in tests.
static FID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Generate a unique 8-byte flow ID for tests.
fn test_fid() -> [u8; 8] {
    let counter = FID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&counter.to_be_bytes());
    seed.extend_from_slice(b"fid-salt");
    let h = sha256(&seed);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// Build a signed TransitRequest for a stub URL.
fn build_transit_request(client_sk: &[u8; 32]) -> TransitRequest {
    let mut req = TransitRequest {
        req_id: test_req_id(),
        method: "GET".into(),
        url: "http://stub.example/n202".into(),
        tls_termination: "GATEWAY_PLAINTEXT".into(),
        max_response_bytes: 65536,
        deadline: u64::MAX,
        reply_to: [0u8; 32],
        // N2.2.2-hardening: embed the client's Ed25519 public key (part of
        // the signed preimage, bound to client_sig).
        client_ed25519_public_key: derive_public_key(client_sk),
        client_sig: [0u8; 64],
    };
    sign_transit_request(&mut req, client_sk);
    req
}

/// Build a signed stub TransitResponse (status=200, body="hello from gateway").
fn build_stub_response(
    req_id: [u8; 16],
    gateway_sk: &[u8; 32],
) -> TransitResponse {
    let gateway_pk = derive_public_key(gateway_sk);
    let gateway_id = derive_node_id(&gateway_pk);
    let body = b"hello from gateway (N2.0.2 stub)";
    let object_id = sha256(body);
    let mut resp = TransitResponse {
        req_id,
        status: 200,
        headers: vec![("content-type".into(), "text/plain".into())],
        object_id,
        fetched_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        gateway_id,
        gateway_sig: [0u8; 64],
    };
    sign_transit_response(&mut resp, gateway_sk);
    resp
}

/// Wrap a TcpStream in a Link AFTER a SNP-IK/0.1 handshake, using the
/// handshake-derived keys.
fn link_from_handshake(stream: TcpStream, handshake: &HandshakeResult) -> Link {
    Link::new(
        stream,
        LinkKeys {
            send_key: handshake.link_keys.send_key,
            recv_key: handshake.link_keys.recv_key,
        },
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: SNP-IK/0.1 handshake — fresh keys, identity verification,
//         wrong-identity rejection, transcript-tamper rejection
// ═══════════════════════════════════════════════════════════════════════════

/// Test 1a: Two nodes perform the SNP-IK/0.1 handshake. Both sides derive
/// matching directional keys. The initiator verifies the responder's
/// identity via `expected_peer_node_id`.
#[test]
fn test_1a_snp_ik_handshake_basic() {
    let (a_ed_sk, a_ed_pk) = ed25519_keypair_from_seed(b"node A ed25519 seed");
    let (a_x_sk, a_x_pk) = x25519_static_keypair();
    let (b_ed_sk, b_ed_pk) = ed25519_keypair_from_seed(b"node B ed25519 seed");
    let (b_x_sk, b_x_pk) = x25519_static_keypair();
    let a_node_id = derive_node_id(&a_ed_pk);
    let b_node_id = derive_node_id(&b_ed_pk);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let b_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        perform_snp_ik_handshake(
            &mut stream,
            false,
            &b_ed_sk,
            &b_ed_pk,
            &b_x_sk,
            &b_x_pk,
            None,
        )
        .expect("responder handshake should succeed")
    });

    let mut a_stream = TcpStream::connect(addr).expect("connect");
    let a_result = perform_snp_ik_handshake(
        &mut a_stream,
        true,
        &a_ed_sk,
        &a_ed_pk,
        &a_x_sk,
        &a_x_pk,
        Some(&b_node_id),
    )
    .expect("initiator handshake should succeed");

    let b_result = b_handle.join().expect("join");

    // Directional keys: initiator.send_key == responder.recv_key, etc.
    assert_eq!(
        a_result.link_keys.send_key,
        b_result.link_keys.recv_key,
        "initiator.send_key MUST equal responder.recv_key"
    );
    assert_eq!(
        a_result.link_keys.recv_key,
        b_result.link_keys.send_key,
        "initiator.recv_key MUST equal responder.send_key"
    );
    assert_ne!(
        a_result.link_keys.send_key,
        a_result.link_keys.recv_key,
        "send_key and recv_key MUST differ (directional separation)"
    );

    // Identity binding.
    assert_eq!(a_result.peer_node_id, b_node_id, "A sees B's NodeId");
    assert_eq!(a_result.peer_public_key, b_ed_pk, "A sees B's Ed25519 pub");
    assert_eq!(b_result.peer_node_id, a_node_id, "B sees A's NodeId");
    assert_eq!(b_result.peer_public_key, a_ed_pk, "B sees A's Ed25519 pub");

    // Session IDs match across both sides (they are derived from the same
    // ephemeral keys + dh3, which both sides compute identically).
    assert_eq!(
        a_result.session_id, b_result.session_id,
        "both sides MUST compute the same session_id"
    );
    assert_ne!(
        a_result.session_id,
        [0u8; 32],
        "session_id must not be all-zero"
    );

    // Both sides see the peer's static X25519 pub.
    assert_eq!(
        a_result.peer_x25519_public,
        b_x_pk.to_bytes(),
        "A sees B's static X25519 pub"
    );
    assert_eq!(
        b_result.peer_x25519_public,
        a_x_pk.to_bytes(),
        "B sees A's static X25519 pub"
    );
}

/// Test 1b: Wrong-identity rejection. The initiator passes an
/// `expected_peer_node_id` that does NOT match the responder's actual
/// NodeId. The handshake MUST fail with `HandshakeUnexpectedPeer`.
#[test]
fn test_1b_snp_ik_handshake_wrong_identity_rejected() {
    let (a_ed_sk, a_ed_pk) = ed25519_keypair_from_seed(b"node A ed25519 seed");
    let (a_x_sk, a_x_pk) = x25519_static_keypair();
    let (b_ed_sk, b_ed_pk) = ed25519_keypair_from_seed(b"node B ed25519 seed");
    let (b_x_sk, b_x_pk) = x25519_static_keypair();

    // Generate a THIRD node — the initiator will (incorrectly) expect this
    // node's NodeId as the peer, but will actually be connected to node B.
    let (_, c_ed_pk) = ed25519_keypair_from_seed(b"node C ed25519 seed");
    let c_node_id = derive_node_id(&c_ed_pk);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let b_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // The responder's handshake will succeed on its end (it does not
        // verify the initiator's identity — only the initiator verifies the
        // responder's identity via expected_peer_node_id). But the responder
        // WILL verify the initiator's signature, which is valid, so the
        // responder returns Ok. The initiator, however, will reject the
        // responder's NodeId (it expected C but got B).
        let _ = perform_snp_ik_handshake(
            &mut stream,
            false,
            &b_ed_sk,
            &b_ed_pk,
            &b_x_sk,
            &b_x_pk,
            None,
        );
    });

    let mut a_stream = TcpStream::connect(addr).expect("connect");
    let a_result = perform_snp_ik_handshake(
        &mut a_stream,
        true,
        &a_ed_sk,
        &a_ed_pk,
        &a_x_sk,
        &a_x_pk,
        Some(&c_node_id), // wrong — expects C, will get B
    );

    assert!(
        matches!(a_result, Err(LinkError::HandshakeUnexpectedPeer)),
        "initiator MUST reject the responder whose NodeId is B when it expected C; got {:?}",
        a_result.err()
    );

    let _ = b_handle.join();
}

/// Test 1c: Transcript-tamper rejection. The initiator sends a handshake
/// message with a tampered signature (one byte flipped). The responder's
/// handshake MUST fail with `HandshakeBadSignature`.
///
/// This test uses a CUSTOM initiator that mimics `perform_snp_ik_handshake`
/// but flips a bit in the outgoing signature. The responder uses the real
/// `perform_snp_ik_handshake` and MUST reject the tampered message.
#[test]
fn test_1c_snp_ik_handshake_tamper_rejected() {
    use snp_cbor::CborValue;

    let (a_ed_sk, a_ed_pk) = ed25519_keypair_from_seed(b"node A ed25519 seed");
    let (a_x_sk, a_x_pk) = x25519_static_keypair();
    let (b_ed_sk, b_ed_pk) = ed25519_keypair_from_seed(b"node B ed25519 seed");
    let (b_x_sk, b_x_pk) = x25519_static_keypair();

    let a_node_id = derive_node_id(&a_ed_pk);
    let b_node_id = derive_node_id(&b_ed_pk);
    let _ = a_node_id;
    let _ = b_node_id;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // The responder uses the REAL perform_snp_ik_handshake. It MUST reject
    // the tampered message.
    let b_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let result = perform_snp_ik_handshake(
            &mut stream,
            false,
            &b_ed_sk,
            &b_ed_pk,
            &b_x_sk,
            &b_x_pk,
            None,
        );
        result
    });

    // The initiator is a CUSTOM implementation that tampers with the sig.
    let mut a_stream = TcpStream::connect(addr).expect("connect");
    a_stream.set_nodelay(true).ok();

    // --- Custom initiator: build + sign a handshake message, then flip a
    //     bit in the signature, then send the tampered message. ---
    let (eph_secret, eph_pub) = snp_crypto::x25519_ephemeral_keypair();
    let eph_pub_bytes = eph_pub.to_bytes();
    let static_pub_bytes = a_x_pk.to_bytes();
    let my_node_id = derive_node_id(&a_ed_pk);

    // Build the NodeDescriptor preimage.
    let preimage = CborValue::Map(vec![
        (CborValue::TextString("nodeId".into()), CborValue::ByteString(my_node_id.to_vec())),
        (CborValue::TextString("pubKey".into()), CborValue::ByteString(a_ed_pk.to_vec())),
        (CborValue::TextString("ephPub".into()), CborValue::ByteString(eph_pub_bytes.to_vec())),
        (CborValue::TextString("staticPub".into()), CborValue::ByteString(static_pub_bytes.to_vec())),
    ]);
    let preimage_bytes = snp_cbor::encode(&preimage).expect("encode preimage");
    let mut signed_msg = Vec::with_capacity(snp_crypto::sig_contexts::NODE_DESCRIPTOR.len() + preimage_bytes.len());
    signed_msg.extend_from_slice(snp_crypto::sig_contexts::NODE_DESCRIPTOR);
    signed_msg.extend_from_slice(&preimage_bytes);
    let mut sig = ed25519_sign(&a_ed_sk, &signed_msg);

    // TAMPER: flip a bit in the signature.
    sig[0] ^= 0xff;

    // Build the tampered handshake message.
    let msg = CborValue::Map(vec![
        (CborValue::TextString("nodeId".into()), CborValue::ByteString(my_node_id.to_vec())),
        (CborValue::TextString("pubKey".into()), CborValue::ByteString(a_ed_pk.to_vec())),
        (CborValue::TextString("ephPub".into()), CborValue::ByteString(eph_pub_bytes.to_vec())),
        (CborValue::TextString("staticPub".into()), CborValue::ByteString(static_pub_bytes.to_vec())),
        (CborValue::TextString("sig".into()), CborValue::ByteString(sig.to_vec())),
    ]);
    let msg_bytes = snp_cbor::encode(&msg).expect("encode msg");

    // Send the tampered message (length-prefixed).
    let len = u32::try_from(msg_bytes.len()).unwrap();
    a_stream.write_all(&len.to_be_bytes()).expect("write len");
    a_stream.write_all(&msg_bytes).expect("write msg");
    a_stream.flush().expect("flush");

    // Drop the eph_secret — we don't need to complete the handshake on the
    // initiator side (we expect the responder to reject).
    drop(eph_secret);

    let b_result = b_handle.join().expect("join");
    assert!(
        matches!(b_result, Err(LinkError::HandshakeBadSignature)),
        "responder MUST reject the tampered signature; got {:?}",
        b_result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Generic Gateway C — arbitrary Ed25519 identity, no compile-time
//         knowledge of GatewayChoice::A/B
// ═══════════════════════════════════════════════════════════════════════════

/// Test 2: Gateway C uses an ARBITRARY Ed25519 key (not GatewayChoice::A or
/// GatewayChoice::B). The client performs the SNP-IK/0.1 handshake, sends a
/// TransitRequest through the established link + fresh circuit DH, and
/// verifies the gateway's signature on the response.
///
/// This test PROVES that the N2.0.2 production API does not require
/// compile-time knowledge of which gateway it is talking to. The gateway's
/// identity is learned at runtime (via the handshake result + the
/// advertisement's signature).
#[test]
fn test_2_generic_gateway_c() {
    // Gateway C: arbitrary Ed25519 + X25519 keypairs (NOT GatewayChoice::A/B).
    let (gw_ed_sk, gw_ed_pk) = ed25519_keypair_from_seed(b"Gateway C arbitrary ed25519 seed");
    let (gw_x_sk, gw_x_pk) = x25519_static_keypair();
    let gw_node_id = derive_node_id(&gw_ed_pk);

    // Verify this is NOT GatewayChoice::A or B (compile-time check would
    // require importing GatewayChoice — instead we verify at runtime by
    // comparing against the N2.0 test gateway public keys).
    use snp_node::legacy::{gateway_public_key_for, GatewayChoice};
    assert_ne!(
        gw_ed_pk,
        gateway_public_key_for(GatewayChoice::A),
        "Gateway C MUST NOT be GatewayChoice::A"
    );
    assert_ne!(
        gw_ed_pk,
        gateway_public_key_for(GatewayChoice::B),
        "Gateway C MUST NOT be GatewayChoice::B"
    );

    // Client: arbitrary Ed25519 + X25519 keypairs.
    let (client_ed_sk, client_ed_pk) = ed25519_keypair_from_seed(b"client ed25519 seed");
    let (client_x_sk, client_x_pk) = x25519_static_keypair();
    let client_node_id = derive_node_id(&client_ed_pk);

    // Spawn the gateway as a thread.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let gw_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // 1. Perform the SNP-IK/0.1 handshake (responder).
        let handshake =
            perform_snp_ik_handshake(&mut stream, false, &gw_ed_sk, &gw_ed_pk, &gw_x_sk, &gw_x_pk, None)
                .expect("gateway handshake should succeed");
        // 2. Wrap the stream in a Link with the handshake-derived keys.
        let link = link_from_handshake(stream.try_clone().expect("try_clone"), &handshake);
        // 3. Receive the request frame.
        let req_frame = link.recv_frame().expect("recv req frame");
        // 4. Open the circuit payload (extracts client_eph_pub, derives keys,
        //    decrypts).
        let (client_eph_pub, req_bytes) = open_circuit_payload_with_fresh_eph(&gw_x_sk, &req_frame.body)
            .expect("open circuit payload should succeed");
        // 5. Decode + verify the TransitRequest.
        let transit_req = decode_transit_request(&req_bytes).expect("decode req");
        assert!(
            verify_transit_request(&transit_req),
            "client signature on TransitRequest MUST verify"
        );
        // 6. Build a stub TransitResponse (no real Internet fetch).
        let mut resp = build_stub_response(transit_req.req_id, &gw_ed_sk);
        // 7. Seal the response with the SAME DH-derived keys (responder role).
        let resp_keys = derive_gateway_response_keys(&gw_x_sk, &client_eph_pub);
        let resp_bytes = encode_transit_response(&resp).expect("encode resp");
        let sealed_resp = encrypt_circuit_payload(&resp_keys.send_key, &resp_bytes);
        // 8. Send the response frame.
        let resp_frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: req_frame.src,
            src: handshake.peer_node_id, // == client_node_id (we are the gateway, sending TO the client)
            ttl: FRAME_TTL_MAX,
            fid: req_frame.fid,
            seq: req_frame.seq + 1,
            body: sealed_resp,
        };
        link.send_frame(&resp_frame).expect("send resp frame");
        // Mark `resp` as used (we encoded it above).
        let _ = &resp;
    });

    // Client side.
    let mut stream = TcpStream::connect(addr).expect("connect");
    // 1. Perform the SNP-IK/0.1 handshake (initiator) — pin the expected
    //    peer NodeId to the gateway's NodeId (learnt from the advertisement
    //    in production; here we pass it directly).
    let handshake = perform_snp_ik_handshake(
        &mut stream,
        true,
        &client_ed_sk,
        &client_ed_pk,
        &client_x_sk,
        &client_x_pk,
        Some(&gw_node_id),
    )
    .expect("client handshake should succeed");

    // Verify the handshake authenticated the gateway's identity.
    assert_eq!(handshake.peer_node_id, gw_node_id, "handshake must authenticate gw_node_id");
    assert_eq!(handshake.peer_public_key, gw_ed_pk, "handshake must authenticate gw_ed_pk");

    // 2. Wrap the stream in a Link.
    let link = link_from_handshake(stream.try_clone().expect("try_clone"), &handshake);

    // 3. Build + sign a TransitRequest.
    let transit_req = build_transit_request(&client_ed_sk);
    let req_bytes = encode_transit_request(&transit_req).expect("encode req");

    // 4. Seal the request with a FRESH client X25519 ephemeral key (circuit DH).
    let gw_x_pub_from_handshake = x25519_public_from_bytes(&handshake.peer_x25519_public);
    let (circuit_keys, _client_eph_pub, sealed_req) =
        seal_circuit_payload_with_fresh_eph(&gw_x_pub_from_handshake, &req_bytes);

    // 5. Send the request frame.
    let req_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: gw_node_id,
        src: client_node_id,
        ttl: FRAME_TTL_MAX,
        fid: test_fid(),
        seq: 1,
        body: sealed_req,
    };
    link.send_frame(&req_frame).expect("send req frame");

    // 6. Receive the response frame.
    let resp_frame = link.recv_frame().expect("recv resp frame");
    assert_eq!(resp_frame.cls, b'B', "response must be Class B");

    // 7. Decrypt the response with the circuit recv_key (derived alongside
    //    the send_key in step 4).
    let resp_bytes = decrypt_circuit_payload(&circuit_keys.recv_key, &resp_frame.body)
        .expect("decrypt resp should succeed");
    let transit_resp = decode_transit_response(&resp_bytes).expect("decode resp");

    // 8. Verify the gateway's signature on the response.
    assert!(
        verify_transit_response(&transit_resp, &gw_ed_pk),
        "gateway signature on TransitResponse MUST verify"
    );
    assert_eq!(transit_resp.status, 200, "stub response status must be 200");
    assert_eq!(transit_resp.req_id, transit_req.req_id, "req_id must match");

    let _ = gw_handle.join();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Fresh keys per session — two handshakes between the same pair
//         produce DIFFERENT LinkKeys
// ═══════════════════════════════════════════════════════════════════════════

/// Test 3: Two SNP-IK/0.1 handshakes between the SAME pair of nodes produce
/// DIFFERENT `LinkKeys` (because the ephemeral X25519 keys are fresh per
/// handshake). The two sessions also have DIFFERENT `session_id`s.
#[test]
fn test_3_fresh_keys_per_session() {
    let (a_ed_sk, a_ed_pk) = ed25519_keypair_from_seed(b"node A ed25519 seed");
    let (a_x_sk, a_x_pk) = x25519_static_keypair();
    let (b_ed_sk, b_ed_pk) = ed25519_keypair_from_seed(b"node B ed25519 seed");
    let (b_x_sk, b_x_pk) = x25519_static_keypair();
    let b_node_id = derive_node_id(&b_ed_pk);

    // First handshake.
    let listener1 = TcpListener::bind("127.0.0.1:0").expect("bind1");
    let addr1 = listener1.local_addr().expect("local_addr1");
    let (a_ed_sk_1, a_x_sk_1, a_x_pk_1) = (a_ed_sk, a_x_sk.clone(), a_x_pk.clone());
    let (b_ed_sk_1, b_ed_pk_1, b_x_sk_1, b_x_pk_1) = (b_ed_sk, b_ed_pk, b_x_sk.clone(), b_x_pk.clone());
    let b_node_id_1 = b_node_id;
    let b_handle1 = thread::spawn(move || {
        let (mut stream, _) = listener1.accept().expect("accept1");
        perform_snp_ik_handshake(&mut stream, false, &b_ed_sk_1, &b_ed_pk_1, &b_x_sk_1, &b_x_pk_1, None)
            .expect("responder handshake 1 should succeed")
    });
    let mut a_stream1 = TcpStream::connect(addr1).expect("connect1");
    let a_result1 = perform_snp_ik_handshake(
        &mut a_stream1, true, &a_ed_sk_1, &a_ed_pk, &a_x_sk_1, &a_x_pk_1, Some(&b_node_id_1),
    )
    .expect("initiator handshake 1 should succeed");
    let b_result1 = b_handle1.join().expect("join1");

    // Second handshake (same pair, fresh ephemerals).
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind2");
    let addr2 = listener2.local_addr().expect("local_addr2");
    let (a_ed_sk_2, a_x_sk_2, a_x_pk_2) = (a_ed_sk, a_x_sk, a_x_pk);
    let (b_ed_sk_2, b_ed_pk_2, b_x_sk_2, b_x_pk_2) = (b_ed_sk, b_ed_pk, b_x_sk, b_x_pk);
    let b_node_id_2 = b_node_id;
    let b_handle2 = thread::spawn(move || {
        let (mut stream, _) = listener2.accept().expect("accept2");
        perform_snp_ik_handshake(&mut stream, false, &b_ed_sk_2, &b_ed_pk_2, &b_x_sk_2, &b_x_pk_2, None)
            .expect("responder handshake 2 should succeed")
    });
    let mut a_stream2 = TcpStream::connect(addr2).expect("connect2");
    let a_result2 = perform_snp_ik_handshake(
        &mut a_stream2, true, &a_ed_sk_2, &a_ed_pk, &a_x_sk_2, &a_x_pk_2, Some(&b_node_id_2),
    )
    .expect("initiator handshake 2 should succeed");
    let b_result2 = b_handle2.join().expect("join2");

    // The two sessions MUST have DIFFERENT LinkKeys (fresh ephemerals).
    assert_ne!(
        a_result1.link_keys.send_key, a_result2.link_keys.send_key,
        "two sessions between the same pair MUST have different send_keys (fresh ephemerals)"
    );
    assert_ne!(
        a_result1.link_keys.recv_key, a_result2.link_keys.recv_key,
        "two sessions between the same pair MUST have different recv_keys (fresh ephemerals)"
    );

    // The two sessions MUST have DIFFERENT session_ids.
    assert_ne!(
        a_result1.session_id, a_result2.session_id,
        "two sessions between the same pair MUST have different session_ids"
    );

    // But each session's initiator/responder keys MUST still match each other.
    assert_eq!(a_result1.link_keys.send_key, b_result1.link_keys.recv_key, "session 1: A.send == B.recv");
    assert_eq!(a_result2.link_keys.send_key, b_result2.link_keys.recv_key, "session 2: A.send == B.recv");

    // Both sessions authenticated the SAME peer identity.
    assert_eq!(a_result1.peer_node_id, b_node_id, "session 1: peer is B");
    assert_eq!(a_result2.peer_node_id, b_node_id, "session 2: peer is B");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: PeerSession state machine — legal transitions succeed, illegal
//         transitions are rejected
// ═══════════════════════════════════════════════════════════════════════════

/// Test 4: Verify the PeerSession state machine. Legal transitions:
///   New → Handshaking → Established → Degraded → Established → Closing → Closed
/// Illegal transitions (e.g. New → Established, Established → Handshaking)
/// are rejected with an error.
#[test]
fn test_4_peer_session_state_machine() {
    let (peer_ed_sk, peer_ed_pk) = ed25519_keypair_from_seed(b"peer ed25519 seed");
    let (peer_x_sk, peer_x_pk) = x25519_static_keypair();
    let peer_node_id = derive_node_id(&peer_ed_pk);

    // Create a session in the New state.
    let mut session = PeerSession::new(peer_node_id, peer_ed_pk);
    assert_eq!(session.state(), PeerSessionState::New, "new session is in New state");
    assert!(!session.is_alive(), "New session is not alive");

    // Illegal: New → Established (must go through Handshaking first).
    let err = session.transition_to(PeerSessionState::Established).unwrap_err();
    assert!(
        err.to_string().contains("illegal PeerSession transition"),
        "New → Established must be rejected: {}",
        err
    );

    // Legal: New → Handshaking.
    session.begin_handshake().expect("New → Handshaking should succeed");
    assert_eq!(session.state(), PeerSessionState::Handshaking);

    // Illegal: Handshaking → Degraded (must establish first).
    let err = session.transition_to(PeerSessionState::Degraded).unwrap_err();
    assert!(
        err.to_string().contains("illegal PeerSession transition"),
        "Handshaking → Degraded must be rejected: {}",
        err
    );

    // To transition to Established, we need a HandshakeResult. Synthesize one.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (peer_ed_sk_c, peer_ed_pk_c) = (peer_ed_sk, peer_ed_pk);
    let (peer_x_sk_c, peer_x_pk_c) = (peer_x_sk.clone(), peer_x_pk.clone());
    let peer_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        perform_snp_ik_handshake(
            &mut stream, false, &peer_ed_sk_c, &peer_ed_pk_c, &peer_x_sk_c, &peer_x_pk_c, None,
        )
        .expect("responder handshake should succeed")
    });
    let (client_ed_sk, client_ed_pk) = ed25519_keypair_from_seed(b"client ed25519 seed");
    let (client_x_sk, client_x_pk) = x25519_static_keypair();
    let mut client_stream = TcpStream::connect(addr).expect("connect");
    let handshake = perform_snp_ik_handshake(
        &mut client_stream, true, &client_ed_sk, &client_ed_pk, &client_x_sk, &client_x_pk,
        Some(&peer_node_id),
    )
    .expect("initiator handshake should succeed");
    let _ = peer_handle.join();

    // Legal: Handshaking → Established.
    session.establish(&handshake).expect("Handshaking → Established should succeed");
    assert_eq!(session.state(), PeerSessionState::Established);
    assert!(session.is_alive(), "Established session is alive");
    assert_eq!(session.send_key, handshake.link_keys.send_key, "session has the handshake send_key");
    assert_eq!(session.recv_key, handshake.link_keys.recv_key, "session has the handshake recv_key");
    assert_eq!(session.session_id, handshake.session_id, "session has the handshake session_id");

    // Legal: Established → Degraded → Established (recovery).
    session.transition_to(PeerSessionState::Degraded).expect("Established → Degraded should succeed");
    assert!(session.is_alive(), "Degraded session is still alive");
    session.transition_to(PeerSessionState::Established).expect("Degraded → Established should succeed");

    // Legal: Established → Closing → Closed.
    session.close().expect("close should succeed (Established → Closing → Closed)");
    assert_eq!(session.state(), PeerSessionState::Closed);
    assert!(!session.is_alive(), "Closed session is not alive");

    // Illegal: Closed → Established (cannot revive a closed session).
    let err = session.transition_to(PeerSessionState::Established).unwrap_err();
    assert!(
        err.to_string().contains("illegal PeerSession transition"),
        "Closed → Established must be rejected: {}",
        err
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Circuit with fresh keys — circuit keys are derived from the
//         client↔gateway DH, NOT from a deterministic seed. Two circuits to
//         the same gateway have different keys.
// ═══════════════════════════════════════════════════════════════════════════

/// Test 5: Two circuits to the same gateway produce DIFFERENT circuit keys,
/// because each call to `seal_circuit_payload_with_fresh_eph` generates a
/// fresh client X25519 ephemeral key. The gateway's static X25519 key is the
/// same in both calls, but the DH output differs (because the client's
/// ephemeral differs).
#[test]
fn test_5_circuit_with_fresh_keys() {
    let (gw_x_sk, gw_x_pk) = x25519_static_keypair();

    // First circuit.
    let plaintext1 = b"circuit request 1".to_vec();
    let (keys1, eph_pub1, body1) = seal_circuit_payload_with_fresh_eph(&gw_x_pk, &plaintext1);

    // Second circuit (same gateway, fresh ephemeral).
    let plaintext2 = b"circuit request 2".to_vec();
    let (keys2, eph_pub2, body2) = seal_circuit_payload_with_fresh_eph(&gw_x_pk, &plaintext2);

    // The two circuits MUST have different keys (fresh ephemerals).
    assert_ne!(
        keys1.send_key, keys2.send_key,
        "two circuits to the same gateway MUST have different send_keys (fresh ephemerals)"
    );
    assert_ne!(
        keys1.recv_key, keys2.recv_key,
        "two circuits to the same gateway MUST have different recv_keys (fresh ephemerals)"
    );
    assert_ne!(
        eph_pub1.to_bytes(), eph_pub2.to_bytes(),
        "two circuits MUST use different ephemeral pub keys"
    );
    assert_ne!(
        body1, body2,
        "two circuits MUST produce different frame bodies (different keys → different ciphertext)"
    );

    // The gateway can decrypt BOTH circuits using its static secret.
    let (eph_pub1_back, pt1_back) = open_circuit_payload_with_fresh_eph(&gw_x_sk, &body1)
        .expect("open circuit 1 should succeed");
    assert_eq!(pt1_back, plaintext1, "circuit 1 plaintext round-trips");
    assert_eq!(eph_pub1_back.to_bytes(), eph_pub1.to_bytes(), "eph pub 1 matches");

    let (eph_pub2_back, pt2_back) = open_circuit_payload_with_fresh_eph(&gw_x_sk, &body2)
        .expect("open circuit 2 should succeed");
    assert_eq!(pt2_back, plaintext2, "circuit 2 plaintext round-trips");
    assert_eq!(eph_pub2_back.to_bytes(), eph_pub2.to_bytes(), "eph pub 2 matches");

    // Verify the keys are NOT from a deterministic seed (compare against
    // N1.9-style derive_circuit_keys(b"some-seed", true)).
    let seeded_keys = snp_link::derive_circuit_keys(b"some deterministic seed", true);
    assert_ne!(
        keys1.send_key, seeded_keys.send_key,
        "fresh-DH circuit keys MUST differ from any deterministic-seed keys"
    );
    assert_ne!(
        keys2.send_key, seeded_keys.send_key,
        "fresh-DH circuit keys MUST differ from any deterministic-seed keys"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Relay cannot derive circuit key — the relay has hop keys from the
//         SNP-IK/0.1 handshake but cannot derive the circuit key (which
//         comes from a separate client↔gateway DH).
// ═══════════════════════════════════════════════════════════════════════════

/// Test 6: The relay has the hop keys (from the SNP-IK/0.1 link handshake
/// with each neighbour) but CANNOT derive the circuit key (which is derived
/// from a separate client↔gateway X25519 DH).
///
/// Setup:
///   CLIENT ──[SNP-IK/0.1 link 1]──> RELAY ──[SNP-IK/0.1 link 2]──> GATEWAY
///     └────────────────[client↔gateway circuit DH]─────────────────────┘
///
/// The relay sees the frame body (which contains the client's circuit eph
/// pub + the sealed TransitRequest). The relay has its OWN link keys (from
/// its SNP-IK/0.1 handshakes with the client and the gateway). The relay
/// attempts to derive the circuit key using:
///   1. Its link send_key with the client.
///   2. Its link recv_key with the client.
///   3. Its link send_key with the gateway.
///   4. Its link recv_key with the gateway.
///   5. The client's circuit eph pub (visible in the frame body) + the
///      relay's OWN static X25519 key (NOT the gateway's static key).
///
/// ALL FIVE attempts MUST fail (the relay cannot decrypt the circuit
/// payload). The end-to-end round-trip (client → relay → gateway → relay →
/// client) succeeds: the relay forwards the frame body verbatim, the
/// gateway decrypts and responds, the client decrypts the response.
#[test]
fn test_6_relay_cannot_derive_circuit_key() {
    // ── Generate identities for all three nodes ──
    let (client_ed_sk, client_ed_pk) = ed25519_keypair_from_seed(b"client ed25519 seed 6");
    let (client_x_sk, client_x_pk) = x25519_static_keypair();
    let client_node_id = derive_node_id(&client_ed_pk);

    let (relay_ed_sk, relay_ed_pk) = ed25519_keypair_from_seed(b"relay ed25519 seed 6");
    let (relay_x_sk, relay_x_pk) = x25519_static_keypair();
    let relay_node_id = derive_node_id(&relay_ed_pk);

    let (gw_ed_sk, gw_ed_pk) = ed25519_keypair_from_seed(b"gateway ed25519 seed 6");
    let (gw_x_sk, gw_x_pk) = x25519_static_keypair();
    let gw_node_id = derive_node_id(&gw_ed_pk);

    // ── Allocate ephemeral TCP ports ──
    // We bind the listeners in the main thread, get their addresses, then
    // PASS THE LISTENERS to the spawned threads. This avoids a race where
    // the client tries to connect before the relay thread has bound.
    let relay_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr relay");
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gw_addr = gw_listener.local_addr().expect("local_addr gw");

    let relay_addr_str = relay_addr.to_string();
    let gw_addr_str = gw_addr.to_string();
    let gw_addr_str_for_relay = gw_addr_str.clone();
    let relay_addr_str_for_client = relay_addr_str.clone();

    // ── Spawn the GATEWAY ──
    // The gateway:
    //   1. Listens on gw_addr.
    //   2. Accepts the relay's connection.
    //   3. Performs the SNP-IK/0.1 handshake (responder).
    //   4. Loops: receive a frame, decrypt the circuit payload using its
    //      static X25519 secret, build a stub response, seal the response
    //      with the same DH-derived keys, send the response frame.
    let gw_handle = thread::spawn(move || {
        let listener = gw_listener;
        let (mut stream, _) = listener.accept().expect("accept gw");
        let handshake = perform_snp_ik_handshake(
            &mut stream, false, &gw_ed_sk, &gw_ed_pk, &gw_x_sk, &gw_x_pk, None,
        )
        .expect("gw handshake should succeed");
        let link = link_from_handshake(stream.try_clone().expect("try_clone"), &handshake);
        // Serve one request.
        let req_frame = link.recv_frame().expect("gw recv req");
        let (client_eph_pub, req_bytes) = open_circuit_payload_with_fresh_eph(&gw_x_sk, &req_frame.body)
            .expect("gw open circuit payload");
        let transit_req = decode_transit_request(&req_bytes).expect("gw decode req");
        assert!(verify_transit_request(&transit_req), "gw verifies client sig");
        let resp = build_stub_response(transit_req.req_id, &gw_ed_sk);
        let resp_keys = derive_gateway_response_keys(&gw_x_sk, &client_eph_pub);
        let resp_bytes = encode_transit_response(&resp).expect("gw encode resp");
        let sealed_resp = encrypt_circuit_payload(&resp_keys.send_key, &resp_bytes);
        let resp_frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: req_frame.src,
            src: gw_node_id,
            ttl: FRAME_TTL_MAX,
            fid: req_frame.fid,
            seq: req_frame.seq + 1,
            body: sealed_resp,
        };
        link.send_frame(&resp_frame).expect("gw send resp");
    });

    // ── Spawn the RELAY ──
    // The relay:
    //   1. Listens on relay_addr.
    //   2. Accepts the client's connection.
    //   3. Performs the SNP-IK/0.1 handshake with the client (responder).
    //      -- the relay now has link_keys_client (its session with the client)
    //   4. Connects to the gateway, performs the SNP-IK/0.1 handshake (initiator).
    //      -- the relay now has link_keys_gw (its session with the gateway)
    //   5. Receives a frame from the client (DECRYPTS with link_keys_client.recv_key).
    //   6. ATTEMPTS to decrypt the frame body (circuit ciphertext) with ALL of
    //      its keys — every attempt MUST FAIL (returns None).
    //   7. RE-ENCRYPTS the outer frame with link_keys_gw.send_key and forwards
    //      to the gateway (the frame body is preserved verbatim).
    //   8. Receives the response frame from the gateway, RE-ENCRYPTS with
    //      link_keys_client.send_key, forwards to the client.
    //
    // The relay captures its link_keys_client + link_keys_gw + the frame body
    // it saw, and exposes them via a Mutex for the test to inspect.
    let relay_capture: Arc<Mutex<Option<RelayCapture>>> = Arc::new(Mutex::new(None));
    let relay_capture_clone = Arc::clone(&relay_capture);
    let relay_handle = thread::spawn(move || {
        let listener = relay_listener;
        let (client_stream, _) = listener.accept().expect("accept client");

        // Handshake with the client (responder).
        let mut client_stream = client_stream;
        let handshake_client = perform_snp_ik_handshake(
            &mut client_stream, false, &relay_ed_sk, &relay_ed_pk, &relay_x_sk, &relay_x_pk, None,
        )
        .expect("relay-client handshake should succeed");
        let client_link = link_from_handshake(client_stream.try_clone().expect("try_clone"), &handshake_client);

        // Connect + handshake with the gateway (initiator).
        let mut gw_stream = TcpStream::connect(&gw_addr_str_for_relay).expect("relay connect gw");
        let handshake_gw = perform_snp_ik_handshake(
            &mut gw_stream, true, &relay_ed_sk, &relay_ed_pk, &relay_x_sk, &relay_x_pk, None,
        )
        .expect("relay-gw handshake should succeed");
        let gw_link = link_from_handshake(gw_stream.try_clone().expect("try_clone"), &handshake_gw);

        // Receive the request frame from the client.
        let req_frame = client_link.recv_frame().expect("relay recv req from client");

        // Capture the relay's view: the link keys + the frame body.
        *relay_capture_clone.lock().unwrap() = Some(RelayCapture {
            link_keys_client_send: handshake_client.link_keys.send_key,
            link_keys_client_recv: handshake_client.link_keys.recv_key,
            link_keys_gw_send: handshake_gw.link_keys.send_key,
            link_keys_gw_recv: handshake_gw.link_keys.recv_key,
            relay_x_sk_bytes: relay_x_sk.to_bytes(),
            frame_body: req_frame.body.clone(),
        });

        // Forward the request to the gateway (re-encrypt the outer frame;
        // preserve the body verbatim).
        let fwd_frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: req_frame.dst,
            src: req_frame.src,
            ttl: req_frame.ttl.saturating_sub(1),
            fid: req_frame.fid,
            seq: req_frame.seq,
            body: req_frame.body.clone(),
        };
        gw_link.send_frame(&fwd_frame).expect("relay forward req to gw");

        // Receive the response from the gateway.
        let resp_frame = gw_link.recv_frame().expect("relay recv resp from gw");
        let resp_fwd = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: resp_frame.dst,
            src: resp_frame.src,
            ttl: resp_frame.ttl.saturating_sub(1),
            fid: resp_frame.fid,
            seq: resp_frame.seq,
            body: resp_frame.body.clone(),
        };
        client_link.send_frame(&resp_fwd).expect("relay forward resp to client");
    });

    // ── CLIENT side ──
    let mut stream = TcpStream::connect(&relay_addr_str_for_client).expect("client connect relay");
    // Handshake with the relay (initiator).
    let handshake_relay = perform_snp_ik_handshake(
        &mut stream, true, &client_ed_sk, &client_ed_pk, &client_x_sk, &client_x_pk,
        Some(&relay_node_id),
    )
    .expect("client-relay handshake should succeed");
    let link = link_from_handshake(stream.try_clone().expect("try_clone"), &handshake_relay);

    // Build + sign a TransitRequest.
    let transit_req = build_transit_request(&client_ed_sk);
    let req_bytes = encode_transit_request(&transit_req).expect("encode req");

    // Seal the request with a FRESH client↔gateway DH (the gateway's static
    // X25519 pub is `gw_x_pk` — in production the client would learn this
    // from the gateway's advertisement or NodeDescriptor).
    let (circuit_keys, _client_eph_pub, sealed_req) =
        seal_circuit_payload_with_fresh_eph(&gw_x_pk, &req_bytes);

    // Send the request frame addressed to the gateway (the relay routes based
    // on dst NodeId).
    let req_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: gw_node_id,
        src: client_node_id,
        ttl: FRAME_TTL_MAX,
        fid: test_fid(),
        seq: 1,
        body: sealed_req,
    };
    link.send_frame(&req_frame).expect("client send req");

    // Receive the response frame.
    let resp_frame = link.recv_frame().expect("client recv resp");
    assert_eq!(resp_frame.cls, b'B', "response must be Class B");

    // Decrypt the response.
    let resp_bytes = decrypt_circuit_payload(&circuit_keys.recv_key, &resp_frame.body)
        .expect("client decrypt resp should succeed");
    let transit_resp = decode_transit_response(&resp_bytes).expect("decode resp");
    assert!(verify_transit_response(&transit_resp, &gw_ed_pk), "gw sig must verify");
    assert_eq!(transit_resp.status, 200, "stub response status=200");
    assert_eq!(transit_resp.req_id, transit_req.req_id, "req_id matches");

    // Wait for the relay thread to finish (so the capture is populated).
    relay_handle.join().expect("relay join");

    // ── Inspect the relay's capture: verify the relay CANNOT decrypt the
    //    circuit payload with ANY of its keys. ──
    let capture = relay_capture.lock().unwrap().clone().expect("relay capture");
    let body = &capture.frame_body;
    assert!(
        body.len() > CIRCUIT_EPH_PUB_LEN,
        "frame body must contain the client eph pub prefix + sealed payload"
    );

    // Extract the client's circuit eph pub from the frame body (the relay CAN
    // see this — it's in cleartext).
    let mut client_eph_pub_arr = [0u8; 32];
    client_eph_pub_arr.copy_from_slice(&body[..CIRCUIT_EPH_PUB_LEN]);
    let client_eph_pub_visible = x25519_public_from_bytes(&client_eph_pub_arr);
    let circuit_ciphertext = &body[CIRCUIT_EPH_PUB_LEN..];

    // Attempt 1: decrypt with the relay's link send_key to the client.
    let attempt1 = decrypt_circuit_payload(&capture.link_keys_client_send, body);
    assert!(attempt1.is_none(), "relay MUST NOT decrypt circuit with link_keys_client_send");

    // Attempt 2: decrypt with the relay's link recv_key from the client.
    let attempt2 = decrypt_circuit_payload(&capture.link_keys_client_recv, body);
    assert!(attempt2.is_none(), "relay MUST NOT decrypt circuit with link_keys_client_recv");

    // Attempt 3: decrypt with the relay's link send_key to the gateway.
    let attempt3 = decrypt_circuit_payload(&capture.link_keys_gw_send, body);
    assert!(attempt3.is_none(), "relay MUST NOT decrypt circuit with link_keys_gw_send");

    // Attempt 4: decrypt with the relay's link recv_key from the gateway.
    let attempt4 = decrypt_circuit_payload(&capture.link_keys_gw_recv, body);
    assert!(attempt4.is_none(), "relay MUST NOT decrypt circuit with link_keys_gw_recv");

    // Attempt 5: the relay tries to derive the circuit key using the client's
    // visible eph pub + the RELAY's OWN static X25519 secret. This produces a
    // DH output, but it's the WRONG DH (the relay is not the gateway). The
    // derived keys MUST NOT decrypt the ciphertext.
    let relay_x_sk = X25519Secret::from(capture.relay_x_sk_bytes);
    let relay_dh = x25519_dh(&relay_x_sk, &client_eph_pub_visible);
    let relay_keys = derive_circuit_keys_from_dh(&relay_dh, false);
    let attempt5 = decrypt_circuit_payload(&relay_keys.recv_key, body);
    assert!(
        attempt5.is_none(),
        "relay MUST NOT decrypt circuit using its OWN static X25519 + the visible client eph pub (it's the wrong DH — the gateway's static key is required)"
    );

    // Attempt 6: just for paranoia — try decrypting the bare ciphertext (no
    // eph-pub prefix) with the relay's keys. Also must fail.
    let attempt6 = decrypt_circuit_payload(&capture.link_keys_client_send, circuit_ciphertext);
    assert!(attempt6.is_none(), "relay MUST NOT decrypt bare ciphertext");

    // The end-to-end round-trip succeeded (we got a valid response above).
    // The relay forwarded the body verbatim and could NOT decrypt it — this
    // is the cryptographic non-inspection property required by ADR-0011
    // Layer 2.

    // Wait for the gateway thread to finish.
    let _ = gw_handle.join();
}

/// Capture struct for Test 6: the relay's view of the frame and its keys.
#[derive(Debug, Clone)]
struct RelayCapture {
    link_keys_client_send: SymmetricKey,
    link_keys_client_recv: SymmetricKey,
    link_keys_gw_send: SymmetricKey,
    link_keys_gw_recv: SymmetricKey,
    /// The relay's OWN static X25519 secret, as raw 32 bytes (for test
    /// inspection only — production code never exposes this).
    relay_x_sk_bytes: [u8; 32],
    frame_body: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional: GatewayDirectory, Route, CircuitV2 state-machine unit tests
// ═══════════════════════════════════════════════════════════════════════════

/// Test 7a: GatewayDirectory upsert + lookup + mark_unreachable/mark_active.
#[test]
fn test_7a_gateway_directory_basic() {
    let (gw_a_ed_sk, gw_a_ed_pk) = ed25519_keypair_from_seed(b"gw A ed25519 seed");
    let gw_a_identity = NodeIdentity::from_secret(gw_a_ed_sk);
    let advert_a = GatewayAdvertisement::for_identity(&gw_a_identity, "127.0.0.1:7001", "127.0.0.1:7002");

    let (gw_b_ed_sk, _) = ed25519_keypair_from_seed(b"gw B ed25519 seed");
    let gw_b_identity = NodeIdentity::from_secret(gw_b_ed_sk);
    let advert_b = GatewayAdvertisement::for_identity(&gw_b_identity, "127.0.0.1:7003", "127.0.0.1:7004");

    let mut directory = GatewayDirectory::new();
    assert!(directory.is_empty());

    directory.upsert(GatewayDirectoryEntry {
        advertisement: advert_a.clone(),
        last_seen: 0,
        observed_latency: None,
        observed_reliability: None,
        state: GatewayState::Discovered,
    });
    assert_eq!(directory.len(), 1);

    directory.upsert(GatewayDirectoryEntry {
        advertisement: advert_b.clone(),
        last_seen: 0,
        observed_latency: None,
        observed_reliability: None,
        state: GatewayState::Discovered,
    });
    assert_eq!(directory.len(), 2);

    // Lookup by NodeId.
    let entry = directory.get(&advert_a.node_id).expect("gw A should be in directory");
    assert_eq!(entry.advertisement.node_id, advert_a.node_id);
    assert_eq!(entry.state(), GatewayState::Discovered);

    // Mark unreachable.
    directory.mark_unreachable(&advert_a.node_id);
    let entry = directory.get(&advert_a.node_id).expect("gw A still in directory");
    assert_eq!(entry.state(), GatewayState::Unreachable);

    // Mark active.
    directory.mark_active(&advert_a.node_id);
    let entry = directory.get(&advert_a.node_id).expect("gw A still in directory");
    assert_eq!(entry.state(), GatewayState::Active);

    // FirstAvailableSelector skips Unreachable entries.
    directory.mark_unreachable(&advert_a.node_id);
    let selector = FirstAvailableSelector;
    let selected = selector.select(&directory).expect("selector should pick gw B");
    assert_eq!(selected.advertisement.node_id, advert_b.node_id, "selector picks gw B (gw A is unreachable)");
}

/// Test 7b: Route state machine — legal + illegal transitions.
#[test]
fn test_7b_route_state_machine() {
    let (client_ed_sk, client_ed_pk) = ed25519_keypair_from_seed(b"client ed25519 seed 7b");
    let client_id = derive_node_id(&client_ed_pk);
    let (gw_ed_sk, gw_ed_pk) = ed25519_keypair_from_seed(b"gw ed25519 seed 7b");
    let gw_id = derive_node_id(&gw_ed_pk);

    let mut route = Route::new(client_id, gw_id, vec![]);
    assert_eq!(route.state(), RouteState::Proposed);
    assert_eq!(route.hops(), Vec::<[u8; 32]>::new());
    assert_ne!(route.route_commitment().as_bytes(), &[0u8; 32], "route_id must not be all-zero");

    // Legal: Proposed → Establishing → Active.
    route.transition_to(RouteState::Establishing).expect("Proposed → Establishing");
    route.transition_to(RouteState::Active).expect("Establishing → Active");
    assert!(route.last_validated() > 0, "Active route has a non-zero last_validated");

    // Legal: Active → Degraded → Active (recovery).
    route.transition_to(RouteState::Degraded).expect("Active → Degraded");
    route.transition_to(RouteState::Active).expect("Degraded → Active");

    // Legal: Active → Migrating → Active (migration completes).
    route.transition_to(RouteState::Migrating).expect("Active → Migrating");
    route.transition_to(RouteState::Active).expect("Migrating → Active");

    // Legal: Active → Failed → Closed.
    route.transition_to(RouteState::Failed).expect("Active → Failed");
    route.transition_to(RouteState::Closed).expect("Failed → Closed");

    // Illegal: Closed → Active.
    let err = route.transition_to(RouteState::Active).unwrap_err();
    assert!(err.to_string().contains("Route transition error"), "Closed → Active must be rejected: {err}");

    // Illegal: Proposed → Active (must go through Establishing).
    let mut route2 = Route::new(client_id, gw_id, vec![]);
    let err = route2.transition_to(RouteState::Active).unwrap_err();
    assert!(err.to_string().contains("Route transition error"), "Proposed → Active must be rejected: {err}");
}

/// Test 7c: CircuitV2 state machine — legal + illegal transitions.
#[test]
fn test_7c_circuit_v2_state_machine() {
    let (client_ed_sk, client_ed_pk) = ed25519_keypair_from_seed(b"client ed25519 seed 7c");
    let client_id = derive_node_id(&client_ed_pk);
    let (gw_ed_sk, gw_ed_pk) = ed25519_keypair_from_seed(b"gw ed25519 seed 7c");
    let gw_id = derive_node_id(&gw_ed_pk);

    let mut route = Route::new(client_id, gw_id, vec![]);
    let mut circuit = CircuitV2::new(client_id, gw_id, [0u8;32], [0u8;32]);
    assert_eq!(circuit.state(), CircuitState::Discovering);
    assert_ne!(circuit.circuit_id, [0u8; 32], "circuit_id must not be all-zero");

    // Legal: Discovering → Establishing → Active.
    circuit.transition_to(CircuitState::Establishing).expect("Discovering → Establishing");
    circuit.transition_to(CircuitState::Active).expect("Establishing → Active");

    // Legal: Active → Degraded → Active.
    circuit.transition_to(CircuitState::Degraded).expect("Active → Degraded");
    circuit.transition_to(CircuitState::Active).expect("Degraded → Active");

    // Legal: Active → Migrating → Active.
    circuit.transition_to(CircuitState::Migrating).expect("Active → Migrating");
    circuit.transition_to(CircuitState::Active).expect("Migrating → Active");

    // Legal: Active → Failed → Closed.
    circuit.transition_to(CircuitState::Failed).expect("Active → Failed");
    circuit.transition_to(CircuitState::Closed).expect("Failed → Closed");

    // Illegal: Closed → Active.
    let err = circuit.transition_to(CircuitState::Active).unwrap_err();
    assert!(err.to_string().contains("illegal CircuitV2 transition"), "Closed → Active must be rejected: {err}");

    // Illegal: Discovering → Active (must go through Establishing).
    let mut circuit2 = CircuitV2::new(client_id, gw_id, [0u8;32], [0u8;32]);
    let err = circuit2.transition_to(CircuitState::Active).unwrap_err();
    assert!(err.to_string().contains("illegal CircuitV2 transition"), "Discovering → Active must be rejected: {err}");

    // Two circuits to the same gateway MUST have different circuit_ids.
    let circuit3 = CircuitV2::new(client_id, gw_id, [0u8;32], [0u8;32]);
    assert_ne!(circuit.circuit_id, circuit3.circuit_id, "two circuits must have different circuit_ids");
}

/// Test 7d: GatewayAdvertisement::for_identity produces a verifiable
/// advertisement for an ARBITRARY identity (no GatewayChoice).
#[test]
fn test_7d_advertisement_for_identity_verifies() {
    let (gw_ed_sk, _) = ed25519_keypair_from_seed(b"arbitrary gw ed25519 seed 7d");
    let identity = NodeIdentity::from_secret(gw_ed_sk);
    let advert = GatewayAdvertisement::for_identity(&identity, "127.0.0.1:7001", "127.0.0.1:7002");

    // The advertisement MUST verify.
    assert!(advert.verify(), "for_identity advertisement must verify");

    // The advertised NodeId MUST match the identity's NodeId.
    assert_eq!(advert.node_id, identity.node_id);
    assert_eq!(advert.public_key, identity.public_key);

    // I4 cross-check: NodeId == SHA-256("SNP/0.1 node\0" || publicKey).
    let expected_id = derive_node_id(&identity.public_key);
    assert_eq!(advert.node_id, expected_id, "I4: nodeId == SHA-256(...||publicKey)");
}
