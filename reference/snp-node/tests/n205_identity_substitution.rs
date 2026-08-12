//! N2.0.5 (Item 4) — Identity Substitution Test
//!
//! This test PROVES that the SNP-IK/0.1 handshake's identity binding
//! detects endpoint/identity substitution attacks.
//!
//! ## Attack scenario
//!
//! 1. Gateway A advertises its real identity (signed advertisement with
//!    `node_id = SHA-256("SNP/0.1 node\0" || gateway_A_public_key)`).
//! 2. A network attacker INTERCEPTS the advertisement (or learns of it
//!    through some other channel) and substitutes their OWN TCP endpoint
//!    for the gateway's `listen_addr` / `discovery_addr`. (For example,
//!    the attacker poisons DNS, or hijacks the route to the gateway, or
//!    rewrites the advertisement in flight — though the signature check
//!    would catch in-flight rewriting, so this scenario assumes the
//!    attacker uses a SEPARATE channel to direct the client to their
//!    endpoint, e.g. a malicious bootstrap list.)
//! 3. The client connects to the attacker's endpoint.
//! 4. The client performs the SNP-IK/0.1 handshake, pinning the expected
//!    peer NodeId to Gateway A's NodeId (learnt from the advertisement).
//! 5. The attacker does NOT have Gateway A's Ed25519 secret key, so the
//!    attacker responds with their OWN NodeDescriptor (signed under the
//!    attacker's secret key, advertising the attacker's NodeId).
//! 6. The client's `perform_snp_ik_handshake` call returns
//!    `Err(LinkError::HandshakeUnexpectedPeer)` — the attacker's
//!    authenticated NodeId does NOT match the expected (Gateway A's)
//!    NodeId.
//!
//! ## What this test PROVES
//!
//! The SNP-IK/0.1 handshake's "I"-style identity pinning (initiator knows
//! the responder's NodeId in advance) is the cryptographic defence against
//! endpoint substitution. A network attacker who redirects the client to a
//! different endpoint CANNOT fool the client into accepting the attacker
//! as the legitimate gateway — the attacker would need Gateway A's Ed25519
//! secret key (which they don't have), and the handshake's identity check
//! rejects any responder whose authenticated NodeId doesn't match the
//! expected one.
//!
//! This is the core security guarantee that makes ShareNet's "discovery
//! via signed advertisements" safe: even if the discovery link is
//! unauthenticated (N2.0.4 raw protocol) and the bootstrap list is
//! attacker-controlled, the client's SNP-IK/0.1 handshake with the
//! gateway pins the gateway's identity to the advertised NodeId. A
//! man-in-the-middle attacker at the gateway endpoint is detected and
//! rejected.

#![allow(clippy::pedantic)]
#![allow(clippy::needless_pass_by_value)]

use std::net::{TcpListener, TcpStream};
use std::thread;

use snp_crypto::{
    derive_node_id, derive_public_key, sha256, x25519_static_keypair,
};
use snp_link::{perform_snp_ik_handshake, HandshakeResult, LinkError};

// ═══════════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Construct a deterministic Ed25519 secret key from a seed string. The seed
/// is hashed with SHA-256 to produce the 32-byte secret. This is a TEST
/// HELPER — production code generates Ed25519 keys from the OS CSPRNG.
fn ed25519_secret_from_seed(seed: &[u8]) -> [u8; 32] {
    sha256(seed)
}

/// A node's identity bundle: Ed25519 (signing) + X25519 (DH) keypairs +
/// NodeId. Used to set up the gateway, client, and attacker identities in
/// the test scenario.
struct TestIdentity {
    ed_sk: [u8; 32],
    ed_pk: [u8; 32],
    x_sk: snp_crypto::X25519Secret,
    x_pk: snp_crypto::X25519PubKey,
    node_id: [u8; 32],
}

impl TestIdentity {
    fn from_seed(seed: &[u8]) -> Self {
        let ed_sk = ed25519_secret_from_seed(seed);
        let ed_pk = derive_public_key(&ed_sk);
        let (x_sk, x_pk) = x25519_static_keypair();
        let node_id = derive_node_id(&ed_pk);
        Self { ed_sk, ed_pk, x_sk, x_pk, node_id }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: identity substitution rejected by SNP-IK/0.1 handshake
// ═══════════════════════════════════════════════════════════════════════════

/// Test 1: Identity substitution attack.
///
/// Scenario:
/// 1. Gateway A advertises (its identity is `gateway_A`).
/// 2. The client learns Gateway A's NodeId from the advertisement.
/// 3. An attacker redirects the client to the attacker's own endpoint.
/// 4. The client connects to the attacker's endpoint and performs the
///    SNP-IK/0.1 handshake, pinning `expected_peer_node_id = gateway_A_node_id`.
/// 5. The attacker responds with its OWN NodeDescriptor (signed under the
///    attacker's Ed25519 secret key, advertising the attacker's NodeId).
/// 6. The client's `perform_snp_ik_handshake` returns
///    `Err(LinkError::HandshakeUnexpectedPeer)` — the attacker's NodeId
///    does not match the expected (Gateway A's) NodeId.
///
/// This proves the SNP-IK/0.1 handshake's "I"-style identity pinning
/// detects endpoint/identity substitution.
#[test]
fn test_identity_substitution_rejected_by_snp_ik_handshake() {
    // Gateway A's identity (the legitimate gateway the client expects to
    // reach).
    let gateway_a = TestIdentity::from_seed(b"N2.0.5 identity-substitution gateway A seed");
    // Attacker's identity (the man-in-the-middle at the redirected
    // endpoint). The attacker has its OWN Ed25519 + X25519 keypairs (it
    // cannot forge Gateway A's signatures).
    let attacker = TestIdentity::from_seed(b"N2.0.5 identity-substitution attacker seed");
    // Client's identity (the initiator).
    let client = TestIdentity::from_seed(b"N2.0.5 identity-substitution client seed");

    // Sanity check: the gateway and attacker have DIFFERENT NodeIds.
    assert_ne!(
        gateway_a.node_id, attacker.node_id,
        "test setup: gateway A and attacker MUST have distinct NodeIds"
    );

    // The attacker starts a TCP listener (this is the endpoint the client
    // will be redirected to).
    let attacker_listener = TcpListener::bind("127.0.0.1:0").expect("bind attacker listener");
    let attacker_addr = attacker_listener.local_addr().expect("local_addr");
    let attacker_ed_sk = attacker.ed_sk;
    let attacker_ed_pk = attacker.ed_pk;
    let attacker_x_sk = attacker.x_sk.clone();
    let attacker_x_pk = attacker.x_pk.clone();

    // The attacker thread: accepts the client's connection and performs the
    // SNP-IK/0.1 handshake as the responder, using its OWN identity (NOT
    // Gateway A's identity — the attacker does NOT have Gateway A's
    // secret key).
    let attacker_handle = thread::spawn(move || {
        let (mut stream, _) = attacker_listener.accept().expect("attacker accept");
        // The attacker performs the handshake honestly (using its OWN
        // identity). It does NOT need to forge Gateway A's identity — the
        // attack scenario is that the client was redirected to the
        // attacker's endpoint and the attacker will try to fool the client
        // into accepting the attacker as the legitimate gateway.
        //
        // The attacker's only hope is that the client does NOT pin the
        // expected peer NodeId. If the client pins Gateway A's NodeId, the
        // handshake will fail with HandshakeUnexpectedPeer (which is what
        // this test verifies).
        let result = perform_snp_ik_handshake(
            &mut stream,
            false, // responder
            &attacker_ed_sk,
            &attacker_ed_pk,
            &attacker_x_sk,
            &attacker_x_pk,
            None, // responder does not pin the initiator's identity
        );
        result
    });

    // The client connects to the attacker's endpoint (because the
    // advertisement / bootstrap list was tampered with — the endpoint
    // points to the attacker, but the advertised NodeId is Gateway A's).
    let mut client_stream = TcpStream::connect(attacker_addr).expect("connect to attacker");

    // The client pins the expected peer NodeId to Gateway A's NodeId
    // (learnt from the signed advertisement — the advertisement's
    // signature verifies, so the client trusts the NodeId even though the
    // endpoint may have been tampered with).
    let expected_peer_node_id = gateway_a.node_id;

    let client_result = perform_snp_ik_handshake(
        &mut client_stream,
        true, // initiator
        &client.ed_sk,
        &client.ed_pk,
        &client.x_sk,
        &client.x_pk,
        Some(&expected_peer_node_id),
    );

    // The client's handshake MUST fail with HandshakeUnexpectedPeer — the
    // attacker's authenticated NodeId does NOT match the expected (Gateway
    // A's) NodeId.
    assert!(
        matches!(client_result, Err(LinkError::HandshakeUnexpectedPeer)),
        "client MUST reject the attacker whose authenticated NodeId does NOT \
         match the advertised (Gateway A's) NodeId; got {:?}",
        client_result.err()
    );

    // The attacker's handshake on its end — it may or may not have
    // completed. We don't care about the attacker's view; what matters is
    // that the CLIENT rejected the attacker.
    let _ = attacker_handle.join();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: legitimate gateway handshake succeeds (control / positive case)
// ═══════════════════════════════════════════════════════════════════════════

/// Test 2: Control case — when the client connects to the LEGITIMATE
/// gateway (not the attacker), the handshake succeeds and the client
/// authenticates the gateway's NodeId.
///
/// This is the positive counterpart to Test 1: it confirms the test setup
/// is correct (the identities, the handshake function, the pinning logic)
/// and that the rejection in Test 1 was specifically due to identity
/// substitution (not some other failure in the test setup).
#[test]
fn test_legitimate_gateway_handshake_succeeds() {
    let gateway_a = TestIdentity::from_seed(b"N2.0.5 identity-substitution gateway A seed");
    let client = TestIdentity::from_seed(b"N2.0.5 identity-substitution client seed");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let gw_ed_sk = gateway_a.ed_sk;
    let gw_ed_pk = gateway_a.ed_pk;
    let gw_x_sk = gateway_a.x_sk.clone();
    let gw_x_pk = gateway_a.x_pk.clone();

    let gw_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        perform_snp_ik_handshake(
            &mut stream, false, &gw_ed_sk, &gw_ed_pk, &gw_x_sk, &gw_x_pk, None,
        ).expect("gateway handshake should succeed")
    });

    let mut client_stream = TcpStream::connect(addr).expect("connect");
    let client_result = perform_snp_ik_handshake(
        &mut client_stream, true, &client.ed_sk, &client.ed_pk, &client.x_sk, &client.x_pk,
        Some(&gateway_a.node_id),
    ).expect("client handshake with legitimate gateway should succeed");

    let gw_result: HandshakeResult = gw_handle.join().expect("join");

    // The client authenticated the gateway's NodeId.
    assert_eq!(
        client_result.peer_node_id, gateway_a.node_id,
        "client MUST authenticate the gateway's NodeId"
    );
    assert_eq!(
        client_result.peer_public_key, gateway_a.ed_pk,
        "client MUST authenticate the gateway's Ed25519 public key"
    );

    // Both sides derived matching directional keys.
    assert_eq!(
        client_result.link_keys.send_key, gw_result.link_keys.recv_key,
        "client send_key MUST equal gateway recv_key"
    );
    assert_eq!(
        client_result.link_keys.recv_key, gw_result.link_keys.send_key,
        "client recv_key MUST equal gateway send_key"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: identity substitution with full advertisement + circuit attempt
// ═══════════════════════════════════════════════════════════════════════════

/// Test 3: Full identity substitution scenario.
///
/// This test exercises the FULL attack scenario:
/// 1. Gateway A advertises a signed advertisement (with `node_id = A_node_id`).
/// 2. The client receives the advertisement (the signature verifies, so the
///    client trusts `node_id = A_node_id`).
/// 3. The client is redirected to the attacker's endpoint (the
///    `listen_addr` was tampered with — but the signature covers
///    `listen_addr`, so this scenario assumes the attacker used a
///    SEPARATE channel to redirect the client, e.g. a malicious bootstrap
///    list, OR the client fetched the advertisement from a trusted cache
///    that was poisoned).
/// 4. The client attempts to establish a circuit to the gateway via the
///    SNP-IK/0.1 handshake, pinning `expected_peer_node_id = A_node_id`.
/// 5. The handshake FAILS with `HandshakeUnexpectedPeer`.
///
/// This is the end-to-end scenario: even with a signed, verified
/// advertisement, if the client is redirected to a different endpoint,
/// the SNP-IK/0.1 handshake detects the substitution.
#[test]
fn test_full_identity_substitution_scenario_with_advertisement() {
    use snp_node::node::{GatewayAdvertisement, NodeIdentity};

    // Gateway A's identity (the legitimate gateway).
    let gateway_a_sk = sha256(b"N2.0.5 full-substitution gateway A secret");
    let gateway_a_identity = NodeIdentity::from_secret(gateway_a_sk);
    let gateway_a_node_id = gateway_a_identity.node_id;
    let gateway_a_public_key = gateway_a_identity.public_key;

    // Attacker's identity (the man-in-the-middle at the redirected endpoint).
    let attacker_sk = sha256(b"N2.0.5 full-substitution attacker secret");
    let attacker_identity = NodeIdentity::from_secret(attacker_sk);
    let attacker_node_id = attacker_identity.node_id;
    let attacker_ed_pk = attacker_identity.public_key;
    let (attacker_x_sk, attacker_x_pk) = x25519_static_keypair();

    // Sanity check.
    assert_ne!(
        gateway_a_node_id, attacker_node_id,
        "test setup: gateway and attacker MUST have distinct NodeIds"
    );

    // Step 1: Gateway A signs a legitimate advertisement. The client will
    // verify this signature and trust the advertised NodeId.
    let legit_advert = GatewayAdvertisement::for_identity(
        &gateway_a_identity,
        "127.0.0.1:7001", // transit listen addr (this is what the attacker will redirect)
        "127.0.0.1:7002", // discovery addr
    );
    assert!(
        legit_advert.verify(),
        "test setup: legitimate advertisement MUST verify"
    );
    assert_eq!(
        legit_advert.node_id, gateway_a_node_id,
        "advertised NodeId MUST match Gateway A's NodeId"
    );

    // Step 2: The attacker starts a listener at a DIFFERENT address. In the
    // attack scenario, the client is redirected to this address (e.g. via a
    // poisoned bootstrap list, DNS poisoning, or BGP hijack).
    let attacker_listener = TcpListener::bind("127.0.0.1:0").expect("bind attacker");
    let attacker_addr = attacker_listener.local_addr().expect("local_addr");
    let attacker_addr_for_thread = attacker_addr;

    let attacker_handle = thread::spawn(move || {
        let (mut stream, _) = attacker_listener.accept().expect("attacker accept");
        // The attacker performs the SNP-IK/0.1 handshake using its OWN
        // identity (NOT Gateway A's identity). The attacker CANNOT forge
        // Gateway A's identity because it does not have Gateway A's
        // Ed25519 secret key.
        let _ = perform_snp_ik_handshake(
            &mut stream, false, &attacker_sk, &attacker_ed_pk,
            &attacker_x_sk, &attacker_x_pk, None,
        );
    });

    // Step 3: The client connects to the attacker's endpoint (the
    // `listen_addr` from the advertisement was tampered with in a separate
    // channel — the advertisement's signature is NOT broken, but the
    // client's connection target has been substituted).
    let mut client_stream = TcpStream::connect(attacker_addr_for_thread).expect("connect");

    // The client pins the expected peer NodeId to the ADVERTISED NodeId
    // (Gateway A's NodeId, which the client trusts because the
    // advertisement's signature verified).
    let client_sk = sha256(b"N2.0.5 full-substitution client secret");
    let client_pk = derive_public_key(&client_sk);
    let (client_x_sk, client_x_pk) = x25519_static_keypair();

    let client_result = perform_snp_ik_handshake(
        &mut client_stream, true, &client_sk, &client_pk, &client_x_sk, &client_x_pk,
        Some(&gateway_a_node_id),
    );

    // Step 4: The handshake MUST fail with HandshakeUnexpectedPeer — the
    // attacker's authenticated NodeId (attacker_node_id) does NOT match
    // the advertised/expected NodeId (gateway_a_node_id).
    assert!(
        matches!(client_result, Err(LinkError::HandshakeUnexpectedPeer)),
        "client MUST reject the attacker whose authenticated NodeId ({}) does NOT match \
         the advertised (Gateway A's) NodeId ({}); got {:?}",
        hex_short(&attacker_node_id),
        hex_short(&gateway_a_node_id),
        client_result.err()
    );

    // Verify the attacker's NodeId is DIFFERENT from Gateway A's — this is
    // the cryptographic reason the handshake failed.
    assert_ne!(
        attacker_node_id, gateway_a_node_id,
        "the attacker's NodeId MUST differ from Gateway A's (otherwise the handshake \
         would have succeeded — the attacker would have to know Gateway A's Ed25519 \
         secret key, which it doesn't)"
    );

    // Verify the attacker's public key is DIFFERENT from Gateway A's.
    assert_ne!(
        attacker_ed_pk, gateway_a_public_key,
        "the attacker's Ed25519 public key MUST differ from Gateway A's"
    );

    let _ = attacker_handle.join();
}

/// Helper: format the first 8 bytes of a 32-byte NodeId as hex (for
/// diagnostic messages).
fn hex_short(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n].iter().map(|x| format!("{x:02x}")).collect::<String>() + "…"
}
