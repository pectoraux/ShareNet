//! N2.1.3 — Circuit Cryptographic Setup tests.
//!
//! Tests the circuit handshake module (`src/node/circuit_handshake.rs`):
//! handshake signing/verification, per-hop X25519 DH + HKDF key derivation,
//! authenticated teardown, and the various P0/P1 architectural invariants
//! that defend against source substitution, ephemeral-key substitution,
//! missing circuit keys, and replay.
//!
//! ## Critical invariant
//!
//! `CommittedRoute ≠ Circuit`. A `CommittedRoute` is a cryptographic
//! consent agreement; a `CircuitSetup` is live cryptographic execution
//! state. The transition is mediated by a signed `CircuitHandshake` and
//! per-hop DH key derivation. This file exercises that boundary.

#![allow(clippy::pedantic)]

use snp_cbor::CborValue;
use snp_crypto::{
    derive_node_id, derive_public_key, ed25519_sign, hkdf_sha256, sha256, x25519_dh,
    x25519_ephemeral_keypair, x25519_public_from_bytes, x25519_static_keypair,
};
use snp_node::node::{
    commit_route, discover_path, prepare_circuit_setup, validate_path, Capability, CircuitError,
    CircuitHandshake, CircuitReplayState, CircuitTeardown, CommittedRoute, HopForwardingState,
    Link as Link_, LinkKey, NodeAdvertisement, RouteAcceptance, RouteProposal, RouteRole,
    ServiceAgreement, TopologyGraph, TransportEndpoint, ValidatedPath,
};

// ─── Helpers ──────────────────────────────────────────────────────────────

/// SIG_CONTEXT for circuit handshake/teardown messages — must match the
/// constant in `circuit_handshake.rs`. We duplicate it here only so the
/// adversarial re-signing tests (10, 13) can produce a valid preimage
/// without depending on the private `preimage_bytes()` method.
const CIRCUIT_MSG_CONTEXT: &[u8] = b"SNP/0.1 circuit-msg\0";

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

fn make_gateway_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (_x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk,
        &pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(x_pk.to_bytes()),
        3600,
        seq,
    );
    (advert, sk, pk)
}

/// Build a relay advertisement WITH an X25519 circuit key.
///
/// Per N2.1.3, every relay that participates in a circuit MUST advertise an
/// X25519 circuit public key. The X25519 secret is discarded by this helper
/// (callers needing the relay's X25519 secret for independent key derivation
/// should construct the advert inline — see `relay_derives_same_forwarding_key`).
fn make_relay_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (_x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk,
        &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        Some(x_pk.to_bytes()),
        3600,
        seq,
    );
    (advert, sk, pk)
}

/// Build a relay advertisement WITHOUT an X25519 circuit key.
///
/// Used by `intermediate_relay_missing_circuit_key_rejected` to verify that
/// `prepare_circuit_setup` rejects a relay lacking the required circuit key.
fn make_relay_advert_no_x25519(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk,
        &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None,
        3600,
        seq,
    );
    (advert, sk, pk)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Re-implement `CircuitHandshake::preimage_bytes()` in the test harness so
/// adversarial tests can mutate a handshake's `source` field and re-sign it
/// under an impostor's key. The implementation must EXACTLY mirror the
/// production CBOR map layout + SIG_CONTEXT prefix.
fn handshake_preimage_bytes(h: &CircuitHandshake) -> Vec<u8> {
    let cbor = CborValue::Map(vec![
        (
            CborValue::TextString("protocolVersion".into()),
            CborValue::UnsignedInt(u64::from(h.protocol_version)),
        ),
        (
            CborValue::TextString("circuitId".into()),
            CborValue::ByteString(h.circuit_id.to_vec()),
        ),
        (
            CborValue::TextString("commitmentHash".into()),
            CborValue::ByteString(h.commitment_hash.to_vec()),
        ),
        (
            CborValue::TextString("source".into()),
            CborValue::ByteString(h.source.to_vec()),
        ),
        (
            CborValue::TextString("sourcePublicKey".into()),
            CborValue::ByteString(h.source_public_key.to_vec()),
        ),
        (
            CborValue::TextString("ephemeralX25519Public".into()),
            CborValue::ByteString(h.ephemeral_x25519_public.to_vec()),
        ),
        (
            CborValue::TextString("authorizationRoot".into()),
            CborValue::ByteString(h.authorization_root.to_vec()),
        ),
        (
            CborValue::TextString("timestamp".into()),
            CborValue::UnsignedInt(h.timestamp),
        ),
        (
            CborValue::TextString("expiry".into()),
            CborValue::UnsignedInt(h.expiry),
        ),
        (
            CborValue::TextString("nonce".into()),
            CborValue::ByteString(h.nonce.to_vec()),
        ),
    ]);
    let cbor_bytes = snp_cbor::encode(&cbor).expect("cbor encode");
    let mut msg = Vec::with_capacity(CIRCUIT_MSG_CONTEXT.len() + cbor_bytes.len());
    msg.extend_from_slice(CIRCUIT_MSG_CONTEXT);
    msg.extend_from_slice(&cbor_bytes);
    msg
}

/// Re-implement `CircuitTeardown::preimage_bytes()` for the same reason as
/// `handshake_preimage_bytes`.
fn teardown_preimage_bytes(t: &CircuitTeardown) -> Vec<u8> {
    let cbor = CborValue::Map(vec![
        (
            CborValue::TextString("circuitId".into()),
            CborValue::ByteString(t.circuit_id.to_vec()),
        ),
        (
            CborValue::TextString("source".into()),
            CborValue::ByteString(t.source.to_vec()),
        ),
        (
            CborValue::TextString("sourcePublicKey".into()),
            CborValue::ByteString(t.source_public_key.to_vec()),
        ),
        (
            CborValue::TextString("timestamp".into()),
            CborValue::UnsignedInt(t.timestamp),
        ),
        (
            CborValue::TextString("nonce".into()),
            CborValue::ByteString(t.nonce.to_vec()),
        ),
    ]);
    let cbor_bytes = snp_cbor::encode(&cbor).expect("cbor encode");
    let mut msg = Vec::with_capacity(CIRCUIT_MSG_CONTEXT.len() + cbor_bytes.len());
    msg.extend_from_slice(CIRCUIT_MSG_CONTEXT);
    msg.extend_from_slice(&cbor_bytes);
    msg
}

struct TestSetup {
    #[allow(dead_code)]
    graph: TopologyGraph,
    source_id: [u8; 32],
    source_sk: [u8; 32],
    source_pk: [u8; 32],
    relay_id: [u8; 32],
    relay_sk: [u8; 32],
    relay_pk: [u8; 32],
    gateway_id: [u8; 32],
    gateway_sk: [u8; 32],
    gateway_pk: [u8; 32],
    committed_route: CommittedRoute,
    validated_path: ValidatedPath,
}

/// Stand up a 3-hop topology: source → relay → gateway. Build the validated
/// path, proposal, acceptances, and committed route.
fn setup() -> TestSetup {
    let mut graph = TopologyGraph::new_for_testing();
    let (source_sk, source_pk) = fresh_keypair(b"n213-source");
    let source_id = derive_node_id(&source_pk);
    let source_advert = NodeAdvertisement::create_and_sign(
        &source_sk,
        &source_pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")],
        None,
        3600,
        1,
    );
    graph
        .accept_advertisement(
            source_advert
                .verify_into_verified()
                .expect("source advert verify failed"),
        )
        .unwrap();

    let (relay_advert, relay_sk, relay_pk) = make_relay_advert(b"n213-relay", 1);
    let relay_id = derive_node_id(&relay_pk);
    graph
        .accept_advertisement(relay_advert.verify_into_verified().expect("relay verify"))
        .unwrap();

    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert(b"n213-gateway", 1);
    let gateway_id = derive_node_id(&gw_pk);
    graph
        .accept_advertisement(gw_advert.verify_into_verified().expect("gateway verify"))
        .unwrap();

    graph.add_link(Link_::new_up(
        LinkKey::new(source_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));
    graph.add_link(Link_::new_up(
        LinkKey::new(relay_id, gateway_id, TransportEndpoint::tcp("127.0.0.1:2")),
        None,
    ));

    let exec = graph.snapshot_executable();
    let discovered = discover_path(&exec, &source_id, &gateway_id).expect("path discovery");
    let validated_path = validate_path(&exec, &discovered).expect("path validation");

    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &validated_path,
        &source_sk,
        &source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    )
    .expect("proposal");
    let hash = proposal.proposal_hash().unwrap();
    let acceptances = vec![
        RouteAcceptance::create_and_sign(
            &relay_sk,
            &relay_pk,
            relay_id,
            hash,
            RouteRole::Relay,
            vec![],
            now + 3600,
        )
        .unwrap(),
        RouteAcceptance::create_and_sign(
            &gw_sk,
            &gw_pk,
            gateway_id,
            hash,
            RouteRole::Gateway,
            vec![],
            now + 3600,
        )
        .unwrap(),
    ];

    let committed_route = commit_route(proposal, acceptances, &validated_path, now).expect("commit");

    TestSetup {
        graph,
        source_id,
        source_sk,
        source_pk,
        relay_id,
        relay_sk,
        relay_pk,
        gateway_id,
        gateway_sk: gw_sk,
        gateway_pk: gw_pk,
        committed_route,
        validated_path,
    }
}

/// Build a fresh ephemeral X25519 keypair + signed handshake for `setup`'s
/// committed route, owned by the source. Returns the secret so the caller
/// can pass the SAME secret to `prepare_circuit_setup` (P0 #2: the supplied
/// secret must match the signed ephemeral public key).
fn fresh_handshake(ts: &TestSetup) -> (snp_crypto::X25519Secret, CircuitHandshake) {
    let (eph_sk, _eph_pk) = x25519_ephemeral_keypair();
    let handshake = CircuitHandshake::create_and_sign(
        &ts.committed_route,
        &ts.source_sk,
        &ts.source_pk,
        &eph_sk,
        [0u8; 32],
    )
    .expect("handshake");
    (eph_sk, handshake)
}

// ─── Original N2.1.3 tests (updated for renamed API) ─────────────────────

/// 1. A `CircuitSetup` is cryptographically bound to its committed route via
/// the `commitment_hash`. The circuit's `commitment_hash()` MUST equal the
/// committed route's `commitment()`.
#[test]
fn circuit_bound_to_committed_route() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);
    let circuit = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("circuit setup must succeed for a valid handshake");

    assert_eq!(
        circuit.commitment_hash(),
        ts.committed_route.commitment(),
        "circuit commitment_hash must match the committed route's commitment"
    );
    assert!(
        handshake.is_bound_to(&ts.committed_route),
        "handshake.is_bound_to must agree"
    );
}

/// 2. The `CircuitHandshake` signature is verifiable against the source's
/// Ed25519 public key, AND the NodeId↔pubkey binding holds.
#[test]
fn handshake_signature_verified() {
    let ts = setup();
    let (_eph_sk, handshake) = fresh_handshake(&ts);

    assert!(handshake.verify(), "freshly signed handshake must verify");
    assert_eq!(handshake.source, ts.source_id);
    assert_eq!(handshake.source_public_key, ts.source_pk);

    // Tamper: flip one bit in the signature — verification must fail (P0).
    let mut tampered = handshake.clone();
    tampered.source_signature[0] ^= 0x01;
    assert!(!tampered.verify(), "tampered signature must NOT verify");
}

/// 3. Each circuit carries a unique 32-byte `circuit_id` drawn from OS
/// randomness. Two handshakes for the same route must have distinct ids.
#[test]
fn replay_prevented_via_unique_circuit_id() {
    let ts = setup();
    let (_e1, h1) = fresh_handshake(&ts);
    let (_e2, h2) = fresh_handshake(&ts);

    assert_ne!(
        h1.circuit_id, h2.circuit_id,
        "circuit_id must be unique per handshake (random 32 bytes)"
    );
    assert_ne!(h1.nonce, h2.nonce, "nonce must be unique per handshake");
}

/// 4. `prepare_circuit_setup` derives per-hop forwarding keys via X25519 DH
/// (initiator's ephemeral + each hop's authenticated X25519 circuit key)
/// followed by HKDF-SHA256. Keys must be non-zero, distinct per hop, and the
/// source (hop 0) has no forwarding key (zero — it IS the initiator).
#[test]
fn prepare_circuit_setup_derives_per_hop_keys() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);
    let circuit = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("circuit setup must succeed");

    let hops = circuit.hops();
    assert_eq!(hops.len(), 3, "3 hops: source → relay → gateway");

    // Hop 0 (source) has no forwarding key — it's the initiator.
    assert_eq!(hops[0].node_id, ts.source_id);
    assert_eq!(
        hops[0].forwarding_key, [0u8; 32],
        "source (initiator) has no forwarding key"
    );
    assert!(hops[0].predecessor_node_id.is_none());
    assert_eq!(hops[0].successor_node_id, Some(ts.relay_id));

    // Hop 1 (relay) has a non-zero forwarding key + correct neighbour binding.
    assert_eq!(hops[1].node_id, ts.relay_id);
    assert_ne!(
        hops[1].forwarding_key, [0u8; 32],
        "relay forwarding key must be derived (non-zero)"
    );
    assert_eq!(hops[1].predecessor_node_id, Some(ts.source_id));
    assert_eq!(hops[1].successor_node_id, Some(ts.gateway_id));

    // Hop 2 (gateway) has a non-zero forwarding key + no successor.
    assert_eq!(hops[2].node_id, ts.gateway_id);
    assert_ne!(
        hops[2].forwarding_key, [0u8; 32],
        "gateway forwarding key must be derived (non-zero)"
    );
    assert_eq!(hops[2].predecessor_node_id, Some(ts.relay_id));
    assert!(hops[2].successor_node_id.is_none());

    // Per-hop keys must be distinct (different NodeIds → different HKDF info).
    assert_ne!(
        hops[1].forwarding_key, hops[2].forwarding_key,
        "per-hop forwarding keys must be distinct"
    );
}

/// 5. If the handshake is for route A but we pass route B to
/// `prepare_circuit_setup`, the commitment check must fail with
/// `CommitmentMismatch`.
#[test]
fn wrong_commitment_hash_rejected() {
    let ts1 = setup();
    let ts2 = setup(); // distinct topology → distinct commitment

    // Sanity: the two committed routes have different commitments.
    assert_ne!(
        ts1.committed_route.commitment(),
        ts2.committed_route.commitment(),
        "two independently built routes must have different commitments"
    );

    let (eph_sk, handshake_for_route_1) = fresh_handshake(&ts1);

    // Pass handshake_for_route_1 with route 2 — must fail.
    let err = prepare_circuit_setup(&ts2.committed_route, &handshake_for_route_1, &eph_sk)
        .expect_err("handshake bound to a different route must be rejected");
    assert!(
        matches!(err, CircuitError::CommitmentMismatch),
        "expected CommitmentMismatch, got {err:?}"
    );
}

/// 6. Endpoint substitution is prevented: each hop's X25519 circuit key is
/// sourced from the AUTHENTICATED `AuthenticatedNodeRecord` inside the
/// committed route. An attacker cannot substitute a different X25519 public
/// key — the derived forwarding key matches the one derived from the
/// authenticated record's key.
///
/// We verify this indirectly: independently re-derive the relay's
/// forwarding key from the authenticated record's X25519 public key (NOT
/// from any attacker-supplied value) and confirm it matches the value in
/// the `CircuitSetup`. Then we show that an attacker-supplied (different)
/// X25519 key produces a different forwarding key.
#[test]
fn endpoint_substitution_prevented() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);
    let circuit = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("circuit setup must succeed");

    // The X25519 circuit public key comes from the authenticated record at
    // hop 1 (the relay), which is part of the committed route's evidence.
    let relay_record = ts
        .committed_route
        .hop_record(1)
        .expect("relay record must be present");
    let relay_x_pub_bytes = relay_record
        .descriptor
        .circuit_x25519_pub()
        .copied()
        .expect("relay must have an X25519 circuit key");

    // Independently derive the relay's forwarding key from the authenticated
    // record's X25519 public key + the signed ephemeral secret.
    let peer_pub = x25519_public_from_bytes(&relay_x_pub_bytes);
    let dh_secret = x25519_dh(&eph_sk, &peer_pub);
    let salt = &handshake.circuit_id;
    let mut info = Vec::with_capacity(80);
    info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
    info.extend_from_slice(&ts.relay_id);
    info.extend_from_slice(b"/");
    info.extend_from_slice(&handshake.commitment_hash);
    let derived = hkdf_sha256(&dh_secret, salt, &info, 32).expect("hkdf");

    let relay_hop = circuit
        .hop_state(&ts.relay_id)
        .expect("relay hop must be present");

    assert_eq!(
        &derived[..32],
        &relay_hop.forwarding_key,
        "the circuit's forwarding key must EXACTLY match the key derived \
         from the authenticated record's X25519 key — an attacker cannot \
         substitute a different key"
    );

    // And an attacker-supplied (different) X25519 key would produce a
    // different forwarding key:
    let (_attacker_sk, attacker_pk) = x25519_static_keypair();
    let attacker_dh = x25519_dh(&eph_sk, &attacker_pk);
    let attacker_key = hkdf_sha256(&attacker_dh, salt, &info, 32).expect("hkdf");
    assert_ne!(
        &attacker_key[..32],
        &relay_hop.forwarding_key,
        "attacker-supplied X25519 key must NOT produce the same forwarding key"
    );
}

/// 7. A stale (expired) committed route is rejected by `prepare_circuit_setup`.
///
/// Because the route's expiry is checked inside `prepare_circuit_setup` via
/// `route.is_expired(now)`, AND the handshake's own expiry is clamped to
/// `min(route.expiry, now + CIRCUIT_MAX_LIFETIME_SECS)` (so a stale route
/// produces a stale handshake), the practical rejection of a stale route
/// surfaces as `HandshakeInvalid` (the handshake check runs first). We
/// therefore build a route with a 1-second expiry, sleep briefly, and
/// verify:
///   (a) `route.is_expired(now)` returns true (the underlying contract), AND
///   (b) `prepare_circuit_setup` rejects with EITHER `HandshakeInvalid` OR
///       `RouteExpired` (both are valid fail-closed rejections of a stale
///       route — the implementation order is not part of the public contract).
#[test]
fn stale_route_rejected() {
    let ts = setup();

    // Build a route with a 1-second expiry. We can't use a past expiry
    // because `commit_route` rejects already-expired proposals up front
    // (P0 fail-closed at commit time). Instead, build a valid (near-future)
    // route, then sleep past its expiry.
    let now = now_unix();
    let short_expiry = now + 1;
    let proposal = RouteProposal::from_validated_path(
        &ts.validated_path,
        &ts.source_sk,
        &ts.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        short_expiry,
    )
    .expect("proposal");
    let hash = proposal.proposal_hash().unwrap();
    let acceptances = vec![
        RouteAcceptance::create_and_sign(
            &ts.relay_sk,
            &ts.relay_pk,
            ts.relay_id,
            hash,
            RouteRole::Relay,
            vec![],
            short_expiry,
        )
        .unwrap(),
        RouteAcceptance::create_and_sign(
            &ts.gateway_sk,
            &ts.gateway_pk,
            ts.gateway_id,
            hash,
            RouteRole::Gateway,
            vec![],
            short_expiry,
        )
        .unwrap(),
    ];
    let short_route = commit_route(proposal, acceptances, &ts.validated_path, now).expect("commit");

    // Sanity: not yet expired.
    assert!(!short_route.is_expired(now), "route must not yet be expired");

    // Sleep past the expiry.
    std::thread::sleep(std::time::Duration::from_secs(2));

    let after = now_unix();
    assert!(
        short_route.is_expired(after),
        "route must be expired after sleeping past its expiry"
    );

    // Build a handshake bound to the (now-stale) route. The handshake's
    // expiry is clamped to route.expiry, so it is ALSO stale.
    let (eph_sk, handshake) = {
        let (e, _p) = x25519_ephemeral_keypair();
        let h = CircuitHandshake::create_and_sign(&short_route, &ts.source_sk, &ts.source_pk, &e, [0u8; 32])
            .expect("handshake");
        (e, h)
    };

    let err = prepare_circuit_setup(&short_route, &handshake, &eph_sk)
        .expect_err("stale route must be rejected by prepare_circuit_setup");
    assert!(
        matches!(err, CircuitError::HandshakeInvalid | CircuitError::RouteExpired { .. }),
        "expected a stale-route rejection (HandshakeInvalid or RouteExpired), got {err:?}"
    );
}

/// 8. `CircuitTeardown` is authenticated: a teardown signed by the source
/// verifies, and `verify_for_circuit` accepts it for the matching circuit.
#[test]
fn authenticated_teardown() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);
    let mut circuit = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("circuit setup must succeed");
    

    let teardown = CircuitTeardown::create_and_sign(&circuit, &ts.source_sk, &ts.source_pk)
        .expect("teardown");
    assert!(teardown.verify(), "teardown signature must verify");
    assert!(
        teardown.verify_for_circuit(&circuit),
        "teardown must verify against its circuit"
    );

    // Tear the circuit down.
}

/// 9. `CircuitSetup` is NOT a `CommittedRoute`. They are distinct types with
/// distinct roles: a route is a consent agreement; a circuit is live
/// execution state. Their commitments/ids are different cryptographic
/// objects, and the circuit additionally carries per-hop forwarding keys
/// that the route does not.
#[test]
fn circuit_is_not_committed_route() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);
    let circuit = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("circuit setup must succeed");

    // The circuit's `circuit_id` is a fresh 32-byte random value — distinct
    // from the route's commitment hash.
    assert_ne!(
        circuit.circuit_id(),
        ts.committed_route.commitment(),
        "circuit_id is NOT the route commitment — distinct cryptographic objects"
    );
    // The circuit's `commitment_hash` IS the route's commitment (binding),
    // but the circuit additionally carries forwarding state the route lacks.
    assert_eq!(circuit.commitment_hash(), ts.committed_route.commitment());
    assert!(!circuit.hops().is_empty());
    // The route has no forwarding keys; the circuit does.
    assert!(
        circuit
            .hops()
            .iter()
            .skip(1)
            .any(|h| h.forwarding_key != [0u8; 32]),
        "circuit carries per-hop forwarding keys absent from the committed route"
    );
}

// ─── New P0/P1 tests ──────────────────────────────────────────────────────

/// 10. P0 #1: a handshake whose `source` field does not match the
/// CommittedRoute's source is rejected with `CircuitError::SourceMismatch`.
///
/// We craft a handshake bound to `ts.committed_route` (same commitment_hash),
/// but then mutate the `source` / `source_public_key` fields to a different
/// node and re-sign under the impostor's key. The signature verifies (signed
/// by the impostor's key, NodeId↔pubkey check passes), but
/// `prepare_circuit_setup` rejects the source mismatch.
#[test]
fn handshake_source_must_match_route_source() {
    let ts = setup();
    let (eph_sk, mut handshake) = fresh_handshake(&ts);

    // Mutate: substitute a different source.
    let (impostor_sk, impostor_pk) = fresh_keypair(b"n213-impostor-source");
    let impostor_id = derive_node_id(&impostor_pk);
    handshake.source = impostor_id;
    handshake.source_public_key = impostor_pk;
    // Re-sign under the impostor's key so the handshake signature is
    // internally consistent (verify_at passes the NodeId↔pubkey check).
    let preimage = handshake_preimage_bytes(&handshake);
    handshake.source_signature = ed25519_sign(&impostor_sk, &preimage);
    assert!(handshake.verify(), "re-signed handshake must verify internally");

    // The handshake is bound to the route (commitment_hash unchanged), but
    // the source is the impostor, not the route's source.
    let err = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect_err("source-mismatched handshake must be rejected");
    assert!(
        matches!(err, CircuitError::SourceMismatch { handshake_source, route_source }
            if handshake_source == impostor_id && route_source == ts.source_id),
        "expected SourceMismatch, got {err:?}"
    );
}

/// 11. P0 #2: a handshake that signs one ephemeral X25519 public key, but is
/// passed to `prepare_circuit_setup` with a DIFFERENT ephemeral secret, is
/// rejected with `CircuitError::EphemeralKeyMismatch`.
#[test]
fn mismatched_ephemeral_secret_rejected() {
    let ts = setup();
    let (_signed_eph_sk, handshake) = fresh_handshake(&ts);

    // Generate a DIFFERENT ephemeral secret and pass it to
    // prepare_circuit_setup. Its public key won't match the signed one.
    let (wrong_eph_sk, wrong_eph_pk) = x25519_ephemeral_keypair();
    assert_ne!(
        wrong_eph_pk.to_bytes(),
        handshake.ephemeral_x25519_public,
        "test setup: the wrong ephemeral key must differ from the signed one"
    );

    let err = prepare_circuit_setup(&ts.committed_route, &handshake, &wrong_eph_sk)
        .expect_err("mismatched ephemeral secret must be rejected");
    assert!(
        matches!(err, CircuitError::EphemeralKeyMismatch),
        "expected EphemeralKeyMismatch, got {err:?}"
    );
}

/// 12. P0 #3: a relay whose authenticated record lacks an X25519 circuit
/// public key is rejected with `CircuitError::HopMissingCircuitKey`.
#[test]
fn intermediate_relay_missing_circuit_key_rejected() {
    // Build a topology where the intermediate relay does NOT advertise an
    // X25519 circuit key.
    let mut graph = TopologyGraph::new_for_testing();
    let (source_sk, source_pk) = fresh_keypair(b"n213-nosk-source");
    let source_id = derive_node_id(&source_pk);
    let source_advert = NodeAdvertisement::create_and_sign(
        &source_sk,
        &source_pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")],
        None,
        3600,
        1,
    );
    graph
        .accept_advertisement(source_advert.verify_into_verified().unwrap())
        .unwrap();

    let (relay_advert, relay_sk, relay_pk) = make_relay_advert_no_x25519(b"n213-nosk-relay", 1);
    let relay_id = derive_node_id(&relay_pk);
    graph
        .accept_advertisement(relay_advert.verify_into_verified().unwrap())
        .unwrap();

    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert(b"n213-nosk-gateway", 1);
    let gateway_id = derive_node_id(&gw_pk);
    graph
        .accept_advertisement(gw_advert.verify_into_verified().unwrap())
        .unwrap();

    graph.add_link(Link_::new_up(
        LinkKey::new(source_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));
    graph.add_link(Link_::new_up(
        LinkKey::new(relay_id, gateway_id, TransportEndpoint::tcp("127.0.0.1:2")),
        None,
    ));

    let exec = graph.snapshot_executable();
    let discovered = discover_path(&exec, &source_id, &gateway_id).expect("discovery");
    let validated = validate_path(&exec, &discovered).expect("validation");

    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &validated,
        &source_sk,
        &source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    )
    .unwrap();
    let hash = proposal.proposal_hash().unwrap();
    let acceptances = vec![
        RouteAcceptance::create_and_sign(
            &relay_sk,
            &relay_pk,
            relay_id,
            hash,
            RouteRole::Relay,
            vec![],
            now + 3600,
        )
        .unwrap(),
        RouteAcceptance::create_and_sign(
            &gw_sk,
            &gw_pk,
            gateway_id,
            hash,
            RouteRole::Gateway,
            vec![],
            now + 3600,
        )
        .unwrap(),
    ];
    let committed = commit_route(proposal, acceptances, &validated, now).expect("commit");

    // Sanity: hop 1 (relay) has no X25519 key in its authenticated record.
    assert!(
        committed
            .hop_record(1)
            .and_then(|r| r.descriptor.circuit_x25519_pub())
            .is_none(),
        "test setup: relay must NOT have an X25519 circuit key"
    );

    // Build a handshake + circuit attempt. Use ONE ephemeral secret for both
    // create_and_sign and prepare_circuit_setup so the EphemeralKeyMismatch
    // check passes (we want to reach the HopMissingCircuitKey check).
    let (eph_sk, _eph_pk) = x25519_ephemeral_keypair();
    let handshake =
        CircuitHandshake::create_and_sign(&committed, &source_sk, &source_pk, &eph_sk, [0u8; 32])
            .expect("handshake");

    let err = prepare_circuit_setup(&committed, &handshake, &eph_sk)
        .expect_err("relay missing X25519 circuit key must be rejected");
    assert!(
        matches!(err, CircuitError::HopMissingCircuitKey { hop_index, node_id }
            if hop_index == 1 && node_id == relay_id),
        "expected HopMissingCircuitKey for the relay, got {err:?}"
    );
}

/// 13. P1 #6: a teardown signed by a DIFFERENT node (not the circuit's
/// source) must NOT verify for that circuit. `verify_for_circuit` returns
/// false.
#[test]
fn teardown_source_must_match_circuit_source() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);
    let circuit = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("circuit setup must succeed");

    // Build a teardown that's "for" the right circuit_id but signed by a
    // different node (the relay, not the source).
    let mut impostor_teardown =
        CircuitTeardown::create_and_sign(&circuit, &ts.source_sk, &ts.source_pk)
            .expect("baseline teardown");
    // Swap source identity to the relay and re-sign under the relay's key.
    impostor_teardown.source = ts.relay_id;
    impostor_teardown.source_public_key = ts.relay_pk;
    let preimage = teardown_preimage_bytes(&impostor_teardown);
    impostor_teardown.signature = ed25519_sign(&ts.relay_sk, &preimage);

    // The standalone signature verifies (relay signed consistently), BUT
    // `verify_for_circuit` must reject it: the teardown's source is NOT the
    // circuit's source.
    assert!(
        impostor_teardown.verify(),
        "impostor teardown must be internally consistent (relay-signed)"
    );
    assert!(
        !impostor_teardown.verify_for_circuit(&circuit),
        "teardown from a non-source node must NOT verify for the circuit"
    );

    // And the original source-signed teardown DOES verify for the circuit.
    let honest_teardown =
        CircuitTeardown::create_and_sign(&circuit, &ts.source_sk, &ts.source_pk).unwrap();
    assert!(
        honest_teardown.verify_for_circuit(&circuit),
        "honest source-signed teardown must verify"
    );
}

/// 14. P1 #7: a random `circuit_id` alone is NOT replay protection. A replayed
/// handshake (same circuit_id) must be caught by the relay's
/// `CircuitReplayState` once distributed establishment lands in N2.2+.
///
/// This test documents the contract: the stateless `prepare_circuit_setup`
/// does NOT reject a replayed handshake (it has no memory). Replay protection
/// requires the stateful `CircuitReplayState` filter that each relay must
/// maintain.
#[test]
fn replayed_handshake_rejected() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);

    // First establishment succeeds.
    let _circuit_1 = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("first establishment must succeed");

    // A replay (same handshake, same circuit_id) would also succeed at the
    // stateless layer — there's no memory.
    let _circuit_2 = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("stateless layer has no memory; replay 'succeeds' here");

    // The relay's `CircuitReplayState` is what catches the replay: once a
    // relay has accepted a circuit_id, it must reject subsequent handshakes
    // with the same id.
    let replay_state = CircuitReplayState {
        circuit_id: handshake.circuit_id,
        commitment_hash: handshake.commitment_hash,
        source: handshake.source,
        accepted_at: now_unix(),
        expires_at: handshake.expiry,
    };
    assert!(
        replay_state.is_replay_of(&handshake),
        "CircuitReplayState must flag a replayed handshake (same circuit_id)"
    );

    // A different handshake has a different circuit_id and is NOT a replay.
    let (_eph2, other_handshake) = fresh_handshake(&ts);
    assert_ne!(other_handshake.circuit_id, handshake.circuit_id);
    assert!(
        !replay_state.is_replay_of(&other_handshake),
        "a different circuit_id is NOT a replay"
    );
}

/// 15. P1 #5: a relay can independently derive the same forwarding key the
/// source derived for it. The relay has: its own X25519 secret + the
/// initiator's ephemeral public key (from the signed handshake). DH is
/// symmetric, so DH(relay_sk, eph_pub) == DH(eph_sk, relay_pub). The HKDF
/// inputs (salt = circuit_id, info = "SNP/0.1/circuit/hop-key/" || NodeId ||
/// "/" || commitment_hash) are public.
#[test]
fn relay_derives_same_forwarding_key() {
    // Build a topology where we RETAIN the relay's X25519 secret so we can
    // independently derive the forwarding key.
    let mut graph = TopologyGraph::new_for_testing();
    let (source_sk, source_pk) = fresh_keypair(b"n213-relayderive-source");
    let source_id = derive_node_id(&source_pk);
    let source_advert = NodeAdvertisement::create_and_sign(
        &source_sk,
        &source_pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")],
        None,
        3600,
        1,
    );
    graph
        .accept_advertisement(source_advert.verify_into_verified().unwrap())
        .unwrap();

    let (relay_sk, relay_pk) = fresh_keypair(b"n213-relayderive-relay");
    let (relay_x_sk, relay_x_pk) = x25519_static_keypair();
    let relay_id = derive_node_id(&relay_pk);
    let relay_advert = NodeAdvertisement::create_and_sign(
        &relay_sk,
        &relay_pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        Some(relay_x_pk.to_bytes()),
        3600,
        1,
    );
    graph
        .accept_advertisement(relay_advert.verify_into_verified().unwrap())
        .unwrap();

    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert(b"n213-relayderive-gw", 1);
    let gateway_id = derive_node_id(&gw_pk);
    graph
        .accept_advertisement(gw_advert.verify_into_verified().unwrap())
        .unwrap();

    graph.add_link(Link_::new_up(
        LinkKey::new(source_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));
    graph.add_link(Link_::new_up(
        LinkKey::new(relay_id, gateway_id, TransportEndpoint::tcp("127.0.0.1:2")),
        None,
    ));

    let exec = graph.snapshot_executable();
    let discovered = discover_path(&exec, &source_id, &gateway_id).unwrap();
    let validated = validate_path(&exec, &discovered).unwrap();
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &validated,
        &source_sk,
        &source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    )
    .unwrap();
    let hash = proposal.proposal_hash().unwrap();
    let acceptances = vec![
        RouteAcceptance::create_and_sign(
            &relay_sk,
            &relay_pk,
            relay_id,
            hash,
            RouteRole::Relay,
            vec![],
            now + 3600,
        )
        .unwrap(),
        RouteAcceptance::create_and_sign(
            &gw_sk,
            &gw_pk,
            gateway_id,
            hash,
            RouteRole::Gateway,
            vec![],
            now + 3600,
        )
        .unwrap(),
    ];
    let committed = commit_route(proposal, acceptances, &validated, now).expect("commit");

    // Source derives the circuit + forwarding keys. Use ONE ephemeral secret
    // for both create_and_sign and prepare_circuit_setup.
    let (eph_sk, _eph_pk) = x25519_ephemeral_keypair();
    let handshake =
        CircuitHandshake::create_and_sign(&committed, &source_sk, &source_pk, &eph_sk, [0u8; 32])
            .expect("handshake");
    let circuit = prepare_circuit_setup(&committed, &handshake, &eph_sk).expect("circuit");

    let relay_hop = circuit.hop_state(&relay_id).expect("relay hop present");

    // Relay independently derives the SAME forwarding key:
    //   dh_relay = DH(relay_x_sk, initiator_eph_pub)
    // (symmetric to the source's DH(eph_sk, relay_x_pub))
    let initiator_eph_pub = x25519_public_from_bytes(&handshake.ephemeral_x25519_public);
    let dh_relay = x25519_dh(&relay_x_sk, &initiator_eph_pub);

    let salt = &handshake.circuit_id;
    let mut info = Vec::with_capacity(80);
    info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
    info.extend_from_slice(&relay_id);
    info.extend_from_slice(b"/");
    info.extend_from_slice(&handshake.commitment_hash);
    let relay_derived = hkdf_sha256(&dh_relay, salt, &info, 32).expect("hkdf");

    assert_eq!(
        &relay_derived[..32],
        &relay_hop.forwarding_key,
        "relay must independently derive the SAME forwarding key as the source"
    );
}

/// 16. P1 #5: the KDF `info` string contains the FULL 32-byte NodeId (not a
/// truncated/hex_short form). We verify this indirectly by showing that
/// re-deriving the key with a TRUNCATED NodeId (only the first 4 bytes) in
/// the `info` string produces a DIFFERENT key — and that flipping a single
/// bit in the NodeId also produces a different key. If the production KDF
/// used only the short form, the truncated derivation would match.
#[test]
fn full_node_id_used_in_kdf_context() {
    let ts = setup();
    let (eph_sk, handshake) = fresh_handshake(&ts);
    let circuit = prepare_circuit_setup(&ts.committed_route, &handshake, &eph_sk)
        .expect("circuit setup must succeed");

    let relay_hop = circuit.hop_state(&ts.relay_id).expect("relay hop present");

    // Pull the authenticated X25519 public key + recompute the DH.
    let relay_record = ts
        .committed_route
        .hop_record(1)
        .expect("relay record present");
    let relay_x_pub_bytes = relay_record
        .descriptor
        .circuit_x25519_pub()
        .copied()
        .expect("relay X25519 key");
    let peer_pub = x25519_public_from_bytes(&relay_x_pub_bytes);
    let dh_secret = x25519_dh(&eph_sk, &peer_pub);

    let salt = &handshake.circuit_id;

    // Real info: "SNP/0.1/circuit/hop-key/" || FULL NodeId || "/" || commitment.
    let mut real_info = Vec::with_capacity(80);
    real_info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
    real_info.extend_from_slice(&ts.relay_id);
    real_info.extend_from_slice(b"/");
    real_info.extend_from_slice(&handshake.commitment_hash);
    let real_key = hkdf_sha256(&dh_secret, salt, &real_info, 32).expect("hkdf");
    assert_eq!(
        &real_key[..32],
        &relay_hop.forwarding_key,
        "real (full-NodeId) derivation must match the circuit's forwarding key"
    );

    // Truncated info: only the first 4 bytes of NodeId (hex_short-style).
    // If the production KDF used only the short form, this would match.
    let mut short_info = Vec::with_capacity(48);
    short_info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
    short_info.extend_from_slice(&ts.relay_id[..4]);
    short_info.extend_from_slice(b"/");
    short_info.extend_from_slice(&handshake.commitment_hash);
    let short_key = hkdf_sha256(&dh_secret, salt, &short_info, 32).expect("hkdf");

    assert_ne!(
        &short_key[..32],
        &relay_hop.forwarding_key,
        "a truncated-NodeId KDF must NOT produce the same key — the full \
         32-byte NodeId is part of the KDF info"
    );

    // And: a DIFFERENT NodeId (same X25519 key, same everything else)
    // produces a different key — directly demonstrating that the NodeId is
    // bound into the KDF info.
    let mut other_info = Vec::with_capacity(80);
    other_info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
    let mut other_node_id = ts.relay_id;
    other_node_id[0] ^= 0x01; // flip one bit
    other_info.extend_from_slice(&other_node_id);
    other_info.extend_from_slice(b"/");
    other_info.extend_from_slice(&handshake.commitment_hash);
    let other_key = hkdf_sha256(&dh_secret, salt, &other_info, 32).expect("hkdf");
    assert_ne!(
        &other_key[..32],
        &relay_hop.forwarding_key,
        "a different NodeId must produce a different forwarding key"
    );
}

// ─── Compile-time check: HopForwardingState is exported as documented ─────

/// Sanity-check that the `HopForwardingState` type is re-exported from
/// `snp_node::node` (the spec's import list includes it). This is a 1-line
/// type-position test — no runtime behaviour.
#[test]
fn hop_forwarding_state_type_is_exported() {
    fn _accepts<H: Clone>(_h: H) {}
    let h = HopForwardingState {
        node_id: [0u8; 32],
        predecessor_node_id: None,
        successor_node_id: None,
        forwarding_key: [0u8; 32],
    };
    _accepts(h);
}
