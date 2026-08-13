//! N2.2 — Distributed Circuit Establishment & Forwarding State tests.
//!
//! Tests the distributed handshake, relay-side processing, replay prevention,
//! and ActiveCircuit construction.

#![allow(clippy::pedantic)]

use snp_crypto::{
    derive_node_id, derive_public_key, sha256, x25519_static_keypair,
    x25519_ephemeral_keypair, x25519_dh, x25519_public_from_bytes,
    hkdf_sha256,
};
use snp_node::node::{
    ActiveCircuit, Capability, CircuitAcceptanceStore, CircuitHandshake,
    CircuitSetup, CommittedRoute, CommitError, DistributedCircuitError,
    HopForwardingState, Link as Link_, LinkKey, NodeAdvertisement,
    RelayForwardingState, RelayHandshakeRequest, RelayHandshakeResponse,
    RelayHandshakeTransport, RouteAcceptance, RouteProposal, RouteRole,
    ServiceAgreement, TopologyGraph, TransportEndpoint, ValidatedPath,
    accept_relay_handshake, commit_route, discover_path, establish_distributed_circuit,
    prepare_circuit_setup, validate_path, verify_dh_proof,
};
use std::collections::HashMap;

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

fn make_gateway_advert_with_x25519(label: &[u8], seq: u64, x25519_pk: &[u8; 32]) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(*x25519_pk), 3600, seq,
    );
    (advert, sk, pk)
}

fn make_relay_advert_with_x25519(label: &[u8], seq: u64, x25519_pk: &[u8; 32]) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        Some(*x25519_pk), 3600, seq,
    );
    (advert, sk, pk)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mock relay info: stores all key material for a relay.
struct MockRelay {
    node_id: [u8; 32],
    ed25519_sk: [u8; 32],
    ed25519_pk: [u8; 32],
    x25519_sk: snp_crypto::X25519Secret,
    x25519_pk: [u8; 32],
    acceptance_store: CircuitAcceptanceStore,
}

/// Mock transport that simulates relay responses.
struct MockTransport {
    relays: HashMap<[u8; 32], std::cell::RefCell<MockRelay>>,
    /// If set, this relay will be "unreachable".
    unreachable: Option<[u8; 32]>,
}

impl RelayHandshakeTransport for MockTransport {
    fn send_handshake(&self, request: &RelayHandshakeRequest) -> Option<RelayHandshakeResponse> {
        let relay_id = request.relay_node_id;

        // Check if this relay is unreachable.
        if self.unreachable == Some(relay_id) {
            return None;
        }

        let relay_cell = self.relays.get(&relay_id)?;
        let mut relay = relay_cell.borrow_mut();

        // Clone key material to avoid borrow issues (acceptance_store is also in the struct).
        let x25519_sk = relay.x25519_sk.clone();
        let ed25519_sk = relay.ed25519_sk;
        let ed25519_pk = relay.ed25519_pk;

        // Process the handshake on the relay side.
        let result = accept_relay_handshake(
            request,
            &x25519_sk,
            &ed25519_sk,
            &ed25519_pk,
            &mut relay.acceptance_store,
        );

        match result {
            Ok((response, _forwarding_state)) => Some(response),
            Err(_) => None,
        }
    }
}

struct TestSetup {
    source_id: [u8; 32],
    source_sk: [u8; 32],
    source_pk: [u8; 32],
    relay_id: [u8; 32],
    relay_sk: [u8; 32],
    relay_pk: [u8; 32],
    relay_x25519_sk: snp_crypto::X25519Secret,
    relay_x25519_pk: [u8; 32],
    gateway_id: [u8; 32],
    gateway_sk: [u8; 32],
    gateway_pk: [u8; 32],
    gateway_x25519_sk: snp_crypto::X25519Secret,
    gateway_x25519_pk: [u8; 32],
    committed_route: CommittedRoute,
    validated_path: ValidatedPath,
    circuit_setup: CircuitSetup,
    circuit_handshake: CircuitHandshake,
    ephemeral_secret: snp_crypto::X25519Secret,
}

fn setup() -> TestSetup {
    let mut graph = TopologyGraph::new_for_testing();
    let (source_sk, source_pk) = fresh_keypair(b"n22-source");
    let source_id = derive_node_id(&source_pk);
    let source_advert = NodeAdvertisement::create_and_sign(
        &source_sk, &source_pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")], None, 3600, 1,
    );
    graph.accept_advertisement(source_advert.verify_into_verified().unwrap()).unwrap();

    let (relay_x25519_sk, relay_x25519_pk_pair) = x25519_static_keypair();
    let relay_x25519_pk = relay_x25519_pk_pair.to_bytes();
    let (relay_advert, relay_sk, relay_pk) = make_relay_advert_with_x25519(b"n22-relay", 1, &relay_x25519_pk);
    let relay_id = derive_node_id(&relay_pk);
    graph.accept_advertisement(relay_advert.verify_into_verified().unwrap()).unwrap();

    let (gateway_x25519_sk, gateway_x25519_pk_pair) = x25519_static_keypair();
    let gateway_x25519_pk = gateway_x25519_pk_pair.to_bytes();
    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert_with_x25519(b"n22-gateway", 1, &gateway_x25519_pk);
    let gateway_id = derive_node_id(&gw_pk);
    graph.accept_advertisement(gw_advert.verify_into_verified().unwrap()).unwrap();

    graph.add_link(Link_::new_up(
        LinkKey::new(source_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));
    graph.add_link(Link_::new_up(
        LinkKey::new(relay_id, gateway_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));

    let exec = graph.snapshot_executable();
    let discovered = discover_path(&exec, &source_id, &gateway_id).unwrap();
    let validated_path = validate_path(&exec, &discovered).unwrap();
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &validated_path, &source_sk, &source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    ).unwrap();
    let hash = proposal.proposal_hash().unwrap();
    let relay_acc = RouteAcceptance::create_and_sign(
        &relay_sk, &relay_pk, relay_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    ).unwrap();
    let gateway_acc = RouteAcceptance::create_and_sign(
        &gw_sk, &gw_pk, gateway_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    ).unwrap();
    let committed_route = commit_route(proposal, vec![relay_acc, gateway_acc], &validated_path, now).unwrap();

    let (ephemeral_secret, _) = x25519_ephemeral_keypair();
    let circuit_handshake = CircuitHandshake::create_and_sign(
        &committed_route, &source_sk, &source_pk, &ephemeral_secret,
    ).unwrap();
    let circuit_setup = prepare_circuit_setup(&committed_route, &circuit_handshake, &ephemeral_secret).unwrap();

    TestSetup {
        source_id, source_sk, source_pk,
        relay_id, relay_sk, relay_pk,
        relay_x25519_sk, relay_x25519_pk,
        gateway_id, gateway_sk: gw_sk, gateway_pk: gw_pk,
        gateway_x25519_sk, gateway_x25519_pk,
        committed_route, validated_path,
        circuit_setup, circuit_handshake,
        ephemeral_secret,
    }
}

fn make_mock_transport(ts: &TestSetup) -> MockTransport {
    let mut relays = HashMap::new();
    relays.insert(ts.relay_id, std::cell::RefCell::new(MockRelay {
        node_id: ts.relay_id,
        ed25519_sk: ts.relay_sk,
        ed25519_pk: ts.relay_pk,
        x25519_sk: ts.relay_x25519_sk.clone(),
        x25519_pk: ts.relay_x25519_pk,
        acceptance_store: CircuitAcceptanceStore::new(),
    }));
    relays.insert(ts.gateway_id, std::cell::RefCell::new(MockRelay {
        node_id: ts.gateway_id,
        ed25519_sk: ts.gateway_sk,
        ed25519_pk: ts.gateway_pk,
        x25519_sk: ts.gateway_x25519_sk.clone(),
        x25519_pk: ts.gateway_x25519_pk,
        acceptance_store: CircuitAcceptanceStore::new(),
    }));
    MockTransport { relays, unreachable: None }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

/// An ActiveCircuit is produced only after ALL required relays acknowledge.
#[test]
fn distributed_circuit_requires_all_acknowledgements() {
    let ts = setup();
    let transport = make_mock_transport(&ts);

    let result = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    );

    assert!(result.is_ok(), "distributed circuit must succeed when all relays respond");
    let circuit = result.unwrap();
    assert_eq!(circuit.relay_responses().len(), 2, "both relay + gateway must acknowledge");
    assert!(circuit.relay_acknowledged(&ts.relay_id));
    assert!(circuit.relay_acknowledged(&ts.gateway_id));
}

/// If one relay is unreachable, the circuit cannot be established.
#[test]
fn active_circuit_not_produced_if_relay_unreachable() {
    let ts = setup();
    let mut transport = make_mock_transport(&ts);
    transport.unreachable = Some(ts.relay_id);

    let result = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    );

    assert!(
        matches!(result, Err(DistributedCircuitError::RelayUnreachable { relay_node_id }) if relay_node_id == ts.relay_id),
        "must fail with RelayUnreachable when relay is unreachable"
    );
}

/// The relay proves X25519 key possession by computing the same DH and
/// including SHA-256(dh_secret) in its response.
#[test]
fn relay_proves_x25519_possession() {
    let ts = setup();
    let transport = make_mock_transport(&ts);

    // Establish the circuit.
    let circuit = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    ).unwrap();

    // Get the relay's response.
    let relay_response = circuit.relay_response(&ts.relay_id).unwrap();

    // The DH proof should be non-zero.
    assert!(
        !relay_response.dh_proof.iter().all(|&b| b == 0),
        "DH proof must be non-zero"
    );

    // Verify the DH proof: recompute DH(source_ephemeral, relay_x25519_pub)
    // and check SHA-256(dh_secret) == response.dh_proof.
    let relay_pub = x25519_public_from_bytes(&ts.relay_x25519_pk);
    let dh_secret = x25519_dh(&ts.ephemeral_secret, &relay_pub);
    let expected_proof = sha256(&dh_secret);

    assert_eq!(
        relay_response.dh_proof, expected_proof,
        "relay's DH proof must match SHA-256 of the DH shared secret"
    );

    // Verify the DH proof using the verify_dh_proof function.
    assert!(
        verify_dh_proof(relay_response, &dh_secret),
        "verify_dh_proof must confirm the relay proved X25519 key possession"
    );
}

/// The relay derives the same forwarding key as the source.
#[test]
fn relay_derives_same_forwarding_key() {
    let ts = setup();

    // Source's forwarding key for the relay (from CircuitSetup).
    let source_relay_key = ts.circuit_setup.hops()[1].forwarding_key;

    // Relay computes the same DH + HKDF.
    let source_eph_pub = x25519_public_from_bytes(&ts.circuit_handshake.ephemeral_x25519_public);
    let dh_secret = x25519_dh(&ts.relay_x25519_sk, &source_eph_pub);

    let mut info = Vec::new();
    info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
    info.extend_from_slice(&ts.relay_id);
    info.extend_from_slice(b"/");
    info.extend_from_slice(&ts.circuit_handshake.commitment_hash);
    let key_material = hkdf_sha256(&dh_secret, &ts.circuit_handshake.circuit_id, &info, 32).unwrap();
    let mut relay_key = [0u8; 32];
    relay_key.copy_from_slice(&key_material[..32]);

    assert_eq!(
        source_relay_key, relay_key,
        "source and relay must derive the same forwarding key"
    );
}

/// Replay is rejected by the relay's acceptance state.
#[test]
fn replay_rejected_by_acceptance_state() {
    let ts = setup();
    let transport = make_mock_transport(&ts);

    // First establishment succeeds.
    let result1 = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    );
    assert!(result1.is_ok(), "first establishment must succeed");

    // Second establishment with the SAME handshake must fail (replay).
    // The relays' acceptance stores already have this circuit_id.
    let result2 = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    );
    assert!(
        result2.is_err(),
        "replay must be rejected — relay acceptance stores already have this circuit_id"
    );
}

/// Relay-side accept_relay_handshake produces RelayForwardingState.
#[test]
fn relay_forwarding_state_installed() {
    let ts = setup();

    // Create a request for the relay.
    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        relay_node_id: ts.relay_id,
        predecessor_node_id: ts.source_id,
        successor_node_id: Some(ts.gateway_id),
        role: RouteRole::Relay,
    };

    let mut acceptance_store = CircuitAcceptanceStore::new();
    let (response, forwarding_state) = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    ).unwrap();

    // Response is valid.
    assert!(response.verify());
    assert_eq!(response.relay_node_id, ts.relay_id);

    // Forwarding state is correct.
    assert_eq!(forwarding_state.circuit_id, ts.circuit_handshake.circuit_id);
    assert_eq!(forwarding_state.predecessor_node_id, ts.source_id);
    assert_eq!(forwarding_state.successor_node_id, Some(ts.gateway_id));
    assert_eq!(forwarding_state.role, RouteRole::Relay);
    assert!(
        !forwarding_state.forwarding_key.iter().all(|&b| b == 0),
        "forwarding key must be non-zero"
    );

    // Acceptance store recorded the circuit.
    assert_eq!(acceptance_store.len(), 1);
    assert!(acceptance_store.is_replay(&ts.circuit_handshake));
}

/// ActiveCircuit ≠ CircuitSetup (architectural distinction).
#[test]
fn active_circuit_is_not_circuit_setup() {
    let ts = setup();
    let transport = make_mock_transport(&ts);

    let circuit = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    ).unwrap();

    // ActiveCircuit has relay_responses — CircuitSetup does not.
    assert!(!circuit.relay_responses().is_empty());

    // ActiveCircuit has established_at — CircuitSetup has created_at.
    assert!(circuit.established_at() > 0);

    // Both share the same circuit_id and commitment_hash.
    assert_eq!(circuit.circuit_id(), ts.circuit_setup.circuit_id());
    assert_eq!(circuit.commitment_hash(), ts.circuit_setup.commitment_hash());
}

/// Wrong role in relay response is rejected.
#[test]
fn wrong_role_in_response_rejected() {
    let ts = setup();

    // Create a transport where the relay returns a Gateway role instead of Relay.
    struct WrongRoleTransport {
        inner: MockTransport,
    }
    impl RelayHandshakeTransport for WrongRoleTransport {
        fn send_handshake(&self, request: &RelayHandshakeRequest) -> Option<RelayHandshakeResponse> {
            let response = self.inner.send_handshake(request)?;
            // Tamper with the role (but this breaks the signature, so verify_at will fail).
            Some(RelayHandshakeResponse {
                role: RouteRole::Gateway, // Wrong!
                ..response
            })
        }
    }

    let transport = WrongRoleTransport {
        inner: make_mock_transport(&ts),
    };

    let result = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    );

    // The tampered signature will fail verification → RelayResponseInvalid.
    assert!(result.is_err(), "tampered response must be rejected");
}

/// Gateway's DH proof also verifies correctly.
#[test]
fn gateway_dh_proof_verifies() {
    let ts = setup();
    let transport = make_mock_transport(&ts);

    let circuit = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &transport,
    ).unwrap();

    let gw_response = circuit.relay_response(&ts.gateway_id).unwrap();

    // Verify the gateway's DH proof.
    let gw_pub = x25519_public_from_bytes(&ts.gateway_x25519_pk);
    let dh_secret = x25519_dh(&ts.ephemeral_secret, &gw_pub);
    assert!(
        verify_dh_proof(gw_response, &dh_secret),
        "gateway's DH proof must verify"
    );
}
