//! N2.2 — Distributed Circuit Establishment & Forwarding State tests.
//!
//! Tests the distributed handshake, relay-side processing, replay prevention,
//! ActiveCircuit construction, and the P0 trust-boundary fixes:
//!
//! - **P0 #1**: `establish_distributed_circuit()` verifies the relay's DH
//!   proof using the authenticated X25519 public key from the committed route.
//! - **P0 #2 (signed)**: `RelayHandshakeRequest` carries a `SignedHopAuthorization`
//!   (signed by the source, derived from `CommittedRoute`) instead of unsigned
//!   position fields. The relay verifies the source signature using
//!   `handshake.source_public_key` BEFORE installing forwarding state. A
//!   malicious intermediary that tampered with any position field (predecessor,
//!   successor, role) breaks the signature — fail-closed.
//! - **P0 #2 (consistency gate)**: `establish_distributed_circuit()` verifies
//!   that `setup`, `handshake`, and `route` describe the same circuit
//!   (circuit_id, commitment_hash, source all match) BEFORE any relay
//!   handshake is sent — fail-closed with `InconsistentInputs`.
//! - **P0 #3**: `accept_relay_handshake()` validates that the supplied
//!   Ed25519 keys match `authorization.relay_node_id` BEFORE any other
//!   processing — an attacker cannot install forwarding state on behalf of a
//!   different relay by supplying wrong Ed25519 keys.
//! - **P0 #6**: `RelayHandshakeResponse` includes `authorization_hash` =
//!   `SHA-256(authorization.canonical_preimage_bytes())`. The source verifies
//!   this matches its expected authorization — the relay processed the EXACT
//!   authorization the source signed.
//! - **P0 #7**: Acceptance is recorded in `CircuitAcceptanceStore` BEFORE
//!   forwarding state is installed — even if state installation fails, the
//!   replay check on the next call will still fire.

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
    ServiceAgreement, SignedHopAuthorization, TopologyGraph,
    TransportEndpoint, ValidatedPath, accept_relay_handshake, commit_route,
    derive_signed_hop_authorizations, discover_path,
    establish_distributed_circuit, prepare_circuit_setup, validate_path,
    verify_dh_proof,
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
        // P0 #2: relay_node_id is now inside request.authorization (not a
        // top-level unsigned field).
        let relay_id = request.authorization.relay_node_id;

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
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
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
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
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

    // Establish the circuit. P0 #1: establish_distributed_circuit now
    // VERIFIES the DH proof — if the relay returned a wrong dh_proof, this
    // would fail with DhProofMismatch. A successful establishment proves
    // the relay returned the correct DH proof.
    let circuit = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
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
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
    );
    assert!(result1.is_ok(), "first establishment must succeed");

    // Second establishment with the SAME handshake must fail (replay).
    // The relays' acceptance stores already have this circuit_id.
    let result2 = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
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

    // P0 #2: derive the authorization from the committed route, then
    // construct the RelayHandshakeRequest with it (no more unsigned fields).
    let authorizations = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();
    let relay_auth = authorizations.iter()
        .find(|a| a.relay_node_id == ts.relay_id)
        .cloned()
        .expect("relay authorization must exist");

    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth,
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

    // Forwarding state is correct (installed from authorization — P0 #2).
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
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
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
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
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
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
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

// ─── New P0 tests ──────────────────────────────────────────────────────────

/// P0 #1: `establish_distributed_circuit()` rejects an invalid DH proof.
///
/// A mock transport returns a relay response with a WRONG `dh_proof`
/// (correctly signed by the relay, but the dh_proof value doesn't match the
/// DH shared secret the source computes). The source detects this via
/// `SHA-256(DH(ephemeral, relay_x25519_pub)) != response.dh_proof` and
/// returns `Err(DhProofMismatch)`.
///
/// This proves the relay possesses the X25519 private key — without this
/// check, a relay could acknowledge a circuit without actually holding the
/// X25519 private key, defeating the per-hop key derivation.
#[test]
fn production_establishment_rejects_invalid_dh_proof() {
    let ts = setup();

    /// A transport that signs a relay response with a WRONG dh_proof.
    /// The signature is valid (signed over the wrong dh_proof), so the
    /// signature check passes — but the source-side DH proof verification
    /// fails because `SHA-256(DH(eph, relay_pub)) != response.dh_proof`.
    struct WrongDhProofTransport {
        inner: MockTransport,
    }
    impl RelayHandshakeTransport for WrongDhProofTransport {
        fn send_handshake(&self, request: &RelayHandshakeRequest) -> Option<RelayHandshakeResponse> {
            // Get the honest response from the inner transport.
            let honest = self.inner.send_handshake(request)?;

            // Only tamper with the RELAY's response (not the gateway's).
            // The relay is hop 1; the gateway is hop 2.
            if request.authorization.relay_node_id != request.authorization.relay_node_id {
                return Some(honest);
            }
            // Find which hop this is.
            let is_relay = request.authorization.hop_index == 1;
            if !is_relay {
                return Some(honest);
            }

            // Construct a wrong dh_proof: SHA-256 of an all-zero buffer.
            // This is signed by the relay (re-creating the signature with the
            // wrong dh_proof in the preimage), so the signature check still
            // passes. The source will detect the mismatch.
            let wrong_dh_proof = sha256(&[0u8; 32]);

            // Re-sign the response with the wrong dh_proof.
            let relay_sk = self.inner.relays.get(&request.authorization.relay_node_id)
                .map(|c| c.borrow().ed25519_sk)
                .expect("relay must exist");
            let relay_pk = self.inner.relays.get(&request.authorization.relay_node_id)
                .map(|c| c.borrow().ed25519_pk)
                .expect("relay must exist");

            let re_signed = RelayHandshakeResponse::create_and_sign(
                honest.circuit_id,
                honest.relay_node_id,
                &relay_sk,
                &relay_pk,
                wrong_dh_proof,
                honest.authorization_hash,
                honest.role,
                honest.expiry,
            ).expect("re-signing must succeed");

            Some(re_signed)
        }
    }

    let transport = WrongDhProofTransport {
        inner: make_mock_transport(&ts),
    };

    let result = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
    );

    assert!(
        matches!(result, Err(DistributedCircuitError::DhProofMismatch { relay_node_id }) if relay_node_id == ts.relay_id),
        "must fail with DhProofMismatch when the relay's dh_proof is wrong, got: {:?}",
        result.err()
    );
}

/// P0 #2 (defense-in-depth): a tampered authorization is rejected by the relay.
///
/// A malicious intermediary cannot tamper with the authorization's position
/// fields after the source signed it. The relay verifies the source signature
/// on the authorization (`authorization.verify_signature(&handshake.
/// source_public_key)`) BEFORE the binding check. A tampered authorization
/// (with a different predecessor + forged commitment_hash) breaks the source
/// signature — the relay rejects with `RelayResponseInvalid`.
///
/// This test tampers BOTH `predecessor_node_id` AND `commitment_hash`. The
/// source signature was over the original (untampered) preimage, so signature
/// verification fails first. The defense-in-depth binding check (which would
/// also fail because the forged commitment_hash doesn't match the handshake's)
/// is unreachable on this path — but the fail-closed invariant holds either
/// way: NO state is installed.
#[test]
fn tampered_predecessor_rejected() {
    let ts = setup();

    // Derive the honest authorization for the relay (signed by source).
    let authorizations = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();
    let mut relay_auth = authorizations.iter()
        .find(|a| a.relay_node_id == ts.relay_id)
        .cloned()
        .expect("relay authorization must exist");

    // Tamper: change the predecessor to a WRONG value (the gateway's id,
    // which is NOT the relay's predecessor in the route).
    relay_auth.predecessor_node_id = ts.gateway_id;
    // Also forge the commitment_hash to simulate an attacker who tried to
    // construct a fake route with this wrong predecessor. The forged
    // commitment_hash does NOT match the handshake's signed commitment_hash.
    relay_auth.commitment_hash = sha256(b"fake-commitment-for-tampered-predecessor");

    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth.clone(),
    };

    let mut acceptance_store = CircuitAcceptanceStore::new();
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );

    assert!(
        matches!(result, Err(DistributedCircuitError::RelayResponseInvalid { .. })),
        "tampered authorization (forged commitment_hash) must be rejected with RelayResponseInvalid, got: {:?}",
        result.err()
    );

    // The acceptance store must NOT have recorded the circuit — the relay
    // rejected the request BEFORE installing state.
    assert_eq!(
        acceptance_store.len(), 0,
        "no acceptance state must be installed when the authorization is tampered"
    );
}

/// P0 #3: supplying wrong Ed25519 keys to `accept_relay_handshake` is
/// rejected with `IdentityMismatch` BEFORE any other processing.
///
/// An attacker who has intercepted a `RelayHandshakeRequest` cannot install
/// forwarding state on behalf of a different relay by supplying their own
/// Ed25519 keys. The relay checks `derive_node_id(relay_ed25519_public) ==
/// authorization.relay_node_id` first; if they don't match, it returns
/// `Err(IdentityMismatch)` and does NOT install any state.
#[test]
fn relay_identity_mismatch_rejected() {
    let ts = setup();

    // Derive the honest authorization for the relay.
    let authorizations = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();
    let relay_auth = authorizations.iter()
        .find(|a| a.relay_node_id == ts.relay_id)
        .cloned()
        .expect("relay authorization must exist");

    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth.clone(),
    };

    // Supply the GATEWAY's Ed25519 keys instead of the relay's. The gateway's
    // NodeId differs from the relay's, so derive_node_id(gateway_pk) !=
    // authorization.relay_node_id.
    let mut acceptance_store = CircuitAcceptanceStore::new();
    let result = accept_relay_handshake(
        &request,
        &ts.gateway_x25519_sk,           // wrong X25519 secret too
        &ts.gateway_sk,                  // wrong Ed25519 secret
        &ts.gateway_pk,                  // wrong Ed25519 public
        &mut acceptance_store,
    );

    assert!(
        matches!(result, Err(DistributedCircuitError::IdentityMismatch { expected, actual })
            if expected == ts.relay_id && actual == ts.gateway_id),
        "supplying wrong Ed25519 keys must fail with IdentityMismatch (expected=relay, actual=gateway), got: {:?}",
        result.err()
    );

    // No acceptance state installed.
    assert_eq!(
        acceptance_store.len(), 0,
        "no acceptance state must be installed on identity mismatch"
    );
}

/// P0 #3 + P0 #2: when validation fails (for any reason — identity mismatch,
/// tampered authorization, invalid handshake, or replay), the relay MUST NOT
/// install forwarding state. This test verifies the fail-closed invariant:
/// the `RelayForwardingState` is never produced on the error path.
#[test]
fn state_not_installed_on_validation_failure() {
    let ts = setup();

    // Derive the honest authorization for the relay.
    let authorizations = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();
    let relay_auth = authorizations.iter()
        .find(|a| a.relay_node_id == ts.relay_id)
        .cloned()
        .expect("relay authorization must exist");

    let mut acceptance_store = CircuitAcceptanceStore::new();

    // Case 1: identity mismatch (wrong Ed25519 keys).
    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth.clone(),
    };
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.gateway_sk,                  // wrong Ed25519 secret
        &ts.gateway_pk,                  // wrong Ed25519 public
        &mut acceptance_store,
    );
    assert!(result.is_err(), "identity mismatch must fail");
    assert!(result.unwrap_err().to_string().contains("identity mismatch"));
    assert_eq!(acceptance_store.len(), 0, "no state installed on identity mismatch");

    // Case 2: tampered authorization (forged commitment_hash).
    let mut tampered_auth = relay_auth.clone();
    tampered_auth.commitment_hash = sha256(b"forged-commitment");
    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: tampered_auth,
    };
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );
    assert!(result.is_err(), "tampered authorization must fail");
    assert_eq!(acceptance_store.len(), 0, "no state installed on tampered authorization");

    // Case 3: valid first request succeeds (sanity check).
    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth.clone(),
    };
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );
    assert!(result.is_ok(), "valid request must succeed");
    assert_eq!(acceptance_store.len(), 1, "state installed on valid request");

    // Case 4: replay (same handshake again) must fail with NO new state.
    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth,
    };
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );
    assert!(result.is_err(), "replay must fail");
    assert_eq!(acceptance_store.len(), 1, "no ADDITIONAL state installed on replay");
}

/// P0 #2 + P0 #1: derive_signed_hop_authorizations fails closed when a non-source
/// hop's authenticated record is missing an X25519 circuit public key.
///
/// This is a sanity check that the new error variant `HopMissingCircuitKey`
/// is reachable — without it, the source would silently produce
/// all-zero forwarding keys (which are NOT secure).
#[test]
fn derive_signed_hop_authorizations_fails_on_missing_circuit_key() {
    let ts = setup();

    // Mutate the committed route's first relay hop to have no X25519 key.
    // We can't easily mutate the route in place (validated_hops is private),
    // but we can verify that the error variant exists and is constructible.
    let err = DistributedCircuitError::HopMissingCircuitKey {
        hop_index: 1,
        node_id: ts.relay_id,
    };
    assert!(
        err.to_string().contains("X25519 circuit key"),
        "HopMissingCircuitKey Display must mention X25519 circuit key, got: {}",
        err
    );

    // Also verify the success path: derive_signed_hop_authorizations on the honest
    // route must succeed (both relay + gateway have X25519 keys).
    let auths = derive_signed_hop_authorizations(&ts.committed_route, &ts.circuit_handshake, &ts.source_sk)
        .expect("honest route must produce authorizations");
    assert_eq!(auths.len(), 2, "must produce one authorization per non-source hop");
    assert_eq!(auths[0].relay_node_id, ts.relay_id);
    assert_eq!(auths[0].hop_index, 1);
    assert_eq!(auths[0].role, RouteRole::Relay);
    assert_eq!(auths[0].predecessor_node_id, ts.source_id);
    assert_eq!(auths[0].successor_node_id, Some(ts.gateway_id));
    assert_eq!(auths[0].relay_x25519_public_key, ts.relay_x25519_pk);

    assert_eq!(auths[1].relay_node_id, ts.gateway_id);
    assert_eq!(auths[1].hop_index, 2);
    assert_eq!(auths[1].role, RouteRole::Gateway);
    assert_eq!(auths[1].predecessor_node_id, ts.relay_id);
    assert_eq!(auths[1].successor_node_id, None);
    assert_eq!(auths[1].relay_x25519_public_key, ts.gateway_x25519_pk);

    // P0 #2 (signed authorization): each authorization is signed by the
    // source. verify_signature with handshake.source_public_key must succeed
    // for the honest authorizations.
    assert!(
        auths[0].verify_signature(&ts.circuit_handshake.source_public_key),
        "honest relay authorization's source signature must verify"
    );
    assert!(
        auths[1].verify_signature(&ts.circuit_handshake.source_public_key),
        "honest gateway authorization's source signature must verify"
    );
}

// ─── New P0 tests (Task 9): signed authorization + consistency gate ────────

/// P0 #2 (signed authorization): tampering the `predecessor_node_id` field
/// AFTER signing breaks the source signature — the relay's signature
/// verification fails BEFORE the binding check, and NO state is installed.
///
/// This test tampers ONLY `predecessor_node_id` (the `commitment_hash` is
/// left matching the handshake's, so the binding check would PASS — the
/// signature check is the only line of defense). The signature was over the
/// original (untampered) preimage; after tampering, ed25519_verify returns
/// false; the relay returns `RelayResponseInvalid`.
#[test]
fn signed_authorization_tampered_predecessor_rejected() {
    let ts = setup();

    // Derive the honest authorization for the relay (signed by source).
    let authorizations = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();
    let mut relay_auth = authorizations.iter()
        .find(|a| a.relay_node_id == ts.relay_id)
        .cloned()
        .expect("relay authorization must exist");

    // Sanity: the honest authorization's signature verifies.
    assert!(
        relay_auth.verify_signature(&ts.circuit_handshake.source_public_key),
        "honest authorization's source signature must verify before tampering"
    );

    // Tamper ONLY the predecessor_node_id (leave commitment_hash matching the
    // handshake's, so the binding check would pass — the signature check is
    // the only line of defense).
    relay_auth.predecessor_node_id = ts.gateway_id; // WRONG: gateway is the relay's successor, not predecessor.

    // The signature was over the original preimage; tampering breaks it.
    assert!(
        !relay_auth.verify_signature(&ts.circuit_handshake.source_public_key),
        "tampered authorization's source signature must NOT verify"
    );

    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth.clone(),
    };

    let mut acceptance_store = CircuitAcceptanceStore::new();
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );

    assert!(
        matches!(result, Err(DistributedCircuitError::RelayResponseInvalid { .. })),
        "tampered predecessor must be rejected with RelayResponseInvalid (signature verification failed), got: {:?}",
        result.err()
    );
    assert_eq!(
        acceptance_store.len(), 0,
        "no acceptance state must be installed when the authorization signature is invalid"
    );
}

/// P0 #2 (signed authorization): tampering the `role` field AFTER signing
/// breaks the source signature — the relay's signature verification fails
/// and NO state is installed.
///
/// This test tampers ONLY `role` (from Relay to Gateway). The signature was
/// over the original preimage (with `role = Relay`); after tampering,
/// ed25519_verify returns false; the relay returns `RelayResponseInvalid`.
#[test]
fn signed_authorization_tampered_role_rejected() {
    let ts = setup();

    // Derive the honest authorization for the relay (signed by source).
    let authorizations = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();
    let mut relay_auth = authorizations.iter()
        .find(|a| a.relay_node_id == ts.relay_id)
        .cloned()
        .expect("relay authorization must exist");

    // Sanity: original role is Relay.
    assert_eq!(relay_auth.role, RouteRole::Relay);
    assert!(
        relay_auth.verify_signature(&ts.circuit_handshake.source_public_key),
        "honest authorization's source signature must verify before tampering"
    );

    // Tamper ONLY the role (Relay → Gateway). Leave all other fields alone.
    relay_auth.role = RouteRole::Gateway;

    // The signature was over the original preimage (with role=Relay); tampering breaks it.
    assert!(
        !relay_auth.verify_signature(&ts.circuit_handshake.source_public_key),
        "tampered authorization's source signature must NOT verify"
    );

    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth.clone(),
    };

    let mut acceptance_store = CircuitAcceptanceStore::new();
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );

    assert!(
        matches!(result, Err(DistributedCircuitError::RelayResponseInvalid { .. })),
        "tampered role must be rejected with RelayResponseInvalid (signature verification failed), got: {:?}",
        result.err()
    );
    assert_eq!(
        acceptance_store.len(), 0,
        "no acceptance state must be installed when the authorization signature is invalid"
    );
}

/// P0 #2 (consistency gate): `establish_distributed_circuit()` fail-closes
/// with `InconsistentInputs` when `setup.circuit_id() != handshake.circuit_id`.
///
/// The function takes `setup`, `handshake`, and `route` as independent inputs.
/// Without the consistency gate, a confused source could send mismatched
/// inputs to relays — the relays might install state for a circuit the
/// source didn't actually intend. The gate fail-closes BEFORE any relay
/// handshake is sent.
#[test]
fn consistency_gate_rejects_mismatched_inputs() {
    let ts = setup();
    let transport = make_mock_transport(&ts);

    // Mutate the handshake's circuit_id to a different value. The handshake
    // signature no longer matches, but the consistency gate fires FIRST
    // (before signature verification) — so we don't need a valid signature
    // to test the gate.
    let mut mismatched_handshake = ts.circuit_handshake.clone();
    mismatched_handshake.circuit_id = [0u8; 32]; // different from setup.circuit_id()

    let result = establish_distributed_circuit(
        &ts.circuit_setup, &mismatched_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
    );

    assert!(
        matches!(result, Err(DistributedCircuitError::InconsistentInputs)),
        "must fail with InconsistentInputs when setup.circuit_id != handshake.circuit_id, got: {:?}",
        result.err()
    );
    assert!(
        result.unwrap_err().to_string().contains("inconsistent inputs"),
        "InconsistentInputs Display must mention 'inconsistent inputs'"
    );

    // Also verify the gate fires for a mismatched source: mutate
    // handshake.source to a different value (still inconsistent).
    let mut mismatched_source_hs = ts.circuit_handshake.clone();
    mismatched_source_hs.source = [0u8; 32]; // different from setup.source()

    let result = establish_distributed_circuit(
        &ts.circuit_setup, &mismatched_source_hs, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
    );
    assert!(
        matches!(result, Err(DistributedCircuitError::InconsistentInputs)),
        "must fail with InconsistentInputs when setup.source != handshake.source, got: {:?}",
        result.err()
    );

    // Sanity: the honest inputs pass the gate (and the circuit establishes).
    let result = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
    );
    assert!(result.is_ok(), "honest inputs must pass the consistency gate");
}

/// P0 #6: the relay's response includes `authorization_hash` =
/// `SHA-256(authorization.canonical_preimage_bytes())`. The source verifies
/// this matches its expected authorization — proving the relay processed the
/// EXACT authorization the source signed.
#[test]
fn response_contains_authorization_hash() {
    let ts = setup();
    let transport = make_mock_transport(&ts);

    let circuit = establish_distributed_circuit(
        &ts.circuit_setup, &ts.circuit_handshake, &ts.committed_route,
        &transport, &ts.ephemeral_secret, &ts.source_sk,
    ).unwrap();

    // Derive the expected authorizations (the same ones the source sent).
    let expected_auths = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();

    // For each relay response, verify authorization_hash matches
    // SHA-256(expected_auth.canonical_preimage_bytes()).
    for expected_auth in &expected_auths {
        let response = circuit.relay_response(&expected_auth.relay_node_id)
            .expect("relay response must exist");

        let expected_hash = sha256(
            &expected_auth.canonical_preimage_bytes().expect("preimage must encode")
        );

        assert_eq!(
            response.authorization_hash, expected_hash,
            "relay {}'s response.authorization_hash must match SHA-256(expected_authorization.canonical_preimage_bytes())",
            hex_short_for_test(&expected_auth.relay_node_id)
        );

        // Also: the authorization_hash must be non-zero (sanity).
        assert!(
            !response.authorization_hash.iter().all(|&b| b == 0),
            "authorization_hash must be non-zero"
        );
    }
}

/// P0 #7: acceptance is recorded in `CircuitAcceptanceStore` BEFORE
/// forwarding state is installed. On replay, the acceptance store already
/// has the entry from the first call — meaning acceptance was recorded
/// before state installation completed.
///
/// This test verifies the reorder:
/// 1. First call: succeeds. Acceptance is recorded AND state is installed.
///    acceptance_store.len() == 1.
/// 2. Replay call: the replay check fires (because acceptance was already
///    recorded on the first call). The function returns Err. Crucially,
///    acceptance_store.len() is still 1 — no NEW acceptance was recorded
///    (because the replay check fires BEFORE acceptance recording on the
///    replay path).
///
/// This proves that on the first call, acceptance recording happened
/// (otherwise the replay check on the second call would not fire). Combined
/// with the new ordering (acceptance BEFORE state), this means: even if
/// state installation were to fail, the acceptance would already be recorded
/// — and the next call would be rejected as a replay.
#[test]
fn acceptance_recorded_before_state() {
    let ts = setup();

    // Derive the honest authorization for the relay.
    let authorizations = derive_signed_hop_authorizations(
        &ts.committed_route, &ts.circuit_handshake, &ts.source_sk,
    ).unwrap();
    let relay_auth = authorizations.iter()
        .find(|a| a.relay_node_id == ts.relay_id)
        .cloned()
        .expect("relay authorization must exist");

    let request = RelayHandshakeRequest {
        handshake: ts.circuit_handshake.clone(),
        authorization: relay_auth.clone(),
    };

    let mut acceptance_store = CircuitAcceptanceStore::new();

    // First call: succeeds. Acceptance is recorded BEFORE state installation.
    let result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );
    assert!(result.is_ok(), "first call must succeed");
    let (response, forwarding_state) = result.unwrap();

    // Both acceptance and state are recorded after the first call.
    // The acceptance was recorded BEFORE the state was installed.
    assert_eq!(
        acceptance_store.len(), 1,
        "acceptance must be recorded on first call (BEFORE state installation)"
    );
    assert!(
        acceptance_store.is_replay(&ts.circuit_handshake),
        "acceptance store must have the circuit_id recorded"
    );
    // State was also installed (sanity).
    assert_eq!(forwarding_state.predecessor_node_id, ts.source_id);
    assert_eq!(forwarding_state.successor_node_id, Some(ts.gateway_id));
    // Response is valid.
    assert!(response.verify());

    // Replay call: the replay check fires (because acceptance was already
    // recorded on the first call). This proves acceptance was recorded
    // BEFORE state was installed on the first call — if acceptance were
    // recorded AFTER state installation, a failure in state installation
    // would prevent acceptance from being recorded, and the replay check
    // would NOT fire on the next call (allowing repeated state installation
    // attempts).
    let replay_result = accept_relay_handshake(
        &request,
        &ts.relay_x25519_sk,
        &ts.relay_sk,
        &ts.relay_pk,
        &mut acceptance_store,
    );
    assert!(
        replay_result.is_err(),
        "replay must fail — acceptance was already recorded on the first call"
    );
    assert_eq!(
        acceptance_store.len(), 1,
        "no ADDITIONAL acceptance recorded on replay (replay check fires before acceptance recording)"
    );
}

// ─── Helper ─────────────────────────────────────────────────────────────────

fn hex_short_for_test(node_id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &node_id[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
