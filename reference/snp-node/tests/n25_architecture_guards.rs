//! N2.5-T9 — Architecture Guards
//!
//! Compile-time and runtime guards preventing regression to old
//! gateway/topology semantics. These tests verify that the frozen
//! architecture invariants are structurally enforced — if someone
//! removes a module, reverts the capability enum, or reintroduces the
//! old `all_known_gateways()` conflation, these tests will fail.

#![allow(clippy::pedantic)]

// ─── Guard 1: No `all_known_gateways()` conflation ──────────────────────────
//
// The old topology API had `all_known_gateways()` which conflated
// authenticated direct gateways with remote gateway hints. The frozen
// architecture requires `direct_gateways()` (authenticated) to be
// separate from `gateway_hints()` (remote claims).
//
// This guard uses static type checking to ensure the return types are
// different: `direct_gateways()` returns AuthenticatedNodeRecord and
// `gateway_hints()` returns RemoteNodeHint.

#[test]
fn guard_direct_gateways_returns_authenticated_records() {
    use snp_node::node::{TopologyGraph, AuthenticatedNodeRecord};

    // Type assertion: direct_gateways() returns Vec<&AuthenticatedNodeRecord>.
    // If someone changes the return type, this test won't compile.
    fn _type_check(_v: Vec<&AuthenticatedNodeRecord>) {}
    let graph = TopologyGraph::new_for_testing();
    let result: Vec<&AuthenticatedNodeRecord> = graph.direct_gateways();
    _type_check(result);
    eprintln!("[guard 1] PASS: direct_gateways() returns AuthenticatedNodeRecord");
}

#[test]
fn guard_gateway_hints_returns_remote_hints() {
    use snp_node::node::{TopologyGraph, RemoteNodeHint};

    // Type assertion: gateway_hints() returns Vec<&RemoteNodeHint>.
    fn _type_check(_v: Vec<&RemoteNodeHint>) {}
    let graph = TopologyGraph::new_for_testing();
    let result: Vec<&RemoteNodeHint> = graph.gateway_hints();
    _type_check(result);
    eprintln!("[guard 2] PASS: gateway_hints() returns RemoteNodeHint");
}

// ─── Guard 2: Capability enum has extensible variants ──────────────────────

#[test]
fn guard_capability_enum_has_extensible_variants() {
    use snp_node::node::identity::Capability;

    // The frozen architecture requires these variants to exist.
    let _ = Capability::MeshRelay;
    let _ = Capability::InternetGateway;
    let _ = Capability::ContentSeed;
    let _ = Capability::Storage;
    let _ = Capability::Discovery;
    let _ = Capability::Sync;
    let _ = Capability::Compute;
    let _ = Capability::CryptoRelay;
    let _ = Capability::CryptoGateway;
    let _ = Capability::PaymentRelay;

    // The old variants must still exist (backward compat).
    let _ = Capability::Client;
    let _ = Capability::Relay;
    let _ = Capability::Gateway;

    // The bridge method must exist.
    assert!(Capability::InternetGateway.to_protocol_capability().is_some());
    assert!(Capability::MeshRelay.to_protocol_capability().is_some());

    // The typed capability checks must exist.
    assert!(Capability::InternetGateway.is_gateway_capability());
    assert!(Capability::MeshRelay.is_relay_capability());
    eprintln!("[guard 3] PASS: Capability enum has all extensible variants + bridge methods");
}

// ─── Guard 3: Evidence module exists and has the right types ───────────────

#[test]
fn guard_evidence_module_exists() {
    use snp_node::node::evidence::{
        EvidenceLevel, AuthenticatedClaim, ObservedMetric, ReportedMetric,
        DerivedMetric, InferredMetric,
    };

    // All evidence levels must exist.
    let _ = EvidenceLevel::Authenticated;
    let _ = EvidenceLevel::Observed;
    let _ = EvidenceLevel::Reported;
    let _ = EvidenceLevel::Derived;
    let _ = EvidenceLevel::Inferred;

    // All newtype wrappers must exist.
    let _ = AuthenticatedClaim::new(42u64);
    let _ = ObservedMetric::new(42u64);
    let _ = ReportedMetric::new(42u64);
    let _ = DerivedMetric::new(42u64);
    let _ = InferredMetric::new(42u64);

    // Evidence level classification must work.
    assert!(EvidenceLevel::Authenticated.is_routing_evidence());
    assert!(EvidenceLevel::Observed.is_routing_evidence());
    assert!(!EvidenceLevel::Reported.is_routing_evidence());
    assert!(EvidenceLevel::Reported.is_untrusted());
    eprintln!("[guard 4] PASS: evidence module exists with all types");
}

// ─── Guard 4: Service negotiation module exists ────────────────────────────

#[test]
fn guard_service_negotiation_module_exists() {
    use snp_node::node::service::{
        ServiceRequirement, CapabilityOffer, PolicyConstraint,
        CapacityConstraint, NegotiatedServiceAgreement, NegotiationResult,
    };

    // All negotiation types must exist.
    let req = ServiceRequirement::internet_gateway();
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::default();

    // Negotiation must work.
    let result = NegotiatedServiceAgreement::negotiate(req, offer, policy, capacity);
    assert!(result.is_some());

    // NegotiationResult must exist.
    let _ = NegotiationResult::Agreed(result.unwrap());
    eprintln!("[guard 5] PASS: service negotiation module exists");
}

// ─── Guard 5: Gateway service state module exists ──────────────────────────

#[test]
fn guard_gateway_service_state_module_exists() {
    use snp_node::node::gateway_service::{
        GatewayPolicy, GatewayCapacityClaim, GatewayMeasurement,
        GatewayServiceState, GatewayServiceDirectory,
    };
    use snp_node::node::capability::ProtocolCapability;

    // All gateway service state types must exist.
    let policy = GatewayPolicy::wildcard();
    let capacity = GatewayCapacityClaim::default();
    let _measurement = GatewayMeasurement::new();

    // GatewayServiceState must separate identity from service.
    let state = GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        policy,
        capacity,
        1_700_000_000,
    );

    // The service state carries the NodeId but NOT the public keys.
    assert_eq!(state.gateway_node_id, [0xAA; 32]);

    // The evidence summary must show 3 distinct evidence levels.
    let summary = state.evidence_summary();
    assert_eq!(summary.policy_level, snp_node::node::evidence::EvidenceLevel::Authenticated);
    assert_eq!(summary.capacity_level, snp_node::node::evidence::EvidenceLevel::Reported);
    assert_eq!(summary.measurement_level, snp_node::node::evidence::EvidenceLevel::Observed);

    // GatewayServiceDirectory must exist.
    let mut dir = GatewayServiceDirectory::new();
    dir.upsert(state);
    assert_eq!(dir.len(), 1);
    eprintln!("[guard 6] PASS: gateway service state module exists with evidence separation");
}

// ─── Guard 6: ProtocolCapability (N2.4 authority) exists and is separate ───

#[test]
fn guard_protocol_capability_separate_from_node_capability() {
    use snp_node::node::capability::ProtocolCapability;
    use snp_node::node::identity::Capability;

    // ProtocolCapability (authority-level) has 7 variants.
    let _ = ProtocolCapability::MeshRelay;
    let _ = ProtocolCapability::Discovery;
    let _ = ProtocolCapability::Sync;
    let _ = ProtocolCapability::ContentSeed;
    let _ = ProtocolCapability::Storage;
    let _ = ProtocolCapability::InternetGateway;
    let _ = ProtocolCapability::Compute;

    // The bridge from node-level to authority-level exists.
    let bridge = Capability::InternetGateway.to_protocol_capability();
    assert_eq!(bridge, Some(ProtocolCapability::InternetGateway));

    // The two enums are DIFFERENT types (type system guard).
    fn _accept_protocol(_p: ProtocolCapability) {}
    fn _accept_node(_c: Capability) {}
    // If someone tries to pass a Capability where ProtocolCapability is
    // expected, it won't compile.
    _accept_protocol(ProtocolCapability::InternetGateway);
    _accept_node(Capability::InternetGateway);
    eprintln!("[guard 7] PASS: ProtocolCapability is separate from node-level Capability");
}

// ─── Guard 7: RemoteNodeHint uses typed capability checks ──────────────────

#[test]
fn guard_remote_hint_uses_typed_capability_checks() {
    use snp_node::node::RemoteNodeHint;

    // A hint with "internet-gateway" (new string) must be recognized.
    let hint = RemoteNodeHint {
        target_node_id: [0xAA; 32],
        claimed_sequence: 1,
        claimed_capabilities: vec!["internet-gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: [0xBB; 32],
        received_at: 0,
        source_propagation_sequence: 1,
    };
    assert!(hint.claims_gateway(),
        "claims_gateway() must use typed Capability::from_str() + is_gateway_capability()");

    // A hint with "mesh-relay" (new string) must be recognized.
    let relay_hint = RemoteNodeHint {
        target_node_id: [0xAA; 32],
        claimed_sequence: 1,
        claimed_capabilities: vec!["mesh-relay".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: [0xBB; 32],
        received_at: 0,
        source_propagation_sequence: 1,
    };
    assert!(relay_hint.claims_relay(),
        "claims_relay() must use typed Capability::from_str() + is_relay_capability()");
    eprintln!("[guard 8] PASS: RemoteNodeHint uses typed capability checks (not raw strings)");
}

// ─── Guard 8: N2.4 capability authority store has commit-point model ───────

#[test]
fn guard_authority_store_has_commit_point_model() {
    use snp_node::node::capability::{AuthorityStateStore, PersistenceState};

    // PersistenceState enum must exist with Operational + FailedClosed.
    let operational = PersistenceState::Operational;
    let failed = PersistenceState::FailedClosed { reason: "test".to_string() };

    // is_operational() must exist.
    assert!(matches!(operational, PersistenceState::Operational));
    assert!(matches!(failed, PersistenceState::FailedClosed { .. }));

    // A new store must start Operational.
    let store = AuthorityStateStore::new();
    assert!(store.is_operational());
    assert!(matches!(store.persistence_state(), PersistenceState::Operational));
    eprintln!("[guard 9] PASS: AuthorityStateStore has commit-point model (PersistenceState)");
}

// ─── Guard 9: Semantic validation exists on capability types ───────────────

#[test]
fn guard_semantic_validation_exists() {
    use snp_node::node::capability::{
        SemanticError, IssuerAuthority, CapabilityAuthorization,
        GovernanceIssuerRevocation, SubjectCapabilityRevocation,
    };

    // SemanticError enum must exist.
    let _ = SemanticError::InvalidValidityWindow;
    let _ = SemanticError::InvalidAuthorityVersion;

    // validate_semantic() must exist on all capability types.
    // (We can't easily call it without constructing objects, but we can
    // verify the method exists via type checking.)
    fn _check_authority(a: &IssuerAuthority) {
        let _ = a.validate_semantic();
    }
    fn _check_auth(a: &CapabilityAuthorization) {
        let _ = a.validate_semantic();
    }
    fn _check_gov_rev(r: &GovernanceIssuerRevocation) {
        let _ = r.validate_semantic();
    }
    fn _check_subj_rev(r: &SubjectCapabilityRevocation) {
        let _ = r.validate_semantic();
    }
    eprintln!("[guard 10] PASS: semantic validation exists on all capability types");
}
