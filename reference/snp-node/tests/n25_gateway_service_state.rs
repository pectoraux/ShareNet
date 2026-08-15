//! N2.5-T5 — Gateway Service State Model Tests
//!
//! Tests for the separation of gateway service state from node identity.
//! GatewayPolicy (AUTHENTICATED), GatewayCapacityClaim (REPORTED),
//! GatewayMeasurement (OBSERVED), GatewayServiceState, GatewayServiceDirectory.

#![allow(clippy::pedantic)]

use snp_node::node::capability::ProtocolCapability;
use snp_node::node::evidence::EvidenceLevel;
use snp_node::node::gateway_service::*;

#[test]
fn test_gateway_policy_is_authenticated() {
    assert_eq!(GatewayPolicy::evidence_level(), EvidenceLevel::Authenticated);
    let policy = GatewayPolicy::wildcard();
    assert!(policy.allowed_destinations.is_empty());
    assert!(!policy.charging_only);
    assert!(!policy.wifi_only);
    eprintln!("[gw 1] PASS: GatewayPolicy is an AuthenticatedClaim");
}

#[test]
fn test_gateway_capacity_claim_is_reported() {
    assert_eq!(GatewayCapacityClaim::evidence_level(), EvidenceLevel::Reported);
    let claim = GatewayCapacityClaim::new(100, 1_000_000, Some(500_000_000), "24/7".to_string());
    assert!(claim.claims_remaining_quota());

    let exhausted = GatewayCapacityClaim::new(100, 1_000_000, Some(0), "24/7".to_string());
    assert!(!exhausted.claims_remaining_quota());

    let unlimited = GatewayCapacityClaim::new(100, 1_000_000, None, "24/7".to_string());
    assert!(unlimited.claims_remaining_quota());
    eprintln!("[gw 2] PASS: GatewayCapacityClaim is a ReportedMetric");
}

#[test]
fn test_gateway_measurement_is_observed() {
    assert_eq!(GatewayMeasurement::evidence_level(), EvidenceLevel::Observed);
    let mut measurement = GatewayMeasurement::new();
    assert_eq!(*measurement.completed_requests.inner(), 0);
    assert_eq!(*measurement.failed_requests.inner(), 0);
    assert!(measurement.observed_success_rate.inner().is_none());

    // Record some measurements.
    measurement.record_success(50, 1_000_000);
    assert_eq!(*measurement.completed_requests.inner(), 1);
    assert!(measurement.observed_success_rate.inner().is_some());
    assert!((measurement.observed_success_rate.inner().unwrap() - 1.0).abs() < 0.01);

    measurement.record_failure();
    assert_eq!(*measurement.failed_requests.inner(), 1);
    assert!((measurement.observed_success_rate.inner().unwrap() - 0.5).abs() < 0.01);
    eprintln!("[gw 3] PASS: GatewayMeasurement is an ObservedMetric with live recording");
}

#[test]
fn test_gateway_service_state_separates_identity_from_service() {
    let gateway_id = [0xAA; 32];
    let policy = GatewayPolicy::wildcard();
    let capacity = GatewayCapacityClaim::default();
    let state = GatewayServiceState::new(
        gateway_id,
        ProtocolCapability::InternetGateway,
        policy,
        capacity,
        1_700_000_000,
    );

    // The service state carries the gateway NodeId but does not carry
    // the gateway's public keys or endpoints — those stay in NodeAdvertisement.
    assert_eq!(state.gateway_node_id, gateway_id);
    assert_eq!(state.capability, ProtocolCapability::InternetGateway);
    eprintln!("[gw 4] PASS: GatewayServiceState separates identity from service state");
}

#[test]
fn test_gateway_service_state_evidence_summary() {
    let state = GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    );
    let summary = state.evidence_summary();
    assert_eq!(summary.policy_level, EvidenceLevel::Authenticated);
    assert_eq!(summary.capacity_level, EvidenceLevel::Reported);
    assert_eq!(summary.measurement_level, EvidenceLevel::Observed);
    eprintln!("[gw 5] PASS: evidence summary shows 3 distinct evidence levels");
}

#[test]
fn test_gateway_service_state_is_healthy_initially() {
    let state = GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    );
    // No measurements yet → can't say it's unhealthy.
    assert!(state.is_healthy());
    eprintln!("[gw 6] PASS: gateway is healthy when no failures observed");
}

#[test]
fn test_gateway_service_state_becomes_unhealthy() {
    let mut state = GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    );

    // Record 1 success + 3 failures = 25% success rate → unhealthy.
    state.record_success(50, 1_000_000, 1_700_000_100);
    state.record_failure(1_700_000_200);
    state.record_failure(1_700_000_300);
    state.record_failure(1_700_000_400);

    assert!(!state.is_healthy(), "gateway with <50% success rate must be unhealthy");
    eprintln!("[gw 7] PASS: gateway becomes unhealthy when success rate drops below 50%");
}

#[test]
fn test_gateway_service_directory_upsert_and_get() {
    let mut dir = GatewayServiceDirectory::new();
    assert!(dir.is_empty());

    let state = GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    );
    dir.upsert(state);

    assert_eq!(dir.len(), 1);
    assert!(dir.get(&[0xAA; 32]).is_some());
    assert!(dir.get(&[0xBB; 32]).is_none());
    eprintln!("[gw 8] PASS: GatewayServiceDirectory upsert + get works");
}

#[test]
fn test_gateway_service_directory_remove() {
    let mut dir = GatewayServiceDirectory::new();
    dir.upsert(GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    ));

    assert_eq!(dir.len(), 1);
    let removed = dir.remove(&[0xAA; 32]);
    assert!(removed.is_some());
    assert!(dir.is_empty());
    eprintln!("[gw 9] PASS: GatewayServiceDirectory remove works");
}

#[test]
fn test_gateway_service_directory_healthy_gateways() {
    let mut dir = GatewayServiceDirectory::new();

    // Healthy gateway.
    let mut healthy = GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    );
    healthy.record_success(50, 1_000_000, 1_700_000_100);
    dir.upsert(healthy);

    // Unhealthy gateway.
    let mut unhealthy = GatewayServiceState::new(
        [0xBB; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    );
    unhealthy.record_success(50, 1_000_000, 1_700_000_100);
    unhealthy.record_failure(1_700_000_200);
    unhealthy.record_failure(1_700_000_300);
    unhealthy.record_failure(1_700_000_400);
    dir.upsert(unhealthy);

    let healthy_ids = dir.healthy_gateways();
    assert_eq!(healthy_ids.len(), 1);
    assert!(healthy_ids.contains(&[0xAA; 32]));
    eprintln!("[gw 10] PASS: GatewayServiceDirectory.healthy_gateways() filters correctly");
}

#[test]
fn test_gateway_service_directory_get_mut_for_recording() {
    let mut dir = GatewayServiceDirectory::new();
    dir.upsert(GatewayServiceState::new(
        [0xAA; 32],
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::default(),
        1_700_000_000,
    ));

    // Record a measurement via mutable access.
    if let Some(state) = dir.get_mut(&[0xAA; 32]) {
        state.record_success(50, 1_000_000, 1_700_000_100);
    }

    let state = dir.get(&[0xAA; 32]).unwrap();
    assert_eq!(*state.measurement.completed_requests.inner(), 1);
    eprintln!("[gw 11] PASS: GatewayServiceDirectory get_mut allows live measurement recording");
}

#[test]
fn test_changing_quota_does_not_change_identity() {
    // The key property: changing remaining_quota, bandwidth, or queue_depth
    // does NOT require changing the node's cryptographic identity.
    let gateway_id = [0xAA; 32];

    // Initial state: 500MB quota.
    let state1 = GatewayServiceState::new(
        gateway_id,
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::new(100, 1_000_000, Some(500_000_000), "24/7".to_string()),
        1_700_000_000,
    );

    // Updated state: 100MB quota (remaining quota decreased).
    let state2 = GatewayServiceState::new(
        gateway_id,
        ProtocolCapability::InternetGateway,
        GatewayPolicy::wildcard(),
        GatewayCapacityClaim::new(100, 1_000_000, Some(100_000_000), "24/7".to_string()),
        1_700_000_100,
    );

    // The gateway NodeId is the same — identity didn't change.
    assert_eq!(state1.gateway_node_id, state2.gateway_node_id);
    // But the capacity claim changed.
    assert_ne!(state1.capacity.remaining_quota_bytes.inner(), state2.capacity.remaining_quota_bytes.inner());
    eprintln!("[gw 12] PASS: changing quota does NOT change node identity");
}
