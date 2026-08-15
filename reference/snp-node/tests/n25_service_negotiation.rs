//! N2.5-T4 — Service/Capability Negotiation Tests
//!
//! Tests for the full negotiation pipeline:
//! ServiceRequirement → CapabilityOffer → PolicyConstraint →
//! CapacityConstraint → NegotiatedServiceAgreement.
//!
//! A route cannot be committed merely because the destination advertises
//! `Gateway`. The route must establish that the requested service is
//! permitted and supported.

#![allow(clippy::pedantic)]

use snp_node::node::capability::ProtocolCapability;
use snp_node::node::service::*;

#[test]
fn test_internet_gateway_requirement_satisfied() {
    let req = ServiceRequirement::internet_gateway();
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::default();

    assert!(req.is_satisfied_by(&offer, &policy, &capacity),
        "internet-gateway requirement must be satisfied by matching offer + wildcard policy");
    eprintln!("[svc 1] PASS: internet-gateway requirement satisfied");
}

#[test]
fn test_requirement_not_satisfied_when_capability_missing() {
    let req = ServiceRequirement::internet_gateway();
    let offer = CapabilityOffer {
        capabilities: vec![ProtocolCapability::Storage], // wrong capability
        service_types: vec!["storage".to_string()],
    };
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::default();

    assert!(!req.is_satisfied_by(&offer, &policy, &capacity),
        "requirement must NOT be satisfied when the offer lacks the capability");
    eprintln!("[svc 2] PASS: requirement not satisfied when capability missing");
}

#[test]
fn test_requirement_not_satisfied_when_destination_blocked() {
    let req = ServiceRequirement {
        capability: ProtocolCapability::InternetGateway,
        required_destinations: vec!["blocked.example.com:443".to_string()],
        required_protocols: vec!["https".to_string()],
        min_bandwidth_bps: None,
        max_latency_ms: None,
    };
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint {
        allowed_destinations: vec!["*.allowed.com".to_string()],
        allowed_protocols: vec![],
        charging_only: false,
        wifi_only: false,
    };
    let capacity = CapacityConstraint::default();

    assert!(!req.is_satisfied_by(&offer, &policy, &capacity),
        "requirement must NOT be satisfied when destination is blocked by policy");
    eprintln!("[svc 3] PASS: requirement not satisfied when destination blocked");
}

#[test]
fn test_requirement_not_satisfied_when_protocol_blocked() {
    let req = ServiceRequirement {
        capability: ProtocolCapability::InternetGateway,
        required_destinations: vec![],
        required_protocols: vec!["tor".to_string()], // blocked protocol
        min_bandwidth_bps: None,
        max_latency_ms: None,
    };
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint {
        allowed_destinations: vec![],
        allowed_protocols: vec!["https".to_string(), "dns".to_string()],
        charging_only: false,
        wifi_only: false,
    };
    let capacity = CapacityConstraint::default();

    assert!(!req.is_satisfied_by(&offer, &policy, &capacity),
        "requirement must NOT be satisfied when protocol is blocked by policy");
    eprintln!("[svc 4] PASS: requirement not satisfied when protocol blocked");
}

#[test]
fn test_requirement_not_satisfied_when_bandwidth_insufficient() {
    let req = ServiceRequirement {
        capability: ProtocolCapability::InternetGateway,
        required_destinations: vec![],
        required_protocols: vec![],
        min_bandwidth_bps: Some(10_000_000), // 10 Mbps required
        max_latency_ms: None,
    };
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::new(100, Some(1_000_000), 0, None, None); // 1 Mbps offered

    assert!(!req.is_satisfied_by(&offer, &policy, &capacity),
        "requirement must NOT be satisfied when bandwidth is insufficient");
    eprintln!("[svc 5] PASS: requirement not satisfied when bandwidth insufficient");
}

#[test]
fn test_negotiation_succeeds() {
    let req = ServiceRequirement::internet_gateway();
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::default();

    let result = NegotiatedServiceAgreement::negotiate(req, offer, policy, capacity);
    assert!(result.is_some(), "negotiation must succeed for matching requirement + offer");

    let agreement = result.unwrap();
    assert_eq!(agreement.service_type(), "internet-transit");
    eprintln!("[svc 6] PASS: negotiation succeeds for matching requirement + offer");
}

#[test]
fn test_negotiation_fails() {
    let req = ServiceRequirement::internet_gateway();
    let offer = CapabilityOffer {
        capabilities: vec![ProtocolCapability::Storage],
        service_types: vec!["storage".to_string()],
    };
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::default();

    let result = NegotiatedServiceAgreement::negotiate(req, offer, policy, capacity);
    assert!(result.is_none(), "negotiation must fail for non-matching capability");
    eprintln!("[svc 7] PASS: negotiation fails for non-matching capability");
}

#[test]
fn test_negotiated_agreement_backward_compat() {
    let req = ServiceRequirement::internet_gateway();
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::default();

    let agreement = NegotiatedServiceAgreement::negotiate(req, offer, policy, capacity).unwrap();

    // The old ServiceAgreement had service_type + requirements.
    assert_eq!(agreement.service_type(), "internet-transit");
    let reqs = agreement.requirements();
    assert!(reqs.iter().any(|r| r.contains("destination")), "requirements must include destination");
    assert!(reqs.iter().any(|r| r.contains("protocol")), "requirements must include protocol");
    eprintln!("[svc 8] PASS: negotiated agreement has backward-compatible service_type + requirements");
}

#[test]
fn test_policy_destination_matching() {
    let policy = PolicyConstraint {
        allowed_destinations: vec!["*.example.com".to_string()],
        allowed_protocols: vec![],
        charging_only: false,
        wifi_only: false,
    };

    assert!(policy.destination_allowed("www.example.com"));
    assert!(policy.destination_allowed("api.example.com"));
    assert!(!policy.destination_allowed("evil.com"));
    eprintln!("[svc 9] PASS: policy destination glob matching works");
}

#[test]
fn test_policy_wildcard_allows_all() {
    let policy = PolicyConstraint::wildcard();

    assert!(policy.destination_allowed("anything.com"));
    assert!(policy.destination_allowed("evil.com:443"));
    assert!(policy.protocol_allowed("https"));
    assert!(policy.protocol_allowed("tor"));
    eprintln!("[svc 10] PASS: wildcard policy allows all destinations + protocols");
}

#[test]
fn test_capacity_constraint_is_reported() {
    let capacity = CapacityConstraint::default();
    // N2.5-T3: Capacity constraints are REPORTED metrics (untrusted gateway claims).
    assert_eq!(CapacityConstraint::evidence_level(), snp_node::node::evidence::EvidenceLevel::Reported);
    let _ = capacity;
    eprintln!("[svc 11] PASS: capacity constraint is a ReportedMetric (untrusted)");
}

#[test]
fn test_capacity_has_remaining_quota() {
    // Unlimited quota.
    let unlimited = CapacityConstraint::new(100, None, 0, None, None);
    assert!(unlimited.has_remaining_quota());

    // Some quota remaining.
    let has_quota = CapacityConstraint::new(100, None, 0, Some(500_000_000), None);
    assert!(has_quota.has_remaining_quota());

    // Zero quota (exhausted).
    let exhausted = CapacityConstraint::new(100, None, 0, Some(0), None);
    assert!(!exhausted.has_remaining_quota());
    eprintln!("[svc 12] PASS: capacity quota check works");
}

#[test]
fn test_negotiation_result_agreed() {
    let req = ServiceRequirement::internet_gateway();
    let offer = CapabilityOffer::internet_gateway();
    let policy = PolicyConstraint::wildcard();
    let capacity = CapacityConstraint::default();

    let agreement = NegotiatedServiceAgreement::negotiate(req, offer, policy, capacity).unwrap();
    let result = NegotiationResult::Agreed(agreement);
    assert!(result.is_agreed());
    assert!(result.agreement().is_some());
    eprintln!("[svc 13] PASS: NegotiationResult::Agreed works");
}

#[test]
fn test_negotiation_result_denied() {
    let result = NegotiationResult::Denied { reason: "capability mismatch".to_string() };
    assert!(!result.is_agreed());
    assert!(result.agreement().is_none());
    eprintln!("[svc 14] PASS: NegotiationResult::Denied works");
}
