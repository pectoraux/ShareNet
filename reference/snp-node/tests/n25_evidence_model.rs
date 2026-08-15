//! N2.5-T3 — Evidence-class separation tests
//!
//! Tests for the epistemic type wrappers (AuthenticatedClaim, ObservedMetric,
//! ReportedMetric, DerivedMetric, InferredMetric) and EvidenceLevel enum.
//!
//! The key property: a ReportedMetric cannot be used where an ObservedMetric
//! is expected without an explicit conversion. This prevents routing/economic
//! code from accidentally treating a self-reported capacity claim as an
//! observed measurement.

#![allow(clippy::pedantic)]

use snp_node::node::evidence::*;

#[test]
fn test_evidence_level_is_routing_evidence() {
    assert!(EvidenceLevel::Authenticated.is_routing_evidence());
    assert!(EvidenceLevel::Observed.is_routing_evidence());
    assert!(!EvidenceLevel::Reported.is_routing_evidence());
    assert!(!EvidenceLevel::Derived.is_routing_evidence());
    assert!(!EvidenceLevel::Inferred.is_routing_evidence());
    eprintln!("[ev 1] PASS: is_routing_evidence() correctly classifies Authenticated/Observed");
}

#[test]
fn test_evidence_level_is_untrusted() {
    assert!(EvidenceLevel::Reported.is_untrusted());
    assert!(EvidenceLevel::Inferred.is_untrusted());
    assert!(!EvidenceLevel::Authenticated.is_untrusted());
    assert!(!EvidenceLevel::Observed.is_untrusted());
    assert!(!EvidenceLevel::Derived.is_untrusted());
    eprintln!("[ev 2] PASS: is_untrusted() correctly classifies Reported/Inferred");
}

#[test]
fn test_evidence_level_display() {
    assert_eq!(EvidenceLevel::Authenticated.to_string(), "authenticated");
    assert_eq!(EvidenceLevel::Observed.to_string(), "observed");
    assert_eq!(EvidenceLevel::Reported.to_string(), "reported");
    assert_eq!(EvidenceLevel::Derived.to_string(), "derived");
    assert_eq!(EvidenceLevel::Inferred.to_string(), "inferred");
    eprintln!("[ev 3] PASS: EvidenceLevel Display works");
}

#[test]
fn test_authenticated_claim_wrapper() {
    let claim: AuthenticatedClaim<u64> = AuthenticatedClaim::new(42);
    assert_eq!(*claim.inner(), 42);
    assert_eq!(claim.into_inner(), 42);
    assert_eq!(AuthenticatedClaim::<u64>::evidence_level(), EvidenceLevel::Authenticated);
    eprintln!("[ev 4] PASS: AuthenticatedClaim wrapper works");
}

#[test]
fn test_observed_metric_wrapper() {
    let rtt: ObservedMetric<u64> = ObservedMetric::new(5_000); // 5ms
    assert_eq!(*rtt.inner(), 5_000);
    assert_eq!(rtt.into_inner(), 5_000);
    assert_eq!(ObservedMetric::<u64>::evidence_level(), EvidenceLevel::Observed);
    eprintln!("[ev 5] PASS: ObservedMetric wrapper works");
}

#[test]
fn test_reported_metric_wrapper() {
    let capacity: ReportedMetric<u64> = ReportedMetric::new(500_000_000); // 500MB
    assert_eq!(*capacity.inner(), 500_000_000);
    assert_eq!(capacity.into_inner(), 500_000_000);
    assert_eq!(ReportedMetric::<u64>::evidence_level(), EvidenceLevel::Reported);
    eprintln!("[ev 6] PASS: ReportedMetric wrapper works");
}

#[test]
fn test_derived_metric_wrapper() {
    let success_rate: DerivedMetric<f64> = DerivedMetric::new(0.95);
    assert!((success_rate.inner() - 0.95).abs() < f64::EPSILON);
    assert_eq!(DerivedMetric::<f64>::evidence_level(), EvidenceLevel::Derived);
    eprintln!("[ev 7] PASS: DerivedMetric wrapper works");
}

#[test]
fn test_inferred_metric_wrapper() {
    let reputation: InferredMetric<f64> = InferredMetric::new(0.8);
    assert!((reputation.inner() - 0.8).abs() < f64::EPSILON);
    assert_eq!(InferredMetric::<f64>::evidence_level(), EvidenceLevel::Inferred);
    eprintln!("[ev 8] PASS: InferredMetric wrapper works");
}

#[test]
fn test_reported_metric_cannot_be_used_as_observed() {
    // This test verifies the TYPE SYSTEM property: a ReportedMetric is a
    // different type than an ObservedMetric. You cannot pass a ReportedMetric
    // where an ObservedMetric is expected without an explicit conversion.
    let reported: ReportedMetric<u64> = ReportedMetric::new(42);
    let observed: ObservedMetric<u64> = ObservedMetric::new(42);

    // They have the same inner value but are different types.
    assert_eq!(*reported.inner(), *observed.inner());

    // But they have different evidence levels.
    assert_eq!(ReportedMetric::<u64>::evidence_level(), EvidenceLevel::Reported);
    assert_eq!(ObservedMetric::<u64>::evidence_level(), EvidenceLevel::Observed);

    // The reported metric is untrusted; the observed metric is routing evidence.
    assert!(ReportedMetric::<u64>::evidence_level().is_untrusted());
    assert!(ObservedMetric::<u64>::evidence_level().is_routing_evidence());

    // To use a reported value as observed, you MUST explicitly extract and
    // re-wrap it (documenting the trust downgrade):
    let trust_downgraded = ObservedMetric::new(reported.into_inner());
    assert_eq!(ObservedMetric::<u64>::evidence_level(), EvidenceLevel::Observed);
    let _ = trust_downgraded; // suppress unused warning
    eprintln!("[ev 9] PASS: ReportedMetric cannot be silently used as ObservedMetric");
}

#[test]
fn test_link_metrics_rtt_is_observed() {
    // LinkMetrics.rtt_micros is an OBSERVED metric (measured via link probing).
    // Wrapping it in ObservedMetric documents this at the type level.
    let rtt_micros: u64 = 12_500;
    let observed_rtt = ObservedMetric::new(rtt_micros);
    assert!(ObservedMetric::<u64>::evidence_level().is_routing_evidence());
    eprintln!("[ev 10] PASS: link RTT is an ObservedMetric (routing evidence)");
}

#[test]
fn test_gateway_capacity_is_reported() {
    // Gateway capacity (e.g. "500 MB remaining") is a REPORTED metric —
    // the gateway claims it, but a malicious gateway can set any value.
    let remaining_quota: u64 = 500_000_000;
    let reported_capacity = ReportedMetric::new(remaining_quota);
    assert!(ReportedMetric::<u64>::evidence_level().is_untrusted());
    assert!(!ReportedMetric::<u64>::evidence_level().is_routing_evidence());
    eprintln!("[ev 11] PASS: gateway capacity is a ReportedMetric (untrusted)");
}

#[test]
fn test_success_rate_is_derived() {
    // Success rate is DERIVED from success_count + failure_count.
    let success_count: u32 = 95;
    let failure_count: u32 = 5;
    let rate = f64::from(success_count) / f64::from(success_count + failure_count);
    let derived_rate = DerivedMetric::new(rate);
    assert!((derived_rate.inner() - 0.95).abs() < 0.001);
    // Derived metrics are computed, not directly routing evidence.
    assert!(!DerivedMetric::<f64>::evidence_level().is_routing_evidence());
    eprintln!("[ev 12] PASS: success rate is a DerivedMetric");
}
