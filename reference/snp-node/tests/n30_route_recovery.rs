//! N3.0 — Route Recovery Tests
//!
//! Tests proving an active client can survive "Gateway A disappears" by
//! establishing "Gateway B" for subsequent traffic.
//!
//! ## Recovery pipeline tested
//!
//! ```text
//! Gateway A disappears (link down / repeated failures)
//!     ↓
//! RouteFailureDetector detects failure
//!     ↓
//! RouteRecoveryManager.attempt_recovery()
//!     ↓
//! Replacement gateway selected from alternatives
//!     ↓
//! New circuit can be established via Gateway B
//! ```

#![allow(clippy::pedantic)]

use snp_node::node::route_recovery::*;
use snp_node::node::evidence::EvidenceLevel;

fn now() -> u64 {
    1_700_000_000
}

fn gw_id(label: u8) -> [u8; 32] {
    [label; 32]
}

// ─── 1. Failure detection: repeated failures ─────────────────────────────────

#[test]
fn n30_detect_failure_repeated_failures() {
    let mut detector = RouteFailureDetector::new(gw_id(1)).with_threshold(3);

    // 2 failures — not yet failed.
    detector.record_failure();
    detector.record_failure();
    assert!(!detector.is_failed(), "2 failures < threshold 3 → not failed");

    // 3rd failure — now failed.
    detector.record_failure();
    assert!(detector.is_failed(), "3 failures >= threshold → failed");
    assert!(matches!(
        detector.failure_reason(),
        Some(FailureReason::RepeatedFailures { count: 3, threshold: 3 })
    ));
    eprintln!("[n30-1] PASS: repeated failures detected (3/3 → failed)");
}

// ─── 2. Failure detection: link down ─────────────────────────────────────────

#[test]
fn n30_detect_failure_link_down() {
    let mut detector = RouteFailureDetector::new(gw_id(1));

    // Link goes down — immediate failure.
    detector.record_link_down();
    assert!(detector.is_failed(), "link down → immediate failure");
    assert_eq!(detector.failure_reason(), Some(FailureReason::LinkDown));
    eprintln!("[n30-2] PASS: link down detected (immediate failure)");
}

// ─── 3. Failure detection: advertisement expired ─────────────────────────────

#[test]
fn n30_detect_failure_advertisement_expired() {
    let mut detector = RouteFailureDetector::new(gw_id(1));

    detector.record_advertisement_expired();
    assert!(detector.is_failed(), "expired advertisement → failure");
    assert_eq!(detector.failure_reason(), Some(FailureReason::AdvertisementExpired));
    eprintln!("[n30-3] PASS: advertisement expiry detected");
}

// ─── 4. Success resets failure count ─────────────────────────────────────────

#[test]
fn n30_success_resets_failure_count() {
    let mut detector = RouteFailureDetector::new(gw_id(1)).with_threshold(3);

    detector.record_failure();
    detector.record_failure();
    // Success resets the count.
    detector.record_success();
    detector.record_failure();
    assert!(!detector.is_failed(), "success resets count → 1 failure after reset");
    eprintln!("[n30-4] PASS: success resets failure count");
}

// ─── 5. Route recovery: find replacement gateway ─────────────────────────────

#[test]
fn n30_recovery_finds_replacement() {
    let mut manager = RouteRecoveryManager::for_gateway(gw_id(1));

    // Register alternatives.
    manager.register_alternative(gw_id(2));
    manager.register_alternative(gw_id(3));

    // Gateway 1 fails.
    manager.record_link_down();
    assert!(manager.is_failed());

    // Attempt recovery.
    let result = manager.attempt_recovery();
    assert!(result.is_some(), "recovery must succeed with alternatives available");

    let recovery = result.unwrap();
    assert_eq!(recovery.failed_gateway, gw_id(1));
    assert_eq!(recovery.replacement_gateway, gw_id(2)); // first alternative
    assert_eq!(recovery.failure_reason, FailureReason::LinkDown);
    eprintln!("[n30-5] PASS: recovery finds replacement gateway");
}

// ─── 6. Route recovery: no alternatives → no recovery ───────────────────────

#[test]
fn n30_recovery_no_alternatives_fails() {
    let mut manager = RouteRecoveryManager::for_gateway(gw_id(1));
    // No alternatives registered.

    manager.record_link_down();
    assert!(manager.is_failed());

    let result = manager.attempt_recovery();
    assert!(result.is_none(), "recovery must fail with no alternatives");
    eprintln!("[n30-6] PASS: no alternatives → recovery fails");
}

// ─── 7. Route recovery: no failure → no recovery needed ──────────────────────

#[test]
fn n30_recovery_no_failure_no_recovery() {
    let mut manager = RouteRecoveryManager::for_gateway(gw_id(1));
    manager.register_alternative(gw_id(2));

    // No failure — recovery not needed.
    let result = manager.attempt_recovery();
    assert!(result.is_none(), "no failure → no recovery needed");
    eprintln!("[n30-7] PASS: no failure → no recovery needed");
}

// ─── 8. Full survival scenario: Gateway A disappears → Gateway B ─────────────

#[test]
fn n30_full_survival_scenario() {
    // Setup: client has a route through Gateway A, with Gateway B as backup.
    let mut manager = RouteRecoveryManager::for_gateway(gw_id(0xAA)); // Gateway A
    manager.register_alternative(gw_id(0xBB)); // Gateway B (backup)

    // Client is active — some requests succeed.
    manager.record_success();
    manager.record_success();
    assert!(!manager.is_failed(), "active route should not be failed");

    // Gateway A disappears — link goes down.
    manager.record_link_down();
    assert!(manager.is_failed(), "route must be failed after link down");

    // Attempt recovery.
    let recovery = manager.attempt_recovery()
        .expect("recovery must succeed with Gateway B available");

    assert_eq!(recovery.failed_gateway, gw_id(0xAA));
    assert_eq!(recovery.replacement_gateway, gw_id(0xBB));
    assert!(manager.is_recovered());
    assert_eq!(manager.replacement_gateway(), Some(gw_id(0xBB)));

    // The client can now establish a new circuit via Gateway B.
    eprintln!("[n30-8] PASS: full survival — Gateway A (0xAA) → Gateway B (0xBB)");
}

// ─── 9. Evidence level ───────────────────────────────────────────────────────

#[test]
fn n30_evidence_level_is_observed() {
    assert_eq!(RouteFailureDetector::evidence_level(), EvidenceLevel::Observed);
    eprintln!("[n30-9] PASS: failure detection is an ObservedMetric");
}

// ─── 10. Recovery result display ─────────────────────────────────────────────

#[test]
fn n30_recovery_result_display() {
    let result = RecoveryResult {
        failed_gateway: gw_id(0xAA),
        replacement_gateway: gw_id(0xBB),
        failure_reason: FailureReason::LinkDown,
        recovered_at: now(),
    };
    let s = format!("{result}");
    assert!(s.contains("failed="));
    assert!(s.contains("replacement="));
    assert!(s.contains("link to gateway is down"));
    eprintln!("[n30-10] PASS: RecoveryResult Display works");
}

// ─── 11. Threshold customization ─────────────────────────────────────────────

#[test]
fn n30_threshold_customization() {
    let mut detector = RouteFailureDetector::new(gw_id(1)).with_threshold(5);

    // 4 failures — not yet failed (threshold is 5).
    for _ in 0..4 {
        detector.record_failure();
    }
    assert!(!detector.is_failed(), "4 failures < threshold 5 → not failed");

    // 5th failure — now failed.
    detector.record_failure();
    assert!(detector.is_failed(), "5 failures >= threshold 5 → failed");
    eprintln!("[n30-11] PASS: threshold customization works (5 failures → failed)");
}

// ─── 12. Recovery with multiple alternatives ─────────────────────────────────

#[test]
fn n30_recovery_with_multiple_alternatives() {
    let mut manager = RouteRecoveryManager::for_gateway(gw_id(1));
    manager.register_alternative(gw_id(2));
    manager.register_alternative(gw_id(3));
    manager.register_alternative(gw_id(4));

    // Gateway 1 fails.
    manager.record_link_down();

    // Recovery picks the first alternative (Gateway 2).
    let recovery = manager.attempt_recovery().unwrap();
    assert_eq!(recovery.replacement_gateway, gw_id(2));
    eprintln!("[n30-12] PASS: recovery with multiple alternatives picks first available");
}
