//! **N2.4 — Network Intelligence Layer Integration Tests.**
//!
//! These tests verify the network intelligence layer end-to-end:
//!
//! - Gateway selection (3 gateways, pick best by weighted score)
//! - Failure learning (A with failures < B clean)
//! - Dynamic degradation (traffic starts → latency rises → score drops →
//!   selector chooses B)
//! - CircuitResult feedback loop
//! - CircuitMonitor state transitions
//! - GatewayFailover with cooldown

#![allow(clippy::pedantic)]

use snp_stack::network_intelligence::{
    BestScoreSelector, CircuitFailureReason, CircuitHealth, CircuitMonitor, CircuitResult,
    FailoverResult, GatewayFailover, GatewayScore, HealthThresholds, ObservationStore, PeerId,
    PeerObservation, ScoringWeights,
};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ════════════════════════════════════════════════════════════════════════════
// Test helpers
// ════════════════════════════════════════════════════════════════════════════

fn make_gateway(
    id: PeerId,
    latency_ms: f64,
    successes: u64,
    failures: u64,
    active_circuits: u32,
) -> PeerObservation {
    let mut obs = PeerObservation::new(id);
    if latency_ms > 0.0 {
        obs.record_latency(latency_ms);
    }
    obs.record_seen();
    for _ in 0..successes {
        obs.record_circuit_success();
    }
    for _ in 0..failures {
        obs.record_circuit_failure();
    }
    // record_circuit_success increments active_circuits, so adjust.
    let excess = obs.active_circuits.saturating_sub(active_circuits);
    for _ in 0..excess {
        obs.record_circuit_closed();
    }
    obs
}

fn make_store(observations: Vec<PeerObservation>) -> Arc<RwLock<ObservationStore>> {
    let mut store = ObservationStore::new();
    for obs in observations {
        store.upsert(obs);
    }
    Arc::new(RwLock::new(store))
}

// ════════════════════════════════════════════════════════════════════════════
// Test 1: Gateway selection (3 gateways, pick best)
// ════════════════════════════════════════════════════════════════════════════

/// **3 gateways, different profiles. The selector must pick B.**
///
/// ```text
/// Gateway A: latency 100ms, reliability 90%
/// Gateway B: latency 20ms,  reliability 95%
/// Gateway C: latency 10ms,  reliability 50%
/// Expected: B selected (fast + reliable)
/// ```
#[test]
fn test_gateway_selection_picks_best() {
    let a = make_gateway([1u8; 32], 100.0, 9, 1, 0); // 90% reliable
    let b = make_gateway([2u8; 32], 20.0, 19, 1, 0); // 95% reliable
    let c = make_gateway([3u8; 32], 10.0, 5, 5, 0); // 50% reliable

    let store = make_store(vec![a, b, c]);
    let selector = BestScoreSelector::new(store);

    let candidates = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let result = selector.select(&candidates);

    assert!(result.is_some(), "should select a gateway");
    let result = result.unwrap();
    assert_eq!(
        result.gateway_id, [2u8; 32],
        "B (20ms, 95% reliable) should be selected — got {:?} with score {:.2}",
        result.gateway_id, result.score.total
    );
    assert_eq!(result.candidates_considered, 3);

    eprintln!(
        "[n2.4-selection] PASS: Selected B (score {:.2}) over A and C",
        result.score.total
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2: Failure learning (A with failures < B clean)
// ════════════════════════════════════════════════════════════════════════════

/// **Gateway A accumulates failures, B stays clean. Score(A) < Score(B).**
#[test]
fn test_failure_learning() {
    let a = make_gateway([1u8; 32], 50.0, 10, 5, 0); // 66.7% reliable
    let b = make_gateway([2u8; 32], 50.0, 10, 0, 0); // 100% reliable

    let store = make_store(vec![a, b]);
    let selector = BestScoreSelector::new(store);

    let candidates = vec![[1u8; 32], [2u8; 32]];
    let result = selector.select(&candidates).unwrap();

    assert_eq!(
        result.gateway_id, [2u8; 32],
        "B (clean) should be selected over A (5 failures)"
    );

    eprintln!(
        "[n2.4-failure-learning] PASS: B selected over A (score B={:.2} > score A)",
        result.score.total
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3: Dynamic degradation
// ════════════════════════════════════════════════════════════════════════════

/// **Gateway A starts healthy. Traffic flows, latency increases. Score
/// drops. Selector switches to B.**
#[test]
fn test_dynamic_degradation() {
    let store = make_store(vec![]);
    let selector = BestScoreSelector::new(Arc::clone(&store));

    // Initial: A is faster.
    {
        let mut s = store.write().unwrap();
        s.record_latency(&[1u8; 32], 20.0);
        s.record_seen(&[1u8; 32]);
        s.record_latency(&[2u8; 32], 30.0);
        s.record_seen(&[2u8; 32]);
    }

    let candidates = vec![[1u8; 32], [2u8; 32]];

    // A should be selected (faster).
    let result = selector.select(&candidates).unwrap();
    assert_eq!(
        result.gateway_id, [1u8; 32],
        "A (20ms) should be selected initially"
    );

    // Simulate traffic: A's latency degrades to 300ms.
    {
        let mut s = store.write().unwrap();
        for _ in 0..10 {
            s.record_latency(&[1u8; 32], 300.0);
        }
    }

    // Now B should be selected (A degraded).
    let result = selector.select(&candidates).unwrap();
    assert_eq!(
        result.gateway_id, [2u8; 32],
        "B (30ms) should be selected after A degrades to 300ms"
    );

    eprintln!(
        "[n2.4-degradation] PASS: Selector switched from A to B after A's latency degraded"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4: CircuitResult feedback loop
// ════════════════════════════════════════════════════════════════════════════

/// **CircuitResult feeds back into observations.**
#[test]
fn test_circuit_result_feedback() {
    let mut store = ObservationStore::new();

    // Successful circuit with latency and bytes.
    let success = CircuitResult::success([1u8; 32])
        .with_latency(50.0)
        .with_bytes(1000, 2000)
        .with_relays(vec![[2u8; 32]]);
    success.apply_to(&mut store);

    let gw_obs = store.get(&[1u8; 32]).unwrap();
    assert_eq!(gw_obs.successful_circuits, 1);
    assert_eq!(gw_obs.bytes_forwarded, 3000);
    assert_eq!(gw_obs.latency(), Some(50.0));

    // Failed circuit.
    let failure = CircuitResult::failed([1u8; 32], CircuitFailureReason::Timeout);
    failure.apply_to(&mut store);

    let gw_obs = store.get(&[1u8; 32]).unwrap();
    assert_eq!(gw_obs.successful_circuits, 1);
    assert_eq!(gw_obs.failed_circuits, 1);
    assert!((gw_obs.reliability() - 0.5).abs() < 0.01);

    eprintln!("[n2.4-feedback] PASS: CircuitResult updates observations correctly");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 5: CircuitMonitor state transitions
// ════════════════════════════════════════════════════════════════════════════

/// **CircuitMonitor transitions: Healthy → Degraded → Failed → (reset) → Healthy**
#[test]
fn test_circuit_monitor_transitions() {
    let mut monitor = CircuitMonitor::with_defaults();

    // Start healthy.
    assert_eq!(monitor.health(), CircuitHealth::Healthy);

    // Normal traffic → stays healthy.
    monitor.record_sample(50.0, 0.0);
    assert_eq!(monitor.health(), CircuitHealth::Healthy);

    // Latency spikes → degraded.
    monitor.record_sample(250.0, 0.0);
    assert_eq!(monitor.health(), CircuitHealth::Degraded);

    // Recovery → healthy.
    monitor.record_data();
    assert_eq!(monitor.health(), CircuitHealth::Healthy);

    // Errors accumulate → degraded then failed.
    for _ in 0..3 {
        monitor.record_error();
    }
    assert_eq!(monitor.health(), CircuitHealth::Degraded);
    for _ in 0..2 {
        monitor.record_error();
    }
    assert_eq!(monitor.health(), CircuitHealth::Failed);

    // Reset → healthy.
    monitor.reset();
    assert_eq!(monitor.health(), CircuitHealth::Healthy);

    eprintln!("[n2.4-health] PASS: CircuitMonitor state transitions correct");
}

/// **CircuitMonitor idle timeout.**
#[test]
fn test_circuit_monitor_idle_timeout() {
    let thresholds = HealthThresholds {
        idle_timeout: Duration::from_millis(10),
        ..HealthThresholds::default()
    };
    let mut monitor = CircuitMonitor::new(thresholds);

    // Initially healthy.
    assert_eq!(monitor.health(), CircuitHealth::Healthy);

    // Wait past idle timeout.
    std::thread::sleep(Duration::from_millis(15));

    // Check → failed (idle too long).
    assert_eq!(monitor.check(), CircuitHealth::Failed);

    eprintln!("[n2.4-health-idle] PASS: Idle timeout triggers Failed");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 6: GatewayFailover with cooldown
// ════════════════════════════════════════════════════════════════════════════

/// **Gateway fails → failover to alternate. Failed gateway on cooldown.**
#[test]
fn test_gateway_failover() {
    let store = make_store(vec![
        make_gateway([1u8; 32], 50.0, 5, 0, 0),
        make_gateway([2u8; 32], 60.0, 5, 0, 0),
    ]);
    let selector = BestScoreSelector::new(Arc::clone(&store));
    let mut failover = GatewayFailover::with_defaults(selector);

    let candidates = vec![[1u8; 32], [2u8; 32]];

    // Gateway A fails → migrate to B.
    let result = failover.handle_failure([1u8; 32], &candidates);
    match result {
        FailoverResult::Migrated { to, .. } => {
            assert_eq!(to, [2u8; 32], "should migrate to B");
        }
        _ => panic!("expected Migrated, got {:?}", result),
    }

    // A is on cooldown.
    assert!(failover.is_on_cooldown(&[1u8; 32], Instant::now()));

    // Now B fails → no candidate (A is on cooldown).
    let result = failover.handle_failure([2u8; 32], &candidates);
    assert!(
        matches!(result, FailoverResult::NoCandidate { .. }),
        "should not go back to A (on cooldown), got {:?}",
        result
    );

    eprintln!("[n2.4-failover] PASS: Failover + cooldown working correctly");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 7: Custom scoring weights
// ════════════════════════════════════════════════════════════════════════════

/// **Custom weights change selection.**
#[test]
fn test_custom_weights_change_selection() {
    // Gateway A: 10ms, 70% reliable
    // Gateway B: 50ms, 100% reliable
    let a = make_gateway([1u8; 32], 10.0, 7, 3, 0);
    let b = make_gateway([2u8; 32], 50.0, 10, 0, 0);

    let candidates = vec![[1u8; 32], [2u8; 32]];

    // Latency-weighted: A should win (10ms vs 50ms).
    {
        let store = make_store(vec![a.clone(), b.clone()]);
        let selector = BestScoreSelector::with_weights(
            store,
            ScoringWeights::new(0.7, 0.1, 0.1, 0.1), // latency-heavy
        );
        let result = selector.select(&candidates).unwrap();
        assert_eq!(
            result.gateway_id, [1u8; 32],
            "with latency-heavy weights, A (10ms) should win"
        );
    }

    // Reliability-weighted: B should win (100% vs 70%).
    {
        let store = make_store(vec![a, b]);
        let selector = BestScoreSelector::with_weights(
            store,
            ScoringWeights::new(0.1, 0.7, 0.1, 0.1), // reliability-heavy
        );
        let result = selector.select(&candidates).unwrap();
        assert_eq!(
            result.gateway_id, [2u8; 32],
            "with reliability-heavy weights, B (100%) should win"
        );
    }

    eprintln!("[n2.4-weights] PASS: Custom weights change selection correctly");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 8: Full feedback loop (observe → score → select → fail → failover)
// ════════════════════════════════════════════════════════════════════════════

/// **End-to-end: observe gateways, score them, select one, simulate failure,
/// failover to the alternate.**
#[test]
fn test_end_to_end_feedback_loop() {
    let store = make_store(vec![]);
    let mut failover = {
        let selector = BestScoreSelector::new(Arc::clone(&store));
        GatewayFailover::with_defaults(selector)
    };

    let candidates = vec![[1u8; 32], [2u8; 32]];

    // Simulate 5 successful circuits through A.
    {
        let mut s = store.write().unwrap();
        for _ in 0..5 {
            let result = CircuitResult::success([1u8; 32])
                .with_latency(30.0)
                .with_bytes(1000, 1000);
            result.apply_to(&mut s);
        }
    }

    // A should be selected.
    let selector = BestScoreSelector::new(Arc::clone(&store));
    let result = selector.select(&candidates).unwrap();
    assert_eq!(result.gateway_id, [1u8; 32]);

    // A fails → failover to B.
    let failover_result = failover.handle_failure([1u8; 32], &candidates);
    assert!(
        matches!(&failover_result, FailoverResult::Migrated { to, .. } if *to == [2u8; 32]),
        "should failover to B, got {:?}",
        failover_result
    );

    // Record A's failure.
    store.write().unwrap().record_circuit_failure(&[1u8; 32]);

    // A's reliability dropped.
    let a_reliability = {
        let s = store.read().unwrap();
        s.get(&[1u8; 32]).unwrap().reliability()
    };
    assert!(a_reliability < 1.0);

    eprintln!("[n2.4-e2e] PASS: Full feedback loop working");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 9: Score display
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_score_display() {
    let obs = make_gateway([1u8; 32], 50.0, 10, 0, 0);
    let weights = ScoringWeights::default();
    let score = GatewayScore::from_observation(&obs, &weights, Instant::now());

    let display = format!("{score}");
    assert!(display.contains("latency:"));
    assert!(display.contains("reliability:"));
    assert!(display.contains("total:"));
}
