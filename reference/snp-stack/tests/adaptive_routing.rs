//! **N2.5 — Adaptive Routing Layer Integration Tests.**
//!
//! These tests verify the adaptive routing layer end-to-end:
//!
//! - Route selection (3 routes, pick best by weighted score)
//! - Dynamic degradation (latency rises → optimizer switches)
//! - Relay failure (relay dies → failover to backup)
//! - Diversity (primary/backup/emergency are independent)
//! - Hysteresis (no flapping)
//! - Failure attribution (HopFailure updates route + peer observations)

#![allow(clippy::pedantic)]

use snp_stack::network_intelligence::{
    AdaptiveRouteOptimizer, CircuitFailureReason, CircuitOutcome, CircuitResult,
    ObservationStore, OptimizationResult, OptimizerConfig, PeerId, RouteCandidate,
    RouteObservationStore, RouteScoringWeights, classify_routes, compute_diversity_score,
};
use std::sync::{Arc, RwLock};
use std::time::Duration;

// ════════════════════════════════════════════════════════════════════════════
// Test helpers
// ════════════════════════════════════════════════════════════════════════════

fn make_route(hops: &[PeerId]) -> Vec<PeerId> {
    hops.to_vec()
}

// ════════════════════════════════════════════════════════════════════════════
// Test 1: Route selection (3 routes, pick best)
// ════════════════════════════════════════════════════════════════════════════

/// **3 routes, different profiles. The optimizer must pick A-D-E-G.**
///
/// ```text
/// Route 1: A-B-C-G, latency 50ms, loss 1%
/// Route 2: A-D-E-G, latency 20ms, loss 0.1%
/// Route 3: A-F-G,   latency 10ms, loss 20%
/// Expected: select A-D-E-G (fast + reliable)
/// ```
#[test]
fn test_route_selection_picks_best() {
    let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));
    let optimizer = AdaptiveRouteOptimizer::with_defaults(Arc::clone(&route_store));

    let route1 = make_route(&[[1u8; 32], [2u8; 32], [3u8; 32], [10u8; 32]]); // A-B-C-G
    let route2 = make_route(&[[1u8; 32], [4u8; 32], [5u8; 32], [10u8; 32]]); // A-D-E-G
    let route3 = make_route(&[[1u8; 32], [6u8; 32], [10u8; 32]]); // A-F-G

    {
        let mut s = route_store.write().unwrap();
        // Route 1: 50ms, 1% loss, reliable
        s.get_or_create(&route1).record_latency(50.0);
        s.get_or_create(&route1).record_packet_loss(0.01);
        for _ in 0..10 {
            s.get_or_create(&route1).record_success();
        }
        // Route 2: 20ms, 0.1% loss, reliable
        s.get_or_create(&route2).record_latency(20.0);
        s.get_or_create(&route2).record_packet_loss(0.001);
        for _ in 0..10 {
            s.get_or_create(&route2).record_success();
        }
        // Route 3: 10ms, 20% loss, unreliable
        s.get_or_create(&route3).record_latency(10.0);
        s.get_or_create(&route3).record_packet_loss(0.20);
        for _ in 0..4 {
            s.get_or_create(&route3).record_success();
        }
        for _ in 0..1 {
            s.get_or_create(&route3).record_failure();
        }
    }

    let candidates = vec![route1.clone(), route2.clone(), route3.clone()];
    let result = optimizer.check(&candidates);

    match result {
        OptimizationResult::Migrate(d) => {
            assert_eq!(
                d.target_route(),
                route2.as_slice(),
                "Route 2 (A-D-E-G, 20ms, 0.1% loss) should be selected"
            );
        }
        _ => panic!("expected Migrate, got {:?}", result),
    }

    eprintln!("[n2.5-selection] PASS: Selected A-D-E-G (best balanced route)");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2: Dynamic degradation
// ════════════════════════════════════════════════════════════════════════════

/// **Route A-B-C-G starts healthy. B's latency degrades to 300ms. Optimizer
/// switches to A-D-E-G.**
#[test]
fn test_dynamic_degradation() {
    let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));

    let route1 = make_route(&[[1u8; 32], [2u8; 32], [3u8; 32], [10u8; 32]]); // A-B-C-G
    let route2 = make_route(&[[1u8; 32], [4u8; 32], [5u8; 32], [10u8; 32]]); // A-D-E-G

    // Initial: route1 is selected (faster: 20ms vs 60ms, both reliable).
    {
        let mut s = route_store.write().unwrap();
        s.get_or_create(&route1).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&route1).record_success(); }
        s.get_or_create(&route2).record_latency(60.0);
        for _ in 0..10 { s.get_or_create(&route2).record_success(); }
    }

    let candidates = vec![route1.clone(), route2.clone()];

    // Use an optimizer with low threshold so route1 is picked initially.
    let mut optimizer = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_store),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 5.0,
            cooldown: Duration::from_millis(10),
            min_attempts_for_confidence: 10,
        },
    );

    // N2.5-R: set_current_route was removed. Establish route1 as the current
    // route via cold-start check() + commit_migration(decision).
    {
        let initial = optimizer.check(&candidates);
        match initial {
            OptimizationResult::Migrate(d) => {
                assert_eq!(
                    d.target_route(),
                    route1.as_slice(),
                    "cold-start should pick route1 (the faster one)"
                );
                optimizer.commit_migration(d).unwrap();
            }
            _ => panic!("expected cold-start Migrate, got {:?}", initial),
        }
    }

    // Simulate degradation: route1 latency rises to 500ms + multiple failures.
    {
        let mut s = route_store.write().unwrap();
        for _ in 0..20 {
            s.get_or_create(&route1).record_latency(500.0);
        }
        for _ in 0..5 {
            s.get_or_create(&route1).record_failure();
        }
    }

    std::thread::sleep(Duration::from_millis(20));

    let result = optimizer.check(&candidates);
    match result {
        OptimizationResult::Migrate(d) => {
            assert_eq!(
                d.source_route(),
                route1.as_slice(),
                "should migrate from degraded route1"
            );
            assert_eq!(
                d.target_route(),
                route2.as_slice(),
                "should migrate to route2"
            );
        }
        _ => panic!("expected Migrate after degradation, got {:?}", result),
    }

    eprintln!("[n2.5-degradation] PASS: Switched from A-B-C-G to A-D-E-G after degradation");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3: Relay failure → failover
// ════════════════════════════════════════════════════════════════════════════

/// **Active route A-B-C-G. Relay B fails. Route observation records failure.
/// Optimizer migrates to A-D-E-G.**
#[test]
fn test_relay_failure_triggers_migration() {
    let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut peer_store = ObservationStore::new();

    let route1 = make_route(&[[1u8; 32], [2u8; 32], [3u8; 32], [10u8; 32]]); // A-B-C-G
    let route2 = make_route(&[[1u8; 32], [4u8; 32], [5u8; 32], [10u8; 32]]); // A-D-E-G

    // Both routes start healthy. Both need ≥10 samples for full confidence.
    {
        let mut s = route_store.write().unwrap();
        s.get_or_create(&route1).record_latency(50.0);
        for _ in 0..10 { s.get_or_create(&route1).record_success(); }
        s.get_or_create(&route2).record_latency(55.0);
        for _ in 0..10 { s.get_or_create(&route2).record_success(); }
    }

    let mut optimizer = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_store),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 5.0, // lower threshold for test
            cooldown: Duration::from_millis(10),
            min_attempts_for_confidence: 10,
        },
    );

    // N2.5-R: set_current_route was removed. Establish route1 as the current
    // route via cold-start check() + commit_migration(decision). Route1 is
    // slightly better at cold-start (50ms vs 55ms, both reliable).
    {
        let initial = optimizer.check(&[route1.clone(), route2.clone()]);
        match initial {
            OptimizationResult::Migrate(d) => {
                assert_eq!(
                    d.target_route(),
                    route1.as_slice(),
                    "cold-start should pick route1 (slightly lower latency)"
                );
                optimizer.commit_migration(d).unwrap();
            }
            _ => panic!("expected cold-start Migrate, got {:?}", initial),
        }
    }

    // Simulate relay B ([2;32]) failure via CircuitResult with HopFailure.
    // Record multiple failures to make route1 clearly worse than route2
    // (10 successes + 5 failures = 67% reliability vs 100%).
    for _ in 0..5 {
        let failure = CircuitResult::failed(
            [10u8; 32], // gateway
            CircuitFailureReason::HopFailure {
                peer_id: [2u8; 32], // relay B
                position: 1,
                reason: Box::new(CircuitFailureReason::Timeout),
            },
        )
        .with_relays(vec![[2u8; 32], [3u8; 32]]);
        failure.apply_to_route_store(&mut route_store.write().unwrap(), &route1, Some(&mut peer_store));
    }

    std::thread::sleep(Duration::from_millis(20));

    let candidates = vec![route1.clone(), route2.clone()];
    let result = optimizer.check(&candidates);

    match result {
        OptimizationResult::Migrate(d) => {
            assert_eq!(d.source_route(), route1.as_slice());
            assert_eq!(
                d.target_route(),
                route2.as_slice(),
                "should migrate to route2 after relay B failure"
            );
        }
        _ => panic!("expected Migrate after relay failure, got {:?}", result),
    }

    // Verify the peer store recorded relay B's failure.
    let b_reliability = peer_store.get(&[2u8; 32]).map(|o| o.reliability()).unwrap_or(1.0);
    assert!(
        b_reliability < 1.0,
        "relay B reliability should be < 1.0 after HopFailure, got {}",
        b_reliability
    );

    eprintln!(
        "[n2.5-relay-failure] PASS: Migrated to A-D-E-G after relay B failed (B reliability={:.2})",
        b_reliability
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4: Diversity — primary/backup/emergency are independent
// ════════════════════════════════════════════════════════════════════════════

/// **5 candidate routes. Verify primary/backup/emergency are independent
/// (no shared relay hops).**
#[test]
fn test_diversity_classification() {
    let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));
    let optimizer = AdaptiveRouteOptimizer::with_defaults(Arc::clone(&route_store));

    // 5 routes, all with different relays.
    let routes = vec![
        make_route(&[[1u8; 32], [2u8; 32], [3u8; 32], [10u8; 32]]),
        make_route(&[[1u8; 32], [4u8; 32], [5u8; 32], [10u8; 32]]),
        make_route(&[[1u8; 32], [6u8; 32], [7u8; 32], [10u8; 32]]),
        make_route(&[[1u8; 32], [8u8; 32], [9u8; 32], [10u8; 32]]),
        make_route(&[[1u8; 32], [11u8; 32], [12u8; 32], [10u8; 32]]),
    ];

    {
        let mut s = route_store.write().unwrap();
        for (i, route) in routes.iter().enumerate() {
            s.get_or_create(route).record_latency(50.0 + i as f64 * 10.0);
            s.get_or_create(route).record_success();
        }
    }

    let diversity = optimizer.classify(&routes);

    assert!(diversity.is_complete(), "all 3 tiers should be filled");
    assert_eq!(diversity.tier_count(), 3);

    // Verify independence: primary and backup share no relays.
    let primary = diversity.primary.as_ref().unwrap();
    let backup = diversity.backup.as_ref().unwrap();
    let emergency = diversity.emergency.as_ref().unwrap();

    assert!(
        snp_stack::network_intelligence::are_independent(&primary.hops, &backup.hops),
        "primary and backup must be independent"
    );
    assert!(
        snp_stack::network_intelligence::are_independent(&primary.hops, &emergency.hops),
        "primary and emergency must be independent"
    );
    assert!(
        snp_stack::network_intelligence::are_independent(&backup.hops, &emergency.hops),
        "backup and emergency must be independent"
    );

    eprintln!(
        "[n2.5-diversity] PASS: 3 independent tiers (primary={}, backup={}, emergency={})",
        diversity.primary.as_ref().unwrap().score,
        diversity.backup.as_ref().unwrap().score,
        diversity.emergency.as_ref().unwrap().score
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Test 5: Hysteresis — no flapping
// ════════════════════════════════════════════════════════════════════════════

/// **Two routes with very similar scores. Optimizer should NOT migrate
/// (improvement < threshold).**
#[test]
fn test_hysteresis_prevents_flapping() {
    let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut optimizer = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_store),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 15.0,
            cooldown: Duration::from_millis(10),
            min_attempts_for_confidence: 10,
        },
    );

    let route1 = make_route(&[[1u8; 32], [2u8; 32], [10u8; 32]]);
    let route2 = make_route(&[[1u8; 32], [4u8; 32], [10u8; 32]]);

    // Both routes nearly identical.
    {
        let mut s = route_store.write().unwrap();
        s.get_or_create(&route1).record_latency(50.0);
        s.get_or_create(&route1).record_success();
        s.get_or_create(&route2).record_latency(48.0); // slightly better
        s.get_or_create(&route2).record_success();
    }

    // N2.5-R: set_current_route was removed. Establish the initial route
    // via cold-start check() + commit_migration(decision). Cold-start picks
    // the best route (route2, slightly lower latency).
    let initial = optimizer.check(&[route1.clone(), route2.clone()]);
    if let OptimizationResult::Migrate(d) = initial {
        optimizer.commit_migration(d).unwrap();
    }

    // Wait for cooldown to pass before checking for migration.
    std::thread::sleep(Duration::from_millis(20));

    let candidates = vec![route1.clone(), route2.clone()];
    let result = optimizer.check(&candidates);

    assert!(
        matches!(result, OptimizationResult::NoMigration { .. }),
        "should NOT migrate — scores are too similar (< 15% threshold), got {:?}",
        result
    );

    eprintln!("[n2.5-hysteresis] PASS: No migration for marginal improvement");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 6: Failure attribution — HopFailure updates both route and peer
// ════════════════════════════════════════════════════════════════════════════

/// **A HopFailure at position 1 (relay B) updates the route's failure count
/// AND relay B's peer observation.**
#[test]
fn test_failure_attribution() {
    let mut route_store = RouteObservationStore::new();
    let mut peer_store = ObservationStore::new();

    let route = make_route(&[[1u8; 32], [2u8; 32], [3u8; 32], [10u8; 32]]); // A-B-C-G

    // Record some successes first.
    route_store.record_success(&route);
    route_store.record_success(&route);

    // Now a HopFailure at relay B ([2;32]).
    let failure = CircuitResult::failed(
        [10u8; 32],
        CircuitFailureReason::HopFailure {
            peer_id: [2u8; 32],
            position: 1,
            reason: Box::new(CircuitFailureReason::Timeout),
        },
    )
    .with_relays(vec![[2u8; 32], [3u8; 32]]);

    failure.apply_to_route_store(&mut route_store, &route, Some(&mut peer_store));

    // Route should have 2 successes + 1 failure.
    use snp_stack::network_intelligence::route_id_from_hops;
    let route_id = route_id_from_hops(&route);
    let route_obs = route_store.get(&route_id).unwrap();
    assert_eq!(route_obs.successful_circuits, 2);
    assert_eq!(route_obs.failed_circuits, 1);

    // Relay B should have a failure recorded.
    let b_obs = peer_store.get(&[2u8; 32]).unwrap();
    assert_eq!(b_obs.failed_circuits, 1);

    // Relay C should NOT have a failure (it wasn't blamed).
    let c_obs = peer_store.get(&[3u8; 32]);
    assert!(c_obs.is_none() || c_obs.unwrap().failed_circuits == 0);

    eprintln!(
        "[n2.5-attribution] PASS: HopFailure attributed to relay B (route: {}/{} success/fail, B: {} failures)",
        route_obs.successful_circuits, route_obs.failed_circuits, b_obs.failed_circuits
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Test 7: Custom weights change selection
// ════════════════════════════════════════════════════════════════════════════

/// **With latency-heavy weights, the fastest route wins. With reliability-heavy
/// weights, the most reliable route wins.**
#[test]
fn test_custom_weights_change_route_selection() {
    // Route 1: 10ms, 70% reliable
    // Route 2: 50ms, 100% reliable
    let route1 = make_route(&[[1u8; 32], [2u8; 32], [10u8; 32]]);
    let route2 = make_route(&[[1u8; 32], [4u8; 32], [10u8; 32]]);

    let candidates = vec![route1.clone(), route2.clone()];

    // Latency-weighted: route1 should win.
    {
        let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));
        {
            let mut s = route_store.write().unwrap();
            s.get_or_create(&route1).record_latency(10.0);
            for _ in 0..7 { s.get_or_create(&route1).record_success(); }
            for _ in 0..3 { s.get_or_create(&route1).record_failure(); }
            s.get_or_create(&route2).record_latency(50.0);
            for _ in 0..10 { s.get_or_create(&route2).record_success(); }
        }

        let opt = AdaptiveRouteOptimizer::new(
            route_store,
            RouteScoringWeights::new(0.1, 0.7, 0.1, 0.1), // latency-heavy
            OptimizerConfig {
                min_improvement_pct: 1.0,
                cooldown: Duration::from_millis(1),
                min_attempts_for_confidence: 10,
            },
        );

        let result = opt.check(&candidates);
        assert!(
            matches!(result, OptimizationResult::Migrate(d) if d.target_route() == route1.as_slice()),
            "latency-heavy weights should select route1"
        );
    }

    // Reliability-weighted: route2 should win.
    {
        let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));
        {
            let mut s = route_store.write().unwrap();
            s.get_or_create(&route1).record_latency(10.0);
            for _ in 0..7 { s.get_or_create(&route1).record_success(); }
            for _ in 0..3 { s.get_or_create(&route1).record_failure(); }
            s.get_or_create(&route2).record_latency(50.0);
            for _ in 0..10 { s.get_or_create(&route2).record_success(); }
        }

        let opt = AdaptiveRouteOptimizer::new(
            route_store,
            RouteScoringWeights::new(0.7, 0.1, 0.1, 0.1), // reliability-heavy
            OptimizerConfig {
                min_improvement_pct: 1.0,
                cooldown: Duration::from_millis(1),
                min_attempts_for_confidence: 10,
            },
        );

        let result = opt.check(&candidates);
        assert!(
            matches!(result, OptimizationResult::Migrate(d) if d.target_route() == route2.as_slice()),
            "reliability-heavy weights should select route2"
        );
    }

    eprintln!("[n2.5-weights] PASS: Custom weights change route selection");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 8: Cooldown blocks rapid migration
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_cooldown_blocks_rapid_migration() {
    let route_store = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut optimizer = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_store),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 5.0,
            cooldown: Duration::from_secs(60), // long cooldown
            min_attempts_for_confidence: 10,
        },
    );

    let route1 = make_route(&[[1u8; 32], [2u8; 32], [10u8; 32]]);
    let route2 = make_route(&[[1u8; 32], [4u8; 32], [10u8; 32]]);

    {
        let mut s = route_store.write().unwrap();
        s.get_or_create(&route1).record_latency(500.0);
        s.get_or_create(&route2).record_latency(10.0);
    }

    // N2.5-R: set_current_route was removed. Cold-start check() recommends the
    // best route (route2). The caller must commit the migration — check() does
    // NOT mutate optimizer state.
    let result = optimizer.check(&[route1.clone(), route2.clone()]);
    assert!(
        matches!(result, OptimizationResult::Migrate(_)),
        "cold-start should recommend migration"
    );
    if let OptimizationResult::Migrate(d) = result {
        optimizer.commit_migration(d).unwrap();
    }

    // Now try to migrate again immediately — should be on cooldown.
    // Make route1 look better than route2 to trigger migration desire.
    {
        let mut s = route_store.write().unwrap();
        s.get_or_create(&route1).record_latency(5.0);
        s.get_or_create(&route2).record_latency(1000.0);
    }

    let result = optimizer.check(&[route1.clone(), route2.clone()]);
    assert!(
        matches!(result, OptimizationResult::Cooldown { .. }),
        "should be on cooldown, got {:?}",
        result
    );

    eprintln!("[n2.5-cooldown] PASS: Cooldown blocks rapid migration");
}
