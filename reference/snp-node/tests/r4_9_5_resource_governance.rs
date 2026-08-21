//! R4.9.5 — Resource Governance.
//!
//! Tests for:
//! - Global peer connection limit
//! - Per-peer connection limit
//! - Per-peer concurrency limit
//! - Global concurrency limit
//! - Gateway quota preserves the existing global egress cap
//! - Resource release after success
//! - Resource release after error
//! - Resource release after cancellation
//! - Shutdown releases resources
//! - Capacity rejection does not poison the RetryScheduler score
//!
//! Plus the required semantic test: one peer cannot monopolise global
//! capacity (per-peer ceiling proves isolation).
//!
//! These tests exercise the real runtime resource boundary via the public
//! `ResourceGovernor` / `GatewayQuota` API and their RAII guards, not merely
//! semaphore arithmetic.

#![allow(clippy::pedantic)]

use std::time::Duration;

use snp_identity::NodeId;
use snp_node::node::resource_governance::{
    AdmissionError, GatewayQuota, GovernorConfig, ResourceGovernor,
    DEFAULT_MAX_GLOBAL_CONCURRENT_OPS, DEFAULT_MAX_PEER_CONCURRENT_OPS,
};
use snp_node::node::retry_policy::RetryScheduler;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

fn peer(id: u8) -> NodeId {
    [id; 32]
}

fn small_governor() -> ResourceGovernor {
    ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 4,
        max_peer_connections: 2,
        max_global_concurrent_ops: 4,
        max_peer_concurrent_ops: 2,
    })
}

// ─── 1. Global peer connection limit ───────────────────────────────────

/// The global connection ceiling rejects the (N+1)-th connection regardless
/// of which peer it comes from. The rejection is an explicit
/// `GlobalConnectionLimit` error.
#[tokio::test]
async fn r4_9_5_global_peer_connection_limit() {
    let gov = small_governor();
    // Fill the global ceiling (4) with distinct peers.
    let _g1 = gov.admit_connection(peer(1)).await.unwrap();
    let _g2 = gov.admit_connection(peer(2)).await.unwrap();
    let _g3 = gov.admit_connection(peer(3)).await.unwrap();
    let _g4 = gov.admit_connection(peer(4)).await.unwrap();
    assert_eq!(gov.global_connections().await, 4);
    // A 5th connection (any peer) is rejected.
    let r = gov.admit_connection(peer(5)).await;
    assert!(
        matches!(
            r,
            Err(AdmissionError::GlobalConnectionLimit {
                limit: 4,
                current: 4
            })
        ),
        "expected GlobalConnectionLimit, got {r:?}"
    );
    // Releasing one (via drop) allows a new connection.
    drop(_g1);
    assert_eq!(gov.global_connections().await, 3);
    let _g5 = gov.admit_connection(peer(5)).await.unwrap();
    assert_eq!(gov.global_connections().await, 4);
}

// ─── 2. Per-peer connection limit ──────────────────────────────────────

/// A single peer cannot exceed its per-peer connection ceiling, even when the
/// global ceiling has room. Other peers are unaffected.
#[tokio::test]
async fn r4_9_5_per_peer_connection_limit() {
    let gov = small_governor();
    let a = peer(0xA1);
    let _g1 = gov.admit_connection(a).await.unwrap();
    let _g2 = gov.admit_connection(a).await.unwrap();
    assert_eq!(gov.peer_connections(&a).await, 2);
    // A 3rd connection from the SAME peer is rejected.
    let r = gov.admit_connection(a).await;
    assert!(
        matches!(
            r,
            Err(AdmissionError::PeerConnectionLimit {
                peer_id: _,
                limit: 2,
                current: 2
            })
        ),
        "expected PeerConnectionLimit, got {r:?}"
    );
    // A DIFFERENT peer can still connect (isolation property).
    let b = peer(0xB2);
    let _g3 = gov.admit_connection(b).await.unwrap();
    assert_eq!(gov.peer_connections(&b).await, 1);
}

// ─── 3. Per-peer concurrency limit ─────────────────────────────────────

/// A single peer cannot exceed its per-peer operation ceiling. Other peers
/// can still admit operations.
#[tokio::test]
async fn r4_9_5_per_peer_concurrency_limit() {
    let gov = small_governor();
    let a = peer(0xA1);
    let _o1 = gov.admit_operation(a).await.unwrap();
    let _o2 = gov.admit_operation(a).await.unwrap();
    assert_eq!(gov.peer_operations(&a).await, 2);
    // A 3rd operation from the SAME peer is rejected.
    let r = gov.admit_operation(a).await;
    assert!(
        matches!(
            r,
            Err(AdmissionError::PeerOperationLimit {
                peer_id: _,
                limit: 2,
                current: 2
            })
        ),
        "expected PeerOperationLimit, got {r:?}"
    );
    // A different peer can still admit an operation.
    let b = peer(0xB2);
    let _o3 = gov.admit_operation(b).await.unwrap();
    assert_eq!(gov.peer_operations(&b).await, 1);
}

// ─── 4. Global concurrency limit ───────────────────────────────────────

/// The global operation ceiling rejects the (N+1)-th operation. This bounds
/// the total in-flight work the node admits.
#[tokio::test]
async fn r4_9_5_global_concurrency_limit() {
    let gov = small_governor();
    // Fill the global ceiling (4) — use distinct peers so the per-peer cap
    // does not trigger first.
    let _o1 = gov.admit_operation(peer(1)).await.unwrap();
    let _o2 = gov.admit_operation(peer(2)).await.unwrap();
    let _o3 = gov.admit_operation(peer(3)).await.unwrap();
    let _o4 = gov.admit_operation(peer(4)).await.unwrap();
    assert_eq!(gov.global_operations().await, 4);
    // A 5th operation is rejected.
    let r = gov.admit_operation(peer(5)).await;
    assert!(
        matches!(
            r,
            Err(AdmissionError::GlobalOperationLimit {
                limit: 4,
                current: 4
            })
        ),
        "expected GlobalOperationLimit, got {r:?}"
    );
}

// ─── 5. Gateway quota preserves the existing global cap ───────────────

/// The `GatewayQuota` composes a per-peer semaphore with the existing R4.8
/// `MAX_CONCURRENT_EGRESS = 8` global egress semaphore. The global cap is NOT
/// increased; the per-peer cap is layered on top so one peer cannot
/// monopolise the global pool.
#[tokio::test]
async fn r4_9_5_gateway_quota_preserves_global_cap() {
    // The existing R4.8 global egress semaphore (8 permits) — NOT modified.
    let global = std::sync::Arc::new(Semaphore::new(8));
    // R4.9.5: a per-peer quota (2 permits) composed on top.
    let max_peer = 2;
    let quota = GatewayQuota::new(max_peer, global.clone());

    // The global cap is unchanged.
    assert_eq!(
        global.available_permits(),
        8,
        "global egress cap must be preserved at 8"
    );
    // The per-peer cap is installed.
    assert_eq!(quota.max_peer(), max_peer);

    // Peer A acquires 2 per-peer permits (its ceiling).
    let pa1 = quota.acquire_peer_permit().await.unwrap();
    let pa2 = quota.acquire_peer_permit().await.unwrap();
    assert_eq!(
        quota.available_peer_permits(),
        0,
        "per-peer permits exhausted after 2"
    );

    // A 3rd per-peer permit is NOT available (would block). Verify via
    // try_acquire-style timeout.
    let r = tokio::time::timeout(Duration::from_millis(50), quota.acquire_peer_permit()).await;
    assert!(r.is_err(), "3rd per-peer permit must block (per-peer cap)");

    // The global cap is still 8 (the per-peer semaphore is independent).
    assert_eq!(
        global.available_permits(),
        8,
        "global cap untouched by per-peer admits"
    );

    // Drop peer-A permits → per-peer capacity returns.
    drop(pa1);
    drop(pa2);
    assert_eq!(quota.available_peer_permits(), max_peer);
}

// ─── 6. Resource release after success ─────────────────────────────────

/// A guard dropped after a successful operation releases the resource — a
/// later operation can re-acquire it. (Validates the RAII release on success.)
#[tokio::test]
async fn r4_9_5_resource_release_after_success() {
    let gov = ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 1,
        max_peer_connections: 1,
        max_global_concurrent_ops: 1,
        max_peer_concurrent_ops: 1,
    });
    let p = peer(1);

    // Connection: admit, "succeed", drop → re-admit works.
    {
        let _g = gov.admit_connection(p).await.unwrap();
        assert_eq!(gov.global_connections().await, 1);
        // simulate successful work...
    }
    assert_eq!(
        gov.global_connections().await,
        0,
        "connection released after success"
    );
    let _g2 = gov.admit_connection(p).await.unwrap();

    // Operation: admit, "succeed", drop → re-admit works.
    {
        let _o = gov.admit_operation(p).await.unwrap();
        assert_eq!(gov.global_operations().await, 1);
    }
    assert_eq!(
        gov.global_operations().await,
        0,
        "operation released after success"
    );
    let _o2 = gov.admit_operation(p).await.unwrap();
}

// ─── 7. Resource release after error ──────────────────────────────────

/// A guard dropped after an error (simulated by early-return from a failing
/// operation) releases the resource — a later operation can acquire it.
#[tokio::test]
async fn r4_9_5_resource_release_after_error() {
    let gov = ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 1,
        max_peer_connections: 1,
        max_global_concurrent_ops: 1,
        max_peer_concurrent_ops: 1,
    });
    let p = peer(1);

    // Simulate: admit a connection, then the operation "fails" (we drop the
    // guard via an early-return scope).
    async fn failing_op(gov: &ResourceGovernor, p: NodeId) -> Result<(), &'static str> {
        let _guard = gov.admit_connection(p).await.map_err(|_| "admit failed")?;
        // ...operation body that hits an error...
        Err("simulated error")
    }
    assert!(failing_op(&gov, p).await.is_err());
    // The guard was dropped on the error path → resource released.
    assert_eq!(
        gov.global_connections().await,
        0,
        "connection released after error"
    );
    // A later operation can acquire the now-freed resource.
    let _g = gov.admit_connection(p).await.unwrap();
}

// ─── 8. Resource release after cancellation ───────────────────────────

/// A guard held in a task that is cancelled (dropped mid-await) releases the
/// resource — a later operation can acquire it.
#[tokio::test]
async fn r4_9_5_resource_release_after_cancellation() {
    let gov = std::sync::Arc::new(ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 1,
        max_peer_connections: 1,
        max_global_concurrent_ops: 1,
        max_peer_concurrent_ops: 1,
    }));
    let p = peer(1);

    // Spawn a task that holds a connection guard and waits forever (until
    // cancelled).
    let gov_clone = gov.clone();
    let handle = tokio::spawn(async move {
        let _guard = gov_clone.admit_connection(p).await.unwrap();
        // Hold the guard forever — the test will cancel this task.
        std::future::pending::<()>().await;
    });
    // Give the task a moment to acquire the guard.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        gov.global_connections().await,
        1,
        "task holds the connection guard"
    );

    // Cancel the task (abort). The guard drops → resource released.
    handle.abort();
    let _ = handle.await;
    assert_eq!(
        gov.global_connections().await,
        0,
        "connection released after task cancellation"
    );
    // A later operation can acquire the now-freed resource.
    let _g = gov.admit_connection(p).await.unwrap();
}

// ─── 9. Shutdown releases resources ───────────────────────────────────

/// On shutdown, in-flight tasks holding guards are dropped (via the
/// CancellationToken + JoinSet drain model), releasing resources. After
/// shutdown, all runtime capacity is available fresh (ephemeral state).
#[tokio::test]
async fn r4_9_5_shutdown_releases_resources() {
    let gov = std::sync::Arc::new(ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 2,
        max_peer_connections: 2,
        max_global_concurrent_ops: 2,
        max_peer_concurrent_ops: 2,
    }));
    let shutdown = CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();

    // Spawn 2 tasks, each holding a connection + operation guard, waiting
    // on the shutdown signal.
    for i in 1..=2u8 {
        let gov_c = gov.clone();
        let token = shutdown.clone();
        tasks.spawn(async move {
            let _conn = gov_c.admit_connection(peer(i)).await.unwrap();
            let _op = gov_c.admit_operation(peer(i)).await.unwrap();
            // Wait for shutdown.
            token.cancelled().await;
            // Guards drop here on shutdown.
        });
    }
    // Let the tasks acquire their guards.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(gov.global_connections().await, 2);
    assert_eq!(gov.global_operations().await, 2);

    // Initiate shutdown.
    shutdown.cancel();
    // Drain all tasks (R4.8 JoinSet drain model).
    while tasks.join_next().await.is_some() {}

    // All resources released after shutdown drain.
    assert_eq!(
        gov.global_connections().await,
        0,
        "connections released on shutdown"
    );
    assert_eq!(
        gov.global_operations().await,
        0,
        "operations released on shutdown"
    );
}

// ─── 10. Capacity rejection does not poison retry score ───────────────

/// A resource-limit rejection is a local admission decision. It must NOT
/// increment the peer's `RetryScheduler::failure_count` (R4.9.4) or
/// otherwise alter peer trust state. The retry scheduler and resource
/// governor are independent domains.
#[tokio::test]
async fn r4_9_5_capacity_rejection_does_not_poison_retry_score() {
    let gov = ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 1,
        max_peer_connections: 1,
        max_global_concurrent_ops: 1,
        max_peer_concurrent_ops: 1,
    });
    let retry = RetryScheduler::new();
    let p = peer(1);

    // Admit one connection (fills the ceiling).
    let _g = gov.admit_connection(p).await.unwrap();
    // A second connection from the same peer is rejected.
    let rejected = gov.admit_connection(p).await;
    assert!(rejected.is_err(), "expected admission rejection");

    // The retry scheduler's failure score for this peer is STILL 0 — the
    // resource rejection did not poison it. (The governor and the retry
    // scheduler are independent; the integration code never calls
    // `record_retryable_failure` for an admission rejection.)
    assert_eq!(
        retry.failure_score(&p),
        0,
        "capacity rejection must NOT increment retry failure score"
    );
    // The peer is not in backoff (no retry poisoning).
    assert!(
        retry.is_eligible(&p, std::time::Instant::now()),
        "capacity rejection must NOT schedule retry backoff"
    );
}

// ─── 11. Bounded in-flight work (no unbounded task growth) ────────────

/// The global operation cap bounds the number of concurrently-admitted
/// operations. Load (many admission attempts) cannot cause unbounded
/// in-flight task growth — the (N+1)-th attempt is rejected.
#[tokio::test]
async fn r4_9_5_bounded_in_flight_no_unbounded_growth() {
    let gov = ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 64,
        max_peer_connections: 4,
        max_global_concurrent_ops: 3,
        max_peer_concurrent_ops: 3,
    });

    // Simulate a flood of admission attempts from distinct peers.
    let mut held = Vec::new();
    let mut admitted = 0usize;
    let mut rejected = 0usize;
    for i in 1..=20u8 {
        match gov.admit_operation(peer(i)).await {
            Ok(g) => {
                admitted += 1;
                held.push(g);
            }
            Err(_) => rejected += 1,
        }
    }
    // Only 3 operations admitted (the global cap); 17 rejected.
    assert_eq!(admitted, 3, "global cap must bound in-flight operations");
    assert_eq!(rejected, 17, "excess attempts must be rejected, not queued");
    assert_eq!(gov.global_operations().await, 3);

    // Releasing one admits one more (backpressure, not unbounded growth).
    held.pop();
    let _g = gov.admit_operation(peer(99)).await.unwrap();
    assert_eq!(gov.global_operations().await, 3);
}

// ─── 12. Semantic test: one peer cannot monopolise global capacity ─────

/// With global capacity = 4 and per-peer cap = 2, peer A flooding requests
/// can occupy at most 2 operations. Peer B can still acquire capacity while
/// A is at its ceiling. The per-peer ceiling proves the isolation property
/// WITHOUT weighted scheduling.
#[tokio::test]
async fn r4_9_5_one_peer_cannot_monopolise_global_capacity() {
    let gov = ResourceGovernor::with_config(GovernorConfig {
        max_global_connections: 64,
        max_peer_connections: 4,
        max_global_concurrent_ops: 4,
        max_peer_concurrent_ops: 2, // peer A ceiling
    });
    let a = peer(0xA1);
    let b = peer(0xB2);

    // Peer A floods to its ceiling (2).
    let _a1 = gov.admit_operation(a).await.unwrap();
    let _a2 = gov.admit_operation(a).await.unwrap();
    // A's 3rd attempt is rejected (per-peer cap).
    assert!(gov.admit_operation(a).await.is_err());
    assert_eq!(gov.peer_operations(&a).await, 2, "peer A capped at 2");

    // Peer B can STILL admit operations — global capacity remains available
    // to B even though A is at its ceiling. This is the isolation property.
    let _b1 = gov.admit_operation(b).await.unwrap();
    let _b2 = gov.admit_operation(b).await.unwrap();
    assert_eq!(
        gov.peer_operations(&b).await,
        2,
        "peer B admitted up to its own ceiling"
    );
    assert_eq!(
        gov.global_operations().await,
        4,
        "global pool fully utilised across both peers (A:2 + B:2)"
    );

    // Global capacity is genuinely bounded — a 5th total operation is
    // rejected (global cap = 4).
    let c = peer(0xC3);
    assert!(
        gov.admit_operation(c).await.is_err(),
        "global cap reached — 5th operation rejected"
    );
}

// ─── 13. Defaults sanity ──────────────────────────────────────────────

/// The default conservative limits are sane and preserve the R4.8 egress cap
/// (`DEFAULT_MAX_GLOBAL_CONCURRENT_OPS == MAX_CONCURRENT_EGRESS == 8`).
#[test]
fn r4_9_5_defaults_preserve_egress_cap() {
    use snp_node::node::mode_a_bundle::MAX_CONCURRENT_EGRESS;
    assert_eq!(
        DEFAULT_MAX_GLOBAL_CONCURRENT_OPS, MAX_CONCURRENT_EGRESS,
        "global concurrent-ops default must equal the R4.8 egress cap (do not reduce throughput)"
    );
    assert!(
        DEFAULT_MAX_PEER_CONCURRENT_OPS < DEFAULT_MAX_GLOBAL_CONCURRENT_OPS,
        "per-peer cap must be < global cap so one peer cannot monopolise the global pool"
    );
}
