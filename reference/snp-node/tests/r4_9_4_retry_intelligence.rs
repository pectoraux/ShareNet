//! R4.9.4 — Retry Intelligence.
//!
//! Tests for:
//! - Exponential backoff increases across attempts
//! - Backoff is capped at MAX_DELAY
//! - Bounded jitter (non-negative, <= MAX_DELAY)
//! - Deterministic RNG produces testable jitter
//! - Success resets failure state
//! - Expired bundle not retried (deadline-aware)
//! - Retryable failure increments failure score
//! - Terminal failure not retried (and does not poison the peer)
//! - Retry wait respects shutdown (cancellation-aware)
//!
//! These tests validate actual behaviour via the public `RetryPolicy` /
//! `RetryScheduler` API and the L5 `BundleStore` expiry filtering, not merely
//! arithmetic helpers.

#![allow(clippy::pedantic)]

use std::time::{Duration, Instant};

use snp_identity::{NodeId, now_unix};
use snp_link::async_link::AsyncLinkError;
use snp_node::node::mode_a_bundle::ModeAError;
use snp_node::node::retry_policy::{
    DeterministicRetryRng, FailureClass, RetryPolicy, RetryScheduler, classify_forwarding_error,
};
use snp_sync::{Bundle, BundlePayload, BundleStore};

fn peer(id: u8) -> NodeId {
    [id; 32]
}

// ─── 1. Backoff increases ───────────────────────────────────────────────

/// The exponential backoff is monotonic across attempts: attempt 1 <= 2 <= 3.
/// With zero jitter the canonical doubling is exact (500, 1000, 2000 ms).
#[test]
fn r4_9_4_backoff_increases() {
    let policy = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(0)));
    let d1 = policy.compute_delay(1);
    let d2 = policy.compute_delay(2);
    let d3 = policy.compute_delay(3);
    assert!(d1 <= d2, "attempt 1 ({d1:?}) must be <= attempt 2 ({d2:?})");
    assert!(d2 <= d3, "attempt 2 ({d2:?}) must be <= attempt 3 ({d3:?})");
    // Canonical doubling with zero jitter.
    assert_eq!(d1, Duration::from_millis(500));
    assert_eq!(d2, Duration::from_millis(1000));
    assert_eq!(d3, Duration::from_millis(2000));
}

// ─── 2. Backoff is capped ───────────────────────────────────────────────

/// A very large failure count saturates at MAX_DELAY, even with maximum jitter.
/// For every attempt (including small ones with max jitter), delay <= MAX_DELAY.
#[test]
fn r4_9_4_backoff_is_capped() {
    let zero_jitter = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(0)));
    // Large failure counts saturate the backoff at MAX_DELAY.
    assert_eq!(zero_jitter.compute_delay(100), Duration::from_secs(30));
    assert_eq!(zero_jitter.compute_delay(1000), Duration::from_secs(30));

    // Max-jitter RNG: jitter = min(u64::MAX, backoff/2) = backoff/2. The total
    // (backoff + backoff/2) must still be capped at MAX_DELAY.
    let max_jitter = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(u64::MAX)));
    for n in &[1usize, 5, 20, 100, 1000] {
        let d = max_jitter.compute_delay(*n as u32);
        assert!(
            d <= Duration::from_secs(30),
            "attempt {n}: {d:?} exceeds MAX_DELAY"
        );
    }
    // Once the raw backoff saturates (n large enough), even max jitter yields
    // exactly MAX_DELAY.
    assert_eq!(
        max_jitter.compute_delay(100),
        Duration::from_secs(30),
        "saturated backoff + max jitter must equal MAX_DELAY"
    );
}

// ─── 3. Jitter is bounded ───────────────────────────────────────────────

/// For every attempt: delay >= BASE_DELAY (backoff floor) and delay <= MAX_DELAY.
/// Jitter is never negative; the result never exceeds MAX_DELAY.
#[test]
fn r4_9_4_jitter_is_bounded() {
    let policy = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(123)));
    // Zero failures => zero delay.
    assert_eq!(policy.compute_delay(0), Duration::ZERO);
    for n in 1..=25u32 {
        let d = policy.compute_delay(n);
        assert!(
            d >= Duration::from_millis(500),
            "attempt {n}: {d:?} below BASE_DELAY"
        );
        assert!(
            d <= Duration::from_secs(30),
            "attempt {n}: {d:?} exceeds MAX_DELAY"
        );
    }
}

// ─── 4. Deterministic RNG produces testable jitter ─────────────────────

/// With a deterministic RNG the jitter is reproducible: the same failure count
/// always yields the same delay. attempt 1 = 500 + 250 = 750 ms.
#[test]
fn r4_9_4_deterministic_rng_produces_testable_jitter() {
    let policy = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(250)));
    // attempt 1: backoff = 500, jitter_bound = 250, jitter = min(250, 250) = 250.
    let a = policy.compute_delay(1);
    let b = policy.compute_delay(1);
    assert_eq!(a, b, "deterministic RNG must be reproducible");
    assert_eq!(a, Duration::from_millis(750));
    // attempt 2: backoff = 1000, jitter_bound = 500, jitter = min(250, 500) = 250.
    assert_eq!(policy.compute_delay(2), Duration::from_millis(1250));
    // attempt 3: backoff = 2000, jitter_bound = 1000, jitter = 250.
    assert_eq!(policy.compute_delay(3), Duration::from_millis(2250));
}

// ─── 5. Success resets failure state ────────────────────────────────────

/// A successful peer interaction resets the failure score to 0 and clears the
/// pending backoff (the peer is immediately eligible again).
#[test]
fn r4_9_4_success_resets_failure_state() {
    let mut sched = RetryScheduler::with_policy(RetryPolicy::with_rng(Box::new(
        DeterministicRetryRng::new(0),
    )));
    let p = peer(0xA1);
    let now = Instant::now();

    // Initial state: no failures, eligible.
    assert_eq!(sched.failure_score(&p), 0);
    assert!(sched.is_eligible(&p, now));

    // A retryable failure: score 1, backoff pending (ineligible).
    sched.record_retryable_failure(&p, now);
    assert_eq!(sched.failure_score(&p), 1);
    assert!(
        !sched.is_eligible(&p, now),
        "peer must be ineligible while backoff is pending"
    );

    // Success: score 0, eligible again.
    sched.record_success(&p);
    assert_eq!(sched.failure_score(&p), 0);
    assert!(sched.is_eligible(&p, now));
}

// ─── 6. Expired bundle not retried ──────────────────────────────────────

/// (a) The retry scheduler refuses to rely on a retry that would occur after
///     the bundle's deadline (`retry_fits_before_deadline`).
/// (b) The L5 `BundleStore::pending` excludes expired bundles — an expired
///     bundle is never handed to the forwarder, so it is not retried.
#[test]
fn r4_9_4_expired_bundle_not_retried() {
    let now = now_unix();

    // (a) Deadline-aware scheduling decision.
    // A 4s backoff does NOT fit within a 1s remaining TTL.
    assert!(!RetryScheduler::retry_fits_before_deadline(
        Duration::from_secs(4),
        now,
        now + 1,
    ));
    // A 500ms backoff DOES fit within a 10s TTL.
    assert!(RetryScheduler::retry_fits_before_deadline(
        Duration::from_millis(500),
        now,
        now + 10,
    ));
    // A bundle already past its deadline: any retry is too late.
    assert!(!RetryScheduler::retry_fits_before_deadline(
        Duration::from_millis(1),
        now + 60,
        now,
    ));

    // (b) Actual store behaviour: an expired bundle is excluded from pending.
    let src: NodeId = [1u8; 32];
    let dst: NodeId = [2u8; 32];
    let live = Bundle::new(src, dst, BundlePayload::new(vec![1, 2, 3]), now, now + 60)
        .expect("live bundle");
    // deadline == created_at => is_expired(now) is true (now >= deadline).
    let expired = Bundle::new(src, dst, BundlePayload::new(vec![4, 5, 6]), now, now)
        .expect("expired bundle");

    let mut store = BundleStore::new();
    store.add(live.clone()).expect("add live");
    store.add(expired.clone()).expect("add expired");

    let pending = store.pending(now);
    assert!(
        pending.iter().any(|b| b.bundle_id() == live.bundle_id()),
        "live bundle must be pending"
    );
    assert!(
        !pending.iter().any(|b| b.bundle_id() == expired.bundle_id()),
        "expired bundle must NOT be pending (not retried)"
    );
}

// ─── 7. Retryable failure increments failure score ─────────────────────

/// Each retryable peer-attributable failure increments the score by 1; a
/// success resets it to 0. The representation is intentionally simple.
#[test]
fn r4_9_4_retryable_failure_increments_failure_score() {
    let mut sched = RetryScheduler::with_policy(RetryPolicy::with_rng(Box::new(
        DeterministicRetryRng::new(0),
    )));
    let p = peer(0xB2);
    let now = Instant::now();

    assert_eq!(sched.failure_score(&p), 0, "initial score must be 0");

    sched.record_retryable_failure(&p, now);
    assert_eq!(sched.failure_score(&p), 1);

    sched.record_retryable_failure(&p, now);
    assert_eq!(sched.failure_score(&p), 2);

    sched.record_retryable_failure(&p, now);
    assert_eq!(sched.failure_score(&p), 3);

    sched.record_success(&p);
    assert_eq!(sched.failure_score(&p), 0, "success must reset to 0");
}

// ─── 8. Terminal failure not retried ───────────────────────────────────

/// A terminal failure (cryptographic / malformed / expiry) marks the bundle
/// terminal so it is not retried, WITHOUT poisoning the peer's failure score
/// or scheduling a backoff.
#[test]
fn r4_9_4_terminal_failure_not_retried() {
    let mut sched = RetryScheduler::with_policy(RetryPolicy::with_rng(Box::new(
        DeterministicRetryRng::new(0),
    )));
    let p = peer(0xC3);
    let now = Instant::now();
    let bundle_id = snp_sync::BundleId::from_bytes([0xAA; 32]);

    // A cryptographic handshake failure is terminal.
    let terminal_err = ModeAError::Link(AsyncLinkError::Handshake(
        "signature verification failed".into(),
    ));
    assert_eq!(
        classify_forwarding_error(&terminal_err),
        FailureClass::Terminal
    );

    // A malformed-CBOR error is terminal.
    let cbor_err = ModeAError::Link(AsyncLinkError::Cbor("bad frame".into()));
    assert_eq!(
        classify_forwarding_error(&cbor_err),
        FailureClass::Terminal
    );

    // An I/O connect failure is retryable.
    let io_err = ModeAError::Link(AsyncLinkError::Io("connect: refused".into()));
    assert_eq!(
        classify_forwarding_error(&io_err),
        FailureClass::Retryable
    );

    // Record a terminal failure for the bundle.
    sched.record_terminal_failure(&bundle_id);
    assert!(sched.is_terminal(&bundle_id), "bundle must be terminal");

    // The peer is NOT penalised: score stays 0, no backoff, still eligible.
    assert_eq!(
        sched.failure_score(&p),
        0,
        "terminal failure must not increment peer score"
    );
    assert!(
        sched.is_eligible(&p, now),
        "terminal failure must not schedule a peer backoff"
    );

    // A retryable I/O failure for the SAME peer still works normally — the
    // terminal bundle did not poison the peer.
    sched.record_retryable_failure(&p, now);
    assert_eq!(sched.failure_score(&p), 1);
    assert!(!sched.is_eligible(&p, now));
}

// ─── 9. Retry wait respects shutdown ────────────────────────────────────

/// A scheduled retry backoff must not block shutdown. The forwarder loop
/// sleeps for at most the poll interval (never the full backoff), and the
/// `CancellationToken` wins the `select!` promptly.
#[tokio::test]
async fn r4_9_4_retry_wait_respects_shutdown() {
    use tokio_util::sync::CancellationToken;

    let mut sched = RetryScheduler::with_policy(RetryPolicy::with_rng(Box::new(
        DeterministicRetryRng::new(0),
    )));
    let p = peer(0xD4);
    let now = Instant::now();
    // Push the backoff to MAX_DELAY (30s) via many failures.
    for _ in 0..100 {
        sched.record_retryable_failure(&p, now);
    }
    assert_eq!(sched.failure_score(&p), 100);

    // The next sleep is bounded by the poll interval — NOT the 30s backoff.
    let poll = Duration::from_millis(500);
    let sleep_dur = sched.next_sleep_duration(now, poll);
    assert!(
        sleep_dur <= poll,
        "sleep {sleep_dur:?} must be <= poll {poll:?} — backoff must not block the loop"
    );

    // Cancellation must win over the backoff sleep, promptly.
    let token = CancellationToken::new();
    let start = Instant::now();
    let handle = tokio::spawn({
        let token = token.clone();
        async move {
            tokio::select! {
                _ = token.cancelled() => "shutdown",
                _ = tokio::time::sleep(sleep_dur) => "slept",
            }
        }
    });
    // Cancel immediately.
    token.cancel();
    let result = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("select did not resolve within 2s")
        .expect("task panicked");
    let elapsed = start.elapsed();
    assert_eq!(result, "shutdown", "shutdown must win the select");
    assert!(
        elapsed < Duration::from_secs(1),
        "shutdown took {elapsed:?} — backoff blocked cancellation"
    );
}
