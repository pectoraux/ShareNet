//! Retry Intelligence (R4.9.4).
//!
//! Operational scheduling policy for bundle forwarding retries. This replaces
//! the pre-R4.9.4 fixed 500ms retry cadence with bounded, jittered,
//! failure-aware exponential backoff.
//!
//! # Architectural boundary
//!
//! Retry intelligence is an **operational scheduling policy** — it decides
//! *when* the next forwarding attempt for a peer should occur. It does NOT
//! decide *which* route a bundle uses (that remains R5 territory) and it does
//! NOT alter `Bundle` / `Route` / custody semantics.
//!
//! ```text
//! Bundle (L5, frozen)
//!   |
//! Route (L6, frozen)
//!   |
//! next hop
//!   |
//! forward attempt  ── success ──▶ reset failure state
//!   |
//!   failure
//!   |
//! classify ──▶ Retryable  ──▶ record failure (score++, backoff+jitter) ──▶ wait ──▶ retry
//!          └─▶ Terminal    ──▶ mark bundle terminal (no retry, no score)
//! ```
//!
//! # State lifetime
//!
//! Retry state is **ephemeral** (in-memory). It is NOT persisted — retry
//! scheduling is operational, not protocol truth. On restart, retry state
//! resets to zero; durable bundles remain authoritative and are retried afresh
//! using a fresh schedule. This mirrors the R4.9.3 quarantine design
//! (operational state is not persisted unless it is protocol truth).
//!
//! # Constants
//!
//! `BASE_DELAY = 500ms` deliberately matches the pre-R4.9.4 poll interval, so
//! the first retry is no slower than before. `MAX_DELAY = 30s` bounds the
//! exponential growth. The primary retry bound remains **bundle expiry** —
//! backoff never extends a bundle's TTL and never becomes a hidden drop policy.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use snp_identity::NodeId;
use snp_link::async_link::AsyncLinkError;
use snp_sync::BundleId;

use crate::node::mode_a_bundle::ModeAError;

/// Base backoff delay. Matches the pre-R4.9.4 500ms cadence so the first
/// retry is no slower than before R4.9.4.
pub const BASE_DELAY: Duration = Duration::from_millis(500);

/// Maximum backoff delay. The exponential series is capped at this value.
pub const MAX_DELAY: Duration = Duration::from_secs(30);

/// Jitter amplitude as a fraction of the capped backoff (50%).
const JITTER_FRACTION_DENOM: u64 = 2;

/// Abstraction over the jitter RNG.
///
/// Production code uses [`SystemRetryRng`] (OS-backed `getrandom`). Unit tests
/// use [`DeterministicRetryRng`] so jitter is reproducible.
pub trait RetryRng: Send + Sync {
    /// Return a random value in `[0, bound_ms]` milliseconds (inclusive of
    /// both ends). `bound_ms == 0` always yields `0`.
    fn jitter_millis(&self, bound_ms: u64) -> u64;
}

/// Production RNG backed by the OS entropy source (`getrandom`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRetryRng;

impl RetryRng for SystemRetryRng {
    fn jitter_millis(&self, bound_ms: u64) -> u64 {
        if bound_ms == 0 {
            return 0;
        }
        // 8 bytes of OS randomness, mapped into [0, bound_ms].
        let mut buf = [0u8; 8];
        // getrandom failure is treated as zero jitter (fail-open for jitter —
        // the backoff itself is still enforced, only the jitter is lost). This
        // never throws the node into an unretryable state.
        if getrandom::getrandom(&mut buf).is_ok() {
            u64::from_le_bytes(buf) % (bound_ms + 1)
        } else {
            0
        }
    }
}

/// Deterministic RNG for tests. Always returns `min(value, bound_ms)`, making
/// jitter fully reproducible.
#[derive(Debug, Clone, Copy)]
pub struct DeterministicRetryRng {
    value: u64,
}

impl DeterministicRetryRng {
    /// Create a deterministic RNG that yields `min(value, bound)` for any
    /// `bound`. Use `new(0)` for zero jitter, or a positive value to pin the
    /// jitter amount.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
}

impl RetryRng for DeterministicRetryRng {
    fn jitter_millis(&self, bound_ms: u64) -> u64 {
        self.value.min(bound_ms)
    }
}

/// Pure, testable exponential-backoff policy with bounded jitter.
///
/// The backoff for failure count `n` (n >= 1) is:
/// ```text
/// backoff = min(MAX_DELAY, BASE_DELAY * 2^(n-1))
/// jitter  = rng.jitter_millis(backoff / 2)        // [0, backoff/2]
/// delay   = min(MAX_DELAY, backoff + jitter)       // <= MAX_DELAY, >= 0
/// ```
///
/// `compute_delay(0)` returns `Duration::ZERO` (no failure → no wait).
pub struct RetryPolicy {
    base_delay: Duration,
    max_delay: Duration,
    rng: Box<dyn RetryRng>,
}

impl RetryPolicy {
    /// Create a production policy with the default constants and OS-backed
    /// jitter RNG.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base_delay: BASE_DELAY,
            max_delay: MAX_DELAY,
            rng: Box::new(SystemRetryRng),
        }
    }

    /// Create a policy with an explicit RNG (for deterministic tests).
    #[must_use]
    pub fn with_rng(rng: Box<dyn RetryRng>) -> Self {
        Self {
            base_delay: BASE_DELAY,
            max_delay: MAX_DELAY,
            rng,
        }
    }

    /// The configured base delay.
    #[must_use]
    pub fn base_delay(&self) -> Duration {
        self.base_delay
    }

    /// The configured maximum delay.
    #[must_use]
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Compute the backoff delay (with bounded jitter) for a given failure
    /// count. See the type-level docs for the formula.
    ///
    /// Guarantees:
    /// - `failure_count == 0` → `Duration::ZERO`
    /// - result is always `<= max_delay`
    /// - jitter is always `>= 0`
    #[must_use]
    pub fn compute_delay(&self, failure_count: u32) -> Duration {
        if failure_count == 0 {
            return Duration::ZERO;
        }
        let base_ms = u64::try_from(self.base_delay.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.max_delay.as_millis()).unwrap_or(u64::MAX);
        // 2^(failure_count - 1), saturating shift to avoid overflow on large
        // counts (the result is capped at max_delay anyway).
        let shift = (failure_count - 1).min(31) as u32;
        let factor = 1u64 << shift;
        let backoff = base_ms.saturating_mul(factor).min(max_ms);
        // Bounded jitter: [0, backoff/2]. Using integer division — for backoff
        // < 2ms the bound is 0 (no jitter), which is safe.
        let jitter_bound = backoff / JITTER_FRACTION_DENOM;
        let jitter = self.rng.jitter_millis(jitter_bound);
        let total = backoff.saturating_add(jitter).min(max_ms);
        Duration::from_millis(total)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Classification of a forwarding failure for retry purposes.
///
/// - [`FailureClass::Retryable`] — a peer-attributable transient failure
///   (connection refused / reset / EOF / timeout / unreachable / I/O during
///   peer forwarding). The peer's failure score is incremented and a backoff
///   is scheduled.
/// - [`FailureClass::Terminal`] — a failure that must not be retried
///   (cryptographic verification, malformed protocol data, expiry, identity
///   substitution, local errors, downstream gateway failures). No score is
///   incremented and no backoff is scheduled; the bundle is marked terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Peer-attributable transient failure — schedule a backoff retry.
    Retryable,
    /// Non-retryable failure — do not retry via the scheduling policy.
    Terminal,
}

/// Classify a `ModeAError` from the forwarding path into a retry category.
///
/// Only errors that can reasonably be attributed to the next hop AND are
/// transient are [`FailureClass::Retryable`]. Everything else is
/// [`FailureClass::Terminal`] (fail-closed: unknown errors are not retried).
///
/// # Attribution rules (per R4.9.4 §7)
///
/// Retryable (peer-attributable):
/// - [`ModeAError::Link`]`(`[`AsyncLinkError::Io`]`(_))` — TCP connect / send /
///   recv I/O failure (connection refused, reset, EOF, timeout, unreachable).
/// - [`ModeAError::Transport`]`(_)` — connect/IO failure (carriers).
///
/// Terminal (NOT retried — not peer-attributable, or not transient):
/// - [`AsyncLinkError::Handshake`] — SNP-IK signature / NodeId failure
///   (cryptographic).
/// - [`AsyncLinkError::DecryptionFailed`] — AEAD verify failure (cryptographic).
/// - [`AsyncLinkError::Cbor`] / [`AsyncLinkError::AbsurdLength`] /
///   [`AsyncLinkError::ReplayDetected`] — malformed / replay (security).
/// - [`ModeAError::Bundle`] — bundle CBOR encode/decode (malformed / local).
/// - [`ModeAError::Gateway`] — downstream gateway failure (not next-hop
///   attributable).
/// - [`ModeAError::Expired`] / [`ModeAError::DestinationMismatch`] /
///   [`ModeAError::IdentitySubstitution`] / [`ModeAError::NoResponse`] /
///   [`ModeAError::Other`] — terminal / local / non-peer.
#[must_use]
pub fn classify_forwarding_error(err: &ModeAError) -> FailureClass {
    match err {
        ModeAError::Link(AsyncLinkError::Io(_)) => FailureClass::Retryable,
        ModeAError::Transport(_) => FailureClass::Retryable,
        _ => FailureClass::Terminal,
    }
}

/// Per-peer ephemeral retry state.
///
/// Tracks how many consecutive peer-attributable failures have occurred and
/// the earliest instant at which the peer is again eligible for a forwarding
/// attempt. This is NOT a reputation model and is NOT persisted.
#[derive(Debug, Clone, Copy)]
pub struct PeerRetryState {
    /// Consecutive peer-attributable retryable failures since the last
    /// successful interaction. Reset to `0` on success.
    pub failure_count: u32,
    /// The earliest `Instant` at which the peer is eligible again. `None`
    /// means the peer is immediately eligible (no backoff pending).
    pub next_eligible_at: Option<Instant>,
}

impl PeerRetryState {
    /// Fresh state: zero failures, immediately eligible.
    #[must_use]
    pub const fn fresh() -> Self {
        Self {
            failure_count: 0,
            next_eligible_at: None,
        }
    }
}

/// Ephemeral retry scheduler holding per-peer backoff state and the set of
/// bundles that hit a terminal failure (and must not be retried).
///
/// State is in-memory only — it does not survive restart (see module docs).
/// Durable bundle custody (R4.6) remains authoritative.
pub struct RetryScheduler {
    policy: RetryPolicy,
    peers: HashMap<NodeId, PeerRetryState>,
    terminal: HashSet<BundleId>,
}

impl RetryScheduler {
    /// Create a scheduler with the default production policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: RetryPolicy::new(),
            peers: HashMap::new(),
            terminal: HashSet::new(),
        }
    }

    /// Create a scheduler with an explicit policy (for deterministic tests).
    #[must_use]
    pub fn with_policy(policy: RetryPolicy) -> Self {
        Self {
            policy,
            peers: HashMap::new(),
            terminal: HashSet::new(),
        }
    }

    /// The current failure score for a peer (`0` if unseen). A successful
    /// interaction resets this to `0`.
    #[must_use]
    pub fn failure_score(&self, peer: &NodeId) -> u32 {
        self.peers
            .get(peer)
            .map_or(0, |s| s.failure_count)
    }

    /// True if the peer is eligible for a forwarding attempt at `now` (i.e.
    /// no backoff is pending, or the backoff has elapsed).
    #[must_use]
    pub fn is_eligible(&self, peer: &NodeId, now: Instant) -> bool {
        match self.peers.get(peer) {
            None => true,
            Some(state) => state.next_eligible_at.map_or(true, |t| now >= t),
        }
    }

    /// True if the bundle hit a terminal failure and must not be retried.
    #[must_use]
    pub fn is_terminal(&self, bundle_id: &BundleId) -> bool {
        self.terminal.contains(bundle_id)
    }

    /// Record a peer-attributable retryable failure. Increments the peer's
    /// failure score and schedules the next eligible instant using the
    /// exponential backoff + jitter. Returns the scheduled delay.
    ///
    /// Tracing fields: `peer_id`, `attempt`, `failure_score`, `retry_delay_ms`.
    pub fn record_retryable_failure(&mut self, peer: &NodeId, now: Instant) -> Duration {
        let state = self
            .peers
            .entry(*peer)
            .or_insert_with(PeerRetryState::fresh);
        state.failure_count = state.failure_count.saturating_add(1);
        let attempt = state.failure_count;
        let delay = self.policy.compute_delay(attempt);
        state.next_eligible_at = Some(now + delay);
        tracing::debug!(
            peer_id = ?peer,
            attempt = attempt,
            failure_score = attempt,
            retry_delay_ms = delay.as_millis() as u64,
            "retry scheduled"
        );
        delay
    }

    /// Record a terminal failure for a specific bundle. The bundle is marked
    /// terminal (skipped on future forwarding ticks) but the peer's score is
    /// NOT touched — a terminal bundle must not poison an otherwise-healthy
    /// peer. The bundle remains in durable custody until expiry pruning.
    pub fn record_terminal_failure(&mut self, bundle_id: &BundleId) {
        if self.terminal.insert(*bundle_id) {
            tracing::debug!(
                bundle_id = %bundle_id.to_hex().get(..16).unwrap_or("?"),
                "terminal failure — bundle will not be retried"
            );
        }
    }

    /// Record a successful peer interaction. Resets the peer's failure score
    /// to `0` and clears any pending backoff. Only a genuine success (a
    /// custody ACK from the next hop) should call this.
    pub fn record_success(&mut self, peer: &NodeId) {
        if let Some(state) = self.peers.get_mut(peer) {
            if state.failure_count != 0 || state.next_eligible_at.is_some() {
                tracing::debug!(
                    peer_id = ?peer,
                    "retry state reset after successful interaction"
                );
            }
            state.failure_count = 0;
            state.next_eligible_at = None;
        }
    }

    /// The earliest pending next-eligible instant across all peers (for
    /// computing an adaptive sleep). `None` if no peer is in backoff.
    #[must_use]
    pub fn next_eligibility(&self, now: Instant) -> Option<Instant> {
        self.peers
            .values()
            .filter_map(|s| s.next_eligible_at)
            .filter(|&t| t > now)
            .min()
    }

    /// The duration the forwarder loop should sleep before re-checking
    /// eligibility. This is `min(poll_interval, time_until_next_eligible)` so
    /// the loop never sleeps longer than one poll interval, and shutdown (in
    /// the surrounding `select!`) is honoured promptly.
    ///
    /// With no peer in backoff this returns `poll_interval`.
    #[must_use]
    pub fn next_sleep_duration(&self, now: Instant, poll_interval: Duration) -> Duration {
        match self.next_eligibility(now) {
            None => poll_interval,
            Some(t) => {
                let remaining = t.saturating_duration_since(now);
                poll_interval.min(remaining)
            }
        }
    }

    /// Determine whether a retry scheduled with `delay` from `now_secs` would
    /// occur before the bundle's `deadline_secs`. If not, the bundle will
    /// have expired by the time the retry is due and the retry must not be
    /// relied upon (the bundle is pruned by its normal expiry handling).
    ///
    /// This never extends a bundle's TTL.
    #[must_use]
    pub fn retry_fits_before_deadline(delay: Duration, now_secs: u64, deadline_secs: u64) -> bool {
        let now_ms = now_secs.saturating_mul(1000);
        let deadline_ms = deadline_secs.saturating_mul(1000);
        let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        let retry_at = now_ms.saturating_add(delay_ms);
        // Strictly less than: a retry exactly at the deadline is too late
        // (the bundle is expired at deadline).
        retry_at < deadline_ms
    }

    /// Read-only access to the underlying policy (for tests / diagnostics).
    #[must_use]
    pub fn policy(&self) -> &RetryPolicy {
        &self.policy
    }
}

impl Default for RetryScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_increases_monotonically() {
        let policy = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(0)));
        let d1 = policy.compute_delay(1);
        let d2 = policy.compute_delay(2);
        let d3 = policy.compute_delay(3);
        assert!(d1 <= d2, "{d1:?} should be <= {d2:?}");
        assert!(d2 <= d3, "{d2:?} should be <= {d3:?}");
        // And the canonical doubling holds with zero jitter.
        assert_eq!(d1, Duration::from_millis(500));
        assert_eq!(d2, Duration::from_millis(1000));
        assert_eq!(d3, Duration::from_millis(2000));
    }

    #[test]
    fn backoff_is_capped_at_max() {
        let policy = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(0)));
        // A very large failure count must saturate at MAX_DELAY.
        let big = policy.compute_delay(100);
        assert_eq!(big, MAX_DELAY);
        // Even with maximum jitter (DeterministicRetryRng returns min(value,
        // bound) — bound is MAX/2 here so jitter = value capped at MAX/2), the
        // total is capped at MAX_DELAY.
        let policy_j = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(u64::MAX)));
        let big_j = policy_j.compute_delay(100);
        assert_eq!(big_j, MAX_DELAY);
    }

    #[test]
    fn jitter_is_bounded_nonnegative() {
        let policy = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(123)));
        for n in 1..=20 {
            let d = policy.compute_delay(n);
            assert!(d <= MAX_DELAY, "attempt {n}: {d:?} exceeds MAX_DELAY");
            assert!(d >= BASE_DELAY, "attempt {n}: {d:?} below BASE_DELAY");
        }
        // zero failure count = zero delay.
        assert_eq!(policy.compute_delay(0), Duration::ZERO);
    }

    #[test]
    fn deterministic_rng_is_reproducible() {
        let rng = DeterministicRetryRng::new(250);
        // jitter = min(250, bound).
        assert_eq!(rng.jitter_millis(0), 0);
        assert_eq!(rng.jitter_millis(100), 100);
        assert_eq!(rng.jitter_millis(250), 250);
        assert_eq!(rng.jitter_millis(1000), 250);
        // Same policy → same delay every call (deterministic).
        let p = RetryPolicy::with_rng(Box::new(DeterministicRetryRng::new(250)));
        let a = p.compute_delay(1);
        let b = p.compute_delay(1);
        assert_eq!(a, b);
        // attempt 1: backoff=500, jitter=min(250, 250)=250, total=750.
        assert_eq!(a, Duration::from_millis(750));
    }
}
