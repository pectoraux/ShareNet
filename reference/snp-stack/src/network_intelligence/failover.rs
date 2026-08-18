//! **N2.4.6 — Gateway Failover.**
//!
//! When a circuit fails, the [`GatewayFailover`] coordinator selects an
//! alternate gateway from the remaining candidates and triggers a reconnect.
//!
//! ## Failover flow
//!
//! ```text
//! Circuit fails (CircuitMonitor → Failed)
//!         ↓
//! GatewayFailover.handle_failure()
//!         ↓
//! Exclude the failed gateway from candidates
//!         ↓
//! BestScoreSelector selects the next best gateway
//!         ↓
//! Caller reconnects using the new gateway
//! ```
//!
//! ## What this does NOT do (yet)
//!
//! - Seamless stream migration (the current stream is lost; the caller must
//!   re-establish). This is a future milestone (N2.5+).
//! - Circuit pre-warming (establishing a backup circuit before failure).
//! - Hysteresis (avoiding rapid back-and-forth between gateways).

use super::observations::{ObservationStore, PeerId};
use super::selector::{BestScoreSelector, SelectionResult};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The result of a failover attempt.
#[derive(Debug, Clone)]
pub enum FailoverResult {
    /// A new gateway was selected.
    Migrated {
        /// The old (failed) gateway.
        from: PeerId,
        /// The new gateway.
        to: PeerId,
        /// The score of the new gateway.
        score: super::scoring::GatewayScore,
    },
    /// No alternate gateway is available.
    NoCandidate {
        /// The failed gateway.
        failed: PeerId,
    },
    /// The failed gateway is on cooldown (recently failed) — retry later.
    Cooldown {
        /// The failed gateway.
        failed: PeerId,
        /// How long until the cooldown expires.
        retry_after: Duration,
    },
}

/// Coordinates gateway failover.
///
/// Tracks failed gateways with a cooldown period to avoid retrying a
/// known-bad gateway too quickly. After the cooldown expires, the gateway
/// is eligible for selection again (it may have recovered).
pub struct GatewayFailover {
    /// The selector used to pick the next gateway.
    selector: BestScoreSelector,
    /// Failed gateways and when they can be retried.
    failed_gateways: Vec<(PeerId, Instant)>,
    /// How long to exclude a failed gateway before retrying.
    cooldown: Duration,
    /// Maximum number of gateways to track as failed.
    max_failed: usize,
}

impl GatewayFailover {
    /// Create a new failover coordinator.
    ///
    /// # Arguments
    /// * `selector` — The gateway selector to use for picking alternates.
    /// * `cooldown` — How long to exclude a failed gateway (default: 60s).
    #[must_use]
    pub fn new(selector: BestScoreSelector, cooldown: Duration) -> Self {
        Self {
            selector,
            failed_gateways: Vec::new(),
            cooldown,
            max_failed: 32,
        }
    }

    /// Create with default cooldown (60 seconds).
    #[must_use]
    pub fn with_defaults(selector: BestScoreSelector) -> Self {
        Self::new(selector, Duration::from_secs(60))
    }

    /// Handle a gateway failure: record the failure, select an alternate.
    ///
    /// # Arguments
    /// * `failed_gateway` — The NodeId of the gateway that failed.
    /// * `candidates` — All available gateway NodeIds (including the failed one).
    ///
    /// Returns the failover result.
    pub fn handle_failure(
        &mut self,
        failed_gateway: PeerId,
        candidates: &[PeerId],
    ) -> FailoverResult {
        let now = Instant::now();

        // Record the failure with cooldown.
        self.add_failed(failed_gateway, now + self.cooldown);

        // Filter out gateways that are on cooldown.
        let available: Vec<PeerId> = candidates
            .iter()
            .filter(|c| !self.is_on_cooldown(c, now))
            .copied()
            .collect();

        // Select the best available gateway.
        match self.selector.select(&available) {
            Some(SelectionResult {
                gateway_id,
                score,
                ..
            }) => FailoverResult::Migrated {
                from: failed_gateway,
                to: gateway_id,
                score,
            },
            None => FailoverResult::NoCandidate {
                failed: failed_gateway,
            },
        }
    }

    /// Check if a gateway is currently on cooldown.
    #[must_use]
    pub fn is_on_cooldown(&self, gateway: &PeerId, now: Instant) -> bool {
        self.failed_gateways
            .iter()
            .any(|(id, retry_at)| id == gateway && *retry_at > now)
    }

    /// Returns the time remaining until a gateway's cooldown expires.
    /// Returns `None` if the gateway is not on cooldown.
    #[must_use]
    pub fn cooldown_remaining(&self, gateway: &PeerId, now: Instant) -> Option<Duration> {
        self.failed_gateways
            .iter()
            .find(|(id, retry_at)| id == gateway && *retry_at > now)
            .map(|(_, retry_at)| retry_at.duration_since(now))
    }

    /// Returns the list of currently-failed gateways.
    #[must_use]
    pub fn failed_gateways(&self) -> &[(PeerId, Instant)] {
        &self.failed_gateways
    }

    /// Remove expired cooldowns (gateways whose retry time has passed).
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        self.failed_gateways.retain(|(_, retry_at)| *retry_at > now);
    }

    /// Clear all failed gateway records (e.g., after a successful reconnect).
    pub fn clear(&mut self) {
        self.failed_gateways.clear();
    }

    /// Add a failed gateway with a retry time. Internal helper.
    fn add_failed(&mut self, gateway: PeerId, retry_at: Instant) {
        // Remove any existing entry for this gateway.
        self.failed_gateways.retain(|(id, _)| id != &gateway);
        self.failed_gateways.push((gateway, retry_at));

        // Prune if we've exceeded the max.
        if self.failed_gateways.len() > self.max_failed {
            let now = Instant::now();
            self.failed_gateways.sort_by_key(|(_, t)| *t);
            self.failed_gateways.retain(|(_, t)| *t > now);
            self.failed_gateways.truncate(self.max_failed);
        }
    }
}

impl std::fmt::Debug for GatewayFailover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayFailover")
            .field("cooldown", &self.cooldown)
            .field("failed_count", &self.failed_gateways.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::observations::PeerObservation;

    fn make_failover() -> (GatewayFailover, Arc<std::sync::RwLock<ObservationStore>>) {
        let store = Arc::new(std::sync::RwLock::new(ObservationStore::new()));
        let selector = BestScoreSelector::new(Arc::clone(&store));
        let failover = GatewayFailover::with_defaults(selector);
        (failover, store)
    }

    #[test]
    fn failover_selects_alternate() {
        let (mut failover, store) = make_failover();

        // Two gateways: A (failed) and B (available).
        let mut a = PeerObservation::new([1u8; 32]);
        a.record_latency(50.0);
        a.record_seen();

        let mut b = PeerObservation::new([2u8; 32]);
        b.record_latency(60.0);
        b.record_seen();

        store.write().unwrap().upsert(a);
        store.write().unwrap().upsert(b);

        let candidates = vec![[1u8; 32], [2u8; 32]];
        let result = failover.handle_failure([1u8; 32], &candidates);

        match result {
            FailoverResult::Migrated { from, to, .. } => {
                assert_eq!(from, [1u8; 32]);
                assert_eq!(to, [2u8; 32]);
            }
            _ => panic!("expected Migrated, got {:?}", result),
        }
    }

    #[test]
    fn failover_no_candidate_when_only_failed_available() {
        let (mut failover, _) = make_failover();
        let candidates = vec![[1u8; 32]];
        let result = failover.handle_failure([1u8; 32], &candidates);
        assert!(matches!(result, FailoverResult::NoCandidate { .. }));
    }

    #[test]
    fn failed_gateway_on_cooldown() {
        let (mut failover, store) = make_failover();

        let mut a = PeerObservation::new([1u8; 32]);
        a.record_latency(50.0);
        a.record_seen();
        let mut b = PeerObservation::new([2u8; 32]);
        b.record_latency(60.0);
        b.record_seen();
        store.write().unwrap().upsert(a);
        store.write().unwrap().upsert(b);

        let now = Instant::now();
        let candidates = vec![[1u8; 32], [2u8; 32]];

        // First failure: A fails → migrate to B.
        let result = failover.handle_failure([1u8; 32], &candidates);
        assert!(matches!(result, FailoverResult::Migrated { to, .. } if to == [2u8; 32]));

        // A should be on cooldown.
        assert!(failover.is_on_cooldown(&[1u8; 32], now));

        // Now B fails → should not go back to A (A is on cooldown).
        let result = failover.handle_failure([2u8; 32], &candidates);
        assert!(
            matches!(result, FailoverResult::NoCandidate { .. }),
            "should not select A (on cooldown), got {:?}",
            result
        );
    }

    #[test]
    fn cooldown_expires() {
        let (mut failover, _) = make_failover();
        let now = Instant::now();
        failover.add_failed([1u8; 32], now + Duration::from_millis(10));
        assert!(failover.is_on_cooldown(&[1u8; 32], now));
        std::thread::sleep(Duration::from_millis(15));
        assert!(!failover.is_on_cooldown(&[1u8; 32], Instant::now()));
    }

    #[test]
    fn prune_expired_removes_old_entries() {
        let (mut failover, _) = make_failover();
        let now = Instant::now();
        failover.add_failed([1u8; 32], now - Duration::from_secs(1)); // expired
        failover.add_failed([2u8; 32], now + Duration::from_secs(60)); // active
        failover.prune_expired();
        assert_eq!(failover.failed_gateways().len(), 1);
        assert_eq!(failover.failed_gateways()[0].0, [2u8; 32]);
    }

    #[test]
    fn clear_removes_all() {
        let (mut failover, _) = make_failover();
        let now = Instant::now();
        failover.add_failed([1u8; 32], now + Duration::from_secs(60));
        failover.add_failed([2u8; 32], now + Duration::from_secs(60));
        failover.clear();
        assert_eq!(failover.failed_gateways().len(), 0);
    }
}
