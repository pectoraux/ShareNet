//! **N2.4.2 — Gateway Health Scoring.**
//!
//! Turns [`PeerObservation`]s into a [`GatewayScore`] — a single number
//! (0.0–100.0) that ranks gateways for selection.
//!
//! ## Formula
//!
//! ```text
//! score =   latency_weight      * latency_score
//!         + reliability_weight  * reliability_score
//!         + capacity_weight     * capacity_score
//!         + availability_weight * availability_score
//! ```
//!
//! Each subscore is normalized to `[0.0, 1.0]`. Weights sum to 1.0. The
//! final score is scaled to `[0.0, 100.0]`.
//!
//! ## Default weights
//!
//! | Component     | Weight | Rationale                          |
//! |---------------|--------|------------------------------------|
//! | Latency       | 25%    | User-perceived speed               |
//! | Reliability   | 35%    | Most important — failed circuits   |
//! |               |        | waste resources and frustrate users|
//! | Capacity      | 20%    | Load distribution                  |
//! | Availability  | 20%    | Uptime track record                |
//!
//! Weights are configurable via [`ScoringWeights`].

use super::observations::PeerObservation;
use std::time::Instant;

/// Configurable weights for gateway scoring. Each weight is in `[0.0, 1.0]`
/// and they should sum to 1.0 (the [`Self::validate`] method checks this).
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    /// Weight for latency (default: 0.25).
    pub latency: f64,
    /// Weight for reliability (default: 0.35).
    pub reliability: f64,
    /// Weight for capacity (default: 0.20).
    pub capacity: f64,
    /// Weight for availability (default: 0.20).
    pub availability: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            latency: 0.25,
            reliability: 0.35,
            capacity: 0.20,
            availability: 0.20,
        }
    }
}

impl ScoringWeights {
    /// Create a new set of weights. The weights need not sum to 1.0 —
    /// if they don't, the final score will be scaled accordingly. However,
    /// summing to 1.0 is recommended for predictable behavior.
    #[must_use]
    pub fn new(latency: f64, reliability: f64, capacity: f64, availability: f64) -> Self {
        Self {
            latency,
            reliability,
            capacity,
            availability,
        }
    }

    /// Validate that all weights are non-negative and sum to approximately 1.0.
    ///
    /// # Errors
    /// Returns a description of the problem if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.latency < 0.0 || self.reliability < 0.0 || self.capacity < 0.0 || self.availability < 0.0 {
            return Err("all weights must be non-negative".into());
        }
        let sum = self.latency + self.reliability + self.capacity + self.availability;
        if (sum - 1.0).abs() > 0.01 {
            return Err(format!("weights must sum to 1.0 (±0.01), got {sum}"));
        }
        Ok(())
    }

    /// Returns the sum of all weights.
    #[must_use]
    pub fn sum(&self) -> f64 {
        self.latency + self.reliability + self.capacity + self.availability
    }
}

/// A gateway score — the result of applying [`ScoringWeights`] to a
/// [`PeerObservation`].
///
/// Each subscore is in `[0.0, 1.0]` (higher is better). The `total` is
/// scaled to `[0.0, 100.0]`.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayScore {
    /// Latency subscore (0.0 = worst, 1.0 = best).
    pub latency_score: f64,
    /// Reliability subscore (0.0 = worst, 1.0 = best).
    pub reliability_score: f64,
    /// Capacity subscore (0.0 = worst, 1.0 = best).
    pub capacity_score: f64,
    /// Availability subscore (0.0 = worst, 1.0 = best).
    pub availability_score: f64,
    /// The total weighted score, scaled to `[0.0, 100.0]`.
    pub total: f64,
}

impl GatewayScore {
    /// Compute a gateway score from an observation and weights.
    ///
    /// The `now` timestamp is used for availability calculation.
    #[must_use]
    pub fn from_observation(
        obs: &PeerObservation,
        weights: &ScoringWeights,
        now: Instant,
    ) -> Self {
        // ── Latency score ────────────────────────────────────────────────
        // Lower latency = higher score. We use a soft decay:
        //   score = 1.0 / (1.0 + latency_ms / 100.0)
        // This gives:
        //   0 ms  → 1.0
        //   100 ms → 0.5
        //   300 ms → 0.25
        //   1000 ms → 0.09
        let latency_score = obs.latency().map_or(0.5, |l| 1.0 / (1.0 + l / 100.0));

        // ── Reliability score ────────────────────────────────────────────
        // Directly from the observation's reliability fraction.
        let reliability_score = obs.reliability();

        // ── Capacity score ───────────────────────────────────────────────
        // More active circuits = lower score (the gateway is loaded).
        // We use: score = 1.0 / (1.0 + active_circuits / 10.0)
        // This gives:
        //   0 circuits  → 1.0
        //   10 circuits → 0.5
        //   50 circuits → 0.17
        let capacity_score = 1.0 / (1.0 + obs.active_circuits as f64 / 10.0);

        // ── Availability score ───────────────────────────────────────────
        // From the observation's availability fraction.
        let availability_score = obs.availability(now);

        // ── Total ────────────────────────────────────────────────────────
        let total_raw = weights.latency * latency_score
            + weights.reliability * reliability_score
            + weights.capacity * capacity_score
            + weights.availability * availability_score;

        // Scale to [0, 100]. If weights don't sum to 1.0, normalize.
        let weight_sum = weights.sum();
        let total = if weight_sum > 0.0 {
            (total_raw / weight_sum) * 100.0
        } else {
            0.0
        };

        Self {
            latency_score,
            reliability_score,
            capacity_score,
            availability_score,
            total,
        }
    }

    /// Returns the total score (0.0–100.0).
    #[must_use]
    pub fn total(&self) -> f64 {
        self.total
    }
}

impl std::fmt::Display for GatewayScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "GatewayScore {{")?;
        writeln!(
            f,
            "  latency:      {:.3}",
            self.latency_score
        )?;
        writeln!(
            f,
            "  reliability:  {:.3}",
            self.reliability_score
        )?;
        writeln!(f, "  capacity:     {:.3}", self.capacity_score)?;
        writeln!(
            f,
            "  availability: {:.3}",
            self.availability_score
        )?;
        writeln!(f, "  total:        {:.2} / 100.0", self.total)?;
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::observations::{PeerId, PeerObservation};

    fn make_obs(peer_id: PeerId) -> PeerObservation {
        PeerObservation::new(peer_id)
    }

    #[test]
    fn default_weights_validate() {
        let w = ScoringWeights::default();
        assert!(w.validate().is_ok());
    }

    #[test]
    fn weights_sum_to_one() {
        let w = ScoringWeights::default();
        assert!((w.sum() - 1.0).abs() < 0.001);
    }

    #[test]
    fn empty_observation_scores_neutral() {
        let obs = make_obs([1u8; 32]);
        let weights = ScoringWeights::default();
        let now = Instant::now();
        let score = GatewayScore::from_observation(&obs, &weights, now);
        // With no data:
        // - latency = 0.5 (neutral default)
        // - reliability = 1.0 (assume reliable)
        // - capacity = 1.0 (no circuits)
        // - availability = 0.0 (never seen)
        // total = (0.25*0.5 + 0.35*1.0 + 0.20*1.0 + 0.20*0.0) * 100 = 67.5
        assert!((score.total - 67.5).abs() < 0.5, "got {}", score.total);
    }

    #[test]
    fn low_latency_scores_higher() {
        let now = Instant::now();
        let weights = ScoringWeights::default();

        let mut fast = make_obs([1u8; 32]);
        fast.record_latency(10.0); // 10ms

        let mut slow = make_obs([2u8; 32]);
        slow.record_latency(500.0); // 500ms

        let fast_score = GatewayScore::from_observation(&fast, &weights, now);
        let slow_score = GatewayScore::from_observation(&slow, &weights, now);

        assert!(
            fast_score.latency_score > slow_score.latency_score,
            "fast latency score {} should be > slow {}",
            fast_score.latency_score,
            slow_score.latency_score
        );
        assert!(
            fast_score.total > slow_score.total,
            "fast total {} should be > slow total {}",
            fast_score.total,
            slow_score.total
        );
    }

    #[test]
    fn reliable_scores_higher_than_unreliable() {
        let now = Instant::now();
        let weights = ScoringWeights::default();

        let mut good = make_obs([1u8; 32]);
        for _ in 0..10 {
            good.record_circuit_success();
        }

        let mut bad = make_obs([2u8; 32]);
        for _ in 0..10 {
            bad.record_circuit_success();
        }
        for _ in 0..5 {
            bad.record_circuit_failure();
        }

        let good_score = GatewayScore::from_observation(&good, &weights, now);
        let bad_score = GatewayScore::from_observation(&bad, &weights, now);

        assert!(
            good_score.reliability_score > bad_score.reliability_score,
            "good reliability {} should be > bad {}",
            good_score.reliability_score,
            bad_score.reliability_score
        );
        assert!(
            good_score.total > bad_score.total,
            "good total {} should be > bad total {}",
            good_score.total,
            bad_score.total
        );
    }

    #[test]
    fn loaded_gateway_scores_lower() {
        let now = Instant::now();
        let weights = ScoringWeights::default();

        let mut idle = make_obs([1u8; 32]);
        // No active circuits.

        let mut loaded = make_obs([2u8; 32]);
        for _ in 0..20 {
            loaded.record_circuit_success(); // increments active_circuits
        }

        let idle_score = GatewayScore::from_observation(&idle, &weights, now);
        let loaded_score = GatewayScore::from_observation(&loaded, &weights, now);

        assert!(
            idle_score.capacity_score > loaded_score.capacity_score,
            "idle capacity {} should be > loaded {}",
            idle_score.capacity_score,
            loaded_score.capacity_score
        );
    }

    #[test]
    fn score_in_range_0_to_100() {
        let now = Instant::now();
        let weights = ScoringWeights::default();

        // Worst case: high latency, all failures, loaded, never seen.
        let mut worst = make_obs([1u8; 32]);
        worst.record_latency(10000.0);
        for _ in 0..10 {
            worst.record_circuit_failure();
        }
        for _ in 0..50 {
            worst.record_circuit_success();
        }
        let worst_score = GatewayScore::from_observation(&worst, &weights, now);
        assert!(worst_score.total >= 0.0 && worst_score.total <= 100.0);

        // Best case: low latency, all success, idle, seen.
        let mut best = make_obs([2u8; 32]);
        best.record_latency(1.0);
        best.record_seen();
        for _ in 0..10 {
            best.record_circuit_success();
        }
        let best_score = GatewayScore::from_observation(&best, &weights, now);
        assert!(best_score.total >= 0.0 && best_score.total <= 100.0);
        assert!(best_score.total > worst_score.total);
    }
}
