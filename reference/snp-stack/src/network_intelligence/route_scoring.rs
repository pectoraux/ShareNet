//! **N2.5.2 — Route Scoring.**
//!
//! Turns [`RouteObservation`]s into a [`RouteScore`] — a single number
//! (0.0–100.0) that ranks routes for selection.
//!
//! ## Formula
//!
//! ```text
//! score =   reliability_weight    * reliability_score
//!         + latency_weight        * latency_score
//!         + throughput_weight     * throughput_score
//!         + diversity_weight      * diversity_score
//! ```
//!
//! ## Default weights
//!
//! | Component   | Weight | Rationale                              |
//! |-------------|--------|----------------------------------------|
//! | Reliability | 40%    | Most important — failed routes waste   |
//! |             |        | resources and break connections        |
//! | Latency     | 25%    | User-perceived speed                   |
//! | Throughput  | 20%    | Capacity for large transfers           |
//! | Diversity   | 15%    | Prefer routes with different hops      |
//! |             |        | (reduces correlated failure)           |

use super::observations::PeerId;
use super::route_observation::RouteObservation;
use std::time::Instant;

/// Configurable weights for route scoring.
#[derive(Debug, Clone)]
pub struct RouteScoringWeights {
    /// Weight for reliability (default: 0.40).
    pub reliability: f64,
    /// Weight for latency (default: 0.25).
    pub latency: f64,
    /// Weight for throughput (default: 0.20).
    pub throughput: f64,
    /// Weight for diversity (default: 0.15).
    pub diversity: f64,
}

impl Default for RouteScoringWeights {
    fn default() -> Self {
        Self {
            reliability: 0.40,
            latency: 0.25,
            throughput: 0.20,
            diversity: 0.15,
        }
    }
}

impl RouteScoringWeights {
    /// Create a new set of weights.
    #[must_use]
    pub fn new(reliability: f64, latency: f64, throughput: f64, diversity: f64) -> Self {
        Self { reliability, latency, throughput, diversity }
    }

    /// Returns the sum of all weights.
    #[must_use]
    pub fn sum(&self) -> f64 {
        self.reliability + self.latency + self.throughput + self.diversity
    }
}

/// A route score — the result of applying [`RouteScoringWeights`] to a
/// [`RouteObservation`].
#[derive(Debug, Clone, PartialEq)]
pub struct RouteScore {
    /// Reliability subscore (0.0 = worst, 1.0 = best).
    pub reliability_score: f64,
    /// Latency subscore (0.0 = worst, 1.0 = best).
    pub latency_score: f64,
    /// Throughput subscore (0.0 = worst, 1.0 = best).
    pub throughput_score: f64,
    /// Diversity subscore (0.0 = worst, 1.0 = best).
    pub diversity_score: f64,
    /// The total weighted score, scaled to `[0.0, 100.0]`.
    pub total: f64,
}

impl RouteScore {
    /// Compute a route score from an observation and weights.
    ///
    /// The `diversity_score` is computed by comparing this route's hops
    /// against a set of "known hops" (peers used by other routes in the
    /// candidate set). A route with more unique hops gets a higher
    /// diversity score.
    #[must_use]
    pub fn from_observation(
        obs: &RouteObservation,
        weights: &RouteScoringWeights,
        diversity_score: f64,
    ) -> Self {
        // ── Reliability ──────────────────────────────────────────────────
        let reliability_score = obs.reliability();

        // ── Latency ──────────────────────────────────────────────────────
        // Lower latency = higher score. Same formula as gateway scoring.
        let latency_score = obs.latency().map_or(0.5, |l| 1.0 / (1.0 + l / 100.0));

        // ── Throughput ───────────────────────────────────────────────────
        // Higher throughput = higher score.
        // score = throughput / (throughput + 1_000_000)
        // This gives:
        //   0 bps     → 0.0
        //   1 MB/s    → 0.5
        //   10 MB/s   → 0.91
        let throughput_score = obs.throughput().map_or(0.5, |t| t / (t + 1_000_000.0));

        // ── Diversity (computed externally) ──────────────────────────────
        let diversity_score = diversity_score.clamp(0.0, 1.0);

        // ── Total ────────────────────────────────────────────────────────
        let total_raw = weights.reliability * reliability_score
            + weights.latency * latency_score
            + weights.throughput * throughput_score
            + weights.diversity * diversity_score;

        let weight_sum = weights.sum();
        let total = if weight_sum > 0.0 {
            (total_raw / weight_sum) * 100.0
        } else {
            0.0
        };

        Self {
            reliability_score,
            latency_score,
            throughput_score,
            diversity_score,
            total,
        }
    }

    /// Returns the total score (0.0–100.0).
    #[must_use]
    pub fn total(&self) -> f64 {
        self.total
    }
}

impl std::fmt::Display for RouteScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "RouteScore {{")?;
        writeln!(f, "  reliability:  {:.3}", self.reliability_score)?;
        writeln!(f, "  latency:      {:.3}", self.latency_score)?;
        writeln!(f, "  throughput:   {:.3}", self.throughput_score)?;
        writeln!(f, "  diversity:    {:.3}", self.diversity_score)?;
        writeln!(f, "  total:        {:.2} / 100.0", self.total)?;
        write!(f, "}}")
    }
}

/// Compute the diversity score for a route, given the set of peers used
/// by all other candidate routes.
///
/// A route gets a high diversity score if its hops are NOT shared with
/// many other routes. This reduces correlated failure.
///
/// # Arguments
/// * `route_hops` — The hops in this route.
/// * `all_routes_hops` — The hops of ALL candidate routes (including this one).
///
/// # Returns
/// A score in `[0.0, 1.0]`. 1.0 = completely unique hops. 0.0 = all hops
/// are shared with every other route.
#[must_use]
pub fn compute_diversity_score(route_hops: &[PeerId], all_routes_hops: &[Vec<PeerId>]) -> f64 {
    if all_routes_hops.len() <= 1 {
        return 1.0; // Only one route — trivially diverse.
    }

    // Count how many other routes share each hop.
    let mut uniqueness_sum = 0.0;
    for hop in route_hops {
        // How many routes (other than this one) use this hop?
        let shared_count = all_routes_hops
            .iter()
            .filter(|other| other != &route_hops && other.contains(hop))
            .count();
        // Uniqueness: 1.0 if no other route uses this hop, decreasing as more share it.
        let uniqueness = 1.0 / (1.0 + shared_count as f64);
        uniqueness_sum += uniqueness;
    }

    // Average uniqueness across all hops.
    uniqueness_sum / route_hops.len().max(1) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::route_observation::RouteObservation;

    #[test]
    fn empty_observation_scores_neutral() {
        let obs = RouteObservation::new(vec![[1u8; 32], [2u8; 32]]);
        let weights = RouteScoringWeights::default();
        let score = RouteScore::from_observation(&obs, &weights, 1.0);
        // With no data: reliability=1.0, latency=0.5, throughput=0.5, diversity=1.0
        // total = (0.40*1.0 + 0.25*0.5 + 0.20*0.5 + 0.15*1.0) * 100 = 77.5
        assert!((score.total - 77.5).abs() < 0.5, "got {}", score.total);
    }

    #[test]
    fn low_latency_scores_higher() {
        let mut fast = RouteObservation::new(vec![[1u8; 32]]);
        fast.record_latency(10.0);
        let mut slow = RouteObservation::new(vec![[2u8; 32]]);
        slow.record_latency(500.0);
        let weights = RouteScoringWeights::default();
        let fast_score = RouteScore::from_observation(&fast, &weights, 1.0);
        let slow_score = RouteScore::from_observation(&slow, &weights, 1.0);
        assert!(fast_score.total > slow_score.total);
    }

    #[test]
    fn reliable_scores_higher_than_unreliable() {
        let mut good = RouteObservation::new(vec![[1u8; 32]]);
        for _ in 0..10 {
            good.record_success();
        }
        let mut bad = RouteObservation::new(vec![[2u8; 32]]);
        for _ in 0..10 {
            bad.record_success();
        }
        for _ in 0..5 {
            bad.record_failure();
        }
        let weights = RouteScoringWeights::default();
        let good_score = RouteScore::from_observation(&good, &weights, 1.0);
        let bad_score = RouteScore::from_observation(&bad, &weights, 1.0);
        assert!(good_score.total > bad_score.total);
    }

    #[test]
    fn diversity_unique_hops_score_higher() {
        let obs = RouteObservation::new(vec![[1u8; 32], [2u8; 32]]);
        let weights = RouteScoringWeights::default();

        // High diversity: no other route shares hops.
        let all_unique = vec![
            vec![[1u8; 32], [2u8; 32]],
            vec![[3u8; 32], [4u8; 32]],
        ];
        let diverse_score = compute_diversity_score(&obs.hops, &all_unique);

        // Low diversity: other routes share hops.
        let all_shared = vec![
            vec![[1u8; 32], [2u8; 32]],
            vec![[1u8; 32], [3u8; 32]],
        ];
        let shared_score = compute_diversity_score(&obs.hops, &all_shared);

        assert!(
            diverse_score > shared_score,
            "unique route should have higher diversity ({}) than shared ({})",
            diverse_score, shared_score
        );
    }

    #[test]
    fn score_in_range_0_to_100() {
        let mut worst = RouteObservation::new(vec![[1u8; 32]]);
        worst.record_latency(10000.0);
        for _ in 0..10 {
            worst.record_failure();
        }
        let weights = RouteScoringWeights::default();
        let worst_score = RouteScore::from_observation(&worst, &weights, 0.0);
        assert!(worst_score.total >= 0.0 && worst_score.total <= 100.0);

        let mut best = RouteObservation::new(vec![[2u8; 32]]);
        best.record_latency(1.0);
        best.record_throughput(10_000_000.0);
        for _ in 0..10 {
            best.record_success();
        }
        let best_score = RouteScore::from_observation(&best, &weights, 1.0);
        assert!(best_score.total >= 0.0 && best_score.total <= 100.0);
        assert!(best_score.total > worst_score.total);
    }
}
