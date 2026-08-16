//! **N2.5.4+5+7 — Route Optimizer with Hysteresis.**
//!
//! The [`AdaptiveRouteOptimizer`] continuously scores routes, compares
//! them against the current route, and triggers migration when a better
//! route exists — subject to hysteresis (minimum improvement threshold
//! + cooldown) to prevent route flapping.
//!
//! ## Core loop
//!
//! ```text
//! loop {
//!     collect_observations();
//!     score_routes();
//!     compare_current_route();
//!     if better_route_exists() {
//!         migrate();
//!     }
//! }
//! ```
//!
//! ## Hysteresis
//!
//! Migration is only triggered if:
//! 1. The new route's score exceeds the current route's score by at least
//!    `min_improvement` (default: 15%).
//! 2. The last migration was at least `cooldown` ago (default: 30 seconds).
//!
//! This prevents the optimizer from rapidly switching back and forth
//! between two routes with similar scores.

use super::observations::PeerId;
use super::route_observation::{RouteId, RouteObservationStore, route_id_from_hops};
use super::route_scoring::{RouteScore, RouteScoringWeights, compute_diversity_score};
use super::diversity::{RouteCandidate, classify_routes, RouteDiversity};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// The result of a route optimization check.
#[derive(Debug, Clone)]
pub enum OptimizationResult {
    /// No migration needed — the current route is good enough.
    NoMigration {
        /// The current route's score.
        current_score: f64,
        /// The best alternative route's score (if any).
        best_alternative_score: Option<f64>,
    },
    /// A better route was found and migration is recommended.
    Migrate {
        /// The current route's hops.
        from: Vec<PeerId>,
        /// The new route's hops.
        to: Vec<PeerId>,
        /// The current route's score.
        from_score: f64,
        /// The new route's score.
        to_score: f64,
        /// The improvement percentage.
        improvement_pct: f64,
    },
    /// No routes are available.
    NoRoutes,
    /// Migration is on cooldown (too soon after the last migration).
    Cooldown {
        /// Time remaining until the next migration is allowed.
        remaining: Duration,
    },
}

/// Configuration for the adaptive route optimizer.
#[derive(Debug, Clone)]
pub struct OptimizerConfig {
    /// Minimum score improvement (percentage) required to trigger migration.
    pub min_improvement_pct: f64,
    /// Minimum time between migrations.
    pub cooldown: Duration,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            min_improvement_pct: 15.0,
            cooldown: Duration::from_secs(30),
        }
    }
}

/// The adaptive route optimizer.
///
/// Holds a reference to the [`RouteObservationStore`] and the scoring
/// weights. The caller invokes [`check`] periodically with the current
/// route and candidate routes.
pub struct AdaptiveRouteOptimizer {
    /// The route observation store (shared).
    observations: Arc<RwLock<RouteObservationStore>>,
    /// The scoring weights.
    weights: RouteScoringWeights,
    /// The optimizer configuration.
    config: OptimizerConfig,
    /// When the last migration occurred.
    last_migration: Option<Instant>,
    /// The currently-active route (if any).
    current_route: Option<Vec<PeerId>>,
}

impl AdaptiveRouteOptimizer {
    /// Create a new optimizer.
    #[must_use]
    pub fn new(
        observations: Arc<RwLock<RouteObservationStore>>,
        weights: RouteScoringWeights,
        config: OptimizerConfig,
    ) -> Self {
        Self {
            observations,
            weights,
            config,
            last_migration: None,
            current_route: None,
        }
    }

    /// Create with default weights and config.
    #[must_use]
    pub fn with_defaults(observations: Arc<RwLock<RouteObservationStore>>) -> Self {
        Self::new(
            observations,
            RouteScoringWeights::default(),
            OptimizerConfig::default(),
        )
    }

    /// Set the current route.
    pub fn set_current_route(&mut self, hops: Vec<PeerId>) {
        self.current_route = Some(hops);
    }

    /// Check whether migration is recommended. Scores all candidate routes
    /// and compares against the current route.
    ///
    /// # Arguments
    /// * `candidates` — All candidate routes (hop sequences).
    pub fn check(&mut self, candidates: &[Vec<PeerId>]) -> OptimizationResult {
        if candidates.is_empty() {
            return OptimizationResult::NoRoutes;
        }

        // Check cooldown.
        if let Some(last) = self.last_migration {
            let elapsed = Instant::now().duration_since(last);
            if elapsed < self.config.cooldown {
                return OptimizationResult::Cooldown {
                    remaining: self.config.cooldown - elapsed,
                };
            }
        }

        // Score all candidates.
        let scores = self.score_routes(candidates);

        // Determine the current route's score.
        let current_hops = match &self.current_route {
            Some(h) => h.clone(),
            None => {
                // No current route — pick the best.
                let best = scores
                    .iter()
                    .max_by(|a, b| {
                        a.1.total
                            .partial_cmp(&b.1.total)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(hops, score)| (hops.clone(), score.total));
                return match best {
                    Some((to, to_score)) => {
                        self.current_route = Some(to.clone());
                        self.last_migration = Some(Instant::now());
                        OptimizationResult::Migrate {
                            from: vec![],
                            to,
                            from_score: 0.0,
                            to_score,
                            improvement_pct: 100.0,
                        }
                    }
                    None => OptimizationResult::NoRoutes,
                };
            }
        };

        let current_score = self.score_route(&current_hops, candidates);
        let current_score_total = current_score.total;

        // Find the best alternative.
        let best_alternative = scores
            .iter()
            .filter(|(hops, _)| hops.as_slice() != current_hops.as_slice())
            .max_by(|a, b| {
                a.1.total
                    .partial_cmp(&b.1.total)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        let best_alt_score = best_alternative.map(|(_, s)| s.total);

        // Check if migration is warranted.
        if let Some((best_hops, best_score)) = best_alternative {
            if current_score_total > 0.0 {
                let improvement_pct =
                    ((best_score.total - current_score_total) / current_score_total) * 100.0;
                if improvement_pct >= self.config.min_improvement_pct {
                    self.current_route = Some(best_hops.clone());
                    self.last_migration = Some(Instant::now());
                    return OptimizationResult::Migrate {
                        from: current_hops,
                        to: best_hops.clone(),
                        from_score: current_score_total,
                        to_score: best_score.total,
                        improvement_pct,
                    };
                }
            }
        }

        OptimizationResult::NoMigration {
            current_score: current_score_total,
            best_alternative_score: best_alt_score,
        }
    }

    /// Classify all candidates into primary/backup/emergency tiers.
    #[must_use]
    pub fn classify(&self, candidates: &[Vec<PeerId>]) -> RouteDiversity {
        let scored: Vec<RouteCandidate> = candidates
            .iter()
            .map(|hops| {
                let score = self.score_route(hops, candidates);
                RouteCandidate::new(hops.clone(), score.total)
            })
            .collect();
        classify_routes(&scored)
    }

    /// Score a single route.
    fn score_route(&self, hops: &[PeerId], all_candidates: &[Vec<PeerId>]) -> RouteScore {
        let obs_store = self.observations.read().unwrap();
        let route_id = route_id_from_hops(hops);
        let obs = obs_store.get(&route_id);

        let diversity = compute_diversity_score(hops, all_candidates);

        match obs {
            Some(o) => RouteScore::from_observation(o, &self.weights, diversity),
            None => {
                // No observation — create a temporary empty one.
                let empty = super::route_observation::RouteObservation::new(hops.to_vec());
                RouteScore::from_observation(&empty, &self.weights, diversity)
            }
        }
    }

    /// Score all candidate routes.
    fn score_routes(&self, candidates: &[Vec<PeerId>]) -> Vec<(Vec<PeerId>, RouteScore)> {
        candidates
            .iter()
            .map(|hops| {
                let score = self.score_route(hops, candidates);
                (hops.clone(), score)
            })
            .collect()
    }
}

impl std::fmt::Debug for AdaptiveRouteOptimizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptiveRouteOptimizer")
            .field("config", &self.config)
            .field("has_current_route", &self.current_route.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::route_observation::RouteObservation;

    fn make_optimizer() -> (AdaptiveRouteOptimizer, Arc<RwLock<RouteObservationStore>>) {
        let store = Arc::new(RwLock::new(RouteObservationStore::new()));
        let optimizer = AdaptiveRouteOptimizer::with_defaults(Arc::clone(&store));
        (optimizer, store)
    }

    #[test]
    fn no_routes_returns_no_routes() {
        let (mut opt, _) = make_optimizer();
        assert!(matches!(opt.check(&[]), OptimizationResult::NoRoutes));
    }

    #[test]
    fn first_route_sets_current() {
        let (mut opt, store) = make_optimizer();
        let hops = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        store.write().unwrap().get_or_create(&hops).record_latency(50.0);

        let result = opt.check(&[hops.clone()]);
        assert!(matches!(result, OptimizationResult::Migrate { to, .. } if to == hops));
    }

    #[test]
    fn no_migration_when_alternative_not_better_enough() {
        let (mut opt, store) = make_optimizer();

        // Route A: 50ms, 100% reliable
        let a = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        // Route B: 45ms, 100% reliable (slightly better but not 15% better)
        let b = vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]];

        {
            let mut s = store.write().unwrap();
            s.get_or_create(&a).record_latency(50.0);
            s.get_or_create(&a).record_success();
            s.get_or_create(&b).record_latency(45.0);
            s.get_or_create(&b).record_success();
        }

        // Set A as current.
        opt.set_current_route(a.clone());

        let result = opt.check(&[a.clone(), b.clone()]);
        assert!(
            matches!(result, OptimizationResult::NoMigration { .. }),
            "should not migrate — B is not 15% better than A"
        );
    }

    #[test]
    fn migration_when_alternative_significantly_better() {
        let (mut opt, store) = make_optimizer();

        // Route A: 500ms (very slow)
        let a = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        // Route B: 10ms (much faster — > 15% improvement)
        let b = vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]];

        {
            let mut s = store.write().unwrap();
            s.get_or_create(&a).record_latency(500.0);
            s.get_or_create(&a).record_success();
            s.get_or_create(&b).record_latency(10.0);
            s.get_or_create(&b).record_success();
        }

        opt.set_current_route(a.clone());

        let result = opt.check(&[a.clone(), b.clone()]);
        match result {
            OptimizationResult::Migrate { from, to, .. } => {
                assert_eq!(from, a);
                assert_eq!(to, b);
            }
            _ => panic!("expected Migrate, got {:?}", result),
        }
    }

    #[test]
    fn cooldown_blocks_migration() {
        let (mut opt, store) = make_optimizer();

        let a = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let b = vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]];

        {
            let mut s = store.write().unwrap();
            s.get_or_create(&a).record_latency(500.0);
            s.get_or_create(&b).record_latency(10.0);
        }

        // First migration: A → B.
        opt.set_current_route(a.clone());
        let result = opt.check(&[a.clone(), b.clone()]);
        assert!(matches!(result, OptimizationResult::Migrate { .. }));

        // Now B is current. A is worse — no migration.
        // But what if we try to migrate back to a "better" route?
        // The cooldown should block it.
        // We need to make B worse than A to trigger migration desire.
        {
            let mut s = store.write().unwrap();
            s.get_or_create(&b).record_latency(1000.0); // B degrades
            s.get_or_create(&a).record_latency(50.0); // A stays good
        }

        let result = opt.check(&[a.clone(), b.clone()]);
        assert!(
            matches!(result, OptimizationResult::Cooldown { .. }),
            "should be on cooldown, got {:?}",
            result
        );
    }

    #[test]
    fn classify_fills_diversity_tiers() {
        let (opt, store) = make_optimizer();

        let routes = vec![
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]],
            vec![[1u8; 32], [6u8; 32], [7u8; 32], [3u8; 32]],
        ];

        {
            let mut s = store.write().unwrap();
            s.get_or_create(&routes[0]).record_latency(50.0);
            s.get_or_create(&routes[0]).record_success();
            s.get_or_create(&routes[1]).record_latency(40.0);
            s.get_or_create(&routes[1]).record_success();
            s.get_or_create(&routes[2]).record_latency(60.0);
            s.get_or_create(&routes[2]).record_success();
        }

        let diversity = opt.classify(&routes);
        assert!(diversity.is_complete());
        assert_eq!(diversity.tier_count(), 3);
    }
}
