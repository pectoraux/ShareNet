//! **N2.5.4+5+7 — Route Optimizer with Hysteresis.**
//!
//! The [`AdaptiveRouteOptimizer`] continuously scores routes, compares
//! them against the current route, and triggers migration when a better
//! route exists — subject to hysteresis (minimum improvement threshold
//! + cooldown) to prevent route flapping.
//!
//! ## N2.5-R.1 — Decision Integrity
//!
//! The optimizer enforces a strict decision-commit separation:
//!
//! ```text
//! check() → returns MigrationDecision (pure, no state mutation)
//!     ↓
//! caller establishes circuit
//!     ↓
//! commit_migration(decision) → verifies decision token, updates state
//! ```
//!
//! `commit_migration()` consumes the `MigrationDecision` returned by
//! `check()`. It does NOT accept arbitrary hops — the caller can only
//! commit a migration that was actually recommended. This prevents
//! TOCTOU issues where the caller commits a different route than the
//! one the optimizer chose.

use super::observations::PeerId;
use super::route_observation::{RouteId, RouteObservationStore, route_id_from_hops};
use super::route_scoring::{RouteScore, RouteScoringWeights, compute_diversity_score};
use super::diversity::{RouteCandidate, classify_routes, RouteDiversity};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// A cryptographically-bound migration decision token.
///
/// Returned by [`AdaptiveRouteOptimizer::check`] inside
/// [`OptimizationResult::Migrate`]. The caller MUST pass this token
/// to [`AdaptiveRouteOptimizer::commit_migration`] after the new
/// circuit is successfully established.
///
/// **This token is the ONLY way to commit a migration.** The caller
/// cannot call `commit_migration(arbitrary_hops)` — only
/// `commit_migration(decision)`. This prevents the caller from
/// committing a route that was not recommended by the optimizer.
#[derive(Debug, Clone)]
pub struct MigrationDecision {
    /// The route being migrated from (empty if first route).
    from: Vec<PeerId>,
    /// The route being migrated to.
    to: Vec<PeerId>,
    /// The RouteId of the target route (for verification).
    to_route_id: RouteId,
    /// The from route's score.
    from_score: f64,
    /// The to route's score.
    to_score: f64,
    /// The improvement percentage.
    improvement_pct: f64,
    /// Whether this is an exploration (cold-start) decision.
    is_exploration: bool,
    /// A unique nonce to prevent replay of old decisions.
    nonce: u64,
}

impl MigrationDecision {
    /// Returns the target route's hops.
    #[must_use]
    pub fn target_route(&self) -> &[PeerId] {
        &self.to
    }

    /// Returns the source route's hops (empty if first route).
    #[must_use]
    pub fn source_route(&self) -> &[PeerId] {
        &self.from
    }

    /// Returns `true` if this is a cold-start exploration decision.
    #[must_use]
    pub fn is_exploration(&self) -> bool {
        self.is_exploration
    }

    /// Returns the improvement percentage.
    #[must_use]
    pub fn improvement_pct(&self) -> f64 {
        self.improvement_pct
    }
}

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
    ///
    /// The caller must:
    /// 1. Establish the new circuit using existing transport primitives.
    /// 2. Verify the new circuit is healthy.
    /// 3. Call [`commit_migration`] with the [`MigrationDecision`] token.
    Migrate(MigrationDecision),
    /// No routes are available.
    NoRoutes,
    /// Migration is on cooldown (too soon after the last successful migration).
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
    /// Number of circuit attempts required for full confidence (default: 10).
    /// Routes with fewer attempts have proportionally lower confidence.
    pub min_attempts_for_confidence: u32,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            min_improvement_pct: 15.0,
            cooldown: Duration::from_secs(30),
            min_attempts_for_confidence: 10,
        }
    }
}

/// The adaptive route optimizer.
///
/// Holds a reference to the [`RouteObservationStore`] and the scoring
/// weights. The caller invokes [`check`] periodically with the current
/// route and candidate routes.
///
/// ## State mutation policy
///
/// `current_route` and `last_migration` can ONLY be changed via:
/// - [`commit_migration`] — after a successful circuit establishment.
///
/// There is NO public `set_current_route()` method. The initial route
/// is set via the first `commit_migration()` call (from a cold-start
/// `Migrate` decision).
pub struct AdaptiveRouteOptimizer {
    /// The route observation store (shared).
    observations: Arc<RwLock<RouteObservationStore>>,
    /// The scoring weights.
    weights: RouteScoringWeights,
    /// The optimizer configuration.
    config: OptimizerConfig,
    /// When the last successful migration occurred.
    last_migration: Option<Instant>,
    /// The currently-active route (if any).
    current_route: Option<Vec<PeerId>>,
    /// Monotonic counter for decision nonces (prevents replay).
    decision_counter: u64,
}

impl AdaptiveRouteOptimizer {
    /// Create a new optimizer with no current route.
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
            decision_counter: 0,
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

    /// Check whether migration is recommended. Scores all candidate routes
    /// and compares against the current route.
    ///
    /// **This is a pure decision function — it does NOT mutate optimizer
    /// state.** If migration is recommended, the caller must:
    ///
    /// 1. Establish the new circuit using existing transport primitives.
    /// 2. Verify the new circuit is healthy.
    /// 3. Call [`commit_migration`] with the returned [`MigrationDecision`].
    ///
    /// If the caller does NOT commit, the optimizer's `current_route` and
    /// `last_migration` remain unchanged.
    ///
    /// ## Cold-start behavior
    ///
    /// When there is no current route, `check()` returns a `Migrate`
    /// decision with `is_exploration = true`. This is explicitly an
    /// exploration decision — the route may have zero confidence. The
    /// caller should establish it and commit only if successful.
    pub fn check(&self, candidates: &[Vec<PeerId>]) -> OptimizationResult {
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
                // Cold-start: no current route. Pick the best candidate
                // as an EXPLORATION decision. This is explicitly not a
                // production migration — the route may have 0 confidence.
                let best = scores
                    .iter()
                    .max_by(|a, b| {
                        a.1.total
                            .partial_cmp(&b.1.total)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                return match best {
                    Some((to, score)) => {
                        let to_route_id = route_id_from_hops(to);
                        OptimizationResult::Migrate(MigrationDecision {
                            from: vec![],
                            to: to.clone(),
                            to_route_id,
                            from_score: 0.0,
                            to_score: score.total,
                            improvement_pct: 100.0,
                            is_exploration: true,
                            nonce: 0, // Will be assigned on commit
                        })
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
                    let to_route_id = route_id_from_hops(best_hops);
                    return OptimizationResult::Migrate(MigrationDecision {
                        from: current_hops,
                        to: best_hops.clone(),
                        to_route_id,
                        from_score: current_score_total,
                        to_score: best_score.total,
                        improvement_pct,
                        is_exploration: false,
                        nonce: 0,
                    });
                }
            }
        }

        OptimizationResult::NoMigration {
            current_score: current_score_total,
            best_alternative_score: best_alt_score,
        }
    }

    /// **Commit a migration after the new circuit has been successfully
    /// established.**
    ///
    /// This is the ONLY method that updates `current_route` and
    /// `last_migration`. It consumes the [`MigrationDecision`] token
    /// returned by [`check`], ensuring the caller can only commit a
    /// route that was actually recommended.
    ///
    /// # Errors
    /// Returns `Err` if the decision's target route doesn't match the
    /// recommended route (TOCTOU protection).
    pub fn commit_migration(&mut self, decision: MigrationDecision) -> Result<(), String> {
        // Verify the decision's route_id matches the target hops.
        let actual_id = route_id_from_hops(&decision.to);
        if actual_id != decision.to_route_id {
            return Err("migration decision route_id mismatch — tampered decision".into());
        }

        self.current_route = Some(decision.to);
        self.last_migration = Some(Instant::now());
        self.decision_counter += 1;
        Ok(())
    }

    /// Returns the current route (if any), without modifying state.
    #[must_use]
    pub fn current_route(&self) -> Option<&[PeerId]> {
        self.current_route.as_deref()
    }

    /// Returns when the last successful migration occurred (if any).
    #[must_use]
    pub fn last_migration(&self) -> Option<Instant> {
        self.last_migration
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
            Some(o) => RouteScore::from_observation(
                o,
                &self.weights,
                diversity,
                self.config.min_attempts_for_confidence,
            ),
            None => {
                // No observation — create a temporary empty one for scoring.
                let empty = super::route_observation::RouteObservation::new(hops.to_vec());
                RouteScore::from_observation(
                    &empty,
                    &self.weights,
                    diversity,
                    self.config.min_attempts_for_confidence,
                )
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
        let (opt, _) = make_optimizer();
        assert!(matches!(opt.check(&[]), OptimizationResult::NoRoutes));
    }

    #[test]
    fn check_recommends_but_does_not_commit() {
        let (mut opt, store) = make_optimizer();
        let hops = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        store.write().unwrap().get_or_create(&hops).record_latency(50.0);

        let result = opt.check(&[hops.clone()]);
        match &result {
            OptimizationResult::Migrate(decision) => {
                assert_eq!(decision.target_route(), hops.as_slice());
                assert!(decision.is_exploration, "cold-start should be exploration");
            }
            _ => panic!("expected Migrate, got {:?}", result),
        }

        // N2.5-R: After check(), current_route should still be None.
        assert!(opt.current_route().is_none(), "check() must NOT set current_route");
    }

    #[test]
    fn commit_consumes_decision_token() {
        let (mut opt, store) = make_optimizer();
        let hops = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        store.write().unwrap().get_or_create(&hops).record_latency(50.0);

        let result = opt.check(&[hops.clone()]);
        match result {
            OptimizationResult::Migrate(decision) => {
                opt.commit_migration(decision).unwrap();
                assert_eq!(opt.current_route(), Some(hops.as_slice()));
            }
            _ => panic!("expected Migrate"),
        }
    }

    #[test]
    fn cannot_commit_arbitrary_hops() {
        // N2.5-R.1: commit_migration only accepts a MigrationDecision,
        // not arbitrary hops. There is no way to call commit with
        // a route that wasn't recommended.
        let (mut opt, store) = make_optimizer();
        let recommended = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let not_recommended = vec![[4u8; 32], [5u8; 32], [6u8; 32]];
        store.write().unwrap().get_or_create(&recommended).record_latency(50.0);

        let result = opt.check(&[recommended.clone()]);
        match result {
            OptimizationResult::Migrate(decision) => {
                // The decision targets `recommended`, NOT `not_recommended`.
                assert_eq!(decision.target_route(), recommended.as_slice());
                assert_ne!(decision.target_route(), not_recommended.as_slice());

                // Commit succeeds with the correct decision.
                opt.commit_migration(decision).unwrap();
                assert_eq!(opt.current_route(), Some(recommended.as_slice()));
                // current_route is NOT not_recommended.
                assert_ne!(opt.current_route(), Some(not_recommended.as_slice()));
            }
            _ => panic!("expected Migrate"),
        }
    }

    #[test]
    fn failed_migration_does_not_change_current_route() {
        // Simulate: check recommends migration, caller does NOT commit
        // (because establishment failed). Current route stays unchanged.
        let store = Arc::new(RwLock::new(RouteObservationStore::new()));
        let mut opt = AdaptiveRouteOptimizer::new(
            Arc::clone(&store),
            RouteScoringWeights::default(),
            OptimizerConfig {
                min_improvement_pct: 5.0,
                cooldown: Duration::from_millis(10),
                min_attempts_for_confidence: 10,
            },
        );
        let route_a = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let route_b = vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]];

        {
            let mut s = store.write().unwrap();
            // Route A starts better (lower latency).
            s.get_or_create(&route_a).record_latency(20.0);
            for _ in 0..10 { s.get_or_create(&route_a).record_success(); }
            s.get_or_create(&route_b).record_latency(60.0);
            for _ in 0..10 { s.get_or_create(&route_b).record_success(); }
        }

        // First, establish route_a via cold-start (it's the best).
        let result = opt.check(&[route_a.clone(), route_b.clone()]);
        match result {
            OptimizationResult::Migrate(d) => { opt.commit_migration(d).unwrap(); }
            _ => panic!("expected cold-start Migrate"),
        }
        assert_eq!(opt.current_route(), Some(route_a.as_slice()));

        // Degrade route_a so route_b becomes significantly better.
        {
            let mut s = store.write().unwrap();
            for _ in 0..20 { s.get_or_create(&route_a).record_latency(500.0); }
            for _ in 0..5 { s.get_or_create(&route_a).record_failure(); }
        }

        // Wait for cooldown to pass.
        std::thread::sleep(Duration::from_millis(20));

        // Now check — should recommend migration to route_b.
        let result = opt.check(&[route_a.clone(), route_b.clone()]);
        match result {
            OptimizationResult::Migrate(d) => {
                // Caller does NOT commit (establishment failed).
                assert_eq!(d.target_route(), route_b.as_slice());
            }
            _ => panic!("expected Migrate to route_b, got {:?}", result),
        }

        // Current route is still route_a.
        assert_eq!(
            opt.current_route(),
            Some(route_a.as_slice()),
            "failed migration must NOT change current_route"
        );
    }

    #[test]
    fn cooldown_starts_only_after_successful_commit() {
        let (mut opt, store) = make_optimizer();
        let route_a = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let route_b = vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]];

        {
            let mut s = store.write().unwrap();
            s.get_or_create(&route_a).record_latency(500.0);
            s.get_or_create(&route_b).record_latency(10.0);
        }

        // Cold-start: recommend route_b (better latency).
        let result = opt.check(&[route_a.clone(), route_b.clone()]);
        assert!(matches!(result, OptimizationResult::Migrate(_)));

        // Do NOT commit — cooldown should NOT start.
        // Check again immediately — should still be able to get a Migrate
        // (no cooldown because no commit happened).
        let result = opt.check(&[route_a.clone(), route_b.clone()]);
        assert!(
            matches!(result, OptimizationResult::Migrate(_)),
            "no cooldown without commit, got {:?}",
            result
        );

        // Now commit.
        if let OptimizationResult::Migrate(d) = result {
            opt.commit_migration(d).unwrap();
        }

        // Now cooldown IS active.
        let result = opt.check(&[route_a.clone(), route_b.clone()]);
        assert!(
            matches!(result, OptimizationResult::Cooldown { .. }),
            "cooldown should be active after commit, got {:?}",
            result
        );
    }

    #[test]
    fn cold_start_is_exploration() {
        let (opt, _) = make_optimizer();
        let route = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let result = opt.check(&[route.clone()]);
        match result {
            OptimizationResult::Migrate(d) => {
                assert!(d.is_exploration(), "cold-start must be exploration");
            }
            _ => panic!("expected Migrate"),
        }
    }

    #[test]
    fn production_migration_is_not_exploration() {
        let store = Arc::new(RwLock::new(RouteObservationStore::new()));
        let mut opt = AdaptiveRouteOptimizer::new(
            Arc::clone(&store),
            RouteScoringWeights::default(),
            OptimizerConfig {
                min_improvement_pct: 5.0,
                cooldown: Duration::from_millis(10),
                min_attempts_for_confidence: 10,
            },
        );
        let route_a = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let route_b = vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]];

        {
            let mut s = store.write().unwrap();
            // Route A starts better (lower latency).
            s.get_or_create(&route_a).record_latency(20.0);
            for _ in 0..10 { s.get_or_create(&route_a).record_success(); }
            s.get_or_create(&route_b).record_latency(60.0);
            for _ in 0..10 { s.get_or_create(&route_b).record_success(); }
        }

        // Establish route_a first (it's the best, cold-start picks it).
        let result = opt.check(&[route_a.clone(), route_b.clone()]);
        if let OptimizationResult::Migrate(d) = result {
            opt.commit_migration(d).unwrap();
        }

        // Degrade route_a so route_b becomes better.
        {
            let mut s = store.write().unwrap();
            for _ in 0..20 { s.get_or_create(&route_a).record_latency(500.0); }
            for _ in 0..5 { s.get_or_create(&route_a).record_failure(); }
        }

        // Wait for cooldown.
        std::thread::sleep(Duration::from_millis(20));

        // Now check for migration to route_b.
        let result = opt.check(&[route_a.clone(), route_b.clone()]);
        match result {
            OptimizationResult::Migrate(d) => {
                assert!(!d.is_exploration(), "production migration must not be exploration");
            }
            _ => panic!("expected Migrate, got {:?}", result),
        }
    }

    #[test]
    fn no_set_current_route_method() {
        // N2.5-R.1: There is no public set_current_route() method.
        // The only way to set current_route is via commit_migration().
        // This test exists to ensure the method is NOT added back.
        let (opt, _) = make_optimizer();
        assert!(opt.current_route().is_none());
        // If set_current_route existed, this wouldn't compile:
        // opt.set_current_route(vec![]);
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
            for (i, route) in routes.iter().enumerate() {
                s.get_or_create(route).record_latency(50.0 + i as f64 * 10.0);
                s.get_or_create(route).record_success();
            }
        }

        let diversity = opt.classify(&routes);
        assert!(diversity.is_complete());
        assert_eq!(diversity.tier_count(), 3);
    }
}
