//! **N2.4.3 — Gateway Selection.**
//!
//! The [`BestScoreSelector`] selects the gateway with the highest
//! [`crate::scoring::GatewayScore`] from a set of candidates.
//!
//! ## Architecture
//!
//! ```text
//! GatewayAdvertisement[] (from discovery)
//!         ↓
//! ObservationStore (runtime measurements)
//!         ↓
//! BestScoreSelector
//!         ↓
//! selected GatewayId
//! ```
//!
//! The selector is stateless — it reads the current observations and
//! computes scores on demand. The caller is responsible for keeping the
//! `ObservationStore` up to date.

use super::observations::{ObservationStore, PeerId};
use super::scoring::{GatewayScore, ScoringWeights};
use std::sync::Arc;
use std::time::Instant;

/// The result of gateway selection.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// The selected gateway's NodeId.
    pub gateway_id: PeerId,
    /// The score of the selected gateway.
    pub score: GatewayScore,
    /// The number of candidates considered.
    pub candidates_considered: usize,
}

/// A gateway selector that picks the gateway with the highest score.
///
/// The selector holds a reference to the [`ObservationStore`] and the
/// [`ScoringWeights`]. It is `Clone + Send + Sync` — safe to share
/// across tasks.
#[derive(Clone)]
pub struct BestScoreSelector {
    /// The observation store (shared).
    observations: Arc<std::sync::RwLock<ObservationStore>>,
    /// The scoring weights.
    weights: ScoringWeights,
}

impl BestScoreSelector {
    /// Create a new selector with the given observation store and default weights.
    #[must_use]
    pub fn new(observations: Arc<std::sync::RwLock<ObservationStore>>) -> Self {
        Self {
            observations,
            weights: ScoringWeights::default(),
        }
    }

    /// Create a new selector with custom weights.
    #[must_use]
    pub fn with_weights(
        observations: Arc<std::sync::RwLock<ObservationStore>>,
        weights: ScoringWeights,
    ) -> Self {
        Self {
            observations,
            weights,
        }
    }

    /// Select the best gateway from a list of candidate NodeIds.
    ///
    /// Returns `None` if the candidate list is empty.
    /// Gateways with no observation data are scored neutrally (they are
    /// NOT excluded — discovery is the first signal, not a barrier).
    pub fn select(&self, candidates: &[PeerId]) -> Option<SelectionResult> {
        if candidates.is_empty() {
            return None;
        }

        let obs_store = self.observations.read().unwrap();
        let now = Instant::now();

        let mut best: Option<(PeerId, GatewayScore)> = None;

        for &candidate in candidates {
            let obs = obs_store.get(&candidate);
            let score = match obs {
                Some(o) => GatewayScore::from_observation(o, &self.weights, now),
                None => {
                    // No observation — create a temporary empty one for scoring.
                    let empty = super::observations::PeerObservation::new(candidate);
                    GatewayScore::from_observation(&empty, &self.weights, now)
                }
            };

            match &best {
                None => best = Some((candidate, score)),
                Some((_, best_score)) => {
                    if score.total > best_score.total {
                        best = Some((candidate, score));
                    }
                }
            }
        }

        best.map(|(gateway_id, score)| SelectionResult {
            gateway_id,
            score,
            candidates_considered: candidates.len(),
        })
    }

    /// Select the best gateway from all observed peers.
    ///
    /// This is useful when the caller wants to consider all known peers,
    /// not a filtered candidate list.
    pub fn select_from_all(&self) -> Option<SelectionResult> {
        let obs_store = self.observations.read().unwrap();
        let candidates: Vec<PeerId> = obs_store.iter().map(|o| o.peer_id).collect();
        drop(obs_store);
        self.select(&candidates)
    }

    /// Returns a reference to the scoring weights.
    #[must_use]
    pub fn weights(&self) -> &ScoringWeights {
        &self.weights
    }
}

impl std::fmt::Debug for BestScoreSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BestScoreSelector")
            .field("weights", &self.weights)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::observations::PeerObservation;

    fn make_selector() -> (BestScoreSelector, Arc<std::sync::RwLock<ObservationStore>>) {
        let store = Arc::new(std::sync::RwLock::new(ObservationStore::new()));
        let selector = BestScoreSelector::new(Arc::clone(&store));
        (selector, store)
    }

    #[test]
    fn empty_candidates_returns_none() {
        let (selector, _) = make_selector();
        assert!(selector.select(&[]).is_none());
    }

    #[test]
    fn single_candidate_selected() {
        let (selector, _) = make_selector();
        let result = selector.select(&[[1u8; 32]]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().gateway_id, [1u8; 32]);
    }

    #[test]
    fn selects_fastest_gateway() {
        let (selector, store) = make_selector();

        // Gateway A: 100ms latency
        let mut a = PeerObservation::new([1u8; 32]);
        a.record_latency(100.0);
        a.record_seen();

        // Gateway B: 20ms latency
        let mut b = PeerObservation::new([2u8; 32]);
        b.record_latency(20.0);
        b.record_seen();

        // Gateway C: 10ms latency but 50% reliability
        let mut c = PeerObservation::new([3u8; 32]);
        c.record_latency(10.0);
        c.record_seen();
        for _ in 0..5 {
            c.record_circuit_success();
        }
        for _ in 0..5 {
            c.record_circuit_failure();
        }

        store.write().unwrap().upsert(a);
        store.write().unwrap().upsert(b);
        store.write().unwrap().upsert(c);

        let result = selector.select(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert!(result.is_some());
        let result = result.unwrap();

        // B (20ms, reliable) should beat C (10ms but 50% reliability)
        // because reliability is weighted 35% vs latency 25%.
        assert_eq!(
            result.gateway_id, [2u8; 32],
            "B (fast + reliable) should be selected over C (faster but unreliable)"
        );
        assert_eq!(result.candidates_considered, 3);
    }

    #[test]
    fn failure_learning_changes_selection() {
        let (selector, store) = make_selector();

        // Initially, A is slightly faster.
        let mut a = PeerObservation::new([1u8; 32]);
        a.record_latency(50.0);
        a.record_seen();

        let mut b = PeerObservation::new([2u8; 32]);
        b.record_latency(60.0);
        b.record_seen();

        store.write().unwrap().upsert(a);
        store.write().unwrap().upsert(b);

        // A should be selected (faster).
        let result = selector.select(&[[1u8; 32], [2u8; 32]]);
        assert_eq!(result.unwrap().gateway_id, [1u8; 32]);

        // Now A accumulates failures.
        {
            let mut s = store.write().unwrap();
            for _ in 0..5 {
                s.record_circuit_failure(&[1u8; 32]);
            }
        }

        // B should now be selected (reliable despite slightly higher latency).
        let result = selector.select(&[[1u8; 32], [2u8; 32]]);
        assert_eq!(
            result.unwrap().gateway_id, [2u8; 32],
            "B should be selected after A accumulates failures"
        );
    }

    #[test]
    fn loaded_gateway_score_lower() {
        let (selector, store) = make_selector();

        // Both have same latency, but A has 20 active circuits.
        let mut a = PeerObservation::new([1u8; 32]);
        a.record_latency(50.0);
        a.record_seen();
        for _ in 0..20 {
            a.record_circuit_success();
        }

        let mut b = PeerObservation::new([2u8; 32]);
        b.record_latency(50.0);
        b.record_seen();

        store.write().unwrap().upsert(a);
        store.write().unwrap().upsert(b);

        let result = selector.select(&[[1u8; 32], [2u8; 32]]);
        assert_eq!(
            result.unwrap().gateway_id, [2u8; 32],
            "B (idle) should be selected over A (loaded with 20 circuits)"
        );
    }
}
