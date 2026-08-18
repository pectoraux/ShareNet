//! **N2.5.3 — Route Diversity Engine.**
//!
//! Maintains a set of independent routes: primary, backup, and emergency.
//! Routes are classified by their independence — two routes that share
//! no relays are fully independent and can survive each other's failures.
//!
//! ## Classification
//!
//! ```text
//! Primary:    The highest-scoring route.
//! Backup:     The highest-scoring route with NO shared relays with primary.
//! Emergency:  The highest-scoring route with NO shared relays with primary
//!             OR backup (fallback of last resort).
//! ```
//!
//! ## Independence
//!
//! Two routes are **independent** if they share no relay NodeIds (excluding
//! the client source and gateway destination, which are necessarily shared).

use super::observations::PeerId;
use super::route_observation::RouteId;
use std::collections::HashSet;

/// A route candidate for the diversity engine.
#[derive(Debug, Clone)]
pub struct RouteCandidate {
    /// The hop sequence (PeerIds).
    pub hops: Vec<PeerId>,
    /// The route's score (higher is better).
    pub score: f64,
}

impl RouteCandidate {
    /// Create a new candidate.
    #[must_use]
    pub fn new(hops: Vec<PeerId>, score: f64) -> Self {
        Self { hops, score }
    }

    /// Returns the relay hops (excluding the first = source, and last = gateway).
    #[must_use]
    pub fn relay_hops(&self) -> &[PeerId] {
        if self.hops.len() <= 2 {
            &[]
        } else {
            &self.hops[1..self.hops.len() - 1]
        }
    }
}

/// The result of diversity classification.
#[derive(Debug, Clone)]
pub struct RouteDiversity {
    /// The primary route (highest score).
    pub primary: Option<RouteCandidate>,
    /// The backup route (highest score, no shared relays with primary).
    pub backup: Option<RouteCandidate>,
    /// The emergency route (highest score, no shared relays with primary or backup).
    pub emergency: Option<RouteCandidate>,
}

impl RouteDiversity {
    /// Returns `true` if all three tiers are populated.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.primary.is_some() && self.backup.is_some() && self.emergency.is_some()
    }

    /// Returns the number of populated tiers (0–3).
    #[must_use]
    pub fn tier_count(&self) -> usize {
        [self.primary.is_some(), self.backup.is_some(), self.emergency.is_some()]
            .iter()
            .filter(|&&b| b)
            .count()
    }
}

/// Classify a set of route candidates into primary, backup, and emergency
/// tiers based on score and independence.
///
/// Routes are sorted by score (descending). The primary is the highest-
/// scoring route. The backup is the highest-scoring route that shares no
/// relay hops with the primary. The emergency is the highest-scoring route
/// that shares no relay hops with either the primary or the backup.
#[must_use]
pub fn classify_routes(candidates: &[RouteCandidate]) -> RouteDiversity {
    if candidates.is_empty() {
        return RouteDiversity {
            primary: None,
            backup: None,
            emergency: None,
        };
    }

    // Sort by score descending.
    let mut sorted: Vec<&RouteCandidate> = candidates.iter().collect();
    sorted.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Primary: highest score.
    let primary = sorted[0];
    let primary_relays: HashSet<PeerId> = primary.relay_hops().iter().copied().collect();

    // Backup: highest score with no shared relays.
    let backup = sorted
        .iter()
        .skip(1)
        .find(|c| !shares_any_relay(c, &primary_relays));

    let backup_relays: HashSet<PeerId> = backup
        .map(|b| b.relay_hops().iter().copied().collect())
        .unwrap_or_default();

    // Emergency: highest score with no shared relays with primary OR backup.
    let emergency = sorted.iter().skip(1).find(|c| {
        !shares_any_relay(c, &primary_relays) && !shares_any_relay(c, &backup_relays)
    });

    RouteDiversity {
        primary: Some((*primary).clone()),
        backup: backup.map(|b| (*b).clone()),
        emergency: emergency.map(|e| (*e).clone()),
    }
}

/// Check if a candidate shares any relay hop with the given set.
fn shares_any_relay(candidate: &&RouteCandidate, relays: &HashSet<PeerId>) -> bool {
    candidate
        .relay_hops()
        .iter()
        .any(|h| relays.contains(h))
}

/// Check if two routes are independent (share no relay hops).
#[must_use]
pub fn are_independent(a: &[PeerId], b: &[PeerId]) -> bool {
    let a_relays = relay_hops_of(a);
    let a_set: HashSet<&PeerId> = a_relays.iter().collect();
    let b_relays = relay_hops_of(b);
    !b_relays.iter().any(|r| a_set.contains(r))
}

/// Extract relay hops from a hop sequence (exclude first = source, last = gateway).
fn relay_hops_of(hops: &[PeerId]) -> Vec<PeerId> {
    if hops.len() <= 2 {
        Vec::new()
    } else {
        hops[1..hops.len() - 1].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(hops: Vec<PeerId>, score: f64) -> RouteCandidate {
        RouteCandidate::new(hops, score)
    }

    #[test]
    fn empty_candidates_returns_empty() {
        let result = classify_routes(&[]);
        assert!(result.primary.is_none());
        assert!(result.backup.is_none());
        assert!(result.emergency.is_none());
        assert_eq!(result.tier_count(), 0);
    }

    #[test]
    fn single_candidate_primary_only() {
        let candidates = vec![make_candidate(vec![[1u8; 32], [2u8; 32], [3u8; 32]], 90.0)];
        let result = classify_routes(&candidates);
        assert!(result.primary.is_some());
        assert!(result.backup.is_none());
        assert!(result.emergency.is_none());
        assert_eq!(result.tier_count(), 1);
    }

    #[test]
    fn two_independent_routes_fill_primary_and_backup() {
        let candidates = vec![
            make_candidate(vec![[1u8; 32], [2u8; 32], [3u8; 32]], 90.0),
            make_candidate(vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]], 85.0),
        ];
        let result = classify_routes(&candidates);
        assert_eq!(result.tier_count(), 2);
        assert_eq!(result.primary.as_ref().unwrap().hops, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert_eq!(result.backup.as_ref().unwrap().hops, vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]]);
        assert!(result.emergency.is_none());
    }

    #[test]
    fn shared_relays_block_backup() {
        // Two routes share relay [2;32] — backup can't be filled.
        let candidates = vec![
            make_candidate(vec![[1u8; 32], [2u8; 32], [3u8; 32]], 90.0),
            make_candidate(vec![[1u8; 32], [2u8; 32], [4u8; 32], [3u8; 32]], 85.0),
        ];
        let result = classify_routes(&candidates);
        assert!(result.primary.is_some());
        assert!(result.backup.is_none(), "backup should be None — routes share relay [2;32]");
    }

    #[test]
    fn three_independent_routes_fill_all_tiers() {
        let candidates = vec![
            make_candidate(vec![[1u8; 32], [2u8; 32], [3u8; 32]], 90.0),
            make_candidate(vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]], 85.0),
            make_candidate(vec![[1u8; 32], [6u8; 32], [7u8; 32], [3u8; 32]], 80.0),
        ];
        let result = classify_routes(&candidates);
        assert!(result.is_complete());
        assert_eq!(result.tier_count(), 3);
    }

    #[test]
    fn are_independent_true_for_different_relays() {
        let a = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let b = vec![[1u8; 32], [5u8; 32], [6u8; 32], [4u8; 32]];
        assert!(are_independent(&a, &b));
    }

    #[test]
    fn are_independent_false_for_shared_relays() {
        let a = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let b = vec![[1u8; 32], [2u8; 32], [5u8; 32], [4u8; 32]];
        assert!(!are_independent(&a, &b));
    }
}
