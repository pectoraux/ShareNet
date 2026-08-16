//! **N2.5.1 — Route Observation.**
//!
//! Like [`PeerObservation`], but for complete paths (routes). A route is
//! identified by its sequence of hops (`Vec<PeerId>`). The
//! [`RouteObservation`] records measurements for the path as a whole —
//! not just individual peers.
//!
//! ## Distinction from N2.4
//!
//! N2.4 asks: "Is Gateway B good?"
//!
//! N2.5 asks: "Is path A→B→C→G good?"
//!
//! A route can be bad even if all its peers are individually good — for
//! example, if the link between B and C has high latency. Route-level
//! observation captures this.

use super::observations::{MovingAverage, PeerId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A route identifier — the SHA-256 hash of the canonical encoding of the
/// hop sequence. This is a cryptographic hash, so collisions are
/// computationally infeasible (2^-128 birthday bound).
///
/// The canonical encoding is: for each hop, the 32-byte NodeId, prefixed
/// by a 1-byte position counter. This ensures that two routes with the
/// same hops in different orders produce different RouteIds.
pub type RouteId = [u8; 32];

/// Compute a `RouteId` from a sequence of hops.
///
/// Uses SHA-256 over a canonical encoding with:
/// - Domain separator: `b"ShareNet/RouteId/v1"` (prevents cross-protocol
///   collision if RouteIds are used in other contexts).
/// - Hop count as u64 (prevents ambiguity about route length).
/// - Each hop prefixed with its position as u32 (supports up to 4 billion
///   hops, not just 256).
///
/// Two routes with the same hops in the same order always produce the
/// same `RouteId`; routes with different hops or different orderings
/// produce different `RouteId`s (with overwhelming probability).
#[must_use]
pub fn route_id_from_hops(hops: &[PeerId]) -> RouteId {
    let mut hasher = Sha256::new();

    // Domain separator — prevents cross-protocol collision.
    hasher.update(b"ShareNet/RouteId/v1");

    // Hop count as u64 big-endian — prevents ambiguity about route length.
    let hop_count = hops.len() as u64;
    hasher.update(hop_count.to_be_bytes());

    // Each hop: position (u32 big-endian) + 32-byte NodeId.
    // u32 supports up to 4 billion hops (not just 256).
    for (pos, hop) in hops.iter().enumerate() {
        hasher.update((pos as u32).to_be_bytes());
        hasher.update(hop);
    }

    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// The observation record for a complete route (path through the mesh).
///
/// Records measurements for the path as a whole. The individual peers
/// in the route also have their own [`PeerObservation`]s in the N2.4
/// [`ObservationStore`].
#[derive(Debug, Clone)]
pub struct RouteObservation {
    /// The route identifier.
    pub route_id: RouteId,
    /// The hop sequence (PeerIds from source to destination, inclusive).
    pub hops: Vec<PeerId>,

    // ── Transport quality ───────────────────────────────────────────────
    /// EWMA of end-to-end latency in milliseconds.
    pub latency_ms: MovingAverage,
    /// EWMA of packet loss fraction (0.0 = no loss, 1.0 = total loss).
    pub packet_loss: MovingAverage,
    /// EWMA of throughput in bytes/second.
    pub throughput_bps: MovingAverage,

    // ── Reliability ─────────────────────────────────────────────────────
    /// Total circuits successfully established through this route.
    pub successful_circuits: u64,
    /// Total circuits that failed through this route.
    pub failed_circuits: u64,
    /// When this route was last used successfully.
    pub last_success: Option<Instant>,

    // ── Metadata ────────────────────────────────────────────────────────
    /// Number of telemetry samples collected (latency, loss, throughput
    /// measurements). This is NOT the same as circuit attempts — a single
    /// circuit can produce many telemetry samples.
    ///
    /// **N2.5-R.1:** Confidence is based on `circuit_attempts`, NOT
    /// `samples`. A route with 10 latency samples but 0 circuit attempts
    /// has confidence 0.0.
    pub samples: u64,
    /// **N2.5-R.1** — Total number of circuit attempts (successful +
    /// failed). This is the authoritative count for confidence scoring.
    /// Only actual circuit establishments/failures increment this —
    /// passive telemetry (latency, loss, throughput) does NOT.
    pub circuit_attempts: u64,
    /// When this observation was last updated.
    pub updated_at: Instant,
}

impl RouteObservation {
    /// Create a new, empty observation for the given route.
    #[must_use]
    pub fn new(hops: Vec<PeerId>) -> Self {
        let route_id = route_id_from_hops(&hops);
        let now = Instant::now();
        Self {
            route_id,
            hops,
            latency_ms: MovingAverage::with_default(),
            packet_loss: MovingAverage::with_default(),
            throughput_bps: MovingAverage::with_default(),
            successful_circuits: 0,
            failed_circuits: 0,
            last_success: None,
            samples: 0,
            circuit_attempts: 0,
            updated_at: now,
        }
    }

    /// Record a latency sample (milliseconds, end-to-end).
    ///
    /// **N2.5-R.1:** This does NOT increment `circuit_attempts` —
    /// latency is a telemetry measurement, not a circuit attempt.
    pub fn record_latency(&mut self, latency_ms: f64) {
        self.latency_ms.update(latency_ms);
        self.touch();
    }

    /// Record a packet loss sample (0.0–1.0).
    ///
    /// **N2.5-R.1:** This does NOT increment `circuit_attempts`.
    pub fn record_packet_loss(&mut self, loss: f64) {
        self.packet_loss.update(loss.clamp(0.0, 1.0));
        self.touch();
    }

    /// Record a throughput sample (bytes/second).
    ///
    /// **N2.5-R.1:** This does NOT increment `circuit_attempts`.
    pub fn record_throughput(&mut self, bps: f64) {
        self.throughput_bps.update(bps);
        self.touch();
    }

    /// Record a successful circuit through this route.
    ///
    /// **N2.5-R.1:** This DOES increment `circuit_attempts` — a circuit
    /// attempt is an independent route-level observation.
    pub fn record_success(&mut self) {
        self.successful_circuits += 1;
        self.circuit_attempts += 1;
        self.last_success = Some(Instant::now());
        self.touch();
    }

    /// Record a failed circuit through this route.
    ///
    /// **N2.5-R.1:** This DOES increment `circuit_attempts`.
    pub fn record_failure(&mut self) {
        self.failed_circuits += 1;
        self.circuit_attempts += 1;
        self.touch();
    }

    /// Returns the reliability fraction: `success / (success + failure)`.
    /// Returns `1.0` if no circuits have been attempted.
    #[must_use]
    pub fn reliability(&self) -> f64 {
        let total = self.successful_circuits + self.failed_circuits;
        if total == 0 {
            return 1.0;
        }
        self.successful_circuits as f64 / total as f64
    }

    /// Returns the current latency in milliseconds, or `None` if no samples.
    #[must_use]
    pub fn latency(&self) -> Option<f64> {
        self.latency_ms.value()
    }

    /// Returns the current packet loss fraction, or `None` if no samples.
    #[must_use]
    pub fn loss(&self) -> Option<f64> {
        self.packet_loss.value()
    }

    /// Returns the current throughput in bytes/second, or `None` if no samples.
    #[must_use]
    pub fn throughput(&self) -> Option<f64> {
        self.throughput_bps.value()
    }

    /// Returns the total number of circuit attempts (successful + failed).
    #[must_use]
    pub fn circuit_attempts(&self) -> u64 {
        self.circuit_attempts
    }

    /// Returns the number of hops in this route.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Update the `updated_at` timestamp and increment sample count.
    fn touch(&mut self) {
        self.samples += 1;
        self.updated_at = Instant::now();
    }
}

/// A store of route observations, indexed by `RouteId`.
#[derive(Debug, Default)]
pub struct RouteObservationStore {
    observations: HashMap<RouteId, RouteObservation>,
}

impl RouteObservationStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the observation for a route.
    #[must_use]
    pub fn get(&self, route_id: &RouteId) -> Option<&RouteObservation> {
        self.observations.get(route_id)
    }

    /// Get a mutable reference to the observation for a route. Creates a
    /// new observation if it doesn't exist.
    pub fn get_or_create(&mut self, hops: &[PeerId]) -> &mut RouteObservation {
        let route_id = route_id_from_hops(hops);
        self.observations
            .entry(route_id)
            .or_insert_with(|| RouteObservation::new(hops.to_vec()))
    }

    /// Insert or replace an observation.
    pub fn upsert(&mut self, obs: RouteObservation) {
        self.observations.insert(obs.route_id, obs);
    }

    /// Returns all observations.
    pub fn iter(&self) -> impl Iterator<Item = &RouteObservation> {
        self.observations.values()
    }

    /// Returns the number of observed routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Record a latency sample for a route. Creates the observation if needed.
    pub fn record_latency(&mut self, hops: &[PeerId], latency_ms: f64) {
        self.get_or_create(hops).record_latency(latency_ms);
    }

    /// Record a successful circuit for a route.
    pub fn record_success(&mut self, hops: &[PeerId]) {
        self.get_or_create(hops).record_success();
    }

    /// Record a failed circuit for a route.
    pub fn record_failure(&mut self, hops: &[PeerId]) {
        self.get_or_create(hops).record_failure();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_id_consistent_for_same_hops() {
        let hops = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let id1 = route_id_from_hops(&hops);
        let id2 = route_id_from_hops(&hops);
        assert_eq!(id1, id2);
    }

    #[test]
    fn route_id_different_for_different_hops() {
        let hops1 = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let hops2 = vec![[1u8; 32], [4u8; 32], [3u8; 32]];
        assert_ne!(route_id_from_hops(&hops1), route_id_from_hops(&hops2));
    }

    #[test]
    fn route_observation_starts_empty() {
        let obs = RouteObservation::new(vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(obs.successful_circuits, 0);
        assert_eq!(obs.failed_circuits, 0);
        assert!(obs.latency().is_none());
        assert_eq!(obs.reliability(), 1.0);
        assert_eq!(obs.hop_count(), 2);
    }

    #[test]
    fn reliability_calculated() {
        let mut obs = RouteObservation::new(vec![[1u8; 32]]);
        obs.record_success();
        obs.record_success();
        obs.record_failure();
        assert!((obs.reliability() - 0.6667).abs() < 0.01);
    }

    #[test]
    fn store_creates_on_demand() {
        let mut store = RouteObservationStore::new();
        assert!(store.is_empty());
        store.record_latency(&[[1u8; 32], [2u8; 32]], 50.0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_get_or_create_returns_same_entry() {
        let mut store = RouteObservationStore::new();
        let hops = vec![[1u8; 32], [2u8; 32]];
        store.get_or_create(&hops).record_success();
        store.get_or_create(&hops).record_success();
        let id = route_id_from_hops(&hops);
        assert_eq!(store.get(&id).unwrap().successful_circuits, 2);
    }
}
