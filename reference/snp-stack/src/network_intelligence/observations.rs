//! **N2.4.1 — Network Observation.**
//!
//! Every peer/gateway gets a continuously updated observation record. This is
//! **observation, not reputation** — it records what was measured, not how
//! much the peer is trusted.
//!
//! ## Design
//!
//! - [`PeerObservation`] — the observation record for one peer.
//! - [`MovingAverage`] — an exponentially-weighted moving average (EWMA) for
//!   smooth latency/jitter tracking.
//! - [`ObservationStore`] — a collection of `PeerObservation`s indexed by
//!   `NodeId`, with update/query methods.
//!
//! ## What is observed
//!
//! - **Availability**: `last_seen`, `uptime`
//! - **Transport**: `latency_ms`, `jitter_ms`, `packet_loss`
//! - **Capacity**: `active_circuits`, `active_streams`, `bytes_forwarded`
//! - **Reliability**: `successful_circuits`, `failed_circuits`
//!
//! ## What is NOT here
//!
//! - Trust scores (that's reputation, not observation)
//! - Subjective ratings
//! - Economic value
//!
//! These are pure measurements. The [`crate::scoring`] module turns them
//! into scores.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A 32-byte ShareNet NodeId (SHA-256 of the node's Ed25519 public key).
pub type PeerId = [u8; 32];

/// An exponentially-weighted moving average (EWMA).
///
/// Updates are O(1). The smoothing factor `alpha` (0.0–1.0) controls how
/// quickly the average adapts to new values:
/// - `alpha = 1.0` — no smoothing (the average is always the latest value)
/// - `alpha = 0.1` — slow adaptation (90% old, 10% new)
/// - `alpha = 0.3` — moderate adaptation (default)
#[derive(Debug, Clone)]
pub struct MovingAverage {
    /// The current average value. `None` until the first update.
    value: Option<f64>,
    /// The smoothing factor (0.0–1.0).
    alpha: f64,
}

impl Default for MovingAverage {
    fn default() -> Self {
        Self {
            value: None,
            alpha: 0.3,
        }
    }
}

impl MovingAverage {
    /// Create a new EWMA with the given smoothing factor.
    ///
    /// # Panics
    /// Panics if `alpha` is not in `[0.0, 1.0]`.
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&alpha),
            "alpha must be in [0.0, 1.0], got {alpha}"
        );
        Self { value: None, alpha }
    }

    /// Create a new EWMA with the default smoothing (alpha = 0.3).
    #[must_use]
    pub fn with_default() -> Self {
        Self::default()
    }

    /// Update the average with a new sample.
    pub fn update(&mut self, sample: f64) {
        match self.value {
            None => self.value = Some(sample),
            Some(old) => {
                self.value = Some(self.alpha * sample + (1.0 - self.alpha) * old);
            }
        }
    }

    /// Returns the current average, or `None` if no samples have been added.
    #[must_use]
    pub fn value(&self) -> Option<f64> {
        self.value
    }

    /// Returns the current average, or `default` if no samples.
    #[must_use]
    pub fn value_or(&self, default: f64) -> f64 {
        self.value.unwrap_or(default)
    }

    /// Reset the average to `None` (no samples).
    pub fn reset(&mut self) {
        self.value = None;
    }
}

/// The observation record for one peer (gateway or relay).
///
/// This is **pure observation** — it records what was measured, not how
/// much the peer is trusted. The [`crate::scoring`] module turns these
/// observations into a [`crate::scoring::GatewayScore`].
#[derive(Debug, Clone)]
pub struct PeerObservation {
    /// The peer's NodeId.
    pub peer_id: PeerId,

    // ── Availability ────────────────────────────────────────────────────
    /// When this peer was last seen (any activity). `None` if never.
    pub last_seen: Option<Instant>,
    /// Total observed uptime (accumulated across sessions). This is NOT
    /// wall-clock time since first seen — it is the sum of durations during
    /// which the peer was reachable.
    pub uptime: Duration,

    // ── Transport quality ───────────────────────────────────────────────
    /// EWMA of round-trip latency in milliseconds.
    pub latency_ms: MovingAverage,
    /// EWMA of jitter (latency variation) in milliseconds.
    pub jitter_ms: MovingAverage,
    /// EWMA of packet loss fraction (0.0 = no loss, 1.0 = total loss).
    pub packet_loss: MovingAverage,

    // ── Capacity ────────────────────────────────────────────────────────
    /// Number of currently-active circuits through this peer.
    pub active_circuits: u32,
    /// Number of currently-active streams through this peer.
    pub active_streams: u32,
    /// Total bytes forwarded through this peer (cumulative).
    pub bytes_forwarded: u64,

    // ── Reliability ─────────────────────────────────────────────────────
    /// Total circuits successfully established through this peer.
    pub successful_circuits: u64,
    /// Total circuits that failed through this peer.
    pub failed_circuits: u64,

    /// When this observation was last updated.
    pub updated_at: Instant,
}

impl PeerObservation {
    /// Create a new, empty observation for the given peer.
    #[must_use]
    pub fn new(peer_id: PeerId) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            last_seen: None,
            uptime: Duration::ZERO,
            latency_ms: MovingAverage::with_default(),
            jitter_ms: MovingAverage::with_default(),
            packet_loss: MovingAverage::with_default(),
            active_circuits: 0,
            active_streams: 0,
            bytes_forwarded: 0,
            successful_circuits: 0,
            failed_circuits: 0,
            updated_at: now,
        }
    }

    /// Record a latency sample (milliseconds). Updates the latency EWMA
    /// and the jitter EWMA (based on the difference from the previous
    /// latency sample).
    pub fn record_latency(&mut self, latency_ms: f64) {
        let prev = self.latency_ms.value();
        self.latency_ms.update(latency_ms);
        // Jitter = absolute difference from the previous latency sample.
        if let Some(prev) = prev {
            let delta = (latency_ms - prev).abs();
            self.jitter_ms.update(delta);
        }
        self.touch();
    }

    /// Record a packet loss sample (0.0 = no loss, 1.0 = total loss).
    pub fn record_packet_loss(&mut self, loss: f64) {
        let clamped = loss.clamp(0.0, 1.0);
        self.packet_loss.update(clamped);
        self.touch();
    }

    /// Record a successful circuit establishment.
    pub fn record_circuit_success(&mut self) {
        self.successful_circuits += 1;
        self.active_circuits = self.active_circuits.saturating_add(1);
        self.last_seen = Some(Instant::now());
        self.touch();
    }

    /// Record a failed circuit establishment.
    pub fn record_circuit_failure(&mut self) {
        self.failed_circuits += 1;
        self.touch();
    }

    /// Record that a circuit was closed (decrement active count).
    pub fn record_circuit_closed(&mut self) {
        self.active_circuits = self.active_circuits.saturating_sub(1);
        self.touch();
    }

    /// Record bytes forwarded through this peer.
    pub fn record_bytes(&mut self, bytes: u64) {
        self.bytes_forwarded = self.bytes_forwarded.saturating_add(bytes);
        self.touch();
    }

    /// Record that the peer was seen (updates `last_seen` and `uptime`).
    pub fn record_seen(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_seen {
            let elapsed = now.duration_since(last);
            // Accumulate uptime only if the gap is reasonable (< 60s).
            // Larger gaps suggest the peer was unreachable between observations.
            if elapsed < Duration::from_secs(60) {
                self.uptime += elapsed;
            }
        }
        self.last_seen = Some(now);
        self.touch();
    }

    /// Returns the reliability fraction: `successful / (successful + failed)`.
    /// Returns `1.0` if no circuits have been attempted (no data = assume
    /// reliable until proven otherwise).
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

    /// Returns the current jitter in milliseconds, or `None` if no samples.
    #[must_use]
    pub fn jitter(&self) -> Option<f64> {
        self.jitter_ms.value()
    }

    /// Returns the current packet loss fraction, or `None` if no samples.
    #[must_use]
    pub fn loss(&self) -> Option<f64> {
        self.packet_loss.value()
    }

    /// Returns the availability fraction based on uptime vs total observed
    /// time. If the peer has never been seen, returns 0.0.
    #[must_use]
    pub fn availability(&self, now: Instant) -> f64 {
        match self.last_seen {
            None => 0.0,
            Some(last) => {
                let total = now.duration_since(last);
                if total.is_zero() {
                    return 1.0;
                }
                let ratio = self.uptime.as_secs_f64() / total.as_secs_f64();
                ratio.clamp(0.0, 1.0)
            }
        }
    }

    /// Update the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = Instant::now();
    }
}

/// A store of peer observations, indexed by `PeerId`.
///
/// This is the central observation registry. The client maintains one
/// `ObservationStore`, updates it as circuits are established and data
/// flows, and passes it to the [`crate::selector::BestScoreSelector`] for
/// gateway selection.
#[derive(Debug, Default)]
pub struct ObservationStore {
    observations: HashMap<PeerId, PeerObservation>,
}

impl ObservationStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the observation for a peer.
    #[must_use]
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerObservation> {
        self.observations.get(peer_id)
    }

    /// Get a mutable reference to the observation for a peer. If the peer
    /// is not in the store, a new empty observation is inserted.
    pub fn get_or_create(&mut self, peer_id: &PeerId) -> &mut PeerObservation {
        self.observations
            .entry(*peer_id)
            .or_insert_with(|| PeerObservation::new(*peer_id))
    }

    /// Insert or replace an observation.
    pub fn upsert(&mut self, obs: PeerObservation) {
        self.observations.insert(obs.peer_id, obs);
    }

    /// Returns all observations.
    pub fn iter(&self) -> impl Iterator<Item = &PeerObservation> {
        self.observations.values()
    }

    /// Returns the number of observed peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Record a latency sample for a peer. Creates the observation if it
    /// doesn't exist.
    pub fn record_latency(&mut self, peer_id: &PeerId, latency_ms: f64) {
        self.get_or_create(peer_id).record_latency(latency_ms);
    }

    /// Record a successful circuit for a peer.
    pub fn record_circuit_success(&mut self, peer_id: &PeerId) {
        self.get_or_create(peer_id).record_circuit_success();
    }

    /// Record a failed circuit for a peer.
    pub fn record_circuit_failure(&mut self, peer_id: &PeerId) {
        self.get_or_create(peer_id).record_circuit_failure();
    }

    /// Record that a circuit was closed for a peer.
    pub fn record_circuit_closed(&mut self, peer_id: &PeerId) {
        self.get_or_create(peer_id).record_circuit_closed();
    }

    /// Record bytes forwarded through a peer.
    pub fn record_bytes(&mut self, peer_id: &PeerId, bytes: u64) {
        self.get_or_create(peer_id).record_bytes(bytes);
    }

    /// Record that a peer was seen.
    pub fn record_seen(&mut self, peer_id: &PeerId) {
        self.get_or_create(peer_id).record_seen();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moving_average_starts_none() {
        let ma = MovingAverage::with_default();
        assert!(ma.value().is_none());
    }

    #[test]
    fn moving_average_first_sample() {
        let mut ma = MovingAverage::with_default();
        ma.update(100.0);
        assert_eq!(ma.value(), Some(100.0));
    }

    #[test]
    fn moving_average_ewma() {
        let mut ma = MovingAverage::new(0.5);
        ma.update(100.0);
        ma.update(200.0);
        // 0.5 * 200 + 0.5 * 100 = 150
        assert!((ma.value().unwrap() - 150.0).abs() < 0.001);
    }

    #[test]
    fn peer_obsation_starts_empty() {
        let obs = PeerObservation::new([1u8; 32]);
        assert_eq!(obs.successful_circuits, 0);
        assert_eq!(obs.failed_circuits, 0);
        assert!(obs.latency().is_none());
        assert_eq!(obs.reliability(), 1.0); // No data = assume reliable
    }

    #[test]
    fn record_latency_updates_jitter() {
        let mut obs = PeerObservation::new([1u8; 32]);
        obs.record_latency(100.0);
        assert!(obs.jitter().is_none()); // No jitter on first sample
        obs.record_latency(110.0);
        assert!((obs.jitter().unwrap() - 10.0).abs() < 0.001);
    }

    #[test]
    fn reliability_calculated() {
        let mut obs = PeerObservation::new([1u8; 32]);
        obs.record_circuit_success();
        obs.record_circuit_success();
        obs.record_circuit_failure();
        // 2 / 3 = 0.666...
        assert!((obs.reliability() - 0.6667).abs() < 0.01);
    }

    #[test]
    fn observation_store_creates_on_demand() {
        let mut store = ObservationStore::new();
        assert!(store.is_empty());
        store.record_latency(&[1u8; 32], 50.0);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&[1u8; 32]).unwrap().latency(), Some(50.0));
    }

    #[test]
    fn bytes_accumulate() {
        let mut store = ObservationStore::new();
        store.record_bytes(&[1u8; 32], 1000);
        store.record_bytes(&[1u8; 32], 2000);
        assert_eq!(store.get(&[1u8; 32]).unwrap().bytes_forwarded, 3000);
    }
}
