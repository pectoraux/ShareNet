//! N2.5-T5 — Gateway Service State Model
//!
//! Separates gateway-specific **service state** from node **identity**.
//!
//! ## The problem
//!
//! The old `GatewayAdvertisement` conflates static node identity (NodeId,
//! public keys, endpoints) with dynamic gateway service state (egress
//! policy, capacity, measurements). This means changing remaining quota,
//! bandwidth, or availability requires changing the node's cryptographic
//! identity — which is wrong.
//!
//! ## The target
//!
//! ```text
//! AuthenticatedNodeRecord (static identity)
//!     └── GatewayCapability
//!             └── GatewayServiceState (dynamic)
//!                    ├── GatewayPolicy (AUTHENTICATED claim)
//!                    ├── GatewayCapacityClaim (REPORTED claim)
//!                    └── GatewayMeasurement (OBSERVED)
//! ```
//!
//! Static identity stays in `NodeAdvertisement`.
//! Dynamic gateway conditions are separate service-state objects.

use crate::node::capability::ProtocolCapability;
use crate::node::evidence::{AuthenticatedClaim, ObservedMetric, ReportedMetric, EvidenceLevel};
use std::fmt;

// ─── GatewayPolicy ──────────────────────────────────────────────────────────

/// Gateway egress policy — an AUTHENTICATED operator claim.
///
/// This is signed by the gateway operator and is stable across service
/// sessions. Changes to policy require a new signed advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPolicy {
    /// Allowed destination patterns (e.g. ["*:443"]).
    /// Empty = wildcard.
    pub allowed_destinations: Vec<String>,
    /// Allowed protocols (e.g. ["https", "dns"]).
    /// Empty = wildcard.
    pub allowed_protocols: Vec<String>,
    /// Whether charging-only mode is enabled.
    pub charging_only: bool,
    /// Whether Wi-Fi-only mode is enabled.
    pub wifi_only: bool,
    /// Trusted peer NodeIds (empty = open to all).
    pub trusted_peers: Vec<[u8; 32]>,
}

impl GatewayPolicy {
    /// Create a wildcard policy (allow everything, open to all).
    #[must_use]
    pub fn wildcard() -> Self {
        Self {
            allowed_destinations: vec![],
            allowed_protocols: vec![],
            charging_only: false,
            wifi_only: false,
            trusted_peers: vec![],
        }
    }

    /// Evidence level: Authenticated (signed by gateway operator).
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Authenticated
    }

    /// N2.7: Check if a destination is allowed by this policy.
    /// Delegates to the same logic as `PolicyConstraint::destination_allowed`.
    #[must_use]
    pub fn destination_allowed(&self, destination: &str) -> bool {
        if self.allowed_destinations.is_empty() {
            return true; // wildcard
        }
        self.allowed_destinations.iter().any(|pattern| {
            pattern == destination
                || pattern == "*"
                || pattern == "*:*"
                || destination_matches_pattern(destination, pattern)
        })
    }

    /// N2.7: Check if a protocol is allowed by this policy.
    #[must_use]
    pub fn protocol_allowed(&self, protocol: &str) -> bool {
        if self.allowed_protocols.is_empty() {
            return true; // wildcard
        }
        self.allowed_protocols.iter().any(|p| p == protocol || p == "*")
    }
}

/// Simple glob matching: "*" matches any sequence.
fn destination_matches_pattern(dest: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        if let Some(suffix) = pattern.strip_prefix('*') {
            return dest.ends_with(suffix);
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return dest.starts_with(prefix);
        }
    }
    dest == pattern
}

impl Default for GatewayPolicy {
    fn default() -> Self {
        Self::wildcard()
    }
}

// ─── GatewayCapacityClaim ──────────────────────────────────────────────────

/// Gateway capacity claim — a REPORTED operator claim.
///
/// This is what the gateway CLAIMS it can provide. A malicious gateway
/// can set any value. The network MUST NOT treat these as trusted without
/// external verification (measurements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayCapacityClaim {
    /// Maximum concurrent circuits the gateway will accept.
    pub max_circuits: ReportedMetric<u64>,
    /// Maximum bandwidth in bits per second.
    pub max_bandwidth_bps: ReportedMetric<u64>,
    /// Remaining quota in bytes (None = unlimited).
    pub remaining_quota_bytes: ReportedMetric<Option<u64>>,
    /// Availability schedule (e.g. "24/7" or "09:00-17:00 UTC").
    pub availability_schedule: String,
}

impl GatewayCapacityClaim {
    /// Create a capacity claim with reported values.
    #[must_use]
    pub fn new(
        max_circuits: u64,
        max_bandwidth_bps: u64,
        remaining_quota_bytes: Option<u64>,
        availability_schedule: String,
    ) -> Self {
        Self {
            max_circuits: ReportedMetric::new(max_circuits),
            max_bandwidth_bps: ReportedMetric::new(max_bandwidth_bps),
            remaining_quota_bytes: ReportedMetric::new(remaining_quota_bytes),
            availability_schedule,
        }
    }

    /// Evidence level: Reported (untrusted gateway claim).
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Reported
    }

    /// Check if the gateway claims to have remaining quota.
    #[must_use]
    pub fn claims_remaining_quota(&self) -> bool {
        match self.remaining_quota_bytes.inner() {
            None => true,
            Some(0) => false,
            Some(_) => true,
        }
    }
}

impl Default for GatewayCapacityClaim {
    fn default() -> Self {
        Self::new(100, 1_000_000, None, "24/7".to_string())
    }
}

// ─── GatewayMeasurement ─────────────────────────────────────────────────────

/// Gateway service measurement — an OBSERVED metric.
///
/// These are metrics measured by THIS node (or the network) through actual
/// interaction with the gateway. They are NOT self-reported; they are
/// routing evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayMeasurement {
    /// Observed round-trip time in milliseconds.
    pub observed_rtt_ms: ObservedMetric<Option<u64>>,
    /// Observed success rate (0.0–1.0).
    pub observed_success_rate: ObservedMetric<Option<f64>>,
    /// Observed throughput in bits per second.
    pub observed_throughput_bps: ObservedMetric<Option<u64>>,
    /// Number of completed transit requests.
    pub completed_requests: ObservedMetric<u64>,
    /// Number of failed transit requests.
    pub failed_requests: ObservedMetric<u64>,
}

impl GatewayMeasurement {
    /// Create a fresh measurement (no observations yet).
    #[must_use]
    pub fn new() -> Self {
        Self {
            observed_rtt_ms: ObservedMetric::new(None),
            observed_success_rate: ObservedMetric::new(None),
            observed_throughput_bps: ObservedMetric::new(None),
            completed_requests: ObservedMetric::new(0),
            failed_requests: ObservedMetric::new(0),
        }
    }

    /// Record a successful transit request.
    pub fn record_success(&mut self, rtt_ms: u64, throughput_bps: u64) {
        self.observed_rtt_ms = ObservedMetric::new(Some(rtt_ms));
        self.observed_throughput_bps = ObservedMetric::new(Some(throughput_bps));
        self.completed_requests = ObservedMetric::new(self.completed_requests.inner().saturating_add(1));
        self.recompute_success_rate();
    }

    /// Record a failed transit request.
    pub fn record_failure(&mut self) {
        self.failed_requests = ObservedMetric::new(self.failed_requests.inner().saturating_add(1));
        self.recompute_success_rate();
    }

    fn recompute_success_rate(&mut self) {
        let total = *self.completed_requests.inner() + *self.failed_requests.inner();
        if total == 0 {
            self.observed_success_rate = ObservedMetric::new(None);
        } else {
            let success = *self.completed_requests.inner();
            let rate = f64::from(success as u32) / f64::from(total as u32);
            self.observed_success_rate = ObservedMetric::new(Some(rate));
        }
    }

    /// Evidence level: Observed (measured by this node).
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Observed
    }
}

impl Default for GatewayMeasurement {
    fn default() -> Self {
        Self::new()
    }
}

// ─── GatewayServiceState ────────────────────────────────────────────────────

/// The complete dynamic service state of a gateway.
///
/// This is SEPARATE from the gateway's static node identity
/// (`NodeAdvertisement` / `AuthenticatedNodeRecord`).
///
/// ```text
/// AuthenticatedNodeRecord (static identity)
///     └── GatewayCapability
///             └── GatewayServiceState (dynamic)
///                    ├── policy: GatewayPolicy (AUTHENTICATED)
///                    ├── capacity: GatewayCapacityClaim (REPORTED)
///                    └── measurement: GatewayMeasurement (OBSERVED)
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayServiceState {
    /// The NodeId of the gateway this state belongs to.
    pub gateway_node_id: [u8; 32],
    /// The gateway capability this state is for.
    pub capability: ProtocolCapability,
    /// Egress policy (authenticated operator claim).
    pub policy: AuthenticatedClaim<GatewayPolicy>,
    /// Capacity claim (reported, untrusted).
    pub capacity: GatewayCapacityClaim,
    /// Measurements (observed by this node).
    pub measurement: GatewayMeasurement,
    /// When this service state was last updated (unix seconds).
    pub updated_at: u64,
}

impl GatewayServiceState {
    /// Create a new gateway service state.
    #[must_use]
    pub fn new(
        gateway_node_id: [u8; 32],
        capability: ProtocolCapability,
        policy: GatewayPolicy,
        capacity: GatewayCapacityClaim,
        updated_at: u64,
    ) -> Self {
        Self {
            gateway_node_id,
            capability,
            policy: AuthenticatedClaim::new(policy),
            capacity,
            measurement: GatewayMeasurement::new(),
            updated_at,
        }
    }

    /// Record a successful transit measurement.
    pub fn record_success(&mut self, rtt_ms: u64, throughput_bps: u64, now: u64) {
        self.measurement.record_success(rtt_ms, throughput_bps);
        self.updated_at = now;
    }

    /// Record a failed transit measurement.
    pub fn record_failure(&mut self, now: u64) {
        self.measurement.record_failure();
        self.updated_at = now;
    }

    /// Check if the gateway is healthy based on observed measurements.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        if let Some(rate) = self.measurement.observed_success_rate.inner() {
            // If we have observations, require > 50% success rate.
            if *rate < 0.5 {
                return false;
            }
        }
        // If no observations yet, we can't say it's unhealthy.
        true
    }

    /// Get the evidence level summary for this service state.
    #[must_use]
    pub fn evidence_summary(&self) -> GatewayServiceEvidenceSummary {
        GatewayServiceEvidenceSummary {
            policy_level: GatewayPolicy::evidence_level(),
            capacity_level: GatewayCapacityClaim::evidence_level(),
            measurement_level: GatewayMeasurement::evidence_level(),
        }
    }
}

impl fmt::Display for GatewayServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GatewayServiceState({})", self.capability.to_byte())
    }
}

// ─── GatewayServiceEvidenceSummary ──────────────────────────────────────────

/// Summary of evidence levels for the three components of gateway service state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayServiceEvidenceSummary {
    pub policy_level: EvidenceLevel,
    pub capacity_level: EvidenceLevel,
    pub measurement_level: EvidenceLevel,
}

impl fmt::Display for GatewayServiceEvidenceSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "policy={}, capacity={}, measurement={}",
            self.policy_level, self.capacity_level, self.measurement_level
        )
    }
}

// ─── GatewayServiceDirectory ────────────────────────────────────────────────

/// A directory of gateway service states, keyed by gateway NodeId.
/// This replaces the old `known_gateways: Vec<GatewayAdvertisement>`
/// conflation on the Node struct.
#[derive(Debug, Clone, Default)]
pub struct GatewayServiceDirectory {
    states: std::collections::HashMap<[u8; 32], GatewayServiceState>,
}

impl GatewayServiceDirectory {
    /// Create an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            states: std::collections::HashMap::new(),
        }
    }

    /// Insert or update a gateway service state.
    pub fn upsert(&mut self, state: GatewayServiceState) {
        self.states.insert(state.gateway_node_id, state);
    }

    /// Get a gateway service state by NodeId.
    #[must_use]
    pub fn get(&self, gateway_node_id: &[u8; 32]) -> Option<&GatewayServiceState> {
        self.states.get(gateway_node_id)
    }

    /// Get a mutable gateway service state by NodeId.
    pub fn get_mut(&mut self, gateway_node_id: &[u8; 32]) -> Option<&mut GatewayServiceState> {
        self.states.get_mut(gateway_node_id)
    }

    /// Remove a gateway service state.
    pub fn remove(&mut self, gateway_node_id: &[u8; 32]) -> Option<GatewayServiceState> {
        self.states.remove(gateway_node_id)
    }

    /// List all known gateway NodeIds.
    #[must_use]
    pub fn gateway_ids(&self) -> Vec<[u8; 32]> {
        self.states.keys().copied().collect()
    }

    /// Count of known gateway service states.
    #[must_use]
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Is the directory empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// List all healthy gateways (based on observed measurements).
    #[must_use]
    pub fn healthy_gateways(&self) -> Vec<[u8; 32]> {
        self.states
            .iter()
            .filter(|(_, state)| state.is_healthy())
            .map(|(id, _)| *id)
            .collect()
    }
}
