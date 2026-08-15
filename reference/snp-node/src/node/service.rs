//! N2.5-T4 — Service / Capability Negotiation
//!
//! Replaces the old `ServiceAgreement` (typed but NOT negotiated) with a
//! full negotiation pipeline:
//!
//! ```text
//! route candidate
//!     ↓
//! ServiceRequirement (what the client needs)
//!     ↓
//! CapabilityOffer (what the gateway/relay can provide)
//!     ↓
//! PolicyConstraint (egress, destinations, protocols)
//!     ↓
//! CapacityConstraint (bandwidth, quota, connections)
//!     ↓
//! ServiceAgreement (matched + signed terms)
//!     ↓
//! Route Proposal
//! ```
//!
//! A route cannot be committed merely because the destination advertises
//! `Gateway`. The route must establish that the requested service is
//! permitted and supported.

use crate::node::capability::ProtocolCapability;
use crate::node::evidence::{ReportedMetric, EvidenceLevel};
use std::fmt;

// ─── ServiceRequirement ──────────────────────────────────────────────────────

/// What a client needs from the network service.
/// This is the CLIENT's side of the negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRequirement {
    /// The capability the client needs (e.g. InternetGateway for transit).
    pub capability: ProtocolCapability,
    /// Required destination patterns (e.g. ["*:443"] for HTTPS).
    pub required_destinations: Vec<String>,
    /// Required protocols (e.g. ["https", "dns"]).
    pub required_protocols: Vec<String>,
    /// Minimum bandwidth required (bits per second).
    pub min_bandwidth_bps: Option<u64>,
    /// Maximum acceptable latency (milliseconds).
    pub max_latency_ms: Option<u64>,
}

impl ServiceRequirement {
    /// Create a basic Internet gateway transit requirement.
    #[must_use]
    pub fn internet_gateway() -> Self {
        Self {
            capability: ProtocolCapability::InternetGateway,
            required_destinations: vec!["*:443".to_string()],
            required_protocols: vec!["https".to_string()],
            min_bandwidth_bps: None,
            max_latency_ms: None,
        }
    }

    /// Check if this requirement is satisfied by the given offer + constraints.
    #[must_use]
    pub fn is_satisfied_by(
        &self,
        offer: &CapabilityOffer,
        policy: &PolicyConstraint,
        capacity: &CapacityConstraint,
    ) -> bool {
        // 1. Capability match.
        if !offer.capabilities.contains(&self.capability) {
            return false;
        }

        // 2. Destination check: every required destination must be allowed
        //    by the policy.
        for req_dest in &self.required_destinations {
            if !policy.destination_allowed(req_dest) {
                return false;
            }
        }

        // 3. Protocol check.
        for req_proto in &self.required_protocols {
            if !policy.protocol_allowed(req_proto) {
                return false;
            }
        }

        // 4. Bandwidth check (if the capacity claim is available).
        if let Some(min_bw) = self.min_bandwidth_bps {
            if let Some(offer_bw) = capacity.available_bandwidth_bps.inner() {
                if *offer_bw < min_bw {
                    return false;
                }
            }
        }

        // 5. Latency check (if reported).
        if let Some(max_lat) = self.max_latency_ms {
            if let Some(offer_lat) = capacity.estimated_latency_ms.inner() {
                if *offer_lat > max_lat {
                    return false;
                }
            }
        }

        true
    }
}

// ─── CapabilityOffer ────────────────────────────────────────────────────────

/// What a gateway/relay offers to provide.
/// This is the PROVIDER's side of the negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityOffer {
    /// Capabilities the node offers.
    pub capabilities: Vec<ProtocolCapability>,
    /// Service types supported (e.g. "internet-transit", "content-seed").
    pub service_types: Vec<String>,
}

impl CapabilityOffer {
    /// Create an offer for Internet gateway transit.
    #[must_use]
    pub fn internet_gateway() -> Self {
        Self {
            capabilities: vec![ProtocolCapability::InternetGateway],
            service_types: vec!["internet-transit".to_string()],
        }
    }
}

// ─── PolicyConstraint ────────────────────────────────────────────────────────

/// Egress policy constraints from the gateway.
/// This is an AUTHENTICATED claim (signed by the gateway operator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConstraint {
    /// Allowed destination patterns (e.g. ["*:443", "*.example.com"]).
    /// Empty = wildcard (all destinations allowed).
    pub allowed_destinations: Vec<String>,
    /// Allowed protocols (e.g. ["https", "dns"]).
    /// Empty = wildcard (all protocols allowed).
    pub allowed_protocols: Vec<String>,
    /// Whether charging-only mode is enabled (no free transit).
    pub charging_only: bool,
    /// Whether Wi-Fi-only mode is enabled (no mobile data transit).
    pub wifi_only: bool,
}

impl PolicyConstraint {
    /// Create a wildcard policy (allow everything).
    #[must_use]
    pub fn wildcard() -> Self {
        Self {
            allowed_destinations: vec![],
            allowed_protocols: vec![],
            charging_only: false,
            wifi_only: false,
        }
    }

    /// Check if a destination pattern is allowed by this policy.
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

    /// Check if a protocol is allowed by this policy.
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
        // Very simple wildcard: "*" at the start matches everything after.
        if let Some(suffix) = pattern.strip_prefix('*') {
            return dest.ends_with(suffix);
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return dest.starts_with(prefix);
        }
    }
    dest == pattern
}

// ─── CapacityConstraint ──────────────────────────────────────────────────────

/// Capacity constraints from the gateway.
///
/// N2.5-T3: All fields are `ReportedMetric` — the gateway CLAIMS these
/// values, but a malicious gateway can set any value. They MUST NOT be
/// used as trusted routing/security values without external verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityConstraint {
    /// Maximum circuits the gateway will accept.
    pub max_circuits: ReportedMetric<u64>,
    /// Available bandwidth in bits per second.
    pub available_bandwidth_bps: ReportedMetric<Option<u64>>,
    /// Current queue depth (number of pending requests).
    pub queue_depth: ReportedMetric<u64>,
    /// Remaining quota in bytes (None = unlimited).
    pub remaining_quota_bytes: ReportedMetric<Option<u64>>,
    /// Estimated latency in milliseconds.
    pub estimated_latency_ms: ReportedMetric<Option<u64>>,
}

impl CapacityConstraint {
    /// Create a capacity constraint with reported values.
    #[must_use]
    pub fn new(
        max_circuits: u64,
        available_bandwidth_bps: Option<u64>,
        queue_depth: u64,
        remaining_quota_bytes: Option<u64>,
        estimated_latency_ms: Option<u64>,
    ) -> Self {
        Self {
            max_circuits: ReportedMetric::new(max_circuits),
            available_bandwidth_bps: ReportedMetric::new(available_bandwidth_bps),
            queue_depth: ReportedMetric::new(queue_depth),
            remaining_quota_bytes: ReportedMetric::new(remaining_quota_bytes),
            estimated_latency_ms: ReportedMetric::new(estimated_latency_ms),
        }
    }

    /// Returns the evidence level of these capacity constraints.
    /// Always `Reported` — these are untrusted gateway claims.
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Reported
    }

    /// Check if the gateway has remaining quota (None = unlimited).
    #[must_use]
    pub fn has_remaining_quota(&self) -> bool {
        match self.remaining_quota_bytes.inner() {
            None => true, // unlimited
            Some(0) => false,
            Some(_) => true,
        }
    }
}

impl Default for CapacityConstraint {
    fn default() -> Self {
        Self::new(100, None, 0, None, None)
    }
}

// ─── ServiceAgreement (enhanced) ────────────────────────────────────────────

/// A negotiated service agreement.
///
/// N2.5-T4: This replaces the old `ServiceAgreement` (which was just a typed
/// string + empty requirements vector) with a full negotiation result that
/// records the matched requirement, offer, policy, and capacity.
///
/// The agreement is signed by all participants as part of the route proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedServiceAgreement {
    /// The client's original requirement.
    pub requirement: ServiceRequirement,
    /// The provider's offer that was matched.
    pub offer: CapabilityOffer,
    /// The policy constraint under which the service is provided.
    pub policy: PolicyConstraint,
    /// The capacity constraint at the time of agreement.
    pub capacity: CapacityConstraint,
    /// The service type string (for backward compat with the old ServiceAgreement).
    pub service_type: String,
}

impl NegotiatedServiceAgreement {
    /// Negotiate an agreement from a requirement + offer + policy + capacity.
    /// Returns `None` if the requirement is not satisfied.
    #[must_use]
    pub fn negotiate(
        requirement: ServiceRequirement,
        offer: CapabilityOffer,
        policy: PolicyConstraint,
        capacity: CapacityConstraint,
    ) -> Option<Self> {
        if !requirement.is_satisfied_by(&offer, &policy, &capacity) {
            return None;
        }
        let service_type = offer
            .service_types
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        Some(Self {
            requirement,
            offer,
            policy,
            capacity,
            service_type,
        })
    }

    /// Returns the service type string (backward compat).
    #[must_use]
    pub fn service_type(&self) -> &str {
        &self.service_type
    }

    /// Returns the requirements as a string vector (backward compat with
    /// the old `ServiceAgreement::requirements` field).
    #[must_use]
    pub fn requirements(&self) -> Vec<String> {
        let mut reqs = Vec::new();
        for dest in &self.requirement.required_destinations {
            reqs.push(format!("destination:{dest}"));
        }
        for proto in &self.requirement.required_protocols {
            reqs.push(format!("protocol:{proto}"));
        }
        if let Some(bw) = self.requirement.min_bandwidth_bps {
            reqs.push(format!("min-bandwidth:{bw}"));
        }
        if let Some(lat) = self.requirement.max_latency_ms {
            reqs.push(format!("max-latency:{lat}"));
        }
        reqs
    }
}

impl fmt::Display for NegotiatedServiceAgreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceAgreement({})", self.service_type)
    }
}

// ─── NegotiationResult ──────────────────────────────────────────────────────

/// The result of a service negotiation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationResult {
    /// Negotiation succeeded — the agreement is valid.
    Agreed(NegotiatedServiceAgreement),
    /// Negotiation failed — the requirement was not satisfied.
    Denied { reason: String },
}

impl NegotiationResult {
    /// Returns true if negotiation succeeded.
    #[must_use]
    pub fn is_agreed(&self) -> bool {
        matches!(self, Self::Agreed(_))
    }

    /// Returns the agreement if agreed, None otherwise.
    #[must_use]
    pub fn agreement(&self) -> Option<&NegotiatedServiceAgreement> {
        match self {
            Self::Agreed(a) => Some(a),
            Self::Denied { .. } => None,
        }
    }
}
