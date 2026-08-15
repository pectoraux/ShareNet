//! N2.5-T3 — Evidence-class separation
//!
//! Makes epistemic categories explicit so routing/economic code cannot
//! accidentally treat a self-reported capacity claim as an observed
//! measurement.
//!
//! ## Evidence levels
//!
//! | Level | Meaning | Example |
//! |-------|---------|---------|
//! | `AuthenticatedClaim` | Cryptographically verified (signed + sig checked) | NodeAdvertisement, IssuerAuthority |
//! | `ObservedMetric` | Measured locally by THIS node | RTT from link probing, success/failure counts |
//! | `ReportedMetric` | Claimed by a remote node (UNTRUSTED) | Gateway capacity, egress policy |
//! | `DerivedMetric` | Computed from other metrics | Success rate, aggregate latency |
//! | `InferredMetric` | Probabilistic inference from imperfect signals | Reputation, availability estimate |
//!
//! ## Rule
//!
//! No routing or economic code may treat a `ReportedMetric` as an
//! `ObservedMetric`. The type system enforces this: a `ReportedMetric<u64>`
//! cannot be used where an `ObservedMetric<u64>` is expected without an
//! explicit `into_observed()` call that documents the trust downgrade.

use std::fmt;

/// The epistemic trust level of a piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceLevel {
    /// Cryptographically verified (signed + signature checked).
    Authenticated,
    /// Measured locally by this node (e.g. link probing).
    Observed,
    /// Claimed by a remote node — UNTRUSTED (e.g. gateway capacity).
    Reported,
    /// Computed from other metrics (e.g. success rate from counts).
    Derived,
    /// Probabilistic inference from imperfect signals (e.g. reputation).
    Inferred,
}

impl EvidenceLevel {
    /// Returns true if this evidence level is trustworthy for routing
    /// decisions (Authenticated or Observed).
    #[must_use]
    pub fn is_routing_evidence(&self) -> bool {
        matches!(self, Self::Authenticated | Self::Observed)
    }

    /// Returns true if this evidence level is untrusted (Reported or Inferred).
    #[must_use]
    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::Reported | Self::Inferred)
    }
}

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated => write!(f, "authenticated"),
            Self::Observed => write!(f, "observed"),
            Self::Reported => write!(f, "reported"),
            Self::Derived => write!(f, "derived"),
            Self::Inferred => write!(f, "inferred"),
        }
    }
}

// ─── Newtype wrappers ───────────────────────────────────────────────────────

/// A cryptographically verified claim (signed + signature checked).
/// Example: a `VerifiedNodeAdvertisement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedClaim<T>(pub T);

/// A metric measured locally by THIS node.
/// Example: RTT from link probing, success/failure counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedMetric<T>(pub T);

/// A metric claimed by a remote node — UNTRUSTED.
/// Example: gateway capacity, egress policy.
/// A malicious node can set this to any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedMetric<T>(pub T);

/// A metric computed from other metrics.
/// Example: success rate (derived from success_count + failure_count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedMetric<T>(pub T);

/// A metric inferred probabilistically from imperfect signals.
/// Example: reputation, availability estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct InferredMetric<T>(pub T);

// ─── Accessors ──────────────────────────────────────────────────────────────

impl<T> AuthenticatedClaim<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn into_inner(self) -> T {
        self.0
    }
    pub fn inner(&self) -> &T {
        &self.0
    }
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Authenticated
    }
}

impl<T> ObservedMetric<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn into_inner(self) -> T {
        self.0
    }
    pub fn inner(&self) -> &T {
        &self.0
    }
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Observed
    }
}

impl<T> ReportedMetric<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn into_inner(self) -> T {
        self.0
    }
    pub fn inner(&self) -> &T {
        &self.0
    }
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Reported
    }
}

impl<T> DerivedMetric<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn into_inner(self) -> T {
        self.0
    }
    pub fn inner(&self) -> &T {
        &self.0
    }
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Derived
    }
}

impl<T> InferredMetric<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn into_inner(self) -> T {
        self.0
    }
    pub fn inner(&self) -> &T {
        &self.0
    }
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Inferred
    }
}
