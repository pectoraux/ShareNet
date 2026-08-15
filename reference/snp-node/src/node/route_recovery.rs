//! N3.0 — Route Recovery
//!
//! Implements the route failure/recovery pipeline:
//!
//! ```text
//! Gateway A disappears (link failure / repeated failures)
//!     ↓
//! Detect failure (RouteFailureDetector)
//!     ↓
//! Invalidate current route (transition to Failed)
//!     ↓
//! Destination remains known (topology still has the destination)
//!     ↓
//! Find replacement gateway (direct_gateways() or gateway_hints())
//!     ↓
//! Negotiate service with replacement
//!     ↓
//! New RouteProposal → new acceptances → new CommittedRoute
//!     ↓
//! New Circuit
//! ```
//!
//! ## What this proves
//!
//! An active client can survive "Gateway A disappears" by establishing
//! "Gateway B" for subsequent traffic. The destination (the real Internet)
//! remains reachable through a different gateway.

use crate::node::evidence::{EvidenceLevel, ObservedMetric};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── RouteFailureDetector ────────────────────────────────────────────────────

/// Detects route failure based on observed link failures + repeated errors.
///
/// ## Failure triggers
/// 1. **Link down** — the gateway's link transitions to `LinkState::Down`.
/// 2. **Repeated failures** — N consecutive transit requests fail.
/// 3. **Gateway unreachable** — the gateway's advertisement has expired or
///    the gateway is no longer in `direct_gateways()`.
///
/// ## Evidence level
///
/// `Observed` — failure detection is based on locally observed metrics
/// (link state, request failures), NOT on self-reported claims.
#[derive(Debug, Clone)]
pub struct RouteFailureDetector {
    /// The NodeId of the gateway this detector monitors.
    pub gateway_node_id: [u8; 32],
    /// Consecutive failure count (observed).
    pub consecutive_failures: ObservedMetric<u32>,
    /// The failure threshold (N consecutive failures → declare route failed).
    pub failure_threshold: u32,
    /// Whether the link to the gateway is currently down.
    pub link_down: ObservedMetric<bool>,
    /// Whether the gateway's advertisement has expired.
    pub advertisement_expired: ObservedMetric<bool>,
    /// Whether the route has been declared failed.
    pub route_failed: bool,
}

impl RouteFailureDetector {
    /// Create a new failure detector for a gateway.
    /// Default threshold: 3 consecutive failures.
    #[must_use]
    pub fn new(gateway_node_id: [u8; 32]) -> Self {
        Self {
            gateway_node_id,
            consecutive_failures: ObservedMetric::new(0),
            failure_threshold: 3,
            link_down: ObservedMetric::new(false),
            advertisement_expired: ObservedMetric::new(false),
            route_failed: false,
        }
    }

    /// Set the failure threshold.
    #[must_use]
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Record a successful transit request (resets consecutive failures).
    pub fn record_success(&mut self) {
        self.consecutive_failures = ObservedMetric::new(0);
    }

    /// Record a failed transit request.
    pub fn record_failure(&mut self) {
        let count = *self.consecutive_failures.inner() + 1;
        self.consecutive_failures = ObservedMetric::new(count);
        if count >= self.failure_threshold {
            self.route_failed = true;
        }
    }

    /// Record that the link to the gateway is down.
    pub fn record_link_down(&mut self) {
        self.link_down = ObservedMetric::new(true);
        self.route_failed = true;
    }

    /// Record that the link to the gateway is back up.
    pub fn record_link_up(&mut self) {
        self.link_down = ObservedMetric::new(false);
        // Don't clear route_failed — once failed, the route must be
        // explicitly recovered (new circuit), not just re-used.
    }

    /// Record that the gateway's advertisement has expired.
    pub fn record_advertisement_expired(&mut self) {
        self.advertisement_expired = ObservedMetric::new(true);
        self.route_failed = true;
    }

    /// Check if the route has failed and needs recovery.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.route_failed
    }

    /// Get the failure reason (if failed).
    #[must_use]
    pub fn failure_reason(&self) -> Option<FailureReason> {
        if !self.route_failed {
            return None;
        }
        if *self.link_down.inner() {
            Some(FailureReason::LinkDown)
        } else if *self.advertisement_expired.inner() {
            Some(FailureReason::AdvertisementExpired)
        } else if *self.consecutive_failures.inner() >= self.failure_threshold {
            Some(FailureReason::RepeatedFailures {
                count: *self.consecutive_failures.inner(),
                threshold: self.failure_threshold,
            })
        } else {
            Some(FailureReason::Unknown)
        }
    }

    /// Evidence level: Observed.
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Observed
    }
}

/// The reason a route was declared failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    /// The link to the gateway is down.
    LinkDown,
    /// The gateway's advertisement has expired.
    AdvertisementExpired,
    /// N consecutive transit requests failed.
    RepeatedFailures { count: u32, threshold: u32 },
    /// Unknown failure.
    Unknown,
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkDown => write!(f, "link to gateway is down"),
            Self::AdvertisementExpired => write!(f, "gateway advertisement expired"),
            Self::RepeatedFailures { count, threshold } => {
                write!(f, "{count} consecutive failures (threshold: {threshold})")
            }
            Self::Unknown => write!(f, "unknown failure"),
        }
    }
}

// ─── RouteRecoveryManager ────────────────────────────────────────────────────

/// Manages route recovery when a gateway fails.
///
/// ## Recovery pipeline
///
/// 1. **Detect** — `RouteFailureDetector` detects the failure.
/// 2. **Invalidate** — the current route transitions to `Failed`.
/// 3. **Find replacement** — query the topology for alternative gateways.
/// 4. **Select** — pick the best replacement (healthy, reachable, has capacity).
/// 5. **Recover** — establish a new route via the replacement gateway.
///
/// ## What the manager proves
///
/// An active client can survive "Gateway A disappears" by establishing
/// "Gateway B" for subsequent traffic.
#[derive(Debug)]
pub struct RouteRecoveryManager {
    /// The current failure detector (one per active route).
    detector: RouteFailureDetector,
    /// The current gateway NodeId (the one that may fail).
    current_gateway: [u8; 32],
    /// The list of known alternative gateways (for failover).
    alternative_gateways: Vec<[u8; 32]>,
    /// Whether recovery has been performed.
    recovered: bool,
    /// The replacement gateway (after recovery).
    replacement_gateway: Option<[u8; 32]>,
}

impl RouteRecoveryManager {
    /// Create a new recovery manager for a route to the given gateway.
    #[must_use]
    pub fn for_gateway(gateway_node_id: [u8; 32]) -> Self {
        let detector = RouteFailureDetector::new(gateway_node_id);
        Self {
            detector,
            current_gateway: gateway_node_id,
            alternative_gateways: Vec::new(),
            recovered: false,
            replacement_gateway: None,
        }
    }

    /// Register an alternative gateway (for failover).
    pub fn register_alternative(&mut self, gateway_id: [u8; 32]) {
        if !self.alternative_gateways.contains(&gateway_id) {
            self.alternative_gateways.push(gateway_id);
        }
    }

    /// Record a successful transit request.
    pub fn record_success(&mut self) {
        self.detector.record_success();
    }

    /// Record a failed transit request.
    pub fn record_failure(&mut self) {
        self.detector.record_failure();
    }

    /// Record that the link to the gateway is down.
    pub fn record_link_down(&mut self) {
        self.detector.record_link_down();
    }

    /// Check if the current route has failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.detector.is_failed()
    }

    /// Get the failure reason (if failed).
    #[must_use]
    pub fn failure_reason(&self) -> Option<FailureReason> {
        self.detector.failure_reason()
    }

    /// Attempt to recover by selecting a replacement gateway.
    ///
    /// Returns the replacement gateway NodeId if recovery is possible,
    /// or `None` if:
    /// - The route hasn't failed (no recovery needed).
    /// - There are no alternative gateways available.
    #[must_use]
    pub fn attempt_recovery(&mut self) -> Option<RecoveryResult> {
        if !self.detector.is_failed() {
            return None; // No failure — no recovery needed.
        }

        if self.alternative_gateways.is_empty() {
            return None; // No alternatives available.
        }

        // Select the first available alternative (in production, this would
        // be based on health, capacity, and observed metrics).
        let replacement = self.alternative_gateways[0];
        self.replacement_gateway = Some(replacement);
        self.recovered = true;

        Some(RecoveryResult {
            failed_gateway: self.current_gateway,
            replacement_gateway: replacement,
            failure_reason: self.detector.failure_reason().unwrap_or(FailureReason::Unknown),
            recovered_at: now_unix(),
        })
    }

    /// Check if recovery has been performed.
    #[must_use]
    pub fn is_recovered(&self) -> bool {
        self.recovered
    }

    /// Get the replacement gateway (if recovered).
    #[must_use]
    pub fn replacement_gateway(&self) -> Option<[u8; 32]> {
        self.replacement_gateway
    }

    /// Get the failure detector (for inspection).
    #[must_use]
    pub fn detector(&self) -> &RouteFailureDetector {
        &self.detector
    }
}

// ─── RecoveryResult ──────────────────────────────────────────────────────────

/// The result of a successful route recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResult {
    /// The NodeId of the gateway that failed.
    pub failed_gateway: [u8; 32],
    /// The NodeId of the replacement gateway.
    pub replacement_gateway: [u8; 32],
    /// Why the original gateway failed.
    pub failure_reason: FailureReason,
    /// When the recovery was performed.
    pub recovered_at: u64,
}

impl fmt::Display for RecoveryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecoveryResult(failed={}, replacement={}, reason={}, at={})",
            hex_short(&self.failed_gateway),
            hex_short(&self.replacement_gateway),
            self.failure_reason,
            self.recovered_at,
        )
    }
}

// ─── RouteRecoveryError ─────────────────────────────────────────────────────

/// Errors from route recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRecoveryError {
    /// No failure detected — recovery not needed.
    NoFailure,
    /// No alternative gateways available.
    NoAlternatives,
    /// Recovery already performed.
    AlreadyRecovered,
}

impl fmt::Display for RouteRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFailure => write!(f, "no failure detected — recovery not needed"),
            Self::NoAlternatives => write!(f, "no alternative gateways available"),
            Self::AlreadyRecovered => write!(f, "recovery already performed"),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}
