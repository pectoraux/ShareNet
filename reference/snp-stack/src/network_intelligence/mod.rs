//! **N2.4 — Network Intelligence Layer.**
//!
//! Sits above the frozen transport layer. Provides observation, scoring,
//! selection, feedback, health monitoring, and failover for the ShareNet
//! network — without modifying any transport or protocol primitives.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │           Network Intelligence              │
//! │                                             │
//! │  ┌─────────────┐    ┌──────────────┐       │
//! │  │ Observation │───→│   Scoring    │       │
//! │  │   Store     │    │ (GatewayScore)│       │
//! │  └──────┬──────┘    └──────┬───────┘       │
//! │         │                  │                │
//! │         │    ┌─────────────▼──────────┐    │
//! │         │    │  BestScoreSelector     │    │
//! │         │    │  (gateway selection)   │    │
//! │         │    └─────────────┬──────────┘    │
//! │         │                  │                │
//! │  ┌──────▼──────┐    ┌──────▼───────┐       │
//! │  │  Circuit    │───→│  Failover    │       │
//! │  │  Result     │    │  Coordinator │       │
//! │  │  (feedback) │    └──────────────┘       │
//! │  └─────────────┘                           │
//! │                                             │
//! │  ┌─────────────────────────────────┐       │
//! │  │  CircuitMonitor (per-circuit    │       │
//! │  │  health: Healthy→Degraded→Failed)│       │
//! │  └─────────────────────────────────┘       │
//! └─────────────────────────────────────────────┘
//!                    │
//!                    ↓
//! ┌─────────────────────────────────────────────┐
//! │         Frozen Transport Layer              │
//! │  (snp-link, snp-crypto, snp-frames, etc.)  │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Design principles
//!
//! 1. **Observation, not reputation** — `PeerObservation` records what was
//!    measured, not trust. Scores are derived from observations.
//! 2. **Passive metrics** — the intelligence layer reads transport events
//!    and updates state. It does NOT inject packets or modify transport
//!    behavior.
//! 3. **Configurable** — scoring weights and health thresholds are
//!    configurable. No hardcoded policy.
//! 4. **Above transport** — this module imports nothing from `snp-link`,
//!    `snp-crypto`, `snp-frames`, or `snp-cbor`. It only uses `PeerId`
//!    (a 32-byte array) and `Instant`/`Duration`.

pub mod failover;
pub mod feedback;
pub mod health;
pub mod observations;
pub mod scoring;
pub mod selector;

pub use failover::{FailoverResult, GatewayFailover};
pub use feedback::{CircuitFailureReason, CircuitOutcome, CircuitResult};
pub use health::{CircuitHealth, CircuitMonitor, HealthThresholds};
pub use observations::{MovingAverage, ObservationStore, PeerId, PeerObservation};
pub use scoring::{GatewayScore, ScoringWeights};
pub use selector::{BestScoreSelector, SelectionResult};
