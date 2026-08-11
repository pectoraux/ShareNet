//! SNP-CIVIC — L11 contribution proofs and value function
//!
//! Implements the SNP/0.1 L11 civic layer (per `01-ARCHITECTURE.md` §2.4,
//! `02-PROTOCOL-SPEC.md` §11, and `/public/spec/05-CIVIC-CONTENT-CONSISTENCY.md`).
//!
//! **Scope boundary (CRITICAL):** this crate computes a *value function* — a
//! reputation score — from contribution proofs. It does **not** do
//! settlement, it does **not** issue transferable points, and it does
//! **not** touch money. Those are 🔴 human-gated (per
//! `/public/spec/07-MIGRATION-AND-ROADMAP.md` §1.2 and §6) and live in
//! `backend/` under human control.
//!
//! What this crate does:
//! - **`ContributionProof`** — a signed record produced by a gateway
//!   (or a relay chain) attesting that a node carried N bytes for peer P at
//!   time T. Built on `TransitReceipt`s from `snp-gateway`.
//! - **Value function** — sub-linear in volume (per ADR-0005) and weighted
//!   by diversity (carrying for many distinct peers is worth more than
//!   carrying the same total for one). The output is a non-transferable
//!   per-node score, NOT a balance.
//! - **Durable fraud controls** — signature-verifying storage; the
//!   contribution store is append-only and every entry is independently
//!   verifiable. (The audit found `FraudControls.kt` used in-memory counters
//!   that reset on restart; that mistake is not repeated here.)
//!
//! This is the Rust equivalent of `/src/lib/snp/civic.ts` + parts of
//! `/src/lib/snp/receipts.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/12-civic-points.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the L11 civic layer.
#[derive(Debug, Error)]
pub enum CivicError {
    /// A contribution proof's signature failed verification.
    #[error("invalid contribution proof signature")]
    InvalidSignature,
    /// A contribution proof was already in the store (duplicate).
    #[error("duplicate contribution proof")]
    Duplicate,
    /// A contribution proof references a future timestamp.
    #[error("contribution proof timestamp in the future")]
    FutureTimestamp,
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] snp_crypto::CryptoError),
}

/// Convenience `Result` alias.
pub type CivicResult<T> = Result<T, CivicError>;

/// A contribution proof: a signed record that node `contributor` carried
/// `bytes` for `requester` at `at_time`, issued by `attester`.
#[derive(Debug, Clone)]
pub struct ContributionProof {
    /// The NodeId of the node that did the carrying (gets the credit).
    pub contributor: snp_identity::NodeId,
    /// The NodeId of the node that requested the carry.
    pub requester: snp_identity::NodeId,
    /// The NodeId of the attester (a gateway, or the next hop in the chain).
    pub attester: snp_identity::NodeId,
    /// Bytes carried.
    pub bytes: u64,
    /// Unix timestamp (seconds) at which the carry completed.
    pub at_time: u64,
    /// Nonce to make this proof unique (random 16 bytes).
    pub nonce: [u8; 16],
    /// Attester's signature over canonical CBOR of all fields above.
    pub signature: snp_crypto::Signature,
}

impl ContributionProof {
    /// Attest to a contribution. Called by the gateway or relay that observed
    /// the carry.
    pub fn attest(
        _contributor: &snp_identity::NodeId,
        _requester: &snp_identity::NodeId,
        _attester: &snp_identity::NodeId,
        _bytes: u64,
        _at_time: u64,
        _attester_secret: &snp_crypto::SecretKey,
    ) -> CivicResult<Self> {
        todo!("Build and sign a ContributionProof per SNP/0.1 §11.2")
    }

    /// Verify the attester's signature.
    pub fn verify(&self, _attester_public: &snp_crypto::PublicKey) -> CivicResult<()> {
        todo!("Verify ContributionProof signature via snp_crypto::ed25519_verify")
    }
}

/// The contribution store: append-only, signature-verifying. The audit's
/// finding of in-memory counters that reset on restart (T5, ADR-0005) is
/// corrected here.
pub struct ContributionStore;

impl ContributionStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self
    }

    /// Append a contribution proof. Returns `Err(Duplicate)` if the proof's
    /// `(attester, nonce)` pair is already present.
    pub fn append(&mut self, _proof: ContributionProof) -> CivicResult<()> {
        todo!("Append a proof, dedup on (attester, nonce), persist durably")
    }

    /// Iterate over all proofs for `contributor`.
    pub fn for_contributor(
        &self,
        _contributor: &snp_identity::NodeId,
    ) -> impl Iterator<Item = &ContributionProof> {
        // SKELETON: returns an empty iterator.
        std::iter::empty()
    }
}

impl Default for ContributionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The value function per ADR-0005 (`/public/docs/adr/0005-sublinear-volume-factor.md`)
/// and `05-CIVIC-CONTENT-CONSISTENCY.md` §A5.
///
/// The full value function is a product of six factors:
///
/// ```text
/// points = base_rate
///        × quality_factor        (interactive / bulk / background)
///        × volume_factor         (sub-linear: log₂(1 + MiB))
///        × scarcity_factor       (more reward where gateways are rare)
///        × diversity_factor      (anti-collusion: N distinct counterparties)
///        × reputation_factor     (locally computed, never accepted from peers)
///        × holdback              (30% held 30 days — I14)
/// ```
///
/// `volume_factor` is **`log₂(1 + mib)`** where `mib` is the relayed volume in
/// mebibytes. This is sub-linear: doubling volume adds 1 to the factor, it
/// does not double it. (Alternative (c) `√(1 + mib)` was considered and
/// rejected on interpretability grounds — see ADR-0005.)
///
/// The output is a non-transferable reputation score in `[0, u64::MAX]`,
/// rounded to the nearest integer (round-half-to-even per 05 §B3). It is
/// NEVER called a "balance" and NEVER transferred between nodes.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValueFunction {
    /// Base rate (points per 1 MiB at canonical baseline). Policy parameter,
    /// 🔴 human-only per 06 §B5 — this struct holds the value chosen by the
    /// operator; the Rust crate does not pick a default.
    pub base_rate: f64,
    /// Diversity factor bounds (anti-collusion): 1 counterparty →
    /// `min_diversity`, 5+ counterparties → `max_diversity`. Defaults per
    /// `civic-diversity-collapse` vector.
    pub min_diversity: f64,
    pub max_diversity: f64,
    /// Holdback fraction (e.g. 0.30 for 30%) applied to the final points
    /// value. Defaults per `civic-holdback-30-percent` vector and I14.
    pub holdback_fraction: f64,
}

impl ValueFunction {
    /// Construct the value function with the parameters pinned by the
    /// conformance vectors in `12-civic-points.json`. The `base_rate` is left
    /// to the caller because it is a 🔴 human-only policy parameter (06 §B5).
    pub fn default_per_adr_0005(base_rate: f64) -> Self {
        Self {
            base_rate,
            min_diversity: 0.2,
            max_diversity: 1.0,
            holdback_fraction: 0.30,
        }
    }

    /// Compute the volume factor `log₂(1 + mib)` per ADR-0005.
    ///
    /// At `mib = 1`: returns `1.0`. At `mib = 1000`: returns `≈9.967`.
    /// IEEE 754 `f64::log2` is deterministic across platforms for non-special
    /// inputs; the conformance vector pins 15 significant digits.
    pub fn volume_factor(_mib: f64) -> f64 {
        todo!("Compute f64::log2(1.0 + mib) per ADR-0005")
    }

    /// Compute the diversity factor for `distinct_counterparties` counterparties.
    ///
    /// Per `civic-diversity-collapse`: 1 → 0.2, 5+ → 1.0, linear in between.
    pub fn diversity_factor(&self, _distinct_counterparties: u32) -> f64 {
        todo!("Compute diversity_factor per civic-diversity-collapse vector")
    }

    /// Compute the scarcity factor given `known_gateways` in the region.
    ///
    /// Per `civic-scarcity-single-gateway`: 1 gateway → ~2.43, 10 gateways →
    /// ~1.07.
    pub fn scarcity_factor(_known_gateways: u32) -> f64 {
        todo!("Compute scarcity_factor per civic-scarcity-single-gateway vector")
    }

    /// Compute the reputation score for `contributor` given their proof set
    /// and the network context. The output is a non-transferable reputation
    /// score in `[0, u64::MAX]`, NOT a balance. Rounded half-to-even per
    /// 05 §B3.
    pub fn score(
        &self,
        _proofs: &[ContributionProof],
        _known_gateways: u32,
        _network_mean_diversity: f64,
        _reputation_factor: f64,
        _quality_factor: f64,
    ) -> CivicResult<u64> {
        todo!("Compose base_rate × quality × volume × scarcity × diversity × reputation × (1 − holdback)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/12-civic-points.json:
        //   - civic-volume-factor-sublinear: log₂(1 + mib) for mib ∈ {1,2,10,100,1000}
        //   - civic-value-computation-transit-interactive: full value function
        //   - civic-diversity-collapse: diversity_factor bounds
        //   - civic-scarcity-single-gateway: scarcity_factor bounds
        //   - civic-holdback-30-percent: holdback applied to final points
        // Plus ContributionProof signatures and duplicate rejection.
        let _ = ValueFunction::default_per_adr_0005(1.0);
    }
}
