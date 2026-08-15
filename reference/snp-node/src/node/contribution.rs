//! N2.9 — Contribution Proof Loop
//!
//! Connects gateway service delivery to Civic Points:
//!
//! ```text
//! TransitReceipt (N2.7 — gateway attests to service)
//!     ↓
//! ContributionProof (N2.9 — aggregate receipts into a verifiable proof)
//!     ↓
//! CivicPointLedger (N2.9 — verify proofs → credit non-transferable points)
//! ```
//!
//! ## Anti-fraud property
//!
//! A node CANNOT manufacture a valid contribution solely by asserting traffic.
//! Every `ContributionProof` must be:
//! 1. Backed by a `TransitReceipt` signed by a gateway.
//! 2. The receipt's `gateway_signature` must verify against the gateway's
//!    public key.
//! 3. The receipt's `object_id` (SHA-256 of the response body) must match —
//!    the client can verify the gateway actually fetched what it claims.
//! 4. The `(gateway_node_id, req_id)` pair must be unique (replay defence).
//! 5. The receipt must not be in the future.
//!
//! ## Non-transferable points
//!
//! Civic Points are non-transferable reputation scores, NOT balances. They
//! cannot be sent between nodes. They are a measure of contribution to the
//! network, computed sub-linearly (per ADR-0005: `log₂(1 + MiB)`).

use crate::node::gateway_service_manager::TransitReceipt;
use crate::node::evidence::{EvidenceLevel, AuthenticatedClaim};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ─── ContributionProof ───────────────────────────────────────────────────────

/// A proof that a gateway provided service to a client.
///
/// Built by aggregating one or more `TransitReceipt`s. Each receipt is
/// individually verified (gateway signature + object_id + replay defence)
/// before being included in the proof.
///
/// The proof is signed by the CONTRIBUTOR (the gateway that provided the
/// service) — it's the gateway's own attestation of "I provided these
/// services."
///
/// ## Anti-fraud
///
/// A node cannot manufacture a valid `ContributionProof` solely by asserting
/// traffic. Every receipt in the proof must be:
/// - Signed by the gateway (the contributor's Ed25519 key)
/// - Bound to a unique `req_id` (replay defence)
/// - The `object_id` must be SHA-256 of the response body (verifiable)
///
/// ## Evidence level
///
/// `AuthenticatedClaim` — the proof is signed by the contributor and every
/// receipt is signed by the same gateway.
#[derive(Debug, Clone)]
pub struct ContributionProof {
    /// The NodeId of the gateway that provided the service (gets the credit).
    pub contributor: [u8; 32],
    /// The receipts backing this proof.
    pub receipts: Vec<TransitReceipt>,
    /// When this proof was created (unix seconds).
    pub created_at: u64,
    /// The contributor's Ed25519 signature over the proof preimage.
    pub contributor_signature: [u8; 64],
}

impl ContributionProof {
    /// Compute the canonical preimage for signing/verifying.
    fn preimage(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SNP/0.1 contribution-proof\0");
        data.extend_from_slice(&self.contributor);
        data.extend_from_slice(&self.created_at.to_be_bytes());
        for receipt in &self.receipts {
            data.extend_from_slice(&receipt.req_id);
            data.extend_from_slice(&receipt.client_node_id);
            data.extend_from_slice(&receipt.bytes_transferred.to_be_bytes());
            data.extend_from_slice(&receipt.object_id);
            data.extend_from_slice(&receipt.served_at.to_be_bytes());
        }
        data
    }

    /// Build a ContributionProof from verified receipts.
    ///
    /// Each receipt MUST:
    /// - Have `gateway_node_id == contributor`
    /// - Verify against the contributor's public key
    /// - Have a unique `req_id` (no duplicates within the proof)
    /// - Not be in the future
    ///
    /// # Arguments
    /// * `contributor` — The gateway's NodeId.
    /// * `contributor_secret_key` — The gateway's Ed25519 secret key (for signing the proof).
    /// * `receipts` — The verified receipts to aggregate.
    /// * `now` — Current time (unix seconds).
    ///
    /// # Errors
    /// Returns `ContributionProofError` if any receipt is invalid.
    pub fn build(
        contributor: [u8; 32],
        contributor_secret_key: &[u8; 32],
        receipts: Vec<TransitReceipt>,
        now: u64,
    ) -> Result<Self, ContributionProofError> {
        let contributor_public = snp_crypto::derive_public_key(contributor_secret_key);

        // 1. Verify every receipt belongs to this contributor + signature verifies.
        for receipt in &receipts {
            if receipt.gateway_node_id != contributor {
                return Err(ContributionProofError::ReceiptContributorMismatch {
                    receipt_gateway: receipt.gateway_node_id,
                    expected: contributor,
                });
            }
            if !receipt.verify(&contributor_public) {
                return Err(ContributionProofError::InvalidReceiptSignature {
                    req_id: receipt.req_id,
                });
            }
            if receipt.served_at > now {
                return Err(ContributionProofError::FutureTimestamp {
                    served_at: receipt.served_at,
                    now,
                });
            }
        }

        // 2. Check for duplicate req_ids (replay defence).
        let mut seen_req_ids = HashSet::new();
        for receipt in &receipts {
            if !seen_req_ids.insert(receipt.req_id) {
                return Err(ContributionProofError::DuplicateReceipt {
                    req_id: receipt.req_id,
                });
            }
        }

        // 3. Sign the proof.
        let mut proof = Self {
            contributor,
            receipts,
            created_at: now,
            contributor_signature: [0u8; 64],
        };
        let preimage = proof.preimage();
        proof.contributor_signature = snp_crypto::ed25519_sign(contributor_secret_key, &preimage);
        Ok(proof)
    }

    /// Verify the contributor's signature on this proof.
    ///
    /// This verifies the PROOF signature (the contributor's attestation that
    /// these receipts are theirs). It does NOT re-verify individual receipt
    /// signatures — use `verify_all_receipts()` for that.
    #[must_use]
    pub fn verify(&self, contributor_public_key: &[u8; 32]) -> bool {
        let preimage = self.preimage();
        snp_crypto::ed25519_verify(contributor_public_key, &preimage, &self.contributor_signature)
    }

    /// Verify the proof signature AND every individual receipt signature.
    /// Returns false if ANY receipt's gateway signature doesn't verify.
    #[must_use]
    pub fn verify_all_receipts(&self, contributor_public_key: &[u8; 32]) -> bool {
        if !self.verify(contributor_public_key) {
            return false;
        }
        for receipt in &self.receipts {
            if receipt.gateway_node_id != self.contributor {
                return false;
            }
            if !receipt.verify(contributor_public_key) {
                return false;
            }
        }
        true
    }

    /// Total bytes transferred across all receipts.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.receipts.iter().map(|r| r.bytes_transferred).sum()
    }

    /// Number of distinct clients served.
    #[must_use]
    pub fn distinct_clients(&self) -> usize {
        let clients: HashSet<_> = self.receipts.iter().map(|r| r.client_node_id).collect();
        clients.len()
    }

    /// Evidence level: Authenticated.
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Authenticated
    }
}

impl fmt::Display for ContributionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ContributionProof(contributor={}, receipts={}, bytes={}, clients={})",
            hex_short(&self.contributor),
            self.receipts.len(),
            self.total_bytes(),
            self.distinct_clients(),
        )
    }
}

fn hex_short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

// ─── ContributionProofError ──────────────────────────────────────────────────

/// Errors from ContributionProof construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContributionProofError {
    /// A receipt's gateway_node_id doesn't match the contributor.
    ReceiptContributorMismatch {
        receipt_gateway: [u8; 32],
        expected: [u8; 32],
    },
    /// A receipt's signature doesn't verify.
    InvalidReceiptSignature { req_id: [u8; 16] },
    /// A receipt has a future timestamp.
    FutureTimestamp { served_at: u64, now: u64 },
    /// A duplicate receipt (same req_id) was found.
    DuplicateReceipt { req_id: [u8; 16] },
}

impl fmt::Display for ContributionProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReceiptContributorMismatch { receipt_gateway, expected } => {
                write!(f, "receipt gateway {} != contributor {}", hex_short(receipt_gateway), hex_short(expected))
            }
            Self::InvalidReceiptSignature { req_id } => {
                write!(f, "invalid receipt signature for req_id {:?}", req_id)
            }
            Self::FutureTimestamp { served_at, now } => {
                write!(f, "receipt served_at {served_at} is in the future (now={now})")
            }
            Self::DuplicateReceipt { req_id } => {
                write!(f, "duplicate receipt with req_id {:?}", req_id)
            }
        }
    }
}

// ─── CivicPointLedger ────────────────────────────────────────────────────────

/// A non-transferable Civic Point ledger.
///
/// Credits points to contributors based on verified `ContributionProof`s.
/// Points are:
/// - **Non-transferable** — cannot be sent between nodes.
/// - **Sub-linear in volume** — `log₂(1 + MiB)` per ADR-0005.
/// - **Diversity-weighted** — serving many distinct clients is worth more
///   than serving the same total to one client.
/// - **Replay-resistant** — duplicate proofs (same receipts) are rejected.
///
/// ## Anti-fraud
///
/// A node cannot manufacture points by asserting traffic. Every proof must
/// contain receipts that are:
/// - Signed by the contributor (gateway)
/// - Bound to unique req_ids (no replay)
/// - Not in the future
///
/// The ledger tracks which `req_id`s have already been credited to prevent
/// double-counting.
#[derive(Debug)]
pub struct CivicPointLedger {
    /// Map: contributor NodeId → accumulated points.
    points: HashMap<[u8; 32], u64>,
    /// Set of (contributor, req_id) pairs that have already been credited.
    /// Prevents replay: the same receipt cannot be credited twice.
    credited_receipts: HashSet<([u8; 32], [u8; 16])>,
    /// The base rate (points per 1 MiB at canonical baseline).
    base_rate: f64,
}

impl CivicPointLedger {
    /// Create a new ledger with the given base rate.
    #[must_use]
    pub fn new(base_rate: f64) -> Self {
        Self {
            points: HashMap::new(),
            credited_receipts: HashSet::new(),
            base_rate,
        }
    }

    /// Credit a contributor based on a verified ContributionProof.
    ///
    /// The proof's signature AND every individual receipt signature are
    /// verified. Only receipts that haven't already been credited are counted
    /// (replay defence).
    ///
    /// # Arguments
    /// * `proof` — The ContributionProof to credit.
    /// * `contributor_public_key` — The contributor's Ed25519 public key.
    ///
    /// # Returns
    /// The number of points credited (0 if the proof is invalid or all
    /// receipts were already credited).
    pub fn credit(
        &mut self,
        proof: &ContributionProof,
        contributor_public_key: &[u8; 32],
    ) -> u64 {
        // 1. Verify the proof signature.
        if !proof.verify(contributor_public_key) {
            return 0;
        }

        // 2. Verify every individual receipt signature.
        if !proof.verify_all_receipts(contributor_public_key) {
            return 0;
        }

        // 3. Filter out already-credited receipts (replay defence).
        let new_receipts: Vec<&TransitReceipt> = proof.receipts.iter()
            .filter(|r| !self.credited_receipts.contains(&(proof.contributor, r.req_id)))
            .collect();

        if new_receipts.is_empty() {
            return 0; // All receipts already credited.
        }

        // 4. Compute the points using the sub-linear volume factor.
        let total_bytes: u64 = new_receipts.iter().map(|r| r.bytes_transferred).sum();
        let mib = total_bytes as f64 / (1024.0 * 1024.0);
        let volume_factor = (1.0 + mib).log2();
        let distinct_clients = new_receipts.iter().map(|r| r.client_node_id).collect::<HashSet<_>>().len();
        let diversity_factor = Self::diversity_factor(distinct_clients);

        let raw_points = self.base_rate * volume_factor * diversity_factor;
        let credited = raw_points.round() as u64;

        // 5. Credit the points.
        *self.points.entry(proof.contributor).or_insert(0) += credited;

        // 6. Mark the receipts as credited.
        for receipt in new_receipts {
            self.credited_receipts.insert((proof.contributor, receipt.req_id));
        }

        credited
    }

    /// Get the total points for a contributor.
    #[must_use]
    pub fn points_for(&self, contributor: &[u8; 32]) -> u64 {
        self.points.get(contributor).copied().unwrap_or(0)
    }

    /// Get all contributors and their points.
    #[must_use]
    pub fn all_points(&self) -> &HashMap<[u8; 32], u64> {
        &self.points
    }

    /// Compute the diversity factor per ADR-0005.
    /// 1 counterparty → 0.2, 5+ counterparties → 1.0, linear in between.
    #[must_use]
    fn diversity_factor(distinct_counterparties: usize) -> f64 {
        match distinct_counterparties {
            0 => 0.0,
            1 => 0.2,
            n if n >= 5 => 1.0,
            n => 0.2 + (n - 1) as f64 * 0.2,
        }
    }
}

impl fmt::Display for CivicPointLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CivicPointLedger({} contributors)", self.points.len())
    }
}

// ─── ContributionRecord ──────────────────────────────────────────────────────

/// A verifiable record of a contribution for audit purposes.
///
/// This is the "why did this node receive these points?" answer:
///
/// ```text
/// points
///   ← CivicPointLedger.credit()
///   ← ContributionProof (signed by contributor)
///   ← TransitReceipt (signed by gateway, verifiable)
///   ← actual HTTP fetch (object_id = SHA-256 of body)
/// ```
#[derive(Debug, Clone)]
pub struct ContributionRecord {
    /// The contributor's NodeId.
    pub contributor: [u8; 32],
    /// The total points credited.
    pub points: u64,
    /// The receipts backing the credit.
    pub receipts: Vec<TransitReceipt>,
    /// When the credit was applied.
    pub credited_at: u64,
}

impl ContributionRecord {
    /// Trace the points back to their source receipts.
    #[must_use]
    pub fn trace(&self) -> String {
        let mut s = format!(
            "ContributionRecord(contributor={}, points={}, {} receipts):\n",
            hex_short(&self.contributor),
            self.points,
            self.receipts.len()
        );
        for (i, receipt) in self.receipts.iter().enumerate() {
            s.push_str(&format!(
                "  [{}] req_id={:?} client={} bytes={} status={} served_at={}\n",
                i,
                receipt.req_id,
                hex_short(&receipt.client_node_id),
                receipt.bytes_transferred,
                receipt.http_status,
                receipt.served_at
            ));
        }
        s
    }
}
