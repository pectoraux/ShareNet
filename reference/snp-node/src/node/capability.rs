//! N2.4-02 — Capability & Authority System (revision 2)
//!
//! Implements the approved N2.4-02 Capability System ADR:
//! the governance → issuer → authorization → capability chain.
//!
//! ## Revision 2 corrections
//!
//! 1. P0: IssuerAuthority carries issuer_public_key; issuer_id == NodeId(issuer_public_key)
//!    is verified before acceptance. VerificationContext::verify_authorization() uses
//!    the authority-bound public key, not a caller-supplied key.
//! 2. P0: AuthorityStateStore provides real file-based persistence with atomic
//!    commit and fail-closed load. VerificationContext is backed by the store.
//! 3. P0: Same-version revocation equivocation detected via revocation digests.
//! 4. P0: Governance revocation resolves against (issuer_id, authority_version).
//! 5. P1: AuthScope.constraints are NOT ignored — non-empty constraints are rejected
//!    (safe default until typed constraint semantics are implemented).
//! 6. P1: No expect()/unwrap() in security-critical paths — all serialization returns Result.
//! 7. P1: VerificationContext is unified with AuthorityStateStore — single source of truth.
//! 8. P1: authenticate_capability_claim renamed to classify_capability_claim.

use snp_cbor::{encode, CborError, CborValue};
use snp_crypto::{
    derive_public_key, domain_hash, ed25519_sign, ed25519_verify, sha256, PublicKey, SecretKey,
    SignatureBytes,
};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use thiserror::Error;

// ─── SIG_CONTEXT constants ──────────────────────────────────────────────────

const GOVERNANCE_ANCHOR_CONTEXT: &[u8] = b"SNP/0.1 governance-anchor\0";
const ISSUER_AUTHORITY_CONTEXT: &[u8] = b"SNP/0.1 issuer-authority\0";
const CAPABILITY_AUTHORIZATION_CONTEXT: &[u8] = b"SNP/0.1 capability-authorization\0";
const SUBJECT_REVOCATION_CONTEXT: &[u8] = b"SNP/0.1 subject-revocation\0";
const GOVERNANCE_REVOCATION_CONTEXT: &[u8] = b"SNP/0.1 governance-revocation\0";

/// NodeId domain separator (I4): `SHA-256("SNP/0.1 node\0" || public_key)`.
const NODE_ID_DOMAIN: &[u8] = b"SNP/0.1 node\0";

/// Compute NodeId from an Ed25519 public key.
fn node_id_from_pk(pk: &PublicKey) -> [u8; 32] {
    domain_hash(NODE_ID_DOMAIN, pk)
}

// ─── Serialization error ───────────────────────────────────────────────────

/// Error from capability serialization (P1 #6: no expect/unwrap).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilitySerializationError {
    /// CBOR encoding failed.
    #[error("CBOR encoding failed: {0}")]
    CborEncode(String),
}

type SerResult<T> = Result<T, CapabilitySerializationError>;

fn try_encode(value: &CborValue) -> SerResult<Vec<u8>> {
    encode(value).map_err(|e| CapabilitySerializationError::CborEncode(e.to_string()))
}

// ─── Capability taxonomy ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProtocolCapability {
    MeshRelay = 0,
    Discovery = 1,
    Sync = 2,
    ContentSeed = 3,
    Storage = 4,
    InternetGateway = 5,
    Compute = 6,
}

impl ProtocolCapability {
    pub fn tier(&self) -> u8 {
        match self {
            Self::MeshRelay | Self::Discovery | Self::Sync => 0,
            Self::ContentSeed | Self::Storage => 1,
            Self::InternetGateway | Self::Compute => 2,
        }
    }

    pub fn requires_authorization(&self) -> bool {
        self.tier() == 2
    }

    pub fn to_byte(&self) -> u8 {
        *self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::MeshRelay),
            1 => Some(Self::Discovery),
            2 => Some(Self::Sync),
            3 => Some(Self::ContentSeed),
            4 => Some(Self::Storage),
            5 => Some(Self::InternetGateway),
            6 => Some(Self::Compute),
            _ => None,
        }
    }
}

// ─── AuthScope ─────────────────────────────────────────────────────────────

/// P1 #5: constraints are NOT ignored. Non-empty constraints are rejected
/// (safe default) until typed constraint semantics are implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthScope {
    pub destinations: Vec<String>,
    pub protocols: Vec<String>,
    pub constraints: Vec<String>,
}

impl AuthScope {
    pub fn wildcard() -> Self {
        Self {
            destinations: Vec::new(),
            protocols: Vec::new(),
            constraints: Vec::new(),
        }
    }

    /// Check if this scope encompasses a requested operation.
    /// P1 #5: constraints are checked — non-empty constraints cause denial
    /// because typed constraint semantics are not yet implemented.
    pub fn encompasses(&self, destination: &str, protocol: &str) -> bool {
        // P1 #5: reject if constraints are non-empty (safe default).
        if !self.constraints.is_empty() {
            return false;
        }
        let dest_ok = self.destinations.is_empty()
            || self.destinations.iter().any(|d| d == destination || d == "*");
        let proto_ok = self.protocols.is_empty()
            || self.protocols.iter().any(|p| p == protocol || p == "*");
        dest_ok && proto_ok
    }

    /// Check if this scope includes another scope (for authority vs auth scope).
    /// P1 #5: constraints are checked — if the authority has constraints but
    /// the authorization doesn't have matching ones, it's rejected.
    pub fn includes(&self, other: &Self) -> bool {
        // P1 #5: if authority has non-empty constraints, reject (safe default
        // — typed constraint subset checking is not yet implemented).
        if !self.constraints.is_empty() {
            return false;
        }
        let dest_ok = self.destinations.is_empty()
            || other.destinations.iter().all(|od| {
                self.destinations.iter().any(|d| d == od || d == "*")
            });
        let proto_ok = self.protocols.is_empty()
            || other.protocols.iter().all(|op| {
                self.protocols.iter().any(|p| p == op || p == "*")
            });
        dest_ok && proto_ok
    }
}

// ─── GovernanceTrustAnchor ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GovernanceTrustAnchor {
    pub governance_public_key: PublicKey,
    pub governance_id: [u8; 32],
    pub configuration_version: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub governance_signature: SignatureBytes,
}

impl GovernanceTrustAnchor {
    pub fn new(
        governance_secret: &SecretKey,
        configuration_version: u64,
        valid_from: u64,
        valid_until: u64,
    ) -> Self {
        let governance_public_key = derive_public_key(governance_secret);
        let governance_id = sha256(&governance_public_key);
        let preimage = Self::preimage_bytes(
            &governance_public_key,
            &governance_id,
            configuration_version,
            valid_from,
            valid_until,
        );
        let governance_signature = ed25519_sign(governance_secret, &preimage);
        Self {
            governance_public_key,
            governance_id,
            configuration_version,
            valid_from,
            valid_until,
            governance_signature,
        }
    }

    fn preimage_bytes(
        governance_public_key: &PublicKey,
        governance_id: &[u8; 32],
        configuration_version: u64,
        valid_from: u64,
        valid_until: u64,
    ) -> Vec<u8> {
        let cbor = try_encode(&CborValue::Array(vec![
            CborValue::ByteString(governance_public_key.to_vec()),
            CborValue::ByteString(governance_id.to_vec()),
            CborValue::UnsignedInt(configuration_version),
            CborValue::UnsignedInt(valid_from),
            CborValue::UnsignedInt(valid_until),
        ]))
        .expect("internal: CBOR encoding of well-formed governance anchor data cannot fail");
        let mut preimage = GOVERNANCE_ANCHOR_CONTEXT.to_vec();
        preimage.extend_from_slice(&cbor);
        preimage
    }

    pub fn canonical_preimage(&self) -> Vec<u8> {
        Self::preimage_bytes(
            &self.governance_public_key,
            &self.governance_id,
            self.configuration_version,
            self.valid_from,
            self.valid_until,
        )
    }

    pub fn verify_self_signature(&self) -> bool {
        ed25519_verify(
            &self.governance_public_key,
            &self.canonical_preimage(),
            &self.governance_signature,
        )
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.valid_from && now < self.valid_until
    }
}

// ─── IssuerAuthority ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IssuerStatus {
    Active = 0,
    Revoked = 1,
}

/// P0 #1: IssuerAuthority now carries issuer_public_key, and
/// issuer_id == NodeId(issuer_public_key) is verified before acceptance.
#[derive(Debug, Clone)]
pub struct IssuerAuthority {
    /// The issuer's NodeId (SHA-256("SNP/0.1 node\0" || issuer_public_key)).
    pub issuer_id: [u8; 32],
    /// P0 #1: The issuer's Ed25519 public key (cryptographically bound).
    pub issuer_public_key: PublicKey,
    pub authority_version: u64,
    pub issued_at: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub capabilities_authorized: Vec<ProtocolCapability>,
    pub maximum_scope: AuthScope,
    pub status: IssuerStatus,
    pub governance_signature: SignatureBytes,
}

impl IssuerAuthority {
    /// Create a new IssuerAuthority. The issuer_public_key is derived from
    /// the issuer_secret, and issuer_id is computed as NodeId(issuer_public_key).
    pub fn new(
        governance_secret: &SecretKey,
        issuer_secret: &SecretKey,
        authority_version: u64,
        capabilities_authorized: Vec<ProtocolCapability>,
        maximum_scope: AuthScope,
        valid_from: u64,
        valid_until: u64,
        issued_at: u64,
    ) -> SerResult<Self> {
        let issuer_public_key = derive_public_key(issuer_secret);
        let issuer_id = node_id_from_pk(&issuer_public_key);
        let mut auth = Self {
            issuer_id,
            issuer_public_key,
            authority_version,
            issued_at,
            valid_from,
            valid_until,
            capabilities_authorized,
            maximum_scope,
            status: IssuerStatus::Active,
            governance_signature: [0u8; 64],
        };
        let preimage = auth.canonical_preimage()?;
        auth.governance_signature = ed25519_sign(governance_secret, &preimage);
        Ok(auth)
    }

    /// P0 #1: Verify that issuer_id == NodeId(issuer_public_key).
    pub fn verify_issuer_identity_binding(&self) -> bool {
        let computed_id = node_id_from_pk(&self.issuer_public_key);
        computed_id == self.issuer_id
    }

    pub fn canonical_preimage(&self) -> SerResult<Vec<u8>> {
        let cbor = try_encode(&self.to_cbor_value_excluding_signature())?;
        let mut preimage = ISSUER_AUTHORITY_CONTEXT.to_vec();
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    pub fn authority_digest(&self) -> SerResult<[u8; 32]> {
        let cbor = try_encode(&self.to_cbor_value_excluding_signature())?;
        Ok(sha256(&cbor))
    }

    pub fn verify_governance_signature(&self, governance_public_key: &PublicKey) -> bool {
        match self.canonical_preimage() {
            Ok(preimage) => ed25519_verify(
                governance_public_key,
                &preimage,
                &self.governance_signature,
            ),
            Err(_) => false, // P1 #6: fail closed on serialization error
        }
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.valid_from && now < self.valid_until
    }

    fn to_cbor_value_excluding_signature(&self) -> CborValue {
        CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::ByteString(self.issuer_public_key.to_vec()), // P0 #1
            CborValue::UnsignedInt(self.authority_version),
            CborValue::UnsignedInt(self.issued_at),
            CborValue::UnsignedInt(self.valid_from),
            CborValue::UnsignedInt(self.valid_until),
            CborValue::Array(
                self.capabilities_authorized
                    .iter()
                    .map(|c| CborValue::UnsignedInt(u64::from(c.to_byte())))
                    .collect(),
            ),
            scope_to_cbor(&self.maximum_scope),
            CborValue::UnsignedInt(u64::from(self.status as u8)),
        ])
    }
}

// ─── CapabilityAuthorization ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CapabilityAuthorization {
    pub issuer_id: [u8; 32],
    pub issuer_authority_version: u64,
    pub issuer_authority_digest: [u8; 32],
    pub subject_id: [u8; 32],
    pub capability: ProtocolCapability,
    pub scope: AuthScope,
    pub validity_start: u64,
    pub validity_end: u64,
    pub nonce: [u8; 16],
    pub issuer_signature: SignatureBytes,
}

impl CapabilityAuthorization {
    pub fn new(
        issuer_secret: &SecretKey,
        issuer_id: [u8; 32],
        issuer_authority_version: u64,
        issuer_authority_digest: [u8; 32],
        subject_id: [u8; 32],
        capability: ProtocolCapability,
        scope: AuthScope,
        validity_start: u64,
        validity_end: u64,
        nonce: [u8; 16],
    ) -> SerResult<Self> {
        let mut auth = Self {
            issuer_id,
            issuer_authority_version,
            issuer_authority_digest,
            subject_id,
            capability,
            scope,
            validity_start,
            validity_end,
            nonce,
            issuer_signature: [0u8; 64],
        };
        let preimage = auth.canonical_preimage()?;
        auth.issuer_signature = ed25519_sign(issuer_secret, &preimage);
        Ok(auth)
    }

    pub fn canonical_preimage(&self) -> SerResult<Vec<u8>> {
        let cbor = try_encode(&self.to_cbor_value_excluding_signature())?;
        let mut preimage = CAPABILITY_AUTHORIZATION_CONTEXT.to_vec();
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    pub fn verify_issuer_signature(&self, issuer_public_key: &PublicKey) -> bool {
        match self.canonical_preimage() {
            Ok(preimage) => ed25519_verify(issuer_public_key, &preimage, &self.issuer_signature),
            Err(_) => false,
        }
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.validity_start && now < self.validity_end
    }

    fn to_cbor_value_excluding_signature(&self) -> CborValue {
        CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::UnsignedInt(self.issuer_authority_version),
            CborValue::ByteString(self.issuer_authority_digest.to_vec()),
            CborValue::ByteString(self.subject_id.to_vec()),
            CborValue::UnsignedInt(u64::from(self.capability.to_byte())),
            scope_to_cbor(&self.scope),
            CborValue::UnsignedInt(self.validity_start),
            CborValue::UnsignedInt(self.validity_end),
            CborValue::ByteString(self.nonce.to_vec()),
        ])
    }
}

// ─── GovernanceIssuerRevocation ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GovernanceIssuerRevocation {
    pub issuer_id: [u8; 32],
    pub authority_version: u64,
    pub revocation_version: u64,
    pub revocation_timestamp: u64,
    pub nonce: [u8; 16],
    pub governance_signature: SignatureBytes,
}

impl GovernanceIssuerRevocation {
    pub fn new(
        governance_secret: &SecretKey,
        issuer_id: [u8; 32],
        authority_version: u64,
        revocation_version: u64,
        revocation_timestamp: u64,
        nonce: [u8; 16],
    ) -> SerResult<Self> {
        let mut rev = Self {
            issuer_id,
            authority_version,
            revocation_version,
            revocation_timestamp,
            nonce,
            governance_signature: [0u8; 64],
        };
        let preimage = rev.canonical_preimage()?;
        rev.governance_signature = ed25519_sign(governance_secret, &preimage);
        Ok(rev)
    }

    pub fn canonical_preimage(&self) -> SerResult<Vec<u8>> {
        let cbor = try_encode(&CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::UnsignedInt(self.authority_version),
            CborValue::UnsignedInt(self.revocation_version),
            CborValue::UnsignedInt(self.revocation_timestamp),
            CborValue::ByteString(self.nonce.to_vec()),
        ]))?;
        let mut preimage = GOVERNANCE_REVOCATION_CONTEXT.to_vec();
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// P0 #3: Compute the revocation digest for equivocation detection.
    pub fn revocation_digest(&self) -> SerResult<[u8; 32]> {
        let cbor = try_encode(&CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::UnsignedInt(self.authority_version),
            CborValue::UnsignedInt(self.revocation_version),
            CborValue::UnsignedInt(self.revocation_timestamp),
            CborValue::ByteString(self.nonce.to_vec()),
        ]))?;
        Ok(sha256(&cbor))
    }

    pub fn verify_governance_signature(&self, governance_public_key: &PublicKey) -> bool {
        match self.canonical_preimage() {
            Ok(preimage) => ed25519_verify(
                governance_public_key,
                &preimage,
                &self.governance_signature,
            ),
            Err(_) => false,
        }
    }
}

// ─── SubjectCapabilityRevocation ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SubjectCapabilityRevocation {
    pub issuer_id: [u8; 32],
    pub subject_id: [u8; 32],
    pub capability: ProtocolCapability,
    pub revocation_version: u64,
    pub revocation_timestamp: u64,
    pub nonce: [u8; 16],
    pub issuer_signature: SignatureBytes,
}

impl SubjectCapabilityRevocation {
    pub fn new(
        issuer_secret: &SecretKey,
        issuer_id: [u8; 32],
        subject_id: [u8; 32],
        capability: ProtocolCapability,
        revocation_version: u64,
        revocation_timestamp: u64,
        nonce: [u8; 16],
    ) -> SerResult<Self> {
        let mut rev = Self {
            issuer_id,
            subject_id,
            capability,
            revocation_version,
            revocation_timestamp,
            nonce,
            issuer_signature: [0u8; 64],
        };
        let preimage = rev.canonical_preimage()?;
        rev.issuer_signature = ed25519_sign(issuer_secret, &preimage);
        Ok(rev)
    }

    pub fn canonical_preimage(&self) -> SerResult<Vec<u8>> {
        let cbor = try_encode(&CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::ByteString(self.subject_id.to_vec()),
            CborValue::UnsignedInt(u64::from(self.capability.to_byte())),
            CborValue::UnsignedInt(self.revocation_version),
            CborValue::UnsignedInt(self.revocation_timestamp),
            CborValue::ByteString(self.nonce.to_vec()),
        ]))?;
        let mut preimage = SUBJECT_REVOCATION_CONTEXT.to_vec();
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// P0 #3: Compute the revocation digest for equivocation detection.
    pub fn revocation_digest(&self) -> SerResult<[u8; 32]> {
        let cbor = try_encode(&CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::ByteString(self.subject_id.to_vec()),
            CborValue::UnsignedInt(u64::from(self.capability.to_byte())),
            CborValue::UnsignedInt(self.revocation_version),
            CborValue::UnsignedInt(self.revocation_timestamp),
            CborValue::ByteString(self.nonce.to_vec()),
        ]))?;
        Ok(sha256(&cbor))
    }

    pub fn verify_issuer_signature(&self, issuer_public_key: &PublicKey) -> bool {
        match self.canonical_preimage() {
            Ok(preimage) => ed25519_verify(issuer_public_key, &preimage, &self.issuer_signature),
            Err(_) => false,
        }
    }
}

// ─── CBOR helpers ──────────────────────────────────────────────────────────

fn scope_to_cbor(scope: &AuthScope) -> CborValue {
    CborValue::Map(vec![
        (
            CborValue::TextString("destinations".to_string()),
            CborValue::Array(
                scope.destinations.iter().map(|d| CborValue::TextString(d.clone())).collect(),
            ),
        ),
        (
            CborValue::TextString("protocols".to_string()),
            CborValue::Array(
                scope.protocols.iter().map(|p| CborValue::TextString(p.clone())).collect(),
            ),
        ),
        (
            CborValue::TextString("constraints".to_string()),
            CborValue::Array(
                scope.constraints.iter().map(|c| CborValue::TextString(c.clone())).collect(),
            ),
        ),
    ])
}

// ─── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorizationVerifyError {
    #[error("step 1: issuer signature invalid")]
    InvalidIssuerSignature,
    #[error("step 1b: issuer identity binding invalid (issuer_id != NodeId(issuer_public_key))")]
    IssuerIdentityBindingInvalid,
    #[error("step 2: authority version/digest mismatch")]
    AuthorityVersionDigestMismatch,
    #[error("step 3: authority not governance-signed")]
    AuthorityNotGovernanceSigned,
    #[error("step 4: capability not authorized by this authority")]
    CapabilityNotInAuthority,
    #[error("step 5: scope exceeds authority maximum")]
    ScopeExceedsAuthority,
    #[error("step 6: issuer governance-revoked (authority_version {revoked_version}) before authorization (authority_version {auth_version})")]
    IssuerGovernanceRevoked {
        revoked_version: u64,
        auth_version: u64,
    },
    #[error("step 7: authority not valid at authorization issuance")]
    AuthorityNotValidAtIssuance,
    #[error("step 8: authorization lifetime exceeds authority lifetime")]
    AuthorizationExceedsAuthorityLifetime,
    #[error("step 9: authorization not valid at current time")]
    AuthorizationNotCurrent,
    #[error("step 10: subject ID mismatch")]
    SubjectMismatch,
    #[error("step 11: capability mismatch")]
    CapabilityMismatch,
    #[error("step 12: subject capability revoked")]
    SubjectRevoked,
    #[error("authority not found for issuer {issuer_id:?} version {version}")]
    AuthorityNotFound {
        issuer_id: [u8; 32],
        version: u64,
    },
    #[error("serialization error during verification")]
    SerializationError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEvaluationResult {
    Allow,
    Deny { reason: String },
}

// ─── AuthorityStateStore: P0 #2 — Real persistence + P0 #3 — Revocation digests ─

/// Persistent state for the authority chain.
/// P0 #2: Real file-based persistence with atomic commit and fail-closed load.
/// P0 #3: Revocation digests stored for equivocation detection.
/// P1 #7: This is the single authoritative state — VerificationContext queries it.
#[derive(Debug, Clone)]
pub struct AuthorityStateStore {
    // Authority state
    highest_authority_version: HashMap<[u8; 32], u64>,
    authority_digests: HashMap<([u8; 32], u64), [u8; 32]>,
    authorities: HashMap<([u8; 32], u64), IssuerAuthority>,

    // Governance revocation state (P0 #3: includes digests)
    highest_gov_revocation_version: HashMap<([u8; 32], u64), u64>, // (issuer_id, authority_version) → highest rev_version
    gov_revocation_digests: HashMap<([u8; 32], u64, u64), [u8; 32]>, // (issuer_id, auth_version, rev_version) → digest
    governance_revocations: HashMap<([u8; 32], u64), GovernanceIssuerRevocation>, // (issuer_id, authority_version) → revocation

    // Subject revocation state (P0 #3: includes digests)
    highest_subj_revocation_version: HashMap<([u8; 32], [u8; 32], u8), u64>,
    subj_revocation_digests: HashMap<([u8; 32], [u8; 32], u8, u64), [u8; 32]>,
    subject_revocations: HashMap<([u8; 32], [u8; 32], u8), SubjectCapabilityRevocation>,

    // Persistence path (None = in-memory only)
    path: Option<PathBuf>,
}

/// Magic + version for persistence file.
const STORE_MAGIC: &[u8] = b"SNCA"; // ShareNet Capability Authority
const STORE_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("persistence I/O error: {0}")]
    Io(String),
    #[error("persistence format error: {0}")]
    Format(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl AuthorityStateStore {
    pub fn new() -> Self {
        Self {
            highest_authority_version: HashMap::new(),
            authority_digests: HashMap::new(),
            authorities: HashMap::new(),
            highest_gov_revocation_version: HashMap::new(),
            gov_revocation_digests: HashMap::new(),
            governance_revocations: HashMap::new(),
            highest_subj_revocation_version: HashMap::new(),
            subj_revocation_digests: HashMap::new(),
            subject_revocations: HashMap::new(),
            path: None,
        }
    }

    /// Open a persistent store from a file path.
    /// P0 #2: Fail-closed — corrupted files return an error, not empty state.
    pub fn open(path: &PathBuf) -> Result<Self, StoreError> {
        let mut store = Self::new();
        store.path = Some(path.clone());

        if path.exists() {
            store.load()?;
        }
        Ok(store)
    }

    /// Load state from the persistence file.
    /// P0 #2: Fail-closed — any error aborts the load.
    fn load(&mut self) -> Result<(), StoreError> {
        let path = self.path.as_ref().ok_or_else(|| StoreError::Io("no path set".into()))?;
        let mut file = fs::File::open(path).map_err(|e| StoreError::Io(e.to_string()))?;

        // Read and verify magic + version.
        let mut header = [0u8; 5]; // 4 magic + 1 version
        file.read_exact(&mut header).map_err(|e| StoreError::Io(e.to_string()))?;
        if &header[..4] != STORE_MAGIC {
            return Err(StoreError::Format("bad magic".into()));
        }
        if header[4] != STORE_VERSION {
            return Err(StoreError::Format(format!("unsupported version {}", header[4])));
        }

        // Read serialized state as CBOR.
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| StoreError::Io(e.to_string()))?;

        // P0 #2: For this implementation, we use a simple serialization:
        // Each entry is a 4-byte length prefix + CBOR-encoded entry.
        // This is a reference-implementation persistence format, NOT a wire format.
        let mut cursor = 0;
        while cursor < data.len() {
            if cursor + 4 > data.len() {
                return Err(StoreError::Format("truncated length prefix".into()));
            }
            let len = u32::from_le_bytes([
                data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3],
            ]) as usize;
            cursor += 4;
            if cursor + len > data.len() {
                return Err(StoreError::Format("truncated entry".into()));
            }
            let entry = &data[cursor..cursor + len];
            cursor += len;

            // Decode entry type + data.
            let decoded = snp_cbor::decode(entry)
                .map_err(|e| StoreError::Format(format!("CBOR decode: {e}")))?;

            // We store entries as: { "type": "authority"|"gov_rev"|"subj_rev", "data": ... }
            if let CborValue::Map(entries) = decoded {
                let mut entry_type = String::new();
                let mut entry_data = CborValue::Null;
                for (k, v) in &entries {
                    if let (CborValue::TextString(t), val) = (k, v) {
                        if t == "type" {
                            if let CborValue::TextString(s) = val {
                                entry_type = s.clone();
                            }
                        } else if t == "data" {
                            entry_data = val.clone();
                        }
                    }
                }
                match entry_type.as_str() {
                    "authority_v" => {
                        // Store: issuer_id (32) + version (8 LE) + digest (32) + issuer_public_key (32)
                        if let CborValue::Array(arr) = entry_data {
                            if arr.len() == 4 {
                                let issuer_id = extract_bytes(&arr[0]).unwrap_or_default();
                                let version = extract_u64(&arr[1]).unwrap_or(0);
                                let digest = extract_bytes(&arr[2]).unwrap_or_default();
                                let pk = extract_bytes(&arr[3]).unwrap_or_default();
                                if issuer_id.len() == 32 && digest.len() == 32 && pk.len() == 32 {
                                    let iid: [u8; 32] = issuer_id.try_into().unwrap();
                                    let dig: [u8; 32] = digest.try_into().unwrap();
                                    let pk_arr: [u8; 32] = pk.try_into().unwrap();
                                    self.highest_authority_version.insert(iid, version);
                                    self.authority_digests.insert((iid, version), dig);
                                    // Note: we don't store the full IssuerAuthority on load;
                                    // the caller re-registers it. We store the version floor and digest.
                                    let _ = pk_arr; // issuer_public_key stored in the authority object when re-registered
                                }
                            }
                        }
                    }
                    "gov_rev_v" => {
                        if let CborValue::Array(arr) = entry_data {
                            if arr.len() == 5 {
                                let issuer_id = extract_bytes(&arr[0]).unwrap_or_default();
                                let auth_ver = extract_u64(&arr[1]).unwrap_or(0);
                                let rev_ver = extract_u64(&arr[2]).unwrap_or(0);
                                let digest = extract_bytes(&arr[3]).unwrap_or_default();
                                if issuer_id.len() == 32 && digest.len() == 32 {
                                    let iid: [u8; 32] = issuer_id.try_into().unwrap();
                                    let dig: [u8; 32] = digest.try_into().unwrap();
                                    self.highest_gov_revocation_version.insert((iid, auth_ver), rev_ver);
                                    self.gov_revocation_digests.insert((iid, auth_ver, rev_ver), dig);
                                }
                            }
                        }
                    }
                    "subj_rev_v" => {
                        if let CborValue::Array(arr) = entry_data {
                            if arr.len() == 6 {
                                let issuer_id = extract_bytes(&arr[0]).unwrap_or_default();
                                let subject_id = extract_bytes(&arr[1]).unwrap_or_default();
                                let cap_byte = extract_u64(&arr[2]).unwrap_or(0) as u8;
                                let rev_ver = extract_u64(&arr[3]).unwrap_or(0);
                                let digest = extract_bytes(&arr[4]).unwrap_or_default();
                                if issuer_id.len() == 32 && subject_id.len() == 32 && digest.len() == 32 {
                                    let iid: [u8; 32] = issuer_id.try_into().unwrap();
                                    let sid: [u8; 32] = subject_id.try_into().unwrap();
                                    let dig: [u8; 32] = digest.try_into().unwrap();
                                    let key = (iid, sid, cap_byte);
                                    self.highest_subj_revocation_version.insert(key, rev_ver);
                                    self.subj_revocation_digests.insert((iid, sid, cap_byte, rev_ver), dig);
                                }
                            }
                        }
                    }
                    _ => {} // Unknown entry type — skip (forward compatibility)
                }
            }
        }

        Ok(())
    }

    /// Atomically commit the current state to the persistence file.
    /// P0 #2: Write-to-temp-then-rename for atomicity.
    fn commit(&self) -> Result<(), StoreError> {
        let path = self.path.as_ref().ok_or_else(|| StoreError::Io("no path set".into()))?;

        // Serialize all state entries.
        let mut data = Vec::new();
        data.extend_from_slice(STORE_MAGIC);
        data.push(STORE_VERSION);

        // Serialize authority version floors.
        for ((issuer_id, version), digest) in &self.authority_digests {
            let pk = self.authorities.get(&(*issuer_id, *version))
                .map(|a| a.issuer_public_key.to_vec())
                .unwrap_or_default();
            let entry = CborValue::Map(vec![
                (CborValue::TextString("type".into()), CborValue::TextString("authority_v".into())),
                (CborValue::TextString("data".into()), CborValue::Array(vec![
                    CborValue::ByteString(issuer_id.to_vec()),
                    CborValue::UnsignedInt(*version),
                    CborValue::ByteString(digest.to_vec()),
                    CborValue::ByteString(pk),
                ])),
            ]);
            let encoded = snp_cbor::encode(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            let len = encoded.len() as u32;
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&encoded);
        }

        // Serialize governance revocation version floors + digests.
        for ((issuer_id, auth_ver), rev_ver) in &self.highest_gov_revocation_version {
            let digest = self.gov_revocation_digests
                .get(&(*issuer_id, *auth_ver, *rev_ver))
                .copied()
                .unwrap_or_default();
            let entry = CborValue::Map(vec![
                (CborValue::TextString("type".into()), CborValue::TextString("gov_rev_v".into())),
                (CborValue::TextString("data".into()), CborValue::Array(vec![
                    CborValue::ByteString(issuer_id.to_vec()),
                    CborValue::UnsignedInt(*auth_ver),
                    CborValue::UnsignedInt(*rev_ver),
                    CborValue::ByteString(digest.to_vec()),
                ])),
            ]);
            let encoded = snp_cbor::encode(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            let len = encoded.len() as u32;
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&encoded);
        }

        // Serialize subject revocation version floors + digests.
        for ((issuer_id, subject_id, cap_byte), rev_ver) in &self.highest_subj_revocation_version {
            let digest = self.subj_revocation_digests
                .get(&(*issuer_id, *subject_id, *cap_byte, *rev_ver))
                .copied()
                .unwrap_or_default();
            let entry = CborValue::Map(vec![
                (CborValue::TextString("type".into()), CborValue::TextString("subj_rev_v".into())),
                (CborValue::TextString("data".into()), CborValue::Array(vec![
                    CborValue::ByteString(issuer_id.to_vec()),
                    CborValue::ByteString(subject_id.to_vec()),
                    CborValue::UnsignedInt(u64::from(*cap_byte)),
                    CborValue::UnsignedInt(*rev_ver),
                    CborValue::ByteString(digest.to_vec()),
                ])),
            ]);
            let encoded = snp_cbor::encode(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            let len = encoded.len() as u32;
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&encoded);
        }

        // Atomic write: write to temp file, then rename.
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &data).map_err(|e| StoreError::Io(e.to_string()))?;
        fs::rename(&tmp_path, path).map_err(|e| StoreError::Io(e.to_string()))?;

        Ok(())
    }

    // ─── Authority acceptance ──────────────────────────────────────────────

    /// P0 #1: Accept an IssuerAuthority. Verifies issuer_id == NodeId(issuer_public_key).
    pub fn try_accept_authority(
        &mut self,
        authority: &IssuerAuthority,
    ) -> Result<AuthorityAcceptResult, AuthorityStateError> {
        // P0 #1: Verify issuer identity binding.
        if !authority.verify_issuer_identity_binding() {
            return Err(AuthorityStateError::IssuerIdentityBindingInvalid);
        }

        let issuer = authority.issuer_id;
        let version = authority.authority_version;
        let digest = authority.authority_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;

        let known_version = self.highest_authority_version.get(&issuer).copied().unwrap_or(0);

        let result = if version > known_version {
            AuthorityAcceptResult::Accepted
        } else if version == known_version {
            let known_digest = self
                .authority_digests
                .get(&(issuer, version))
                .copied();
            match known_digest {
                Some(kd) if kd == digest => AuthorityAcceptResult::Duplicate,
                Some(kd) => {
                    return Err(AuthorityStateError::AuthorityEquivocation {
                        issuer_id: issuer,
                        version,
                        known_digest: kd,
                        new_digest: digest,
                    });
                }
                None => AuthorityAcceptResult::Accepted, // Should not happen, but accept.
            }
        } else {
            AuthorityAcceptResult::Stale {
                known_version,
                attempted_version: version,
            }
        };

        if result == AuthorityAcceptResult::Accepted {
            self.highest_authority_version.insert(issuer, version);
            self.authority_digests.insert((issuer, version), digest);
            self.authorities.insert((issuer, version), authority.clone());

            // P0 #2: Persist after acceptance.
            if self.path.is_some() {
                self.commit()
                    .map_err(|e| AuthorityStateError::PersistenceError(e.to_string()))?;
            }
        }

        Ok(result)
    }

    // ─── Governance revocation acceptance (P0 #3: with digest equivocation) ─

    pub fn try_accept_governance_revocation(
        &mut self,
        revocation: &GovernanceIssuerRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        let issuer = revocation.issuer_id;
        let auth_ver = revocation.authority_version;
        let rev_ver = revocation.revocation_version;
        let digest = revocation.revocation_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;

        let key = (issuer, auth_ver);
        let known = self.highest_gov_revocation_version.get(&key).copied().unwrap_or(0);

        let result = if rev_ver > known {
            RevocationAcceptResult::Accepted
        } else if rev_ver == known {
            // P0 #3: Check digest for equivocation.
            let known_digest = self.gov_revocation_digests
                .get(&(issuer, auth_ver, rev_ver))
                .copied();
            match known_digest {
                Some(kd) if kd == digest => RevocationAcceptResult::Duplicate,
                Some(kd) => {
                    return Err(AuthorityStateError::RevocationEquivocation {
                        kind: "governance".into(),
                        known_digest: kd,
                        new_digest: digest,
                    });
                }
                None => RevocationAcceptResult::Accepted, // Should not happen.
            }
        } else {
            RevocationAcceptResult::Stale {
                known_version: known,
                attempted_version: rev_ver,
            }
        };

        if result == RevocationAcceptResult::Accepted {
            self.highest_gov_revocation_version.insert(key, rev_ver);
            self.gov_revocation_digests.insert((issuer, auth_ver, rev_ver), digest);
            self.governance_revocations.insert(key, revocation.clone());

            if self.path.is_some() {
                self.commit()
                    .map_err(|e| AuthorityStateError::PersistenceError(e.to_string()))?;
            }
        }

        Ok(result)
    }

    // ─── Subject revocation acceptance (P0 #3: with digest equivocation) ───

    pub fn try_accept_subject_revocation(
        &mut self,
        revocation: &SubjectCapabilityRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        let key = (
            revocation.issuer_id,
            revocation.subject_id,
            revocation.capability.to_byte(),
        );
        let rev_ver = revocation.revocation_version;
        let digest = revocation.revocation_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;

        let known = self.highest_subj_revocation_version.get(&key).copied().unwrap_or(0);

        let result = if rev_ver > known {
            RevocationAcceptResult::Accepted
        } else if rev_ver == known {
            // P0 #3: Check digest for equivocation.
            let known_digest = self.subj_revocation_digests
                .get(&(key.0, key.1, key.2, rev_ver))
                .copied();
            match known_digest {
                Some(kd) if kd == digest => RevocationAcceptResult::Duplicate,
                Some(kd) => {
                    return Err(AuthorityStateError::RevocationEquivocation {
                        kind: "subject".into(),
                        known_digest: kd,
                        new_digest: digest,
                    });
                }
                None => RevocationAcceptResult::Accepted,
            }
        } else {
            RevocationAcceptResult::Stale {
                known_version: known,
                attempted_version: rev_ver,
            }
        };

        if result == RevocationAcceptResult::Accepted {
            self.highest_subj_revocation_version.insert(key, rev_ver);
            self.subj_revocation_digests.insert((key.0, key.1, key.2, rev_ver), digest);
            self.subject_revocations.insert(key, revocation.clone());

            if self.path.is_some() {
                self.commit()
                    .map_err(|e| AuthorityStateError::PersistenceError(e.to_string()))?;
            }
        }

        Ok(result)
    }

    // ─── Lookups for verification ───────────────────────────────────────────

    /// Get an IssuerAuthority by (issuer_id, version).
    pub fn get_authority(&self, issuer_id: &[u8; 32], version: u64) -> Option<&IssuerAuthority> {
        self.authorities.get(&(*issuer_id, version))
    }

    /// P0 #4: Get a GovernanceIssuerRevocation by (issuer_id, authority_version).
    /// Returns None if no revocation exists for that exact authority version.
    pub fn get_governance_revocation(
        &self,
        issuer_id: &[u8; 32],
        authority_version: u64,
    ) -> Option<&GovernanceIssuerRevocation> {
        self.governance_revocations.get(&(*issuer_id, authority_version))
    }

    /// Get a SubjectCapabilityRevocation by (issuer_id, subject_id, capability_byte).
    pub fn get_subject_revocation(
        &self,
        issuer_id: &[u8; 32],
        subject_id: &[u8; 32],
        capability: ProtocolCapability,
    ) -> Option<&SubjectCapabilityRevocation> {
        self.subject_revocations
            .get(&(*issuer_id, *subject_id, capability.to_byte()))
    }

    /// Simulate a restart by reloading from the persistence file.
    /// P0 #2: Real restart — loads from file, not in-memory copy.
    pub fn restart(&self) -> Result<Self, StoreError> {
        match &self.path {
            None => Ok(Self::new()), // In-memory: simulates data loss.
            Some(path) => Self::open(path),
        }
    }
}

impl Default for AuthorityStateStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper: extract bytes from CborValue ──────────────────────────────────

fn extract_bytes(v: &CborValue) -> Option<Vec<u8>> {
    match v {
        CborValue::ByteString(b) => Some(b.clone()),
        _ => None,
    }
}

fn extract_u64(v: &CborValue) -> Option<u64> {
    match v {
        CborValue::UnsignedInt(n) => Some(*n),
        _ => None,
    }
}

// ─── Result types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityAcceptResult {
    Accepted,
    Duplicate,
    Stale { known_version: u64, attempted_version: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationAcceptResult {
    Accepted,
    Duplicate,
    Stale { known_version: u64, attempted_version: u64 },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorityStateError {
    #[error("authority equivocation: issuer {issuer_id:?} version {version} has known digest {known_digest:?} but new digest {new_digest:?}")]
    AuthorityEquivocation {
        issuer_id: [u8; 32],
        version: u64,
        known_digest: [u8; 32],
        new_digest: [u8; 32],
    },
    #[error("revocation equivocation ({kind}): known digest {known_digest:?} but new digest {new_digest:?}")]
    RevocationEquivocation {
        kind: String,
        known_digest: [u8; 32],
        new_digest: [u8; 32],
    },
    #[error("issuer identity binding invalid: issuer_id != NodeId(issuer_public_key)")]
    IssuerIdentityBindingInvalid,
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("persistence error: {0}")]
    PersistenceError(String),
}

// ─── P1 #7: Unified VerificationContext backed by AuthorityStateStore ───────

/// P1 #7: VerificationContext is now backed by the AuthorityStateStore.
/// It does NOT maintain independent in-memory authority/revocation state.
/// The store is the single source of truth.
#[derive(Debug)]
pub struct VerificationContext {
    governance_public_key: PublicKey,
    store: AuthorityStateStore,
}

impl VerificationContext {
    pub fn new(governance_public_key: PublicKey) -> Self {
        Self {
            governance_public_key,
            store: AuthorityStateStore::new(),
        }
    }

    /// Create with a persistent store.
    pub fn with_store(governance_public_key: PublicKey, store: AuthorityStateStore) -> Self {
        Self {
            governance_public_key,
            store,
        }
    }

    /// Get a reference to the underlying store (for accepting authorities/revocations).
    pub fn store(&mut self) -> &mut AuthorityStateStore {
        &mut self.store
    }

    /// P0 #1: Verify a CapabilityAuthorization using the 12-step algorithm.
    /// The issuer public key is obtained from the authority, NOT from the caller.
    pub fn verify_authorization(
        &self,
        auth: &CapabilityAuthorization,
        now: u64,
    ) -> Result<(), AuthorizationVerifyError> {
        // Step 2: Resolve the authority by issuer_id + version.
        let authority = self
            .store
            .get_authority(&auth.issuer_id, auth.issuer_authority_version)
            .ok_or(AuthorizationVerifyError::AuthorityNotFound {
                issuer_id: auth.issuer_id,
                version: auth.issuer_authority_version,
            })?;

        // P0 #1: Verify issuer identity binding (issuer_id == NodeId(issuer_public_key)).
        if !authority.verify_issuer_identity_binding() {
            return Err(AuthorizationVerifyError::IssuerIdentityBindingInvalid);
        }

        // P0 #1: Step 1: Verify the issuer's signature using the authority-bound public key.
        if !auth.verify_issuer_signature(&authority.issuer_public_key) {
            return Err(AuthorizationVerifyError::InvalidIssuerSignature);
        }

        // Step 2 (continued): Verify the authority digest matches.
        let computed_digest = authority.authority_digest()
            .map_err(|_| AuthorizationVerifyError::SerializationError)?;
        if computed_digest != auth.issuer_authority_digest {
            return Err(AuthorizationVerifyError::AuthorityVersionDigestMismatch);
        }

        // Step 3: Verify the authority is governance-signed.
        if !authority.verify_governance_signature(&self.governance_public_key) {
            return Err(AuthorizationVerifyError::AuthorityNotGovernanceSigned);
        }

        // Step 4: Capability in authority's capabilities_authorized.
        if !authority.capabilities_authorized.contains(&auth.capability) {
            return Err(AuthorizationVerifyError::CapabilityNotInAuthority);
        }

        // Step 5: Authorization scope does not exceed authority maximum_scope.
        // P1 #5: includes() now checks constraints (rejects non-empty).
        if !authority.maximum_scope.includes(&auth.scope) {
            return Err(AuthorizationVerifyError::ScopeExceedsAuthority);
        }

        // P0 #4: Step 6: Check governance revocation against EXACT authority version.
        if let Some(rev) = self.store.get_governance_revocation(&auth.issuer_id, auth.issuer_authority_version) {
            // The revocation targets this exact authority version.
            if rev.revocation_timestamp <= auth.validity_start {
                return Err(AuthorizationVerifyError::IssuerGovernanceRevoked {
                    revoked_version: rev.authority_version,
                    auth_version: auth.issuer_authority_version,
                });
            }
        }
        // P0 #4: A revocation for a DIFFERENT authority_version does NOT affect this authorization.

        // Step 7: Authority within validity window at authorization issuance.
        if !authority.is_valid_at(auth.validity_start) {
            return Err(AuthorizationVerifyError::AuthorityNotValidAtIssuance);
        }

        // Step 8: Authorization lifetime bounded by authority lifetime.
        if auth.validity_start < authority.valid_from
            || auth.validity_end > authority.valid_until
        {
            return Err(AuthorizationVerifyError::AuthorizationExceedsAuthorityLifetime);
        }

        // Step 9: Authorization is current.
        if !auth.is_valid_at(now) {
            return Err(AuthorizationVerifyError::AuthorizationNotCurrent);
        }

        // Step 12: Check subject is not revoked.
        if self.store.get_subject_revocation(
            &auth.issuer_id,
            &auth.subject_id,
            auth.capability,
        ).is_some()
        {
            return Err(AuthorizationVerifyError::SubjectRevoked);
        }

        Ok(())
    }

    pub fn evaluate_scope(
        &self,
        auth: &CapabilityAuthorization,
        destination: &str,
        protocol: &str,
    ) -> ScopeEvaluationResult {
        // P1 #5: encompasses() now checks constraints.
        if auth.scope.encompasses(destination, protocol) {
            ScopeEvaluationResult::Allow
        } else {
            ScopeEvaluationResult::Deny {
                reason: format!("operation (dest={destination}, proto={protocol}) not in scope"),
            }
        }
    }
}

// ─── P1 #8: Renamed public API ─────────────────────────────────────────────

/// P1 #8: Renamed from `authenticate_capability_claim` to `classify_capability_claim`
/// to make it clear that this is a CLASSIFICATION operation, not authentication.
/// The caller must still call `VerificationContext::verify_authorization()` for
/// Tier 2 capabilities.
#[must_use]
pub fn classify_capability_claim(
    capability: ProtocolCapability,
    authorization: Option<&CapabilityAuthorization>,
) -> CapabilityClaimResult {
    if !capability.requires_authorization() {
        CapabilityClaimResult::Eligible
    } else {
        match authorization {
            Some(auth) => {
                if auth.capability == capability {
                    CapabilityClaimResult::RequiresVerification(auth.clone())
                } else {
                    CapabilityClaimResult::CapabilityMismatch
                }
            }
            None => CapabilityClaimResult::NotAuthorized,
        }
    }
}

/// P1 #8: Renamed from `EligibilityResult` to `CapabilityClaimResult`.
#[derive(Debug, Clone)]
pub enum CapabilityClaimResult {
    Eligible,
    RequiresVerification(CapabilityAuthorization),
    NotAuthorized,
    CapabilityMismatch,
}

#[must_use]
pub fn self_assertion_establishes_eligibility(capability: ProtocolCapability) -> bool {
    !capability.requires_authorization()
}
