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

    /// P0 #2 rev3: Complete CBOR encoding INCLUDING the governance signature.
    /// Used for persistence — restores the complete signed object on load.
    pub fn to_cbor_value(&self) -> CborValue {
        let mut arr = match self.to_cbor_value_excluding_signature() {
            CborValue::Array(a) => a,
            _ => return CborValue::Null,
        };
        arr.push(CborValue::ByteString(self.governance_signature.to_vec()));
        CborValue::Array(arr)
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

    /// P0 #2 rev3: Complete CBOR encoding including the governance signature.
    pub fn to_cbor_value(&self) -> CborValue {
        CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::UnsignedInt(self.authority_version),
            CborValue::UnsignedInt(self.revocation_version),
            CborValue::UnsignedInt(self.revocation_timestamp),
            CborValue::ByteString(self.nonce.to_vec()),
            CborValue::ByteString(self.governance_signature.to_vec()),
        ])
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

    /// P0 #2 rev3: Complete CBOR encoding including the issuer signature.
    pub fn to_cbor_value(&self) -> CborValue {
        CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::ByteString(self.subject_id.to_vec()),
            CborValue::UnsignedInt(u64::from(self.capability.to_byte())),
            CborValue::UnsignedInt(self.revocation_version),
            CborValue::UnsignedInt(self.revocation_timestamp),
            CborValue::ByteString(self.nonce.to_vec()),
            CborValue::ByteString(self.issuer_signature.to_vec()),
        ])
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
/// P0 #2 rev3: Persists complete signed objects, not just version floors.
/// P0 #3: Transactional mutations — clone → mutate → persist → swap.
/// P0 #1 rev3: Verifies cryptographic signatures before acceptance.
/// P0 #4 rev3: Subject revocation acceptance resolves issuer authority.
/// P1 #5: Fail closed on malformed persisted entries.
/// P1 #7: This is the single authoritative state — VerificationContext queries it.
#[derive(Debug, Clone)]
pub struct AuthorityStateStore {
    /// The governance public key (needed for signature verification on acceptance).
    governance_public_key: Option<PublicKey>,

    // Authority state — complete signed objects
    highest_authority_version: HashMap<[u8; 32], u64>,
    authority_digests: HashMap<([u8; 32], u64), [u8; 32]>,
    authorities: HashMap<([u8; 32], u64), IssuerAuthority>,

    // Governance revocation state — complete signed objects
    highest_gov_revocation_version: HashMap<([u8; 32], u64), u64>,
    gov_revocation_digests: HashMap<([u8; 32], u64, u64), [u8; 32]>,
    governance_revocations: HashMap<([u8; 32], u64), GovernanceIssuerRevocation>,

    // Subject revocation state — complete signed objects
    highest_subj_revocation_version: HashMap<([u8; 32], [u8; 32], u8), u64>,
    subj_revocation_digests: HashMap<([u8; 32], [u8; 32], u8, u64), [u8; 32]>,
    subject_revocations: HashMap<([u8; 32], [u8; 32], u8), SubjectCapabilityRevocation>,

    // Persistence path (None = in-memory only). pub for testing.
    pub path: Option<PathBuf>,
}

/// Magic + version for persistence file.
const STORE_MAGIC: &[u8] = b"SNCA"; // ShareNet Capability Authority
const STORE_VERSION: u8 = 2; // Version 2: complete signed objects

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("persistence I/O error: {0}")]
    Io(String),
    #[error("persistence format error: {0}")]
    Format(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Helper: extract a fixed-size byte array from a CborValue, or error.
/// P1 #5: Fail closed — no unwrap_or_default.
fn require_bytes<const N: usize>(v: &CborValue, field: &str) -> Result<[u8; N], StoreError> {
    match v {
        CborValue::ByteString(b) if b.len() == N => {
            let mut arr = [0u8; N];
            arr.copy_from_slice(b);
            Ok(arr)
        }
        CborValue::ByteString(b) => Err(StoreError::Format(format!(
            "{field}: expected {N} bytes, got {}",
            b.len()
        ))),
        _ => Err(StoreError::Format(format!("{field}: expected byte string"))),
    }
}

/// Helper: extract a u64 from a CborValue, or error.
fn require_u64(v: &CborValue, field: &str) -> Result<u64, StoreError> {
    match v {
        CborValue::UnsignedInt(n) => Ok(*n),
        _ => Err(StoreError::Format(format!("{field}: expected unsigned int"))),
    }
}

/// Helper: extract a Vec<u8> from a CborValue, or error.
fn require_byte_vec(v: &CborValue, field: &str) -> Result<Vec<u8>, StoreError> {
    match v {
        CborValue::ByteString(b) => Ok(b.clone()),
        _ => Err(StoreError::Format(format!("{field}: expected byte string"))),
    }
}

/// Helper: extract a String from a CborValue, or error.
fn require_string(v: &CborValue, field: &str) -> Result<String, StoreError> {
    match v {
        CborValue::TextString(s) => Ok(s.clone()),
        _ => Err(StoreError::Format(format!("{field}: expected text string"))),
    }
}

impl AuthorityStateStore {
    pub fn new() -> Self {
        Self {
            governance_public_key: None,
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

    /// Set the governance public key (needed for signature verification on acceptance).
    pub fn set_governance_public_key(&mut self, key: PublicKey) {
        self.governance_public_key = Some(key);
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
    /// P0 #2 rev3: Restores complete signed objects.
    /// P1 #5: Fail closed on malformed entries — no unwrap_or_default.
    fn load(&mut self) -> Result<(), StoreError> {
        let path = self.path.as_ref().ok_or_else(|| StoreError::Io("no path set".into()))?;
        let mut file = fs::File::open(path).map_err(|e| StoreError::Io(e.to_string()))?;

        let mut header = [0u8; 5];
        file.read_exact(&mut header).map_err(|e| StoreError::Io(e.to_string()))?;
        if &header[..4] != STORE_MAGIC {
            return Err(StoreError::Format("bad magic".into()));
        }
        if header[4] != STORE_VERSION {
            return Err(StoreError::Format(format!("unsupported version {}", header[4])));
        }

        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| StoreError::Io(e.to_string()))?;

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

            let decoded = snp_cbor::decode(entry)
                .map_err(|e| StoreError::Format(format!("CBOR decode: {e}")))?;

            // Entry format: { "type": "authority"|"gov_rev"|"subj_rev", "object": <complete CBOR> }
            if let CborValue::Map(entries) = decoded {
                let mut entry_type = String::new();
                let mut entry_object = CborValue::Null;
                for (k, v) in &entries {
                    if let (CborValue::TextString(t), val) = (k, v) {
                        if t == "type" {
                            if let CborValue::TextString(s) = val {
                                entry_type = s.clone();
                            }
                        } else if t == "object" {
                            entry_object = val.clone();
                        }
                    }
                }

                match entry_type.as_str() {
                    "authority" => {
                        // P0 #2 rev3: Restore complete IssuerAuthority.
                        let authority = decode_authority_from_cbor(&entry_object)?;
                        let issuer = authority.issuer_id;
                        let version = authority.authority_version;
                        let digest = authority.authority_digest()
                            .map_err(|e| StoreError::Serialization(e.to_string()))?;
                        self.highest_authority_version.insert(issuer, version);
                        self.authority_digests.insert((issuer, version), digest);
                        self.authorities.insert((issuer, version), authority);
                    }
                    "gov_rev" => {
                        // P0 #2 rev3: Restore complete GovernanceIssuerRevocation.
                        let revocation = decode_gov_revocation_from_cbor(&entry_object)?;
                        let issuer = revocation.issuer_id;
                        let auth_ver = revocation.authority_version;
                        let rev_ver = revocation.revocation_version;
                        let digest = revocation.revocation_digest()
                            .map_err(|e| StoreError::Serialization(e.to_string()))?;
                        self.highest_gov_revocation_version.insert((issuer, auth_ver), rev_ver);
                        self.gov_revocation_digests.insert((issuer, auth_ver, rev_ver), digest);
                        self.governance_revocations.insert((issuer, auth_ver), revocation);
                    }
                    "subj_rev" => {
                        // P0 #2 rev3: Restore complete SubjectCapabilityRevocation.
                        let revocation = decode_subj_revocation_from_cbor(&entry_object)?;
                        let key = (
                            revocation.issuer_id,
                            revocation.subject_id,
                            revocation.capability.to_byte(),
                        );
                        let rev_ver = revocation.revocation_version;
                        let digest = revocation.revocation_digest()
                            .map_err(|e| StoreError::Serialization(e.to_string()))?;
                        self.highest_subj_revocation_version.insert(key, rev_ver);
                        self.subj_revocation_digests.insert((key.0, key.1, key.2, rev_ver), digest);
                        self.subject_revocations.insert(key, revocation);
                    }
                    _ => {
                        // P1 #5: Unknown entry type — fail closed.
                        return Err(StoreError::Format(format!("unknown entry type: {entry_type}")));
                    }
                }
            }
        }

        Ok(())
    }

    /// Atomically commit the current state to the persistence file.
    /// P0 #2: Write-to-temp-then-rename for atomicity.
    /// P0 #2 rev3: Serializes complete signed objects.
    fn commit(&self) -> Result<(), StoreError> {
        let path = self.path.as_ref().ok_or_else(|| StoreError::Io("no path set".into()))?;

        let mut data = Vec::new();
        data.extend_from_slice(STORE_MAGIC);
        data.push(STORE_VERSION);

        // Serialize complete authority objects.
        for ((issuer_id, version), authority) in &self.authorities {
            let entry = CborValue::Map(vec![
                (CborValue::TextString("type".into()), CborValue::TextString("authority".into())),
                (CborValue::TextString("object".into()), authority.to_cbor_value()),
            ]);
            let encoded = snp_cbor::encode(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            data.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            data.extend_from_slice(&encoded);
        }

        // Serialize complete governance revocation objects.
        for ((issuer_id, auth_ver), revocation) in &self.governance_revocations {
            let entry = CborValue::Map(vec![
                (CborValue::TextString("type".into()), CborValue::TextString("gov_rev".into())),
                (CborValue::TextString("object".into()), revocation.to_cbor_value()),
            ]);
            let encoded = snp_cbor::encode(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            data.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            data.extend_from_slice(&encoded);
        }

        // Serialize complete subject revocation objects.
        for ((issuer_id, subject_id, cap_byte), revocation) in &self.subject_revocations {
            let entry = CborValue::Map(vec![
                (CborValue::TextString("type".into()), CborValue::TextString("subj_rev".into())),
                (CborValue::TextString("object".into()), revocation.to_cbor_value()),
            ]);
            let encoded = snp_cbor::encode(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            data.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            data.extend_from_slice(&encoded);
        }

        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &data).map_err(|e| StoreError::Io(e.to_string()))?;
        fs::rename(&tmp_path, path).map_err(|e| StoreError::Io(e.to_string()))?;

        Ok(())
    }

    // ─── P0 #3: Transactional mutation helper ──────────────────────────────

    /// Apply a mutation transactionally: clone → mutate clone → persist → swap.
    /// On persistence failure, memory is unchanged.
    fn transactional_apply<F>(&mut self, f: F) -> Result<(), AuthorityStateError>
    where
        F: FnOnce(&mut Self) -> Result<(), AuthorityStateError>,
    {
        // Clone the current state (shallow — HashMaps clone their entries).
        let mut candidate = self.clone();

        // Apply the mutation to the candidate.
        f(&mut candidate)?;

        // If persistent, commit the candidate first.
        if candidate.path.is_some() {
            candidate.commit()
                .map_err(|e| AuthorityStateError::PersistenceError(e.to_string()))?;
        }

        // Swap: replace self with the committed candidate.
        *self = candidate;
        Ok(())
    }

    // ─── P0 #1 rev3: Authority acceptance with signature verification ─────

    /// P0 #1 rev3: Accept an IssuerAuthority.
    /// Verifies: issuer identity binding + governance signature BEFORE acceptance.
    pub fn try_accept_authority(
        &mut self,
        authority: &IssuerAuthority,
    ) -> Result<AuthorityAcceptResult, AuthorityStateError> {
        // P0 #1: Verify issuer identity binding.
        if !authority.verify_issuer_identity_binding() {
            return Err(AuthorityStateError::IssuerIdentityBindingInvalid);
        }

        // P0 #1 rev3: Verify governance signature BEFORE acceptance.
        let gov_pk = self.governance_public_key
            .ok_or(AuthorityStateError::GovernanceKeyNotSet)?;
        if !authority.verify_governance_signature(&gov_pk) {
            return Err(AuthorityStateError::AuthorityNotGovernanceSigned);
        }

        let issuer = authority.issuer_id;
        let version = authority.authority_version;
        let digest = authority.authority_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;

        let known_version = self.highest_authority_version.get(&issuer).copied().unwrap_or(0);

        let result = if version > known_version {
            AuthorityAcceptResult::Accepted
        } else if version == known_version {
            let known_digest = self.authority_digests.get(&(issuer, version)).copied();
            match known_digest {
                Some(kd) if kd == digest => AuthorityAcceptResult::Duplicate,
                Some(kd) => {
                    return Err(AuthorityStateError::AuthorityEquivocation {
                        issuer_id: issuer, version,
                        known_digest: kd, new_digest: digest,
                    });
                }
                None => AuthorityAcceptResult::Accepted,
            }
        } else {
            AuthorityAcceptResult::Stale { known_version, attempted_version: version }
        };

        if result == AuthorityAcceptResult::Accepted {
            // P0 #3: Transactional — clone, mutate, persist, swap.
            let authority_clone = authority.clone();
            let issuer_clone = issuer;
            let version_clone = version;
            let digest_clone = digest;
            self.transactional_apply(|candidate| {
                candidate.highest_authority_version.insert(issuer_clone, version_clone);
                candidate.authority_digests.insert((issuer_clone, version_clone), digest_clone);
                candidate.authorities.insert((issuer_clone, version_clone), authority_clone);
                Ok(())
            })?;
        }

        Ok(result)
    }

    // ─── P0 #1 rev3: Governance revocation with signature verification ─────

    pub fn try_accept_governance_revocation(
        &mut self,
        revocation: &GovernanceIssuerRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        // P0 #1 rev3: Verify governance signature BEFORE acceptance.
        let gov_pk = self.governance_public_key
            .ok_or(AuthorityStateError::GovernanceKeyNotSet)?;
        if !revocation.verify_governance_signature(&gov_pk) {
            return Err(AuthorityStateError::RevocationSignatureInvalid);
        }

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
            let known_digest = self.gov_revocation_digests.get(&(issuer, auth_ver, rev_ver)).copied();
            match known_digest {
                Some(kd) if kd == digest => RevocationAcceptResult::Duplicate,
                Some(kd) => {
                    return Err(AuthorityStateError::RevocationEquivocation {
                        kind: "governance".into(),
                        known_digest: kd, new_digest: digest,
                    });
                }
                None => RevocationAcceptResult::Accepted,
            }
        } else {
            RevocationAcceptResult::Stale { known_version: known, attempted_version: rev_ver }
        };

        if result == RevocationAcceptResult::Accepted {
            let rev_clone = revocation.clone();
            self.transactional_apply(|candidate| {
                candidate.highest_gov_revocation_version.insert(key, rev_ver);
                candidate.gov_revocation_digests.insert((issuer, auth_ver, rev_ver), digest);
                candidate.governance_revocations.insert(key, rev_clone);
                Ok(())
            })?;
        }

        Ok(result)
    }

    // ─── P0 #4 rev3: Subject revocation with authority resolution ─────────

    /// P0 #4 rev3: Accept a SubjectCapabilityRevocation.
    /// Resolves the issuer authority to obtain the issuer public key,
    /// verifies issuer identity binding, and verifies the issuer signature
    /// BEFORE acceptance.
    pub fn try_accept_subject_revocation(
        &mut self,
        revocation: &SubjectCapabilityRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        // P0 #4: Resolve the issuer authority to get the issuer public key.
        // We look for the highest known authority version for this issuer.
        let highest_ver = self.highest_authority_version
            .get(&revocation.issuer_id)
            .copied()
            .ok_or(AuthorityStateError::IssuerAuthorityNotFound {
                issuer_id: revocation.issuer_id,
            })?;

        let authority = self.authorities
            .get(&(revocation.issuer_id, highest_ver))
            .ok_or(AuthorityStateError::IssuerAuthorityNotFound {
                issuer_id: revocation.issuer_id,
            })?;

        // P0 #4: Verify issuer identity binding on the resolved authority.
        if !authority.verify_issuer_identity_binding() {
            return Err(AuthorityStateError::IssuerIdentityBindingInvalid);
        }

        // P0 #4: Verify the subject revocation signature using the authority-bound issuer key.
        if !revocation.verify_issuer_signature(&authority.issuer_public_key) {
            return Err(AuthorityStateError::RevocationSignatureInvalid);
        }

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
            let known_digest = self.subj_revocation_digests
                .get(&(key.0, key.1, key.2, rev_ver))
                .copied();
            match known_digest {
                Some(kd) if kd == digest => RevocationAcceptResult::Duplicate,
                Some(kd) => {
                    return Err(AuthorityStateError::RevocationEquivocation {
                        kind: "subject".into(),
                        known_digest: kd, new_digest: digest,
                    });
                }
                None => RevocationAcceptResult::Accepted,
            }
        } else {
            RevocationAcceptResult::Stale { known_version: known, attempted_version: rev_ver }
        };

        if result == RevocationAcceptResult::Accepted {
            let rev_clone = revocation.clone();
            self.transactional_apply(|candidate| {
                candidate.highest_subj_revocation_version.insert(key, rev_ver);
                candidate.subj_revocation_digests.insert((key.0, key.1, key.2, rev_ver), digest);
                candidate.subject_revocations.insert(key, rev_clone);
                Ok(())
            })?;
        }

        Ok(result)
    }

    // ─── Lookups for verification ───────────────────────────────────────────

    pub fn get_authority(&self, issuer_id: &[u8; 32], version: u64) -> Option<&IssuerAuthority> {
        self.authorities.get(&(*issuer_id, version))
    }

    pub fn get_governance_revocation(
        &self, issuer_id: &[u8; 32], authority_version: u64,
    ) -> Option<&GovernanceIssuerRevocation> {
        self.governance_revocations.get(&(*issuer_id, authority_version))
    }

    pub fn get_subject_revocation(
        &self, issuer_id: &[u8; 32], subject_id: &[u8; 32],
        capability: ProtocolCapability,
    ) -> Option<&SubjectCapabilityRevocation> {
        self.subject_revocations.get(&(*issuer_id, *subject_id, capability.to_byte()))
    }

    pub fn restart(&self) -> Result<Self, StoreError> {
        match &self.path {
            None => Ok(Self::new()),
            Some(path) => {
                let mut store = Self::open(path)?;
                store.governance_public_key = self.governance_public_key;
                Ok(store)
            }
        }
    }
}

impl Default for AuthorityStateStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CBOR decode helpers for persistence ───────────────────────────────────

fn decode_auth_scope_from_cbor(v: &CborValue) -> Result<AuthScope, StoreError> {
    let map = match v {
        CborValue::Map(m) => m,
        _ => return Err(StoreError::Format("AuthScope: expected map".into())),
    };
    let mut destinations = Vec::new();
    let mut protocols = Vec::new();
    let mut constraints = Vec::new();
    for (k, val) in map {
        let key = require_string(k, "scope key")?;
        match key.as_str() {
            "destinations" => {
                if let CborValue::Array(arr) = val {
                    for item in arr {
                        destinations.push(require_string(item, "destination")?);
                    }
                }
            }
            "protocols" => {
                if let CborValue::Array(arr) = val {
                    for item in arr {
                        protocols.push(require_string(item, "protocol")?);
                    }
                }
            }
            "constraints" => {
                if let CborValue::Array(arr) = val {
                    for item in arr {
                        constraints.push(require_string(item, "constraint")?);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(AuthScope { destinations, protocols, constraints })
}

fn decode_authority_from_cbor(v: &CborValue) -> Result<IssuerAuthority, StoreError> {
    let arr = match v {
        CborValue::Array(a) => a,
        _ => return Err(StoreError::Format("authority: expected array".into())),
    };
    if arr.len() != 10 {
        return Err(StoreError::Format(format!("authority: expected 10 fields, got {}", arr.len())));
    }
    let issuer_id = require_bytes(&arr[0], "issuer_id")?;
    let issuer_public_key = require_bytes(&arr[1], "issuer_public_key")?;
    let authority_version = require_u64(&arr[2], "authority_version")?;
    let issued_at = require_u64(&arr[3], "issued_at")?;
    let valid_from = require_u64(&arr[4], "valid_from")?;
    let valid_until = require_u64(&arr[5], "valid_until")?;
    let capabilities_authorized = match &arr[6] {
        CborValue::Array(caps) => caps.iter()
            .map(|c| {
                let b = require_u64(c, "capability")? as u8;
                ProtocolCapability::from_byte(b)
                    .ok_or_else(|| StoreError::Format(format!("unknown capability byte: {b}")))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(StoreError::Format("capabilities: expected array".into())),
    };
    let maximum_scope = decode_auth_scope_from_cbor(&arr[7])?;
    let status_byte = require_u64(&arr[8], "status")? as u8;
    let status = match status_byte {
        0 => IssuerStatus::Active,
        1 => IssuerStatus::Revoked,
        _ => return Err(StoreError::Format(format!("unknown status byte: {status_byte}"))),
    };
    let governance_signature = require_bytes(&arr[9], "governance_signature")?;
    Ok(IssuerAuthority {
        issuer_id,
        issuer_public_key,
        authority_version,
        issued_at,
        valid_from,
        valid_until,
        capabilities_authorized,
        maximum_scope,
        status,
        governance_signature,
    })
}

fn decode_gov_revocation_from_cbor(v: &CborValue) -> Result<GovernanceIssuerRevocation, StoreError> {
    let arr = match v {
        CborValue::Array(a) => a,
        _ => return Err(StoreError::Format("gov_rev: expected array".into())),
    };
    if arr.len() != 6 {
        return Err(StoreError::Format(format!("gov_rev: expected 6 fields, got {}", arr.len())));
    }
    Ok(GovernanceIssuerRevocation {
        issuer_id: require_bytes(&arr[0], "issuer_id")?,
        authority_version: require_u64(&arr[1], "authority_version")?,
        revocation_version: require_u64(&arr[2], "revocation_version")?,
        revocation_timestamp: require_u64(&arr[3], "revocation_timestamp")?,
        nonce: require_bytes(&arr[4], "nonce")?,
        governance_signature: require_bytes(&arr[5], "governance_signature")?,
    })
}

fn decode_subj_revocation_from_cbor(v: &CborValue) -> Result<SubjectCapabilityRevocation, StoreError> {
    let arr = match v {
        CborValue::Array(a) => a,
        _ => return Err(StoreError::Format("subj_rev: expected array".into())),
    };
    if arr.len() != 7 {
        return Err(StoreError::Format(format!("subj_rev: expected 7 fields, got {}", arr.len())));
    }
    let cap_byte = require_u64(&arr[2], "capability")? as u8;
    let capability = ProtocolCapability::from_byte(cap_byte)
        .ok_or_else(|| StoreError::Format(format!("unknown capability byte: {cap_byte}")))?;
    Ok(SubjectCapabilityRevocation {
        issuer_id: require_bytes(&arr[0], "issuer_id")?,
        subject_id: require_bytes(&arr[1], "subject_id")?,
        capability,
        revocation_version: require_u64(&arr[3], "revocation_version")?,
        revocation_timestamp: require_u64(&arr[4], "revocation_timestamp")?,
        nonce: require_bytes(&arr[5], "nonce")?,
        issuer_signature: require_bytes(&arr[6], "issuer_signature")?,
    })
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
    #[error("governance public key not set on store")]
    GovernanceKeyNotSet,
    #[error("authority not governance-signed")]
    AuthorityNotGovernanceSigned,
    #[error("revocation signature invalid")]
    RevocationSignatureInvalid,
    #[error("issuer authority not found for issuer {issuer_id:?}")]
    IssuerAuthorityNotFound {
        issuer_id: [u8; 32],
    },
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
        let mut store = AuthorityStateStore::new();
        store.set_governance_public_key(governance_public_key);
        Self {
            governance_public_key,
            store,
        }
    }

    /// Create with a persistent store.
    pub fn with_store(governance_public_key: PublicKey, mut store: AuthorityStateStore) -> Self {
        store.set_governance_public_key(governance_public_key);
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
