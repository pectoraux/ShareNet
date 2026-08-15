//! N2.4-02 — Capability & Authority System (revision 4)
//!
//! Implements the approved N2.4-02 Capability System ADR:
//! the governance → issuer → authorization → capability chain.
//!
//! ## Revision 4 corrections (N2.4-I1 rev4)
//!
//! 1. P0 #1: `verify_authorization()` now enforces `IssuerStatus::Active`.
//!    A governance-signed `IssuerAuthority` whose `status == Revoked` is
//!    rejected even when no separate `GovernanceIssuerRevocation` object
//!    exists. The persisted status survives restart and is respected after
//!    reload.
//! 2. P0 #2: `SubjectCapabilityRevocation` is bound to the exact issuing
//!    authority via `issuer_authority_version` + `issuer_authority_digest`
//!    (both covered by the issuer signature). Acceptance resolves the EXACT
//!    authority version — never the "highest" — so a v1 revocation remains
//!    verifiable after a v2 authority with a different issuer key is accepted.
//!    A v2 key cannot masquerade as the signer of a v1 revocation. The
//!    subject-revocation store key incorporates the authority version.
//! 3. P0 #3: Persistence is now durable across power loss:
//!    write temp → fsync temp → atomic rename → fsync parent directory →
//!    expose. Any durability failure rejects the operation with live state
//!    unchanged.
//! 4. P1 #4: `load()` reconstructs state into a temporary candidate and
//!    validates the same cryptographic provenance + equivocation rules used
//!    at ingestion (identity binding, governance signatures, exact
//!    version/digest binding, subject-revocation issuer signatures). The
//!    live store is replaced only after the ENTIRE file validates. One bad
//!    record → entire load fails (no partial authoritative state exposed).
//! 5. P1 #5: `decode_auth_scope_from_cbor()` fails closed
//!    (`StoreError::Format`) when a known field has the wrong CBOR type,
//!    instead of silently skipping it.
//!
//! ## Retained from rev3
//!
//! - Issuer public-key binding (`issuer_id == NodeId(issuer_public_key)`).
//! - Complete signed-object persistence (not version floors).
//! - Transactional mutation (clone → mutate → persist → swap).
//! - Exact governance-revocation version binding.
//! - Same-version equivocation detection via revocation digests.
//! - Safe constraint default (reject, not silently broaden scope).
//! - Unified store/verifier (single source of truth).
//! - Fail-closed serialization.
//! - `authenticate_capability_claim` renamed to `classify_capability_claim`.

use snp_cbor::{encode, CborValue};
use snp_crypto::{
    derive_public_key, domain_hash, ed25519_sign, ed25519_verify, sha256, PublicKey, SecretKey,
    SignatureBytes,
};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
    /// P1 #4 rev5: Semantic validation failed during construction.
    #[error("semantic validation failed: {0}")]
    Semantic(String),
}

type SerResult<T> = Result<T, CapabilitySerializationError>;

fn try_encode(value: &CborValue) -> SerResult<Vec<u8>> {
    encode(value).map_err(|e| CapabilitySerializationError::CborEncode(e.to_string()))
}

// ─── Semantic validation error (P1 #4 rev5) ────────────────────────────────

/// P1 #4 rev5: Structural/semantic validation errors.
/// Cryptographic validity does NOT imply semantic validity. A governance-signed
/// but malformed authority must not enter authoritative state merely because
/// its signature is valid.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SemanticError {
    #[error("valid_from must be < valid_until")]
    InvalidValidityWindow,
    #[error("issued_at must be <= valid_from")]
    IssuedAfterValidFrom,
    #[error("authority_version must be > 0")]
    InvalidAuthorityVersion,
    #[error("revocation_version must be > 0")]
    InvalidRevocationVersion,
    #[error("authority_version in revocation must be > 0")]
    InvalidRevocationAuthorityVersion,
    #[error("configuration_version must be > 0")]
    InvalidVersion,
    #[error("validity_start must be < validity_end")]
    InvalidAuthorizationWindow,
    #[error("authorization lifetime exceeds authority lifetime")]
    AuthorizationExceedsAuthority,
    #[error("capabilities_authorized must not be empty")]
    EmptyCapabilities,
    #[error("scope contains invalid characters or structure")]
    InvalidScopeStructure,
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
    /// P0 #2 rev5: Returns `SerResult` — no `expect()` in security-critical
    /// serialization.
    /// P1 #4 rev5: Also validates semantic invariants on construction.
    pub fn new(
        governance_secret: &SecretKey,
        configuration_version: u64,
        valid_from: u64,
        valid_until: u64,
    ) -> SerResult<Self> {
        let governance_public_key = derive_public_key(governance_secret);
        let governance_id = sha256(&governance_public_key);
        let preimage = Self::preimage_bytes(
            &governance_public_key,
            &governance_id,
            configuration_version,
            valid_from,
            valid_until,
        )?;
        let governance_signature = ed25519_sign(governance_secret, &preimage);
        let anchor = Self {
            governance_public_key,
            governance_id,
            configuration_version,
            valid_from,
            valid_until,
            governance_signature,
        };
        anchor.validate_semantic()
            .map_err(|e| CapabilitySerializationError::Semantic(e.to_string()))?;
        Ok(anchor)
    }

    /// P0 #2 rev5: Propagates `SerResult` — no `expect()`.
    fn preimage_bytes(
        governance_public_key: &PublicKey,
        governance_id: &[u8; 32],
        configuration_version: u64,
        valid_from: u64,
        valid_until: u64,
    ) -> SerResult<Vec<u8>> {
        let cbor = try_encode(&CborValue::Array(vec![
            CborValue::ByteString(governance_public_key.to_vec()),
            CborValue::ByteString(governance_id.to_vec()),
            CborValue::UnsignedInt(configuration_version),
            CborValue::UnsignedInt(valid_from),
            CborValue::UnsignedInt(valid_until),
        ]))?;
        let mut preimage = GOVERNANCE_ANCHOR_CONTEXT.to_vec();
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// P0 #2 rev5: Returns `SerResult` — no `expect()`.
    pub fn canonical_preimage(&self) -> SerResult<Vec<u8>> {
        Self::preimage_bytes(
            &self.governance_public_key,
            &self.governance_id,
            self.configuration_version,
            self.valid_from,
            self.valid_until,
        )
    }

    /// P0 #2 rev5: Fail-closed on serialization error (returns `false`).
    pub fn verify_self_signature(&self) -> bool {
        match self.canonical_preimage() {
            Ok(preimage) => ed25519_verify(
                &self.governance_public_key,
                &preimage,
                &self.governance_signature,
            ),
            Err(_) => false,
        }
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.valid_from && now < self.valid_until
    }

    /// P1 #4 rev5: Structural validity check.
    pub fn validate_semantic(&self) -> Result<(), SemanticError> {
        if self.valid_from >= self.valid_until {
            return Err(SemanticError::InvalidValidityWindow);
        }
        if self.configuration_version == 0 {
            return Err(SemanticError::InvalidVersion);
        }
        Ok(())
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
    /// P0 #1 rev4: Status of this authority. `verify_authorization()` rejects
    /// authorities whose status != Active.
    pub status: IssuerStatus,
    pub governance_signature: SignatureBytes,
}

impl IssuerAuthority {
    /// Create a new IssuerAuthority. The issuer_public_key is derived from
    /// the issuer_secret, and issuer_id is computed as NodeId(issuer_public_key).
    /// P1 #4 rev5: Validates semantic invariants on construction.
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
        auth.validate_semantic()
            .map_err(|e| CapabilitySerializationError::Semantic(e.to_string()))?;
        let preimage = auth.canonical_preimage()?;
        auth.governance_signature = ed25519_sign(governance_secret, &preimage);
        Ok(auth)
    }

    /// P1 #4 rev5: Structural/semantic validity check.
    /// Validates: valid_from < valid_until, issued_at <= valid_from,
    /// authority_version > 0, non-empty capabilities, structurally valid scope.
    pub fn validate_semantic(&self) -> Result<(), SemanticError> {
        if self.valid_from >= self.valid_until {
            return Err(SemanticError::InvalidValidityWindow);
        }
        if self.issued_at > self.valid_from {
            return Err(SemanticError::IssuedAfterValidFrom);
        }
        if self.authority_version == 0 {
            return Err(SemanticError::InvalidAuthorityVersion);
        }
        if self.capabilities_authorized.is_empty() {
            return Err(SemanticError::EmptyCapabilities);
        }
        validate_scope_structure(&self.maximum_scope)?;
        Ok(())
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
        auth.validate_semantic()
            .map_err(|e| CapabilitySerializationError::Semantic(e.to_string()))?;
        let preimage = auth.canonical_preimage()?;
        auth.issuer_signature = ed25519_sign(issuer_secret, &preimage);
        Ok(auth)
    }

    /// P1 #4 rev5: Structural/semantic validity check.
    /// Validates: validity_start < validity_end, authority_version > 0,
    /// structurally valid scope.
    pub fn validate_semantic(&self) -> Result<(), SemanticError> {
        if self.validity_start >= self.validity_end {
            return Err(SemanticError::InvalidAuthorizationWindow);
        }
        if self.issuer_authority_version == 0 {
            return Err(SemanticError::InvalidAuthorityVersion);
        }
        validate_scope_structure(&self.scope)?;
        Ok(())
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
        rev.validate_semantic()
            .map_err(|e| CapabilitySerializationError::Semantic(e.to_string()))?;
        let preimage = rev.canonical_preimage()?;
        rev.governance_signature = ed25519_sign(governance_secret, &preimage);
        Ok(rev)
    }

    /// P1 #4 rev5: Structural/semantic validity check.
    /// Validates: authority_version > 0, revocation_version > 0.
    pub fn validate_semantic(&self) -> Result<(), SemanticError> {
        if self.authority_version == 0 {
            return Err(SemanticError::InvalidRevocationAuthorityVersion);
        }
        if self.revocation_version == 0 {
            return Err(SemanticError::InvalidRevocationVersion);
        }
        Ok(())
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

/// P0 #2 rev4: Subject revocations are now bound to the exact issuing
/// authority via `issuer_authority_version` + `issuer_authority_digest`.
/// Both fields are covered by the issuer signature. Acceptance resolves the
/// EXACT authority version (never the "highest") so that a v1 revocation
/// remains verifiable after a v2 authority (different issuer key) is accepted.
#[derive(Debug, Clone)]
pub struct SubjectCapabilityRevocation {
    pub issuer_id: [u8; 32],
    /// P0 #2 rev4: Exact authority version this revocation was issued under.
    pub issuer_authority_version: u64,
    /// P0 #2 rev4: Digest of the exact authority this revocation binds to.
    pub issuer_authority_digest: [u8; 32],
    pub subject_id: [u8; 32],
    pub capability: ProtocolCapability,
    pub revocation_version: u64,
    pub revocation_timestamp: u64,
    pub nonce: [u8; 16],
    pub issuer_signature: SignatureBytes,
}

impl SubjectCapabilityRevocation {
    /// P0 #2 rev4: `issuer_authority_version` and `issuer_authority_digest`
    /// are now required and are covered by the issuer signature.
    /// P1 #4 rev5: Validates semantic invariants on construction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_secret: &SecretKey,
        issuer_id: [u8; 32],
        issuer_authority_version: u64,
        issuer_authority_digest: [u8; 32],
        subject_id: [u8; 32],
        capability: ProtocolCapability,
        revocation_version: u64,
        revocation_timestamp: u64,
        nonce: [u8; 16],
    ) -> SerResult<Self> {
        let mut rev = Self {
            issuer_id,
            issuer_authority_version,
            issuer_authority_digest,
            subject_id,
            capability,
            revocation_version,
            revocation_timestamp,
            nonce,
            issuer_signature: [0u8; 64],
        };
        rev.validate_semantic()
            .map_err(|e| CapabilitySerializationError::Semantic(e.to_string()))?;
        let preimage = rev.canonical_preimage()?;
        rev.issuer_signature = ed25519_sign(issuer_secret, &preimage);
        Ok(rev)
    }

    /// P1 #4 rev5: Structural/semantic validity check.
    /// Validates: issuer_authority_version > 0, revocation_version > 0.
    pub fn validate_semantic(&self) -> Result<(), SemanticError> {
        if self.issuer_authority_version == 0 {
            return Err(SemanticError::InvalidRevocationAuthorityVersion);
        }
        if self.revocation_version == 0 {
            return Err(SemanticError::InvalidRevocationVersion);
        }
        Ok(())
    }

    pub fn canonical_preimage(&self) -> SerResult<Vec<u8>> {
        let cbor = try_encode(&self.to_cbor_value_excluding_signature())?;
        let mut preimage = SUBJECT_REVOCATION_CONTEXT.to_vec();
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// P0 #2 rev4: Fields excluding signature (signed preimage payload).
    fn to_cbor_value_excluding_signature(&self) -> CborValue {
        CborValue::Array(vec![
            CborValue::ByteString(self.issuer_id.to_vec()),
            CborValue::UnsignedInt(self.issuer_authority_version),
            CborValue::ByteString(self.issuer_authority_digest.to_vec()),
            CborValue::ByteString(self.subject_id.to_vec()),
            CborValue::UnsignedInt(u64::from(self.capability.to_byte())),
            CborValue::UnsignedInt(self.revocation_version),
            CborValue::UnsignedInt(self.revocation_timestamp),
            CborValue::ByteString(self.nonce.to_vec()),
        ])
    }

    /// P0 #2 rev4: Complete CBOR encoding including the issuer signature.
    pub fn to_cbor_value(&self) -> CborValue {
        let mut arr = match self.to_cbor_value_excluding_signature() {
            CborValue::Array(a) => a,
            _ => return CborValue::Null,
        };
        arr.push(CborValue::ByteString(self.issuer_signature.to_vec()));
        CborValue::Array(arr)
    }

    /// P0 #3: Compute the revocation digest for equivocation detection.
    /// P0 #2 rev4: Now includes the authority-version binding fields so that
    /// two revocations bound to different authority versions are distinct.
    pub fn revocation_digest(&self) -> SerResult<[u8; 32]> {
        let cbor = try_encode(&self.to_cbor_value_excluding_signature())?;
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

/// P1 #4 rev5: Validate the structural well-formedness of an AuthScope.
/// Checks that all strings are non-empty and contain no control characters
/// (which could be used to forge misleading scope entries).
fn validate_scope_structure(scope: &AuthScope) -> Result<(), SemanticError> {
    for s in scope.destinations.iter().chain(scope.protocols.iter()).chain(scope.constraints.iter()) {
        if s.is_empty() {
            return Err(SemanticError::InvalidScopeStructure);
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(SemanticError::InvalidScopeStructure);
        }
    }
    Ok(())
}

// ─── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorizationVerifyError {
    /// P0 #1 rev5: Store is in FailedClosed state — verification is rejected.
    #[error("store not operational (failed-closed): {0}")]
    StoreNotOperational(String),
    #[error("step 0: authority status is not Active")]
    AuthorityStatusNotActive,
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

// ─── AuthorityStateStore ───────────────────────────────────────────────────

/// P0 #1 rev5: The persistence state of the store.
/// After a post-rename durability failure, the store enters `FailedClosed`
/// and rejects ALL further capability operations until restart/recovery.
/// This is because disk may already contain the NEW generation while
/// the durability barrier (parent directory fsync) is uncertain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceState {
    /// Normal operation: commits succeed, verification/acceptance allowed.
    Operational,
    /// P0 #1 rev5: A post-rename durability failure occurred. The NEW
    /// generation may be on disk, but the directory metadata is not
    /// guaranteed to be durable. All further operations are rejected until
    /// the store is restarted (re-opened from the persistence file).
    FailedClosed { reason: String },
}

/// Persistent state for the authority chain.
/// P0 #2: Real file-based persistence with atomic commit and fail-closed load.
/// P0 #2 rev3: Persists complete signed objects, not just version floors.
/// P0 #3: Transactional mutations — clone → mutate → persist → swap.
/// P0 #3 rev4: Durable persistence (fsync temp + rename + fsync parent dir).
/// P0 #1 rev5: Commit-point model — rename is the commit point; a post-rename
///             fsync failure enters `FailedClosed`, not a silent rollback.
/// P0 #1 rev3: Verifies cryptographic signatures before acceptance.
/// P0 #2 rev4: Subject revocation bound to exact authority version + digest.
/// P0 #4 rev3: Subject revocation acceptance resolves issuer authority.
/// P1 #4 rev4: load() validates crypto provenance + equivocation into a
///             candidate; live store replaced only after entire file validates.
/// P1 #4 rev5: load() also validates semantic invariants.
/// P1 #5 rev4: Fail closed on malformed persisted entries/fields.
/// P1 #7: This is the single authoritative state — VerificationContext queries it.
#[derive(Debug, Clone)]
pub struct AuthorityStateStore {
    /// The governance public key (needed for signature verification on acceptance/load).
    governance_public_key: Option<PublicKey>,

    // Authority state — complete signed objects
    highest_authority_version: HashMap<[u8; 32], u64>,
    authority_digests: HashMap<([u8; 32], u64), [u8; 32]>,
    authorities: HashMap<([u8; 32], u64), IssuerAuthority>,

    // Governance revocation state — complete signed objects
    highest_gov_revocation_version: HashMap<([u8; 32], u64), u64>,
    gov_revocation_digests: HashMap<([u8; 32], u64, u64), [u8; 32]>,
    governance_revocations: HashMap<([u8; 32], u64), GovernanceIssuerRevocation>,

    // Subject revocation state — complete signed objects.
    // P0 #2 rev4: key now includes issuer_authority_version so that revocations
    // bound to different authority versions coexist as distinct objects.
    highest_subj_revocation_version: HashMap<([u8; 32], [u8; 32], u8, u64), u64>,
    subj_revocation_digests: HashMap<([u8; 32], [u8; 32], u8, u64, u64), [u8; 32]>,
    subject_revocations: HashMap<([u8; 32], [u8; 32], u8, u64), SubjectCapabilityRevocation>,

    /// P0 #1 rev5: The persistence state. After a post-rename durability
    /// failure, this becomes `FailedClosed` and all further operations are
    /// rejected until restart/recovery.
    pub persistence_state: PersistenceState,

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
    /// P0 #3 rev4: durability barrier (fsync) failure.
    #[error("durability barrier failure: {0}")]
    Durability(String),
    /// P0 #1 rev5: Post-rename durability uncertainty. The rename succeeded
    /// (NEW generation is committed on disk), but a subsequent durability
    /// barrier (parent directory fsync) failed. The store MUST enter
    /// `FailedClosed` — it cannot claim durable state is unchanged.
    #[error("post-commit durability uncertainty: {0}")]
    PostCommitDurabilityUncertain(String),
    /// P1 #3 rev5: The platform cannot provide the durability guarantee
    /// required for security-state persistence (e.g. non-Unix without
    /// directory fsync). Fail closed rather than silently succeeding.
    #[error("unsupported platform for durable persistence: {0}")]
    UnsupportedPlatform(String),
    /// P1 #4 rev5: A persisted record failed semantic validation on load.
    #[error("semantic validation failure on load: {0}")]
    SemanticValidation(String),
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

/// Helper: extract a String from a CborValue, or error.
fn require_string(v: &CborValue, field: &str) -> Result<String, StoreError> {
    match v {
        CborValue::TextString(s) => Ok(s.clone()),
        _ => Err(StoreError::Format(format!("{field}: expected text string"))),
    }
}

/// P1 #5 rev4: Helper that requires a CBOR array (fail closed on wrong type).
fn require_array<'a>(v: &'a CborValue, field: &str) -> Result<&'a Vec<CborValue>, StoreError> {
    match v {
        CborValue::Array(a) => Ok(a),
        _ => Err(StoreError::Format(format!("{field}: expected array"))),
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
            persistence_state: PersistenceState::Operational,
            path: None,
        }
    }

    /// P0 #1 rev5: Returns true if the store is operational (not FailedClosed).
    pub fn is_operational(&self) -> bool {
        matches!(self.persistence_state, PersistenceState::Operational)
    }

    /// P0 #1 rev5: Returns a reference to the persistence state for inspection.
    pub fn persistence_state(&self) -> &PersistenceState {
        &self.persistence_state
    }

    /// P0 #1 rev5: Reject all operations if the store is FailedClosed.
    fn ensure_operational(&self) -> Result<(), AuthorityStateError> {
        match &self.persistence_state {
            PersistenceState::Operational => Ok(()),
            PersistenceState::FailedClosed { reason } => Err(
                AuthorityStateError::StoreFailedClosed { reason: reason.clone() },
            ),
        }
    }

    /// Set the governance public key (needed for signature verification on
    /// acceptance). For a persistent store, prefer `open(path, gov_pk)` so
    /// that persisted records are cryptographically validated at load time.
    pub fn set_governance_public_key(&mut self, key: PublicKey) {
        self.governance_public_key = Some(key);
    }

    /// Open a persistent store from a file path.
    /// P0 #2: Fail-closed — corrupted files return an error, not empty state.
    /// P1 #4 rev4: The governance public key is required at open time so that
    /// `load()` can verify the cryptographic provenance of every persisted
    /// record (governance signatures, issuer identity binding, exact
    /// authority-version binding, subject-revocation issuer signatures)
    /// BEFORE the live store is exposed.
    pub fn open(path: &PathBuf, governance_public_key: PublicKey) -> Result<Self, StoreError> {
        let mut store = Self::new();
        store.path = Some(path.clone());
        store.governance_public_key = Some(governance_public_key);

        if path.exists() {
            store.load()?;
        }
        Ok(store)
    }

    /// Load state from the persistence file.
    /// P0 #2: Fail-closed — any error aborts the load.
    /// P0 #2 rev3: Restores complete signed objects.
    /// P1 #4 rev4: Validates the same cryptographic provenance + equivocation
    /// rules used at ingestion, into a temporary candidate. The live store is
    /// replaced only after the ENTIRE file validates. One bad record → entire
    /// load fails (no partial authoritative state exposed).
    fn load(&mut self) -> Result<(), StoreError> {
        let path = self.path.as_ref().ok_or_else(|| StoreError::Io("no path set".into()))?;
        let gov_pk = self.governance_public_key
            .ok_or_else(|| StoreError::Format("governance public key not set for load".into()))?;

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

        // ── Decode pass: parse every length-prefixed entry, reject unknown types.
        //    Store decoded (type, object) pairs for the validation passes.
        type EntryKind = &'static str;
        let mut entries: Vec<(EntryKind, CborValue)> = Vec::new();

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
            let map = match decoded {
                CborValue::Map(m) => m,
                _ => return Err(StoreError::Format("entry: expected map".into())),
            };
            let mut entry_type = String::new();
            let mut entry_object = CborValue::Null;
            for (k, v) in &map {
                if let (CborValue::TextString(t), val) = (k, v) {
                    if t == "type" {
                        if let CborValue::TextString(s) = val {
                            entry_type = s.clone();
                        } else {
                            // P1 #5: type field with wrong CBOR type → fail closed.
                            return Err(StoreError::Format("entry type: expected text string".into()));
                        }
                    } else if t == "object" {
                        entry_object = val.clone();
                    }
                }
            }

            let kind: EntryKind = match entry_type.as_str() {
                "authority" => "authority",
                "gov_rev" => "gov_rev",
                "subj_rev" => "subj_rev",
                other => {
                    // P1 #5: Unknown entry type — fail closed.
                    return Err(StoreError::Format(format!("unknown entry type: {other}")));
                }
            };
            entries.push((kind, entry_object));
        }

        // ── Build a fresh candidate. The live store is untouched until the
        //    entire file validates.
        let mut candidate = Self::new();
        candidate.path = self.path.clone();
        candidate.governance_public_key = Some(gov_pk);

        // Pass 1: authorities (verify identity binding + governance signature,
        //         apply version/digest/equivocation rules, order-independent).
        for (kind, obj) in &entries {
            if *kind != "authority" {
                continue;
            }
            let authority = decode_authority_from_cbor(obj)?;
            // P1 #4 rev5: Validate semantic invariants on load.
            authority.validate_semantic()
                .map_err(|e| StoreError::SemanticValidation(e.to_string()))?;
            if !authority.verify_issuer_identity_binding() {
                return Err(StoreError::Format(
                    "persisted authority: issuer identity binding invalid".into(),
                ));
            }
            if !authority.verify_governance_signature(&gov_pk) {
                return Err(StoreError::Format(
                    "persisted authority: governance signature invalid".into(),
                ));
            }
            Self::load_apply_authority(&mut candidate, &authority)?;
        }

        // Pass 2: governance revocations (verify governance signature,
        //         apply equivocation rules, order-independent).
        for (kind, obj) in &entries {
            if *kind != "gov_rev" {
                continue;
            }
            let revocation = decode_gov_revocation_from_cbor(obj)?;
            // P1 #4 rev5: Validate semantic invariants on load.
            revocation.validate_semantic()
                .map_err(|e| StoreError::SemanticValidation(e.to_string()))?;
            if !revocation.verify_governance_signature(&gov_pk) {
                return Err(StoreError::Format(
                    "persisted governance revocation: signature invalid".into(),
                ));
            }
            Self::load_apply_gov_revocation(&mut candidate, &revocation)?;
        }

        // Pass 3: subject revocations (resolve EXACT authority, verify digest,
        //         identity binding, authority governance signature, issuer
        //         signature; apply equivocation rules, order-independent).
        for (kind, obj) in &entries {
            if *kind != "subj_rev" {
                continue;
            }
            let revocation = decode_subj_revocation_from_cbor(obj)?;
            // P1 #4 rev5: Validate semantic invariants on load.
            revocation.validate_semantic()
                .map_err(|e| StoreError::SemanticValidation(e.to_string()))?;

            let authority = candidate
                .authorities
                .get(&(revocation.issuer_id, revocation.issuer_authority_version))
                .ok_or_else(|| StoreError::Format(format!(
                    "persisted subject revocation: authority not found (issuer {:?} version {})",
                    revocation.issuer_id, revocation.issuer_authority_version
                )))?;

            let computed_digest = authority
                .authority_digest()
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            if computed_digest != revocation.issuer_authority_digest {
                return Err(StoreError::Format(
                    "persisted subject revocation: authority digest mismatch".into(),
                ));
            }
            if !authority.verify_issuer_identity_binding() {
                return Err(StoreError::Format(
                    "persisted subject revocation: authority identity binding invalid".into(),
                ));
            }
            if !authority.verify_governance_signature(&gov_pk) {
                return Err(StoreError::Format(
                    "persisted subject revocation: authority governance signature invalid".into(),
                ));
            }
            if !revocation.verify_issuer_signature(&authority.issuer_public_key) {
                return Err(StoreError::Format(
                    "persisted subject revocation: issuer signature invalid".into(),
                ));
            }
            Self::load_apply_subj_revocation(&mut candidate, &revocation)?;
        }

        // ── Only replace the live store after the ENTIRE file validates.
        *self = candidate;
        Ok(())
    }

    /// Atomically AND durably commit the current state to the persistence file.
    /// P0 #2: Write-to-temp-then-rename for atomicity.
    /// P0 #2 rev3: Serializes complete signed objects.
    /// P0 #3 rev4: Durability sequence:
    ///     write temp → fsync temp → atomic rename → fsync parent directory
    /// P0 #1 rev5: Commit-point model — the RENAME is the commit point.
    ///     - Pre-rename failures (temp create/write/fsync) return a normal
    ///       `StoreError`; the caller (transactional_apply) does NOT swap
    ///       memory, so old state remains authoritative.
    ///     - Post-rename failures (parent directory fsync) return
    ///       `StoreError::PostCommitDurabilityUncertain`; the caller MUST swap
    ///       memory to the candidate (disk has the NEW generation) AND mark
    ///       the store `FailedClosed`.
    fn commit(&self) -> Result<(), StoreError> {
        let path = self.path.as_ref().ok_or_else(|| StoreError::Io("no path set".into()))?;

        // P1 #3 rev5: Verify the platform supports the durability guarantee
        // BEFORE attempting any I/O. On unsupported platforms, fail closed
        // rather than silently reporting a successful security-state commit.
        if !Self::platform_supports_durable_fsync() {
            return Err(StoreError::UnsupportedPlatform(
                "durable authority-state persistence requires Unix directory fsync; \
                 this platform cannot provide the durability guarantee".into(),
            ));
        }

        let mut data = Vec::new();
        data.extend_from_slice(STORE_MAGIC);
        data.push(STORE_VERSION);

        // Serialize complete authority objects.
        for authority in self.authorities.values() {
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
        for revocation in self.governance_revocations.values() {
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
        for revocation in self.subject_revocations.values() {
            let entry = CborValue::Map(vec![
                (CborValue::TextString("type".into()), CborValue::TextString("subj_rev".into())),
                (CborValue::TextString("object".into()), revocation.to_cbor_value()),
            ]);
            let encoded = snp_cbor::encode(&entry)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            data.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            data.extend_from_slice(&encoded);
        }

        // ── P0 #1 rev5: durable persistence sequence with commit-point model ──
        let tmp_path = path.with_extension("tmp");

        // 1. Write temp file. (PRE-RENAME: failure → rollback OK)
        let mut tmp_file = fs::File::create(&tmp_path)
            .map_err(|e| StoreError::Io(format!("temp create: {e}")))?;
        tmp_file
            .write_all(&data)
            .map_err(|e| StoreError::Io(format!("temp write: {e}")))?;

        // 2. fsync temp file data (durability of the data itself). (PRE-RENAME)
        tmp_file
            .sync_all()
            .map_err(|e| StoreError::Durability(format!("fsync temp: {e}")))?;

        // Close the temp handle BEFORE rename (Windows requires it; harmless on Unix).
        drop(tmp_file);

        // 3. Atomic rename. THIS IS THE COMMIT POINT.
        //    After this succeeds, the NEW generation is committed on disk.
        //    Any failure here is a pre-commit failure (old state remains).
        fs::rename(&tmp_path, path)
            .map_err(|e| StoreError::Io(format!("rename: {e}")))?;

        // 4. fsync the parent directory so the rename is durable across power loss.
        //    P0 #1 rev5: If this fails, the NEW generation is already on disk
        //    (rename succeeded), but the directory metadata durability is
        //    uncertain. Return PostCommitDurabilityUncertain so the caller
        //    enters FailedClosed — do NOT claim durable state is unchanged.
        if let Some(parent) = path.parent() {
            Self::fsync_dir(parent).map_err(|e| match e {
                StoreError::UnsupportedPlatform(msg) => {
                    StoreError::PostCommitDurabilityUncertain(msg)
                }
                StoreError::Durability(msg) => {
                    StoreError::PostCommitDurabilityUncertain(msg)
                }
                other => other,
            })?;
        }

        Ok(())
    }

    /// P1 #3 rev5: Returns true if the platform supports the directory-fsync
    /// durability guarantee required for security-state persistence.
    /// The reference implementation scopes durable persistence to Unix.
    fn platform_supports_durable_fsync() -> bool {
        cfg!(unix)
    }

    /// P0 #3 rev4: fsync a directory's metadata (durability barrier for renames).
    /// Opens the directory read-only and calls sync_all() (fsync on Unix).
    #[cfg(unix)]
    fn fsync_dir(dir: &Path) -> Result<(), StoreError> {
        let d = fs::File::open(dir)
            .map_err(|e| StoreError::Durability(format!("open parent dir {dir:?}: {e}")))?;
        d.sync_all()
            .map_err(|e| StoreError::Durability(format!("fsync parent dir {dir:?}: {e}")))?;
        Ok(())
    }

    /// P1 #3 rev5: Non-Unix platforms cannot provide the directory-fsync
    /// durability guarantee. Fail closed with `UnsupportedPlatform` rather
    /// than silently returning Ok(()). The reference implementation declares
    /// durable authority-state persistence Unix-only for I1.
    #[cfg(not(unix))]
    fn fsync_dir(_dir: &Path) -> Result<(), StoreError> {
        Err(StoreError::UnsupportedPlatform(
            "directory fsync is not available on this platform; \
             durable authority-state persistence is Unix-only".into(),
        ))
    }

    // ─── P0 #3: Transactional mutation helper ──────────────────────────────

    /// Apply a mutation transactionally: clone → mutate clone → persist → swap.
    /// P0 #3 rev4: Returns the closure's value so acceptance methods can return
    /// their classify result. On persistence failure, memory is unchanged
    /// (the `?` returns before the swap).
    /// P0 #1 rev5: Commit-point model — if `commit()` returns
    /// `PostCommitDurabilityUncertain` (rename succeeded but parent fsync
    /// failed), memory IS swapped to the candidate (disk has the NEW
    /// generation), but the store enters `FailedClosed`. All further
    /// operations are rejected until restart/recovery.
    fn transactional_apply<T, F>(&mut self, f: F) -> Result<T, AuthorityStateError>
    where
        F: FnOnce(&mut Self) -> Result<T, AuthorityStateError>,
    {
        // P0 #1 rev5: Reject all operations if the store is FailedClosed.
        self.ensure_operational()?;

        // Clone the current state (shallow — HashMaps clone their entries).
        let mut candidate = self.clone();

        // Apply the mutation to the candidate.
        let result = f(&mut candidate)?;

        // If persistent, durably commit the candidate first.
        if candidate.path.is_some() {
            match candidate.commit() {
                Ok(()) => {}
                Err(StoreError::PostCommitDurabilityUncertain(reason)) => {
                    // P0 #1 rev5: Rename succeeded → NEW generation is committed
                    // on disk. Memory MUST switch to the candidate (disk and
                    // memory agree on the NEW state), but the store enters
                    // FailedClosed because the durability barrier is uncertain.
                    candidate.persistence_state = PersistenceState::FailedClosed {
                        reason: reason.clone(),
                    };
                    *self = candidate;
                    return Err(AuthorityStateError::PersistenceUncertain { reason });
                }
                Err(e) => {
                    // Pre-rename failure: old memory remains authoritative.
                    return Err(AuthorityStateError::PersistenceError(e.to_string()));
                }
            }
        }

        // Swap: replace self with the committed candidate.
        *self = candidate;
        Ok(result)
    }

    // ─── In-memory classify + insert (accept semantics) ───────────────────
    //
    // `classify_*` perform a READ-ONLY version/digest/equivocation check and
    // return the Accept result WITHOUT mutating. `insert_*` materialize the
    // object (caller has already classified as Accepted). The `try_accept_*`
    // methods call `classify_*` on self; only when the result is `Accepted` do
    // they invoke `transactional_apply(|c| c.insert_*(...))` (which clones,
    // inserts, durably commits, and swaps). Duplicate / Stale / Equivocation
    // therefore NEVER trigger a (possibly failing) commit.

    /// Read-only classification of an authority (no mutation).
    /// Precondition: identity binding + governance signature already verified
    /// by the caller.
    fn classify_authority(
        &self,
        authority: &IssuerAuthority,
    ) -> Result<AuthorityAcceptResult, AuthorityStateError> {
        let issuer = authority.issuer_id;
        let version = authority.authority_version;
        let digest = authority
            .authority_digest()
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
                        issuer_id: issuer,
                        version,
                        known_digest: kd,
                        new_digest: digest,
                    });
                }
                None => AuthorityAcceptResult::Accepted,
            }
        } else {
            AuthorityAcceptResult::Stale { known_version, attempted_version: version }
        };

        Ok(result)
    }

    /// Insert an authority (caller has already classified as Accepted).
    /// Called inside `transactional_apply`; performs NO persistence.
    fn insert_authority(&mut self, authority: &IssuerAuthority) -> Result<(), AuthorityStateError> {
        let issuer = authority.issuer_id;
        let version = authority.authority_version;
        let digest = authority
            .authority_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;
        self.highest_authority_version.insert(issuer, version);
        self.authority_digests.insert((issuer, version), digest);
        self.authorities.insert((issuer, version), authority.clone());
        Ok(())
    }

    /// Read-only classification of a governance revocation (no mutation).
    /// Precondition: governance signature already verified by the caller.
    fn classify_gov_revocation(
        &self,
        revocation: &GovernanceIssuerRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        let issuer = revocation.issuer_id;
        let auth_ver = revocation.authority_version;
        let rev_ver = revocation.revocation_version;
        let digest = revocation
            .revocation_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;

        let key = (issuer, auth_ver);
        let known = self.highest_gov_revocation_version.get(&key).copied().unwrap_or(0);

        let result = if rev_ver > known {
            RevocationAcceptResult::Accepted
        } else if rev_ver == known {
            let known_digest =
                self.gov_revocation_digests.get(&(issuer, auth_ver, rev_ver)).copied();
            match known_digest {
                Some(kd) if kd == digest => RevocationAcceptResult::Duplicate,
                Some(kd) => {
                    return Err(AuthorityStateError::RevocationEquivocation {
                        kind: "governance".into(),
                        known_digest: kd,
                        new_digest: digest,
                    });
                }
                None => RevocationAcceptResult::Accepted,
            }
        } else {
            RevocationAcceptResult::Stale { known_version: known, attempted_version: rev_ver }
        };

        Ok(result)
    }

    /// Insert a governance revocation (caller has already classified as Accepted).
    fn insert_gov_revocation(
        &mut self,
        revocation: &GovernanceIssuerRevocation,
    ) -> Result<(), AuthorityStateError> {
        let issuer = revocation.issuer_id;
        let auth_ver = revocation.authority_version;
        let rev_ver = revocation.revocation_version;
        let digest = revocation
            .revocation_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;
        let key = (issuer, auth_ver);
        self.highest_gov_revocation_version.insert(key, rev_ver);
        self.gov_revocation_digests.insert((issuer, auth_ver, rev_ver), digest);
        self.governance_revocations.insert(key, revocation.clone());
        Ok(())
    }

    /// Read-only classification of a subject revocation (no mutation).
    /// Precondition: exact authority resolution + digest match + issuer
    /// signature already verified by the caller.
    /// P0 #2 rev4: key incorporates `issuer_authority_version`.
    fn classify_subj_revocation(
        &self,
        revocation: &SubjectCapabilityRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        let issuer = revocation.issuer_id;
        let subject = revocation.subject_id;
        let cap = revocation.capability.to_byte();
        let auth_ver = revocation.issuer_authority_version;
        let rev_ver = revocation.revocation_version;
        let key = (issuer, subject, cap, auth_ver);
        let digest = revocation
            .revocation_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;

        let known = self.highest_subj_revocation_version.get(&key).copied().unwrap_or(0);

        let result = if rev_ver > known {
            RevocationAcceptResult::Accepted
        } else if rev_ver == known {
            let known_digest = self
                .subj_revocation_digests
                .get(&(issuer, subject, cap, auth_ver, rev_ver))
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
            RevocationAcceptResult::Stale { known_version: known, attempted_version: rev_ver }
        };

        Ok(result)
    }

    /// Insert a subject revocation (caller has already classified as Accepted).
    /// P0 #2 rev4: key incorporates `issuer_authority_version`.
    fn insert_subj_revocation(
        &mut self,
        revocation: &SubjectCapabilityRevocation,
    ) -> Result<(), AuthorityStateError> {
        let issuer = revocation.issuer_id;
        let subject = revocation.subject_id;
        let cap = revocation.capability.to_byte();
        let auth_ver = revocation.issuer_authority_version;
        let rev_ver = revocation.revocation_version;
        let key = (issuer, subject, cap, auth_ver);
        let digest = revocation
            .revocation_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;
        self.highest_subj_revocation_version.insert(key, rev_ver);
        self.subj_revocation_digests
            .insert((issuer, subject, cap, auth_ver, rev_ver), digest);
        self.subject_revocations.insert(key, revocation.clone());
        Ok(())
    }

    // ─── Load-time apply (order-independent) ───────────────────────────────
    //
    // Used by `load()`. These insert by EXACT key regardless of file order,
    // but still detect same-key equivocation (same (issuer,version) with a
    // different digest). They perform NO persistence and NO accept-path
    // "Stale" reporting — every record is materialized.

    /// Order-independent authority insertion for `load()`.
    /// Fails on same (issuer, version) with a different digest (equivocation).
    fn load_apply_authority(
        candidate: &mut Self,
        authority: &IssuerAuthority,
    ) -> Result<(), StoreError> {
        let issuer = authority.issuer_id;
        let version = authority.authority_version;
        let digest = authority
            .authority_digest()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        let key = (issuer, version);

        if let Some(existing) = candidate.authority_digests.get(&key).copied() {
            if existing != digest {
                return Err(StoreError::Format(format!(
                    "persisted authority equivocation: issuer {issuer:?} version {version} \
                     known digest {existing:?} but new digest {digest:?}"
                )));
            }
            // identical duplicate — already present; nothing to do.
        } else {
            candidate.authority_digests.insert(key, digest);
            candidate.authorities.insert(key, authority.clone());
        }

        let cur = candidate.highest_authority_version.get(&issuer).copied().unwrap_or(0);
        if version > cur {
            candidate.highest_authority_version.insert(issuer, version);
        }
        Ok(())
    }

    /// Order-independent governance-revocation insertion for `load()`.
    fn load_apply_gov_revocation(
        candidate: &mut Self,
        revocation: &GovernanceIssuerRevocation,
    ) -> Result<(), StoreError> {
        let issuer = revocation.issuer_id;
        let auth_ver = revocation.authority_version;
        let rev_ver = revocation.revocation_version;
        let digest = revocation
            .revocation_digest()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        let key = (issuer, auth_ver);

        if let Some(existing) =
            candidate.gov_revocation_digests.get(&(issuer, auth_ver, rev_ver)).copied()
        {
            if existing != digest {
                return Err(StoreError::Format(format!(
                    "persisted governance revocation equivocation: issuer {issuer:?} \
                     authority_version {auth_ver} rev_version {rev_ver}"
                )));
            }
        } else {
            candidate
                .gov_revocation_digests
                .insert((issuer, auth_ver, rev_ver), digest);
            candidate.governance_revocations.insert(key, revocation.clone());
        }

        let cur = candidate.highest_gov_revocation_version.get(&key).copied().unwrap_or(0);
        if rev_ver > cur {
            candidate.highest_gov_revocation_version.insert(key, rev_ver);
        }
        Ok(())
    }

    /// Order-independent subject-revocation insertion for `load()`.
    /// P0 #2 rev4: key incorporates `issuer_authority_version`.
    fn load_apply_subj_revocation(
        candidate: &mut Self,
        revocation: &SubjectCapabilityRevocation,
    ) -> Result<(), StoreError> {
        let issuer = revocation.issuer_id;
        let subject = revocation.subject_id;
        let cap = revocation.capability.to_byte();
        let auth_ver = revocation.issuer_authority_version;
        let rev_ver = revocation.revocation_version;
        let key = (issuer, subject, cap, auth_ver);
        let digest = revocation
            .revocation_digest()
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        if let Some(existing) = candidate
            .subj_revocation_digests
            .get(&(issuer, subject, cap, auth_ver, rev_ver))
            .copied()
        {
            if existing != digest {
                return Err(StoreError::Format(format!(
                    "persisted subject revocation equivocation: issuer {issuer:?} \
                     subject {subject:?} capability {cap} authority_version {auth_ver} \
                     rev_version {rev_ver}"
                )));
            }
        } else {
            candidate
                .subj_revocation_digests
                .insert((issuer, subject, cap, auth_ver, rev_ver), digest);
            candidate.subject_revocations.insert(key, revocation.clone());
        }

        let cur = candidate.highest_subj_revocation_version.get(&key).copied().unwrap_or(0);
        if rev_ver > cur {
            candidate.highest_subj_revocation_version.insert(key, rev_ver);
        }
        Ok(())
    }

    // ─── P0 #1 rev3: Authority acceptance with signature verification ─────

    /// P0 #1 rev3: Accept an IssuerAuthority.
    /// Verifies: semantic invariants + issuer identity binding + governance signature
    /// BEFORE acceptance.
    pub fn try_accept_authority(
        &mut self,
        authority: &IssuerAuthority,
    ) -> Result<AuthorityAcceptResult, AuthorityStateError> {
        // P0 #1 rev5: Reject if store is FailedClosed.
        self.ensure_operational()?;

        // P1 #4 rev5: Validate semantic invariants.
        authority.validate_semantic()
            .map_err(|e| AuthorityStateError::SemanticError(e.to_string()))?;

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

        // Classify read-only; only persist on an actual state change (Accepted).
        // Duplicate / Stale must NOT trigger a (possibly failing) commit.
        let result = self.classify_authority(authority)?;
        if result == AuthorityAcceptResult::Accepted {
            self.transactional_apply(|c| c.insert_authority(authority))?;
        }
        Ok(result)
    }

    // ─── P0 #1 rev3: Governance revocation with signature verification ─────

    pub fn try_accept_governance_revocation(
        &mut self,
        revocation: &GovernanceIssuerRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        // P0 #1 rev5: Reject if store is FailedClosed.
        self.ensure_operational()?;

        // P1 #4 rev5: Validate semantic invariants.
        revocation.validate_semantic()
            .map_err(|e| AuthorityStateError::SemanticError(e.to_string()))?;

        // P0 #1 rev3: Verify governance signature BEFORE acceptance.
        let gov_pk = self.governance_public_key
            .ok_or(AuthorityStateError::GovernanceKeyNotSet)?;
        if !revocation.verify_governance_signature(&gov_pk) {
            return Err(AuthorityStateError::RevocationSignatureInvalid);
        }

        let result = self.classify_gov_revocation(revocation)?;
        if result == RevocationAcceptResult::Accepted {
            self.transactional_apply(|c| c.insert_gov_revocation(revocation))?;
        }
        Ok(result)
    }

    // ─── P0 #2 rev4: Subject revocation bound to EXACT authority ──────────

    /// P0 #4 rev3 / P0 #2 rev4: Accept a SubjectCapabilityRevocation.
    ///
    /// Resolves the EXACT `issuer_authority_version` declared by the
    /// revocation (NOT the highest known authority version), verifies:
    ///   - the authority's digest matches `issuer_authority_digest`
    ///   - the authority's issuer identity binding
    ///   - the authority's governance signature
    ///   - the subject-revocation issuer signature with that exact authority key
    /// BEFORE acceptance.
    pub fn try_accept_subject_revocation(
        &mut self,
        revocation: &SubjectCapabilityRevocation,
    ) -> Result<RevocationAcceptResult, AuthorityStateError> {
        // P0 #1 rev5: Reject if store is FailedClosed.
        self.ensure_operational()?;

        // P1 #4 rev5: Validate semantic invariants.
        revocation.validate_semantic()
            .map_err(|e| AuthorityStateError::SemanticError(e.to_string()))?;

        // P0 #2 rev4: Resolve the EXACT authority version declared by the revocation.
        let authority = self
            .authorities
            .get(&(revocation.issuer_id, revocation.issuer_authority_version))
            .ok_or(AuthorityStateError::IssuerAuthorityNotFound {
                issuer_id: revocation.issuer_id,
                version: revocation.issuer_authority_version,
            })?;

        // P0 #2 rev4: Verify the authority digest matches the revocation's binding.
        let computed_digest = authority
            .authority_digest()
            .map_err(|e| AuthorityStateError::SerializationError(e.to_string()))?;
        if computed_digest != revocation.issuer_authority_digest {
            return Err(AuthorityStateError::AuthorityDigestMismatch);
        }

        // P0 #4: Verify issuer identity binding on the resolved authority.
        if !authority.verify_issuer_identity_binding() {
            return Err(AuthorityStateError::IssuerIdentityBindingInvalid);
        }

        // P0 #2 rev4: Verify the authority's governance signature.
        let gov_pk = self.governance_public_key
            .ok_or(AuthorityStateError::GovernanceKeyNotSet)?;
        if !authority.verify_governance_signature(&gov_pk) {
            return Err(AuthorityStateError::AuthorityNotGovernanceSigned);
        }

        // P0 #2 rev4: Verify the subject revocation signature with the
        // EXACT authority-bound issuer key.
        if !revocation.verify_issuer_signature(&authority.issuer_public_key) {
            return Err(AuthorityStateError::RevocationSignatureInvalid);
        }

        let result = self.classify_subj_revocation(revocation)?;
        if result == RevocationAcceptResult::Accepted {
            self.transactional_apply(|c| c.insert_subj_revocation(revocation))?;
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

    /// P0 #2 rev4: Subject-revocation lookup now requires the exact
    /// `authority_version` the authorization was issued under. A v1
    /// authorization is checked only against v1 revocations.
    pub fn get_subject_revocation(
        &self,
        issuer_id: &[u8; 32],
        subject_id: &[u8; 32],
        capability: ProtocolCapability,
        authority_version: u64,
    ) -> Option<&SubjectCapabilityRevocation> {
        self.subject_revocations
            .get(&(*issuer_id, *subject_id, capability.to_byte(), authority_version))
    }

    pub fn restart(&self) -> Result<Self, StoreError> {
        match (&self.path, self.governance_public_key) {
            (None, _) => Ok(Self::new()),
            (Some(path), Some(gov_pk)) => Self::open(path, gov_pk),
            (Some(_), None) => Err(StoreError::Io(
                "cannot restart persistent store: governance public key not set".into(),
            )),
        }
    }
}

impl Default for AuthorityStateStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CBOR decode helpers for persistence ───────────────────────────────────

/// P1 #5 rev4: decode_auth_scope_from_cbor now FAILS CLOSED when a known
/// field (`destinations` / `protocols` / `constraints`) has the wrong CBOR
/// type. Previously, a malformed field was silently skipped, which could turn
/// malformed persisted security state into a different valid semantic object.
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
                let arr = require_array(val, "destinations")?;
                for item in arr {
                    destinations.push(require_string(item, "destination")?);
                }
            }
            "protocols" => {
                let arr = require_array(val, "protocols")?;
                for item in arr {
                    protocols.push(require_string(item, "protocol")?);
                }
            }
            "constraints" => {
                let arr = require_array(val, "constraints")?;
                for item in arr {
                    constraints.push(require_string(item, "constraint")?);
                }
            }
            // P1 #5 rev4: Unknown forward-compatible fields are tolerated.
            // (No typed constraint semantics exist yet, so an unknown scope
            // key cannot widen authorization; it is ignored.)
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

/// P0 #2 rev4: SubjectCapabilityRevocation now decodes 9 fields (was 7):
///   issuer_id, issuer_authority_version, issuer_authority_digest,
///   subject_id, capability, revocation_version, revocation_timestamp,
///   nonce, issuer_signature
fn decode_subj_revocation_from_cbor(v: &CborValue) -> Result<SubjectCapabilityRevocation, StoreError> {
    let arr = match v {
        CborValue::Array(a) => a,
        _ => return Err(StoreError::Format("subj_rev: expected array".into())),
    };
    if arr.len() != 9 {
        return Err(StoreError::Format(format!("subj_rev: expected 9 fields, got {}", arr.len())));
    }
    let issuer_id = require_bytes(&arr[0], "issuer_id")?;
    let issuer_authority_version = require_u64(&arr[1], "issuer_authority_version")?;
    let issuer_authority_digest = require_bytes(&arr[2], "issuer_authority_digest")?;
    let subject_id = require_bytes(&arr[3], "subject_id")?;
    let cap_byte = require_u64(&arr[4], "capability")? as u8;
    let capability = ProtocolCapability::from_byte(cap_byte)
        .ok_or_else(|| StoreError::Format(format!("unknown capability byte: {cap_byte}")))?;
    let revocation_version = require_u64(&arr[5], "revocation_version")?;
    let revocation_timestamp = require_u64(&arr[6], "revocation_timestamp")?;
    let nonce = require_bytes(&arr[7], "nonce")?;
    let issuer_signature = require_bytes(&arr[8], "issuer_signature")?;
    Ok(SubjectCapabilityRevocation {
        issuer_id,
        issuer_authority_version,
        issuer_authority_digest,
        subject_id,
        capability,
        revocation_version,
        revocation_timestamp,
        nonce,
        issuer_signature,
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
    /// P0 #2 rev4: subject revocation bound to an authority whose digest does
    /// not match `issuer_authority_digest`.
    #[error("authority digest mismatch on subject revocation binding")]
    AuthorityDigestMismatch,
    #[error("revocation signature invalid")]
    RevocationSignatureInvalid,
    #[error("issuer authority not found for issuer {issuer_id:?} version {version}")]
    IssuerAuthorityNotFound {
        issuer_id: [u8; 32],
        version: u64,
    },
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("persistence error: {0}")]
    PersistenceError(String),
    /// P0 #1 rev5: Post-rename durability uncertainty. The store has entered
    /// `FailedClosed`; all further operations are rejected until restart.
    #[error("persistence uncertainty (store failed-closed): {reason}")]
    PersistenceUncertain { reason: String },
    /// P0 #1 rev5: Store is in FailedClosed state. All operations rejected.
    #[error("store failed-closed: {reason}")]
    StoreFailedClosed { reason: String },
    /// P1 #4 rev5: Semantic validation failure.
    #[error("semantic validation error: {0}")]
    SemanticError(String),
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
    /// P1 #4 rev4: the store should have been opened via
    /// `AuthorityStateStore::open(path, gov_pk)` so that persisted records were
    /// cryptographically validated at load time.
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

    /// P0 #1 rev4: Verify a CapabilityAuthorization using the 12-step algorithm.
    /// The issuer public key is obtained from the authority, NOT from the caller.
    ///
    /// Step 0 (rev4): the resolved authority's status MUST be Active. A
    /// governance-signed authority carrying `status == Revoked` is rejected
    /// here, independent of any `GovernanceIssuerRevocation` object.
    pub fn verify_authorization(
        &self,
        auth: &CapabilityAuthorization,
        now: u64,
    ) -> Result<(), AuthorizationVerifyError> {
        // P0 #1 rev5: Reject verification if the store is FailedClosed.
        if !self.store.is_operational() {
            let reason = match &self.store.persistence_state {
                PersistenceState::FailedClosed { reason } => reason.clone(),
                PersistenceState::Operational => String::new(),
            };
            return Err(AuthorizationVerifyError::StoreNotOperational(reason));
        }

        // Step 2: Resolve the authority by issuer_id + version.
        let authority = self
            .store
            .get_authority(&auth.issuer_id, auth.issuer_authority_version)
            .ok_or(AuthorizationVerifyError::AuthorityNotFound {
                issuer_id: auth.issuer_id,
                version: auth.issuer_authority_version,
            })?;

        // P0 #1 rev4: Step 0 — authority status MUST be Active.
        if authority.status != IssuerStatus::Active {
            return Err(AuthorizationVerifyError::AuthorityStatusNotActive);
        }

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

        // Step 12 (rev4): Check subject is not revoked under the EXACT
        // authority version this authorization was issued under. A v1
        // authorization is not revoked by a v2 (different issuer key) revocation.
        if self.store.get_subject_revocation(
            &auth.issuer_id,
            &auth.subject_id,
            auth.capability,
            auth.issuer_authority_version,
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
