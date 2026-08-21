//! SNP-IDENTITY — The four-way identity split for `ShareNet` 2.0
//!
//! Implements SNP/0.1 §2 (identity). `ShareNet` splits identity into four
//! distinct objects to avoid the audit's finding that `NodeId` was a "key, a
//! hash, and a routing locator all at once":
//!
//! 1. **`IdentityKey`** — the Ed25519 secret key, never transmitted.
//! 2. **`NodeId`** — `SHA-256("SNP/0.1 node\0" || pk)` (per I4), the durable
//!    identifier. NOT the bare public key, NOT a routing locator.
//! 3. **`DeviceCert`** — a short-lived certificate binding a `NodeId` to a
//!    device public key, signed by the node's identity key.
//! 4. **`NodeDescriptor`** — the signed, broadcastable record containing the
//!    `NodeId`, supported link types, capabilities, and current device cert.
//!
//! This crate implements `NodeId` derivation and Ed25519 signature verification
//! against the committed conformance vectors in
//! `public/conformance/vectors/03-identity.json`. The full `DeviceCert` /
//! `NodeDescriptor` CBOR structures are not yet implemented; they are exercised
//! by the conformance harness as `UNSUPPORTED` where they require CBOR
//! reconstruction of complex payload shapes.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// R4.2 interop: allow common pedantic lints that do not indicate bugs.
#![allow(
    clippy::must_use_candidate,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::return_self_not_must_use,
    clippy::map_unwrap_or,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    clippy::double_must_use,
    clippy::items_after_statements,
    clippy::should_implement_trait,
    clippy::match_same_arms,
    clippy::semicolon_if_nothing_returned
)]

use thiserror::Error;

/// Errors from SNP identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// A signature over a `DeviceCert` or `NodeDescriptor` failed verification.
    #[error("invalid identity signature")]
    InvalidSignature,
    /// A certificate has expired.
    #[error("certificate expired")]
    Expired,
    /// A certificate was issued for a different `NodeId` than the one presented.
    #[error("NodeId mismatch in certificate")]
    NodeIdMismatch,
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// R2.2 (DESCRIPTOR-EXTRACTION): a `GatewayAdvertisement` / descriptor
    /// failed to (de)serialise for a reason NOT covered by [`Self::Cbor`]
    /// (e.g. a required CBOR field was missing, or a field had the wrong
    /// CBOR type). The previous snp-node implementation surfaced these as
    /// `NodeError::Other(format!(...))`; snp-identity surfaces them as
    /// `IdentityError::Other(String)` so callers can map them back to
    /// `NodeError::Other` without losing the diagnostic message.
    #[error("{0}")]
    Other(String),
}

// ─── Identity Lifecycle (R4.9.1) ───────────────────────────────────────

/// The lifecycle state of a node identity. **R4.9.1.**
///
/// This state does NOT confer cryptographic authority — it is operational
/// metadata that governs whether the identity should be used for new
/// authenticated operations. The cryptographic validity of signatures and
/// handshakes remains determined by the existing Ed25519 / SNP-IK protocol.
///
/// # States
///
/// - **`Active`** — normal operating state. The identity may authenticate,
///   sign custody operations, sign protocol responses, and publish
///   advertisements.
///
/// - **`Rotating`** — rotation has begun but the new identity is not
///   authoritative yet. The old identity remains authoritative during this
///   state. The new identity must not become active until durable
///   persistence succeeds.
///
/// - **`Revoked`** — the identity is no longer valid for new authenticated
///   operations. Historical verification of existing signatures remains
///   possible where the protocol already supports it.
///
/// - **`Retired`** — permanently superseded. A retired identity must never
///   be selected as the active identity for a new authenticated session.
///   Historical cryptographic verification remains possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityState {
    /// Normal operating state — identity is authoritative.
    Active,
    /// Rotation in progress — old identity remains authoritative.
    Rotating,
    /// No longer valid for new authenticated operations.
    Revoked,
    /// Permanently superseded — never selected for new sessions.
    Retired,
}

impl IdentityState {
    /// Returns `true` if this state permits new authenticated operations
    /// (SNP-IK sessions, custody signing, advertisement publishing).
    #[must_use]
    pub fn is_active_for_new_operations(self) -> bool {
        matches!(self, Self::Active)
    }

    /// String representation for persistence.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Retired => "retired",
        }
    }

    /// Parse from string representation.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "revoked" => Some(Self::Revoked),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

/// Errors from identity lifecycle operations.
#[derive(Debug, Error)]
pub enum IdentityLifecycleError {
    /// The identity file is corrupt (truncated, invalid format, wrong version).
    #[error("corrupt identity file: {0}")]
    Corrupt(String),
    /// An IO error occurred during persistence.
    #[error("identity IO error: {0}")]
    Io(String),
    /// Rotation was attempted from a non-Active state.
    #[error("cannot begin rotation from {current:?} state (must be Active)")]
    InvalidRotationSource {
        /// The current lifecycle state.
        current: IdentityState,
    },
    /// Rotation completion was attempted without a pending new identity.
    #[error("cannot complete rotation — no pending new identity")]
    NoPendingRotation,
    /// An operation was attempted on a revoked or retired identity.
    #[error("identity is {state:?} — operation rejected")]
    IdentityNotActive {
        /// The lifecycle state that rejected the operation.
        state: IdentityState,
    },
}

/// The identity file format magic + version.
const IDENTITY_FILE_MAGIC: &[u8; 4] = b"SNPI";
const IDENTITY_FILE_VERSION: u8 = 1;

/// A lifecycle wrapper around [`NodeIdentity`]. **R4.9.1.**
///
/// Provides:
/// - Durable identity persistence (atomic write + fsync + rename)
/// - Atomic identity rotation (old identity remains active until new is
///   durably persisted)
/// - Explicit lifecycle states (`Active`, `Rotating`, `Revoked`, `Retired`)
/// - Startup load/create with fail-closed corruption handling
///
/// # Invariant
///
/// ```text
/// Durable state FIRST
/// Memory mutation SECOND
/// ```
///
/// Rotation:
/// ```text
/// old identity Active
///     → begin_rotation(new_identity) → state = Rotating
///     → persist new identity (fsync)
///     → success → state = Active (new identity)
///     → failure → state = Active (old identity restored)
/// ```
///
/// # File Format
///
/// ```text
/// [4 bytes: magic "SNPI"]
/// [1 byte: version = 1]
/// [32 bytes: Ed25519 secret key]
/// [variable: lifecycle state string (null-terminated)]
/// ```
///
/// The public key and NodeId are recomputed from the secret key — they are
/// NEVER independently trusted from the file.
pub struct IdentityLifecycle {
    /// The current authoritative identity.
    identity: NodeIdentity,
    /// The current lifecycle state.
    state: IdentityState,
    /// The pending new identity during rotation (if any).
    pending_new: Option<NodeIdentity>,
    /// The path to the identity file (if file-backed).
    path: Option<std::path::PathBuf>,
}

impl IdentityLifecycle {
    /// Create a new `IdentityLifecycle` with the given identity in `Active`
    /// state. Does NOT persist — use `save()` or `load_or_create()` for
    /// durability.
    #[must_use]
    pub fn new(identity: NodeIdentity) -> Self {
        Self {
            identity,
            state: IdentityState::Active,
            pending_new: None,
            path: None,
        }
    }

    /// Generate a fresh identity and create a lifecycle in `Active` state.
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        let _ = getrandom::getrandom(&mut secret);
        Self::new(NodeIdentity::from_secret(secret))
    }

    /// Load an identity from a file, or create + persist a new one if the
    /// file does not exist. **Fail-closed on corruption.**
    ///
    /// # Errors
    /// - `Corrupt` if the file exists but is malformed (wrong magic,
    ///   unsupported version, truncated, invalid state string).
    /// - `Io` if the file cannot be read/written.
    pub fn load_or_create(path: impl AsRef<std::path::Path>) -> Result<Self, IdentityLifecycleError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            Self::load(&path)
        } else {
            let mut lifecycle = Self::generate();
            lifecycle.path = Some(path.clone());
            lifecycle.save()?;
            Ok(lifecycle)
        }
    }

    /// Load an identity from a file. **Fail-closed on corruption.**
    ///
    /// # Errors
    /// - `Corrupt` if the file is malformed.
    /// - `Io` if the file cannot be read.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, IdentityLifecycleError> {
        let path = path.as_ref().to_path_buf();
        let data = std::fs::read(&path)
            .map_err(|e| IdentityLifecycleError::Io(format!("read {}: {e}", path.display())))?;
        // Minimum: magic (4) + version (1) + secret_key (32) + state string + null.
        if data.len() < 4 + 1 + 32 + 1 {
            return Err(IdentityLifecycleError::Corrupt(format!(
                "file too short: {} bytes",
                data.len()
            )));
        }
        // Check magic.
        if &data[..4] != IDENTITY_FILE_MAGIC {
            return Err(IdentityLifecycleError::Corrupt(format!(
                "invalid magic: expected {:?}, got {:?}",
                IDENTITY_FILE_MAGIC,
                &data[..4]
            )));
        }
        // Check version.
        if data[4] != IDENTITY_FILE_VERSION {
            return Err(IdentityLifecycleError::Corrupt(format!(
                "unsupported version: expected {}, got {}",
                IDENTITY_FILE_VERSION, data[4]
            )));
        }
        // Extract secret key.
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&data[5..37]);
        // Extract lifecycle state (null-terminated string after byte 37).
        let state_bytes = &data[37..];
        let state_str = match state_bytes.iter().position(|&b| b == 0) {
            Some(pos) => std::str::from_utf8(&state_bytes[..pos])
                .map_err(|e| IdentityLifecycleError::Corrupt(format!("state not UTF-8: {e}")))?,
            None => std::str::from_utf8(state_bytes)
                .map_err(|e| IdentityLifecycleError::Corrupt(format!("state not UTF-8: {e}")))?,
        };
        let state = IdentityState::from_str(state_str).ok_or_else(|| {
            IdentityLifecycleError::Corrupt(format!("unknown lifecycle state: \"{state_str}\""))
        })?;
        let identity = NodeIdentity::from_secret(secret);
        Ok(Self {
            identity,
            state,
            pending_new: None,
            path: Some(path),
        })
    }

    /// Persist the current identity + lifecycle state to the file.
    /// Uses atomic write-to-temp-then-rename + fsync.
    ///
    /// # Errors
    /// - `Io` if persistence fails.
    /// - No file path set → no-op (returns `Ok`).
    pub fn save(&self) -> Result<(), IdentityLifecycleError> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()),
        };
        let mut data = Vec::with_capacity(4 + 1 + 32 + 16);
        data.extend_from_slice(IDENTITY_FILE_MAGIC);
        data.push(IDENTITY_FILE_VERSION);
        data.extend_from_slice(&self.identity.secret_key);
        data.extend_from_slice(self.state.as_str().as_bytes());
        data.push(0); // null terminator
        // Atomic write: write to temp, fsync, rename, fsync dir.
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &data)
            .map_err(|e| IdentityLifecycleError::Io(format!("write tmp: {e}")))?;
        // fsync temp file.
        {
            let file = std::fs::File::open(&tmp_path)
                .map_err(|e| IdentityLifecycleError::Io(format!("open tmp for fsync: {e}")))?;
            file.sync_all()
                .map_err(|e| IdentityLifecycleError::Io(format!("fsync tmp: {e}")))?;
        }
        // Atomic rename.
        std::fs::rename(&tmp_path, path)
            .map_err(|e| IdentityLifecycleError::Io(format!("rename: {e}")))?;
        // fsync parent directory.
        if let Some(dir) = path.parent() {
            let dir_file = std::fs::File::open(dir)
                .map_err(|e| IdentityLifecycleError::Io(format!("open dir for fsync: {e}")))?;
            dir_file
                .sync_all()
                .map_err(|e| IdentityLifecycleError::Io(format!("fsync dir: {e}")))?;
        }
        Ok(())
    }

    /// Get the current authoritative identity.
    #[must_use]
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Get the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> IdentityState {
        self.state
    }

    /// Returns `true` if the identity is `Active` and can be used for new
    /// authenticated operations.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.is_active_for_new_operations()
    }

    /// Returns `true` if the identity has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.state == IdentityState::Revoked
    }

    /// Returns `true` if the identity is authorized for new authenticated
    /// sessions. This is the authorization boundary — it combines the
    /// lifecycle state with any external revocation store.
    ///
    /// For R4.9.2, this checks only the local lifecycle state.
    /// A revoked or retired identity is NOT authorized.
    #[must_use]
    pub fn is_authorized_for_new_sessions(&self) -> bool {
        self.state == IdentityState::Active
    }

    /// Begin identity rotation. The old identity remains authoritative
    /// until `complete_rotation()` succeeds.
    ///
    /// # Errors
    /// - `InvalidRotationSource` if the current state is not `Active`.
    pub fn begin_rotation(&mut self, new_identity: NodeIdentity) -> Result<(), IdentityLifecycleError> {
        if self.state != IdentityState::Active {
            return Err(IdentityLifecycleError::InvalidRotationSource {
                current: self.state,
            });
        }
        self.state = IdentityState::Rotating;
        self.pending_new = Some(new_identity);
        Ok(())
    }

    /// Complete identity rotation: persist the new identity, then make it
    /// authoritative. If persistence fails, the old identity is restored.
    ///
    /// # Errors
    /// - `NoPendingRotation` if `begin_rotation` was not called.
    /// - `Io` if persistence fails (old identity remains active).
    pub fn complete_rotation(&mut self) -> Result<(), IdentityLifecycleError> {
        let new_identity = self
            .pending_new
            .take()
            .ok_or(IdentityLifecycleError::NoPendingRotation)?;
        // Persist the NEW identity FIRST (durable before memory mutation).
        let old_identity = std::mem::replace(&mut self.identity, new_identity);
        // On success, state becomes Active. On failure, state reverts to Active
        // (the old identity is restored — it was Active before rotation began).
        self.state = IdentityState::Active;
        match self.save() {
            Ok(()) => {
                // Success — new identity is now authoritative + durable.
                Ok(())
            }
            Err(e) => {
                // Failure — restore the old identity + revert to Active.
                self.identity = old_identity;
                // old_state was Rotating, but since we're restoring the old
                // identity, the effective state is Active (the old identity
                // was Active before rotation began).
                self.state = IdentityState::Active;
                Err(e)
            }
        }
    }

    /// Revoke the identity. After revocation, the identity cannot be used
    /// for new authenticated operations. The revocation is persisted.
    ///
    /// # Errors
    /// - `Io` if persistence fails (state is NOT changed on failure).
    pub fn revoke(&mut self) -> Result<(), IdentityLifecycleError> {
        let old_state = self.state;
        self.state = IdentityState::Revoked;
        match self.save() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = old_state;
                Err(e)
            }
        }
    }

    /// Retire the identity. A retired identity is permanently superseded
    /// and must never be selected for new sessions. The retirement is
    /// persisted.
    ///
    /// # Errors
    /// - `Io` if persistence fails (state is NOT changed on failure).
    pub fn retire(&mut self) -> Result<(), IdentityLifecycleError> {
        let old_state = self.state;
        self.state = IdentityState::Retired;
        match self.save() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = old_state;
                Err(e)
            }
        }
    }

    /// Get the path to the identity file, if file-backed.
    #[must_use]
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Set the file path for persistence. Chainable.
    #[must_use]
    pub fn with_path(mut self, path: impl AsRef<std::path::Path>) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }
}

// ─── Revocation Store (R4.9.2) ───────────────────────────────────────────

/// The revocation store file format magic + version.
const REVOCATION_FILE_MAGIC: &[u8; 4] = b"SNPR";
const REVOCATION_FILE_VERSION: u8 = 1;

/// A durable store of revoked NodeIds. **R4.9.2.**
///
/// This is the trust enforcement boundary: a NodeId in this store is
/// NOT authorized for new authenticated sessions, new trust decisions,
/// or new advertisement authority — even if its cryptographic signatures
/// remain valid for historical verification.
///
/// # Persistence
///
/// Uses the same atomic write-to-temp-then-rename + fsync pattern as
/// `IdentityLifecycle` and `PersistentBundleStore`. Revocation survives
/// restart.
///
/// # Invariant
///
/// ```text
/// Durable state FIRST
/// Memory mutation SECOND
/// ```
///
/// # Local vs Remote
///
/// - **Local revocation:** `IdentityLifecycle::revoke()` persists the
///   local identity's revocation. The `RevocationStore` records the
///   local NodeId for consistency.
/// - **Remote revocation:** A peer is marked as revoked based on
///   authoritative information available to the node. R4.9.2 does NOT
///   implement distributed revocation — it provides the local trust
///   enforcement boundary.
pub struct RevocationStore {
    /// The set of revoked NodeIds.
    revoked: std::collections::HashSet<NodeId>,
    /// The path to the revocation file (if file-backed).
    path: Option<std::path::PathBuf>,
}

impl RevocationStore {
    /// Create a new empty `RevocationStore` (in-memory only).
    #[must_use]
    pub fn new() -> Self {
        Self {
            revoked: std::collections::HashSet::new(),
            path: None,
        }
    }

    /// Open a durable `RevocationStore` from a file, or create a new empty
    /// one if the file does not exist. **Fail-closed on corruption.**
    ///
    /// # Errors
    /// - `Corrupt` if the file exists but is malformed.
    /// - `Io` if the file cannot be read/written.
    pub fn load_or_create(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, IdentityLifecycleError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            Self::load(&path)
        } else {
            Ok(Self {
                revoked: std::collections::HashSet::new(),
                path: Some(path),
            })
        }
    }

    /// Load a `RevocationStore` from a file. **Fail-closed on corruption.**
    ///
    /// # File format
    /// ```text
    /// [4 bytes: magic "SNPR"]
    /// [1 byte: version = 1]
    /// [4 bytes: count (u32 big-endian)]
    /// [count × 32 bytes: NodeId entries]
    /// ```
    ///
    /// # Errors
    /// - `Corrupt` if the file is malformed.
    /// - `Io` if the file cannot be read.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, IdentityLifecycleError> {
        let path = path.as_ref().to_path_buf();
        let data = std::fs::read(&path)
            .map_err(|e| IdentityLifecycleError::Io(format!("read {}: {e}", path.display())))?;
        // Minimum: magic (4) + version (1) + count (4) = 9 bytes.
        if data.len() < 9 {
            return Err(IdentityLifecycleError::Corrupt(format!(
                "revocation file too short: {} bytes",
                data.len()
            )));
        }
        if &data[..4] != REVOCATION_FILE_MAGIC {
            return Err(IdentityLifecycleError::Corrupt(format!(
                "invalid revocation file magic: expected {:?}, got {:?}",
                REVOCATION_FILE_MAGIC,
                &data[..4]
            )));
        }
        if data[4] != REVOCATION_FILE_VERSION {
            return Err(IdentityLifecycleError::Corrupt(format!(
                "unsupported revocation file version: expected {}, got {}",
                REVOCATION_FILE_VERSION, data[4]
            )));
        }
        let count = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
        let expected_len = 9 + count * 32;
        if data.len() != expected_len {
            return Err(IdentityLifecycleError::Corrupt(format!(
                "revocation file length mismatch: expected {expected_len}, got {}",
                data.len()
            )));
        }
        let mut revoked = std::collections::HashSet::new();
        for i in 0..count {
            let offset = 9 + i * 32;
            let mut node_id = [0u8; 32];
            node_id.copy_from_slice(&data[offset..offset + 32]);
            revoked.insert(node_id);
        }
        Ok(Self {
            revoked,
            path: Some(path),
        })
    }

    /// Persist the revocation store to the file.
    /// Uses atomic write-to-temp-then-rename + fsync.
    ///
    /// # Errors
    /// - `Io` if persistence fails.
    /// - No file path set → no-op (returns `Ok`).
    pub fn save(&self) -> Result<(), IdentityLifecycleError> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()),
        };
        let count = u32::try_from(self.revoked.len()).unwrap_or(u32::MAX);
        let mut data = Vec::with_capacity(9 + self.revoked.len() * 32);
        data.extend_from_slice(REVOCATION_FILE_MAGIC);
        data.push(REVOCATION_FILE_VERSION);
        data.extend_from_slice(&count.to_be_bytes());
        for node_id in &self.revoked {
            data.extend_from_slice(node_id);
        }
        // Atomic write: write to temp, fsync, rename, fsync dir.
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &data)
            .map_err(|e| IdentityLifecycleError::Io(format!("write tmp: {e}")))?;
        {
            let file = std::fs::File::open(&tmp_path)
                .map_err(|e| IdentityLifecycleError::Io(format!("open tmp for fsync: {e}")))?;
            file.sync_all()
                .map_err(|e| IdentityLifecycleError::Io(format!("fsync tmp: {e}")))?;
        }
        std::fs::rename(&tmp_path, path)
            .map_err(|e| IdentityLifecycleError::Io(format!("rename: {e}")))?;
        if let Some(dir) = path.parent() {
            let dir_file = std::fs::File::open(dir)
                .map_err(|e| IdentityLifecycleError::Io(format!("open dir for fsync: {e}")))?;
            dir_file
                .sync_all()
                .map_err(|e| IdentityLifecycleError::Io(format!("fsync dir: {e}")))?;
        }
        Ok(())
    }

    /// Add a NodeId to the revocation set. **Durable — persists before
    /// returning.**
    ///
    /// # Errors
    /// - `Io` if persistence fails (the NodeId is NOT added to memory).
    pub fn revoke(&mut self, node_id: NodeId) -> Result<(), IdentityLifecycleError> {
        if self.revoked.contains(&node_id) {
            return Ok(()); // Already revoked — idempotent.
        }
        self.revoked.insert(node_id);
        match self.save() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.revoked.remove(&node_id);
                Err(e)
            }
        }
    }

    /// Check if a NodeId is revoked. Returns `true` if the NodeId is in
    /// the revocation set.
    #[must_use]
    pub fn is_revoked(&self, node_id: &NodeId) -> bool {
        self.revoked.contains(node_id)
    }

    /// Returns `true` if the NodeId is authorized for new authenticated
    /// sessions. This is the trust enforcement boundary: a revoked NodeId
    /// is NOT authorized.
    #[must_use]
    pub fn is_authorized_for_new_sessions(&self, node_id: &NodeId) -> bool {
        !self.is_revoked(node_id)
    }

    /// Get the number of revoked NodeIds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Returns `true` if no NodeIds are revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Set the file path for persistence. Chainable.
    #[must_use]
    pub fn with_path(mut self, path: impl AsRef<std::path::Path>) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }
}

impl Default for RevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience `Result` alias.
pub type IdentityResult<T> = Result<T, IdentityError>;

/// A 32-byte `NodeId`: `SHA-256("SNP/0.1 node\0" || pk)`.
pub type NodeId = [u8; 32];

/// Domain-separation tag used in `NodeId` derivation (I4).
pub const NODE_ID_DOMAIN: &[u8] = snp_crypto::NODE_ID_DOMAIN;

/// Derive a `NodeId` from an Ed25519 public key.
///
/// Per invariant I4: `NodeId = SHA-256("SNP/0.1 node\0" || pk)`. The bare key
/// is NEVER used as a `NodeId`.
#[must_use]
pub fn derive_node_id(public_key: &snp_crypto::PublicKey) -> NodeId {
    snp_crypto::derive_node_id(public_key)
}

/// Verify an Ed25519 signature made under a specific `SIG_CONTEXT`.
///
/// Preimage = `sig_context(name) || bytes`. Returns `true` iff the signature
/// is valid under RFC 8032 verification for `public_key`.
///
/// Returns `false` if `name` is not a known `SIG_CONTEXT`.
#[must_use]
pub fn verify_signed(
    public_key: &snp_crypto::PublicKey,
    context_name: &str,
    payload_bytes: &[u8],
    signature: &snp_crypto::SignatureBytes,
) -> bool {
    let Some(ctx) = snp_crypto::sig_context(context_name) else {
        return false;
    };
    let mut preimage = Vec::with_capacity(ctx.len() + payload_bytes.len());
    preimage.extend_from_slice(ctx);
    preimage.extend_from_slice(payload_bytes);
    snp_crypto::ed25519_verify(public_key, &preimage, signature)
}

/// Current unix timestamp in seconds.
///
/// R2.2 (DESCRIPTOR-EXTRACTION): moved verbatim from
/// `snp-node/src/node/mod.rs` so the `GatewayAdvertisement` constructors in
/// [`gateway`] can use it without depending on snp-node. snp-node's
/// `node::mod.rs` re-exports this via `pub(crate) use snp_identity::now_unix;`
/// so all existing in-crate callers (`now_unix()`, `super::now_unix()`)
/// continue to compile.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// === Submodules ===
//
// R2.2 (DESCRIPTOR-EXTRACTION): the `gateway` and `descriptor` modules were
// moved verbatim from `snp-node/src/node/{gateway,descriptor}.rs`. The CBOR
// encoding, signature preimage, verification logic, and type-system
// distinctions are byte-for-byte identical to the pre-extraction
// implementation — no field names, types, or canonical-CBOR shapes were
// changed.

pub mod descriptor;
pub mod gateway;

// Re-export the public types at the crate root for ergonomic access
// (`snp_identity::GatewayAdvertisement`, etc.).
pub use descriptor::{
    verify_node_id_consistency, IdentityConsistentNodeDescriptor, TransportEndpoint,
    UnverifiedNodeDescriptor, VerifiedGatewayAdvertisement, VerifiedNodeDescriptor,
};
pub use gateway::{GatewayAdvertisement, ADVERTISEMENT_TTL_SECS};

// === Runtime identity types (extracted from snp-node/src/node/identity.rs) ===
//
// These are the production identity types used by the runtime. They were
// previously owned by snp-node but are extracted here (R2.2) to establish
// the L1 identity layer as a real architectural boundary.
//
// The older skeleton types (DeviceCert, Capabilities struct, NodeDescriptor)
// below are retained for API compatibility but are NOT used by the runtime.

/// A node's cryptographic identity: Ed25519 secret key, public key, `NodeId`.
///
/// `NodeId = SHA-256("SNP/0.1 node\0" || public_key)` per invariant I4 — the
/// bare public key is NEVER used as a `NodeId`.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    /// Ed25519 secret key (32 bytes).
    pub secret_key: [u8; 32],
    /// Ed25519 public key (32 bytes), derived from `secret_key`.
    pub public_key: [u8; 32],
    /// `NodeId` = `SHA-256("SNP/0.1 node\0" || public_key)`.
    pub node_id: [u8; 32],
}

impl NodeIdentity {
    /// Construct a `NodeIdentity` from a secret key.
    #[must_use]
    pub fn from_secret(secret_key: [u8; 32]) -> Self {
        let public_key = snp_crypto::derive_public_key(&secret_key);
        let node_id = snp_crypto::derive_node_id(&public_key);
        Self {
            secret_key,
            public_key,
            node_id,
        }
    }

    /// Construct a gateway identity from an X25519 keypair in addition to
    /// the Ed25519 identity.
    ///
    /// **N2.0.5:** This is the canonical production constructor for gateway
    /// nodes. The Ed25519 keypair provides the node's signing identity; the
    /// X25519 keypair provides the static key for the SNP-IK/0.1 handshake.
    #[must_use]
    pub fn new_with_x25519(secret_key: [u8; 32]) -> Self {
        Self::from_secret(secret_key)
    }
}

/// A node's role in the network. A single node MAY hold multiple capabilities
/// (e.g. a gateway might also relay), but in N2.0.1 each node has exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Can send `TransitRequests` (a client node).
    Client,
    /// Can forward frames between peers (a relay node).
    Relay,
    /// Can terminate circuits and fetch from the Internet (a gateway node).
    Gateway,
}

impl Capability {
    /// String representation for advertisement serialisation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Client => "client",
            Capability::Relay => "relay",
            Capability::Gateway => "gateway",
        }
    }

    /// Parse from string (for advertisement deserialisation).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Capability::Client),
            "relay" => Some(Capability::Relay),
            "gateway" => Some(Capability::Gateway),
            _ => None,
        }
    }
}

// === Frozen wire types (R4.2 interop — NodeDescriptor + DeviceCert) ========
//
// The frozen TS reference (`src/lib/snp/identity.ts`) defines `NodeDescriptor`
// and `DeviceCert` with specific field sets that do NOT match the previous
// Rust skeleton. The skeleton had wrong fields (node_id/identity_key/
// device_cert/capabilities/seq/issued_at/signature) and no codecs.
//
// This implementation matches the frozen TS `nodeDescriptorToCborMap` /
// `nodeDescriptorFromWireMap` (identity.ts:362-382, sync.ts:552-570) +
// `deviceCertToCborMap` (identity.ts:229-239) field-for-field, and provides
// the canonical byte-level encoder/decoder that R4.2's `DescriptorPayload`
// carries.
//
// CDDL (02-PROTOCOL-SPEC.md §4.4, identity.ts:305-318):
//   NodeDescriptor = {
//     nodeId:        bstr .size 32,
//     nodePubKey:    bstr .size 32,
//     rendezvousPub: bstr .size 32,
//     capabilities:  [+ tstr],
//     platform:      tstr,
//     protoVersion:  tstr,            ; "SNP/0.1"
//     epoch:         uint,
//     expiresAt:     uint,
//     links:         [* tstr],
//     deviceCert:    DeviceCert / null,
//     signature:     bstr .size 64
//   }
//
//   DeviceCert = {
//     deviceId:      bstr .size 32,
//     userId:        bstr .size 32,
//     capabilities:  [+ tstr],
//     platform:      tstr,
//     notBefore:     uint,
//     notAfter:      uint,
//     attestation:   bstr / null,
//     signature:     bstr .size 64
//   }
//
// The NodeDescriptor signature preimage is
// `SIG_CONTEXT("nodeDescriptor") ‖ CBOR(fields 1-10)` (identity.ts:387-388).
// The `signature` field is NOT part of the signed preimage. The embedded
// `deviceCert.signature` (if any) IS part of the signed preimage — it is
// bound into the descriptor so stripping/substituting the DeviceCert
// invalidates the descriptor signature.
//
// The DeviceCert signature preimage is
// `SIG_CONTEXT("deviceCert") ‖ CBOR(fields 1-7)` (identity.ts:244-245).

/// Protocol version string (frozen: `"SNP/0.1"`).
pub const PROTO_VERSION: &str = "SNP/0.1";

/// Allowed capability strings (frozen: constants.ts:69-80).
pub const CAPABILITIES: &[&str] = &[
    "MESH_CLIENT",
    "MESH_RELAY",
    "INTERNET_GATEWAY",
    "CONTENT_SEED",
    "STORAGE",
    "DISCOVERY",
    "SYNC",
    "COMPUTE",
    "COMMUNITY_RELAY",
    "CUSTODY",
];

/// Allowed platform strings (frozen: constants.ts:109-116).
pub const PLATFORMS: &[&str] = &["android", "ios", "linux", "windows", "macos", "embedded"];

/// A 64-byte Ed25519 signature.
pub type DescriptorSignature = [u8; 64];

// ─── DeviceCert (frozen identity.ts:192-217) ──────────────────────────────

/// A complete `DeviceCert`, including the 64-byte Ed25519 signature.
///
/// Binds a device to a user identity with capabilities, platform, validity
/// window, and optional hardware attestation. Signed by the `UserIdentity`'s
/// key under `SIG_CONTEXT` `"deviceCert"`.
///
/// # Wire format
///
/// `encode_cbor()` produces canonical CBOR matching the TS
/// `deviceCertToCborMap`. `decode_cbor()` is the inverse. The decode is
/// STRUCTURAL ONLY — it does NOT verify the signature (use `verify` for
/// that). This preserves the separation: decode ≠ verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    /// `NodeId` (32 bytes) of the device's Ed25519 identity key.
    pub device_id: NodeId,
    /// `NodeId` (32 bytes) of the user's Ed25519 identity key.
    pub user_id: NodeId,
    /// Capabilities the device is authorised to advertise.
    pub capabilities: Vec<String>,
    /// Platform string (one of `PLATFORMS`).
    pub platform: String,
    /// Validity start (unix seconds).
    pub not_before: u64,
    /// Validity end (unix seconds).
    pub not_after: u64,
    /// Platform hardware attestation or `None`. Treated as advisory reputation
    /// input ONLY — never trusted without external verification.
    pub attestation: Option<Vec<u8>>,
    /// 64-byte Ed25519 signature by the `UserIdentity` under `SIG_CONTEXT`
    /// `"deviceCert"`.
    pub signature: DescriptorSignature,
}

/// Fields of a `DeviceCert`, excluding the signature. This is what gets signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertUnsigned {
    /// `NodeId` (32 bytes) of the device's Ed25519 identity key.
    pub device_id: NodeId,
    /// `NodeId` (32 bytes) of the user's Ed25519 identity key.
    pub user_id: NodeId,
    /// Capabilities the device is authorised to advertise.
    pub capabilities: Vec<String>,
    /// Platform string (one of `PLATFORMS`).
    pub platform: String,
    /// Validity start (unix seconds).
    pub not_before: u64,
    /// Validity end (unix seconds).
    pub not_after: u64,
    /// Platform hardware attestation or `None`.
    pub attestation: Option<Vec<u8>>,
}

impl DeviceCert {
    /// The `SIG_CONTEXT` name for `DeviceCert` signatures (`"deviceCert"`).
    pub const SIG_CONTEXT_NAME: &'static str = "deviceCert";

    /// Construct the unsigned fields view (excludes `signature`).
    #[must_use]
    pub fn unsigned(&self) -> DeviceCertUnsigned {
        DeviceCertUnsigned {
            device_id: self.device_id,
            user_id: self.user_id,
            capabilities: self.capabilities.clone(),
            platform: self.platform.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
            attestation: self.attestation.clone(),
        }
    }

    /// Build the canonical CBOR wire representation (INCLUDES `signature`).
    /// Used for the nested `deviceCert` field in `NodeDescriptor`.
    fn to_cbor_value(&self) -> snp_cbor::CborValue {
        use snp_cbor::CborValue;
        let mut entries = match self.unsigned_cbor() {
            CborValue::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((
            CborValue::TextString("signature".into()),
            CborValue::ByteString(self.signature.to_vec()),
        ));
        CborValue::Map(entries)
    }

    /// Build the canonical CBOR preimage map for a `DeviceCert`, EXCLUDING the
    /// `signature` field (identity.ts:229-239).
    fn unsigned_cbor(&self) -> snp_cbor::CborValue {
        use snp_cbor::CborValue;
        let attestation_val = match &self.attestation {
            Some(b) => CborValue::ByteString(b.clone()),
            None => CborValue::Null,
        };
        CborValue::Map(vec![
            (
                CborValue::TextString("deviceId".into()),
                CborValue::ByteString(self.device_id.to_vec()),
            ),
            (
                CborValue::TextString("userId".into()),
                CborValue::ByteString(self.user_id.to_vec()),
            ),
            (
                CborValue::TextString("capabilities".into()),
                CborValue::Array(
                    self.capabilities
                        .iter()
                        .map(|c| CborValue::TextString(c.clone()))
                        .collect(),
                ),
            ),
            (
                CborValue::TextString("platform".into()),
                CborValue::TextString(self.platform.clone()),
            ),
            (
                CborValue::TextString("notBefore".into()),
                CborValue::UnsignedInt(self.not_before),
            ),
            (
                CborValue::TextString("notAfter".into()),
                CborValue::UnsignedInt(self.not_after),
            ),
            (CborValue::TextString("attestation".into()), attestation_val),
        ])
    }

    /// Build the signature preimage: `SIG_CONTEXT("deviceCert") ||
    /// canonical_cbor(unsigned_fields)`.
    fn signature_preimage(&self) -> IdentityResult<Vec<u8>> {
        let ctx = snp_crypto::sig_context(Self::SIG_CONTEXT_NAME)
            .ok_or_else(|| IdentityError::Other("unknown SIG_CONTEXT".into()))?;
        let cbor = snp_cbor::encode(&self.unsigned_cbor())
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))?;
        let mut preimage = Vec::with_capacity(ctx.len() + cbor.len());
        preimage.extend_from_slice(ctx);
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// Validate the STRUCTURE of this `DeviceCert`.
    ///
    /// # Errors
    /// Returns `IdentityError` on any violation (wrong field lengths, invalid
    /// platform, invalid capability, `not_after <= not_before`, wrong
    /// signature length).
    pub fn validate(&self) -> IdentityResult<()> {
        if self.device_id.len() != 32 {
            return Err(IdentityError::Other(
                "DeviceCert.deviceId must be 32 bytes".into(),
            ));
        }
        if self.user_id.len() != 32 {
            return Err(IdentityError::Other(
                "DeviceCert.userId must be 32 bytes".into(),
            ));
        }
        for (i, c) in self.capabilities.iter().enumerate() {
            if !CAPABILITIES.contains(&c.as_str()) {
                return Err(IdentityError::Other(format!(
                    "DeviceCert.capabilities[{i}] must be one of {CAPABILITIES:?}; got {c:?}"
                )));
            }
        }
        if !PLATFORMS.contains(&self.platform.as_str()) {
            return Err(IdentityError::Other(format!(
                "DeviceCert.platform must be one of {PLATFORMS:?}; got {:?}",
                self.platform
            )));
        }
        if self.not_after <= self.not_before {
            return Err(IdentityError::Other(format!(
                "DeviceCert.notAfter ({}) must be > notBefore ({})",
                self.not_after, self.not_before
            )));
        }
        if self.signature.len() != 64 {
            return Err(IdentityError::InvalidSignature);
        }
        Ok(())
    }

    /// Sign the unsigned `DeviceCert` fields with the user identity's secret
    /// key, producing the 64-byte Ed25519 signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails.
    pub fn sign(
        unsigned: &DeviceCertUnsigned,
        user_secret: &snp_crypto::SecretKey,
    ) -> IdentityResult<DescriptorSignature> {
        let cert_for_validation = DeviceCert {
            device_id: unsigned.device_id,
            user_id: unsigned.user_id,
            capabilities: unsigned.capabilities.clone(),
            platform: unsigned.platform.clone(),
            not_before: unsigned.not_before,
            not_after: unsigned.not_after,
            attestation: unsigned.attestation.clone(),
            signature: [0u8; 64],
        };
        cert_for_validation.validate()?;
        let preimage = cert_for_validation.signature_preimage()?;
        Ok(snp_crypto::ed25519_sign(user_secret, &preimage))
    }

    /// Verify the `DeviceCert`'s signature against the user identity's public
    /// key. Returns `false` on any failure (I20 — never throws).
    #[must_use]
    pub fn verify(&self, user_pubkey: &snp_crypto::PublicKey) -> bool {
        if self.signature.len() != 64 {
            return false;
        }
        if self.validate().is_err() {
            return false;
        }
        let Ok(preimage) = self.signature_preimage() else {
            return false;
        };
        snp_crypto::ed25519_verify(user_pubkey, &preimage, &self.signature)
    }

    /// Encode to canonical CBOR bytes (the wire format, including `signature`).
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails or CBOR encoding fails.
    pub fn encode_cbor(&self) -> IdentityResult<Vec<u8>> {
        self.validate()?;
        use snp_cbor::CborValue;
        let mut entries = match self.unsigned_cbor() {
            CborValue::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((
            CborValue::TextString("signature".into()),
            CborValue::ByteString(self.signature.to_vec()),
        ));
        snp_cbor::encode(&CborValue::Map(entries))
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))
    }

    /// Decode from canonical CBOR bytes. STRUCTURAL ONLY — does NOT verify
    /// the signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if the bytes are not canonical CBOR, a field
    /// has the wrong type, or validation fails.
    pub fn decode_cbor(bytes: &[u8]) -> IdentityResult<Self> {
        let value = snp_cbor::decode(bytes)
            .map_err(|e| IdentityError::Other(format!("CBOR decode: {e}")))?;
        let entries = match &value {
            snp_cbor::CborValue::Map(e) => e,
            _ => return Err(IdentityError::Other("DeviceCert must be a CBOR map".into())),
        };
        let mut device_id: Option<NodeId> = None;
        let mut user_id: Option<NodeId> = None;
        let mut capabilities: Option<Vec<String>> = None;
        let mut platform: Option<String> = None;
        let mut not_before: Option<u64> = None;
        let mut not_after: Option<u64> = None;
        let mut attestation: Option<Option<Vec<u8>>> = None;
        let mut signature: Option<DescriptorSignature> = None;
        for (k, v) in entries {
            let key = match k {
                snp_cbor::CborValue::TextString(s) => s.as_str(),
                _ => return Err(IdentityError::Other("DeviceCert key must be text".into())),
            };
            match key {
                "deviceId" => device_id = Some(decode_bstr_32(v, "DeviceCert.deviceId")?),
                "userId" => user_id = Some(decode_bstr_32(v, "DeviceCert.userId")?),
                "capabilities" => {
                    capabilities = Some(decode_tstr_array(v, "DeviceCert.capabilities")?);
                }
                "platform" => platform = Some(decode_tstr(v, "DeviceCert.platform")?),
                "notBefore" => not_before = Some(decode_uint(v, "DeviceCert.notBefore")?),
                "notAfter" => not_after = Some(decode_uint(v, "DeviceCert.notAfter")?),
                "attestation" => match v {
                    snp_cbor::CborValue::Null => attestation = Some(None),
                    snp_cbor::CborValue::ByteString(b) => attestation = Some(Some(b.clone())),
                    _ => {
                        return Err(IdentityError::Other(
                            "DeviceCert.attestation must be null or bstr".into(),
                        ))
                    }
                },
                "signature" => signature = Some(decode_bstr_64(v, "DeviceCert.signature")?),
                _ => {
                    return Err(IdentityError::Other(format!(
                        "unknown key '{key}' in DeviceCert (signed structure — must be rejected per §9)"
                    )));
                }
            }
        }
        let cert = Self {
            device_id: device_id
                .ok_or_else(|| IdentityError::Other("DeviceCert missing deviceId".into()))?,
            user_id: user_id
                .ok_or_else(|| IdentityError::Other("DeviceCert missing userId".into()))?,
            capabilities: capabilities
                .ok_or_else(|| IdentityError::Other("DeviceCert missing capabilities".into()))?,
            platform: platform
                .ok_or_else(|| IdentityError::Other("DeviceCert missing platform".into()))?,
            not_before: not_before
                .ok_or_else(|| IdentityError::Other("DeviceCert missing notBefore".into()))?,
            not_after: not_after
                .ok_or_else(|| IdentityError::Other("DeviceCert missing notAfter".into()))?,
            attestation: attestation.unwrap_or(None),
            signature: signature
                .ok_or_else(|| IdentityError::Other("DeviceCert missing signature".into()))?,
        };
        cert.validate()?;
        Ok(cert)
    }
}

// ─── NodeDescriptor (frozen identity.ts:320-347) ──────────────────────────

/// A complete `NodeDescriptor`, including the 64-byte Ed25519 signature.
///
/// The signed, broadcastable record published by a node. Binds a `NodeId` to
/// its public keys, capabilities, platform, validity window, and optional
/// `DeviceCert`. Signed by the node's `nodePubKey` under `SIG_CONTEXT`
/// `"nodeDescriptor"`.
///
/// # Wire format
///
/// `encode_cbor()` produces canonical CBOR matching the TS
/// `nodeDescriptorToWireMap` (sync.ts:552-570). `decode_cbor()` is the
/// inverse. The decode is STRUCTURAL ONLY — does NOT verify the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptor {
    /// `NodeId` (32 bytes) — SHA-256("SNP/0.1 node\0" ‖ nodePubKey).
    pub node_id: NodeId,
    /// 32-byte Ed25519 public key of the `NodeIdentity`.
    pub node_pub_key: snp_crypto::PublicKey,
    /// 32-byte X25519 public key of the `RendezvousIdentity`.
    pub rendezvous_pub: [u8; 32],
    /// Capabilities the node advertises (strings from `CAPABILITIES`).
    pub capabilities: Vec<String>,
    /// Platform string (one of `PLATFORMS`).
    pub platform: String,
    /// Protocol version string — MUST be `PROTO_VERSION` ("SNP/0.1").
    pub proto_version: String,
    /// Epoch number this descriptor is valid for.
    pub epoch: u64,
    /// Expiry (unix seconds). Mandatory; SHOULD be ≤ 1h for mobile.
    pub expires_at: u64,
    /// Link-layer hints for reaching the node.
    pub links: Vec<String>,
    /// `DeviceCert` binding this node to a device/user, or `None` for privacy.
    pub device_cert: Option<DeviceCert>,
    /// 64-byte Ed25519 signature by `node_pub_key` over `SIG_CONTEXT`
    /// `"nodeDescriptor"`.
    pub signature: DescriptorSignature,
}

/// Fields of a `NodeDescriptor`, excluding the signature. This is what gets
/// signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptorUnsigned {
    /// `NodeId` (32 bytes).
    pub node_id: NodeId,
    /// 32-byte Ed25519 public key.
    pub node_pub_key: snp_crypto::PublicKey,
    /// 32-byte X25519 public key.
    pub rendezvous_pub: [u8; 32],
    /// Capabilities (strings from `CAPABILITIES`).
    pub capabilities: Vec<String>,
    /// Platform string.
    pub platform: String,
    /// Protocol version — MUST be `PROTO_VERSION`.
    pub proto_version: String,
    /// Epoch number.
    pub epoch: u64,
    /// Expiry (unix seconds).
    pub expires_at: u64,
    /// Link-layer hints.
    pub links: Vec<String>,
    /// Optional `DeviceCert`.
    pub device_cert: Option<DeviceCert>,
}

impl NodeDescriptor {
    /// The `SIG_CONTEXT` name for `NodeDescriptor` signatures.
    pub const SIG_CONTEXT_NAME: &'static str = "nodeDescriptor";

    /// Construct the unsigned fields view (excludes `signature`).
    #[must_use]
    pub fn unsigned(&self) -> NodeDescriptorUnsigned {
        NodeDescriptorUnsigned {
            node_id: self.node_id,
            node_pub_key: self.node_pub_key,
            rendezvous_pub: self.rendezvous_pub,
            capabilities: self.capabilities.clone(),
            platform: self.platform.clone(),
            proto_version: self.proto_version.clone(),
            epoch: self.epoch,
            expires_at: self.expires_at,
            links: self.links.clone(),
            device_cert: self.device_cert.clone(),
        }
    }

    /// Build the canonical CBOR preimage map for a `NodeDescriptor`, EXCLUDING
    /// the `signature` field (identity.ts:362-382).
    fn unsigned_cbor(&self) -> snp_cbor::CborValue {
        use snp_cbor::CborValue;
        // The embedded DeviceCert is encoded as the FULL cert (including its
        // own signature) — per the frozen TS `nodeDescriptorToCborMap`
        // (identity.ts:362-382) which calls `deviceCertToCborMap` (the full
        // cert, not the unsigned fields). The DeviceCert's signature IS part
        // of the NodeDescriptor's signed preimage — it is bound into the
        // descriptor so stripping/substituting the DeviceCert invalidates the
        // descriptor signature.
        let device_cert_val = match &self.device_cert {
            Some(c) => c.to_cbor_value(),
            None => CborValue::Null,
        };
        CborValue::Map(vec![
            (
                CborValue::TextString("nodeId".into()),
                CborValue::ByteString(self.node_id.to_vec()),
            ),
            (
                CborValue::TextString("nodePubKey".into()),
                CborValue::ByteString(self.node_pub_key.to_vec()),
            ),
            (
                CborValue::TextString("rendezvousPub".into()),
                CborValue::ByteString(self.rendezvous_pub.to_vec()),
            ),
            (
                CborValue::TextString("capabilities".into()),
                CborValue::Array(
                    self.capabilities
                        .iter()
                        .map(|c| CborValue::TextString(c.clone()))
                        .collect(),
                ),
            ),
            (
                CborValue::TextString("platform".into()),
                CborValue::TextString(self.platform.clone()),
            ),
            (
                CborValue::TextString("protoVersion".into()),
                CborValue::TextString(self.proto_version.clone()),
            ),
            (
                CborValue::TextString("epoch".into()),
                CborValue::UnsignedInt(self.epoch),
            ),
            (
                CborValue::TextString("expiresAt".into()),
                CborValue::UnsignedInt(self.expires_at),
            ),
            (
                CborValue::TextString("links".into()),
                CborValue::Array(
                    self.links
                        .iter()
                        .map(|l| CborValue::TextString(l.clone()))
                        .collect(),
                ),
            ),
            (CborValue::TextString("deviceCert".into()), device_cert_val),
        ])
    }

    /// Build the signature preimage: `SIG_CONTEXT("nodeDescriptor") ||
    /// canonical_cbor(unsigned_fields)`.
    fn signature_preimage(&self) -> IdentityResult<Vec<u8>> {
        let ctx = snp_crypto::sig_context(Self::SIG_CONTEXT_NAME)
            .ok_or_else(|| IdentityError::Other("unknown SIG_CONTEXT".into()))?;
        let cbor = snp_cbor::encode(&self.unsigned_cbor())
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))?;
        let mut preimage = Vec::with_capacity(ctx.len() + cbor.len());
        preimage.extend_from_slice(ctx);
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// Validate the STRUCTURE of this `NodeDescriptor`.
    ///
    /// # Errors
    /// Returns `IdentityError` on any violation.
    pub fn validate(&self) -> IdentityResult<()> {
        if self.node_id.len() != 32 {
            return Err(IdentityError::Other(
                "NodeDescriptor.nodeId must be 32 bytes".into(),
            ));
        }
        if self.node_pub_key.len() != 32 {
            return Err(IdentityError::Other(
                "NodeDescriptor.nodePubKey must be 32 bytes".into(),
            ));
        }
        if self.rendezvous_pub.len() != 32 {
            return Err(IdentityError::Other(
                "NodeDescriptor.rendezvousPub must be 32 bytes".into(),
            ));
        }
        for (i, c) in self.capabilities.iter().enumerate() {
            if !CAPABILITIES.contains(&c.as_str()) {
                return Err(IdentityError::Other(format!(
                    "NodeDescriptor.capabilities[{i}] must be one of {CAPABILITIES:?}; got {c:?}"
                )));
            }
        }
        if !PLATFORMS.contains(&self.platform.as_str()) {
            return Err(IdentityError::Other(format!(
                "NodeDescriptor.platform must be one of {PLATFORMS:?}; got {:?}",
                self.platform
            )));
        }
        if self.proto_version != PROTO_VERSION {
            return Err(IdentityError::Other(format!(
                "NodeDescriptor.protoVersion must be {PROTO_VERSION:?}; got {:?}",
                self.proto_version
            )));
        }
        if let Some(cert) = &self.device_cert {
            cert.validate()?;
        }
        if self.signature.len() != 64 {
            return Err(IdentityError::InvalidSignature);
        }
        Ok(())
    }

    /// Sign the unsigned `NodeDescriptor` fields with the node identity's
    /// secret key, producing the 64-byte Ed25519 signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails.
    pub fn sign(
        unsigned: &NodeDescriptorUnsigned,
        node_secret: &snp_crypto::SecretKey,
    ) -> IdentityResult<DescriptorSignature> {
        let desc_for_validation = NodeDescriptor {
            node_id: unsigned.node_id,
            node_pub_key: unsigned.node_pub_key,
            rendezvous_pub: unsigned.rendezvous_pub,
            capabilities: unsigned.capabilities.clone(),
            platform: unsigned.platform.clone(),
            proto_version: unsigned.proto_version.clone(),
            epoch: unsigned.epoch,
            expires_at: unsigned.expires_at,
            links: unsigned.links.clone(),
            device_cert: unsigned.device_cert.clone(),
            signature: [0u8; 64],
        };
        desc_for_validation.validate()?;
        let preimage = desc_for_validation.signature_preimage()?;
        Ok(snp_crypto::ed25519_sign(node_secret, &preimage))
    }

    /// Verify the `NodeDescriptor`'s signature against the node's public key.
    /// Returns `false` on any failure (I20 — never throws).
    #[must_use]
    pub fn verify(&self, node_pubkey: &snp_crypto::PublicKey) -> bool {
        if self.signature.len() != 64 {
            return false;
        }
        if self.validate().is_err() {
            return false;
        }
        let Ok(preimage) = self.signature_preimage() else {
            return false;
        };
        snp_crypto::ed25519_verify(node_pubkey, &preimage, &self.signature)
    }

    /// Encode to canonical CBOR bytes (the wire format, including `signature`).
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails or CBOR encoding fails.
    pub fn encode_cbor(&self) -> IdentityResult<Vec<u8>> {
        self.validate()?;
        use snp_cbor::CborValue;
        let mut entries = match self.unsigned_cbor() {
            CborValue::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((
            CborValue::TextString("signature".into()),
            CborValue::ByteString(self.signature.to_vec()),
        ));
        snp_cbor::encode(&CborValue::Map(entries))
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))
    }

    /// Decode from canonical CBOR bytes. STRUCTURAL ONLY — does NOT verify
    /// the signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if the bytes are not canonical CBOR, a field
    /// has the wrong type, or validation fails.
    pub fn decode_cbor(bytes: &[u8]) -> IdentityResult<Self> {
        let value = snp_cbor::decode(bytes)
            .map_err(|e| IdentityError::Other(format!("CBOR decode: {e}")))?;
        let entries = match &value {
            snp_cbor::CborValue::Map(e) => e,
            _ => {
                return Err(IdentityError::Other(
                    "NodeDescriptor must be a CBOR map".into(),
                ))
            }
        };
        let mut node_id: Option<NodeId> = None;
        let mut node_pub_key: Option<snp_crypto::PublicKey> = None;
        let mut rendezvous_pub: Option<[u8; 32]> = None;
        let mut capabilities: Option<Vec<String>> = None;
        let mut platform: Option<String> = None;
        let mut proto_version: Option<String> = None;
        let mut epoch: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        let mut links: Option<Vec<String>> = None;
        let mut device_cert: Option<Option<DeviceCert>> = None;
        let mut signature: Option<DescriptorSignature> = None;
        for (k, v) in entries {
            let key = match k {
                snp_cbor::CborValue::TextString(s) => s.as_str(),
                _ => {
                    return Err(IdentityError::Other(
                        "NodeDescriptor key must be text".into(),
                    ))
                }
            };
            match key {
                "nodeId" => node_id = Some(decode_bstr_32(v, "NodeDescriptor.nodeId")?),
                "nodePubKey" => {
                    node_pub_key = Some(decode_bstr_32(v, "NodeDescriptor.nodePubKey")?);
                }
                "rendezvousPub" => {
                    rendezvous_pub = Some(decode_bstr_32(v, "NodeDescriptor.rendezvousPub")?);
                }
                "capabilities" => {
                    capabilities = Some(decode_tstr_array(v, "NodeDescriptor.capabilities")?);
                }
                "platform" => platform = Some(decode_tstr(v, "NodeDescriptor.platform")?),
                "protoVersion" => {
                    proto_version = Some(decode_tstr(v, "NodeDescriptor.protoVersion")?);
                }
                "epoch" => epoch = Some(decode_uint(v, "NodeDescriptor.epoch")?),
                "expiresAt" => expires_at = Some(decode_uint(v, "NodeDescriptor.expiresAt")?),
                "links" => links = Some(decode_tstr_array(v, "NodeDescriptor.links")?),
                "deviceCert" => {
                    if v == &snp_cbor::CborValue::Null {
                        device_cert = Some(None)
                    } else {
                        let cert = DeviceCert::decode_cbor_value(v)?;
                        device_cert = Some(Some(cert));
                    }
                }
                "signature" => signature = Some(decode_bstr_64(v, "NodeDescriptor.signature")?),
                _ => {
                    return Err(IdentityError::Other(format!(
                        "unknown key '{key}' in NodeDescriptor (signed structure — must be rejected per §9)"
                    )));
                }
            }
        }
        let desc = Self {
            node_id: node_id
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing nodeId".into()))?,
            node_pub_key: node_pub_key
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing nodePubKey".into()))?,
            rendezvous_pub: rendezvous_pub.ok_or_else(|| {
                IdentityError::Other("NodeDescriptor missing rendezvousPub".into())
            })?,
            capabilities: capabilities.ok_or_else(|| {
                IdentityError::Other("NodeDescriptor missing capabilities".into())
            })?,
            platform: platform
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing platform".into()))?,
            proto_version: proto_version.ok_or_else(|| {
                IdentityError::Other("NodeDescriptor missing protoVersion".into())
            })?,
            epoch: epoch
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing epoch".into()))?,
            expires_at: expires_at
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing expiresAt".into()))?,
            links: links
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing links".into()))?,
            device_cert: device_cert.unwrap_or(None),
            signature: signature
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing signature".into()))?,
        };
        desc.validate()?;
        Ok(desc)
    }
}

// ─── CBOR helpers for identity decode ─────────────────────────────────────

fn decode_bstr_32(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<[u8; 32]> {
    let b = match v {
        snp_cbor::CborValue::ByteString(b) => b,
        _ => {
            return Err(IdentityError::Other(format!(
                "{field} must be a byte string"
            )))
        }
    };
    if b.len() != 32 {
        return Err(IdentityError::Other(format!(
            "{field} must be 32 bytes, got {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(b);
    Ok(arr)
}

fn decode_bstr_64(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<[u8; 64]> {
    let b = match v {
        snp_cbor::CborValue::ByteString(b) => b,
        _ => {
            return Err(IdentityError::Other(format!(
                "{field} must be a byte string"
            )))
        }
    };
    if b.len() != 64 {
        return Err(IdentityError::Other(format!(
            "{field} must be 64 bytes, got {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(b);
    Ok(arr)
}

fn decode_uint(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<u64> {
    match v {
        snp_cbor::CborValue::UnsignedInt(n) => Ok(*n),
        _ => Err(IdentityError::Other(format!(
            "{field} must be an unsigned int"
        ))),
    }
}

fn decode_tstr(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<String> {
    match v {
        snp_cbor::CborValue::TextString(s) => Ok(s.clone()),
        _ => Err(IdentityError::Other(format!(
            "{field} must be a text string"
        ))),
    }
}

fn decode_tstr_array(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<Vec<String>> {
    let arr = match v {
        snp_cbor::CborValue::Array(a) => a,
        _ => return Err(IdentityError::Other(format!("{field} must be an array"))),
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        out.push(decode_tstr(item, &format!("{field}[{i}]"))?);
    }
    Ok(out)
}

impl DeviceCert {
    /// Decode a `DeviceCert` from a CBOR value (for nested deviceCert field
    /// in `NodeDescriptor`).
    fn decode_cbor_value(v: &snp_cbor::CborValue) -> IdentityResult<Self> {
        let bytes = snp_cbor::encode(v)
            .map_err(|e| IdentityError::Other(format!("CBOR re-encode: {e}")))?;
        Self::decode_cbor(&bytes)
    }
}

// ─── Legacy Capabilities struct (kept for backward compat, NOT used by the
// frozen NodeDescriptor which uses `Vec<String>`) ───────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::format_collect)]
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nodeid_deterministic_alice() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_to_bytes(pk_hex));
        let id = derive_node_id(&pk);
        let got: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            "4ae95ccb41544dccde22eca97a7cdc99101cb5aa91606c257b56cdd35b414913"
        );
        // Deterministic: same input → same output.
        let id2 = derive_node_id(&pk);
        assert_eq!(id, id2);
    }

    #[test]
    fn rfc8032_test1_verify() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_to_bytes(pk_hex));
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&hex_to_bytes(sig_hex));
        assert!(snp_crypto::ed25519_verify(&pk, b"", &sig));
    }

    #[test]
    fn unknown_context_rejects() {
        let pk = [0u8; 32];
        let sig = [0u8; 64];
        assert!(!verify_signed(&pk, "nonsense", b"", &sig));
    }

    // ─── R4.2 interop: NodeDescriptor + DeviceCert codec tests ──────────────

    fn test_keypair(seed: u8) -> (snp_crypto::SecretKey, snp_crypto::PublicKey) {
        let secret = [seed; 32];
        let public = snp_crypto::derive_public_key(&secret);
        (secret, public)
    }

    fn test_node_id(seed: u8) -> NodeId {
        [seed; 32]
    }

    fn test_device_cert_unsigned() -> DeviceCertUnsigned {
        DeviceCertUnsigned {
            device_id: test_node_id(0x11),
            user_id: test_node_id(0x22),
            capabilities: vec!["MESH_CLIENT".into(), "CONTENT_SEED".into()],
            platform: "linux".into(),
            not_before: 1_000,
            not_after: 10_000,
            attestation: None,
        }
    }

    fn test_node_descriptor_unsigned(cert: Option<DeviceCert>) -> NodeDescriptorUnsigned {
        NodeDescriptorUnsigned {
            node_id: test_node_id(0xAA),
            node_pub_key: test_keypair(0xBB).1,
            rendezvous_pub: [0xCC; 32],
            capabilities: vec!["MESH_RELAY".into(), "DISCOVERY".into()],
            platform: "android".into(),
            proto_version: PROTO_VERSION.into(),
            epoch: 42,
            expires_at: 9_000,
            links: vec!["tcp://1.2.3.4:5678".into()],
            device_cert: cert,
        }
    }

    #[test]
    fn device_cert_roundtrip() {
        let (user_secret, user_pubkey) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let bytes = cert.encode_cbor().expect("encode");
        let decoded = DeviceCert::decode_cbor(&bytes).expect("decode");
        assert_eq!(cert, decoded);
        // Verify the signature.
        assert!(cert.verify(&user_pubkey), "signature must verify");
    }

    #[test]
    fn device_cert_encode_decode_reencode_identical() {
        // Determinism: encode → decode → re-encode produces identical bytes.
        let (user_secret, _) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let bytes1 = cert.encode_cbor().expect("encode 1");
        let decoded = DeviceCert::decode_cbor(&bytes1).expect("decode");
        let bytes2 = decoded.encode_cbor().expect("encode 2");
        assert_eq!(bytes1, bytes2, "encode→decode→re-encode must be identical");
    }

    #[test]
    fn device_cert_tampered_signature_rejected() {
        let (user_secret, user_pubkey) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let mut cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        // Tamper the signature.
        cert.signature[0] ^= 0xFF;
        assert!(
            !cert.verify(&user_pubkey),
            "tampered signature must NOT verify"
        );
    }

    #[test]
    fn device_cert_unknown_key_rejected() {
        let (user_secret, _) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let bytes = cert.encode_cbor().expect("encode");
        // Inject an unknown key by appending a new map entry before the
        // closing. Easier: decode, re-encode with an extra key, then try
        // to decode.
        use snp_cbor::{decode, encode, CborValue};
        let mut value = decode(&bytes).expect("decode");
        if let CborValue::Map(ref mut entries) = value {
            entries.push((
                CborValue::TextString("unknownKey".into()),
                CborValue::UnsignedInt(99),
            ));
        }
        let tampered_bytes = encode(&value).expect("re-encode with unknown key");
        let result = DeviceCert::decode_cbor(&tampered_bytes);
        assert!(
            result.is_err(),
            "unknown key in signed structure must be rejected"
        );
    }

    #[test]
    fn device_cert_missing_field_rejected() {
        // Omit the `signature` field.
        use snp_cbor::encode;
        let cert_unsigned_cbor = DeviceCert {
            device_id: test_node_id(0x11),
            user_id: test_node_id(0x22),
            capabilities: vec!["MESH_CLIENT".into()],
            platform: "linux".into(),
            not_before: 1_000,
            not_after: 10_000,
            attestation: None,
            signature: [0u8; 64],
        };
        // Encode WITHOUT the signature field (just the unsigned_cbor).
        let unsigned_value = cert_unsigned_cbor.unsigned_cbor();
        let bytes = encode(&unsigned_value).expect("encode without sig");
        let result = DeviceCert::decode_cbor(&bytes);
        assert!(result.is_err(), "missing signature must be rejected");
    }

    #[test]
    fn device_cert_wrong_field_type_rejected() {
        // `notBefore` as a text string instead of uint.
        use snp_cbor::{encode, CborValue};
        let cert = DeviceCert {
            device_id: test_node_id(0x11),
            user_id: test_node_id(0x22),
            capabilities: vec!["MESH_CLIENT".into()],
            platform: "linux".into(),
            not_before: 1_000,
            not_after: 10_000,
            attestation: None,
            signature: [0u8; 64],
        };
        let mut value = cert.unsigned_cbor();
        if let CborValue::Map(ref mut entries) = value {
            for (k, v) in entries.iter_mut() {
                if let CborValue::TextString(s) = k {
                    if s == "notBefore" {
                        *v = CborValue::TextString("not-a-uint".into());
                    }
                }
            }
        }
        let bytes = encode(&value).expect("encode");
        let result = DeviceCert::decode_cbor(&bytes);
        assert!(result.is_err(), "wrong field type must be rejected");
    }

    #[test]
    fn node_descriptor_roundtrip_no_cert() {
        let (node_secret, node_pubkey) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes = desc.encode_cbor().expect("encode");
        let decoded = NodeDescriptor::decode_cbor(&bytes).expect("decode");
        assert_eq!(desc, decoded);
        assert!(desc.verify(&node_pubkey), "signature must verify");
    }

    #[test]
    fn node_descriptor_roundtrip_with_cert() {
        let (node_secret, node_pubkey) = test_keypair(0xBB);
        let (user_secret, _) = test_keypair(0x99);
        let cert_unsigned = test_device_cert_unsigned();
        let cert_sig = DeviceCert::sign(&cert_unsigned, &user_secret).expect("sign cert");
        let cert = DeviceCert {
            signature: cert_sig,
            ..DeviceCert {
                device_id: cert_unsigned.device_id,
                user_id: cert_unsigned.user_id,
                capabilities: cert_unsigned.capabilities,
                platform: cert_unsigned.platform,
                not_before: cert_unsigned.not_before,
                not_after: cert_unsigned.not_after,
                attestation: cert_unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let unsigned = test_node_descriptor_unsigned(Some(cert));
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes = desc.encode_cbor().expect("encode");
        let decoded = NodeDescriptor::decode_cbor(&bytes).expect("decode");
        assert_eq!(desc, decoded);
        assert!(desc.verify(&node_pubkey), "signature must verify");
    }

    #[test]
    fn node_descriptor_encode_decode_reencode_identical() {
        let (node_secret, _) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes1 = desc.encode_cbor().expect("encode 1");
        let decoded = NodeDescriptor::decode_cbor(&bytes1).expect("decode");
        let bytes2 = decoded.encode_cbor().expect("encode 2");
        assert_eq!(bytes1, bytes2, "encode→decode→re-encode must be identical");
    }

    #[test]
    fn node_descriptor_tampered_signature_rejected() {
        let (node_secret, node_pubkey) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let mut desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        desc.signature[0] ^= 0xFF;
        assert!(
            !desc.verify(&node_pubkey),
            "tampered signature must NOT verify"
        );
    }

    #[test]
    fn node_descriptor_wrong_proto_version_rejected() {
        let (node_secret, _) = test_keypair(0xBB);
        let mut unsigned = test_node_descriptor_unsigned(None);
        unsigned.proto_version = "SNP/0.2".into(); // wrong!
        let result = NodeDescriptor::sign(&unsigned, &node_secret);
        assert!(
            result.is_err(),
            "wrong protoVersion must be rejected at sign time"
        );
    }

    #[test]
    fn node_descriptor_invalid_capability_rejected() {
        let (node_secret, _) = test_keypair(0xBB);
        let mut unsigned = test_node_descriptor_unsigned(None);
        unsigned.capabilities = vec!["INVALID_CAP".into()];
        let result = NodeDescriptor::sign(&unsigned, &node_secret);
        assert!(result.is_err(), "invalid capability must be rejected");
    }

    #[test]
    fn node_descriptor_unknown_key_rejected() {
        let (node_secret, _) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes = desc.encode_cbor().expect("encode");
        use snp_cbor::{decode, encode, CborValue};
        let mut value = decode(&bytes).expect("decode");
        if let CborValue::Map(ref mut entries) = value {
            entries.push((
                CborValue::TextString("unknownKey".into()),
                CborValue::UnsignedInt(99),
            ));
        }
        let tampered = encode(&value).expect("re-encode");
        let result = NodeDescriptor::decode_cbor(&tampered);
        assert!(
            result.is_err(),
            "unknown key in signed structure must be rejected"
        );
    }

    #[test]
    fn node_descriptor_missing_field_rejected() {
        // Omit the `signature` field.
        let (node_secret, _) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let unsigned_value = desc.unsigned_cbor();
        let bytes = snp_cbor::encode(&unsigned_value).expect("encode without sig");
        let result = NodeDescriptor::decode_cbor(&bytes);
        assert!(result.is_err(), "missing signature must be rejected");
    }
}
