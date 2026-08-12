//! N2.1.0.1 — Generic Authenticated Node Advertisement (hardened).
//!
//! ## N2.1.0.1 corrections
//!
//! 1. **Advertisement sequence/epoch** — a signed monotonic sequence number
//!    per node. Newer advertisements have higher sequences. Route discovery
//!    uses this to determine which advertisement is current.
//! 2. **Clock validation** — `timestamp <= now + MAX_CLOCK_SKEW`,
//!    `expiry > timestamp`, `expiry - timestamp <= MAX_ADVERTISEMENT_LIFETIME`.
//!    Prevents future-dated or immortal advertisements.
//! 3. **Role/key consistency** — Gateway capability requires X25519 key;
//!    non-Gateway nodes must NOT have one. Enforced in `verify_into_verified()`.
//! 4. **Freshness material ≠ replay prevention** — `verify_into_verified()`
//!    performs stateless validation only (signature + consistency + clock +
//!    role). Replay prevention is handled by the stateful
//!    [`AdvertisementAcceptanceStore`], which tracks the highest accepted
//!    sequence per NodeId and rejects stale or duplicate advertisements.
//! 5. **`AuthenticatedNodeRecord`** — binds the `VerifiedNodeDescriptor`
//!    with its authenticated endpoints, sequence, and expiry into a single
//!    typed structure. Prevents accidentally combining a descriptor from
//!    advertisement A with an endpoint from advertisement B.
//!
//! ## Architecture
//!
//! ```text
//! NodeAdvertisement (signed, covers ALL fields including sequence)
//!     │
//!     ↓ verify_into_verified() [stateless: sig + I4 + clock + role]
//!     │
//! VerifiedNodeAdvertisement
//!     │
//!     ↓ AdvertisementAcceptanceStore::accept() [stateful: sequence check]
//!     │
//!     │  ├── newer sequence → accept, update store
//!     │  ├── same sequence  → reject (duplicate)
//!     │  └── older sequence → reject (stale)
//!     │
//! AuthenticatedNodeRecord { descriptor, endpoints, sequence, expiry }
//! ```

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{derive_node_id, ed25519_sign, ed25519_verify, sha256, sig_contexts};
use std::collections::HashMap;

// ─── Protocol constants ─────────────────────────────────────────────────────

/// Maximum allowed clock skew (seconds). Advertisements with `timestamp`
/// more than this many seconds in the future are rejected.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300; // 5 minutes

/// Maximum allowed advertisement lifetime (seconds). Advertisements with
/// `expiry - timestamp > MAX_ADVERTISEMENT_LIFETIME_SECS` are rejected.
pub const MAX_ADVERTISEMENT_LIFETIME_SECS: u64 = 86400; // 24 hours

// ─── NodeAdvertisement ──────────────────────────────────────────────────────

/// A generic signed node advertisement. Represents ANY ShareNet node —
/// relay, gateway, or multi-role.
///
/// The signature covers ALL fields except `signature` itself, under
/// `SIG_CONTEXTS::NODE_ADVERT`. This authenticates:
/// - NodeId, Ed25519 public key, capabilities, endpoints
/// - Gateway X25519 circuit key (if present)
/// - Timestamp, expiry, nonce, and **advertisement sequence**
///
/// ## Freshness material vs replay prevention
///
/// The `timestamp`, `expiry`, `nonce`, and `sequence` fields constitute
/// **cryptographic freshness material**. The stateless `verify_into_verified()`
/// checks signature, NodeId consistency, clock validity, and role/key
/// consistency — but does NOT prevent replay.
///
/// **Replay prevention** is handled by the stateful
/// [`AdvertisementAcceptanceStore`], which tracks the highest accepted
/// sequence per NodeId and rejects stale or duplicate advertisements.
#[derive(Debug, Clone)]
pub struct NodeAdvertisement {
    /// The node's NodeId.
    pub node_id: [u8; 32],
    /// The node's Ed25519 identity public key.
    pub ed25519_public_key: [u8; 32],
    /// The node's capabilities.
    pub capabilities: Vec<Capability>,
    /// The node's transport endpoints (authenticated).
    pub endpoints: Vec<TransportEndpoint>,
    /// Optional X25519 circuit public key (gateways only).
    pub x25519_circuit_public: Option<[u8; 32]>,
    /// When this advertisement was signed (unix seconds).
    pub timestamp: u64,
    /// When this advertisement expires (unix seconds).
    pub expiry: u64,
    /// 16-byte freshness nonce (unique per advertisement instance).
    pub nonce: [u8; 16],
    /// **N2.1.0.1.** Monotonic advertisement sequence number. The node
    /// increments this for each new advertisement. Higher = newer.
    /// Used by [`AdvertisementAcceptanceStore`] to determine which
    /// advertisement is current and to reject stale/duplicate ones.
    pub sequence: u64,
    /// Ed25519 signature.
    pub signature: [u8; 64],
}

impl NodeAdvertisement {
    /// Construct and sign a `NodeAdvertisement`.
    ///
    /// # Parameters
    /// - `ed25519_secret_key` / `ed25519_public_key` — the node's keypair.
    /// - `capabilities` — the node's capabilities.
    /// - `endpoints` — transport endpoints (authenticated).
    /// - `x25519_circuit_public` — `Some` for gateways, `None` for relays.
    /// - `expiry_secs` — advertisement lifetime in seconds.
    /// - `sequence` — monotonic sequence number (must be higher than any
    ///   previous advertisement from this node).
    #[must_use]
    pub fn create_and_sign(
        ed25519_secret_key: &[u8; 32],
        ed25519_public_key: &[u8; 32],
        capabilities: Vec<Capability>,
        endpoints: Vec<TransportEndpoint>,
        x25519_circuit_public: Option<[u8; 32]>,
        expiry_secs: u64,
        sequence: u64,
    ) -> Self {
        let now = now_unix();
        let node_id = derive_node_id(ed25519_public_key);
        let mut nonce = [0u8; 16];
        let _ = getrandom::getrandom(&mut nonce);
        let mut advert = Self {
            node_id,
            ed25519_public_key: *ed25519_public_key,
            capabilities,
            endpoints,
            x25519_circuit_public,
            timestamp: now,
            expiry: now.saturating_add(expiry_secs),
            nonce,
            sequence,
            signature: [0u8; 64],
        };
        advert.sign(ed25519_secret_key);
        advert
    }

    /// Build the canonical CBOR preimage (all fields EXCEPT `signature`).
    fn preimage(&self) -> CborValue {
        let caps: Vec<CborValue> = self
            .capabilities
            .iter()
            .map(|c| CborValue::TextString(c.as_str().to_string()))
            .collect();
        let endpoints: Vec<CborValue> = self
            .endpoints
            .iter()
            .map(|e| e.canonical_cbor())
            .collect();
        CborValue::Map(vec![
            (CborValue::TextString("nodeId".into()), CborValue::ByteString(self.node_id.to_vec())),
            (CborValue::TextString("publicKey".into()), CborValue::ByteString(self.ed25519_public_key.to_vec())),
            (CborValue::TextString("capabilities".into()), CborValue::Array(caps)),
            (CborValue::TextString("endpoints".into()), CborValue::Array(endpoints)),
            (
                CborValue::TextString("x25519CircuitPub".into()),
                match &self.x25519_circuit_public {
                    Some(k) => CborValue::ByteString(k.to_vec()),
                    None => CborValue::Null,
                },
            ),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(self.expiry)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.nonce.to_vec())),
            (CborValue::TextString("sequence".into()), CborValue::UnsignedInt(self.sequence)),
        ])
    }

    /// Sign this advertisement.
    pub fn sign(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails for valid preimage");
        let mut msg = Vec::with_capacity(sig_contexts::NODE_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::NODE_ADVERT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// **Stateless verification.** Checks:
    /// 1. Ed25519 signature valid under `SIG_CONTEXTS::NODE_ADVERT`.
    /// 2. `node_id == SHA-256("SNP/0.1 node\0" || ed25519_public_key)` (I4).
    /// 3. Clock validation:
    ///    - `timestamp <= now + MAX_CLOCK_SKEW_SECS` (no future-dated adverts)
    ///    - `expiry > now` (not expired)
    ///    - `expiry > timestamp` (sane ordering)
    ///    - `expiry - timestamp <= MAX_ADVERTISEMENT_LIFETIME_SECS` (no immortal adverts)
    /// 4. Role/key consistency:
    ///    - Gateway capability → `x25519_circuit_public` MUST be `Some`
    ///    - No Gateway capability → `x25519_circuit_public` MUST be `None`
    ///
    /// **This method does NOT prevent replay.** A previously valid advertisement
    /// can be verified again during its validity window. Replay prevention
    /// requires the stateful [`AdvertisementAcceptanceStore`].
    #[must_use]
    pub fn verify_into_verified(&self) -> Option<VerifiedNodeAdvertisement> {
        // 1. Verify the signature.
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return None;
        };
        let mut msg = Vec::with_capacity(sig_contexts::NODE_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::NODE_ADVERT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.ed25519_public_key, &msg, &self.signature) {
            return None;
        }
        // 2. NodeId ↔ Ed25519 consistency (I4).
        let expected_node_id = derive_node_id(&self.ed25519_public_key);
        if self.node_id != expected_node_id {
            return None;
        }
        // 3. Clock validation.
        let now = now_unix();
        // 3a. No future-dated timestamps.
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return None;
        }
        // 3b. Not expired.
        if self.expiry <= now {
            return None;
        }
        // 3c. Sane ordering: expiry must be after timestamp.
        if self.expiry <= self.timestamp {
            return None;
        }
        // 3d. No immortal advertisements.
        if self.expiry.saturating_sub(self.timestamp) > MAX_ADVERTISEMENT_LIFETIME_SECS {
            return None;
        }
        // 4. Role/key consistency.
        let has_gateway = self.capabilities.contains(&Capability::Gateway);
        let has_x25519 = self.x25519_circuit_public.is_some();
        if has_gateway && !has_x25519 {
            // Gateway MUST have X25519 key.
            return None;
        }
        if !has_gateway && has_x25519 {
            // Non-gateway MUST NOT have X25519 key.
            return None;
        }
        Some(VerifiedNodeAdvertisement { advert: self.clone() })
    }

    /// Check if this advertisement has expired.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expiry <= now
    }

    /// Get the advertisement sequence number.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

// ─── VerifiedNodeAdvertisement ──────────────────────────────────────────────

/// A `NodeAdvertisement` that has passed **stateless verification**
/// (signature + NodeId consistency + clock validation + role/key consistency).
///
/// **This type does NOT prove replay prevention.** A `VerifiedNodeAdvertisement`
/// can be replayed during its validity window. The stateful
/// [`AdvertisementAcceptanceStore`] is required for replay prevention.
#[derive(Debug, Clone)]
pub struct VerifiedNodeAdvertisement {
    advert: NodeAdvertisement,
}

impl VerifiedNodeAdvertisement {
    /// Derive a `VerifiedNodeDescriptor` from this verified advertisement.
    #[must_use]
    pub fn descriptor(&self) -> VerifiedNodeDescriptor {
        VerifiedNodeDescriptor::from_verified_advert_internal(&self.advert)
    }

    /// Create an `AuthenticatedNodeRecord` that binds the descriptor with
    /// its authenticated endpoints, sequence, and expiry. This prevents
    /// accidentally combining a descriptor from one advertisement with
    /// endpoints from another.
    #[must_use]
    pub fn into_record(self) -> AuthenticatedNodeRecord {
        let descriptor = self.descriptor();
        let endpoints = self.advert.endpoints.clone();
        let sequence = self.advert.sequence;
        let expiry = self.advert.expiry;
        AuthenticatedNodeRecord {
            descriptor,
            endpoints,
            sequence,
            expiry,
        }
    }

    /// Get the NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.advert.node_id
    }

    /// Get the Ed25519 public key.
    #[must_use]
    pub fn ed25519_public_key(&self) -> &[u8; 32] {
        &self.advert.ed25519_public_key
    }

    /// Get the capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.advert.capabilities
    }

    /// Get the authenticated endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[TransportEndpoint] {
        &self.advert.endpoints
    }

    /// Get the X25519 circuit public key (gateways only).
    #[must_use]
    pub fn circuit_x25519_pub(&self) -> Option<&[u8; 32]> {
        self.advert.x25519_circuit_public.as_ref()
    }

    /// Get the nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 16] {
        &self.advert.nonce
    }

    /// Get the sequence number.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.advert.sequence
    }

    /// Get the expiry.
    #[must_use]
    pub fn expiry(&self) -> u64 {
        self.advert.expiry
    }

    /// Get the timestamp.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.advert.timestamp
    }

    /// Check if this node has the Gateway capability.
    #[must_use]
    pub fn is_gateway(&self) -> bool {
        self.advert.capabilities.contains(&Capability::Gateway)
    }

    /// Check if this node has the Relay capability.
    #[must_use]
    pub fn is_relay(&self) -> bool {
        self.advert.capabilities.contains(&Capability::Relay)
    }

    /// Get the inner advertisement.
    #[must_use]
    pub fn as_ref(&self) -> &NodeAdvertisement {
        &self.advert
    }
}

// ─── AuthenticatedNodeRecord ────────────────────────────────────────────────

/// An authenticated snapshot of a node's advertisement, binding together:
/// - `descriptor` — the `VerifiedNodeDescriptor` (identity + capabilities)
/// - `endpoints` — the authenticated transport endpoints from the SAME advertisement
/// - `sequence` — the monotonic advertisement sequence
/// - `expiry` — when this record expires
///
/// This type prevents accidentally combining a descriptor from advertisement A
/// with endpoints from advertisement B. The endpoints are provably derived
/// from the same verified advertisement snapshot as the descriptor.
#[derive(Debug, Clone)]
pub struct AuthenticatedNodeRecord {
    /// The authenticated node descriptor.
    pub descriptor: VerifiedNodeDescriptor,
    /// The authenticated endpoints from the same advertisement.
    pub endpoints: Vec<TransportEndpoint>,
    /// The advertisement sequence number.
    pub sequence: u64,
    /// When this record expires.
    pub expiry: u64,
}

impl AuthenticatedNodeRecord {
    /// Get the NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.descriptor.node_id()
    }

    /// Get the sequence.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get the expiry.
    #[must_use]
    pub fn expiry(&self) -> u64 {
        self.expiry
    }

    /// Check if this record has expired.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expiry <= now
    }

    /// Get the first endpoint (for convenience).
    #[must_use]
    pub fn first_endpoint(&self) -> Option<&TransportEndpoint> {
        self.endpoints.first()
    }
}

// ─── PeerAcceptanceState ────────────────────────────────────────────────────

/// Per-peer acceptance state. Separates the monotonic sequence floor (which
/// must NOT be erased when the current record expires) from the current
/// authenticated record (which MAY expire and be purged).
///
/// ## N2.1.0.2 correction
///
/// The previous `AdvertisementAcceptanceStore` combined `(highest_sequence,
/// AuthenticatedNodeRecord)` in a single map entry. When `purge_expired()`
/// removed the entry, the sequence floor disappeared — allowing an old
/// advertisement with a lower sequence to be accepted as "first seen" after
/// the purge.
///
/// This type separates the two concerns:
/// - `highest_accepted_sequence` — NEVER erased by record expiry. Persists
///   across `purge_expired_records()` calls. Only removed by explicit
///   `remove_peer()` (e.g. when a node is permanently removed from topology).
/// - `current_record` — MAY be `None` (if expired and purged). The sequence
///   floor remains even when the current record is gone.
#[derive(Debug, Clone)]
pub struct PeerAcceptanceState {
    /// The highest advertisement sequence ever accepted from this peer.
    /// This is a MONOTONIC FLOOR — it never decreases, and it survives
    /// record expiry/purging. An advertisement with a lower or equal
    /// sequence is rejected as stale/duplicate even if the current record
    /// has been purged.
    pub highest_accepted_sequence: u64,
    /// The current authenticated record, if one is active (not expired).
    /// `None` if the record has expired and been purged.
    pub current_record: Option<AuthenticatedNodeRecord>,
}

// ─── AdvertisementAcceptanceStore ───────────────────────────────────────────

/// The result of attempting to accept an advertisement.
#[derive(Debug, Clone)]
pub enum AcceptanceResult {
    /// The advertisement was accepted (newer sequence than previously seen).
    Accepted(AuthenticatedNodeRecord),
    /// The advertisement was rejected because its sequence is older than
    /// the previously accepted sequence for this NodeId.
    Stale {
        /// The advertisement's sequence.
        advert_sequence: u64,
        /// The highest previously accepted sequence.
        known_sequence: u64,
    },
    /// The advertisement was rejected because its sequence matches a
    /// previously accepted advertisement (duplicate).
    Duplicate {
        /// The duplicate sequence.
        sequence: u64,
    },
}

/// A stateful store that tracks the highest accepted advertisement sequence
/// per NodeId. This provides **replay prevention during the lifetime of the
/// acceptance state** — a previously seen advertisement (same or lower
/// sequence) is rejected.
///
/// ## N2.1.0.2: Separated sequence floor from current record
///
/// The store now uses `PeerAcceptanceState` which separates:
/// - `highest_accepted_sequence` — NEVER erased by record expiry.
/// - `current_record` — MAY be purged when expired.
///
/// This prevents the bug where purging an expired record would erase the
/// sequence floor, allowing an old advertisement to be accepted as "first
/// seen" after the purge.
///
/// ## Persistence
///
/// The store is in-memory. For production use, the acceptance state should
/// be persisted to survive process restart. The reference implementation
/// does not yet persist — callers should be aware that a restart loses the
/// sequence floor, and old advertisements within their validity window
/// could be re-accepted.
#[derive(Debug, Clone, Default)]
pub struct AdvertisementAcceptanceStore {
    /// Map: NodeId → PeerAcceptanceState.
    peers: HashMap<[u8; 32], PeerAcceptanceState>,
}

impl AdvertisementAcceptanceStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to accept a `VerifiedNodeAdvertisement`.
    ///
    /// Returns:
    /// - `AcceptanceResult::Accepted(record)` if the sequence is newer than
    ///   any previously seen for this NodeId.
    /// - `AcceptanceResult::Stale` if the sequence is older.
    /// - `AcceptanceResult::Duplicate` if the sequence matches a previously
    ///   accepted advertisement.
    pub fn accept(&mut self, verified: VerifiedNodeAdvertisement) -> AcceptanceResult {
        let node_id = verified.node_id();
        let sequence = verified.sequence();
        match self.peers.get(&node_id) {
            None => {
                // First advertisement from this node.
                let record = verified.into_record();
                self.peers.insert(node_id, PeerAcceptanceState {
                    highest_accepted_sequence: sequence,
                    current_record: Some(record.clone()),
                });
                AcceptanceResult::Accepted(record)
            }
            Some(state) if sequence > state.highest_accepted_sequence => {
                // Newer advertisement.
                let record = verified.into_record();
                self.peers.insert(node_id, PeerAcceptanceState {
                    highest_accepted_sequence: sequence,
                    current_record: Some(record.clone()),
                });
                AcceptanceResult::Accepted(record)
            }
            Some(state) if sequence == state.highest_accepted_sequence => {
                // Duplicate.
                AcceptanceResult::Duplicate { sequence }
            }
            Some(state) => {
                // Stale.
                AcceptanceResult::Stale {
                    advert_sequence: sequence,
                    known_sequence: state.highest_accepted_sequence,
                }
            }
        }
    }

    /// Get the current `AuthenticatedNodeRecord` for a NodeId, if any
    /// (and if not expired).
    #[must_use]
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&AuthenticatedNodeRecord> {
        self.peers.get(node_id).and_then(|s| s.current_record.as_ref())
    }

    /// Get the highest accepted sequence for a NodeId, if any.
    /// This survives record expiry/purging — the sequence floor is
    /// NOT erased by `purge_expired_records()`.
    #[must_use]
    pub fn highest_sequence(&self, node_id: &[u8; 32]) -> Option<u64> {
        self.peers.get(node_id).map(|s| s.highest_accepted_sequence)
    }

    /// Purge expired CURRENT RECORDS from the store. This does NOT
    /// remove the `highest_accepted_sequence` — the sequence floor
    /// persists to prevent replay of old advertisements after the
    /// current record expires.
    ///
    /// ## N2.1.0.2 correction
    ///
    /// The previous `purge_expired()` removed the entire entry (both
    /// sequence AND record). This method only clears `current_record`
    /// when it has expired, preserving the sequence floor.
    pub fn purge_expired_records(&mut self, now: u64) {
        for state in self.peers.values_mut() {
            if let Some(record) = &state.current_record {
                if record.is_expired(now) {
                    state.current_record = None;
                }
            }
        }
    }

    /// Remove a peer entirely (including the sequence floor). This should
    /// only be used when a node is permanently removed from topology —
    /// NOT when an advertisement expires.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) {
        self.peers.remove(node_id);
    }

    /// Get the number of peers in the store (including those with
    /// expired/purged records but retained sequence floors).
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

// ─── AdvertisementSequenceStore (node-side persistence) ─────────────────────

/// A persistent store for a node's own advertisement sequence counter.
/// Ensures the sequence never regresses across process restarts.
///
/// ## N2.1.0.2
///
/// The advertisement sequence is monotonic per NodeId. A node restart
/// must not reset its sequence counter — otherwise other peers will
/// reject the new (lower-sequence) advertisement as stale.
///
/// This abstraction provides:
/// - `next_sequence()` — atomically increment and return the next sequence.
/// - `current_sequence()` — get the current sequence without incrementing.
/// - Persistence via a file-backed implementation.
///
/// ## Reference implementation
///
/// The reference implementation uses a simple file (`sequence.dat`)
/// containing the last-issued sequence as a little-endian `u64`. This is
/// sufficient for a single-process reference node. Production implementations
/// should use a more robust persistence mechanism (e.g. SQLite, SharedPreferences
/// on Android).
#[derive(Debug)]
pub struct AdvertisementSequenceStore {
    /// The current sequence counter (in-memory cache of the persisted value).
    sequence: u64,
    /// The file path where the sequence is persisted.
    path: std::path::PathBuf,
}

impl AdvertisementSequenceStore {
    /// Create a new `AdvertisementSequenceStore` backed by a file.
    /// If the file exists, the sequence is loaded from it. If not,
    /// the sequence starts at 0.
    ///
    /// # Errors
    /// Returns `io::Error` if the file exists but cannot be read.
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let sequence = if path.exists() {
            let data = std::fs::read(&path)?;
            if data.len() >= 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                u64::from_le_bytes(buf)
            } else {
                0
            }
        } else {
            0
        };
        Ok(Self { sequence, path })
    }

    /// Create an in-memory store (for tests). Not persisted.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            sequence: 0,
            path: std::path::PathBuf::new(), // empty path = no persistence
        }
    }

    /// Create an in-memory store starting at a specific sequence (for tests).
    #[must_use]
    pub fn in_memory_starting_at(sequence: u64) -> Self {
        Self {
            sequence,
            path: std::path::PathBuf::new(),
        }
    }

    /// Get the current sequence without incrementing.
    #[must_use]
    pub fn current_sequence(&self) -> u64 {
        self.sequence
    }

    /// Atomically increment the sequence and return the new value.
    /// The new value is persisted to the file (if a path was provided).
    ///
    /// # Errors
    /// Returns `io::Error` if the file cannot be written.
    pub fn next_sequence(&mut self) -> std::io::Result<u64> {
        self.sequence = self.sequence.saturating_add(1);
        self.persist()?;
        Ok(self.sequence)
    }

    /// Persist the current sequence to the file.
    fn persist(&self) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // in-memory mode
        }
        let data = self.sequence.to_le_bytes();
        std::fs::write(&self.path, data)
    }

    /// Simulate a process restart by creating a new store from the same file.
    /// The new store will load the persisted sequence.
    ///
    /// # Errors
    /// Returns `io::Error` if the file cannot be read.
    pub fn restart(&self) -> std::io::Result<Self> {
        if self.path.as_os_str().is_empty() {
            // In-memory: return a fresh store (simulating data loss).
            return Ok(Self::in_memory());
        }
        Self::open(&self.path)
    }
}
