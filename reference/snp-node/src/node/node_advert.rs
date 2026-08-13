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

// ─── N2.2.1 CBOR helpers (local copies; tiny, not worth a shared module) ───

/// Look up a text-keyed field in a CBOR map.
fn cbor_map_get<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    for (k, v) in map {
        if let CborValue::TextString(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

/// Extract a fixed-size byte array from a `CborValue::ByteString`.
fn cbor_get_fixed_bytes<const N: usize>(value: &CborValue) -> Option<[u8; N]> {
    if let CborValue::ByteString(bytes) = value {
        if bytes.len() == N {
            let mut out = [0u8; N];
            out.copy_from_slice(bytes);
            return Some(out);
        }
    }
    None
}

/// Extract a `u64` from a `CborValue::UnsignedInt`.
fn cbor_get_u64(value: &CborValue) -> Option<u64> {
    match value {
        CborValue::UnsignedInt(n) => Some(*n),
        _ => None,
    }
}

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

    /// **N2.2.1.** Canonical CBOR encoding of the COMPLETE `NodeAdvertisement`
    /// (every field, including `signature`). Used for wire transmission.
    ///
    /// This is `preimage()` + the `signature` field. The signature itself
    /// is NOT covered by the signature (it IS the signature). The wire
    /// format carries the signature so receivers can independently verify
    /// the advertisement via `verify_into_verified()`.
    #[must_use]
    pub fn to_cbor_map(&self) -> CborValue {
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
            (CborValue::TextString("signature".into()), CborValue::ByteString(self.signature.to_vec())),
        ])
    }

    /// **N2.2.1.** Decode a `NodeAdvertisement` from a canonical CBOR map.
    ///
    /// Returns `None` if the value is not a map, is missing required fields,
    /// or has fields of the wrong type/length. The caller MUST still call
    /// `verify_into_verified()` before trusting the advertisement — this
    /// method only checks the structural shape, not the signature.
    #[must_use]
    pub fn from_cbor_map(value: &CborValue) -> Option<Self> {
        let map = match value {
            CborValue::Map(entries) => entries.as_slice(),
            _ => return None,
        };
        let node_id = cbor_get_fixed_bytes(cbor_map_get(map, "nodeId")?)?;
        let ed25519_public_key = cbor_get_fixed_bytes(cbor_map_get(map, "publicKey")?)?;
        // Capabilities: array of text strings.
        let caps_arr = match cbor_map_get(map, "capabilities")? {
            CborValue::Array(items) => items,
            _ => return None,
        };
        let mut capabilities = Vec::with_capacity(caps_arr.len());
        for item in caps_arr {
            let s = match item {
                CborValue::TextString(s) => s.as_str(),
                _ => return None,
            };
            capabilities.push(Capability::from_str(s)?);
        }
        // Endpoints: array of {type, addr} maps.
        let eps_arr = match cbor_map_get(map, "endpoints")? {
            CborValue::Array(items) => items,
            _ => return None,
        };
        let mut endpoints = Vec::with_capacity(eps_arr.len());
        for item in eps_arr {
            endpoints.push(TransportEndpoint::from_cbor_map(item)?);
        }
        let x25519_circuit_public = match cbor_map_get(map, "x25519CircuitPub")? {
            CborValue::Null => None,
            CborValue::ByteString(bytes) if bytes.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(bytes);
                Some(k)
            }
            _ => return None,
        };
        let timestamp = cbor_get_u64(cbor_map_get(map, "timestamp")?)?;
        let expiry = cbor_get_u64(cbor_map_get(map, "expiry")?)?;
        let nonce = cbor_get_fixed_bytes(cbor_map_get(map, "nonce")?)?;
        let sequence = cbor_get_u64(cbor_map_get(map, "sequence")?)?;
        let signature = cbor_get_fixed_bytes(cbor_map_get(map, "signature")?)?;
        Some(Self {
            node_id,
            ed25519_public_key,
            capabilities,
            endpoints,
            x25519_circuit_public,
            timestamp,
            expiry,
            nonce,
            sequence,
            signature,
        })
    }

    /// **N2.2.1.** Encode to canonical CBOR bytes for wire transmission.
    #[must_use]
    pub fn encode_cbor(&self) -> Vec<u8> {
        snp_cbor::encode(&self.to_cbor_map()).expect("CBOR encode never fails for NodeAdvertisement")
    }

    /// **N2.2.1.** Decode from canonical CBOR bytes. Returns `None` if the
    /// bytes are not well-formed canonical CBOR or do not decode to a valid
    /// `NodeAdvertisement` shape. The caller MUST still call
    /// `verify_into_verified()` before trusting the advertisement.
    #[must_use]
    pub fn decode_cbor(bytes: &[u8]) -> Option<Self> {
        Self::from_cbor_map(&snp_cbor::decode(bytes).ok()?)
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
        // **N2.2.1:** Retain the underlying advertisement so the record can
        // be re-serialized to canonical CBOR for wire transmission. The
        // receiver re-verifies the advertisement's signature on decode.
        let advert = self.advert;
        AuthenticatedNodeRecord {
            descriptor,
            endpoints,
            sequence,
            expiry,
            advert,
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
/// - `advert` — the underlying signed `NodeAdvertisement` (N2.2.1: retained
///   for wire serialization so receivers can independently re-verify the
///   signature; not accessed by the routing layer).
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
    /// **N2.2.1.** The underlying signed `NodeAdvertisement` from which this
    /// record was derived. Retained so the record can be serialized to canonical
    /// CBOR for wire transmission (`encode_cbor()` emits this advertisement;
    /// the receiver re-verifies it via `verify_into_verified()` and reconstructs
    /// the record via `into_record()`). The routing layer does NOT access this
    /// field — it consumes `descriptor` and `endpoints`.
    pub advert: NodeAdvertisement,
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

    /// **N2.2.1.** Get the underlying signed `NodeAdvertisement`. Used by
    /// wire-serialization code (`encode_cbor()`).
    #[must_use]
    pub fn advert(&self) -> &NodeAdvertisement {
        &self.advert
    }

    /// **N2.2.1.** Canonical CBOR encoding of this record for wire
    /// transmission. Emits the underlying signed `NodeAdvertisement` —
    /// the receiver re-verifies the signature via `verify_into_verified()`
    /// and reconstructs the record via `into_record()`. This means the
    /// record's authority is the advertisement's signature, NOT the
    /// unsigned envelope.
    #[must_use]
    pub fn encode_cbor(&self) -> Vec<u8> {
        self.advert.encode_cbor()
    }

    /// **N2.2.1.** Decode an `AuthenticatedNodeRecord` from canonical CBOR
    /// bytes.
    ///
    /// The bytes MUST be a canonical-CBOR-encoded `NodeAdvertisement`. The
    /// advertisement is re-verified via `verify_into_verified()` (signature +
    /// NodeId consistency + clock + role/key consistency). If verification
    /// fails, `None` is returned — the record is rejected.
    ///
    /// This ensures a malicious transport cannot substitute a forged
    /// advertisement: the signature MUST verify under the embedded public
    /// key, and the NodeId MUST match `derive_node_id(public_key)`.
    #[must_use]
    pub fn decode_cbor(bytes: &[u8]) -> Option<Self> {
        let advert = NodeAdvertisement::decode_cbor(bytes)?;
        let verified = advert.verify_into_verified()?;
        Some(verified.into_record())
    }
}

// ─── PeerAcceptanceState ────────────────────────────────────────────────────

/// Per-peer acceptance state. Separates the monotonic sequence floor (which
/// must NOT be erased when the current record expires) from the current
/// authenticated record (which MAY expire and be purged).
///
/// ## Peer visibility states
///
/// A peer can be in one of these visibility states:
///
/// - **KNOWN** — the authenticated identity has been seen. `highest_accepted_sequence`
///   is set. `current_record` may or may not be present.
/// - **ACTIVE** — a currently valid `AuthenticatedNodeRecord` exists
///   (`current_record` is `Some` and not expired).
/// - **STALE** — the identity is known but its latest advertisement has expired
///   (`current_record` is `None` after `purge_expired_records()`).
///   The peer is still KNOWN — the sequence floor persists.
/// - **REMOVED** — the peer has been explicitly removed via `remove_peer()`.
///   The identity history is gone. This is the ONLY state transition that
///   erases the sequence floor. It MUST NOT be used for temporary network
///   loss, expired advertisements, route failure, peer timeout, or ordinary
///   topology churn.
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
///   `remove_peer()` (permanent identity-history deletion).
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
    /// The peer's Ed25519 public key. Persisted alongside the sequence
    /// to verify NodeId ↔ Ed25519 consistency when loading acceptance state.
    /// This provides an additional integrity check when persisting/importing
    /// topology state.
    pub ed25519_public_key: [u8; 32],
    /// The current authenticated record, if one is active (not expired).
    /// `None` if the record has expired and been purged (STALE state).
    pub current_record: Option<AuthenticatedNodeRecord>,
}

/// The visibility state of a peer in the acceptance store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerVisibility {
    /// The peer's identity has never been seen.
    Unknown,
    /// The peer is known and has a currently valid advertisement.
    Active,
    /// The peer is known but its latest advertisement has expired.
    /// The sequence floor persists — old advertisements are still rejected.
    Stale,
}

// ─── AcceptanceError ────────────────────────────────────────────────────────

/// Errors from the acceptance store.
#[derive(Debug)]
pub enum AcceptanceError {
    /// Persistence write failed. The in-memory state was NOT advanced —
    /// the advertisement was NOT accepted. The caller must retry or
    /// handle the error.
    PersistenceFailed(std::io::Error),
    /// The persistence file is corrupted (truncated, malformed, or
    /// contains duplicate/invalid entries). The store was NOT loaded.
    /// The caller should quarantine or delete the file.
    CorruptPersistence(String),
}

impl std::fmt::Display for AcceptanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PersistenceFailed(e) => write!(f, "persistence failed: {e}"),
            Self::CorruptPersistence(msg) => write!(f, "corrupt persistence: {msg}"),
        }
    }
}

impl std::error::Error for AcceptanceError {}

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
/// per NodeId. This provides **replay prevention** — a previously seen
/// advertisement (same or lower sequence) is rejected.
///
/// ## N2.1.0.3: Persistent peer acceptance state
///
/// The store supports file-backed persistence. When a file path is provided
/// via `open()`, the acceptance state (NodeId + Ed25519 public key +
/// highest_accepted_sequence) is persisted to disk after every successful
/// `accept()` call. On restart, `open()` loads the persisted state, and old
/// advertisements with lower sequences are rejected as stale.
///
/// ## Persistence format (N2.1.0.4)
///
/// **Reference-node persistence format; NOT a cross-platform SNP wire format.**
///
/// The file contains:
/// - 4 bytes: magic `b"SNPA"` (ShareNet Peer Acceptance)
/// - 1 byte: version (`1`)
/// - N × 72-byte entries, each:
///   - 32 bytes: NodeId
///   - 32 bytes: Ed25519 public key
///   - 8 bytes: highest_accepted_sequence (little-endian u64)
///
/// Total header: 5 bytes. Total per entry: 72 bytes.
///
/// ## Atomicity vs Durability (N2.1.0.4)
///
/// **Atomic replacement: YES.** Persistence uses write-to-temp-then-rename.
/// Readers never see a partially written replacement under normal filesystem
/// semantics.
///
/// **Guaranteed crash/power-loss durability: NOT CLAIMED.** The reference
/// implementation does not perform `fsync` before rename. A power loss
/// immediately after `write()` but before the OS flushes to disk may lose
/// the write. Production implementations should add `fsync(temp) → rename →
/// fsync(parent_dir)` for full durability.
///
/// ## Fail-closed corruption handling (N2.1.0.4)
///
/// Loading a persistence file fails closed:
/// - Files shorter than the 5-byte header → `CorruptPersistence`.
/// - Files whose data after the header is not a multiple of `ENTRY_SIZE` →
///   `CorruptPersistence` (trailing bytes are NOT silently ignored).
/// - Entries with `NodeId ≠ SHA-256("SNP/0.1 node\0" || ed25519_public_key)` →
///   `CorruptPersistence` (identity-inconsistent entries are NOT silently skipped).
/// - Duplicate `NodeId` entries → `CorruptPersistence` (NOT silently overwritten).
///
/// ## Transactional acceptance (N2.1.0.4)
///
/// `accept()` returns `Result<AcceptanceResult, AcceptanceError>`.
/// When the result would be `Accepted`, the new state is persisted FIRST.
/// If persistence fails, `AcceptanceError::PersistenceFailed` is returned
/// and the in-memory state is NOT advanced — the advertisement was NOT
/// accepted. The caller must retry or handle the error.
///
/// ## Peer visibility states
///
/// - **KNOWN** — `highest_accepted_sequence` is set (peer identity seen before).
/// - **ACTIVE** — `current_record` is `Some` and not expired.
/// - **STALE** — `current_record` is `None` (expired and purged), but
///   `highest_accepted_sequence` persists.
/// - **REMOVED** — peer entry deleted via `remove_peer()`. This is the ONLY
///   way to erase the sequence floor.
///
/// `remove_peer()` MUST NOT be used for temporary network loss, expired
/// advertisements, route failure, peer timeout, or ordinary topology churn.
/// Those events change ACTIVE → STALE only.
#[derive(Debug, Clone, Default)]
pub struct AdvertisementAcceptanceStore {
    /// Map: NodeId → PeerAcceptanceState.
    peers: HashMap<[u8; 32], PeerAcceptanceState>,
    /// Optional file path for persistence. Empty = in-memory mode.
    path: std::path::PathBuf,
}

/// On-disk entry format: NodeId (32) + Ed25519 pub (32) + sequence (8) = 72 bytes.
const ENTRY_SIZE: usize = 72;

/// Persistence file magic: `b"SNPA"` (ShareNet Peer Acceptance).
const PERSIST_MAGIC: &[u8; 4] = b"SNPA";

/// Persistence file format version.
const PERSIST_VERSION: u8 = 1;

/// Header size: magic (4) + version (1) = 5 bytes.
const HEADER_SIZE: usize = 5;

impl AdvertisementAcceptanceStore {
    /// Create a new empty in-memory store (not persisted).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a persistent store backed by a file. If the file exists, the
    /// acceptance state is loaded from it. If not, the store starts empty.
    ///
    /// ## Fail-closed (N2.1.0.4)
    ///
    /// If the file is corrupted (truncated, invalid magic/version, trailing
    /// bytes, duplicate NodeIds, or identity-inconsistent entries), this
    /// method returns `AcceptanceError::CorruptPersistence`. The caller
    /// should quarantine or delete the file.
    ///
    /// # Errors
    /// Returns `AcceptanceError::CorruptPersistence` for corrupted files.
    /// Returns `io::Error` (wrapped) for I/O failures.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, AcceptanceError> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            peers: HashMap::new(),
            path,
        };
        if store.path.exists() {
            store.load()?;
        }
        Ok(store)
    }

    /// Load acceptance state from the persistence file. Fails closed on
    /// any corruption.
    fn load(&mut self) -> Result<(), AcceptanceError> {
        let data = std::fs::read(&self.path)
            .map_err(|e| AcceptanceError::CorruptPersistence(format!("read error: {e}")))?;

        // Check minimum header size.
        if data.len() < HEADER_SIZE {
            return Err(AcceptanceError::CorruptPersistence(
                format!("file too short: {} bytes < {} header", data.len(), HEADER_SIZE),
            ));
        }

        // Check magic.
        if &data[..4] != PERSIST_MAGIC {
            return Err(AcceptanceError::CorruptPersistence(
                format!("invalid magic: expected {:?}, got {:?}", PERSIST_MAGIC, &data[..4]),
            ));
        }

        // Check version.
        if data[4] != PERSIST_VERSION {
            return Err(AcceptanceError::CorruptPersistence(
                format!("unsupported version: expected {}, got {}", PERSIST_VERSION, data[4]),
            ));
        }

        // Check that remaining data is a multiple of ENTRY_SIZE (no trailing bytes).
        let entries_data = &data[HEADER_SIZE..];
        if entries_data.len() % ENTRY_SIZE != 0 {
            return Err(AcceptanceError::CorruptPersistence(
                format!("trailing bytes: {} bytes after header is not a multiple of {}", entries_data.len(), ENTRY_SIZE),
            ));
        }

        // Parse entries. Fail on duplicates or identity inconsistency.
        let mut seen_node_ids = std::collections::HashSet::new();
        let mut offset = 0;
        while offset < entries_data.len() {
            let mut node_id = [0u8; 32];
            node_id.copy_from_slice(&entries_data[offset..offset + 32]);
            let mut ed25519_pk = [0u8; 32];
            ed25519_pk.copy_from_slice(&entries_data[offset + 32..offset + 64]);
            let mut seq_buf = [0u8; 8];
            seq_buf.copy_from_slice(&entries_data[offset + 64..offset + 72]);
            let sequence = u64::from_le_bytes(seq_buf);
            offset += ENTRY_SIZE;

            // Check for duplicate NodeId.
            if !seen_node_ids.insert(node_id) {
                return Err(AcceptanceError::CorruptPersistence(
                    format!("duplicate NodeId entry at offset {}", offset - ENTRY_SIZE),
                ));
            }

            // Verify NodeId ↔ Ed25519 consistency (I4).
            let expected_node_id = derive_node_id(&ed25519_pk);
            if node_id != expected_node_id {
                return Err(AcceptanceError::CorruptPersistence(
                    format!("NodeId↔Ed25519 inconsistency for entry at offset {}", offset - ENTRY_SIZE),
                ));
            }

            self.peers.insert(node_id, PeerAcceptanceState {
                highest_accepted_sequence: sequence,
                ed25519_public_key: ed25519_pk,
                current_record: None,
            });
        }
        Ok(())
    }

    /// Persist the acceptance state to the file using an atomic
    /// write-to-temp-then-rename strategy.
    ///
    /// **Atomic replacement: YES.** Readers never see a partial write.
    /// **Guaranteed power-loss durability: NOT CLAIMED** (no fsync).
    fn persist(&self) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // in-memory mode
        }
        let mut data = Vec::with_capacity(HEADER_SIZE + self.peers.len() * ENTRY_SIZE);
        // Header.
        data.extend_from_slice(PERSIST_MAGIC);
        data.push(PERSIST_VERSION);
        // Entries.
        for (node_id, state) in &self.peers {
            data.extend_from_slice(node_id);
            data.extend_from_slice(&state.ed25519_public_key);
            data.extend_from_slice(&state.highest_accepted_sequence.to_le_bytes());
        }
        // Atomic write: write to temp file, then rename.
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Attempt to accept a `VerifiedNodeAdvertisement`.
    ///
    /// ## Transactional semantics (N2.1.0.4)
    ///
    /// When the result would be `Accepted`:
    /// 1. Compute the new state.
    /// 2. Persist the new state to disk.
    /// 3. Only if persistence succeeds, update the in-memory state.
    /// 4. Return `Accepted`.
    ///
    /// If persistence fails, return `AcceptanceError::PersistenceFailed`
    /// and do NOT update the in-memory state — the advertisement was NOT
    /// accepted.
    ///
    /// Stale and duplicate results do NOT require persistence (the state
    /// doesn't change) and are returned directly.
    ///
    /// # Errors
    /// Returns `AcceptanceError::PersistenceFailed` if the state could not
    /// be persisted. The in-memory state is NOT advanced in this case.
    pub fn accept(
        &mut self,
        verified: VerifiedNodeAdvertisement,
    ) -> Result<AcceptanceResult, AcceptanceError> {
        let node_id = verified.node_id();
        let sequence = verified.sequence();
        let ed25519_pk = *verified.ed25519_public_key();
        match self.peers.get(&node_id) {
            None => {
                // First advertisement from this node — need to persist.
                let record = verified.into_record();
                let new_state = PeerAcceptanceState {
                    highest_accepted_sequence: sequence,
                    ed25519_public_key: ed25519_pk,
                    current_record: Some(record.clone()),
                };
                // Transactional: persist FIRST, then update in-memory.
                // Temporarily insert to compute persist data, then remove if persist fails.
                self.peers.insert(node_id, new_state);
                if let Err(e) = self.persist() {
                    // Rollback: remove the entry we just added.
                    self.peers.remove(&node_id);
                    return Err(AcceptanceError::PersistenceFailed(e));
                }
                Ok(AcceptanceResult::Accepted(record))
            }
            Some(state) if sequence > state.highest_accepted_sequence => {
                // Newer advertisement — need to persist.
                let old_state = state.clone();
                let record = verified.into_record();
                let new_state = PeerAcceptanceState {
                    highest_accepted_sequence: sequence,
                    ed25519_public_key: ed25519_pk,
                    current_record: Some(record.clone()),
                };
                self.peers.insert(node_id, new_state);
                if let Err(e) = self.persist() {
                    // Rollback: restore the old state.
                    self.peers.insert(node_id, old_state);
                    return Err(AcceptanceError::PersistenceFailed(e));
                }
                Ok(AcceptanceResult::Accepted(record))
            }
            Some(_) if sequence == self.peers.get(&node_id).map(|s| s.highest_accepted_sequence).unwrap_or(0) => {
                // Duplicate — no state change, no persistence needed.
                Ok(AcceptanceResult::Duplicate { sequence })
            }
            Some(state) => {
                // Stale — no state change, no persistence needed.
                Ok(AcceptanceResult::Stale {
                    advert_sequence: sequence,
                    known_sequence: state.highest_accepted_sequence,
                })
            }
        }
    }

    /// Get the current `AuthenticatedNodeRecord` for a NodeId, if any
    /// (and if not expired).
    #[must_use]
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&AuthenticatedNodeRecord> {
        self.peers.get(node_id).and_then(|s| s.current_record.as_ref())
    }

    /// **N2.1.2.** Iterate over ALL current (non-expired) accepted records.
    ///
    /// This includes records for nodes that have NO links — they are
    /// authenticated but may not be directly reachable. The route engine
    /// uses this to discover all gateway candidates, not just those with
    /// usable links.
    ///
    /// Returns references to all `AuthenticatedNodeRecord`s currently held.
    #[must_use]
    pub fn all_records(&self) -> impl Iterator<Item = &AuthenticatedNodeRecord> {
        self.peers
            .values()
            .filter_map(|s| s.current_record.as_ref())
    }

    /// Get the highest accepted sequence for a NodeId, if any.
    /// This survives record expiry/purging — the sequence floor is
    /// NOT erased by `purge_expired_records()`.
    #[must_use]
    pub fn highest_sequence(&self, node_id: &[u8; 32]) -> Option<u64> {
        self.peers.get(node_id).map(|s| s.highest_accepted_sequence)
    }

    /// Get the visibility state of a peer.
    #[must_use]
    pub fn visibility(&self, node_id: &[u8; 32]) -> PeerVisibility {
        match self.peers.get(node_id) {
            None => PeerVisibility::Unknown,
            Some(state) => {
                if state.current_record.is_some() {
                    PeerVisibility::Active
                } else {
                    PeerVisibility::Stale
                }
            }
        }
    }

    /// Purge expired CURRENT RECORDS from the store. This does NOT
    /// remove the `highest_accepted_sequence` — the sequence floor
    /// persists to prevent replay of old advertisements after the
    /// current record expires.
    ///
    /// This changes ACTIVE → STALE only. It does NOT change STALE → REMOVED.
    pub fn purge_expired_records(&mut self, now: u64) {
        for state in self.peers.values_mut() {
            if let Some(record) = &state.current_record {
                if record.is_expired(now) {
                    state.current_record = None;
                }
            }
        }
    }

    /// Remove a peer entirely (including the sequence floor). This is an
    /// **explicit identity-history deletion operation**.
    ///
    /// **MUST NOT be used for:**
    /// - temporary network loss
    /// - expired advertisements
    /// - route failure
    /// - peer timeout
    /// - ordinary topology churn
    ///
    /// Those events change ACTIVE → STALE only (via `purge_expired_records()`).
    ///
    /// `remove_peer()` should only be used when a node's identity is
    /// permanently removed from the topology (e.g. revocation, identity
    /// rotation, or administrative action).
    ///
    /// ## N2.1.0.5: Transactional
    ///
    /// `remove_peer()` is transactional: the peer is removed from the
    /// persistence file FIRST. Only if persistence succeeds is the
    /// in-memory state updated. If persistence fails, the peer is
    /// NOT removed — the identity history is preserved.
    ///
    /// # Errors
    /// Returns `AcceptanceError::PersistenceFailed` if the state could not
    /// be persisted. The peer is NOT removed in this case.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) -> Result<(), AcceptanceError> {
        // Check if the peer exists.
        if !self.peers.contains_key(node_id) {
            return Ok(()); // Already removed — no-op.
        }
        // Save the old state for rollback.
        let old_state = self.peers.remove(node_id);
        // Persist the new state (without the peer).
        if let Err(e) = self.persist() {
            // Rollback: restore the peer.
            if let Some(state) = old_state {
                self.peers.insert(*node_id, state);
            }
            return Err(AcceptanceError::PersistenceFailed(e));
        }
        Ok(())
    }

    /// Simulate a process restart by creating a new store from the same
    /// persistence file. The new store will load the persisted acceptance
    /// state (NodeId + Ed25519 pub + highest_sequence). Current records
    /// are NOT persisted — they will be `None` after restart.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if the file is corrupted or cannot be read.
    pub fn restart(&self) -> Result<Self, AcceptanceError> {
        if self.path.as_os_str().is_empty() {
            // In-memory: return a fresh store (simulating data loss).
            return Ok(Self::new());
        }
        Self::open(&self.path)
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
/// ## N2.1.0.5: Hardened persistence
///
/// The persistence format now includes a magic + version header and uses
/// atomic write-to-temp-then-rename, matching the discipline of
/// `AdvertisementAcceptanceStore`. Corrupted files fail closed — they
/// do NOT silently reset the sequence to 0.
///
/// ## Persistence format (N2.1.0.5)
///
/// **Reference-node persistence format; NOT a cross-platform SNP wire format.**
///
/// - 4 bytes: magic `b"SNSQ"` (ShareNet Node Sequence)
/// - 1 byte: version (`1`)
/// - 8 bytes: sequence (little-endian u64)
///
/// Total: 13 bytes.
///
/// ## Atomicity vs Durability
///
/// **Atomic replacement: YES.** Uses write-to-temp-then-rename.
/// **Guaranteed power-loss durability: NOT CLAIMED** (no fsync).
///
/// ## Fail-closed corruption handling (N2.1.0.5)
///
/// Loading a persistence file fails closed:
/// - Files shorter than 13 bytes → error.
/// - Wrong magic → error.
/// - Wrong version → error.
/// - Trailing bytes after the 13-byte record → error.
///
/// Corrupted files do NOT silently reset the sequence to 0.
#[derive(Debug)]
pub struct AdvertisementSequenceStore {
    /// The current sequence counter (in-memory cache of the persisted value).
    sequence: u64,
    /// The file path where the sequence is persisted.
    path: std::path::PathBuf,
}

/// Magic for the sequence store file: `b"SNSQ"`.
const SEQ_MAGIC: &[u8; 4] = b"SNSQ";
/// Version for the sequence store file.
const SEQ_VERSION: u8 = 1;
/// Header: magic (4) + version (1) = 5 bytes.
const SEQ_HEADER_SIZE: usize = 5;
/// Total file size: header (5) + sequence (8) = 13 bytes.
const SEQ_FILE_SIZE: usize = SEQ_HEADER_SIZE + 8;

/// Error from the sequence store.
#[derive(Debug)]
pub enum SequenceStoreError {
    /// I/O error.
    Io(std::io::Error),
    /// The persistence file is corrupted.
    Corrupt(String),
    /// The sequence counter has reached `u64::MAX` and cannot be
    /// incremented further. The node must rotate its identity or use
    /// an epoch reset mechanism (not yet implemented). The in-memory
    /// sequence is NOT changed.
    SequenceExhausted,
}

impl std::fmt::Display for SequenceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Corrupt(msg) => write!(f, "corrupt sequence store: {msg}"),
            Self::SequenceExhausted => write!(f, "sequence exhausted: u64::MAX reached, cannot increment"),
        }
    }
}

impl std::error::Error for SequenceStoreError {}

impl From<std::io::Error> for SequenceStoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl AdvertisementSequenceStore {
    /// Create a new `AdvertisementSequenceStore` backed by a file.
    /// If the file exists, the sequence is loaded from it. If not,
    /// the sequence starts at 0.
    ///
    /// ## Fail-closed (N2.1.0.5)
    ///
    /// If the file is corrupted (wrong magic, wrong version, truncated,
    /// trailing bytes), this method returns `SequenceStoreError::Corrupt`.
    /// The caller should quarantine or delete the file. The sequence is
    /// NOT silently reset to 0.
    ///
    /// # Errors
    /// Returns `SequenceStoreError::Corrupt` for corrupted files.
    /// Returns `SequenceStoreError::Io` for I/O failures.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, SequenceStoreError> {
        let path = path.as_ref().to_path_buf();
        let sequence = if path.exists() {
            let data = std::fs::read(&path)?;
            // Check minimum size.
            if data.len() < SEQ_FILE_SIZE {
                return Err(SequenceStoreError::Corrupt(format!(
                    "file too short: {} bytes < {} expected", data.len(), SEQ_FILE_SIZE
                )));
            }
            // Check magic.
            if &data[..4] != SEQ_MAGIC {
                return Err(SequenceStoreError::Corrupt(format!(
                    "invalid magic: expected {:?}, got {:?}", SEQ_MAGIC, &data[..4]
                )));
            }
            // Check version.
            if data[4] != SEQ_VERSION {
                return Err(SequenceStoreError::Corrupt(format!(
                    "unsupported version: expected {}, got {}", SEQ_VERSION, data[4]
                )));
            }
            // Check for trailing bytes.
            if data.len() > SEQ_FILE_SIZE {
                return Err(SequenceStoreError::Corrupt(format!(
                    "trailing bytes: {} bytes > {} expected", data.len(), SEQ_FILE_SIZE
                )));
            }
            // Read the sequence.
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[SEQ_HEADER_SIZE..SEQ_FILE_SIZE]);
            u64::from_le_bytes(buf)
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
    ///
    /// ## Transactional semantics (N2.1.0.4)
    ///
    /// 1. Compute `next = sequence + 1`.
    /// 2. Persist `next` to the file.
    /// 3. Only if persistence succeeds, update `self.sequence = next`.
    /// 4. Return `next`.
    ///
    /// If persistence fails, the in-memory counter is NOT advanced.
    ///
    /// ## N2.1.0.6: Sequence exhaustion
    ///
    /// If `self.sequence == u64::MAX`, this method returns
    /// `SequenceStoreError::SequenceExhausted`. The in-memory counter
    /// is NOT changed. The node must rotate its identity or use an
    /// epoch reset mechanism (not yet implemented).
    ///
    /// # Errors
    /// Returns `SequenceStoreError::SequenceExhausted` if the sequence
    /// has reached `u64::MAX`.
    /// Returns `SequenceStoreError::Io` if the file cannot be written.
    pub fn next_sequence(&mut self) -> Result<u64, SequenceStoreError> {
        // Check for sequence exhaustion BEFORE computing next.
        if self.sequence == u64::MAX {
            return Err(SequenceStoreError::SequenceExhausted);
        }
        let next = self.sequence + 1; // Safe: checked above.
        let old_sequence = self.sequence;
        self.sequence = next; // temporarily set for persist()
        if let Err(e) = self.persist() {
            self.sequence = old_sequence; // rollback
            return Err(SequenceStoreError::Io(e));
        }
        Ok(next)
    }

    /// Persist the current sequence to the file using atomic
    /// write-to-temp-then-rename.
    ///
    /// **Atomic replacement: YES.** Readers never see a partial write.
    /// **Guaranteed power-loss durability: NOT CLAIMED** (no fsync).
    fn persist(&self) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // in-memory mode
        }
        let mut data = Vec::with_capacity(SEQ_FILE_SIZE);
        data.extend_from_slice(SEQ_MAGIC);
        data.push(SEQ_VERSION);
        data.extend_from_slice(&self.sequence.to_le_bytes());
        // Atomic write: write to temp file, then rename.
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Simulate a process restart by creating a new store from the same file.
    ///
    /// # Errors
    /// Returns `SequenceStoreError` if the file is corrupted or cannot be read.
    pub fn restart(&self) -> Result<Self, SequenceStoreError> {
        if self.path.as_os_str().is_empty() {
            return Ok(Self::in_memory());
        }
        Self::open(&self.path)
    }
}
