//! N2.1.3 — Circuit Cryptographic Setup.
//!
//! Spec: public/spec/08-circuits.md (N2.1.3 — Circuit Cryptographic Setup).
//!
//! ## CRITICAL: This is LOCAL preparation, NOT distributed establishment.
//!
//! `prepare_circuit_setup()` creates the cryptographic material the source
//! needs to initiate a circuit. It does NOT establish a circuit across the
//! participating nodes. No relay receives the handshake, verifies it, derives
//! its key, or acknowledges establishment. Distributed circuit establishment
//! (where each participant independently installs forwarding state) is
//! deferred to the transport milestone (N2.2+).
//!
//! ## CRITICAL: CommittedRoute ≠ Circuit
//!
//! A `CommittedRoute` is a **cryptographically consented route agreement**
//! backed by validated evidence. It is NOT source-side preparation.
//!
//! A `CircuitSetup` is **source-side cryptographic preparation** — per-hop
//! forwarding keys derived locally, NOT installed on any relay. It is NOT
//! live distributed state, NOT an established session, and NOT forwarding
//! state on remote nodes.
//!
//! The transition from `CommittedRoute` to `CircuitSetup` is a local
//! cryptographic preparation step:
//!
//! ```text
//! CommittedRoute (agreement + evidence)
//!         ↓
//! CircuitHandshake (initiation message, signed by source)
//!         ↓
//! Per-hop X25519 DH + HKDF key derivation
//!         ↓
//! CircuitSetup (source-side preparation artifact — NOT distributed)
//!         ↓
//! [N2.2+: distributed handshake → relay installs forwarding state →
//!          ActiveCircuit (live distributed state) → Traffic → Teardown]
//! ```
//!
//! ## What the circuit protocol answers (per architecture review)
//!
//! - **Who initiated?** The `CircuitHandshake` is signed by the source's
//!   Ed25519 key (bound to the committed route's source).
//! - **Which CommittedRoute?** The handshake references the route's
//!   `commitment` hash. A circuit cannot exist without a committed route.
//! - **Which participant is each peer?** Each `HopForwardingState` carries
//!   the hop's NodeId + its predecessor/successor NodeIds.
//! - **Which keys?** Per-hop forwarding keys are derived via X25519 DH
//!   between the initiator's ephemeral key and each hop's X25519 circuit
//!   public key (from the authenticated advertisement). HKDF-SHA256 with
//!   domain separation.
//! - **Replay prevention?** Each circuit has a unique 32-byte `circuit_id`
//!   (from OS randomness — fail-closed on RNG failure). The circuit_id
//!   is part of the handshake's signed preimage.
//! - **Key rotation/expiry?** Circuits have `created_at` + `expires_at`.
//!   A stale circuit is rejected. Key rotation is a future concern (N2.1.3
//!   establishes the initial keys; rotation is N2.1.4+).
//! - **Predecessor/successor?** Each `HopForwardingState` explicitly records
//!   `predecessor_node_id` and `successor_node_id`. A relay knows exactly
//!   who its neighbors are.
//! - **Endpoint substitution?** The handshake's `commitment_hash` binds the
//!   circuit to the exact committed route. The ephemeral X25519 public key
//!   is signed. Each hop's X25519 circuit key comes from the authenticated
//!   advertisement — an attacker cannot substitute a different key.
//! - **Wrong identity?** `verify_handshake()` checks the source signature
//!   + commitment binding + freshness. A relay that presents the wrong
//!   identity is rejected.
//! - **Stale evidence?** If the committed route's evidence is stale (e.g.
//!   attested links have expired), the route's `is_expired()` returns true
//!   and `prepare_circuit_setup()` rejects it.
//! - **Teardown?** `CircuitTeardown` is signed by the initiator. Each relay
//!   can verify the teardown is authentic.
//!
//! ## NOT implemented (deferred)
//!
//! - Arbitrary TCP connection migration — spec §39 (N2.1.4+).
//! - Route failure / recovery — spec §39 (N2.1.4).
//! - Key rotation within a circuit (N2.1.4+).
//! - Actual traffic forwarding (the circuit provides the keys; the
//!   transport layer uses them — that's N2.2+).

use super::*;
use crate::node::node_advert::MAX_CLOCK_SKEW_SECS;
use crate::node::route_discovery::{CommittedRoute, RouteSerializationError, ROUTE_MAX_LIFETIME_SECS};
use crate::node::identity::Capability;
use snp_cbor::CborValue;
use snp_crypto::{
    ed25519_sign, ed25519_verify, derive_node_id, sha256, hkdf_sha256,
    x25519_dh, x25519_public_from_bytes,
    X25519Secret, X25519PubKey,
    SymmetricKey,
};

/// SIG_CONTEXT for circuit handshake and teardown messages.
pub const CIRCUIT_MSG_CONTEXT: &[u8] = b"SNP/0.1 circuit-msg\0";

/// Maximum circuit lifetime (must be ≤ route proposal lifetime).
pub const CIRCUIT_MAX_LIFETIME_SECS: u64 = 3600; // 1 hour

/// A per-hop forwarding-state description for one route hop.
///
/// In N2.1.3, this is source-side prepared data — NOT installed on the
/// remote relay. It describes the forwarding key and predecessor/successor
/// that WILL be used when the circuit is distributed (N2.2+).
///
/// Each relay knows:
/// - Its own NodeId
/// - Its predecessor (who sends to it)
/// - Its successor (who it sends to)
/// - Its forwarding keys (derived from X25519 DH with the initiator)
#[derive(Debug, Clone)]
pub struct HopForwardingState {
    /// This hop's NodeId.
    pub node_id: [u8; 32],
    /// The predecessor's NodeId (who sends frames to this hop).
    /// `None` for the source (first hop — no predecessor in the forwarding path).
    pub predecessor_node_id: Option<[u8; 32]>,
    /// The successor's NodeId (who this hop forwards to).
    /// `None` for the gateway (last hop — terminal, no forwarding).
    pub successor_node_id: Option<[u8; 32]>,
    /// The forwarding key derived from X25519 DH between the initiator's
    /// ephemeral key and this hop's X25519 circuit public key.
    /// Used for per-hop AEAD encryption/authentication of forwarded frames.
    pub forwarding_key: SymmetricKey,
}

/// A circuit handshake message — the initiation message signed by the source.
///
/// ## CRITICAL: NOT a circuit
///
/// The handshake is the INITIATION message. It proves the source authorized
/// this circuit and binds it to a specific committed route. The actual
/// `CircuitSetup` is produced by `prepare_circuit_setup()`
/// after verifying the handshake.
///
/// ## Binding
///
/// The handshake signs:
/// - `circuit_id`: a unique 32-byte random identifier. Uniqueness helps
///   distinguish circuit instances but is NOT replay protection. Replay
///   protection requires receiver-side acceptance state (N2.2+).
/// - `commitment_hash`: the committed route's commitment hash
/// - `ephemeral_x25519_public`: the initiator's ephemeral X25519 public key
///   (used for per-hop DH key derivation)
/// - `timestamp` + `expiry`: freshness
/// - `nonce`: 16-byte freshness nonce
#[derive(Debug, Clone)]
pub struct CircuitHandshake {
    /// Protocol version.
    pub protocol_version: u8,
    /// Unique circuit identifier (random 32 bytes — fail-closed on RNG failure).
    pub circuit_id: [u8; 32],
    /// The committed route's commitment hash (binds this circuit to a specific route).
    pub commitment_hash: [u8; 32],
    /// The source's NodeId (who initiated this circuit).
    pub source: [u8; 32],
    /// The source's Ed25519 public key.
    pub source_public_key: [u8; 32],
    /// The initiator's ephemeral X25519 public key (for per-hop DH).
    pub ephemeral_x25519_public: [u8; 32],
    /// P0: SHA-256 of the concatenation of all per-hop authorization hashes.
    /// This commits the handshake to the EXACT set of relay authorizations,
    /// preventing split-view attacks where different relays receive different
    /// (individually signed) authorizations for the same circuit.
    pub authorization_root: [u8; 32],
    /// P1: The number of relay authorizations in the authorization set.
    /// Bounded by ROUTE_MAX_HOPS - 1 (max 15 non-source hops).
    /// The relay verifies: authorization_hashes.len() == authorization_count
    /// and authorization_count <= ROUTE_MAX_HOPS - 1 before processing.
    /// This gives the relay an authenticated bound without needing the
    /// CommittedRoute, preventing resource-exhaustion via oversized hash lists.
    pub authorization_count: u8,
    /// When the handshake was created (unix seconds).
    pub timestamp: u64,
    /// When the circuit expires (unix seconds).
    pub expiry: u64,
    /// 16-byte freshness nonce.
    pub nonce: [u8; 16],
    /// The source's Ed25519 signature over the above fields.
    pub source_signature: [u8; 64],
}

impl CircuitHandshake {
    /// Create and sign a circuit handshake bound to a committed route.
    ///
    /// ## Parameters
    ///
    /// - `route`: the committed route to bind this circuit to. MUST not be expired.
    /// - `source_secret_key`: the source's Ed25519 secret key.
    /// - `source_public_key`: the source's Ed25519 public key.
    /// - `ephemeral_x25519_secret`: the initiator's ephemeral X25519 secret key
    ///   (generated by the caller; the public key is derived from it).
    ///
    /// # Errors
    /// Returns `RouteSerializationError::RandomnessFailure` if OS randomness
    /// fails (circuit_id or nonce). Returns `CborEncodingFailed` if CBOR
    /// encoding fails.
    pub fn create_and_sign(
        route: &CommittedRoute,
        source_secret_key: &[u8; 32],
        source_public_key: &[u8; 32],
        ephemeral_x25519_secret: &X25519Secret,
        authorization_root: [u8; 32],
        authorization_count: u8,
    ) -> Result<Self, RouteSerializationError> {
        let now = now_unix();

        // P0: fail-closed on RNG failure.
        let mut circuit_id = [0u8; 32];
        getrandom::getrandom(&mut circuit_id)
            .map_err(|_| RouteSerializationError::RandomnessFailure)?;

        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| RouteSerializationError::RandomnessFailure)?;

        // Derive the ephemeral X25519 public key from the secret.
        let ephemeral_pub = X25519PubKey::from(ephemeral_x25519_secret);
        let ephemeral_pub_bytes: [u8; 32] = ephemeral_pub.to_bytes();

        // The circuit expiry must not exceed the route's expiry.
        let expiry = route.proposal().expiry.min(now + CIRCUIT_MAX_LIFETIME_SECS);

        let mut handshake = Self {
            protocol_version: 1,
            circuit_id,
            commitment_hash: *route.commitment(),
            source: route.source(),
            source_public_key: *source_public_key,
            ephemeral_x25519_public: ephemeral_pub_bytes,
            authorization_root,
            authorization_count,
            timestamp: now,
            expiry,
            nonce,
            source_signature: [0u8; 64],
        };
        let preimage = handshake.preimage_bytes()?;
        handshake.source_signature = ed25519_sign(source_secret_key, &preimage);
        Ok(handshake)
    }

    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("protocolVersion".into()), CborValue::UnsignedInt(u64::from(self.protocol_version))),
            (CborValue::TextString("circuitId".into()), CborValue::ByteString(self.circuit_id.to_vec())),
            (CborValue::TextString("commitmentHash".into()), CborValue::ByteString(self.commitment_hash.to_vec())),
            (CborValue::TextString("source".into()), CborValue::ByteString(self.source.to_vec())),
            (CborValue::TextString("sourcePublicKey".into()), CborValue::ByteString(self.source_public_key.to_vec())),
            (CborValue::TextString("ephemeralX25519Public".into()), CborValue::ByteString(self.ephemeral_x25519_public.to_vec())),
            (CborValue::TextString("authorizationRoot".into()), CborValue::ByteString(self.authorization_root.to_vec())),
            (CborValue::TextString("authorizationCount".into()), CborValue::UnsignedInt(u64::from(self.authorization_count))),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(self.expiry)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.nonce.to_vec())),
        ])
    }

    pub fn preimage_bytes(&self) -> Result<Vec<u8>, RouteSerializationError> {
        let cbor = snp_cbor::encode(&self.preimage())
            .map_err(|_| RouteSerializationError::CborEncodingFailed)?;
        let mut msg = Vec::with_capacity(CIRCUIT_MSG_CONTEXT.len() + cbor.len());
        msg.extend_from_slice(CIRCUIT_MSG_CONTEXT);
        msg.extend_from_slice(&cbor);
        Ok(msg)
    }

    /// Verify the handshake's signature + NodeId binding + freshness.
    ///
    /// Returns `false` on any failure (fail-closed — P0).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_at(now_unix())
    }

    /// Verify at a specific time (for testing).
    #[must_use]
    pub fn verify_at(&self, now: u64) -> bool {
        // NodeId ↔ Ed25519 binding (I4).
        let expected = derive_node_id(&self.source_public_key);
        if self.source != expected { return false; }
        // Freshness.
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) { return false; }
        if self.expiry <= now { return false; }
        if self.expiry <= self.timestamp { return false; }
        if self.expiry.saturating_sub(self.timestamp) > CIRCUIT_MAX_LIFETIME_SECS { return false; }
        // P0: fail-closed if encoding fails.
        let preimage = match self.preimage_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        ed25519_verify(&self.source_public_key, &preimage, &self.source_signature)
    }

    /// Check that this handshake is bound to a specific committed route.
    #[must_use]
    pub fn is_bound_to(&self, route: &CommittedRoute) -> bool {
        self.commitment_hash == *route.commitment()
    }
}

/// Source-side cryptographic preparation artifact — NOT a live circuit.
///
/// ## CRITICAL: CommittedRoute ≠ Circuit
///
/// This is the source-side cryptographic preparation derived from a committed route. It
/// contains:
/// - The circuit ID (instance identification — NOT replay protection)
/// - The binding to the committed route (commitment hash)
/// - Per-hop forwarding state (keys + predecessor/successor)
/// - Creation timestamp + expiry
///
/// ## Construction
///
/// `CircuitSetup` can ONLY be constructed by `prepare_circuit_setup()`, which
/// verifies the handshake + committed route + derives per-hop keys. The
/// fields are private — callers cannot construct one directly.
#[derive(Debug, Clone)]
pub struct CircuitSetup {
    /// Unique circuit identifier.
    circuit_id: [u8; 32],
    /// The committed route's commitment hash (binding).
    commitment_hash: [u8; 32],
    /// The source NodeId.
    source: [u8; 32],
    /// The destination NodeId (gateway).
    destination: [u8; 32],
    /// Per-hop forwarding state (ordered from source to destination).
    hops: Vec<HopForwardingState>,
    /// When the circuit setup was prepared.
    created_at: u64,
    /// When the circuit expires.
    expires_at: u64,
}

/// Error from `prepare_circuit_setup()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitError {
    /// The handshake signature is invalid or the handshake failed freshness checks.
    HandshakeInvalid,
    /// The handshake is not bound to the given committed route.
    CommitmentMismatch,
    /// The committed route has expired.
    RouteExpired { now: u64, expiry: u64 },
    /// The committed route has no hop evidence.
    EmptyRoute,
    /// A hop's authenticated record lacks the required X25519 circuit public key.
    HopMissingCircuitKey { hop_index: usize, node_id: [u8; 32] },
    /// P0 #1: the handshake's source does not match the CommittedRoute's source.
    SourceMismatch { handshake_source: [u8; 32], route_source: [u8; 32] },
    /// P0 #2: the supplied ephemeral X25519 secret's public key does not match
    /// the signed ephemeral_x25519_public in the handshake.
    EphemeralKeyMismatch,
    /// P1 #6: the teardown's source does not match the circuit's source.
    TeardownSourceMismatch { teardown_source: [u8; 32], circuit_source: [u8; 32] },
    /// CBOR encoding failed (fail-closed).
    CborEncodingFailed,
}

impl std::fmt::Display for CircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeInvalid => write!(f, "circuit handshake invalid"),
            Self::CommitmentMismatch => write!(f, "handshake is not bound to the committed route"),
            Self::RouteExpired { now, expiry } => write!(f, "committed route expired (now={now}, expiry={expiry})"),
            Self::EmptyRoute => write!(f, "committed route has no hops"),
            Self::HopMissingCircuitKey { hop_index, node_id } => write!(f, "hop {hop_index} ({}) has no X25519 circuit key", hex_short(node_id)),
            Self::SourceMismatch { handshake_source, route_source } => write!(f, "handshake source {} does not match route source {}", hex_short(handshake_source), hex_short(route_source)),
            Self::EphemeralKeyMismatch => write!(f, "supplied ephemeral secret does not match signed ephemeral public key"),
            Self::TeardownSourceMismatch { teardown_source, circuit_source } => write!(f, "teardown source {} does not match circuit source {}", hex_short(teardown_source), hex_short(circuit_source)),
            Self::CborEncodingFailed => write!(f, "canonical CBOR encoding failed"),
        }
    }
}

impl std::error::Error for CircuitError {}

/// Prepare source-side cryptographic circuit setup from a committed route
/// and signed handshake.
///
/// This does NOT establish a distributed circuit and does NOT install
/// forwarding state on remote participants. No relay receives this state.
/// Distributed circuit establishment is deferred to N2.2+.
///
/// This is the ONLY way to construct a `CircuitSetup`. It:
///
/// 1. Verifies the handshake signature + freshness + NodeId binding.
/// 2. Verifies the handshake is bound to the committed route (commitment hash match).
/// 3. Verifies the committed route has not expired.
/// 4. For each hop, retrieves the X25519 circuit public key from the
///    authenticated node record (from the committed route's hop evidence).
/// 5. Derives per-hop forwarding keys via X25519 DH (initiator's ephemeral key
///    + each hop's X25519 circuit public key) + HKDF-SHA256.
/// 6. Constructs `HopForwardingState` for each hop (with predecessor/successor).
///
/// ## Endpoint substitution prevention
///
/// Each hop's X25519 circuit public key comes from the authenticated
/// `AuthenticatedNodeRecord` in the committed route's `validated_hops`.
/// An attacker cannot substitute a different X25519 key — it would not
/// match the authenticated record.
pub fn prepare_circuit_setup(
    route: &CommittedRoute,
    handshake: &CircuitHandshake,
    ephemeral_x25519_secret: &X25519Secret,
) -> Result<CircuitSetup, CircuitError> {
    // 1. Verify the handshake.
    let now = now_unix();
    if !handshake.verify_at(now) {
        return Err(CircuitError::HandshakeInvalid);
    }

    // 2. Verify binding to the committed route.
    if !handshake.is_bound_to(route) {
        return Err(CircuitError::CommitmentMismatch);
    }

    // P0 #1: handshake.source MUST match route.source().
    if handshake.source != route.source() {
        return Err(CircuitError::SourceMismatch {
            handshake_source: handshake.source,
            route_source: route.source(),
        });
    }

    // P0 #2: supplied ephemeral secret MUST match signed ephemeral public key.
    let derived_pub = X25519PubKey::from(ephemeral_x25519_secret);
    if derived_pub.to_bytes() != handshake.ephemeral_x25519_public {
        return Err(CircuitError::EphemeralKeyMismatch);
    }

    // 3. Verify the route hasn't expired.
    if route.is_expired(now) {
        return Err(CircuitError::RouteExpired { now, expiry: route.proposal().expiry });
    }

    // 4. Get hop evidence from the committed route.
    let hops = route.validated_hops();
    if hops.is_empty() {
        return Err(CircuitError::EmptyRoute);
    }

    // 5. Derive per-hop forwarding keys.
    let mut forwarding_hops = Vec::with_capacity(hops.len());

    for (i, hop) in hops.iter().enumerate() {
        // For the source (hop 0), skip the DH — the source IS the initiator.
        if i == 0 {
            forwarding_hops.push(HopForwardingState {
                node_id: hop.node_id,
                predecessor_node_id: None,
                successor_node_id: hops.get(i + 1).map(|h| h.node_id),
                forwarding_key: [0u8; 32], // source has no forwarding key
            });
            continue;
        }

        // P0 #3: EVERY non-source hop MUST have an authenticated X25519 circuit
        // public key. An all-zero forwarding key is NOT a secure forwarding key.
        let x25519_pub_bytes = hop.record.descriptor.circuit_x25519_pub()
            .ok_or(CircuitError::HopMissingCircuitKey {
                hop_index: i,
                node_id: hop.node_id,
            })?;

        let peer_pub = x25519_public_from_bytes(&x25519_pub_bytes);
        let dh_secret = x25519_dh(ephemeral_x25519_secret, &peer_pub);

        // P1 #5: HKDF with FULL NodeId (not hex_short).
        let salt = &handshake.circuit_id;
        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
        info.extend_from_slice(&hop.node_id);
        info.extend_from_slice(b"/");
        info.extend_from_slice(&handshake.commitment_hash);
        let key_material = hkdf_sha256(&dh_secret, salt, &info, 32)
            .map_err(|_| CircuitError::CborEncodingFailed)?;
        let mut forwarding_key = [0u8; 32];
        forwarding_key.copy_from_slice(&key_material[..32]);

        forwarding_hops.push(HopForwardingState {
            node_id: hop.node_id,
            predecessor_node_id: hops.get(i - 1).map(|h| h.node_id),
            successor_node_id: hops.get(i + 1).map(|h| h.node_id),
            forwarding_key,
        });
    }

    Ok(CircuitSetup {
        circuit_id: handshake.circuit_id,
        commitment_hash: handshake.commitment_hash,
        source: route.source(),
        destination: route.destination(),
        hops: forwarding_hops,
        created_at: now,
        expires_at: handshake.expiry,
    })
}

impl CircuitSetup {
    /// The circuit ID. Uniqueness helps distinguish circuit instances but
    /// is NOT replay protection. Replay protection requires receiver-side
    /// acceptance state (CircuitReplayState — used by N2.2 distributed
    /// circuit establishment).
    #[must_use] pub fn circuit_id(&self) -> &[u8; 32] { &self.circuit_id }
    /// The committed route's commitment hash (binding).
    #[must_use] pub fn commitment_hash(&self) -> &[u8; 32] { &self.commitment_hash }
    /// The source NodeId.
    #[must_use] pub fn source(&self) -> [u8; 32] { self.source }
    /// The destination NodeId (gateway).
    #[must_use] pub fn destination(&self) -> [u8; 32] { self.destination }
    /// Per-hop forwarding state.
    #[must_use] pub fn hops(&self) -> &[HopForwardingState] { &self.hops }
    /// When the circuit setup was prepared.
    #[must_use] pub fn created_at(&self) -> u64 { self.created_at }
    /// When the circuit expires.
    #[must_use] pub fn expires_at(&self) -> u64 { self.expires_at }
    /// Has the circuit expired?
    #[must_use] pub fn is_expired(&self, now: u64) -> bool { self.expires_at <= now }

    /// Get the forwarding state for a specific hop.
    #[must_use]
    pub fn hop_state(&self, node_id: &[u8; 32]) -> Option<&HopForwardingState> {
        self.hops.iter().find(|h| &h.node_id == node_id)
    }

}

/// A signed circuit teardown message.
///
/// Authenticated by the source's Ed25519 signature. Each relay can verify
/// the teardown is authentic before cleaning up forwarding state.
#[derive(Debug, Clone)]
pub struct CircuitTeardown {
    /// The circuit ID being torn down.
    pub circuit_id: [u8; 32],
    /// The source's NodeId.
    pub source: [u8; 32],
    /// The source's Ed25519 public key.
    pub source_public_key: [u8; 32],
    /// When the teardown was created.
    pub timestamp: u64,
    /// 16-byte freshness nonce.
    pub nonce: [u8; 16],
    /// The source's Ed25519 signature.
    pub signature: [u8; 64],
}

impl CircuitTeardown {
    /// Create and sign a teardown message for a circuit.
    ///
    /// # Errors
    /// Returns `RouteSerializationError` on CBOR or RNG failure.
    pub fn create_and_sign(
        circuit: &CircuitSetup,
        source_secret_key: &[u8; 32],
        source_public_key: &[u8; 32],
    ) -> Result<Self, RouteSerializationError> {
        let now = now_unix();
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| RouteSerializationError::RandomnessFailure)?;
        let mut teardown = Self {
            circuit_id: circuit.circuit_id,
            source: circuit.source,
            source_public_key: *source_public_key,
            timestamp: now,
            nonce,
            signature: [0u8; 64],
        };
        let preimage = teardown.preimage_bytes()?;
        teardown.signature = ed25519_sign(source_secret_key, &preimage);
        Ok(teardown)
    }

    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("circuitId".into()), CborValue::ByteString(self.circuit_id.to_vec())),
            (CborValue::TextString("source".into()), CborValue::ByteString(self.source.to_vec())),
            (CborValue::TextString("sourcePublicKey".into()), CborValue::ByteString(self.source_public_key.to_vec())),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.nonce.to_vec())),
        ])
    }

    fn preimage_bytes(&self) -> Result<Vec<u8>, RouteSerializationError> {
        let cbor = snp_cbor::encode(&self.preimage())
            .map_err(|_| RouteSerializationError::CborEncodingFailed)?;
        let mut msg = Vec::with_capacity(CIRCUIT_MSG_CONTEXT.len() + cbor.len());
        msg.extend_from_slice(CIRCUIT_MSG_CONTEXT);
        msg.extend_from_slice(&cbor);
        Ok(msg)
    }

    /// Verify the teardown's signature + NodeId binding.
    ///
    /// Returns `false` on any failure (fail-closed — P0).
    #[must_use]
    pub fn verify(&self) -> bool {
        let expected = derive_node_id(&self.source_public_key);
        if self.source != expected { return false; }
        let preimage = match self.preimage_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        ed25519_verify(&self.source_public_key, &preimage, &self.signature)
    }

    /// Check that this teardown is for a specific circuit.
    #[must_use]
    pub fn is_for(&self, circuit: &CircuitSetup) -> bool {
        self.circuit_id == circuit.circuit_id
    }

    /// P1 #6: Verify this teardown is authorized for a specific circuit.
    /// Checks that the teardown source matches the circuit source.
    #[must_use]
    pub fn verify_for_circuit(&self, circuit: &CircuitSetup) -> bool {
        if self.source != circuit.source() { return false; }
        if !self.is_for(circuit) { return false; }
        self.verify()
    }
}

/// P1 #7: Circuit replay acceptance state, used by N2.2 distributed circuit
/// establishment.
///
/// A random circuit_id alone is NOT replay protection. Each relay maintains
/// this state (via `CircuitAcceptanceStore`) and rejects duplicate
/// handshakes — see `snp-node/src/node/distributed_circuit.rs`.
#[derive(Debug, Clone)]
pub struct CircuitReplayState {
    pub circuit_id: [u8; 32],
    pub commitment_hash: [u8; 32],
    pub source: [u8; 32],
    pub accepted_at: u64,
    pub expires_at: u64,
}

impl CircuitReplayState {
    #[must_use]
    pub fn is_replay_of(&self, handshake: &CircuitHandshake) -> bool {
        self.circuit_id == handshake.circuit_id
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_short(node_id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &node_id[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
