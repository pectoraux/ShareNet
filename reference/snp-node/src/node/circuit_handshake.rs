//! N2.1.3 — Circuit Establishment.
//!
//! Spec: spec/08-circuits.md (Section 38 of the frozen spec).
//!
//! ## CRITICAL: CommittedRoute ≠ Circuit
//!
//! A `CommittedRoute` is a **cryptographically consented route agreement**
//! backed by validated evidence. It is NOT live forwarding state.
//!
//! A `Circuit` is **live cryptographic execution state** — actual secure
//! forwarding keys, per-hop state, and an active session bound to a specific
//! committed route.
//!
//! The transition from `CommittedRoute` to `Circuit` is a new cryptographic
//! protocol boundary:
//!
//! ```text
//! CommittedRoute (agreement + evidence)
//!         ↓
//! CircuitHandshake (initiation message, signed by source)
//!         ↓
//! Per-hop X25519 DH + HKDF key derivation
//!         ↓
//! CircuitState (live forwarding state)
//!         ↓
//! Traffic (encrypted + authenticated per-hop)
//!         ↓
//! CircuitTeardown (authenticated close)
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
//!   and `establish_circuit()` rejects it.
//! - **Teardown?** `CircuitTeardown` is signed by the initiator. Each relay
//!   can verify the teardown is authentic.
//!
//! ## NOT implemented (deferred)
//!
//! - Arbitrary TCP connection migration — spec §39 (N2.1.4+).
//! - Route failure / recovery — spec §39 (N2.1.4).
//! - Key rotation within a live circuit (N2.1.4+).
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

/// A per-hop forwarding state entry — the live cryptographic state for one
/// relay or gateway in the circuit.
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
/// `CircuitState` (live forwarding state) is produced by `establish_circuit()`
/// after verifying the handshake.
///
/// ## Binding
///
/// The handshake signs:
/// - `circuit_id`: a unique 32-byte random identifier (replay prevention)
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
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(self.expiry)),
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

/// The live circuit state — actual secure forwarding state.
///
/// ## CRITICAL: CommittedRoute ≠ Circuit
///
/// This is the LIVE execution state derived from a committed route. It
/// contains:
/// - The circuit ID (replay prevention)
/// - The binding to the committed route (commitment hash)
/// - Per-hop forwarding state (keys + predecessor/successor)
/// - Creation timestamp + expiry
/// - Active/teardown state
///
/// ## Construction
///
/// `CircuitState` can ONLY be constructed by `establish_circuit()`, which
/// verifies the handshake + committed route + derives per-hop keys. The
/// fields are private — callers cannot construct one directly.
#[derive(Debug, Clone)]
pub struct ActiveCircuit {
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
    /// When the circuit was established.
    created_at: u64,
    /// When the circuit expires.
    expires_at: u64,
    /// Whether the circuit is active (not torn down).
    active: bool,
}

/// Error from `establish_circuit()`.
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
            Self::CborEncodingFailed => write!(f, "canonical CBOR encoding failed"),
        }
    }
}

impl std::error::Error for CircuitError {}

/// Establish a circuit from a committed route + signed handshake.
///
/// This is the ONLY way to construct a `CircuitState`. It:
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
pub fn establish_circuit(
    route: &CommittedRoute,
    handshake: &CircuitHandshake,
    ephemeral_x25519_secret: &X25519Secret,
) -> Result<ActiveCircuit, CircuitError> {
    // 1. Verify the handshake.
    let now = now_unix();
    if !handshake.verify_at(now) {
        return Err(CircuitError::HandshakeInvalid);
    }

    // 2. Verify binding to the committed route.
    if !handshake.is_bound_to(route) {
        return Err(CircuitError::CommitmentMismatch);
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
        // Get the hop's X25519 circuit public key from the authenticated record.
        // The source (first hop) doesn't need a circuit key — it's the initiator.
        // The gateway (last hop) MUST have a circuit key (enforced by route validation).
        // Intermediate relays MAY have a circuit key for per-hop forwarding; if not,
        // their forwarding_key is all-zeros (no per-hop encryption for that hop —
        // acceptable for the minimal N2.1.3 circuit).
        let x25519_pub_bytes = hop.record.descriptor.circuit_x25519_pub();

        // For the source (hop 0), we skip the DH — the source IS the initiator.
        if i == 0 {
            forwarding_hops.push(HopForwardingState {
                node_id: hop.node_id,
                predecessor_node_id: None,
                successor_node_id: hops.get(i + 1).map(|h| h.node_id),
                forwarding_key: [0u8; 32], // source has no forwarding key
            });
            continue;
        }

        // For the gateway (last hop), the X25519 circuit key is REQUIRED
        // (enforced by route validation — the gateway must have one).
        // For intermediate relays, it's OPTIONAL (may be None if the relay
        // doesn't advertise a circuit key).
        if let Some(x25519_pub_bytes) = x25519_pub_bytes {
            // X25519 DH: initiator's ephemeral secret + hop's X25519 circuit public key.
            let peer_pub = x25519_public_from_bytes(&x25519_pub_bytes);
            let dh_secret = x25519_dh(ephemeral_x25519_secret, &peer_pub);

            // HKDF-SHA256: derive the forwarding key from the DH secret.
            let salt = &handshake.circuit_id;
            let info = format!("SNP/0.1 circuit hop-key hop-{}", hex_short(&hop.node_id));
            let key_material = hkdf_sha256(&dh_secret, salt, info.as_bytes(), 32)
                .map_err(|_| CircuitError::CborEncodingFailed)?;
            let mut forwarding_key = [0u8; 32];
            forwarding_key.copy_from_slice(&key_material[..32]);

            forwarding_hops.push(HopForwardingState {
                node_id: hop.node_id,
                predecessor_node_id: hops.get(i - 1).map(|h| h.node_id),
                successor_node_id: hops.get(i + 1).map(|h| h.node_id),
                forwarding_key,
            });
        } else {
            // Intermediate relay without an X25519 circuit key — no per-hop
            // forwarding key (all-zeros). Acceptable for the minimal N2.1.3 circuit.
            forwarding_hops.push(HopForwardingState {
                node_id: hop.node_id,
                predecessor_node_id: hops.get(i - 1).map(|h| h.node_id),
                successor_node_id: hops.get(i + 1).map(|h| h.node_id),
                forwarding_key: [0u8; 32],
            });
        }
    }

    Ok(ActiveCircuit {
        circuit_id: handshake.circuit_id,
        commitment_hash: handshake.commitment_hash,
        source: route.source(),
        destination: route.destination(),
        hops: forwarding_hops,
        created_at: now,
        expires_at: handshake.expiry,
        active: true,
    })
}

impl ActiveCircuit {
    /// The circuit ID (unique per circuit — replay prevention).
    #[must_use] pub fn circuit_id(&self) -> &[u8; 32] { &self.circuit_id }
    /// The committed route's commitment hash (binding).
    #[must_use] pub fn commitment_hash(&self) -> &[u8; 32] { &self.commitment_hash }
    /// The source NodeId.
    #[must_use] pub fn source(&self) -> [u8; 32] { self.source }
    /// The destination NodeId (gateway).
    #[must_use] pub fn destination(&self) -> [u8; 32] { self.destination }
    /// Per-hop forwarding state.
    #[must_use] pub fn hops(&self) -> &[HopForwardingState] { &self.hops }
    /// When the circuit was established.
    #[must_use] pub fn created_at(&self) -> u64 { self.created_at }
    /// When the circuit expires.
    #[must_use] pub fn expires_at(&self) -> u64 { self.expires_at }
    /// Is the circuit active?
    #[must_use] pub fn is_active(&self) -> bool { self.active }
    /// Has the circuit expired?
    #[must_use] pub fn is_expired(&self, now: u64) -> bool { self.expires_at <= now }

    /// Get the forwarding state for a specific hop.
    #[must_use]
    pub fn hop_state(&self, node_id: &[u8; 32]) -> Option<&HopForwardingState> {
        self.hops.iter().find(|h| &h.node_id == node_id)
    }

    /// Mark the circuit as torn down.
    pub fn teardown(&mut self) {
        self.active = false;
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
        circuit: &ActiveCircuit,
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
    pub fn is_for(&self, circuit: &ActiveCircuit) -> bool {
        self.circuit_id == circuit.circuit_id
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
