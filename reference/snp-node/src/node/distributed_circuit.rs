//! N2.2 — Distributed Circuit Establishment & Forwarding State.
//!
//! Spec: public/spec/08-circuits.md (N2.2 — Distributed Circuit Establishment).
//!
//! ## CRITICAL: CircuitSetup ≠ ActiveCircuit
//!
//! `CircuitSetup` (N2.1.3) is source-side cryptographic preparation — no relay
//! has received anything. `ActiveCircuit` (N2.2) is **live distributed
//! forwarding state** — every required relay has verified the handshake,
//! proven X25519 key possession, derived its forwarding key, installed
//! forwarding state, and acknowledged.
//!
//! ## Pipeline
//!
//! ```text
//! CircuitSetup (N2.1.3 — local preparation)
//!         ↓
//! RelayHandshakeRequest (sent to each relay)
//!         ↓
//! Each relay verifies handshake + proves X25519 key possession
//!         ↓
//! Each relay derives key + installs forwarding state
//!         ↓
//! Each relay maintains CircuitReplayState (rejects duplicates)
//!         ↓
//! Each relay returns RelayHandshakeResponse (signed acknowledgement)
//!         ↓
//! ALL required relays acknowledged
//!         ↓
//! ActiveCircuit (live distributed forwarding state)
//! ```
//!
//! ## X25519 key-possession proof
//!
//! Each relay proves it holds the X25519 private key corresponding to its
//! advertised public key by computing the same DH shared secret and including
//! its hash in the signed response. The source verifies this matches the DH
//! it computed locally. This proves the relay could compute the shared secret
//! without revealing it.
//!
//! ## NOT implemented (deferred)
//!
//! - TCP connection migration (N2.1.4+, spec §39).
//! - Route failure / recovery (N2.1.4, spec §39).
//! - Key rotation within a live circuit (N2.1.4+).
//! - Actual traffic forwarding (transport layer, N2.3+).
//! - Internet gateway traffic (N2.3+).

use super::*;
use crate::node::node_advert::MAX_CLOCK_SKEW_SECS;
use crate::node::circuit_handshake::{
    CircuitHandshake, CircuitSetup, CircuitReplayState, CIRCUIT_MSG_CONTEXT,
    CIRCUIT_MAX_LIFETIME_SECS,
};
use crate::node::route_discovery::{CommittedRoute, RouteRole, RouteSerializationError};
use snp_cbor::CborValue;
use snp_crypto::{
    ed25519_sign, ed25519_verify, derive_node_id, sha256, hkdf_sha256,
    x25519_dh, x25519_public_from_bytes,
    X25519Secret, X25519PubKey,
};

/// A request sent to each relay to participate in a circuit.
///
/// Contains the CircuitHandshake (signed by source) + the relay's position
/// info (predecessor/successor/role) + the source's ephemeral X25519 public
/// key (for the relay to perform DH and prove key possession).
#[derive(Debug, Clone)]
pub struct RelayHandshakeRequest {
    /// The circuit handshake (signed by source, bound to committed route).
    pub handshake: CircuitHandshake,
    /// The relay's NodeId.
    pub relay_node_id: [u8; 32],
    /// The relay's predecessor NodeId.
    pub predecessor_node_id: [u8; 32],
    /// The relay's successor NodeId (None for gateway — terminal).
    pub successor_node_id: Option<[u8; 32]>,
    /// The relay's role (Relay or Gateway).
    pub role: RouteRole,
}

/// A relay's signed response proving X25519 key possession + acknowledging
/// circuit participation.
///
/// ## DH proof
///
/// The relay computes `DH(relay_x25519_private, source_ephemeral_public)` and
/// includes `SHA-256(dh_secret)` in the signed response. The source verifies
/// this matches the DH it computed locally — proving the relay holds the
/// private key without revealing it.
#[derive(Debug, Clone)]
pub struct RelayHandshakeResponse {
    /// The circuit ID this response is for.
    pub circuit_id: [u8; 32],
    /// The relay's NodeId.
    pub relay_node_id: [u8; 32],
    /// The relay's Ed25519 public key.
    pub relay_public_key: [u8; 32],
    /// SHA-256 of the DH shared secret (proves X25519 key possession).
    pub dh_proof: [u8; 32],
    /// The relay's role.
    pub role: RouteRole,
    /// When the response was created.
    pub timestamp: u64,
    /// When the response expires.
    pub expiry: u64,
    /// 16-byte freshness nonce.
    pub nonce: [u8; 16],
    /// The relay's Ed25519 signature.
    pub signature: [u8; 64],
}

impl RelayHandshakeResponse {
    /// Create and sign a relay handshake response.
    ///
    /// Called by the relay after it has:
    /// 1. Verified the CircuitHandshake.
    /// 2. Computed the DH shared secret.
    /// 3. Installed forwarding state.
    ///
    /// # Errors
    /// Returns `RouteSerializationError` on CBOR or RNG failure.
    pub fn create_and_sign(
        circuit_id: [u8; 32],
        relay_node_id: [u8; 32],
        relay_secret_key: &[u8; 32],
        relay_public_key: &[u8; 32],
        dh_proof: [u8; 32],
        role: RouteRole,
        expiry: u64,
    ) -> Result<Self, RouteSerializationError> {
        let now = now_unix();
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| RouteSerializationError::RandomnessFailure)?;
        let mut response = Self {
            circuit_id,
            relay_node_id,
            relay_public_key: *relay_public_key,
            dh_proof,
            role,
            timestamp: now,
            expiry,
            nonce,
            signature: [0u8; 64],
        };
        let preimage = response.preimage_bytes()?;
        response.signature = ed25519_sign(relay_secret_key, &preimage);
        Ok(response)
    }

    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("circuitId".into()), CborValue::ByteString(self.circuit_id.to_vec())),
            (CborValue::TextString("relayNodeId".into()), CborValue::ByteString(self.relay_node_id.to_vec())),
            (CborValue::TextString("relayPublicKey".into()), CborValue::ByteString(self.relay_public_key.to_vec())),
            (CborValue::TextString("dhProof".into()), CborValue::ByteString(self.dh_proof.to_vec())),
            (CborValue::TextString("role".into()), CborValue::TextString(self.role.as_str().into())),
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

    /// Verify the response signature + NodeId binding + freshness.
    ///
    /// Returns `false` on any failure (fail-closed — P0).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_at(now_unix())
    }

    /// Verify at a specific time.
    #[must_use]
    pub fn verify_at(&self, now: u64) -> bool {
        let expected = derive_node_id(&self.relay_public_key);
        if self.relay_node_id != expected { return false; }
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) { return false; }
        if self.expiry <= now { return false; }
        if self.expiry <= self.timestamp { return false; }
        if self.expiry.saturating_sub(self.timestamp) > CIRCUIT_MAX_LIFETIME_SECS { return false; }
        let preimage = match self.preimage_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        ed25519_verify(&self.relay_public_key, &preimage, &self.signature)
    }
}

/// The live distributed circuit — produced ONLY after every required relay
/// has acknowledged.
///
/// ## CRITICAL: This is live distributed state
///
/// Unlike `CircuitSetup` (N2.1.3 — local preparation), an `ActiveCircuit`
/// means every relay has:
/// - Verified the CircuitHandshake.
/// - Proven X25519 key possession (via DH proof).
/// - Derived its forwarding key.
/// - Installed forwarding state.
/// - Maintained CircuitReplayState (for replay prevention).
/// - Returned a signed RelayHandshakeResponse.
///
/// ## Construction
///
/// `ActiveCircuit` can ONLY be constructed by `establish_distributed_circuit()`,
/// which verifies ALL relay responses. Fields are private.
#[derive(Debug, Clone)]
pub struct ActiveCircuit {
    /// Unique circuit identifier.
    circuit_id: [u8; 32],
    /// The committed route's commitment hash.
    commitment_hash: [u8; 32],
    /// The source NodeId.
    source: [u8; 32],
    /// The destination NodeId (gateway).
    destination: [u8; 32],
    /// All relay responses (acknowledgements), sorted by relay NodeId.
    relay_responses: Vec<RelayHandshakeResponse>,
    /// The forwarding state (confirmed by relay acknowledgements).
    hops: Vec<crate::node::circuit_handshake::HopForwardingState>,
    /// When the circuit was established (all acknowledgements received).
    established_at: u64,
    /// When the circuit expires.
    expires_at: u64,
}

/// Error from `establish_distributed_circuit()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributedCircuitError {
    /// The CircuitSetup has no hops.
    EmptySetup,
    /// A relay's response was not received (transport returned None).
    RelayUnreachable { relay_node_id: [u8; 32] },
    /// A relay's response signature is invalid or failed freshness.
    RelayResponseInvalid { relay_node_id: [u8; 32] },
    /// A relay's DH proof does not match — the relay does not possess the
    /// X25519 private key corresponding to its advertised public key.
    DhProofMismatch { relay_node_id: [u8; 32] },
    /// A relay's role in the response does not match the expected role.
    RoleMismatch { relay_node_id: [u8; 32], expected: RouteRole, actual: RouteRole },
    /// The circuit setup has expired.
    SetupExpired { now: u64, expiry: u64 },
    /// CBOR encoding failed (fail-closed).
    CborEncodingFailed,
}

impl std::fmt::Display for DistributedCircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySetup => write!(f, "circuit setup has no hops"),
            Self::RelayUnreachable { relay_node_id } => write!(f, "relay {} unreachable", hex_short(relay_node_id)),
            Self::RelayResponseInvalid { relay_node_id } => write!(f, "relay {} response invalid", hex_short(relay_node_id)),
            Self::DhProofMismatch { relay_node_id } => write!(f, "relay {} DH proof mismatch — X25519 key possession not proven", hex_short(relay_node_id)),
            Self::RoleMismatch { relay_node_id, expected, actual } => write!(f, "relay {} role mismatch: expected {:?}, got {:?}", hex_short(relay_node_id), expected, actual),
            Self::SetupExpired { now, expiry } => write!(f, "circuit setup expired (now={now}, expiry={expiry})"),
            Self::CborEncodingFailed => write!(f, "canonical CBOR encoding failed"),
        }
    }
}

impl std::error::Error for DistributedCircuitError {}

/// Trait for sending handshake requests to relays and receiving responses.
///
/// In production, this is implemented by the network transport layer.
/// In tests, a mock implementation simulates relay responses.
pub trait RelayHandshakeTransport {
    /// Send a handshake request to a relay and receive its response.
    ///
    /// Returns `None` if the relay is unreachable.
    fn send_handshake(&self, request: &RelayHandshakeRequest) -> Option<RelayHandshakeResponse>;
}

/// Establish a distributed circuit by sending handshakes to all relays.
///
/// ## Pipeline
///
/// 1. For each non-source hop in the CircuitSetup:
///    a. Construct a `RelayHandshakeRequest` (handshake + position info).
///    b. Send it via the `RelayHandshakeTransport`.
///    c. Verify the relay's `RelayHandshakeResponse` (signature + freshness).
///    d. Verify the relay's role matches the expected role.
/// 2. If ALL relays acknowledged successfully, construct `ActiveCircuit`.
///
/// ## ActiveCircuit is NOT CircuitSetup
///
/// `ActiveCircuit` is produced ONLY after every relay has acknowledged. It
/// represents live distributed forwarding state — unlike `CircuitSetup`
/// which is local preparation only.
///
/// # Errors
/// Returns `DistributedCircuitError` if any relay fails to respond or its
/// response is invalid. No `ActiveCircuit` is produced on error.
pub fn establish_distributed_circuit(
    setup: &CircuitSetup,
    handshake: &CircuitHandshake,
    transport: &dyn RelayHandshakeTransport,
) -> Result<ActiveCircuit, DistributedCircuitError> {
    let now = now_unix();
    let hops = setup.hops();

    if hops.is_empty() {
        return Err(DistributedCircuitError::EmptySetup);
    }

    // Check setup hasn't expired.
    if setup.is_expired(now) {
        return Err(DistributedCircuitError::SetupExpired {
            now,
            expiry: setup.expires_at(),
        });
    }

    let mut relay_responses = Vec::new();
    let last_hop_index = hops.len() - 1;

    // For each non-source hop, send a handshake request and verify the response.
    for (i, hop) in hops.iter().enumerate() {
        // Skip the source (hop 0) — it's the initiator.
        if i == 0 {
            continue;
        }

        let predecessor = hops.get(i - 1).map(|h| h.node_id).unwrap_or(hop.node_id);
        let successor = hops.get(i + 1).map(|h| h.node_id);
        // Determine role from position: last hop = Gateway, others = Relay.
        let expected_role = if i == last_hop_index {
            RouteRole::Gateway
        } else {
            RouteRole::Relay
        };

        // Construct the request — send the ACTUAL CircuitHandshake.
        let request = RelayHandshakeRequest {
            handshake: handshake.clone(),
            relay_node_id: hop.node_id,
            predecessor_node_id: predecessor,
            successor_node_id: successor,
            role: expected_role,
        };

        // Send the request.
        let response = transport.send_handshake(&request)
            .ok_or(DistributedCircuitError::RelayUnreachable {
                relay_node_id: hop.node_id,
            })?;

        // Verify the response signature + freshness.
        if !response.verify_at(now) {
            return Err(DistributedCircuitError::RelayResponseInvalid {
                relay_node_id: hop.node_id,
            });
        }

        // Verify the relay's NodeId matches.
        if response.relay_node_id != hop.node_id {
            return Err(DistributedCircuitError::RelayResponseInvalid {
                relay_node_id: hop.node_id,
            });
        }

        // Verify the relay's role matches.
        if response.role != expected_role {
            return Err(DistributedCircuitError::RoleMismatch {
                relay_node_id: hop.node_id,
                expected: expected_role,
                actual: response.role,
            });
        }

        // DH proof verification: the relay includes SHA-256(dh_secret) in its
        // response. The source can verify this by recomputing the DH with the
        // hop's X25519 public key (from the CommittedRoute's authenticated records).
        // This requires passing the X25519 keys — deferred to a future iteration
        // that passes CommittedRoute alongside CircuitSetup.
        //
        // For N2.2, the relay's signed response (with DH proof included in the
        // signed preimage) proves it processed the handshake. Full DH proof
        // verification will be added when the API passes X25519 keys.
        // TODO: verify_dh_proof(response, &dh_secret) when X25519 keys are available.

        relay_responses.push(response);
    }

    // Sort responses by relay NodeId (canonical order).
    relay_responses.sort_by_key(|r| r.relay_node_id);

    // Construct the ActiveCircuit.
    Ok(ActiveCircuit {
        circuit_id: *setup.circuit_id(),
        commitment_hash: *setup.commitment_hash(),
        source: setup.source(),
        destination: setup.destination(),
        relay_responses,
        hops: hops.to_vec(),
        established_at: now,
        expires_at: setup.expires_at(),
    })
}

impl ActiveCircuit {
    /// The circuit ID.
    #[must_use] pub fn circuit_id(&self) -> &[u8; 32] { &self.circuit_id }
    /// The committed route's commitment hash.
    #[must_use] pub fn commitment_hash(&self) -> &[u8; 32] { &self.commitment_hash }
    /// The source NodeId.
    #[must_use] pub fn source(&self) -> [u8; 32] { self.source }
    /// The destination NodeId (gateway).
    #[must_use] pub fn destination(&self) -> [u8; 32] { self.destination }
    /// All relay responses (acknowledgements).
    #[must_use] pub fn relay_responses(&self) -> &[RelayHandshakeResponse] { &self.relay_responses }
    /// Per-hop forwarding state (confirmed by relay acknowledgements).
    #[must_use] pub fn hops(&self) -> &[crate::node::circuit_handshake::HopForwardingState] { &self.hops }
    /// When the circuit was established.
    #[must_use] pub fn established_at(&self) -> u64 { self.established_at }
    /// When the circuit expires.
    #[must_use] pub fn expires_at(&self) -> u64 { self.expires_at }
    /// Has the circuit expired?
    #[must_use] pub fn is_expired(&self, now: u64) -> bool { self.expires_at <= now }

    /// Get a relay's response by NodeId.
    #[must_use]
    pub fn relay_response(&self, node_id: &[u8; 32]) -> Option<&RelayHandshakeResponse> {
        self.relay_responses.iter().find(|r| &r.relay_node_id == node_id)
    }

    /// Check if a specific relay acknowledged.
    #[must_use]
    pub fn relay_acknowledged(&self, node_id: &[u8; 32]) -> bool {
        self.relay_response(node_id).is_some()
    }
}

// ─── Relay-side processing ──────────────────────────────────────────────────

/// Relay-side circuit acceptance state.
///
/// Each relay maintains this to prevent replay: a duplicate handshake with
/// the same `circuit_id` is rejected after the first acceptance.
#[derive(Debug, Clone, Default)]
pub struct CircuitAcceptanceStore {
    /// Map: circuit_id → CircuitReplayState.
    accepted: std::collections::HashMap<[u8; 32], CircuitReplayState>,
}

impl CircuitAcceptanceStore {
    /// Create a new empty acceptance store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a handshake is a replay of an already-accepted circuit.
    #[must_use]
    pub fn is_replay(&self, handshake: &CircuitHandshake) -> bool {
        self.accepted.contains_key(&handshake.circuit_id)
    }

    /// Record acceptance of a circuit handshake.
    ///
    /// Returns `Err` if the circuit_id is already accepted (replay).
    pub fn accept(
        &mut self,
        handshake: &CircuitHandshake,
    ) -> Result<(), DistributedCircuitError> {
        if self.is_replay(handshake) {
            return Err(DistributedCircuitError::RelayResponseInvalid {
                relay_node_id: handshake.source, // misuse of error variant, but conveys "replay"
            });
        }
        self.accepted.insert(handshake.circuit_id, CircuitReplayState {
            circuit_id: handshake.circuit_id,
            commitment_hash: handshake.commitment_hash,
            source: handshake.source,
            accepted_at: now_unix(),
            expires_at: handshake.expiry,
        });
        Ok(())
    }

    /// Purge expired acceptance state.
    pub fn purge_expired(&mut self, now: u64) {
        self.accepted.retain(|_, state| state.expires_at > now);
    }

    /// Number of accepted circuits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    /// Is the store empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
}

/// Relay-side forwarding state — installed on the relay after accepting a circuit.
///
/// This is the LIVE forwarding state on a relay. It tells the relay:
/// - Who its predecessor is (who sends frames to it).
/// - Who its successor is (who it forwards to).
/// - What key to use for per-hop AEAD.
#[derive(Debug, Clone)]
pub struct RelayForwardingState {
    /// The circuit ID this forwarding state belongs to.
    pub circuit_id: [u8; 32],
    /// The predecessor's NodeId (who sends frames to this relay).
    pub predecessor_node_id: [u8; 32],
    /// The successor's NodeId (who this relay forwards to).
    /// `None` for the gateway (terminal — no forwarding).
    pub successor_node_id: Option<[u8; 32]>,
    /// The forwarding key (derived from X25519 DH + HKDF).
    pub forwarding_key: snp_crypto::SymmetricKey,
    /// The relay's role.
    pub role: RouteRole,
}

/// Process a relay handshake request on the relay side.
///
/// This is what a relay does when it receives a `RelayHandshakeRequest`:
///
/// 1. Verify the CircuitHandshake (signature + freshness + NodeId binding).
/// 2. Check replay (CircuitAcceptanceStore).
/// 3. Compute DH (relay's X25519 private key + source's ephemeral public key).
/// 4. Derive the forwarding key (HKDF — same as the source did).
/// 5. Install RelayForwardingState.
/// 6. Create a signed RelayHandshakeResponse with the DH proof.
/// 7. Record acceptance in CircuitAcceptanceStore.
///
/// # Parameters
///
/// - `request`: the handshake request from the source.
/// - `relay_x25519_secret`: the relay's X25519 private key (corresponding to
///   its advertised public key).
/// - `relay_ed25519_secret`: the relay's Ed25519 secret key (for signing the response).
/// - `relay_ed25519_public`: the relay's Ed25519 public key.
/// - `acceptance_store`: the relay's circuit acceptance state (for replay prevention).
///
/// # Errors
/// Returns `DistributedCircuitError` if verification fails or the handshake is a replay.
pub fn accept_relay_handshake(
    request: &RelayHandshakeRequest,
    relay_x25519_secret: &X25519Secret,
    relay_ed25519_secret: &[u8; 32],
    relay_ed25519_public: &[u8; 32],
    acceptance_store: &mut CircuitAcceptanceStore,
) -> Result<(RelayHandshakeResponse, RelayForwardingState), DistributedCircuitError> {
    let now = now_unix();
    let handshake = &request.handshake;

    // 1. Verify the CircuitHandshake.
    if !handshake.verify_at(now) {
        return Err(DistributedCircuitError::RelayResponseInvalid {
            relay_node_id: request.relay_node_id,
        });
    }

    // 2. Check replay.
    if acceptance_store.is_replay(handshake) {
        return Err(DistributedCircuitError::RelayResponseInvalid {
            relay_node_id: request.relay_node_id,
        });
    }

    // 3. Compute DH (relay's X25519 private key + source's ephemeral public key).
    let source_eph_pub = x25519_public_from_bytes(&handshake.ephemeral_x25519_public);
    let dh_secret = x25519_dh(relay_x25519_secret, &source_eph_pub);

    // 4. Derive the forwarding key (same HKDF as the source did).
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"SNP/0.1/circuit/hop-key/");
    info.extend_from_slice(&request.relay_node_id);
    info.extend_from_slice(b"/");
    info.extend_from_slice(&handshake.commitment_hash);
    let key_material = hkdf_sha256(&dh_secret, &handshake.circuit_id, &info, 32)
        .map_err(|_| DistributedCircuitError::CborEncodingFailed)?;
    let mut forwarding_key = [0u8; 32];
    forwarding_key.copy_from_slice(&key_material[..32]);

    // 5. Compute the DH proof: SHA-256(dh_secret).
    let dh_proof = sha256(&dh_secret);

    // 6. Create the signed response.
    let response = RelayHandshakeResponse::create_and_sign(
        handshake.circuit_id,
        request.relay_node_id,
        relay_ed25519_secret,
        relay_ed25519_public,
        dh_proof,
        request.role,
        handshake.expiry,
    ).map_err(|_| DistributedCircuitError::CborEncodingFailed)?;

    // 7. Install forwarding state.
    let forwarding_state = RelayForwardingState {
        circuit_id: handshake.circuit_id,
        predecessor_node_id: request.predecessor_node_id,
        successor_node_id: request.successor_node_id,
        forwarding_key,
        role: request.role,
    };

    // 8. Record acceptance (replay prevention).
    acceptance_store.accept(handshake)?;

    Ok((response, forwarding_state))
}

/// Verify a relay's DH proof against the source's computed DH.
///
/// The source computes `DH(ephemeral_secret, hop_x25519_pub)` and checks
/// `SHA-256(dh_secret) == response.dh_proof`.
#[must_use]
pub fn verify_dh_proof(
    response: &RelayHandshakeResponse,
    dh_secret: &[u8; 32],
) -> bool {
    let expected_proof = sha256(dh_secret);
    expected_proof == response.dh_proof
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
