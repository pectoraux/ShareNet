//! Extracted from node/mod.rs for N2.0.4 Gate E (node decomposition).
use super::*;

use getrandom;
// ─── N2.0.2: PeerSession, GatewayDirectory, Route, Circuit state machines ───
//
// This block adds the N2.0.2 protocol-session objects defined in the task
// spec (Phases 4 and 5). These structures are the production-ready
// state-machine layer that sits ABOVE the SNP-IK/0.1 handshake and the
// circuit DH. They do NOT replace the legacy `Circuit` struct (which is
// kept for backward compat with N2.0/N2.0.1); they provide the new
// production API.
//
// The state machines are pure data + transition logic — they do NOT perform
// any I/O. The Node methods that drive them (serve_gateway_with_handshake,
// send_request_with_handshake, etc.) are responsible for the actual TCP
// and handshake I/O.

/// The state of a [`PeerSession`].
///
/// The legal transitions are:
///   New → Handshaking → Established → (Degraded ↔ Established)* → Closing → Closed
///
/// Any other transition is rejected by [`PeerSession::transition_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSessionState {
    /// The session has been allocated but the SNP-IK/0.1 handshake has not
    /// yet started.
    New,
    /// The SNP-IK/0.1 handshake is in progress (the first message has been
    /// sent or received).
    Handshaking,
    /// The handshake completed; the session has fresh directional link keys
    /// and is carrying frames.
    Established,
    /// The session is alive but has experienced a transient failure (e.g. an
    /// AEAD decryption failure on a single frame, or a timeout). The session
    /// MAY recover back to `Established`, or it MAY transition to `Closing`.
    Degraded,
    /// The session is being shut down gracefully. No new frames will be
    /// accepted; in-flight frames are being drained.
    Closing,
    /// The session is fully closed. The TCP connection has been dropped. The
    /// session is no longer usable.
    Closed,
}

/// A peer session — the result of a successful (or in-progress) SNP-IK/0.1
/// handshake with a specific peer node.
///
/// The session holds:
/// - The peer's authenticated NodeId + Ed25519 public key.
/// - A `session_id` (the SNP-IK/0.1 transcript hash analogue — see
///   [`snp_link::HandshakeResult::session_id`]).
/// - The directional `send_key` / `recv_key` for frame AEAD.
/// - The current `state` of the session state machine.
/// - Timestamps for lifecycle management (`created_at`, `last_activity`).
#[derive(Debug, Clone)]
pub struct PeerSession {
    /// The peer's NodeId (`SHA-256("SNP/0.1 node\0" || peer_public_key)`).
    pub peer_node_id: [u8; 32],
    /// The peer's Ed25519 public key (32 bytes, raw — invariant I3).
    pub peer_public_key: [u8; 32],
    /// The SNP-IK/0.1 session id (transcript hash analogue). Fresh per
    /// handshake (differs across sessions even between the same pair).
    pub session_id: [u8; 32],
    /// The current state of the session.
    pub state: PeerSessionState,
    /// The directional AEAD send key (encrypt outbound frames).
    pub send_key: snp_crypto::SymmetricKey,
    /// The directional AEAD recv key (decrypt inbound frames).
    pub recv_key: snp_crypto::SymmetricKey,
    /// When the session was created (unix seconds).
    pub created_at: u64,
    /// When the session last saw activity (unix seconds).
    pub last_activity: u64,
}

impl PeerSession {
    /// Get the session state.
    #[must_use]
    pub fn state(&self) -> PeerSessionState {
        self.state
    }

    /// Construct a new `PeerSession` in the `New` state. The `send_key` and
    /// `recv_key` are zeroed — they are populated when the session transitions
    /// to `Established` (via [`PeerSession::establish`]).
    #[must_use]
    pub fn new(peer_node_id: [u8; 32], peer_public_key: [u8; 32]) -> Self {
        let now = now_unix();
        Self {
            peer_node_id,
            peer_public_key,
            session_id: [0u8; 32],
            state: PeerSessionState::New,
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            created_at: now,
            last_activity: now,
        }
    }

    /// Construct a `PeerSession` in the `Established` state from a successful
    /// SNP-IK/0.1 handshake result.
    #[must_use]
    pub fn from_handshake(handshake: &snp_link::HandshakeResult) -> Self {
        let now = now_unix();
        Self {
            peer_node_id: handshake.peer_node_id,
            peer_public_key: handshake.peer_public_key,
            session_id: handshake.session_id,
            state: PeerSessionState::Established,
            send_key: handshake.link_keys.send_key,
            recv_key: handshake.link_keys.recv_key,
            created_at: now,
            last_activity: now,
        }
    }

    /// Transition the session to a new state. Returns `Ok(())` if the
    /// transition is legal, or `Err(NodeError)` describing the illegal
    /// transition.
    ///
    /// Legal transitions (per [`PeerSessionState`] docs):
    ///   New → Handshaking → Established → (Degraded ↔ Established)* → Closing → Closed
    ///
    /// Also: any state → Closed (forced close), New → Closed (abandon before
    /// handshake), Handshaking → Closed (handshake failed).
    pub fn transition_to(&mut self, new_state: PeerSessionState) -> NodeResult<()> {
        use PeerSessionState::*;
        let allowed = matches!(
            (self.state, new_state),
            (New, Handshaking)
                | (New, Closed)
                | (Handshaking, Established)
                | (Handshaking, Closed)
                | (Established, Degraded)
                | (Established, Closing)
                | (Established, Closed)
                | (Degraded, Established)
                | (Degraded, Closing)
                | (Degraded, Closed)
                | (Closing, Closed)
                | (Closed, Closed)
        );
        if !allowed {
            return Err(NodeError::Other(format!(
                "illegal PeerSession transition: {:?} → {:?}",
                self.state, new_state
            )));
        }
        self.state = new_state;
        self.last_activity = now_unix();
        Ok(())
    }

    /// Convenience: mark the session as handshaking.
    pub fn begin_handshake(&mut self) -> NodeResult<()> {
        self.transition_to(PeerSessionState::Handshaking)
    }

    /// Convenience: mark the session as established (after a successful
    /// handshake). Updates the keys + session_id from the handshake result.
    pub fn establish(&mut self, handshake: &snp_link::HandshakeResult) -> NodeResult<()> {
        // Verify the handshake result is for the expected peer.
        if handshake.peer_node_id != self.peer_node_id {
            return Err(NodeError::Other(format!(
                "PeerSession::establish: handshake peer_node_id {} does not match session peer_node_id {}",
                hex_short(&handshake.peer_node_id),
                hex_short(&self.peer_node_id)
            )));
        }
        self.session_id = handshake.session_id;
        self.send_key = handshake.link_keys.send_key;
        self.recv_key = handshake.link_keys.recv_key;
        self.transition_to(PeerSessionState::Established)
    }

    /// Convenience: mark the session as closing (graceful shutdown).
    pub fn close(&mut self) -> NodeResult<()> {
        self.transition_to(PeerSessionState::Closing)?;
        self.transition_to(PeerSessionState::Closed)
    }

    /// Returns `true` if the session is in a state that can carry frames
    /// (`Established` or `Degraded`).
    #[must_use]
    pub fn is_alive(&self) -> bool {
        matches!(
            self.state,
            PeerSessionState::Established | PeerSessionState::Degraded
        )
    }
}

// ─── GatewayDirectory (Phase 4) ──────────────────────────────────────────────

/// The state of a [`GatewayDirectoryEntry`] — the lifecycle of a gateway
/// from discovery to active use to expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    /// The gateway has been discovered (advertisement received and
    /// signature-verified) but has not yet been reached via a SNP-IK/0.1
    /// handshake.
    Discovered,
    /// The gateway has been reached via a successful SNP-IK/0.1 handshake —
    /// its advertised identity matches its handshake-authenticated identity.
    Verified,
    /// The gateway is the currently-selected gateway for outgoing requests.
    Active,
    /// The gateway has been marked unreachable (recent handshake or request
    /// failed). It MAY be retried later.
    Unreachable,
    /// The gateway's advertisement has expired. It MUST be re-discovered
    /// before use.
    Expired,
}

/// An entry in the [`GatewayDirectory`]. Combines the signed
/// [`GatewayAdvertisement`] with runtime-observed metadata (latency,
/// reliability, state).
#[derive(Debug, Clone)]
pub struct GatewayDirectoryEntry {
    /// The signed advertisement (verified at discovery time).
    pub advertisement: GatewayAdvertisement,
    /// When this entry was last confirmed (unix seconds). Updated on every
    /// successful handshake or request.
    pub last_seen: u64,
    /// The most recently observed round-trip latency (unix microseconds), if
    /// any. `None` until the first request completes.
    pub observed_latency: Option<u64>,
    /// The observed reliability (fraction of successful requests in the
    /// recent window, `[0.0, 1.0]`). `None` until the first request completes.
    pub observed_reliability: Option<f64>,
    /// The current state of this entry.
    pub state: GatewayState,
}

impl GatewayDirectoryEntry {
    /// Get the gateway state.
    #[must_use]
    pub fn state(&self) -> GatewayState {
        self.state
    }
}

/// A directory of known gateways, populated by [`DiscoveryProvider`]s and
/// used by [`GatewaySelector`]s to choose a gateway for outgoing requests.
///
/// The directory is a `Vec<GatewayDirectoryEntry>`; lookups by NodeId are
/// linear (the directory is small — typically tens of entries).
#[derive(Debug, Clone, Default)]
pub struct GatewayDirectory {
    entries: Vec<GatewayDirectoryEntry>,
}

impl GatewayDirectory {
    /// Construct an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace an entry by `node_id`. If an entry with the same
    /// `node_id` already exists, it is replaced (the new advertisement is
    /// assumed to be fresher).
    pub fn upsert(&mut self, entry: GatewayDirectoryEntry) {
        let node_id = entry.advertisement.node_id;
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.advertisement.node_id == node_id)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Look up an entry by NodeId.
    #[must_use]
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&GatewayDirectoryEntry> {
        self.entries
            .iter()
            .find(|e| &e.advertisement.node_id == node_id)
    }

    /// Look up an entry by NodeId (mutable).
    pub fn get_mut(&mut self, node_id: &[u8; 32]) -> Option<&mut GatewayDirectoryEntry> {
        self.entries
            .iter_mut()
            .find(|e| &e.advertisement.node_id == node_id)
    }

    /// Return all entries.
    #[must_use]
    pub fn entries(&self) -> &[GatewayDirectoryEntry] {
        &self.entries
    }

    /// Return the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Mark the entry with `node_id` as unreachable (e.g. after a request
    /// failure). No-op if the entry does not exist.
    pub fn mark_unreachable(&mut self, node_id: &[u8; 32]) {
        if let Some(entry) = self.get_mut(node_id) {
            entry.state = GatewayState::Unreachable;
        }
    }

    /// Mark the entry with `node_id` as active (e.g. after a successful
    /// request via this gateway). No-op if the entry does not exist.
    pub fn mark_active(&mut self, node_id: &[u8; 32]) {
        if let Some(entry) = self.get_mut(node_id) {
            entry.state = GatewayState::Active;
            entry.last_seen = now_unix();
        }
    }

    /// **N2.0.3 (Gate D).** Select an entry using the given [`GatewaySelector`]
    /// strategy. This is the strategy-parameterised gateway-selection entry
    /// point: a caller picks a strategy ([`FirstAvailableSelector`] for
    /// simple failover, [`MetricSelector`] for latency-aware selection, or a
    /// custom implementation) and the directory picks the best entry.
    ///
    /// Returns `None` if the strategy returns `None` (e.g. all entries are
    /// expired, unreachable, or the directory is empty).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use snp_node::node::{GatewayDirectory, MetricSelector};
    /// # let directory: GatewayDirectory = unimplemented!();
    /// let selected = directory.select(&MetricSelector);
    /// if let Some(entry) = selected {
    ///     // Use entry.advertisement.listen_addr to reach the gateway.
    /// }
    /// ```
    #[must_use]
    pub fn select(&self, selector: &dyn GatewaySelector) -> Option<&GatewayDirectoryEntry> {
        selector.select(self)
    }
}

/// A gateway-selection strategy. Implementations decide which entry in a
/// [`GatewayDirectory`] to use for the next outgoing request.
///
/// **N2.0.3 (Gate D).** This is the N2.0.3 abstraction over gateway
/// selection. Implementations:
/// - [`FirstAvailableSelector`] — first non-expired, non-unreachable entry
///   (mirrors the N2.0.1 `select_gateway` behaviour but on the new
///   `GatewayDirectory` API).
/// - [`MetricSelector`] — picks the entry with the lowest observed (or, as a
///   fallback, advertised) latency. Does NOT trust the gateway-self-reported
///   advertised latency blindly — prefers the locally-observed latency.
///
/// A custom implementation might rank by hop count, capacity, cost, or a
/// weighted combination. The trait is `Send + Sync` so a selector can be
/// shared across threads (a long-lived client node holds one in its state).
pub trait GatewaySelector: Send + Sync {
    /// Select an entry from the directory. Returns `None` if no entry is
    /// suitable (e.g. all are expired or unreachable).
    fn select<'a>(&self, directory: &'a GatewayDirectory) -> Option<&'a GatewayDirectoryEntry>;
}

/// The simplest selector: returns the first entry that is not `Expired` or
/// `Unreachable`. This mirrors the N2.0.1 `select_gateway` behaviour but
/// operates on the new `GatewayDirectory` API.
pub struct FirstAvailableSelector;

impl GatewaySelector for FirstAvailableSelector {
    fn select<'a>(&self, directory: &'a GatewayDirectory) -> Option<&'a GatewayDirectoryEntry> {
        let now = now_unix();
        directory.entries().iter().find(|e| {
            !e.advertisement.is_expired(now)
                && !matches!(e.state, GatewayState::Expired | GatewayState::Unreachable)
        })
    }
}

/// **N2.0.3 (Gate D).** Metric-based selector: picks the gateway with the
/// lowest latency. Does NOT trust advertised latency — uses only the locally
/// observed latency if available, falling back to the gateway-self-reported
/// advertised RTT only as a last resort.
///
/// ## Selection key
///
/// The selection key for each entry is:
/// ```text
///   observed_latency.or(advertisement.observed_rtt).unwrap_or(u64::MAX)
/// ```
/// This means:
/// - If the client has observed latency for an entry, that value is used
///   (the advertised RTT is IGNORED — a malicious gateway cannot lower its
///   score by advertising a low RTT once the client has measured it).
/// - If the client has NOT observed latency but the gateway advertised an
///   RTT, the advertised RTT is used (with the understanding that it is
///   self-reported and could be optimistic).
/// - If neither is available, the entry sorts last (`u64::MAX`).
///
/// Only entries in the `Verified` or `Active` state are considered (entries
/// that are merely `Discovered`, or that are `Unreachable` / `Expired`, are
/// skipped — they are not yet known-good or are known-bad).
///
/// ## Spec deviation: `or` instead of `min`
///
/// The N2.0.3 task spec sketches this selector with
/// `observed.min(advertised)` as the selection key. That logic is
/// VULNERABLE to the lying-gateway attack: a malicious gateway could
/// advertise an artificially low RTT (`advertised = 1µs`) to override the
/// client's locally-measured higher latency, attracting traffic it doesn't
/// deserve. The spec's comment ("Does NOT trust advertised latency — uses
/// only observed latency if available, falls back to advertised if not")
/// makes the secure intent clear; the `min` code is a sketch bug.
///
/// This implementation uses `observed.or(advertised).unwrap_or(u64::MAX)`
/// instead, which matches the spec's documented intent. A gateway's
/// advertised RTT is ONLY used when the client has NOT yet measured the
/// latency — once the client has measured it, the advertised value is
/// ignored entirely.
///
/// ## Tiebreaking
///
/// `Iterator::min_by_key` returns the FIRST entry with the minimum key on
/// ties, so the order of entries in the directory matters for ties. The
/// directory preserves insertion order (callers can `upsert` entries in a
/// preferred order if they care about tiebreaking).
pub struct MetricSelector;

impl GatewaySelector for MetricSelector {
    fn select<'a>(&self, directory: &'a GatewayDirectory) -> Option<&'a GatewayDirectoryEntry> {
        directory
            .entries()
            .iter()
            .filter(|e| matches!(e.state, GatewayState::Verified | GatewayState::Active))
            .min_by_key(|e| {
                let observed = e.observed_latency;
                let advertised = e.advertisement.observed_rtt;
                // Prefer the locally-observed latency; fall back to the
                // advertised RTT ONLY if no observation is available. This
                // is `observed.or(advertised).unwrap_or(u64::MAX)`, NOT
                // `min(observed, advertised)` — the latter would let a
                // malicious gateway's advertised RTT override the client's
                // own measurement.
                observed.or(advertised).unwrap_or(u64::MAX)
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// The circuit is being established (the client↔gateway DH is in
    /// progress, embedded in the first TransitRequest).
    Discovering,
    /// The first TransitRequest is in transit; the circuit keys have not
    /// yet been derived on both sides.
    Establishing,
    /// The circuit is active — both sides have derived the circuit keys and
    /// can carry TransitRequest/TransitResponse frames.
    Active,
    /// The circuit is alive but has experienced a transient failure. The
    /// circuit MAY recover, or it MAY transition to `Migrating`.
    Degraded,
    /// The circuit is being migrated to a new gateway (the current gateway
    /// has failed; a new gateway is being selected).
    Migrating,
    /// The circuit has permanently failed.
    Failed,
    /// The circuit has been gracefully closed.
    Closed,
}

/// A client↔gateway circuit with FRESH keys derived from a client↔gateway
/// X25519 DH (NOT from a deterministic seed). This is the N2.0.2 production
/// circuit object, distinct from the legacy [`Circuit`] struct (which uses
/// pre-shared deterministic seeds).
#[derive(Debug, Clone)]
pub struct CircuitV2 {
    pub circuit_id: [u8; 32],
    pub client_node_id: [u8; 32],
    pub gateway_node_id: [u8; 32],
    pub send_key: snp_crypto::SymmetricKey,
    pub recv_key: snp_crypto::SymmetricKey,
    pub state: CircuitState,
    pub created_at: u64,
    pub last_activity: u64,
}

impl CircuitV2 {
    /// Get the circuit state.
    #[must_use]
    pub fn state(&self) -> CircuitState {
        self.state
    }

    pub fn new(
        client_node_id: [u8; 32],
        gateway_node_id: [u8; 32],
        send_key: snp_crypto::SymmetricKey,
        recv_key: snp_crypto::SymmetricKey,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Use getrandom for a unique nonce so two circuits created in the
        // same second have different circuit_ids.
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("getrandom failed");
        let mut id_input = Vec::new();
        id_input.extend_from_slice(&client_node_id);
        id_input.extend_from_slice(&gateway_node_id);
        id_input.extend_from_slice(&now.to_be_bytes());
        id_input.extend_from_slice(&nonce);
        let circuit_id = snp_crypto::sha256(&id_input);
        Self {
            circuit_id,
            client_node_id,
            gateway_node_id,
            send_key,
            recv_key,
            state: CircuitState::Discovering,
            created_at: now,
            last_activity: now,
        }
    }

    pub fn transition_to(&mut self, new_state: CircuitState) -> super::NodeResult<()> {
        use CircuitState::*;
        let legal = matches!(
            (self.state, new_state),
            (Discovering, Establishing)
                | (Discovering, Failed)
                | (Establishing, Active)
                | (Establishing, Failed)
                | (Active, Degraded)
                | (Active, Migrating)
                | (Active, Failed)
                | (Active, Closed)
                | (Degraded, Active)
                | (Degraded, Migrating)
                | (Degraded, Failed)
                | (Migrating, Active)
                | (Migrating, Failed)
                | (Failed, Closed)
                | (Closed, Closed)
        );
        if !legal {
            return Err(super::NodeError::Other(format!(
                "illegal CircuitV2 transition: {:?} → {:?}",
                self.state, new_state
            )));
        }
        self.state = new_state;
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(())
    }
}
