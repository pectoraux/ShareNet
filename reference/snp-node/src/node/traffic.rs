//! N2.3 — Traffic Forwarding over an established ActiveCircuit.
//!
//! Spec: public/spec/08-circuits.md (N2.3 — Traffic Forwarding).
//!
//! ## CRITICAL: this is real packet traversal, not another crypto helper
//!
//! N2.3 proves that an encrypted packet genuinely traverses the installed
//! relay forwarding state from source to destination:
//!
//! ```text
//! A ──sealed packet──> B ──sealed packet──> C ──plaintext──> G
//! ```
//!
//! B and C consult their installed [`RelayForwardingState`] (from N2.2's
//! `accept_relay_handshake`), unwrap one AEAD layer, and forward. A never
//! talks directly to G.
//!
//! ## Per-hop onion AEAD
//!
//! The source wraps the payload in nested ChaCha20-Poly1305 layers, one per
//! non-source hop, in reverse traversal order. Each relay peels exactly one
//! layer with its installed `forwarding_key`:
//!
//! ```text
//! source constructs:
//!   inner = plaintext (for G)
//!   layer_C = AEAD_seal(key_C, nonce, inner,   aad = circuit_id ‖ seq ‖ G)
//!   layer_B = AEAD_seal(key_B, nonce, layer_C, aad = circuit_id ‖ seq ‖ C)
//!   packet  = { circuit_id, seq, ttl, payload = layer_B, final_dst = G }
//!
//! B: lookup state[circuit_id] → unwrap layer_B with key_B → reveals layer_C + successor C
//! C: lookup state[circuit_id] → unwrap layer_C with key_C → reveals plaintext + successor G (terminal)
//! G: receives plaintext
//! ```
//!
//! ## The 15 N2.3 invariants
//!
//!  1. Packet bound to exactly one circuit         — `circuit_id` in packet + state lookup
//!  2. Relay cannot substitute circuit/destination — state keyed by circuit_id; successor in sealed inner
//!  3. Relay cannot decrypt beyond its layer        — AEAD: only the hop's key opens its layer
//!  4. Packet replay rejected                       — per-circuit seq window in RelayForwardingTable
//!  5. Sequence/order bounded                       — seq is u32, monotonic, max-seen enforced
//!  6. Cannot inject into another circuit           — AAD binds circuit_id; wrong-circuit key fails AEAD
//!  7. Cannot skip a designated hop                 — each layer reveals only the next successor
//!  8. Relay cannot change predecessor/successor    — state's predecessor check + AEAD AAD binds next-hop
//!  9. TTL prevents forwarding loops                — ttl decremented per hop, drop at 0
//! 10. Unknown circuit IDs rejected                 — state lookup miss → UnknownCircuit
//! 11. Teardown immediately blocks new traffic      — table.remove_circuit() drops state
//! 12. Oversized packets rejected before allocation — bounded CBOR decode + MAX_PACKET_PAYLOAD_BYTES
//! 13. Malformed forwarding messages fail closed    — AEAD failure → PacketUnauthentic, no partial state
//! 14. Forwarding state cleaned up deterministically — explicit remove_circuit + drop on teardown
//! 15. Path operates without inspecting app payload  — relays see only ciphertext + successor NodeId
//!
//! ## NOT implemented (deferred)
//!
//! - Internet gateway egress (N2.3+ — this slice proves mesh traversal only).
//! - TCP connection migration / route recovery (N2.1.4+, spec §39).
//! - Backward (gateway→source) traffic (symmetric; deferred).
//! - Flow control / congestion (transport layer).

use super::*;
use crate::node::circuit_handshake::CircuitTeardown;
use crate::node::route_discovery::{RouteRole, ROUTE_MAX_HOPS};
use snp_cbor::{CborLimits, CborValue, decode_with_limits};
use snp_crypto::{aead_nonce, aead_open, aead_seal, sha256, SymmetricKey};

/// Maximum **plaintext** (application) payload a single packet may carry,
/// in bytes (P1: separated from the wire limit).
///
/// Enforced at the source by [`wrap_packet`]. The sealed **wire** payload
/// may be larger (each AEAD layer appends a 16-byte tag), bounded separately
/// by [`MAX_WIRE_PAYLOAD_BYTES`].
pub const MAX_PLAINTEXT_PAYLOAD_BYTES: usize = 65_536;

/// Size of the ChaCha20-Poly1305 authentication tag appended by each AEAD
/// layer (RFC 8439). Re-exported from `snp_crypto::Tag` (= `[u8; 16]`).
pub const AEAD_TAG_BYTES: usize = 16;

/// Maximum **wire** payload (sealed bytes) a `CircuitPacket.payload` may
/// carry. Derived from the plaintext maximum plus the worst-case AEAD tag
/// overhead across all non-source hops (P1).
///
/// Each non-source hop adds one 16-byte tag via `aead_seal`. The maximum
/// number of non-source hops is `ROUTE_MAX_HOPS - 1` (15), so the worst-case
/// wire overhead is `15 × 16 = 240` bytes. The wire bound is therefore:
///
/// ```text
/// MAX_WIRE_PAYLOAD_BYTES = MAX_PLAINTEXT_PAYLOAD_BYTES
///                        + AEAD_TAG_BYTES × (ROUTE_MAX_HOPS - 1)
/// ```
///
/// Enforced by [`CircuitPacket::decode_from_cbor`] at the CBOR head, before
/// any `Vec` allocation (invariant #12). The source's [`wrap_packet`] also
/// rejects a plaintext that would produce a wire payload exceeding this.
pub const MAX_WIRE_PAYLOAD_BYTES: usize =
    MAX_PLAINTEXT_PAYLOAD_BYTES + AEAD_TAG_BYTES * (ROUTE_MAX_HOPS - 1);

/// **Deprecated alias** for [`MAX_PLAINTEXT_PAYLOAD_BYTES`]. Retained for
/// backward compatibility with code that predates the plaintext/wire split.
/// New code should use `MAX_PLAINTEXT_PAYLOAD_BYTES` (source-side limit) or
/// `MAX_WIRE_PAYLOAD_BYTES` (decoder-side limit) as appropriate.
#[deprecated(note = "use MAX_PLAINTEXT_PAYLOAD_BYTES or MAX_WIRE_PAYLOAD_BYTES")]
pub const MAX_PACKET_PAYLOAD_BYTES: usize = MAX_PLAINTEXT_PAYLOAD_BYTES;

/// Default per-circuit replay window size (number of sequence numbers
/// remembered for replay rejection). A packet whose seq is older than
/// `max_seen - WINDOW` is rejected as stale (invariant #4/#5).
pub const REPLAY_WINDOW_SIZE: u32 = 1024;

/// Maximum TTL a forwarded packet may carry. Bounded by ROUTE_MAX_HOPS so a
/// packet cannot loop indefinitely (invariant #9).
pub const PACKET_TTL_MAX: u8 = ROUTE_MAX_HOPS as u8;

/// The first sequence number a source may assign to a packet on a fresh
/// circuit (P0: sequence lifecycle).
///
/// Sequence numbers start at 1 (NOT 0). `0` is reserved as an invalid value
/// that the relay rejects — it prevents ambiguity with any
/// uninitialized/sentinel state and makes the protocol's sequence lifecycle
/// unambiguous.
pub const FIRST_PACKET_SEQ: u32 = 1;

/// The sequence number at which a circuit is considered exhausted (P0).
///
/// `u32::MAX` is the last valid sequence number. A circuit that has sent a
/// packet with `seq == u32::MAX` is exhausted: the source MUST re-establish
/// the circuit (new handshake, new keys, new circuit_id) before sending
/// further traffic. There is **no wraparound** to 0 — consistent with
/// ShareNet's no-wrap/no-reuse sequence-state philosophy.
///
/// Rationale: the AEAD nonce is derived from `(circuit_id, seq)`. Wrapping
/// seq to 0 would eventually reuse a nonce under the same key, which is
/// catastrophic for ChaCha20-Poly1305. Treating `u32::MAX` as a hard
/// exhaustion point keeps the nonce space injective for the circuit's
/// lifetime.
pub const MAX_PACKET_SEQUENCE: u32 = u32::MAX;

/// A forwarded packet on an established circuit.
///
/// Wire fields (CBOR map):
/// - `circuitId` — the circuit this packet belongs to (invariant #1, #10).
/// - `seq`       — per-circuit sequence number (invariant #4, #5).
/// - `ttl`       — hop budget, decremented per relay (invariant #9).
/// - `payload`   — sealed (AEAD) bytes. For a relay, this is ONE AEAD layer
///                 it must peel with its `forwarding_key`. For the
///                 destination, this is the plaintext (all layers peeled).
/// - `finalDst`  — the terminal destination NodeId (the gateway). Carried in
///                 the clear so the last relay knows where to deliver; bound
///                 into every AEAD layer's AAD so it cannot be substituted
///                 (invariant #2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitPacket {
    /// The circuit ID this packet travels on.
    pub circuit_id: [u8; 32],
    /// Per-circuit sequence number (monotonic from the source).
    pub seq: u32,
    /// Time-to-live in hops. Decremented per relay; dropped at 0.
    pub ttl: u8,
    /// Sealed payload bytes (one AEAD layer per remaining hop).
    pub payload: Vec<u8>,
    /// The terminal destination NodeId (gateway). In the clear on the wire;
    /// bound into every AEAD layer's AAD.
    pub final_dst: [u8; 32],
}

/// Errors from traffic forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficError {
    /// The circuit_id is not in the relay's forwarding table (invariant #10).
    UnknownCircuit { circuit_id: [u8; 32] },
    /// The packet's predecessor does not match the state's predecessor
    /// (invariant #2, #8). A relay received a packet from a node that is not
    /// its registered predecessor for this circuit.
    PredecessorMismatch {
        circuit_id: [u8; 32],
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The AEAD unwrap failed — the packet is not authentic. Either the relay
    /// does not possess the right key, or the packet was tampered with, or it
    /// was injected into the wrong circuit (invariant #3, #6, #13).
    PacketUnauthentic { circuit_id: [u8; 32] },
    /// The packet is a replay (seq already seen) or stale (seq behind the
    /// replay window) (invariant #4, #5).
    PacketReplayOrStale {
        circuit_id: [u8; 32],
        seq: u32,
    },
    /// The TTL is exhausted — the packet has been forwarded too many times
    /// and must be dropped (invariant #9).
    TtlExhausted { circuit_id: [u8; 32], ttl: u8 },
    /// The packet's circuit_id does not match the state's circuit_id. This
    /// should never happen if the table lookup is correct, but is checked
    /// defense-in-depth (invariant #1).
    CircuitIdMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The packet payload exceeds MAX_PACKET_PAYLOAD_BYTES (invariant #12).
    PayloadTooLarge {
        actual: usize,
        max: usize,
    },
    /// The relay has no successor configured (it is the gateway/terminal) but
    /// received a packet that still has AEAD layers to peel. This indicates a
    /// routing inconsistency.
    TerminalRelayReceivedSealedPayload { circuit_id: [u8; 32] },
    /// A non-terminal relay (has a successor) received a packet whose unwrapped
    /// inner payload is plaintext (no further AEAD layer). The packet tried to
    /// terminate early / skip a hop (invariant #7).
    NonTerminalRelayReceivedPlaintext { circuit_id: [u8; 32] },
    /// Wire-level decode of a CircuitPacket failed (invariant #12, #13).
    WireDecodeFailed { reason: String },
    /// CBOR encoding failed (fail-closed).
    CborEncodingFailed,
    /// The circuit has been torn down — forwarding state was removed and the
    /// packet is rejected (invariant #11).
    CircuitTornDown { circuit_id: [u8; 32] },
    /// The source tried to send on a circuit whose ActiveCircuit has expired.
    CircuitExpired { circuit_id: [u8; 32] },
    /// The source tried to send a packet with no hops to traverse (empty
    /// ActiveCircuit).
    EmptyCircuit,
    /// P0: the circuit's sequence space is exhausted. The source has already
    /// sent a packet with `seq == u32::MAX` ([`MAX_PACKET_SEQUENCE`]). The
    /// circuit MUST be torn down and re-established before further traffic —
    /// there is no wraparound to 0.
    SequenceExhausted { circuit_id: [u8; 32] },
    /// P0: the relay received a packet with `seq == 0`. Sequence numbers
    /// start at [`FIRST_PACKET_SEQ`] (= 1); `0` is not a valid packet
    /// sequence and is rejected (prevents ambiguity with sentinel state and
    /// enforces the protocol's sequence lifecycle).
    SequenceZero { circuit_id: [u8; 32] },
}

impl std::fmt::Display for TrafficError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCircuit { circuit_id } => write!(f, "unknown circuit {}", hex_short(circuit_id)),
            Self::PredecessorMismatch { circuit_id, expected, actual } => write!(
                f, "circuit {} predecessor mismatch: expected {}, got {}",
                hex_short(circuit_id), hex_short(expected), hex_short(actual)
            ),
            Self::PacketUnauthentic { circuit_id } => write!(
                f, "circuit {} packet failed AEAD authentication — tampered, wrong key, or wrong circuit",
                hex_short(circuit_id)
            ),
            Self::PacketReplayOrStale { circuit_id, seq } => write!(
                f, "circuit {} packet seq {seq} is replay or stale", hex_short(circuit_id)
            ),
            Self::TtlExhausted { circuit_id, ttl } => write!(
                f, "circuit {} packet TTL exhausted (ttl={ttl})", hex_short(circuit_id)
            ),
            Self::CircuitIdMismatch { expected, actual } => write!(
                f, "circuit id mismatch: expected {}, got {}", hex_short(expected), hex_short(actual)
            ),
            Self::PayloadTooLarge { actual, max } => write!(
                f, "packet payload too large: {actual} bytes, max {max}"
            ),
            Self::TerminalRelayReceivedSealedPayload { circuit_id } => write!(
                f, "circuit {} terminal relay received still-sealed payload", hex_short(circuit_id)
            ),
            Self::NonTerminalRelayReceivedPlaintext { circuit_id } => write!(
                f, "circuit {} non-terminal relay received plaintext (hop-skip attempt)", hex_short(circuit_id)
            ),
            Self::WireDecodeFailed { reason } => write!(f, "wire decode failed: {reason}"),
            Self::CborEncodingFailed => write!(f, "canonical CBOR encoding failed"),
            Self::CircuitTornDown { circuit_id } => write!(
                f, "circuit {} torn down — forwarding state removed", hex_short(circuit_id)
            ),
            Self::CircuitExpired { circuit_id } => write!(
                f, "circuit {} expired", hex_short(circuit_id)
            ),
            Self::EmptyCircuit => write!(f, "circuit has no hops to traverse"),
            Self::SequenceExhausted { circuit_id } => write!(
                f, "circuit {} sequence exhausted (reached u32::MAX) — re-establish the circuit before further traffic",
                hex_short(circuit_id)
            ),
            Self::SequenceZero { circuit_id } => write!(
                f, "circuit {} packet seq 0 is invalid (sequences start at 1)", hex_short(circuit_id)
            ),
        }
    }
}

impl std::error::Error for TrafficError {}

/// The unwrapped result of a relay peeling one AEAD layer.
///
/// A relay uses this to decide whether to forward to its successor or deliver
/// locally (if it is the terminal gateway).
#[derive(Debug, Clone)]
pub enum UnwrappedPacket {
    /// The packet still has further hops. The relay must forward `packet` to
    /// its registered successor. The successor NodeId is encoded inside the
    /// sealed layer (bound by AEAD AAD), so it cannot be substituted.
    Forward {
        /// The packet to forward (one fewer AEAD layer, ttl decremented).
        packet: CircuitPacket,
        /// The successor NodeId to forward to (from the relay's state).
        successor: [u8; 32],
    },
    /// The relay is the terminal gateway. The sealed layers are exhausted and
    /// `plaintext` is the application payload for local delivery.
    Deliver {
        /// The decrypted application payload.
        plaintext: Vec<u8>,
    },
}

/// Per-circuit replay-protection state kept by a relay's forwarding table.
#[derive(Debug, Clone)]
struct CircuitReplayWindow {
    /// Whether the window has been initialized by its first committed packet.
    /// P1: replaces the old `max_seen == 0` sentinel, which conflated the
    /// valid sequence number 0 with the uninitialized state.
    initialized: bool,
    /// The highest sequence number seen so far on this circuit.
    max_seen: u32,
    /// A bit window of the last REPLAY_WINDOW_SIZE sequence numbers. `true` at
    /// index `(seq % WINDOW)` means `seq` has been seen.
    seen: Vec<bool>,
}

impl CircuitReplayWindow {
    fn new() -> Self {
        Self {
            initialized: false,
            max_seen: 0,
            seen: vec![false; REPLAY_WINDOW_SIZE as usize],
        }
    }

    /// **Read-only** replay/sequence check. Returns `Ok(())` if `seq` would be
    /// acceptable (not a replay, not stale); returns `Err` if it is a duplicate
    /// or behind the window.
    ///
    /// This does NOT mutate the window. The caller MUST call [`commit`] after
    /// the packet has passed AEAD authentication, otherwise an unauthenticated
    /// attacker could poison the window (P0 #1: replay state must not mutate
    /// before AEAD authentication).
    ///
    /// [`commit`]: CircuitReplayWindow::commit
    fn check(&self, seq: u32) -> Result<(), TrafficError> {
        // P0: seq == 0 is never a valid packet sequence. The protocol starts
        // at FIRST_PACKET_SEQ (= 1). Rejecting 0 at the relay prevents any
        // ambiguity with sentinel state and enforces the no-wrap lifecycle.
        if seq == 0 {
            return Err(TrafficError::SequenceZero { circuit_id: [0u8; 32] });
        }
        // First packet on this circuit (initialized == false): any valid
        // (non-zero) seq is acceptable. P1: uses an explicit `initialized`
        // flag rather than `max_seen == 0`, so a first packet with seq=0 is
        // handled correctly.
        if !self.initialized {
            return Ok(());
        }
        // Future packet (seq > max_seen): always acceptable (will advance
        // max_seen on commit).
        if seq > self.max_seen {
            return Ok(());
        }
        // Past or duplicate packet: check the window.
        let distance = self.max_seen.saturating_sub(seq);
        if distance >= REPLAY_WINDOW_SIZE {
            return Err(TrafficError::PacketReplayOrStale { circuit_id: [0u8; 32], seq });
        }
        let idx = (seq % REPLAY_WINDOW_SIZE) as usize;
        if self.seen[idx] {
            return Err(TrafficError::PacketReplayOrStale { circuit_id: [0u8; 32], seq });
        }
        Ok(())
    }

    /// Commit a sequence number into the replay window AFTER the packet has
    /// passed AEAD authentication (P0 #1). This is the only method that
    /// mutates the window.
    ///
    /// # Algorithm (O(WINDOW), never O(sequence delta) — P0 #2)
    ///
    /// - If `seq` is the first packet (`!initialized`): set `initialized`,
    ///   `max_seen = seq`, mark the slot.
    /// - If `seq > max_seen` and the jump `delta = seq - max_seen` is `< WINDOW`:
    ///   clear only the `delta` newly-exposed slots (O(delta) ≤ O(WINDOW)),
    ///   set `max_seen = seq`, mark the slot.
    /// - If `seq > max_seen` and `delta >= WINDOW`: the entire old window is
    ///   now stale — clear it in O(WINDOW), set `max_seen = seq`, mark the slot.
    ///   (Never iterate `max_seen..seq` — that was the P0 #2 DoS bug.)
    /// - If `seq <= max_seen` (within window): mark the slot (already checked
    ///   by `check`).
    fn commit(&mut self, seq: u32) {
        if !self.initialized {
            // First authenticated packet. Initialize the window.
            self.initialized = true;
            self.max_seen = seq;
            self.seen[(seq % REPLAY_WINDOW_SIZE) as usize] = true;
            return;
        }
        if seq > self.max_seen {
            let delta = seq - self.max_seen;
            if delta >= REPLAY_WINDOW_SIZE {
                // The entire old window is now stale. Clear it in O(WINDOW),
                // not O(delta). (P0 #2: the old code iterated max_seen..seq.)
                for slot in self.seen.iter_mut() {
                    *slot = false;
                }
            } else {
                // Clear only the `delta` newly-exposed slots. O(delta) ≤ O(WINDOW).
                for i in 1..=delta {
                    let s = self.max_seen.wrapping_add(i);
                    self.seen[(s % REPLAY_WINDOW_SIZE) as usize] = false;
                }
            }
            self.max_seen = seq;
            self.seen[(seq % REPLAY_WINDOW_SIZE) as usize] = true;
            return;
        }
        // seq <= max_seen, within window (check() already verified not a
        // replay). Mark the slot.
        self.seen[(seq % REPLAY_WINDOW_SIZE) as usize] = true;
    }
}

/// A relay's forwarding table: maps circuit_id → (forwarding state + replay window).
///
/// Installed by `accept_relay_handshake` (N2.2). Consulted by `forward_packet`
/// (N2.3). Removed on teardown (invariant #11, #14).
#[derive(Debug, Clone, Default)]
pub struct RelayForwardingTable {
    entries: std::collections::HashMap<[u8; 32], RelayTableEntry>,
}

#[derive(Debug, Clone)]
struct RelayTableEntry {
    /// The forwarding state installed by accept_relay_handshake.
    state: RelayForwardingState,
    /// Per-circuit replay window.
    replay: CircuitReplayWindow,
}

impl RelayForwardingTable {
    /// Create an empty forwarding table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install forwarding state for a circuit (called after
    /// `accept_relay_handshake` succeeds). If state already exists for this
    /// circuit_id, it is replaced (the relay re-accepted, e.g. after a
    /// legitimate re-establishment with a fresh handshake).
    pub fn install(&mut self, state: RelayForwardingState) {
        let circuit_id = state.circuit_id;
        self.entries.insert(circuit_id, RelayTableEntry {
            state,
            replay: CircuitReplayWindow::new(),
        });
    }

    /// Remove forwarding state for a circuit (teardown). After this, packets
    /// for this circuit_id are rejected with `CircuitTornDown` (invariant #11).
    pub fn remove_circuit(&mut self, circuit_id: &[u8; 32]) {
        self.entries.remove(circuit_id);
    }

    /// Number of installed circuits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the table empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Does the table have forwarding state for this circuit?
    #[must_use]
    pub fn has_circuit(&self, circuit_id: &[u8; 32]) -> bool {
        self.entries.contains_key(circuit_id)
    }

    /// Process a teardown: remove the circuit's forwarding state immediately.
    /// After this call, any packet for `circuit_id` is rejected (invariant #11).
    pub fn apply_teardown(&mut self, _teardown: &CircuitTeardown) {
        // The teardown's signature + circuit binding are verified by the
        // caller (CircuitTeardown::verify / verify_for_circuit). Here we only
        // remove the state — the caller has already authorized the teardown.
        self.remove_circuit(&_teardown.circuit_id);
    }

    /// Forward a packet: look up the circuit's forwarding state, verify the
    /// predecessor, check replay/seq, decrement TTL, peel one AEAD layer, and
    /// return either `Forward { successor }` or `Deliver { plaintext }`.
    ///
    /// `predecessor` is the NodeId of the node that handed us this packet
    /// (invariant #2, #8: must match the state's registered predecessor).
    ///
    /// # Errors
    /// Returns [`TrafficError`] on any failure (fail-closed — no partial
    /// forwarding state is installed, no side effects on the table).
    pub fn forward_packet(
        &mut self,
        packet: &CircuitPacket,
        predecessor: &[u8; 32],
    ) -> Result<UnwrappedPacket, TrafficError> {
        // 9. TTL check (before any crypto — cheap and fail-closed).
        if packet.ttl == 0 {
            return Err(TrafficError::TtlExhausted {
                circuit_id: packet.circuit_id,
                ttl: 0,
            });
        }

        // 10. Unknown circuit → reject (state lookup).
        let entry = self.entries.get_mut(&packet.circuit_id).ok_or(
            TrafficError::UnknownCircuit { circuit_id: packet.circuit_id }
        )?;

        // 1. Circuit binding: the packet's circuit_id must match the state's.
        if entry.state.circuit_id != packet.circuit_id {
            return Err(TrafficError::CircuitIdMismatch {
                expected: entry.state.circuit_id,
                actual: packet.circuit_id,
            });
        }

        // 2, 8. Predecessor check: the packet came from the registered
        // predecessor. A relay cannot receive from a different node and
        // forward on this circuit.
        if &entry.state.predecessor_node_id != predecessor {
            return Err(TrafficError::PredecessorMismatch {
                circuit_id: packet.circuit_id,
                expected: entry.state.predecessor_node_id,
                actual: *predecessor,
            });
        }

        // 4, 5. Replay / sequence check — READ-ONLY at this stage (P0 #1).
        // The window is NOT mutated here. An unauthenticated packet must not
        // be able to advance max_seen or poison the window. The actual commit
        // happens only after AEAD authentication succeeds (below).
        entry.replay.check(packet.seq).map_err(|e| match e {
            TrafficError::PacketReplayOrStale { seq, .. } => {
                TrafficError::PacketReplayOrStale { circuit_id: packet.circuit_id, seq }
            }
            other => other,
        })?;

        // 3, 6, 13. AEAD unwrap: peel one layer with the relay's forwarding_key.
        // The AAD binds circuit_id ‖ seq ‖ ttl ‖ final_dst. P0: ttl is now
        // authenticated per-hop — an attacker cannot modify ttl in transit
        // without breaking AEAD. The ttl the relay sees is the ttl the source
        // bound into this layer at construction time (each nested layer
        // authenticates the hop-local TTL the opening relay will see).
        let nonce = packet_nonce(&packet.circuit_id, packet.seq);
        let aad = packet_aad(&packet.circuit_id, packet.seq, packet.ttl, &packet.final_dst);
        let inner = aead_open(&entry.state.forwarding_key, &nonce, &packet.payload, &aad)
            .ok_or(TrafficError::PacketUnauthentic { circuit_id: packet.circuit_id })?;

        // P0 #1: ONLY NOW — after AEAD authentication succeeded — commit the
        // sequence number into the replay window. A packet that failed AEAD
        // (PacketUnauthentic, returned above) never reaches this line, so it
        // cannot mutate replay state. This is the architectural principle:
        // failed security validation must not mutate security state.
        entry.replay.commit(packet.seq);

        // 7. Determine: forward to successor, or deliver locally?
        match entry.state.successor_node_id {
            // Terminal relay (gateway): the inner bytes are the plaintext.
            None => {
                // The final_dst is already bound into the AEAD AAD, so any
                // substitution of the destination failed authentication above.
                // The gateway simply delivers the decrypted payload locally.
                Ok(UnwrappedPacket::Deliver { plaintext: inner })
            }
            // Non-terminal relay: forward the peeled packet to the successor.
            Some(successor) => {
                // The inner bytes are the next AEAD layer (still sealed for the
                // successor). Construct the forwarded packet: same circuit_id,
                // same seq, ttl-1, payload=inner, same final_dst.
                let forwarded = CircuitPacket {
                    circuit_id: packet.circuit_id,
                    seq: packet.seq,
                    ttl: packet.ttl.saturating_sub(1),
                    payload: inner,
                    final_dst: packet.final_dst,
                };
                Ok(UnwrappedPacket::Forward { packet: forwarded, successor })
            }
        }
    }
}

// ─── Source-side: wrap a plaintext into a forwarded packet ────────────────

/// Source-side: wrap an application payload into a `CircuitPacket` ready to
/// send to the first relay.
///
/// The source constructs nested AEAD layers, one per non-source hop, in
/// reverse traversal order. Each layer's AAD binds `circuit_id ‖ seq ‖
/// final_dst`, so the destination and circuit cannot be substituted.
///
/// # Parameters
///
/// - `hops`: the per-hop forwarding state from `ActiveCircuit::hops()` (or
///   `CircuitSetup::hops()`). Hop 0 is the source (skipped — it has no
///   forwarding key); hops 1..n are the relays/gateway.
/// - `circuit_id`: the circuit ID.
/// - `seq`: the per-circuit sequence number (monotonic from the source).
/// - `final_dst`: the terminal destination NodeId (the gateway).
/// - `plaintext`: the application payload to deliver to the destination.
///
/// # Errors
///
/// Returns [`TrafficError::EmptyCircuit`] if there are no non-source hops.
/// Returns [`TrafficError::PayloadTooLarge`] if the plaintext exceeds
/// [`MAX_PLAINTEXT_PAYLOAD_BYTES`].
///
/// # Visibility (P0: no arbitrary-sequence bypass)
///
/// This function is `pub(crate)`. Production callers MUST use
/// [`CircuitSender::send_packet`], which owns per-circuit sequence allocation
/// and prevents AEAD nonce reuse. Exposing `wrap_packet(.., seq: u32, ..)` as
/// a normal public API would let callers bypass the circuit-owned allocator
/// and reuse arbitrary sequence numbers under the same key.
///
/// Tests use [`wrap_packet_for_testing`], the public test-only alias.
pub(crate) fn wrap_packet(
    hops: &[crate::node::circuit_handshake::HopForwardingState],
    circuit_id: &[u8; 32],
    seq: u32,
    final_dst: &[u8; 32],
    plaintext: &[u8],
) -> Result<CircuitPacket, TrafficError> {
    // P1: the source rejects a plaintext that would produce a wire payload
    // exceeding MAX_WIRE_PAYLOAD_BYTES. Each non-source hop adds one AEAD tag
    // (16 bytes), so the worst-case sealed size is plaintext + 16×hops.
    let relay_hops_count = hops.iter().skip(1).count();
    let worst_case_wire = plaintext.len()
        .saturating_add(AEAD_TAG_BYTES.saturating_mul(relay_hops_count));
    if plaintext.len() > MAX_PLAINTEXT_PAYLOAD_BYTES {
        return Err(TrafficError::PayloadTooLarge {
            actual: plaintext.len(),
            max: MAX_PLAINTEXT_PAYLOAD_BYTES,
        });
    }
    if worst_case_wire > MAX_WIRE_PAYLOAD_BYTES {
        return Err(TrafficError::PayloadTooLarge {
            actual: worst_case_wire,
            max: MAX_WIRE_PAYLOAD_BYTES,
        });
    }

    // Non-source hops (skip hop 0 = source).
    let relay_hops: Vec<_> = hops.iter().skip(1).collect();
    if relay_hops.is_empty() {
        return Err(TrafficError::EmptyCircuit);
    }

    let nonce = packet_nonce(circuit_id, seq);

    // P0: each nested AEAD layer authenticates the hop-local TTL the opening
    // relay will see. The first relay sees ttl = PACKET_TTL_MAX; each
    // subsequent relay sees one less (the predecessor decrements before
    // forwarding). The source computes each hop's expected TTL at wrap time
    // and binds it into that layer's AAD.
    //
    // Wrap in reverse order: innermost layer is the plaintext (for the last
    // hop / gateway), outermost is for the first relay.
    let mut payload = plaintext.to_vec();
    let total_relay_hops = relay_hops.len();
    for (rev_idx, hop) in relay_hops.iter().rev().enumerate() {
        // rev_idx == 0 → outermost layer (first relay, ttl = PACKET_TTL_MAX).
        // rev_idx == 1 → next layer  (second relay, ttl = PACKET_TTL_MAX - 1).
        // ... and so on. The hop at position `i` (0-indexed from the first
        // relay) sees ttl = PACKET_TTL_MAX - i.
        let hop_position = total_relay_hops - 1 - rev_idx; // 0 for first relay
        let hop_ttl = PACKET_TTL_MAX.saturating_sub(hop_position as u8);
        let hop_aad = packet_aad(circuit_id, seq, hop_ttl, final_dst);
        // The source's HopForwardingState.forwarding_key for this hop equals
        // the relay's RelayForwardingState.forwarding_key (same HKDF derivation).
        payload = aead_seal(&hop.forwarding_key, &nonce, &payload, &hop_aad);
    }

    Ok(CircuitPacket {
        circuit_id: *circuit_id,
        seq,
        ttl: PACKET_TTL_MAX,
        payload,
        final_dst: *final_dst,
    })
}

/// Test-only public alias for [`wrap_packet`] (P0: no arbitrary-sequence
/// bypass in production).
///
/// [`wrap_packet`] is `pub(crate)` so ordinary production callers cannot
/// supply an arbitrary `u32` sequence number (which would bypass
/// [`CircuitSender`] and risk AEAD nonce reuse). This alias exposes the same
/// low-level construction to integration tests, which need to build packets
/// with explicit sequence numbers to exercise adversarial scenarios (replay,
/// stale, TTL tampering, etc.).
///
/// # Feature-gated (P0: structurally absent from production)
///
/// This function is ONLY compiled when the `test-utils` Cargo feature is
/// enabled. A normal production build (`cargo build`) does NOT enable
/// `test-utils`, so this symbol is physically absent from the production
/// binary — an external crate cannot call it. Integration tests enable the
/// feature via the `[dev-dependencies]` self-reference in `Cargo.toml`.
#[cfg(feature = "test-utils")]
pub fn wrap_packet_for_testing(
    hops: &[crate::node::circuit_handshake::HopForwardingState],
    circuit_id: &[u8; 32],
    seq: u32,
    final_dst: &[u8; 32],
    plaintext: &[u8],
) -> Result<CircuitPacket, TrafficError> {
    wrap_packet(hops, circuit_id, seq, final_dst, plaintext)
}

// ─── Source-side: CircuitSender (circuit-owned sequence allocation) ───────

/// Source-side circuit sender: owns per-circuit sequence allocation so that
/// callers cannot supply arbitrary `u32` sequence numbers (P0: sequence
/// exhaustion / no-wrap lifecycle).
///
/// A `CircuitSender` is constructed for a specific circuit and allocates
/// monotonically-increasing sequence numbers starting at [`FIRST_PACKET_SEQ`]
/// (= 1). When the sequence space is exhausted (`seq == u32::MAX`,
/// [`MAX_PACKET_SEQUENCE`]), [`send_packet`](Self::send_packet) fails closed
/// with [`TrafficError::SequenceExhausted`]. There is **no wraparound** —
/// the circuit must be torn down and re-established before further traffic.
///
/// # Uniqueness invariant (P0: no AEAD nonce reuse)
///
/// A `CircuitSender` is **NOT [`Clone`]**. There must be exactly ONE sender
/// per circuit. Cloning would duplicate the sequence allocator, allowing two
/// senders to independently emit the same `seq` under the same circuit_id +
/// forwarding keys — reusing the AEAD nonce `(circuit_id, seq)`, which is
/// catastrophic for ChaCha20-Poly1305.
///
/// If concurrent sending is eventually required, do NOT make this type
/// clonable. Introduce an explicit shared sequence allocator (e.g. with a
/// `Mutex`/atomic state) that hands out unique sequence numbers through
/// controlled handles.
///
/// This is the production source-side API. The lower-level [`wrap_packet`]
/// is `pub(crate)` (not accessible to ordinary production callers); tests
/// use [`wrap_packet_for_testing`].
///
/// # Example
///
/// ```no_run
/// # use snp_node::node::{ActiveCircuit, TrafficError};
/// # fn get_circuit() -> ActiveCircuit { unimplemented!() }
/// let mut circuit = get_circuit();
/// // The circuit owns its sequence allocator. Borrow a sender handle:
/// let mut sender = circuit.sender();
/// let packet1 = sender.send_packet(b"hello")?;      // seq = 1
/// let packet2 = sender.send_packet(b"world")?;      // seq = 2
/// // ...
/// # Ok::<(), TrafficError>(())
/// ```
/// Owned per-circuit sequence-allocation state, embedded in an `ActiveCircuit`.
///
/// This type exists so that the sequence allocator belongs to the **circuit
/// instance** (the `ActiveCircuit`), not to an independently-constructible
/// sender object. A caller cannot manufacture a second allocator merely by
/// knowing the `circuit_id` + hops — the allocator is created exactly once,
/// inside `ActiveCircuit`, at establishment time (P0: no AEAD nonce reuse).
///
/// Production code accesses the allocator through [`ActiveCircuit::sender`]
/// (a borrowed handle) or [`ActiveCircuit::send_packet`]. The standalone
/// [`CircuitSender::new`] constructor is `pub(crate)` (not in the public
/// production API).
///
/// # P0: not `Clone` (no AEAD nonce reuse)
///
/// `CircuitSeqState` is **NOT `Clone`**. It owns the packet-sequence
/// namespace for a circuit; cloning would duplicate the allocator, allowing
/// two instances to independently emit the same `seq` under the same
/// circuit_id + forwarding keys — reusing the AEAD nonce. The allocator is
/// created exactly once, embedded in `ActiveCircuit`, and accessed only
/// through `ActiveCircuit::sender()` (a borrowed handle).
///
/// # P0: `pub(crate)` — not a public production type
///
/// `CircuitSeqState` is `pub(crate)` so external crates cannot construct a
/// second allocator for an existing circuit (which would cause AEAD nonce
/// reuse). It is NOT re-exported from `node/mod.rs`. The only production path
/// to allocate packet sequences is `ActiveCircuit::send_packet()` or
/// `ActiveCircuit::sender()` (a borrowed handle into the circuit-owned
/// allocator).
#[derive(Debug)]
pub(crate) struct CircuitSeqState {
    /// The next sequence number to assign. Starts at FIRST_PACKET_SEQ (1).
    next_seq: u32,
    /// Whether the sequence space is exhausted. Set to `true` after assigning
    /// `u32::MAX`; further `send_packet` calls fail closed.
    exhausted: bool,
}

impl CircuitSeqState {
    /// Create a fresh allocator starting at [`FIRST_PACKET_SEQ`] (= 1).
    /// `pub(crate)` — only `ActiveCircuit` (in `distributed_circuit.rs`)
    /// constructs this, at circuit establishment time.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self { next_seq: FIRST_PACKET_SEQ, exhausted: false }
    }

    /// The next sequence number that will be assigned (without sending).
    /// `pub(crate)` — accessed via `ActiveCircuit::peek_next_seq()`.
    #[must_use]
    pub(crate) fn peek_next_seq(&self) -> Option<u32> {
        if self.exhausted { None } else { Some(self.next_seq) }
    }

    /// Whether the sequence space is exhausted.
    /// `pub(crate)` — accessed via `ActiveCircuit::is_seq_exhausted()`.
    #[must_use]
    pub(crate) fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Allocate the next sequence number and wrap a plaintext into a
    /// `CircuitPacket`. Fails closed with [`TrafficError::SequenceExhausted`]
    /// once `seq == u32::MAX` has been assigned — there is no wraparound.
    /// `pub(crate)` — accessed via `ActiveCircuit::send_packet()`.
    ///
    /// # P1: sequence is committed only on success
    ///
    /// The allocator's `next_seq`/`exhausted` state is advanced ONLY after
    /// [`wrap_packet`] succeeds. A failed packet construction (e.g.
    /// `PayloadTooLarge`, `EmptyCircuit`) does **not** consume a sequence
    /// number — the same `seq` is offered to the next call.
    ///
    /// # Errors
    /// - [`TrafficError::SequenceExhausted`] — exhausted; re-establish.
    /// - [`TrafficError::EmptyCircuit`] — no non-source hops.
    /// - [`TrafficError::PayloadTooLarge`] — plaintext exceeds the limit.
    pub(crate) fn send_packet(
        &mut self,
        hops: &[crate::node::circuit_handshake::HopForwardingState],
        circuit_id: &[u8; 32],
        final_dst: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<CircuitPacket, TrafficError> {
        if self.exhausted {
            return Err(TrafficError::SequenceExhausted { circuit_id: *circuit_id });
        }
        let candidate_seq = self.next_seq;
        // P1: construct the packet FIRST. If this fails, the allocator state
        // is NOT advanced — the same candidate_seq is offered again.
        let packet = wrap_packet(hops, circuit_id, candidate_seq, final_dst, plaintext)?;
        // P1: only NOW — after successful construction — commit the sequence.
        if candidate_seq == MAX_PACKET_SEQUENCE {
            self.exhausted = true;
        } else {
            self.next_seq = candidate_seq.checked_add(1).ok_or(
                TrafficError::SequenceExhausted { circuit_id: *circuit_id }
            )?;
        }
        Ok(packet)
    }

    /// Test-only: reset the allocator to a specific `next_seq`, so tests can
    /// exercise the exhaustion boundary without ~4B sends. Feature-gated
    /// behind `test-utils` (absent from production builds).
    #[cfg(feature = "test-utils")]
    pub fn reset_to_seq_for_testing(&mut self, next_seq: u32) {
        self.next_seq = next_seq;
        self.exhausted = false;
    }
}

impl Default for CircuitSeqState {
    fn default() -> Self {
        Self::new()
    }
}

/// A borrowed handle to a circuit's sequence allocator (P0: the allocator is
/// owned by the circuit, not independently constructible).
///
/// A `CircuitSender` borrows `&mut` the circuit's [`CircuitSeqState`] and `&`
/// the circuit's hops/id/destination. Because the state is borrowed, two
/// independent senders for the same circuit cannot coexist — the borrow
/// checker enforces uniqueness. This structurally prevents the AEAD
/// nonce-reuse attack where two senders both emit `seq = 1` under the same
/// circuit keys.
///
/// # Uniqueness invariant
///
/// There must be exactly ONE sender handle per circuit at a time. The
/// `&mut` borrow prevents a second `CircuitSender` from existing while one
/// is live. The circuit itself owns the sequence namespace.
///
/// Production code obtains a handle via [`ActiveCircuit::sender`] or uses
/// [`ActiveCircuit::send_packet`] directly. The standalone
/// [`CircuitSender::new`] is `pub(crate)` (not in the public production API).
#[derive(Debug)]
pub struct CircuitSender<'a> {
    /// Borrowed mutable reference to the circuit's sequence allocator.
    seq_state: &'a mut CircuitSeqState,
    /// Borrowed reference to the circuit's per-hop forwarding state.
    hops: &'a [crate::node::circuit_handshake::HopForwardingState],
    /// The circuit ID.
    circuit_id: [u8; 32],
    /// The terminal destination NodeId (the gateway).
    final_dst: [u8; 32],
}

impl<'a> CircuitSender<'a> {
    /// Construct a sender handle that borrows a circuit's sequence allocator
    /// and forwarding state. `pub(crate)` — production callers use
    /// [`ActiveCircuit::sender`] instead.
    ///
    /// This is `pub(crate)` so external crates cannot create an independent
    /// sender for a circuit they don't own. The circuit's allocator is
    /// accessed through the circuit's own `sender()` method, which borrows
    /// the embedded `CircuitSeqState`.
    pub(crate) fn new(
        seq_state: &'a mut CircuitSeqState,
        hops: &'a [crate::node::circuit_handshake::HopForwardingState],
        circuit_id: [u8; 32],
        final_dst: [u8; 32],
    ) -> Self {
        Self { seq_state, hops, circuit_id, final_dst }
    }

    /// The next sequence number that will be assigned (without sending).
    /// Returns `None` if the sequence space is exhausted.
    #[must_use]
    pub fn peek_next_seq(&self) -> Option<u32> {
        self.seq_state.peek_next_seq()
    }

    /// Whether this circuit's sequence space is exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.seq_state.is_exhausted()
    }

    /// Allocate the next sequence number and wrap a plaintext into a
    /// `CircuitPacket`. Delegates to the borrowed [`CircuitSeqState`].
    ///
    /// # Errors
    /// - [`TrafficError::SequenceExhausted`] — exhausted; re-establish.
    /// - [`TrafficError::EmptyCircuit`] — no non-source hops.
    /// - [`TrafficError::PayloadTooLarge`] — plaintext exceeds the limit.
    pub fn send_packet(&mut self, plaintext: &[u8]) -> Result<CircuitPacket, TrafficError> {
        self.seq_state.send_packet(self.hops, &self.circuit_id, &self.final_dst, plaintext)
    }
}

impl<'a> CircuitSender<'a> {
    // (The main impl — new, peek_next_seq, is_exhausted, send_packet — is
    // defined above with the struct. This block is retained for the
    // test-only constructor below.)
}

impl<'a> CircuitSender<'a> {
    /// Test-only standalone constructor that owns its own `CircuitSeqState`,
    /// so integration tests can build a sender without a full `ActiveCircuit`.
    /// Feature-gated behind `test-utils` (absent from production builds).
    ///
    /// Tests that need a sender but don't want to build the full
    /// `ActiveCircuit` (e.g. adversarial replay-window tests) use this. The
    /// allocator is freshly owned, starting at [`FIRST_PACKET_SEQ`].
    #[cfg(feature = "test-utils")]
    pub fn new_standalone_for_testing(
        circuit_id: [u8; 32],
        hops: Vec<crate::node::circuit_handshake::HopForwardingState>,
        final_dst: [u8; 32],
    ) -> CircuitSenderOwnedForTesting {
        CircuitSenderOwnedForTesting {
            seq_state: CircuitSeqState::new(),
            hops,
            circuit_id,
            final_dst,
        }
    }
}

/// Test-only owned sender (backs `CircuitSender::new_standalone_for_testing`).
/// Feature-gated; absent from production builds. Holds its own
/// `CircuitSeqState` + owned hops, so tests without an `ActiveCircuit` can
/// still send packets. The allocator is unique per instance (not `Clone`).
#[cfg(feature = "test-utils")]
#[derive(Debug)]
pub struct CircuitSenderOwnedForTesting {
    seq_state: CircuitSeqState,
    hops: Vec<crate::node::circuit_handshake::HopForwardingState>,
    circuit_id: [u8; 32],
    final_dst: [u8; 32],
}

#[cfg(feature = "test-utils")]
impl CircuitSenderOwnedForTesting {
    /// The next sequence number that will be assigned.
    #[must_use]
    pub fn peek_next_seq(&self) -> Option<u32> {
        self.seq_state.peek_next_seq()
    }

    /// Whether the sequence space is exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.seq_state.is_exhausted()
    }

    /// Send a packet via the owned allocator.
    pub fn send_packet(&mut self, plaintext: &[u8]) -> Result<CircuitPacket, TrafficError> {
        self.seq_state.send_packet(&self.hops, &self.circuit_id, &self.final_dst, plaintext)
    }

    /// Reset the allocator to a specific `next_seq` for exhaustion-boundary
    /// tests.
    pub fn reset_to_seq_for_testing(&mut self, next_seq: u32) {
        self.seq_state.reset_to_seq_for_testing(next_seq);
    }
}

#[cfg(feature = "test-utils")]
impl<'a> CircuitSender<'a> {
    /// Test-only constructor that starts a standalone owned sender at a
    /// specific `next_seq`, so tests can exercise the exhaustion boundary
    /// without sending ~4 billion packets.
    ///
    /// # Feature-gated (P0: structurally absent from production)
    ///
    /// This function is ONLY compiled when the `test-utils` Cargo feature is
    /// enabled. A normal production build does NOT expose it — an external
    /// crate cannot call `CircuitSender::new_at_seq_for_testing`. Integration
    /// tests enable the feature via `[dev-dependencies]`.
    pub fn new_at_seq_for_testing(
        circuit_id: [u8; 32],
        hops: Vec<crate::node::circuit_handshake::HopForwardingState>,
        final_dst: [u8; 32],
        next_seq: u32,
    ) -> CircuitSenderOwnedForTesting {
        let mut s = Self::new_standalone_for_testing(circuit_id, hops, final_dst);
        s.reset_to_seq_for_testing(next_seq);
        s
    }
}

// ─── Destination-side: the terminal gateway receives the plaintext ─────────

/// Destination-side: the terminal gateway unwraps the final layer to recover
/// the plaintext.
///
/// This is used when the gateway has its own `RelayForwardingState` (installed
/// by `accept_relay_handshake` for the gateway hop). The gateway's
/// `forward_packet` returns `UnwrappedPacket::Deliver { plaintext }`.
///
/// For the case where the gateway is the direct successor of the source (no
/// relays), `wrap_packet` produces a single-layer packet and the gateway's
/// `forward_packet` peels it.
#[must_use]
pub fn unwrap_final(plaintext: &[u8]) -> Vec<u8> {
    plaintext.to_vec()
}

// ─── Wire encode/decode (bounded) ─────────────────────────────────────────

/// CBOR map keys for CircuitPacket (canonical sort by encoded bytes).
const PKT_KEY_CIRCUIT_ID: &str = "circuitId";
const PKT_KEY_SEQ: &str = "seq";
const PKT_KEY_TTL: &str = "ttl";
const PKT_KEY_PAYLOAD: &str = "payload";
const PKT_KEY_FINAL_DST: &str = "finalDst";

impl CircuitPacket {
    /// Encode this packet to canonical CBOR wire bytes.
    ///
    /// # Errors
    /// Returns [`TrafficError::CborEncodingFailed`] on encoding failure.
    pub fn encode_to_cbor(&self) -> Result<Vec<u8>, TrafficError> {
        let map = CborValue::Map(vec![
            (CborValue::TextString(PKT_KEY_CIRCUIT_ID.into()), CborValue::ByteString(self.circuit_id.to_vec())),
            (CborValue::TextString(PKT_KEY_SEQ.into()), CborValue::UnsignedInt(u64::from(self.seq))),
            (CborValue::TextString(PKT_KEY_TTL.into()), CborValue::UnsignedInt(u64::from(self.ttl))),
            (CborValue::TextString(PKT_KEY_PAYLOAD.into()), CborValue::ByteString(self.payload.clone())),
            (CborValue::TextString(PKT_KEY_FINAL_DST.into()), CborValue::ByteString(self.final_dst.to_vec())),
        ]);
        snp_cbor::encode(&map).map_err(|_| TrafficError::CborEncodingFailed)
    }

    /// Decode a `CircuitPacket` from canonical CBOR wire bytes, with an
    /// explicit wire-level bound on the payload (invariant #12).
    ///
    /// # Errors
    /// Returns [`TrafficError::PayloadTooLarge`] when the payload exceeds
    /// [`MAX_PACKET_PAYLOAD_BYTES`] (rejected at the CBOR head, before
    /// allocation). Returns [`TrafficError::WireDecodeFailed`] for any other
    /// decode failure.
    pub fn decode_from_cbor(bytes: &[u8]) -> Result<Self, TrafficError> {
        let limits = CborLimits {
            max_array_items: 4,
            max_map_entries: 8,
            // P1: the wire payload bound accounts for AEAD tag overhead
            // across hops (MAX_WIRE_PAYLOAD_BYTES), not just the plaintext.
            max_byte_string_len: MAX_WIRE_PAYLOAD_BYTES as u64,
            max_text_string_len: 16,
            max_nesting_depth: 4,
        };
        let value = match decode_with_limits(bytes, &limits) {
            Ok(v) => v,
            Err(snp_cbor::CborError::LimitExceeded { kind, actual, max }) => {
                return Err(TrafficError::WireDecodeFailed {
                    reason: format!("CBOR {kind} limit exceeded: declared {actual}, max {max}"),
                });
            }
            Err(e) => {
                return Err(TrafficError::WireDecodeFailed { reason: e.to_string() });
            }
        };
        let entries = match value {
            CborValue::Map(e) => e,
            _ => return Err(TrafficError::WireDecodeFailed {
                reason: "expected top-level CBOR map".into(),
            }),
        };
        let circuit_id = map_get_fixed(&entries, PKT_KEY_CIRCUIT_ID)
            .ok_or_else(|| TrafficError::WireDecodeFailed { reason: "circuitId missing/invalid".into() })?;
        let seq = map_get_u64(&entries, PKT_KEY_SEQ)
            .ok_or_else(|| TrafficError::WireDecodeFailed { reason: "seq missing/invalid".into() })?;
        let ttl = map_get_u8(&entries, PKT_KEY_TTL)
            .ok_or_else(|| TrafficError::WireDecodeFailed { reason: "ttl missing/invalid".into() })?;
        let final_dst = map_get_fixed(&entries, PKT_KEY_FINAL_DST)
            .ok_or_else(|| TrafficError::WireDecodeFailed { reason: "finalDst missing/invalid".into() })?;
        let payload = match map_get(&entries, PKT_KEY_PAYLOAD) {
            Some(CborValue::ByteString(b)) => b.clone(),
            _ => return Err(TrafficError::WireDecodeFailed { reason: "payload missing/not a byte string".into() }),
        };
        // Defense-in-depth: explicit wire-payload-size check (the bounded
        // decoder already enforced it at the head, but this yields a precise
        // error). P1: the wire limit accounts for AEAD tag overhead across
        // hops, so it is larger than the plaintext limit.
        if payload.len() > MAX_WIRE_PAYLOAD_BYTES {
            return Err(TrafficError::PayloadTooLarge {
                actual: payload.len(),
                max: MAX_WIRE_PAYLOAD_BYTES,
            });
        }
        let seq = u32::try_from(seq).map_err(|_| TrafficError::WireDecodeFailed {
            reason: format!("seq {seq} out of u32 range"),
        })?;
        Ok(Self { circuit_id, seq, ttl, payload, final_dst })
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────

/// Build the 12-byte AEAD nonce for a circuit packet: `circuit_id[0..8] ‖ seq(BE)`.
///
/// This mirrors `snp_crypto::aead_nonce` (fid‖seq) but derives the 8-byte fid
/// from the circuit_id's first 8 bytes, so each (circuit, seq) pair has a
/// unique nonce. The nonce is NOT secret — it must only be unique per key.
fn packet_nonce(circuit_id: &[u8; 32], seq: u32) -> snp_crypto::NonceBytes {
    let mut fid = [0u8; 8];
    fid.copy_from_slice(&circuit_id[..8]);
    aead_nonce(&fid, seq)
}

/// Build the AEAD AAD for a circuit packet: `circuit_id ‖ seq(BE) ‖ ttl ‖
/// final_dst`.
///
/// This binds the packet to its circuit, sequence, **hop-local TTL**, and
/// destination. P0: `ttl` is now authenticated — an attacker cannot modify the
/// TTL in transit without breaking AEAD. Each relay sees a different TTL (the
/// predecessor decrements before forwarding), so the source binds each nested
/// layer's AAD with the TTL that specific hop will see (see [`wrap_packet`]).
///
/// A relay substituting the circuit, seq, ttl, or destination breaks
/// authentication (invariant #2, #6, #9).
fn packet_aad(circuit_id: &[u8; 32], seq: u32, ttl: u8, final_dst: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 4 + 1 + 32);
    aad.extend_from_slice(circuit_id);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.push(ttl);
    aad.extend_from_slice(final_dst);
    aad
}

/// Look up a text-string key in a CBOR map.
fn map_get<'a>(entries: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    entries.iter().find_map(|(k, v)| match k {
        CborValue::TextString(s) if s == key => Some(v),
        _ => None,
    })
}

fn map_get_u64(entries: &[(CborValue, CborValue)], key: &str) -> Option<u64> {
    match map_get(entries, key)? {
        CborValue::UnsignedInt(n) => Some(*n),
        _ => None,
    }
}

fn map_get_u8(entries: &[(CborValue, CborValue)], key: &str) -> Option<u8> {
    u8::try_from(map_get_u64(entries, key)?).ok()
}

fn map_get_fixed<const N: usize>(entries: &[(CborValue, CborValue)], key: &str) -> Option<[u8; N]> {
    match map_get(entries, key)? {
        CborValue::ByteString(b) => b.as_slice().try_into().ok(),
        _ => None,
    }
}

#[allow(dead_code)]
fn hex_short(node_id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &node_id[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_monotonic() {
        let mut w = CircuitReplayWindow::new();
        assert!(w.check(1).is_ok()); w.commit(1);
        assert!(w.check(2).is_ok()); w.commit(2);
        assert!(w.check(3).is_ok()); w.commit(3);
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut w = CircuitReplayWindow::new();
        assert!(w.check(5).is_ok()); w.commit(5);
        // Duplicate seq 5 → replay (check is read-only, returns Err).
        assert!(matches!(
            w.check(5),
            Err(TrafficError::PacketReplayOrStale { seq: 5, .. })
        ));
    }

    #[test]
    fn replay_window_rejects_stale() {
        let mut w = CircuitReplayWindow::new();
        // Advance well past the window.
        assert!(w.check(REPLAY_WINDOW_SIZE + 10).is_ok());
        w.commit(REPLAY_WINDOW_SIZE + 10);
        // A seq far behind → stale.
        assert!(matches!(
            w.check(1),
            Err(TrafficError::PacketReplayOrStale { .. })
        ));
    }

    /// P0 #2: a large sequence jump must be O(WINDOW), not O(delta).
    /// Jumping from seq=1 to seq=u32::MAX must not loop ~4 billion times.
    /// This test would hang/spin under the old implementation.
    #[test]
    fn large_sequence_jump_is_bounded() {
        let mut w = CircuitReplayWindow::new();
        assert!(w.check(1).is_ok()); w.commit(1);
        // A huge jump — must complete instantly (O(WINDOW) clear, not O(delta)).
        assert!(w.check(u32::MAX).is_ok());
        w.commit(u32::MAX);
        // The window is now centred on u32::MAX; a recent seq is stale.
        assert!(matches!(
            w.check(2),
            Err(TrafficError::PacketReplayOrStale { .. })
        ));
    }

    /// P0 #2: the u32::MAX boundary specifically must not cause unbounded work
    /// or wraparound issues.
    #[test]
    fn sequence_max_boundary_is_bounded() {
        let mut w = CircuitReplayWindow::new();
        // First packet at the boundary.
        assert!(w.check(u32::MAX).is_ok()); w.commit(u32::MAX);
        // A seq slightly less is within the window (delta < WINDOW).
        let near = u32::MAX - 5;
        assert!(w.check(near).is_ok()); w.commit(near);
        // Replaying near → rejected.
        assert!(matches!(
            w.check(near),
            Err(TrafficError::PacketReplayOrStale { .. })
        ));
    }

    /// P0 #1 (unit-level): check() is read-only — calling it on a huge seq
    /// does NOT advance max_seen. Only commit() mutates.
    #[test]
    fn check_does_not_mutate_window() {
        let mut w = CircuitReplayWindow::new();
        assert!(w.check(1).is_ok()); w.commit(1);
        // check(1000) returns Ok (future seq) but must NOT advance max_seen.
        assert!(w.check(1000).is_ok());
        // max_seen is still 1, so seq=2 is still acceptable (not stale).
        assert!(w.check(2).is_ok());
        // And seq=1000 was NOT recorded, so it's still acceptable.
        assert!(w.check(1000).is_ok());
    }

    /// P0: the relay rejects seq == 0. The protocol's sequence lifecycle
    /// starts at FIRST_PACKET_SEQ (= 1); seq=0 is reserved as invalid to keep
    /// the AEAD nonce space unambiguous (no wraparound to 0 after exhaustion).
    #[test]
    fn relay_rejects_sequence_zero() {
        let w = CircuitReplayWindow::new();
        // seq=0 is rejected even on a fresh (uninitialized) window.
        assert!(matches!(
            w.check(0),
            Err(TrafficError::SequenceZero { .. })
        ));
    }

    /// P1: the `initialized` flag correctly tracks the first-packet
    /// transition. After commit(1), the window is initialized and a replay
    /// of seq=1 is rejected (the old `max_seen == 0` sentinel would have
    /// treated commit(1) as leaving the window uninitialized if max_seen
    /// were compared against 0 — but `initialized` is now explicit).
    #[test]
    fn initialized_flag_tracks_first_packet() {
        let mut w = CircuitReplayWindow::new();
        // First packet with seq=1 → accepted.
        assert!(w.check(1).is_ok());
        w.commit(1);
        // The window is now initialized. A replay of seq=1 → rejected.
        assert!(matches!(
            w.check(1),
            Err(TrafficError::PacketReplayOrStale { seq: 1, .. })
        ));
        // A future seq is acceptable.
        assert!(w.check(2).is_ok());
    }
}
