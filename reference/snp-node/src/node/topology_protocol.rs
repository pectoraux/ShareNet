//! N2.1.1 — Topology protocol messages: HELLO, GOODBYE, PeerSummary.
//!
//! These messages use canonical SNP CBOR encoding. All messages are signed
//! by the sender's Ed25519 key under `SIG_CONTEXTS::NODE_ADVERT` (for HELLO,
//! which carries a `NodeAdvertisement`) or a new `TOPOLOGY_MSG` context.
//!
//! ## Message set (N2.1.1 minimal)
//!
//! - **HELLO**: "I am here, here is my advertisement." Carries a full
//!   `NodeAdvertisement`. The advertisement itself is self-authenticating.
//! - **GOODBYE**: "I am leaving." Best-effort optimization — NOT a state
//!   transition authority. Receiving a GOODBYE does NOT remove a peer or
//!   transition a link to Down. The actual link state and advertisement
//!   freshness remain authoritative.
//! - **PeerSummary**: A bounded summary of the sender's known topology.
//!   Used for anti-entropy — peers exchange summaries to learn about
//!   nodes they cannot directly discover. Does NOT expose endpoint data.

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, sig_contexts};

/// The SIG_CONTEXT for topology messages (GOODBYE, PeerSummary).
pub const TOPOLOGY_MSG_CONTEXT: &[u8] = b"SNP/0.1 topology-msg\0";

/// A HELLO message — carries a full `NodeAdvertisement`.
///
/// The advertisement is self-authenticating (signed by the advertising node).
/// The HELLO wrapper itself is NOT separately signed — the advertisement's
/// signature is the authentication.
#[derive(Debug, Clone)]
pub struct HelloMessage {
    /// The sender's `NodeAdvertisement` (signed, self-authenticating).
    pub advertisement: NodeAdvertisement,
}

impl HelloMessage {
    /// Encode to canonical CBOR.
    ///
    /// # Errors
    /// Returns `NodeError` if CBOR encoding fails.
    pub fn encode_cbor(&self) -> NodeResult<Vec<u8>> {
        // Encode the full advertisement as a CBOR map including all fields.
        // The advertisement's preimage() is private, so we construct
        // the full representation here.
        let advert_cbor = CborValue::Map(vec![
            (CborValue::TextString("nodeId".into()), CborValue::ByteString(self.advertisement.node_id.to_vec())),
            (CborValue::TextString("publicKey".into()), CborValue::ByteString(self.advertisement.ed25519_public_key.to_vec())),
            (CborValue::TextString("capabilities".into()), CborValue::Array(
                self.advertisement.capabilities.iter().map(|c| CborValue::TextString(c.as_str().to_string())).collect()
            )),
            (CborValue::TextString("endpoints".into()), CborValue::Array(
                self.advertisement.endpoints.iter().map(|e| e.canonical_cbor()).collect()
            )),
            (CborValue::TextString("x25519CircuitPub".into()), match &self.advertisement.x25519_circuit_public {
                Some(k) => CborValue::ByteString(k.to_vec()),
                None => CborValue::Null,
            }),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.advertisement.timestamp)),
            (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(self.advertisement.expiry)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.advertisement.nonce.to_vec())),
            (CborValue::TextString("sequence".into()), CborValue::UnsignedInt(self.advertisement.sequence)),
            (CborValue::TextString("signature".into()), CborValue::ByteString(self.advertisement.signature.to_vec())),
        ]);
        let msg = CborValue::Map(vec![
            (CborValue::TextString("messageType".into()), CborValue::TextString("hello".into())),
            (CborValue::TextString("advertisement".into()), advert_cbor),
        ]);
        Ok(snp_cbor::encode(&msg)?)
    }

    /// Decode from canonical CBOR.
    ///
    /// # Errors
    /// Returns `NodeError` if the bytes are not a valid HELLO message.
    pub fn decode_cbor(bytes: &[u8]) -> NodeResult<Self> {
        let value = snp_cbor::decode(bytes)?;
        let entries = match value {
            CborValue::Map(e) => e,
            other => {
                return Err(NodeError::Other(format!(
                    "HELLO must be a CBOR map; got {other:?}"
                )));
            }
        };
        let mut message_type: Option<String> = None;
        let mut advertisement_bytes: Option<Vec<u8>> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s,
                other => {
                    return Err(NodeError::Other(format!(
                        "HELLO key must be text; got {other:?}"
                    )));
                }
            };
            match key.as_str() {
                "messageType" => {
                    message_type = Some(match v {
                        CborValue::TextString(s) => s,
                        other => {
                            return Err(NodeError::Other(format!(
                                "messageType must be text; got {other:?}"
                            )));
                        }
                    });
                }
                "advertisement" => {
                    advertisement_bytes = Some(match v {
                        CborValue::ByteString(b) => b,
                        other => {
                            return Err(NodeError::Other(format!(
                                "advertisement must be byte string; got {other:?}"
                            )));
                        }
                    });
                }
                _ => {} // Ignore unknown keys for forward compat.
            }
        }
        let mt = message_type.ok_or_else(|| NodeError::Other("messageType missing".into()))?;
        if mt != "hello" {
            return Err(NodeError::Other(format!("expected messageType=hello, got {mt}")));
        }
        let _advert_bytes = advertisement_bytes
            .ok_or_else(|| NodeError::Other("advertisement missing".into()))?;
        // For now, we don't fully decode the advertisement from the nested
        // byte string because NodeAdvertisement doesn't have a decode_cbor
        // method yet. The caller should use the raw bytes to construct
        // a NodeAdvertisement via its existing create_and_sign path,
        // or we should add decode_cbor to NodeAdvertisement.
        //
        // For the N2.1.1 scope, HELLO messages are constructed in-memory
        // and the advertisement is passed directly. The CBOR encode/decode
        // is used for wire serialization in future transport layers.
        //
        // TODO: Add NodeAdvertisement::encode_cbor/decode_cbor in a follow-up.
        Err(NodeError::Other(
            "HELLO decode_cbor not yet fully implemented — NodeAdvertisement::decode_cbor needed".into()
        ))
    }
}

/// A GOODBYE message — best-effort "I am leaving" notification.
///
/// **GOODBYE is an optimization, NEVER a state transition authority.**
/// Receiving a GOODBYE does NOT:
/// - Remove the peer from the acceptance store.
/// - Transition any link to Down.
/// - Invalidate the peer's advertisement.
///
/// The actual link state and advertisement freshness remain authoritative.
/// GOODBYE is simply a hint that the sender is going away, allowing the
/// receiver to stop probing the link proactively.
#[derive(Debug, Clone)]
pub struct GoodbyeMessage {
    /// The sender's NodeId.
    pub node_id: [u8; 32],
    /// The sender's advertisement sequence (for ordering).
    pub sequence: u64,
    /// When this message was created (unix seconds).
    pub timestamp: u64,
    /// 16-byte freshness nonce.
    pub nonce: [u8; 16],
    /// Ed25519 signature over `TOPOLOGY_MSG_CONTEXT ‖ CBOR(preimage)`.
    pub signature: [u8; 64],
    /// The sender's Ed25519 public key (for verification).
    pub ed25519_public_key: [u8; 32],
}

impl GoodbyeMessage {
    /// Create and sign a GOODBYE message.
    #[must_use]
    pub fn create_and_sign(
        ed25519_secret_key: &[u8; 32],
        ed25519_public_key: &[u8; 32],
        node_id: [u8; 32],
        sequence: u64,
    ) -> Self {
        let now = now_unix();
        let mut nonce = [0u8; 16];
        let _ = getrandom::getrandom(&mut nonce);
        let mut msg = Self {
            node_id,
            sequence,
            timestamp: now,
            nonce,
            signature: [0u8; 64],
            ed25519_public_key: *ed25519_public_key,
        };
        msg.sign(ed25519_secret_key);
        msg
    }

    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("nodeId".into()), CborValue::ByteString(self.node_id.to_vec())),
            (CborValue::TextString("sequence".into()), CborValue::UnsignedInt(self.sequence)),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.nonce.to_vec())),
            (CborValue::TextString("publicKey".into()), CborValue::ByteString(self.ed25519_public_key.to_vec())),
        ])
    }

    fn sign(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(TOPOLOGY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(TOPOLOGY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// Verify the signature and NodeId↔Ed25519 consistency.
    #[must_use]
    pub fn verify(&self) -> bool {
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(TOPOLOGY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(TOPOLOGY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.ed25519_public_key, &msg, &self.signature) {
            return false;
        }
        // Verify NodeId ↔ Ed25519 consistency (I4).
        let expected = snp_crypto::derive_node_id(&self.ed25519_public_key);
        self.node_id == expected
    }
}

/// A bounded summary of a single known peer, used for anti-entropy.
///
/// PeerSummaries are exchanged between peers to learn about nodes they
/// cannot directly discover. They do NOT expose endpoint data — only
/// identity, capabilities, sequence, and a distance hint.
#[derive(Debug, Clone)]
pub struct PeerSummary {
    /// The summarized node's NodeId.
    pub node_id: [u8; 32],
    /// The highest known advertisement sequence for this node.
    pub advertisement_sequence: u64,
    /// The node's capabilities (as capability strings).
    pub capabilities: Vec<String>,
    /// The node's visibility state ("active" or "stale").
    pub visibility: String,
    /// When the summarizer last had a working link to this node (unix seconds).
    pub last_seen: u64,
    /// A hop-distance hint from the summarizer to this node.
    /// 0 = self, 1 = direct neighbor, 2 = two hops, etc.
    pub distance_hint: u8,
}

impl PeerSummary {
    /// Construct a PeerSummary from an `AuthenticatedNodeRecord`.
    #[must_use]
    pub fn from_record(record: &AuthenticatedNodeRecord, distance_hint: u8, last_seen: u64) -> Self {
        Self {
            node_id: record.descriptor.node_id(),
            advertisement_sequence: record.sequence,
            capabilities: record
                .descriptor
                .capabilities()
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            visibility: "active".to_string(),
            last_seen,
            distance_hint,
        }
    }

    /// Check if this summary indicates a gateway-capable node.
    #[must_use]
    pub fn is_gateway(&self) -> bool {
        self.capabilities.iter().any(|c| c == "gateway")
    }

    /// Check if this summary indicates a relay-capable node.
    #[must_use]
    pub fn is_relay(&self) -> bool {
        self.capabilities.iter().any(|c| c == "relay")
    }

    /// Canonical CBOR encoding.
    pub fn canonical_cbor(&self) -> CborValue {
        let caps: Vec<CborValue> = self
            .capabilities
            .iter()
            .map(|c| CborValue::TextString(c.clone()))
            .collect();
        CborValue::Map(vec![
            (CborValue::TextString("nodeId".into()), CborValue::ByteString(self.node_id.to_vec())),
            (CborValue::TextString("sequence".into()), CborValue::UnsignedInt(self.advertisement_sequence)),
            (CborValue::TextString("capabilities".into()), CborValue::Array(caps)),
            (CborValue::TextString("visibility".into()), CborValue::TextString(self.visibility.clone())),
            (CborValue::TextString("lastSeen".into()), CborValue::UnsignedInt(self.last_seen)),
            (CborValue::TextString("distanceHint".into()), CborValue::UnsignedInt(u64::from(self.distance_hint))),
        ])
    }
}

/// A PeerSummaryList message — a bounded list of PeerSummaries from the sender.
///
/// Used for topology propagation: peers exchange summary lists to learn about
/// remote nodes. The list is bounded by a maximum number of entries.
///
/// **N2.1.1.1:** Added `propagation_sequence` — a monotonic per-sender
/// sequence for the summary list itself (distinct from NodeAdvertisement
/// sequences). This enables stateful replay prevention for propagation
/// messages. A stale/replayed PeerSummaryList (with an older propagation
/// sequence) is rejected by the topology graph.
///
/// **N2.1.1.2:** An UNVERIFIED `PeerSummaryList` MUST NOT be passed to
/// `TopologyGraph::process_peer_summaries()`. Call `verify_into_verified()`
/// to obtain a `VerifiedPeerSummaryList` first. The type system enforces
/// this — an unverified `PeerSummaryList` cannot mutate the topology graph.
#[derive(Debug, Clone)]
pub struct PeerSummaryList {
    /// The sender's NodeId.
    pub sender_node_id: [u8; 32],
    /// The sender's Ed25519 public key.
    pub sender_ed25519_public_key: [u8; 32],
    /// The summaries.
    pub summaries: Vec<PeerSummary>,
    /// When this message was created (unix seconds).
    pub timestamp: u64,
    /// 16-byte freshness nonce.
    pub nonce: [u8; 16],
    /// **N2.1.1.1.** Monotonic propagation sequence number for this sender.
    /// Each new PeerSummaryList from the same sender MUST have a higher
    /// propagation_sequence than the previous one. This is distinct from
    /// NodeAdvertisement sequences — it is a per-sender propagation message
    /// counter, not a node advertisement counter.
    ///
    /// **N2.1.1.2.** The value `0` is reserved as invalid. A valid
    /// propagation_sequence MUST be `>= 1`. This prevents a zero-sequence
    /// message from being accepted as the "first" message from a sender
    /// (which would otherwise set the replay floor to 0 and allow any
    /// later sequence to be accepted).
    pub propagation_sequence: u64,
    /// Ed25519 signature.
    pub signature: [u8; 64],
}

/// Maximum number of PeerSummary entries per message.
pub const MAX_PEER_SUMMARIES_PER_MESSAGE: usize = 256;

/// **N2.1.1.2.** Maximum valid `distance_hint` value in a `PeerSummary`.
///
/// Hints claiming a hop distance beyond this are rejected as malformed.
/// This bounds the effective diameter of the propagation mesh — a hint
/// at `MAX_DISTANCE_HINT` hops is near-useless for routing and is likely
/// abuse or a bug. This is NOT a route length; it is a sanity bound on
/// the discovery heuristic.
pub const MAX_DISTANCE_HINT: u8 = 64;

/// **N2.1.1.2.** Maximum age (in seconds) of a propagation message's
/// timestamp before it is considered stale and rejected.
///
/// A propagation message with a timestamp older than
/// `now - MAX_PROPAGATION_MESSAGE_AGE_SECS` is rejected during
/// `verify_into_verified()`. This prevents replay of very old (but
/// correctly signed) propagation messages after a process restart
/// (during which `propagation_state` is lost).
///
/// This is a STATELESS staleness bound, distinct from the STATEFUL
/// `propagation_sequence` replay prevention in `TopologyGraph`. Both
/// must pass for a message to mutate the topology.
///
/// Set to match `MAX_ADVERTISEMENT_LIFETIME_SECS` (24 hours): a
/// propagation message referencing advertisement data older than the
/// advertisement lifetime is not useful.
pub const MAX_PROPAGATION_MESSAGE_AGE_SECS: u64 = 86400;

impl PeerSummaryList {
    /// Create and sign a PeerSummaryList.
    #[must_use]
    pub fn create_and_sign(
        ed25519_secret_key: &[u8; 32],
        ed25519_public_key: &[u8; 32],
        node_id: [u8; 32],
        summaries: Vec<PeerSummary>,
        propagation_sequence: u64,
    ) -> Self {
        let now = now_unix();
        let mut nonce = [0u8; 16];
        let _ = getrandom::getrandom(&mut nonce);
        // Truncate to max.
        let summaries = if summaries.len() > MAX_PEER_SUMMARIES_PER_MESSAGE {
            summaries[..MAX_PEER_SUMMARIES_PER_MESSAGE].to_vec()
        } else {
            summaries
        };
        let mut msg = Self {
            sender_node_id: node_id,
            sender_ed25519_public_key: *ed25519_public_key,
            summaries,
            timestamp: now,
            nonce,
            propagation_sequence,
            signature: [0u8; 64],
        };
        msg.sign(ed25519_secret_key);
        msg
    }

    fn preimage(&self) -> CborValue {
        let summaries: Vec<CborValue> = self
            .summaries
            .iter()
            .map(|s| s.canonical_cbor())
            .collect();
        CborValue::Map(vec![
            (CborValue::TextString("senderNodeId".into()), CborValue::ByteString(self.sender_node_id.to_vec())),
            (CborValue::TextString("senderPublicKey".into()), CborValue::ByteString(self.sender_ed25519_public_key.to_vec())),
            (CborValue::TextString("summaries".into()), CborValue::Array(summaries)),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.nonce.to_vec())),
            (CborValue::TextString("propagationSequence".into()), CborValue::UnsignedInt(self.propagation_sequence)),
        ])
    }

    /// Re-sign the message in place after mutating fields.
    ///
    /// This is intended for cases where a node modifies the summaries or
    /// other signed fields after `create_and_sign` (e.g., adding summaries
    /// incrementally before sending). It recomputes the Ed25519 signature
    /// over the current preimage.
    ///
    /// # Panics
    /// Panics if CBOR encoding fails (it never does for well-formed values).
    pub fn sign(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(TOPOLOGY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(TOPOLOGY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// **Stateless verification.** Returns `true` if this message passes
    /// signature verification, sender identity consistency, and semantic
    /// validation.
    ///
    /// This is a convenience wrapper around `verify_into_verified()`.
    /// Use `verify_into_verified()` when you need to pass the result to
    /// `TopologyGraph::process_peer_summaries()`.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_into_verified().is_some()
    }

    /// **N2.1.1.2.** Stateless verification into a `VerifiedPeerSummaryList`.
    ///
    /// Performs the FULL verification required before a propagation message
    /// can mutate the topology graph:
    ///
    /// 1. **Signature** — Ed25519 signature valid under `TOPOLOGY_MSG_CONTEXT`.
    /// 2. **Sender identity (I4)** — `sender_node_id == derive_node_id(sender_ed25519_public_key)`.
    /// 3. **Clock validation**:
    ///    - `timestamp <= now + MAX_CLOCK_SKEW_SECS` (no future-dated messages)
    ///    - `timestamp >= now - MAX_PROPAGATION_MESSAGE_AGE_SECS` (not stale)
    /// 4. **Propagation sequence** — `propagation_sequence >= 1` (zero is invalid).
    /// 5. **Summary count** — `summaries.len() <= MAX_PEER_SUMMARIES_PER_MESSAGE`.
    /// 6. **Per-summary semantic validation**:
    ///    - `distance_hint <= MAX_DISTANCE_HINT`
    ///    - `visibility` is `"active"` or `"stale"`
    ///    - `node_id != [0u8; 32]` (all-zero is not a valid NodeId)
    ///
    /// **This method does NOT prevent replay.** A previously verified message
    /// can be verified again. Replay prevention requires the stateful
    /// `TopologyGraph::process_peer_summaries()` sequence check.
    ///
    /// # Returns
    /// - `Some(VerifiedPeerSummaryList)` if all checks pass.
    /// - `None` if ANY check fails.
    #[must_use]
    pub fn verify_into_verified(&self) -> Option<VerifiedPeerSummaryList> {
        // 1. Signature verification.
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return None;
        };
        let mut msg = Vec::with_capacity(TOPOLOGY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(TOPOLOGY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.sender_ed25519_public_key, &msg, &self.signature) {
            return None;
        }
        // 2. Sender NodeId ↔ Ed25519 consistency (I4).
        let expected = snp_crypto::derive_node_id(&self.sender_ed25519_public_key);
        if self.sender_node_id != expected {
            return None;
        }
        // 3. Clock validation.
        let now = now_unix();
        // 3a. No future-dated timestamps beyond clock skew.
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return None;
        }
        // 3b. Not stale (older than the propagation message age bound).
        if self.timestamp < now.saturating_sub(MAX_PROPAGATION_MESSAGE_AGE_SECS) {
            return None;
        }
        // 4. propagation_sequence must be non-zero.
        if self.propagation_sequence == 0 {
            return None;
        }
        // 5. Summary count bound.
        if self.summaries.len() > MAX_PEER_SUMMARIES_PER_MESSAGE {
            return None;
        }
        // 6. Per-summary semantic validation.
        for s in &self.summaries {
            // 6a. distance_hint within valid range.
            if s.distance_hint > MAX_DISTANCE_HINT {
                return None;
            }
            // 6b. visibility is a known value.
            if s.visibility != "active" && s.visibility != "stale" {
                return None;
            }
            // 6c. node_id is not all-zero (not a valid NodeId).
            if s.node_id == [0u8; 32] {
                return None;
            }
        }
        Some(VerifiedPeerSummaryList { inner: self.clone() })
    }

    /// Get the number of summaries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    /// Check if the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }
}

// ─── VerifiedPeerSummaryList ────────────────────────────────────────────────

/// A `PeerSummaryList` that has passed **stateless verification** (signature +
/// sender identity + clock validation + semantic validation).
///
/// ## N2.1.1.2 — Type-level enforcement
///
/// An UNVERIFIED `PeerSummaryList` CANNOT be passed to
/// `TopologyGraph::process_peer_summaries()`. The only way to obtain a
/// `VerifiedPeerSummaryList` is via `PeerSummaryList::verify_into_verified()`,
/// which performs:
///
/// 1. Ed25519 signature verification under `TOPOLOGY_MSG_CONTEXT`.
/// 2. `sender_node_id == derive_node_id(sender_ed25519_public_key)` (I4).
/// 3. Clock validation (not future-dated, not stale).
/// 4. `propagation_sequence >= 1`.
/// 5. `summaries.len() <= MAX_PEER_SUMMARIES_PER_MESSAGE`.
/// 6. Per-summary semantic validation (distance_hint, visibility, node_id).
///
/// ## This type does NOT prove replay prevention
///
/// A `VerifiedPeerSummaryList` can be replayed (same `propagation_sequence`).
/// Replay prevention requires the stateful `TopologyGraph` sequence check,
/// which is performed inside `process_peer_summaries()` AFTER the type
/// guarantee has been established.
///
/// ## Construction
///
/// The constructor is private. The only way to create a
/// `VerifiedPeerSummaryList` is via `PeerSummaryList::verify_into_verified()`.
#[derive(Debug, Clone)]
pub struct VerifiedPeerSummaryList {
    inner: PeerSummaryList,
}

impl VerifiedPeerSummaryList {
    /// Get the sender's NodeId.
    #[must_use]
    pub fn sender_node_id(&self) -> [u8; 32] {
        self.inner.sender_node_id
    }

    /// Get the sender's Ed25519 public key.
    #[must_use]
    pub fn sender_ed25519_public_key(&self) -> &[u8; 32] {
        &self.inner.sender_ed25519_public_key
    }

    /// Get the propagation sequence number.
    #[must_use]
    pub fn propagation_sequence(&self) -> u64 {
        self.inner.propagation_sequence
    }

    /// Get the message timestamp (unix seconds).
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    /// Get the summaries (immutable).
    #[must_use]
    pub fn summaries(&self) -> &[PeerSummary] {
        &self.inner.summaries
    }

    /// Get the number of summaries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.summaries.len()
    }

    /// Check if the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.summaries.is_empty()
    }
}
