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
//!   Used for **bounded topology propagation** — peers exchange summaries to
//!   learn about nodes they cannot directly discover. This is NOT a full
//!   anti-entropy / request-response convergence protocol; it is one-way
//!   gossiped propagation with sequence-based replay protection. Does NOT
//!   expose endpoint data.

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, sig_contexts};

/// The SIG_CONTEXT for topology messages (GOODBYE, PeerSummary).
pub const TOPOLOGY_MSG_CONTEXT: &[u8] = b"SNP/0.1 topology-msg\0";

/// Maximum age of a `RemoteNodeHint` before it is considered stale.
///
/// A hint's freshness is determined by `now - hint.received_at`, NOT by the
/// hint's `claimed_visibility`. A third-party claim like "the target is
/// active" is a HISTORICAL claim — it cannot mean "the target is currently
/// active indefinitely." (N2.1.1.1 review-gate fix #3.)
///
/// Default: 1 hour. Hints older than this are marked STALE and excluded from
/// `gateway_hints()` until refreshed by a newer propagation message.
pub const REMOTE_HINT_MAX_AGE_SECS: u64 = 3600;

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

/// A bounded summary of a single known peer, used for bounded topology
/// propagation (NOT full anti-entropy convergence — see the module docs).
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
    pub propagation_sequence: u64,
    /// Ed25519 signature.
    pub signature: [u8; 64],
}

/// Maximum number of PeerSummary entries per message.
pub const MAX_PEER_SUMMARIES_PER_MESSAGE: usize = 256;

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

    fn sign(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(TOPOLOGY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(TOPOLOGY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// Verify the signature and sender identity consistency.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_into_verified().is_ok()
    }

    /// Verify the signature and sender identity consistency, returning a
    /// `VerifiedPeerSummaryList` on success.
    ///
    /// ## Trust boundary (N2.1.1.1 review-gate fix)
    ///
    /// `TopologyGraph::process_peer_summaries()` accepts **only**
    /// `&VerifiedPeerSummaryList`. This makes it impossible for an unverified
    /// or forged `PeerSummaryList` to mutate topology state: the only path
    /// from a raw `PeerSummaryList` to topology mutation goes through this
    /// method, which performs:
    ///   1. Ed25519 signature verification under `TOPOLOGY_MSG_CONTEXT`
    ///   2. sender NodeId ↔ Ed25519 public key binding verification (I4)
    ///
    /// This mirrors the `NodeAdvertisement → VerifiedNodeAdvertisement →
    /// AuthenticatedNodeRecord` pattern: the verified type's constructor is
    /// private, so only a successful cryptographic verification can produce
    /// one.
    ///
    /// # Errors
    /// Returns `PropagationVerifyError` if verification fails. The error
    /// variant indicates WHY (invalid signature, NodeId mismatch, or CBOR
    /// encoding failure) without leaking signing-key material.
    pub fn verify_into_verified(
        &self,
    ) -> Result<VerifiedPeerSummaryList, PropagationVerifyError> {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage)
            .map_err(|e| PropagationVerifyError::CborEncodeFailed(e.to_string()))?;
        let mut msg = Vec::with_capacity(TOPOLOGY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(TOPOLOGY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.sender_ed25519_public_key, &msg, &self.signature) {
            return Err(PropagationVerifyError::InvalidSignature);
        }
        // Verify sender NodeId ↔ Ed25519 consistency (I4).
        let expected = snp_crypto::derive_node_id(&self.sender_ed25519_public_key);
        if self.sender_node_id != expected {
            return Err(PropagationVerifyError::NodeIdKeyMismatch);
        }
        Ok(VerifiedPeerSummaryList {
            inner: PeerSummaryList {
                sender_node_id: self.sender_node_id,
                sender_ed25519_public_key: self.sender_ed25519_public_key,
                summaries: self.summaries.clone(),
                timestamp: self.timestamp,
                nonce: self.nonce,
                propagation_sequence: self.propagation_sequence,
                signature: self.signature,
            },
        })
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

/// Verification error for `PeerSummaryList::verify_into_verified()`.
///
/// The variants do NOT leak signing-key material. They describe the class of
/// failure for observability and conformance testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropagationVerifyError {
    /// The Ed25519 signature did not verify under `TOPOLOGY_MSG_CONTEXT`.
    InvalidSignature,
    /// The claimed `sender_node_id` does not match
    /// `derive_node_id(sender_ed25519_public_key)` (invariant I4).
    NodeIdKeyMismatch,
    /// Canonical CBOR encoding of the preimage failed (should be impossible
    /// for well-formed `PeerSummaryList`; indicates internal corruption).
    CborEncodeFailed(String),
}

impl std::fmt::Display for PropagationVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid propagation signature"),
            Self::NodeIdKeyMismatch => write!(f, "sender NodeId does not match Ed25519 public key"),
            Self::CborEncodeFailed(msg) => write!(f, "CBOR encode failed: {msg}"),
        }
    }
}

impl std::error::Error for PropagationVerifyError {}

/// A `PeerSummaryList` that has passed cryptographic verification.
///
/// ## Trust boundary (N2.1.1.1 review-gate fix)
///
/// This type is the ONLY input `TopologyGraph::process_peer_summaries()`
/// accepts. It cannot be constructed directly — the inner field is private,
/// and the only constructor is `PeerSummaryList::verify_into_verified()`,
/// which performs Ed25519 signature verification and NodeId↔pubkey binding
/// verification.
///
/// This mirrors the `VerifiedNodeAdvertisement` pattern: the type system
/// makes it impossible for an unverified message to reach topology mutation.
/// An attacker who manufactures a `PeerSummaryList` with an invalid signature
/// cannot obtain a `VerifiedPeerSummaryList`, and therefore cannot mutate
/// `remote_hints`, `propagation_state`, or any other topology state.
///
/// The `__t` / struct-name discriminator is NOT a security boundary — an
/// attacker can manufacture any struct name on the wire. The security
/// boundary is the private constructor + cryptographic verification.
#[derive(Debug, Clone)]
pub struct VerifiedPeerSummaryList {
    inner: PeerSummaryList,
}

impl VerifiedPeerSummaryList {
    /// The sender's NodeId.
    #[must_use]
    pub fn sender_node_id(&self) -> [u8; 32] {
        self.inner.sender_node_id
    }

    /// The sender's Ed25519 public key.
    #[must_use]
    pub fn sender_ed25519_public_key(&self) -> [u8; 32] {
        self.inner.sender_ed25519_public_key
    }

    /// The propagation sequence number.
    #[must_use]
    pub fn propagation_sequence(&self) -> u64 {
        self.inner.propagation_sequence
    }

    /// The summaries (verified to be signed by the sender).
    #[must_use]
    pub fn summaries(&self) -> &[PeerSummary] {
        &self.inner.summaries
    }

    /// The message timestamp.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }
}
