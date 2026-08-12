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
/// Used for anti-entropy: peers exchange summary lists to learn about
/// remote nodes. The list is bounded by a maximum number of entries.
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
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(TOPOLOGY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(TOPOLOGY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.sender_ed25519_public_key, &msg, &self.signature) {
            return false;
        }
        // Verify sender NodeId ↔ Ed25519 consistency (I4).
        let expected = snp_crypto::derive_node_id(&self.sender_ed25519_public_key);
        self.sender_node_id == expected
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
