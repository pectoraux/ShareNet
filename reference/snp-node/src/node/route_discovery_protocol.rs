//! N2.1.3 — Distributed Route Discovery Protocol (single-step + recursive).
//!
//! ## What is implemented
//!
//! ### Single-step protocol (N2.1.3 / N2.1.3.1)
//!
//! - Signed `NextHopQuery` / `NextHopResponse` messages.
//! - `PendingRouteQuery` state for stateful response acceptance.
//! - Expected-responder binding (response must come from the queried neighbor).
//! - Replay protection (each query can only be consumed once).
//! - Freshness validation (MAX_ROUTE_QUERY_AGE, MAX_ROUTE_RESPONSE_AGE).
//! - Transactional query consumption (failed validation does NOT consume).
//! - `max_hops` validation (>0, reject invalid) + decrement semantics.
//! - `RoutingAssertion` type — individually signed by the responder.
//! - `DistributedRouteResolver` trait — stateful interface for distributed
//!   protocol resolution (separate from the stateless `DestinationResolver`).
//! - `QueryProvenance` — data structure for recursive query chaining.
//! - `NextHopResolver` implementing `DistributedRouteResolver` for
//!   single-step resolution with persistent state.
//!
//! ### Recursive protocol (N2.1.3.2)
//!
//! - `ForwardedQuery` — the canonical recursive protocol message, carrying
//!   parent binding (parent_query_id, parent_responder_node_id,
//!   parent_query_hash), visited_nodes (loop prevention), and hop budget.
//! - `ForwardingNode` — test-only protocol participant that verifies
//!   incoming queries, creates new ForwardedQuery instances with decremented
//!   budget + updated visited_nodes + parent binding, and forwards via
//!   `RecursiveNextHopTransport`.
//! - `SignedResponseStep` — per-hop signed response step binding the
//!   responder's contribution to the actual query hashes, destination
//!   state, hop budget, and next-hop identity.
//! - `RecursiveRouteResponse` — unsigned transport envelope carrying the
//!   accumulated chain. Envelope fields are derived/untrusted; authority
//!   comes from the signed `SignedResponseStep` chain, signed
//!   `RoutingAssertion`s, and authenticated `NodeAdvertisement`s.
//! - `DistributedRouteResolution` — the result of recursive discovery,
//!   verified via `verify()` (checks assertion signatures, response step
//!   signatures, chain coherence, hop budget, loop prevention, destination
//!   capabilities) before conversion to `Route` via `into_route()`.
//!
//! ## Protocol overview (recursive)
//!
//! ```text
//! A (wants route to G)
//!     │
//!     │ 1. Creates ForwardedQuery(budget=16, visited=[A], parent=none)
//!     │ 2. Sends to B via RecursiveNextHopTransport
//!     ▼
//! B (A's authenticated neighbor)
//!     │
//!     │ 3. Verifies ForwardedQuery (signature, parent binding, I4)
//!     │ 4. Checks visited_nodes (loop prevention)
//!     │ 5. Checks hop budget (> 0)
//!     │ 6. If B IS destination → terminal response
//!     │ 7. Otherwise → creates NEW ForwardedQuery:
//!     │    - Decremented budget (15)
//!     │    - Updated visited_nodes ([A, B])
//!     │    - Parent binding (parent_query_hash = SHA-256 of received query)
//!     │ 8. Forwards to C via transport
//!     ▼
//! C
//!     │
//!     │ 9. Same verification + forwarding to G
//!     ▼
//! G (destination)
//!     │
//!     │ 10. Returns RecursiveRouteResponse with destination_reached=true
//!     ▼
//! C → B → A
//!     │
//!     │ 11. Each forwarder prepends its SignedResponseStep +
//!     │     RoutingAssertion + record to the response
//!     ▼
//! A
//!     │
//!     │ 12. Constructs DistributedRouteResolution from response
//!     │ 13. verify() checks all signatures + chain coherence
//!     │ 14. into_route() → validated Route with RouteCommitment
//! ```
//!
//! ## Security model
//!
//! - Every `NextHopQuery`, `NextHopResponse`, `ForwardedQuery`,
//!   `RoutingAssertion`, and `SignedResponseStep` is **signed** by the
//!   sender under `ROUTE_DISCOVERY_MSG_CONTEXT`.
//! - The sender's NodeId is bound to the Ed25519 public key (I4 consistency).
//! - `parent_query_hash` binds each forwarded query to the ACTUAL parent
//!   message (SHA-256 of the complete parent ForwardedQuery).
//! - `SignedResponseStep` chain coherence: `step[i].sent_query_hash ==
//!   step[i+1].received_query_hash`.
//! - Initial query binding: `response_steps[0].received_query_hash` must
//!   match `initial_query.compute_hash()`.
//! - `RecursiveRouteResponse` envelope fields are derived/untrusted —
//!   authority comes from the signed chain, not the envelope.
//!
//! ## What is NOT implemented
//!
//! - ~~Real network transport (only `InMemoryRecursiveTransport`).~~
//!   **N2.2.1:** `TcpRecursiveTransport` is implemented in
//!   `tcp_route_transport.rs` — a production `RecursiveNextHopTransport`
//!   that uses real TCP sockets, SNP-IK/0.1 authentication, and the
//!   canonical CBOR serialization added below.
//! - ~~Wire serialization/deserialization.~~
//!   **N2.2.1:** canonical CBOR `encode_cbor()` / `decode_cbor()` are
//!   implemented on `ForwardedQuery`, `RecursiveRouteResponse`,
//!   `SignedResponseStep`, `RoutingAssertion`, `NodeAdvertisement`,
//!   `AuthenticatedNodeRecord`, and `QueryStep`. The wire format for
//!   `ForwardedQuery` is byte-identical to `compute_hash()`'s preimage,
//!   preserving the `parent_query_hash` binding across wire round-trips.
//! - Proof that the responder has a usable link to the next hop
//!   (the response is a routing assertion, not a link proof).
//! - AEAD encryption of the frame payload. The SNP-IK handshake derives
//!   directional link keys, but the frame payload is sent in plaintext
//!   (it carries its own Ed25519 signatures). Future: encrypt the frame
//!   payload with the derived link keys for confidentiality.
//! - Connection pooling. Each `forward_query` call opens a fresh TCP
//!   connection and tears it down after one query/response.
//!
//! ## N2.1.3.1.1: Stateful composition
//!
//! The `DestinationResolver` trait is **stateless** (`&self`) and remains
//! for LOCAL/pure lookup. The `DistributedRouteResolver` trait is
//! **stateful** (`&mut self`) and owns `PendingRouteQuery` state across
//! query/response exchanges. The `NextHopResolver` no longer implements
//! `DestinationResolver` — callers must use `DistributedRouteResolver`
//! for distributed resolution.

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, sha256, sig_contexts};

/// The SIG_CONTEXT for route-discovery messages.
pub const ROUTE_DISCOVERY_MSG_CONTEXT: &[u8] = b"SNP/0.1 route-discovery\0";

// ════════════════════════════════════════════════════════════════════════════
// N2.2.1 — Canonical CBOR encode/decode helpers
//
// Small helpers used by the encode_cbor / decode_cbor implementations on the
// protocol message types. The canonical-CBOR wire format and the canonical
// CBOR used for hash preimages (e.g. `ForwardedQuery::compute_hash()`) MUST be
// byte-identical — see the security note on `ForwardedQuery::compute_hash()`.
// ════════════════════════════════════════════════════════════════════════════

/// Get the entries of a `CborValue::Map` as a slice. Returns `None` for
/// non-map values.
fn cbor_map_entries(value: &CborValue) -> Option<&[(CborValue, CborValue)]> {
    match value {
        CborValue::Map(entries) => Some(entries.as_slice()),
        _ => None,
    }
}

/// Look up a text-keyed field in a CBOR map. Linear scan — these maps are
/// tiny (≤16 entries) so a HashMap is not worth the allocation.
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

/// Extract a fixed-size byte array from a `CborValue::ByteString`. Returns
/// `None` if the value is not a byte string or has the wrong length.
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

/// Extract a `Vec<[u8; 32]>` from a `CborValue::Array` of `ByteString(32)`.
fn cbor_get_byte_array(value: &CborValue) -> Option<Vec<[u8; 32]>> {
    let arr = match value {
        CborValue::Array(items) => items,
        _ => return None,
    };
    arr.iter().map(cbor_get_fixed_bytes::<32>).collect()
}

/// Extract a `u64` from a `CborValue::UnsignedInt`.
fn cbor_get_u64(value: &CborValue) -> Option<u64> {
    match value {
        CborValue::UnsignedInt(n) => Some(*n),
        _ => None,
    }
}

/// Extract a `bool` from a `CborValue::Bool`.
fn cbor_get_bool(value: &CborValue) -> Option<bool> {
    match value {
        CborValue::Bool(b) => Some(*b),
        _ => None,
    }
}

/// Extract a `String` from a `CborValue::TextString`.
fn cbor_get_string(value: &CborValue) -> Option<String> {
    match value {
        CborValue::TextString(s) => Some(s.clone()),
        _ => None,
    }
}

/// Extract an `Option<[u8; 32]>` from a CBOR value: `Null` → `None`,
/// `ByteString(32)` → `Some`.
fn cbor_get_optional_bytes_32(value: &CborValue) -> Option<Option<[u8; 32]>> {
    match value {
        CborValue::Null => Some(None),
        CborValue::ByteString(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Some(Some(out))
        }
        _ => None,
    }
}

/// Maximum number of NextHopResponse hops allowed in a single response
/// chain (prevents amplification). Reserved for future recursive forwarding.
pub const MAX_RESPONSE_HOPS: u8 = 16;

/// **N2.1.3.1.** Maximum age (in seconds) of a route query. Queries older
/// than this are rejected.
pub const MAX_ROUTE_QUERY_AGE_SECS: u64 = 60; // 1 minute

/// **N2.1.3.1.** Maximum age (in seconds) of a route response. Responses
/// older than this are rejected.
pub const MAX_ROUTE_RESPONSE_AGE_SECS: u64 = 60; // 1 minute

/// **N2.1.3.1.** Maximum clock skew (in seconds) for future-dated
/// queries/responses.
pub const MAX_ROUTE_CLOCK_SKEW_SECS: u64 = 30;

// ════════════════════════════════════════════════════════════════════════════
// NextHopQuery
// ════════════════════════════════════════════════════════════════════════════

/// A signed request from a client asking a neighbor for the next hop
/// toward a destination.
///
/// ## Fields
/// - `source_node_id`: The querying node's NodeId.
/// - `source_ed25519_public_key`: The querying node's Ed25519 public key.
/// - `destination_node_id`: The destination NodeId the source wants to reach.
/// - `query_id`: A unique 16-byte nonce for this query (correlation ID).
/// - `timestamp`: When the query was created (unix seconds).
/// - `max_hops`: The maximum remaining hops the source will accept.
///   Must be > 0. Reserved for future recursive forwarding.
/// - `signature`: Ed25519 signature over the preimage.
#[derive(Debug, Clone)]
pub struct NextHopQuery {
    /// The querying node's NodeId.
    pub source_node_id: [u8; 32],
    /// The querying node's Ed25519 public key.
    pub source_ed25519_public_key: [u8; 32],
    /// The destination NodeId the source wants to reach.
    pub destination_node_id: [u8; 32],
    /// A unique 16-byte nonce for this query (correlation ID).
    pub query_id: [u8; 16],
    /// When this query was created (unix seconds).
    pub timestamp: u64,
    /// The maximum remaining hops the source will accept.
    /// Must be > 0. Reserved for future recursive forwarding.
    pub max_hops: u8,
    /// Ed25519 signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage)`.
    pub signature: [u8; 64],
}

impl NextHopQuery {
    /// Create and sign a `NextHopQuery`.
    ///
    /// # Panics
    /// Panics if `max_hops` is 0 (invalid — query would not be forwardable).
    #[must_use]
    pub fn create_and_sign(
        source_ed25519_secret_key: &[u8; 32],
        source_ed25519_public_key: &[u8; 32],
        source_node_id: [u8; 32],
        destination_node_id: [u8; 32],
        max_hops: u8,
    ) -> Self {
        assert!(max_hops > 0, "max_hops must be > 0");
        let now = now_unix();
        let mut query_id = [0u8; 16];
        let _ = getrandom::getrandom(&mut query_id);
        let mut msg = Self {
            source_node_id,
            source_ed25519_public_key: *source_ed25519_public_key,
            destination_node_id,
            query_id,
            timestamp: now,
            max_hops,
            signature: [0u8; 64],
        };
        msg.sign(source_ed25519_secret_key);
        msg
    }

    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("sourceNodeId".into()), CborValue::ByteString(self.source_node_id.to_vec())),
            (CborValue::TextString("sourcePublicKey".into()), CborValue::ByteString(self.source_ed25519_public_key.to_vec())),
            (CborValue::TextString("destinationNodeId".into()), CborValue::ByteString(self.destination_node_id.to_vec())),
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("maxHops".into()), CborValue::UnsignedInt(u64::from(self.max_hops))),
        ])
    }

    /// Re-sign the message (after field mutation).
    pub fn sign(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// Verify the signature and sender identity consistency (I4).
    ///
    /// Does NOT verify freshness or max_hops — those require stateful
    /// validation via `PendingRouteQuery`.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.source_ed25519_public_key, &msg, &self.signature) {
            return false;
        }
        let expected = snp_crypto::derive_node_id(&self.source_ed25519_public_key);
        self.source_node_id == expected
    }

    /// **N2.1.3.1.** Validate the query's freshness and max_hops.
    ///
    /// Returns `true` if:
    /// - `max_hops > 0`
    /// - `timestamp` is not too far in the future (≤ now + skew)
    /// - `timestamp` is not too old (≥ now - MAX_ROUTE_QUERY_AGE_SECS)
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        if self.max_hops == 0 {
            return false;
        }
        let now = now_unix();
        if self.timestamp > now.saturating_add(MAX_ROUTE_CLOCK_SKEW_SECS) {
            return false; // Future-dated.
        }
        if self.timestamp < now.saturating_sub(MAX_ROUTE_QUERY_AGE_SECS) {
            return false; // Too old.
        }
        true
    }

    /// **N2.1.3.1.1.** Get the remaining hop budget.
    #[must_use]
    pub fn remaining_hops(&self) -> u8 {
        self.max_hops
    }

    /// **N2.1.3.1.1.** Decrement `max_hops` for forwarding.
    ///
    /// Returns `false` if the hop budget is exhausted (max_hops was 0).
    /// The decrement is saturating — it cannot underflow.
    ///
    /// **This method does NOT re-sign the query.** The caller MUST call
    /// `sign()` after mutation if the query will be re-transmitted.
    /// (Future: for recursive forwarding, the forwarding node creates a
    /// NEW query with a decremented max_hops and its own signature.)
    ///
    /// # Returns
    /// - `true` if the hop budget was successfully decremented.
    /// - `false` if the hop budget is exhausted.
    pub fn decrement_max_hops(&mut self) -> bool {
        if self.max_hops == 0 {
            return false;
        }
        self.max_hops = self.max_hops.saturating_sub(1);
        true
    }
}

// ════════════════════════════════════════════════════════════════════════════
// QueryProvenance (N2.1.3.1.1) — for future recursive query chaining
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.1.1.** Provenance for a route-discovery query — tracks the
/// chain of queries that led to the current resolution step.
///
/// ## Purpose
///
/// In the current single-step implementation, `QueryProvenance` has a
/// single entry (the initial query). In the future recursive
/// implementation (N2.1.3.2), each forwarding step will append a new
/// entry, creating a chain:
///
/// ```text
/// QueryProvenance {
///     chain: [
///         QueryStep { source: A, responder: B, query_id: Q1 },
///         QueryStep { source: B, responder: C, query_id: Q2 },
///         QueryStep { source: C, responder: G, query_id: Q3 },
///     ]
/// }
/// ```
///
/// Each step is bound to the preceding query context, preventing
/// assertion injection attacks where a malicious node provides a
/// response for a different query chain.
///
/// ## N2.1.3.1.1
///
/// This data structure exists to make the next milestone (recursive
/// discovery) composable without redesigning the protocol state model.
/// Recursive forwarding is NOT yet implemented.
#[derive(Debug, Clone)]
pub struct QueryProvenance {
    /// The ordered chain of query steps.
    pub chain: Vec<QueryStep>,
}

/// A single step in a query provenance chain.
#[derive(Debug, Clone)]
pub struct QueryStep {
    /// The NodeId of the node that sent the query.
    pub source_node_id: [u8; 32],
    /// The NodeId of the node that was queried (expected responder).
    pub responder_node_id: [u8; 32],
    /// The query_id for this step.
    pub query_id: [u8; 16],
    /// The remaining max_hops at this step.
    pub remaining_hops: u8,
}

impl QueryProvenance {
    /// Create a new empty provenance chain.
    #[must_use]
    pub fn new() -> Self {
        Self { chain: Vec::new() }
    }

    /// Create a provenance with a single initial step.
    #[must_use]
    pub fn from_initial_step(step: QueryStep) -> Self {
        Self { chain: vec![step] }
    }

    /// Append a new step to the provenance chain.
    pub fn append_step(&mut self, step: QueryStep) {
        self.chain.push(step);
    }

    /// Get the number of steps in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Get the last step in the chain (the most recent query).
    #[must_use]
    pub fn last_step(&self) -> Option<&QueryStep> {
        self.chain.last()
    }

    /// Get the remaining hop budget from the last step.
    #[must_use]
    pub fn remaining_hops(&self) -> Option<u8> {
        self.chain.last().map(|s| s.remaining_hops)
    }
}

impl Default for QueryProvenance {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryStep {
    /// **N2.2.1.** Canonical CBOR encoding of this `QueryStep`.
    #[must_use]
    pub fn to_cbor_map(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("sourceNodeId".into()), CborValue::ByteString(self.source_node_id.to_vec())),
            (CborValue::TextString("responderNodeId".into()), CborValue::ByteString(self.responder_node_id.to_vec())),
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("remainingHops".into()), CborValue::UnsignedInt(u64::from(self.remaining_hops))),
        ])
    }

    /// **N2.2.1.** Decode a `QueryStep` from a canonical CBOR map.
    #[must_use]
    pub fn from_cbor_map(value: &CborValue) -> Option<Self> {
        let map = cbor_map_entries(value)?;
        Some(Self {
            source_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "sourceNodeId")?)?,
            responder_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "responderNodeId")?)?,
            query_id: cbor_get_fixed_bytes(cbor_map_get(map, "queryId")?)?,
            remaining_hops: u8::try_from(cbor_get_u64(cbor_map_get(map, "remainingHops")?)?).ok()?,
        })
    }

    /// **N2.2.1.** Encode to canonical CBOR bytes for wire transmission.
    #[must_use]
    pub fn encode_cbor(&self) -> Vec<u8> {
        snp_cbor::encode(&self.to_cbor_map()).expect("CBOR encode never fails for QueryStep")
    }

    /// **N2.2.1.** Decode from canonical CBOR bytes.
    #[must_use]
    pub fn decode_cbor(bytes: &[u8]) -> Option<Self> {
        Self::from_cbor_map(&snp_cbor::decode(bytes).ok()?)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NextHopResponse + NextHopResult
// ════════════════════════════════════════════════════════════════════════════

/// The result of a next-hop query — either a next hop was found, or not.
#[derive(Debug, Clone)]
pub enum NextHopResult {
    /// A next hop was found. Contains the next-hop node's advertisement
    /// (or the destination's advertisement if the responder knows it
    /// directly).
    Found {
        /// The NodeId of the next hop toward the destination.
        next_hop_node_id: [u8; 32],
        /// The next-hop node's advertisement (NOT yet verified by the
        /// receiver — the receiver MUST call `verify_into_verified()`).
        advertisement: NodeAdvertisement,
        /// Whether this next hop IS the destination (the query is complete).
        is_destination: bool,
    },
    /// The responder does not know a path to the destination.
    NotFound,
}

/// A signed response from a neighbor answering a `NextHopQuery`.
///
/// ## Security
///
/// The response is signed by the responder and includes the `query_id`
/// from the original query. The receiver MUST verify:
///
/// 1. Signature + I4 consistency (`verify_signature()`).
/// 2. `responder_node_id == expected_responder` (the neighbor that was queried).
/// 3. `query_id` matches a pending `PendingRouteQuery`.
/// 4. The pending query is not expired and not already consumed.
/// 5. The response timestamp is fresh (not too old, not future-dated).
/// 6. The advertisement verifies independently via `verify_into_verified()`.
#[derive(Debug, Clone)]
pub struct NextHopResponse {
    /// The responder's NodeId.
    pub responder_node_id: [u8; 32],
    /// The responder's Ed25519 public key.
    pub responder_ed25519_public_key: [u8; 32],
    /// The query_id from the original `NextHopQuery` (binds response to query).
    pub query_id: [u8; 16],
    /// When this response was created (unix seconds).
    pub timestamp: u64,
    /// The result: Found (with next hop + advertisement) or NotFound.
    pub result: NextHopResult,
    /// Ed25519 signature over the preimage.
    pub signature: [u8; 64],
}

impl NextHopResponse {
    /// Create and sign a `NextHopResponse` with a `Found` result.
    #[must_use]
    pub fn create_found_and_sign(
        responder_ed25519_secret_key: &[u8; 32],
        responder_ed25519_public_key: &[u8; 32],
        responder_node_id: [u8; 32],
        query_id: [u8; 16],
        next_hop_node_id: [u8; 32],
        advertisement: NodeAdvertisement,
        is_destination: bool,
    ) -> Self {
        let now = now_unix();
        let mut msg = Self {
            responder_node_id,
            responder_ed25519_public_key: *responder_ed25519_public_key,
            query_id,
            timestamp: now,
            result: NextHopResult::Found {
                next_hop_node_id,
                advertisement,
                is_destination,
            },
            signature: [0u8; 64],
        };
        msg.sign(responder_ed25519_secret_key);
        msg
    }

    /// Create and sign a `NextHopResponse` with a `NotFound` result.
    #[must_use]
    pub fn create_not_found_and_sign(
        responder_ed25519_secret_key: &[u8; 32],
        responder_ed25519_public_key: &[u8; 32],
        responder_node_id: [u8; 32],
        query_id: [u8; 16],
    ) -> Self {
        let now = now_unix();
        let mut msg = Self {
            responder_node_id,
            responder_ed25519_public_key: *responder_ed25519_public_key,
            query_id,
            timestamp: now,
            result: NextHopResult::NotFound,
            signature: [0u8; 64],
        };
        msg.sign(responder_ed25519_secret_key);
        msg
    }

    fn preimage(&self) -> CborValue {
        let result_cbor = match &self.result {
            NextHopResult::Found { next_hop_node_id, advertisement, is_destination } => {
                CborValue::Map(vec![
                    (CborValue::TextString("type".into()), CborValue::TextString("found".into())),
                    (CborValue::TextString("nextHopNodeId".into()), CborValue::ByteString(next_hop_node_id.to_vec())),
                    (CborValue::TextString("advertisement".into()), advertisement_canonical_cbor(advertisement)),
                    (CborValue::TextString("isDestination".into()), CborValue::Bool(*is_destination)),
                ])
            }
            NextHopResult::NotFound => {
                CborValue::Map(vec![
                    (CborValue::TextString("type".into()), CborValue::TextString("notfound".into())),
                ])
            }
        };
        CborValue::Map(vec![
            (CborValue::TextString("responderNodeId".into()), CborValue::ByteString(self.responder_node_id.to_vec())),
            (CborValue::TextString("responderPublicKey".into()), CborValue::ByteString(self.responder_ed25519_public_key.to_vec())),
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("result".into()), result_cbor),
        ])
    }

    /// Re-sign the message (after field mutation).
    pub fn sign(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// Verify the signature and responder identity consistency (I4).
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.responder_ed25519_public_key, &msg, &self.signature) {
            return false;
        }
        let expected = snp_crypto::derive_node_id(&self.responder_ed25519_public_key);
        self.responder_node_id == expected
    }

    /// **N2.1.3.1.** Validate the response's freshness.
    ///
    /// Returns `true` if:
    /// - `timestamp` is not too far in the future (≤ now + skew)
    /// - `timestamp` is not too old (≥ now - MAX_ROUTE_RESPONSE_AGE_SECS)
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        let now = now_unix();
        if self.timestamp > now.saturating_add(MAX_ROUTE_CLOCK_SKEW_SECS) {
            return false; // Future-dated.
        }
        if self.timestamp < now.saturating_sub(MAX_ROUTE_RESPONSE_AGE_SECS) {
            return false; // Too old.
        }
        true
    }

    /// Check if this response's `query_id` matches a given query.
    #[must_use]
    pub fn matches_query_id(&self, query_id: &[u8; 16]) -> bool {
        &self.query_id == query_id
    }
}

/// Encode a `NodeAdvertisement` to canonical CBOR for signing.
fn advertisement_canonical_cbor(advert: &NodeAdvertisement) -> CborValue {
    CborValue::Map(vec![
        (CborValue::TextString("nodeId".into()), CborValue::ByteString(advert.node_id.to_vec())),
        (CborValue::TextString("publicKey".into()), CborValue::ByteString(advert.ed25519_public_key.to_vec())),
        (CborValue::TextString("capabilities".into()), CborValue::Array(
            advert.capabilities.iter().map(|c| CborValue::TextString(c.as_str().to_string())).collect()
        )),
        (CborValue::TextString("endpoints".into()), CborValue::Array(
            advert.endpoints.iter().map(|e| e.canonical_cbor()).collect()
        )),
        (CborValue::TextString("x25519CircuitPub".into()), match &advert.x25519_circuit_public {
            Some(k) => CborValue::ByteString(k.to_vec()),
            None => CborValue::Null,
        }),
        (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(advert.timestamp)),
        (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(advert.expiry)),
        (CborValue::TextString("nonce".into()), CborValue::ByteString(advert.nonce.to_vec())),
        (CborValue::TextString("sequence".into()), CborValue::UnsignedInt(advert.sequence)),
        (CborValue::TextString("signature".into()), CborValue::ByteString(advert.signature.to_vec())),
    ])
}

// ════════════════════════════════════════════════════════════════════════════
// PendingRouteQuery (N2.1.3.1) — stateful query tracking
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.1.** State tracking for an outstanding route query.
///
/// A `PendingRouteQuery` is created when a query is sent and consumed when
/// a valid response is received. This provides:
///
/// - **Expected-responder binding:** The response must come from the
///   neighbor that was queried.
/// - **Replay protection:** Each query can only be consumed once. A
///   replayed response is rejected.
/// - **Freshness:** The query has an expiry time. Responses for expired
///   queries are rejected.
/// - **Correlation:** The `query_id` matches the response to the query.
#[derive(Debug, Clone)]
pub struct PendingRouteQuery {
    /// The query_id (correlation ID).
    pub query_id: [u8; 16],
    /// The source node's NodeId (the local node).
    pub source_node_id: [u8; 32],
    /// The destination NodeId being resolved.
    pub destination_node_id: [u8; 32],
    /// **Expected responder:** The NodeId of the neighbor that was queried.
    /// The response MUST come from this node.
    pub expected_responder_node_id: [u8; 32],
    /// The max_hops from the query.
    pub max_hops: u8,
    /// When the query was created (unix seconds).
    pub created_at: u64,
    /// When the query expires (unix seconds). Responses after this are rejected.
    pub expires_at: u64,
    /// Whether the query has been consumed (a valid response was received).
    pub consumed: bool,
}

impl PendingRouteQuery {
    /// Create a new `PendingRouteQuery` for a query sent to `expected_responder`.
    #[must_use]
    pub fn new(
        query: &NextHopQuery,
        expected_responder_node_id: [u8; 32],
    ) -> Self {
        let now = now_unix();
        Self {
            query_id: query.query_id,
            source_node_id: query.source_node_id,
            destination_node_id: query.destination_node_id,
            expected_responder_node_id,
            max_hops: query.max_hops,
            created_at: now,
            expires_at: now.saturating_add(MAX_ROUTE_QUERY_AGE_SECS),
            consumed: false,
        }
    }

    /// Check if a response is valid for this pending query.
    ///
    /// Validates:
    /// 1. `query_id` matches.
    /// 2. `responder_node_id == expected_responder_node_id`.
    /// 3. Query is not expired.
    /// 4. Query is not already consumed.
    ///
    /// Does NOT verify the response signature or freshness — those are
    /// checked separately by the caller.
    #[must_use]
    pub fn matches_response(&self, response: &NextHopResponse) -> bool {
        // 1. query_id must match.
        if response.query_id != self.query_id {
            return false;
        }
        // 2. Responder must be the expected neighbor.
        if response.responder_node_id != self.expected_responder_node_id {
            return false;
        }
        // 3. Query must not be expired.
        if self.is_expired() {
            return false;
        }
        // 4. Query must not be already consumed.
        if self.consumed {
            return false;
        }
        true
    }

    /// Check if the query has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        now_unix() >= self.expires_at
    }

    /// Mark the query as consumed (a valid response was received).
    pub fn consume(&mut self) {
        self.consumed = true;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RoutingAssertion (N2.1.3.1) — distinguishes routing claim from identity
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.1.** A verified routing assertion — the responder's signed claim
/// about the next hop toward a destination.
///
/// ## Trust model
///
/// A `RoutingAssertion` proves:
/// > "Responder B claims that next_hop C is the next hop toward destination G."
///
/// It does **NOT** prove:
/// > "B has a usable authenticated link to C."
///
/// or:
/// > "A can reach C."
///
/// The `next_hop_node_id`'s `NodeAdvertisement` proves C's identity (when
/// independently verified), but the routing assertion is B's claim, not
/// C's proof of reachability.
///
/// ## Construction
///
/// A `RoutingAssertion` is constructed via either:
/// - **`create_and_sign()`** — used in the recursive multi-hop path
///   (N2.1.3.2). The forwarding node signs the assertion preimage
///   (responder_node_id, destination_node_id, next_hop_node_id,
///   is_destination, query_id, timestamp) under
///   `ROUTE_DISCOVERY_MSG_CONTEXT`. The signature and public key are
///   carried in the assertion so that the ultimate receiver (A) can
///   verify the claim was authored by the claimed responder.
/// - **`from_verified_response()`** — used in the SINGLE-STEP path
///   (N2.1.3.1). The assertion is derived from a verified
///   `NextHopResponse` whose signature already proves the responder's
///   authorship. In this path, the assertion's `ed25519_public_key` and
///   `signature` fields are all-zero — they are NOT used because the
///   enclosing `NextHopResponse` signature already binds the claim.
///   `verify_signature()` therefore returns `true` for assertions
///   constructed via `from_verified_response()` only because the caller
///   has already verified the parent `NextHopResponse` signature. The
///   `DistributedRouteResolution::verify()` check for assertion
///   signatures is enforced on the recursive path; the single-step path
///   does not invoke `DistributedRouteResolution::verify()`.
#[derive(Debug, Clone)]
pub struct RoutingAssertion {
    /// The responder's NodeId (the node that made the claim).
    pub responder_node_id: [u8; 32],
    /// The destination NodeId being resolved.
    pub destination_node_id: [u8; 32],
    /// The next-hop NodeId the responder claims is toward the destination.
    pub next_hop_node_id: [u8; 32],
    /// Whether the responder claims this next hop IS the destination.
    pub is_destination: bool,
    /// The query_id that triggered this assertion (provenance).
    pub query_id: [u8; 16],
    /// When the assertion was made (from the response timestamp).
    pub timestamp: u64,
    /// **N2.1.3.2-security.** The responder's Ed25519 public key. The
    /// responder's NodeId MUST equal `derive_node_id(ed25519_public_key)`
    /// (I4 consistency) for `verify_signature()` to return true.
    ///
    /// In the single-step path (`from_verified_response`), this is
    /// all-zero — the assertion is bound by the enclosing
    /// `NextHopResponse` signature instead.
    pub ed25519_public_key: [u8; 32],
    /// **N2.1.3.2-security.** Ed25519 signature over
    /// `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage())`. `preimage()`
    /// covers every assertion field EXCEPT `signature` itself.
    ///
    /// In the single-step path (`from_verified_response`), this is
    /// all-zero — the assertion is bound by the enclosing
    /// `NextHopResponse` signature instead.
    pub signature: [u8; 64],
}

impl RoutingAssertion {
    /// Construct a `RoutingAssertion` from a verified `NextHopResponse`.
    ///
    /// The caller MUST have already verified:
    /// - Response signature.
    /// - Responder matches expected neighbor.
    /// - Query matches pending state.
    /// - Response freshness.
    ///
    /// ## Single-step path
    ///
    /// In this path, the assertion's `ed25519_public_key` and `signature`
    /// fields are all-zero. The enclosing `NextHopResponse` signature
    /// already proves the responder's authorship. This assertion type is
    /// used by the single-step `NextHopResolver::resolve_step()` method
    /// and is NOT subject to `DistributedRouteResolution::verify()`.
    #[must_use]
    pub fn from_verified_response(
        response: &NextHopResponse,
        destination_node_id: [u8; 32],
    ) -> Option<Self> {
        match &response.result {
            NextHopResult::Found { next_hop_node_id, is_destination, .. } => Some(Self {
                responder_node_id: response.responder_node_id,
                destination_node_id,
                next_hop_node_id: *next_hop_node_id,
                is_destination: *is_destination,
                query_id: response.query_id,
                timestamp: response.timestamp,
                // Single-step path: signature fields are all-zero. The
                // enclosing NextHopResponse signature binds the claim.
                ed25519_public_key: [0u8; 32],
                signature: [0u8; 64],
            }),
            NextHopResult::NotFound => None,
        }
    }

    /// **N2.1.3.2-security.** Create and sign a `RoutingAssertion`.
    ///
    /// The forwarding node (responder) signs the assertion preimage
    /// (responder_node_id, destination_node_id, next_hop_node_id,
    /// is_destination, query_id, timestamp) under
    /// `ROUTE_DISCOVERY_MSG_CONTEXT`. The signature and the responder's
    /// public key are stored in the assertion so that any receiver can
    /// independently verify the claim.
    ///
    /// # Parameters
    /// - `secret_key`: The responder's Ed25519 secret key.
    /// - `public_key`: The responder's Ed25519 public key. MUST correspond
    ///   to `secret_key`. The responder's NodeId is derived from this key.
    /// - `responder_node_id`: The responder's NodeId. MUST equal
    ///   `derive_node_id(public_key)` for `verify_signature()` to succeed.
    /// - `destination_node_id`: The destination being resolved.
    /// - `next_hop_node_id`: The next hop the responder claims is toward
    ///   the destination.
    /// - `is_destination`: Whether `next_hop_node_id == destination_node_id`.
    /// - `query_id`: The query_id of the `ForwardedQuery` that triggered
    ///   this assertion.
    #[must_use]
    pub fn create_and_sign(
        secret_key: &[u8; 32],
        public_key: &[u8; 32],
        responder_node_id: [u8; 32],
        destination_node_id: [u8; 32],
        next_hop_node_id: [u8; 32],
        is_destination: bool,
        query_id: [u8; 16],
    ) -> Self {
        let timestamp = now_unix();
        let mut assertion = Self {
            responder_node_id,
            destination_node_id,
            next_hop_node_id,
            is_destination,
            query_id,
            timestamp,
            ed25519_public_key: *public_key,
            signature: [0u8; 64],
        };
        assertion.sign(secret_key);
        assertion
    }

    /// Compute the canonical CBOR preimage of the assertion (every field
    /// EXCEPT the signature itself).
    ///
    /// The signature covers `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage)`.
    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("responderNodeId".into()), CborValue::ByteString(self.responder_node_id.to_vec())),
            (CborValue::TextString("destinationNodeId".into()), CborValue::ByteString(self.destination_node_id.to_vec())),
            (CborValue::TextString("nextHopNodeId".into()), CborValue::ByteString(self.next_hop_node_id.to_vec())),
            (CborValue::TextString("isDestination".into()), CborValue::Bool(self.is_destination)),
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("responderPublicKey".into()), CborValue::ByteString(self.ed25519_public_key.to_vec())),
        ])
    }

    /// Re-sign the assertion (after field mutation).
    pub fn sign(&mut self, secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(secret_key, &msg);
    }

    /// **N2.1.3.2-security.** Verify the assertion's signature and
    /// responder identity consistency (I4).
    ///
    /// Returns `true` iff:
    /// - `ed25519_public_key` is non-zero (i.e., this assertion was
    ///   created via `create_and_sign`, not `from_verified_response`).
    /// - The signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage)`
    ///   verifies under `ed25519_public_key`.
    /// - `responder_node_id == derive_node_id(ed25519_public_key)` (I4).
    ///
    /// ## Single-step path
    ///
    /// For assertions created via `from_verified_response()`, both
    /// `ed25519_public_key` and `signature` are all-zero. This method
    /// returns `false` for such assertions. The single-step path does
    /// NOT call `DistributedRouteResolution::verify()` (which invokes
    /// this method) — single-step assertions are validated by the
    /// enclosing `NextHopResponse::verify_signature()` instead.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        // Single-step assertions have all-zero public key + signature.
        // They are NOT verifiable via this method — they are validated
        // by the enclosing NextHopResponse signature instead.
        if self.ed25519_public_key == [0u8; 32] && self.signature == [0u8; 64] {
            return false;
        }
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.ed25519_public_key, &msg, &self.signature) {
            return false;
        }
        let expected = snp_crypto::derive_node_id(&self.ed25519_public_key);
        self.responder_node_id == expected
    }

    /// Check if this assertion claims the next hop is the destination.
    #[must_use]
    pub fn claims_destination_reached(&self) -> bool {
        self.is_destination && self.next_hop_node_id == self.destination_node_id
    }

    /// **N2.2.1.** Canonical CBOR encoding of the COMPLETE `RoutingAssertion`
    /// (every field, including `signature`). Used for wire transmission.
    ///
    /// Note: this is `preimage()` + the `signature` field. The bytes produced
    /// by `snp_cbor::encode(&self.to_cbor_map())` are NOT the signature
    /// preimage — the signature preimage excludes `signature`. But the wire
    /// format must carry the signature so receivers can verify it.
    #[must_use]
    pub fn to_cbor_map(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("responderNodeId".into()), CborValue::ByteString(self.responder_node_id.to_vec())),
            (CborValue::TextString("destinationNodeId".into()), CborValue::ByteString(self.destination_node_id.to_vec())),
            (CborValue::TextString("nextHopNodeId".into()), CborValue::ByteString(self.next_hop_node_id.to_vec())),
            (CborValue::TextString("isDestination".into()), CborValue::Bool(self.is_destination)),
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("responderPublicKey".into()), CborValue::ByteString(self.ed25519_public_key.to_vec())),
            (CborValue::TextString("signature".into()), CborValue::ByteString(self.signature.to_vec())),
        ])
    }

    /// **N2.2.1.** Decode a `RoutingAssertion` from a canonical CBOR map.
    ///
    /// Returns `None` if the value is not a map, is missing required fields,
    /// or has fields of the wrong type/length. The caller MUST still call
    /// `verify_signature()` before trusting the assertion.
    #[must_use]
    pub fn from_cbor_map(value: &CborValue) -> Option<Self> {
        let map = cbor_map_entries(value)?;
        Some(Self {
            responder_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "responderNodeId")?)?,
            destination_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "destinationNodeId")?)?,
            next_hop_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "nextHopNodeId")?)?,
            is_destination: cbor_get_bool(cbor_map_get(map, "isDestination")?)?,
            query_id: cbor_get_fixed_bytes(cbor_map_get(map, "queryId")?)?,
            timestamp: cbor_get_u64(cbor_map_get(map, "timestamp")?)?,
            ed25519_public_key: cbor_get_fixed_bytes(cbor_map_get(map, "responderPublicKey")?)?,
            signature: cbor_get_fixed_bytes(cbor_map_get(map, "signature")?)?,
        })
    }

    /// **N2.2.1.** Encode to canonical CBOR bytes for wire transmission.
    #[must_use]
    pub fn encode_cbor(&self) -> Vec<u8> {
        snp_cbor::encode(&self.to_cbor_map()).expect("CBOR encode never fails for RoutingAssertion")
    }

    /// **N2.2.1.** Decode from canonical CBOR bytes.
    #[must_use]
    pub fn decode_cbor(bytes: &[u8]) -> Option<Self> {
        Self::from_cbor_map(&snp_cbor::decode(bytes).ok()?)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DistributedRouteResolver trait (N2.1.3.1.1) — stateful distributed resolution
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.1.1.** A stateful trait for distributed route resolution.
///
/// Unlike `DestinationResolver` (which is stateless and used for LOCAL
/// lookup), `DistributedRouteResolver` owns `PendingRouteQuery` state
/// across query/response exchanges. This is essential for:
///
/// - **Replay protection:** Each query can only be consumed once.
/// - **Expected-responder binding:** The response must come from the
///   queried neighbor.
/// - **Freshness:** Queries have bounded lifetimes.
/// - **Future recursive chaining:** Query provenance must survive across
///   multiple resolution steps.
///
/// ## Why not `DestinationResolver`?
///
/// `DestinationResolver` takes `&self` and returns
/// `Option<AuthenticatedNodeRecord>`. It cannot own mutable state.
/// The previous implementation worked around this by creating a temporary
/// resolver per call — but that **discarded the pending-query state**,
/// defeating the replay protection and responder binding.
///
/// `DistributedRouteResolver` takes `&mut self` and returns
/// `Option<NextHopResolution>` (which includes the `RoutingAssertion`).
/// The state survives across calls.
///
/// ## Composition
///
/// - **LOCAL ROUTE COMPUTATION** uses `DestinationResolver` (stateless).
/// - **DISTRIBUTED ROUTE DISCOVERY** uses `DistributedRouteResolver` (stateful).
///
/// The two may be composed by a higher-level route-discovery orchestrator
/// in a future milestone.
pub trait DistributedRouteResolver {
    /// Resolve a destination by querying a single next-hop peer.
    ///
    /// This is SINGLE-STEP resolution. Recursive multi-hop discovery
    /// is a future milestone (N2.1.3.2).
    ///
    /// # Parameters
    /// - `destination`: The NodeId to resolve.
    /// - `hint`: The `RemoteNodeHint` that triggered the resolution.
    ///
    /// # Returns
    /// - `Some(NextHopResolution)` if a valid response was received and
    ///   the advertisement verified.
    /// - `None` if resolution failed.
    fn resolve_step(
        &mut self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
    ) -> Option<NextHopResolution>;

    /// Get the number of pending (unconsumed) queries.
    fn pending_query_count(&self) -> usize;

    /// Check if a specific query_id has been consumed.
    fn is_query_consumed(&self, query_id: &[u8; 16]) -> bool;
}

// ════════════════════════════════════════════════════════════════════════════
// NextHopResolver — single-step distributed destination resolution
// ════════════════════════════════════════════════════════════════════════════

/// A `DistributedRouteResolver` that resolves remote destinations by querying
/// a single authenticated next-hop peer using the `NextHopQuery`/
/// `NextHopResponse` protocol.
///
/// **N2.1.3.1:** This resolver performs SINGLE-STEP resolution only.
/// It does NOT recursively query the next hop. Recursive multi-hop
/// discovery is a future milestone (N2.1.3.2).
///
/// **N2.1.3.1.1:** This resolver implements `DistributedRouteResolver`
/// (NOT `DestinationResolver`). The state (`pending_queries`) survives
/// across `resolve_step()` calls. Callers must use `&mut self`.
///
/// ## How it works (single-step)
///
/// 1. The resolver receives a `RemoteNodeHint` for destination D.
/// 2. It purges expired pending queries (resource management).
/// 3. It checks capacity (total live entries ≤ `MAX_PENDING_ROUTE_QUERIES`).
/// 4. It selects the hint's `learned_from` as the neighbor to query.
/// 5. It creates a `PendingRouteQuery` (stateful tracking).
/// 6. It sends a `NextHopQuery` to that neighbor.
/// 7. It receives a `NextHopResponse`.
/// 8. It verifies the response signature + I4.
/// 9. It verifies response freshness (not too old, not future-dated).
/// 10. It verifies the responder matches the expected neighbor and the
///     pending query is not expired/consumed.
/// 11. It verifies the embedded `NodeAdvertisement` via `verify_into_verified()`.
/// 12. It constructs the `RoutingAssertion` and `NextHopResolution`.
/// 13. **ONLY THEN** it marks the pending query as consumed (replay protection).
///     This is the transactional commit point — a failed validation at any
///     earlier step does NOT consume the query (N2.1.3.1.2).
/// 14. It returns the `NextHopResolution` (assertion + record).
///
/// ## Security
///
/// - Expected-responder binding: response must come from the queried neighbor.
/// - Replay protection: each query can only be consumed once.
/// - Transactional consumption: failed validation does NOT consume the query.
/// - Freshness: query and response have bounded age.
/// - max_hops validation: must be > 0.
/// - Advertisement verified independently.
/// - Capacity bounded: total live entries ≤ `MAX_PENDING_ROUTE_QUERIES` (N2.1.3.1.3).
/// - **State persists across calls** (N2.1.3.1.1).
pub struct NextHopResolver<'a> {
    /// The local topology (for finding authenticated neighbors to query).
    topology: &'a TopologyGraph,
    /// The transport for sending queries and receiving responses.
    transport: &'a dyn NextHopTransport,
    /// **N2.1.3.2-fix.** Optional recursive transport for forwarding
    /// `ForwardedQuery` messages through real protocol participants. When
    /// set, `resolve_route_with_budget` uses this transport (sending ONE
    /// `ForwardedQuery` to the first hop, which recursively forwards).
    /// When `None`, `resolve_route_with_budget` returns `None`.
    recursive_transport: Option<&'a dyn RecursiveNextHopTransport>,
    /// The local node's keypair (for signing queries).
    local_ed25519_secret: [u8; 32],
    /// The local node's public key.
    local_ed25519_public: [u8; 32],
    /// The local node's NodeId.
    local_node_id: [u8; 32],
    /// Pending queries (query_id → PendingRouteQuery). Provides replay protection.
    /// **N2.1.3.1.1:** This state PERSISTS across resolve_step() calls.
    pending_queries: HashMap<[u8; 16], PendingRouteQuery>,
}

/// A transport abstraction for sending `NextHopQuery` messages and
/// receiving `NextHopResponse` messages.
pub trait NextHopTransport {
    /// Send a `NextHopQuery` to the specified neighbor and wait for a
    /// `NextHopResponse`.
    fn query_next_hop(
        &self,
        neighbor_node_id: &[u8; 32],
        query: &NextHopQuery,
    ) -> Option<NextHopResponse>;
}

/// The result of a single-step next-hop resolution.
#[derive(Debug, Clone)]
pub struct NextHopResolution {
    /// The routing assertion from the responder.
    pub assertion: RoutingAssertion,
    /// The next-hop node's authenticated record (independently verified).
    pub record: AuthenticatedNodeRecord,
}

impl<'a> NextHopResolver<'a> {
    /// Create a new `NextHopResolver`.
    ///
    /// The resolver starts without a recursive transport. To use
    /// `resolve_route` / `resolve_route_with_budget`, call
    /// `with_recursive_transport` to attach a `RecursiveNextHopTransport`.
    #[must_use]
    pub fn new(
        topology: &'a TopologyGraph,
        transport: &'a dyn NextHopTransport,
        local_ed25519_secret: [u8; 32],
        local_ed25519_public: [u8; 32],
        local_node_id: [u8; 32],
    ) -> Self {
        Self {
            topology,
            transport,
            recursive_transport: None,
            local_ed25519_secret,
            local_ed25519_public,
            local_node_id,
            pending_queries: HashMap::new(),
        }
    }

    /// **N2.1.3.2-fix.** Attach a `RecursiveNextHopTransport` to this
    /// resolver, enabling `resolve_route` / `resolve_route_with_budget`.
    ///
    /// When set, `resolve_route_with_budget` sends ONE `ForwardedQuery` to
    /// the first hop via `RecursiveNextHopTransport::forward_query`. The
    /// first hop (and subsequent hops) handle recursive forwarding through
    /// their own `ForwardingNode::handle_query` logic. A receives the full
    /// accumulated `RecursiveRouteResponse` and constructs the
    /// `DistributedRouteResolution` from it.
    #[must_use]
    pub fn with_recursive_transport(
        mut self,
        recursive_transport: &'a dyn RecursiveNextHopTransport,
    ) -> Self {
        self.recursive_transport = Some(recursive_transport);
        self
    }

    /// Get a reference to the pending queries map.
    #[must_use]
    pub fn pending_queries(&self) -> &HashMap<[u8; 16], PendingRouteQuery> {
        &self.pending_queries
    }
}

/// **N2.1.3.1.2 / N2.1.3.1.3.** Maximum number of live, non-expired
/// pending/replay-protection entries (both consumed and unconsumed).
/// Prevents unbounded memory growth from route-discovery requests.
///
/// **N2.1.3.1.3:** This limit applies to the **total** number of entries
/// in `pending_queries`, not just unconsumed entries. Consumed queries
/// are retained for replay detection until they expire, and they consume
/// memory just like unconsumed queries.
pub const MAX_PENDING_ROUTE_QUERIES: usize = 256;

impl<'a> DistributedRouteResolver for NextHopResolver<'a> {
    fn resolve_step(
        &mut self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
    ) -> Option<NextHopResolution> {
        // Step 0: Purge expired pending queries (resource management).
        self.purge_expired_pending_queries();

        // Step 0b: Check capacity — reject if too many total live entries.
        // N2.1.3.1.3: This counts ALL entries (consumed + unconsumed),
        // because consumed entries are retained for replay detection and
        // consume memory just like unconsumed entries.
        if self.pending_queries.len() >= MAX_PENDING_ROUTE_QUERIES {
            return None;
        }

        // Step 1: Select the neighbor to query.
        let expected_responder = hint.learned_from;

        // Step 2: Create + sign the query.
        let query = NextHopQuery::create_and_sign(
            &self.local_ed25519_secret,
            &self.local_ed25519_public,
            self.local_node_id,
            *destination,
            MAX_RESPONSE_HOPS,
        );

        // Step 3: Create pending query state (replay protection + responder binding).
        // N2.1.3.1.1: This state PERSISTS in self.pending_queries across calls.
        let pending = PendingRouteQuery::new(&query, expected_responder);
        self.pending_queries.insert(query.query_id, pending);

        // Step 4: Send the query.
        let response = self.transport.query_next_hop(&expected_responder, &query)?;

        // Step 5: Verify response signature + I4.
        if !response.verify_signature() {
            return None; // Query NOT consumed — legitimate retry possible.
        }

        // Step 6: Verify response freshness.
        if !response.is_fresh() {
            return None; // Query NOT consumed — legitimate retry possible.
        }

        // Step 7: Verify response matches pending query (responder binding + replay).
        // Check that the pending query exists and matches.
        let pending_match = self.pending_queries.get(&query.query_id)
            .map_or(false, |p| p.matches_response(&response));
        if !pending_match {
            return None; // Query NOT consumed — legitimate retry possible.
        }

        // Step 8: N2.1.3.1.2 — Transactional consumption.
        // Process the result FULLY before consuming the query.
        // A failed advertisement verification MUST NOT consume the query.
        let resolution = match &response.result {
            NextHopResult::Found { next_hop_node_id, advertisement, is_destination: _ } => {
                // Verify the advertisement independently.
                let verified = match advertisement.verify_into_verified() {
                    Some(v) => v,
                    None => return None, // Query NOT consumed — legitimate retry possible.
                };

                // Check that the advertisement's NodeId matches next_hop_node_id.
                if verified.node_id() != *next_hop_node_id {
                    return None; // Query NOT consumed — legitimate retry possible.
                }

                // Construct the routing assertion.
                let assertion = match RoutingAssertion::from_verified_response(
                    &response,
                    *destination,
                ) {
                    Some(a) => a,
                    None => return None, // Query NOT consumed — legitimate retry possible.
                };

                // All validation passed — construct the resolution.
                NextHopResolution {
                    assertion,
                    record: verified.into_record(),
                }
            }
            NextHopResult::NotFound => {
                // NotFound is a valid protocol response. Consume the query
                // (the responder explicitly said it doesn't know the path).
                // But we return None since no resolution was found.
                if let Some(pending) = self.pending_queries.get_mut(&query.query_id) {
                    pending.consume();
                }
                return None;
            }
        };

        // Step 9: N2.1.3.1.2 — ONLY NOW consume the query.
        // All validation has passed. The resolution is fully constructed.
        // This is the transactional commit point.
        if let Some(pending) = self.pending_queries.get_mut(&query.query_id) {
            pending.consume();
        }

        Some(resolution)
    }

    fn pending_query_count(&self) -> usize {
        self.pending_queries.values().filter(|p| !p.consumed).count()
    }

    fn is_query_consumed(&self, query_id: &[u8; 16]) -> bool {
        self.pending_queries.get(query_id).map_or(false, |p| p.consumed)
    }
}

impl<'a> NextHopResolver<'a> {
    /// **N2.1.3.1.2.** Remove expired pending queries.
    ///
    /// Expired queries are removed to prevent unbounded memory growth.
    /// Consumed queries that are still within their retention window are
    /// kept for replay detection (a replayed response for a consumed query
    /// is rejected by `matches_response`).
    ///
    /// Queries that are both expired AND consumed are safe to remove —
    /// they can no longer be replayed (the query_id is expired, so any
    /// response with that query_id would fail freshness checks).
    pub fn purge_expired_pending_queries(&mut self) {
        let now = now_unix();
        self.pending_queries.retain(|_, pending| {
            // Keep if not expired (still within freshness window).
            // Remove if expired (both consumed and unconsumed — expired
            // queries can no longer accept valid responses).
            now < pending.expires_at
        });
    }

    /// Get the total number of pending queries (consumed + unconsumed).
    #[must_use]
    pub fn total_pending_queries(&self) -> usize {
        self.pending_queries.len()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// In-memory transport (for testing)
// ════════════════════════════════════════════════════════════════════════════

/// **TEST-ONLY.** An in-memory `NextHopTransport` that simulates a mesh
/// of nodes for deterministic testing.
#[derive(Default)]
pub struct InMemoryNextHopTransport {
    /// Map from neighbor NodeId → responder function.
    responders: HashMap<[u8; 32], Box<dyn Fn(&NextHopQuery) -> Option<NextHopResponse> + Send + Sync>>,
}

impl InMemoryNextHopTransport {
    /// Create a new empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a responder for a neighbor NodeId.
    pub fn register_responder<F>(&mut self, neighbor_node_id: [u8; 32], responder: F)
    where
        F: Fn(&NextHopQuery) -> Option<NextHopResponse> + Send + Sync + 'static,
    {
        self.responders.insert(neighbor_node_id, Box::new(responder));
    }
}

impl NextHopTransport for InMemoryNextHopTransport {
    fn query_next_hop(
        &self,
        neighbor_node_id: &[u8; 32],
        query: &NextHopQuery,
    ) -> Option<NextHopResponse> {
        self.responders.get(neighbor_node_id)?(query)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.3.2 — Recursive multi-hop distributed route discovery
//
// Extends the single-step `resolve_step` protocol with recursive forwarding.
// A queries B, B returns "next hop is C", A queries C, C returns "next hop
// is G (destination)". The full chain A → B → C → G is accumulated into a
// `DistributedRouteResolution` with provenance, hop budget tracking, and
// loop prevention.
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.2.** A `NextHopQuery` bound to its parent query for recursive
/// forwarding.
///
/// A `ForwardedQuery` extends `NextHopQuery` with three pieces of parent
/// binding metadata:
///
/// - `parent_query_id` — the `query_id` of the previous step's query
///   (the query whose response triggered this forward). All-zero for the
///   initial query (no parent).
/// - `parent_responder_node_id` — the NodeId of the node that responded to
///   the parent query (the "forwarder"). All-zero for the initial query.
/// - `visited_nodes` — the set of nodes already visited in this resolution
///   chain, including the source. Used for loop prevention.
///
/// ## Signature model
///
/// The `signature` field is the standard `NextHopQuery` signature (signed by
/// the source over the `NextHopQuery` preimage). The `parent_signature`
/// field is an ADDITIONAL signature from the source over the parent binding
/// fields. This binds the parent relationship to the source's identity,
/// preventing assertion injection attacks where a malicious node provides a
/// response for a different query chain.
///
/// ## Why two signatures?
///
/// The `signature` must remain compatible with `NextHopQuery::verify_signature`
/// so that the existing `NextHopTransport` infrastructure (which takes a
/// `&NextHopQuery`) can be reused without modification. The `parent_signature`
/// covers the additional parent binding fields that `NextHopQuery` does not
/// include, providing end-to-end provenance for the recursive chain.
///
/// ## Construction
///
/// A `ForwardedQuery` is constructed via `ForwardedQuery::create_and_sign`.
/// The initial query in a chain has `parent_query_id = [0u8; 16]` and
/// `parent_responder_node_id = [0u8; 32]` (no parent). Each subsequent
/// forwarded query carries the previous step's `query_id` and responder.
#[derive(Debug, Clone)]
pub struct ForwardedQuery {
    // === NextHopQuery fields (preserved for transport compatibility) ===
    /// The querying node's NodeId.
    pub source_node_id: [u8; 32],
    /// The querying node's Ed25519 public key.
    pub source_ed25519_public_key: [u8; 32],
    /// The destination NodeId the source wants to reach.
    pub destination_node_id: [u8; 32],
    /// A unique 16-byte nonce for this query (correlation ID).
    pub query_id: [u8; 16],
    /// When this query was created (unix seconds).
    pub timestamp: u64,
    /// The maximum remaining hops the source will accept.
    pub max_hops: u8,
    /// Ed25519 signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(NextHopQuery preimage)`.
    pub signature: [u8; 64],

    // === Parent binding fields (N2.1.3.2) ===
    /// The query_id of the parent query (the previous step in the chain).
    /// All-zero for the initial query (no parent).
    pub parent_query_id: [u8; 16],
    /// The NodeId of the node that responded to the parent query (the
    /// forwarder). All-zero for the initial query.
    pub parent_responder_node_id: [u8; 32],
    /// Nodes already visited in this resolution chain (loop prevention).
    /// Always includes the source.
    pub visited_nodes: Vec<[u8; 32]>,
    /// **N2.1.3.2-security.** `SHA-256(canonical_CBOR(parent_query))` — a
    /// hash of the COMPLETE parent `ForwardedQuery` (all fields, including
    /// both signatures). This cryptographically binds the forwarded query
    /// to the actual parent message that was received, preventing a
    /// malicious forwarder from inventing a `parent_query_id` for a query
    /// that was never sent.
    ///
    /// All-zero (`[0u8; 32]`) for the initial query (no parent).
    pub parent_query_hash: [u8; 32],
    /// The source's signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖
    /// CBOR(parent_binding_preimage)`. Covers `parent_query_id`,
    /// `parent_responder_node_id`, `parent_query_hash`, `visited_nodes`,
    /// and `query_id` (to bind the parent relationship to this specific
    /// query).
    pub parent_signature: [u8; 64],
}

impl ForwardedQuery {
    /// Create and sign a `ForwardedQuery`.
    ///
    /// The `signature` field is the standard `NextHopQuery` signature (over
    /// the NextHopQuery preimage only). The `parent_signature` field covers
    /// the parent binding fields, INCLUDING the `parent_query_hash` — a
    /// SHA-256 of the COMPLETE parent `ForwardedQuery`.
    ///
    /// # Parameters
    /// - `parent_query_hash`: `SHA-256(canonical_CBOR(parent_query))` for
    ///   forwarded queries. MUST be `[0u8; 32]` for the initial query
    ///   (no parent).
    ///
    /// # Panics
    /// Panics if `max_hops` is 0.
    #[must_use]
    pub fn create_and_sign(
        source_ed25519_secret_key: &[u8; 32],
        source_ed25519_public_key: &[u8; 32],
        source_node_id: [u8; 32],
        destination_node_id: [u8; 32],
        max_hops: u8,
        parent_query_id: [u8; 16],
        parent_responder_node_id: [u8; 32],
        parent_query_hash: [u8; 32],
        visited_nodes: Vec<[u8; 32]>,
    ) -> Self {
        assert!(max_hops > 0, "max_hops must be > 0");
        let now = now_unix();
        let mut query_id = [0u8; 16];
        let _ = getrandom::getrandom(&mut query_id);
        let mut msg = Self {
            source_node_id,
            source_ed25519_public_key: *source_ed25519_public_key,
            destination_node_id,
            query_id,
            timestamp: now,
            max_hops,
            signature: [0u8; 64],
            parent_query_id,
            parent_responder_node_id,
            parent_query_hash,
            visited_nodes,
            parent_signature: [0u8; 64],
        };
        // Sign the NextHopQuery preimage (compatible with NextHopQuery::verify_signature).
        msg.sign_next_hop_query(source_ed25519_secret_key);
        // Sign the parent binding preimage.
        msg.sign_parent_binding(source_ed25519_secret_key);
        msg
    }

    /// Compute the NextHopQuery preimage (same as NextHopQuery::preimage).
    fn next_hop_preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("sourceNodeId".into()), CborValue::ByteString(self.source_node_id.to_vec())),
            (CborValue::TextString("sourcePublicKey".into()), CborValue::ByteString(self.source_ed25519_public_key.to_vec())),
            (CborValue::TextString("destinationNodeId".into()), CborValue::ByteString(self.destination_node_id.to_vec())),
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("maxHops".into()), CborValue::UnsignedInt(u64::from(self.max_hops))),
        ])
    }

    /// Compute the parent binding preimage.
    ///
    /// **N2.1.3.2-security:** The preimage now includes `parent_query_hash`
    /// (SHA-256 of the complete parent query). This binds the parent
    /// binding signature to the actual parent message, preventing a
    /// malicious forwarder from inventing a `parent_query_id` for a query
    /// that was never sent.
    fn parent_binding_preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("parentQueryId".into()), CborValue::ByteString(self.parent_query_id.to_vec())),
            (CborValue::TextString("parentResponderNodeId".into()), CborValue::ByteString(self.parent_responder_node_id.to_vec())),
            (CborValue::TextString("parentQueryHash".into()), CborValue::ByteString(self.parent_query_hash.to_vec())),
            (CborValue::TextString("visitedNodes".into()), CborValue::Array(
                self.visited_nodes.iter().map(|n| CborValue::ByteString(n.to_vec())).collect()
            )),
        ])
    }

    /// **N2.1.3.2-security.** Compute `SHA-256(canonical_CBOR(self))` — a
    /// hash of the COMPLETE `ForwardedQuery` (all fields, including both
    /// signatures).
    ///
    /// This hash is used as the `parent_query_hash` of the NEXT forwarded
    /// query in the chain. It cryptographically binds the next query to
    /// the actual parent message that was received and signed.
    ///
    /// The hash covers EVERY field of `ForwardedQuery`:
    /// - `source_node_id`, `source_ed25519_public_key`, `destination_node_id`,
    ///   `query_id`, `timestamp`, `max_hops`, `signature` (NextHopQuery sig),
    /// - `parent_query_id`, `parent_responder_node_id`, `parent_query_hash`,
    ///   `visited_nodes`, `parent_signature`.
    ///
    /// **N2.2.1:** The hash preimage is the SAME canonical CBOR used for
    /// wire transmission (`to_cbor_map()` → `encode_cbor()`). This is
    /// security-critical: the `parent_query_hash` binding between hops
    /// depends on the wire bytes being byte-identical to the hash preimage.
    /// If they differed, a parent's `compute_hash()` would not match the
    /// child's `parent_query_hash` after a wire round-trip.
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let preimage = self.to_cbor_map();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        sha256(&bytes)
    }

    /// **N2.2.1.** Canonical CBOR encoding of the COMPLETE `ForwardedQuery`
    /// (all fields, including both signatures). Used by `compute_hash()` and
    /// by `encode_cbor()` for wire transmission.
    ///
    /// The bytes produced by `snp_cbor::encode(&self.to_cbor_map())` are
    /// IDENTICAL to the hash preimage used by `compute_hash()`. This is
    /// security-critical — see the docstring on `compute_hash()`.
    #[must_use]
    pub fn to_cbor_map(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("sourceNodeId".into()), CborValue::ByteString(self.source_node_id.to_vec())),
            (CborValue::TextString("sourcePublicKey".into()), CborValue::ByteString(self.source_ed25519_public_key.to_vec())),
            (CborValue::TextString("destinationNodeId".into()), CborValue::ByteString(self.destination_node_id.to_vec())),
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("maxHops".into()), CborValue::UnsignedInt(u64::from(self.max_hops))),
            (CborValue::TextString("signature".into()), CborValue::ByteString(self.signature.to_vec())),
            (CborValue::TextString("parentQueryId".into()), CborValue::ByteString(self.parent_query_id.to_vec())),
            (CborValue::TextString("parentResponderNodeId".into()), CborValue::ByteString(self.parent_responder_node_id.to_vec())),
            (CborValue::TextString("parentQueryHash".into()), CborValue::ByteString(self.parent_query_hash.to_vec())),
            (CborValue::TextString("visitedNodes".into()), CborValue::Array(
                self.visited_nodes.iter().map(|n| CborValue::ByteString(n.to_vec())).collect()
            )),
            (CborValue::TextString("parentSignature".into()), CborValue::ByteString(self.parent_signature.to_vec())),
        ])
    }

    /// **N2.2.1.** Decode a `ForwardedQuery` from a canonical CBOR map.
    ///
    /// Returns `None` if the value is not a map, is missing required fields,
    /// or has fields of the wrong type/length. The caller MUST still call
    /// `verify_all()` to verify both signatures before trusting the query.
    #[must_use]
    pub fn from_cbor_map(value: &CborValue) -> Option<Self> {
        let map = cbor_map_entries(value)?;
        Some(Self {
            source_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "sourceNodeId")?)?,
            source_ed25519_public_key: cbor_get_fixed_bytes(cbor_map_get(map, "sourcePublicKey")?)?,
            destination_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "destinationNodeId")?)?,
            query_id: cbor_get_fixed_bytes(cbor_map_get(map, "queryId")?)?,
            timestamp: cbor_get_u64(cbor_map_get(map, "timestamp")?)?,
            max_hops: u8::try_from(cbor_get_u64(cbor_map_get(map, "maxHops")?)?).ok()?,
            signature: cbor_get_fixed_bytes(cbor_map_get(map, "signature")?)?,
            parent_query_id: cbor_get_fixed_bytes(cbor_map_get(map, "parentQueryId")?)?,
            parent_responder_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "parentResponderNodeId")?)?,
            parent_query_hash: cbor_get_fixed_bytes(cbor_map_get(map, "parentQueryHash")?)?,
            visited_nodes: cbor_get_byte_array(cbor_map_get(map, "visitedNodes")?)?,
            parent_signature: cbor_get_fixed_bytes(cbor_map_get(map, "parentSignature")?)?,
        })
    }

    /// **N2.2.1.** Encode this `ForwardedQuery` to canonical CBOR bytes for
    /// wire transmission. The output is byte-identical to the hash preimage
    /// used by `compute_hash()`.
    #[must_use]
    pub fn encode_cbor(&self) -> Vec<u8> {
        snp_cbor::encode(&self.to_cbor_map()).expect("CBOR encode never fails for canonical ForwardedQuery map")
    }

    /// **N2.2.1.** Decode a `ForwardedQuery` from canonical CBOR bytes.
    ///
    /// Returns `None` if the bytes are not well-formed canonical CBOR or
    /// do not decode to a valid `ForwardedQuery`. The caller MUST still call
    /// `verify_all()` before trusting the query.
    #[must_use]
    pub fn decode_cbor(bytes: &[u8]) -> Option<Self> {
        let value = snp_cbor::decode(bytes).ok()?;
        Self::from_cbor_map(&value)
    }

    /// Sign the NextHopQuery preimage (compatible with NextHopQuery::sign).
    pub fn sign_next_hop_query(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.next_hop_preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// Sign the parent binding preimage.
    pub fn sign_parent_binding(&mut self, ed25519_secret_key: &[u8; 32]) {
        let preimage = self.parent_binding_preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.parent_signature = ed25519_sign(ed25519_secret_key, &msg);
    }

    /// Verify the NextHopQuery signature and source identity consistency (I4).
    ///
    /// This is equivalent to `NextHopQuery::verify_signature` on the
    /// projected `NextHopQuery`.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        let preimage = self.next_hop_preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.source_ed25519_public_key, &msg, &self.signature) {
            return false;
        }
        let expected = snp_crypto::derive_node_id(&self.source_ed25519_public_key);
        self.source_node_id == expected
    }

    /// Verify the parent binding signature.
    ///
    /// This proves the source authored the parent binding fields, binding
    /// the forwarded query to its parent query.
    #[must_use]
    pub fn verify_parent_signature(&self) -> bool {
        let preimage = self.parent_binding_preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        ed25519_verify(&self.source_ed25519_public_key, &msg, &self.parent_signature)
    }

    /// Verify both signatures (NextHopQuery + parent binding).
    #[must_use]
    pub fn verify_all(&self) -> bool {
        self.verify_signature() && self.verify_parent_signature()
    }

    /// Project to a `NextHopQuery` (drops parent binding fields).
    ///
    /// The resulting `NextHopQuery` has the same `signature` (which is the
    /// NextHopQuery signature, compatible with `NextHopQuery::verify_signature`).
    #[must_use]
    pub fn as_next_hop_query(&self) -> NextHopQuery {
        NextHopQuery {
            source_node_id: self.source_node_id,
            source_ed25519_public_key: self.source_ed25519_public_key,
            destination_node_id: self.destination_node_id,
            query_id: self.query_id,
            timestamp: self.timestamp,
            max_hops: self.max_hops,
            signature: self.signature,
        }
    }

    /// Check if this is the initial query in a chain (no parent).
    #[must_use]
    pub fn is_initial(&self) -> bool {
        self.parent_query_id == [0u8; 16]
            && self.parent_responder_node_id == [0u8; 32]
            && self.parent_query_hash == [0u8; 32]
    }

    /// Check if a node has already been visited (loop prevention).
    #[must_use]
    pub fn has_visited(&self, node_id: &[u8; 32]) -> bool {
        self.visited_nodes.contains(node_id)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.3.2-response-auth — SignedResponseStep
//
// Each `ForwardingNode` that handles a `ForwardedQuery` creates and signs a
// `SignedResponseStep` binding its contribution to the query it received and
// (if forwarding) the child query it sent. The `RecursiveRouteResponse`
// carries `response_steps: Vec<SignedResponseStep>` — one per forwarding hop,
// ordered from the first forwarder to the last.
//
// This authenticates the response envelope itself (destination_reached,
// not_found, remaining_hop_budget, query_chain, and the ordering of
// accumulated entries). A transport cannot modify these fields without
// detection — any tampering invalidates the responder's signature.
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.2-response-auth.** A signed response step from a single
/// `ForwardingNode` in the recursive route-discovery chain.
///
/// Each `ForwardingNode` that handles a `ForwardedQuery` creates and signs a
/// `SignedResponseStep` binding its contribution to the query it received
/// and (if forwarding) the child query it sent. The signature covers the
/// canonical CBOR preimage of every field EXCEPT `signature` itself, under
/// `ROUTE_DISCOVERY_MSG_CONTEXT`.
///
/// ## Fields
///
/// - `responder_node_id` — the NodeId of the node that handled this step.
/// - `responder_ed25519_public_key` — the responder's Ed25519 public key.
///   The responder's NodeId MUST equal `derive_node_id(public_key)` (I4
///   consistency) for `verify_signature()` to return true.
/// - `received_query_id` — the `query_id` of the `ForwardedQuery` this
///   responder received.
/// - `received_query_hash` — `SHA-256(canonical_CBOR(received_query))` —
///   binds the step to the ACTUAL query message the responder received.
/// - `sent_query_hash` — `SHA-256(canonical_CBOR(sent_query))` — binds the
///   step to the child query the responder forwarded. All-zeros (`[0u8; 32]`)
///   for terminal steps (destination reached or not found).
/// - `destination_reached` — whether this step reached the destination.
/// - `next_hop_node_id` — the next hop NodeId this responder forwarded to.
///   All-zeros (`[0u8; 32]`) for terminal steps.
/// - `remaining_hop_budget` — the remaining hop budget AFTER this step.
/// - `not_found` — whether the destination was not found at this step.
/// - `signature` — Ed25519 signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖
///   CBOR(preimage())`.
///
/// ## Chain coherence
///
/// For a chain A → B → C → G, the response carries three `SignedResponseStep`s:
///
/// ```text
/// Step 0 (B): received_query_hash = H(Q_AB), sent_query_hash = H(Q_BC)
/// Step 1 (C): received_query_hash = H(Q_BC), sent_query_hash = H(Q_CG)
/// Step 2 (G): received_query_hash = H(Q_CG), sent_query_hash = [0; 32]   (terminal)
/// ```
///
/// Each step's `sent_query_hash` MUST equal the next step's
/// `received_query_hash`. The terminal step's `sent_query_hash` MUST be
/// all-zeros. This chain coherence, combined with each step's signature,
/// proves that the responders actually handled the queries they claim to
/// have handled — a malicious transport cannot reorder, substitute, or
/// fabricate steps without breaking the chain.
#[derive(Debug, Clone)]
pub struct SignedResponseStep {
    /// The responder's NodeId (who handled this step).
    pub responder_node_id: [u8; 32],
    /// The responder's Ed25519 public key.
    pub responder_ed25519_public_key: [u8; 32],
    /// The `query_id` of the query this responder received.
    pub received_query_id: [u8; 16],
    /// The hash of the query this responder received (binds to actual message).
    pub received_query_hash: [u8; 32],
    /// The hash of the child query this responder sent (all-zeros if terminal).
    pub sent_query_hash: [u8; 32],
    /// Whether this step reached the destination.
    pub destination_reached: bool,
    /// The next hop NodeId (all-zeros if terminal/not found).
    pub next_hop_node_id: [u8; 32],
    /// Remaining hop budget after this step.
    pub remaining_hop_budget: u8,
    /// Whether the destination was not found at this step.
    pub not_found: bool,
    /// Ed25519 signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage())`.
    pub signature: [u8; 64],
}

impl SignedResponseStep {
    /// Compute the canonical CBOR preimage of the step (every field EXCEPT
    /// `signature` itself).
    ///
    /// The signature covers `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage())`.
    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("responderNodeId".into()), CborValue::ByteString(self.responder_node_id.to_vec())),
            (CborValue::TextString("responderPublicKey".into()), CborValue::ByteString(self.responder_ed25519_public_key.to_vec())),
            (CborValue::TextString("receivedQueryId".into()), CborValue::ByteString(self.received_query_id.to_vec())),
            (CborValue::TextString("receivedQueryHash".into()), CborValue::ByteString(self.received_query_hash.to_vec())),
            (CborValue::TextString("sentQueryHash".into()), CborValue::ByteString(self.sent_query_hash.to_vec())),
            (CborValue::TextString("destinationReached".into()), CborValue::Bool(self.destination_reached)),
            (CborValue::TextString("nextHopNodeId".into()), CborValue::ByteString(self.next_hop_node_id.to_vec())),
            (CborValue::TextString("remainingHopBudget".into()), CborValue::UnsignedInt(u64::from(self.remaining_hop_budget))),
            (CborValue::TextString("notFound".into()), CborValue::Bool(self.not_found)),
        ])
    }

    /// **N2.1.3.2-response-auth.** Create and sign a `SignedResponseStep`.
    ///
    /// The responder signs the preimage (every field EXCEPT `signature`)
    /// under `ROUTE_DISCOVERY_MSG_CONTEXT`. The signature and the
    /// responder's public key are stored in the step so any receiver can
    /// independently verify the claim.
    ///
    /// # Parameters
    /// - `secret_key`: The responder's Ed25519 secret key.
    /// - `public_key`: The responder's Ed25519 public key. MUST correspond
    ///   to `secret_key`. The responder's NodeId is derived from this key.
    /// - `responder_node_id`: The responder's NodeId. MUST equal
    ///   `derive_node_id(public_key)` for `verify_signature()` to succeed.
    /// - `received_query_id`: The `query_id` of the `ForwardedQuery` the
    ///   responder received.
    /// - `received_query_hash`: `SHA-256(canonical_CBOR(received_query))`.
    /// - `sent_query_hash`: `SHA-256(canonical_CBOR(sent_query))`, or
    ///   `[0u8; 32]` for terminal steps.
    /// - `destination_reached`: Whether this step reached the destination.
    /// - `next_hop_node_id`: The next hop NodeId, or `[0u8; 32]` for
    ///   terminal steps.
    /// - `remaining_hop_budget`: The remaining hop budget after this step.
    /// - `not_found`: Whether the destination was not found at this step.
    #[must_use]
    pub fn create_and_sign(
        secret_key: &[u8; 32],
        public_key: &[u8; 32],
        responder_node_id: [u8; 32],
        received_query_id: [u8; 16],
        received_query_hash: [u8; 32],
        sent_query_hash: [u8; 32],
        destination_reached: bool,
        next_hop_node_id: [u8; 32],
        remaining_hop_budget: u8,
        not_found: bool,
    ) -> Self {
        let mut step = Self {
            responder_node_id,
            responder_ed25519_public_key: *public_key,
            received_query_id,
            received_query_hash,
            sent_query_hash,
            destination_reached,
            next_hop_node_id,
            remaining_hop_budget,
            not_found,
            signature: [0u8; 64],
        };
        step.sign(secret_key);
        step
    }

    /// Re-sign the step (after field mutation).
    pub fn sign(&mut self, secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage).expect("CBOR encode never fails");
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(secret_key, &msg);
    }

    /// **N2.1.3.2-response-auth.** Verify the step's signature and
    /// responder identity consistency (I4).
    ///
    /// Returns `true` iff:
    /// - The signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage)`
    ///   verifies under `responder_ed25519_public_key`.
    /// - `responder_node_id == derive_node_id(responder_ed25519_public_key)`
    ///   (I4 consistency).
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(ROUTE_DISCOVERY_MSG_CONTEXT.len() + bytes.len());
        msg.extend_from_slice(ROUTE_DISCOVERY_MSG_CONTEXT);
        msg.extend_from_slice(&bytes);
        if !ed25519_verify(&self.responder_ed25519_public_key, &msg, &self.signature) {
            return false;
        }
        let expected = snp_crypto::derive_node_id(&self.responder_ed25519_public_key);
        self.responder_node_id == expected
    }

    /// **N2.2.1.** Canonical CBOR encoding of the COMPLETE `SignedResponseStep`
    /// (every field, including `signature`). Used for wire transmission.
    #[must_use]
    pub fn to_cbor_map(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("responderNodeId".into()), CborValue::ByteString(self.responder_node_id.to_vec())),
            (CborValue::TextString("responderPublicKey".into()), CborValue::ByteString(self.responder_ed25519_public_key.to_vec())),
            (CborValue::TextString("receivedQueryId".into()), CborValue::ByteString(self.received_query_id.to_vec())),
            (CborValue::TextString("receivedQueryHash".into()), CborValue::ByteString(self.received_query_hash.to_vec())),
            (CborValue::TextString("sentQueryHash".into()), CborValue::ByteString(self.sent_query_hash.to_vec())),
            (CborValue::TextString("destinationReached".into()), CborValue::Bool(self.destination_reached)),
            (CborValue::TextString("nextHopNodeId".into()), CborValue::ByteString(self.next_hop_node_id.to_vec())),
            (CborValue::TextString("remainingHopBudget".into()), CborValue::UnsignedInt(u64::from(self.remaining_hop_budget))),
            (CborValue::TextString("notFound".into()), CborValue::Bool(self.not_found)),
            (CborValue::TextString("signature".into()), CborValue::ByteString(self.signature.to_vec())),
        ])
    }

    /// **N2.2.1.** Decode a `SignedResponseStep` from a canonical CBOR map.
    ///
    /// Returns `None` if the value is not a map, is missing required fields,
    /// or has fields of the wrong type/length. The caller MUST still call
    /// `verify_signature()` before trusting the step.
    #[must_use]
    pub fn from_cbor_map(value: &CborValue) -> Option<Self> {
        let map = cbor_map_entries(value)?;
        Some(Self {
            responder_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "responderNodeId")?)?,
            responder_ed25519_public_key: cbor_get_fixed_bytes(cbor_map_get(map, "responderPublicKey")?)?,
            received_query_id: cbor_get_fixed_bytes(cbor_map_get(map, "receivedQueryId")?)?,
            received_query_hash: cbor_get_fixed_bytes(cbor_map_get(map, "receivedQueryHash")?)?,
            sent_query_hash: cbor_get_fixed_bytes(cbor_map_get(map, "sentQueryHash")?)?,
            destination_reached: cbor_get_bool(cbor_map_get(map, "destinationReached")?)?,
            next_hop_node_id: cbor_get_fixed_bytes(cbor_map_get(map, "nextHopNodeId")?)?,
            remaining_hop_budget: u8::try_from(cbor_get_u64(cbor_map_get(map, "remainingHopBudget")?)?).ok()?,
            not_found: cbor_get_bool(cbor_map_get(map, "notFound")?)?,
            signature: cbor_get_fixed_bytes(cbor_map_get(map, "signature")?)?,
        })
    }

    /// **N2.2.1.** Encode to canonical CBOR bytes for wire transmission.
    #[must_use]
    pub fn encode_cbor(&self) -> Vec<u8> {
        snp_cbor::encode(&self.to_cbor_map()).expect("CBOR encode never fails for SignedResponseStep")
    }

    /// **N2.2.1.** Decode from canonical CBOR bytes.
    #[must_use]
    pub fn decode_cbor(bytes: &[u8]) -> Option<Self> {
        Self::from_cbor_map(&snp_cbor::decode(bytes).ok()?)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.3.2-fix — RecursiveRouteResponse + RecursiveNextHopTransport
//
// `ForwardedQuery` is now the actual wire message. A sends ONE
// `ForwardedQuery` to its first hop (B), which recursively forwards it
// (creating NEW `ForwardedQuery` instances with decremented hop budget
// and updated `visited_nodes`). Each hop augments the response with its
// own assertion + record. A receives a single `RecursiveRouteResponse`
// carrying the full accumulated chain A → B → C → G.
//
// **N2.1.3.2-response-auth:** The response also carries `response_steps` —
// one `SignedResponseStep` per forwarding hop, ordered from the first
// forwarder to the last. Each step is signed by its responder, binding
// the responder's contribution to the query it received and (if forwarding)
// the child query it sent.
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.2-fix.** The response to a `ForwardedQuery`, carrying the FULL
/// accumulated discovery chain (not just one hop's advertisement).
///
/// ## Trust model — N2.1.3.2-response-auth
///
/// `RecursiveRouteResponse` is an **unsigned transport envelope**. The
/// fields on this struct are **derived/untrusted** — they are convenience
/// data carried by the transport and MUST NOT independently establish
/// security properties. The authority for the response chain comes from:
///
/// 1. **`SignedResponseStep` chain** — each step is individually signed by
///    its responder, binding to the actual query hashes, destination state,
///    hop budget, and next-hop identity. Chain coherence is verified
///    (`step[i].sent_query_hash == step[i+1].received_query_hash`).
/// 2. **Signed `RoutingAssertion`s** — each assertion is individually signed
///    by its responder under `ROUTE_DISCOVERY_MSG_CONTEXT`.
/// 3. **Authenticated `NodeAdvertisement`s** — each advertisement is
///    independently verified via `verify_into_verified()`.
/// 4. **Initial query binding** — the resolver verifies that
///    `response_steps[0].received_query_hash` matches the actual
///    `initial_query.compute_hash()`.
///
/// The unsigned envelope fields (`destination_node_id`,
/// `destination_reached`, `not_found`, `remaining_hop_budget`,
/// `query_chain`, ordering of `accumulated_assertions`/`accumulated_records`)
/// are checked for consistency against the signed data in
/// `DistributedRouteResolution::verify()`. If they disagree with the signed
/// steps/assertions/advertisements, verification fails.
///
/// **Invariant:** No security decision should be made based on the unsigned
/// envelope fields alone. Always go through `DistributedRouteResolution::verify()`
/// (which checks the signed chain) before using the resolution result.
///
/// Each `ForwardingNode` that handles a `ForwardedQuery` either:
/// - Returns a terminal response (it IS the destination, or it cannot
///   forward), OR
/// - Forwards a NEW `ForwardedQuery` to the next hop, receives a
///   `RecursiveRouteResponse`, and PREPENDS its own assertion + record +
///   query step + signed response step to the accumulated chain.
///
/// When the response reaches the original source (A), it contains:
/// - `accumulated_assertions`: one per forwarding hop (B, C, ...).
/// - `accumulated_records`: one per forwarding hop (the next-hop's record
///   at each step). Does NOT include the source A's direct neighbor (B) —
///   A adds B's record from its own topology.
/// - `query_chain`: one `QueryStep` per query (A→B, B→C, C→G, ...).
/// - `destination_advertisement`: the destination's advert (if reached).
/// - `remaining_hop_budget`: the budget at the destination.
/// - `response_steps`: one `SignedResponseStep` per forwarding hop,
///   ordered from the first forwarder to the last. Each step is signed by
///   its responder and binds the responder's contribution to the actual
///   query messages exchanged. **N2.1.3.2-response-auth.**
#[derive(Debug, Clone)]
pub struct RecursiveRouteResponse {
    /// **Derived/untrusted.** The final destination's NodeId.
    /// Verified against the signed response step chain + the initial query.
    pub destination_node_id: [u8; 32],
    /// **Derived/untrusted.** Whether the destination was reached.
    /// Verified against the signed response step chain.
    pub destination_reached: bool,
    /// **Authenticated (independently verified).** The destination's
    /// advertisement (if reached). Verified independently by the receiver
    /// via `verify_into_verified()` before constructing
    /// `DistributedRouteResolution`.
    pub destination_advertisement: Option<NodeAdvertisement>,
    /// **Authenticated (individually signed).** Accumulated routing
    /// assertions from each forwarding hop. Each assertion is signed by
    /// its responder. Ordered from the first forwarder (B) to the last.
    pub accumulated_assertions: Vec<RoutingAssertion>,
    /// **Authenticated (individually verified).** Accumulated node records
    /// (next-hop advertisements from each hop). Each record's advertisement
    /// is verified via `verify_into_verified()`. Ordered from the first
    /// forwarder's next-hop to the destination. Does NOT include A's direct
    /// neighbor — A adds that from its topology.
    pub accumulated_records: Vec<AuthenticatedNodeRecord>,
    /// **Derived/untrusted.** The query chain (provenance). One `QueryStep`
    /// per query. Verified against the signed response step chain
    /// (`received_query_id` must match `query_chain[i].query_id`).
    pub query_chain: Vec<QueryStep>,
    /// **Derived/untrusted.** Remaining hop budget at the destination.
    /// Verified against the signed response step chain + recomputed from
    /// the resolution chain length.
    pub remaining_hop_budget: u8,
    /// **Derived/untrusted.** `true` if the destination wasn't reached.
    /// Verified against the signed response step chain.
    pub not_found: bool,
    /// **Authenticated (individually signed + chain-coherent).** Signed
    /// response steps from each forwarding hop. One per `ForwardingNode`
    /// that handled a query. Ordered from the first forwarder to the last.
    /// Each step is signed by its responder, binding its contribution to
    /// the query it received and (if forwarding) the child query it sent.
    /// **This is the authoritative response chain.**
    pub response_steps: Vec<SignedResponseStep>,
}

/// **N2.1.3.2-fix.** A transport abstraction for forwarding `ForwardedQuery`
/// messages to neighbors and receiving `RecursiveRouteResponse` messages.
///
/// This is the recursive counterpart to `NextHopTransport`. The key
/// difference: `forward_query` sends a `ForwardedQuery` (which carries the
/// hop budget, visited_nodes, and parent binding), and receives a
/// `RecursiveRouteResponse` (which carries the full accumulated chain).
///
/// The transport routes the query to the registered `ForwardingNode` for
/// the target NodeId, which then handles the recursive forwarding logic.
pub trait RecursiveNextHopTransport {
    /// Forward a `ForwardedQuery` to the specified neighbor and wait for a
    /// `RecursiveRouteResponse`.
    ///
    /// Returns `None` if:
    /// - The neighbor is not registered with this transport.
    /// - The neighbor's `handle_query` returned `None` (e.g., bad signature,
    ///   loop detected, hop budget exhausted, no path to destination).
    fn forward_query(
        &self,
        neighbor_node_id: &[u8; 32],
        query: &ForwardedQuery,
    ) -> Option<RecursiveRouteResponse>;
}

impl RecursiveRouteResponse {
    /// **N2.2.1.** Canonical CBOR encoding of the COMPLETE `RecursiveRouteResponse`
    /// envelope (all fields, including the signed `RoutingAssertion`s,
    /// `SignedResponseStep`s, and `NodeAdvertisement`s). Used for wire
    /// transmission.
    ///
    /// The encoded bytes carry:
    /// - The unsigned envelope fields (`destination_node_id`,
    ///   `destination_reached`, `remaining_hop_budget`, `not_found`).
    /// - The signed `accumulated_assertions` (each carries its own signature).
    /// - The signed `accumulated_records` (each carries the underlying
    ///   advertisement's signature; the receiver re-verifies).
    /// - The signed `response_steps` (each carries its own signature).
    /// - The signed `destination_advertisement` (if present).
    /// - The unsigned `query_chain` (verified against the signed
    ///   `response_steps` by `DistributedRouteResolution::verify()`).
    ///
    /// The unsigned envelope fields are checked for consistency against the
    /// signed data by `DistributedRouteResolution::verify()`. A malicious
    /// transport cannot substitute signed data without invalidating the
    /// signatures.
    #[must_use]
    pub fn to_cbor_map(&self) -> CborValue {
        let destination_advert_cbor = match &self.destination_advertisement {
            Some(advert) => CborValue::Array(vec![advert.to_cbor_map()]),
            None => CborValue::Array(Vec::new()),
        };
        CborValue::Map(vec![
            (CborValue::TextString("destinationNodeId".into()), CborValue::ByteString(self.destination_node_id.to_vec())),
            (CborValue::TextString("destinationReached".into()), CborValue::Bool(self.destination_reached)),
            (CborValue::TextString("destinationAdvertisement".into()), destination_advert_cbor),
            (
                CborValue::TextString("accumulatedAssertions".into()),
                CborValue::Array(self.accumulated_assertions.iter().map(|a| a.to_cbor_map()).collect()),
            ),
            (
                CborValue::TextString("accumulatedRecords".into()),
                CborValue::Array(self.accumulated_records.iter().map(|r| r.advert().to_cbor_map()).collect()),
            ),
            (
                CborValue::TextString("queryChain".into()),
                CborValue::Array(self.query_chain.iter().map(|q| q.to_cbor_map()).collect()),
            ),
            (CborValue::TextString("remainingHopBudget".into()), CborValue::UnsignedInt(u64::from(self.remaining_hop_budget))),
            (CborValue::TextString("notFound".into()), CborValue::Bool(self.not_found)),
            (
                CborValue::TextString("responseSteps".into()),
                CborValue::Array(self.response_steps.iter().map(|s| s.to_cbor_map()).collect()),
            ),
        ])
    }

    /// **N2.2.1.** Decode a `RecursiveRouteResponse` from a canonical CBOR map.
    ///
    /// Returns `None` if the value is not a map, is missing required fields,
    /// or any nested signed object (assertion, response step, advertisement)
    /// fails to decode. The caller MUST still independently verify every
    /// signature via `DistributedRouteResolution::verify()` before trusting
    /// the response — this method only checks structural shape.
    #[must_use]
    pub fn from_cbor_map(value: &CborValue) -> Option<Self> {
        let map = cbor_map_entries(value)?;
        let destination_node_id = cbor_get_fixed_bytes(cbor_map_get(map, "destinationNodeId")?)?;
        let destination_reached = cbor_get_bool(cbor_map_get(map, "destinationReached")?)?;
        // destinationAdvertisement: empty array → None, single-element array → Some.
        let dest_advert_arr = match cbor_map_get(map, "destinationAdvertisement")? {
            CborValue::Array(items) => items,
            _ => return None,
        };
        let destination_advertisement = if dest_advert_arr.is_empty() {
            None
        } else if dest_advert_arr.len() == 1 {
            Some(NodeAdvertisement::from_cbor_map(&dest_advert_arr[0])?)
        } else {
            return None;
        };
        // accumulatedAssertions: array of RoutingAssertion maps.
        let assertions_arr = match cbor_map_get(map, "accumulatedAssertions")? {
            CborValue::Array(items) => items,
            _ => return None,
        };
        let mut accumulated_assertions = Vec::with_capacity(assertions_arr.len());
        for item in assertions_arr {
            accumulated_assertions.push(RoutingAssertion::from_cbor_map(item)?);
        }
        // accumulatedRecords: array of NodeAdvertisement maps (re-verified on decode).
        let records_arr = match cbor_map_get(map, "accumulatedRecords")? {
            CborValue::Array(items) => items,
            _ => return None,
        };
        let mut accumulated_records = Vec::with_capacity(records_arr.len());
        for item in records_arr {
            let advert = NodeAdvertisement::from_cbor_map(item)?;
            // Re-verify the advertisement signature before constructing the record.
            // This ensures a malicious transport cannot substitute forged records.
            let verified = advert.verify_into_verified()?;
            accumulated_records.push(verified.into_record());
        }
        // queryChain: array of QueryStep maps.
        let chain_arr = match cbor_map_get(map, "queryChain")? {
            CborValue::Array(items) => items,
            _ => return None,
        };
        let mut query_chain = Vec::with_capacity(chain_arr.len());
        for item in chain_arr {
            query_chain.push(QueryStep::from_cbor_map(item)?);
        }
        let remaining_hop_budget = u8::try_from(cbor_get_u64(cbor_map_get(map, "remainingHopBudget")?)?).ok()?;
        let not_found = cbor_get_bool(cbor_map_get(map, "notFound")?)?;
        // responseSteps: array of SignedResponseStep maps.
        let steps_arr = match cbor_map_get(map, "responseSteps")? {
            CborValue::Array(items) => items,
            _ => return None,
        };
        let mut response_steps = Vec::with_capacity(steps_arr.len());
        for item in steps_arr {
            response_steps.push(SignedResponseStep::from_cbor_map(item)?);
        }
        Some(Self {
            destination_node_id,
            destination_reached,
            destination_advertisement,
            accumulated_assertions,
            accumulated_records,
            query_chain,
            remaining_hop_budget,
            not_found,
            response_steps,
        })
    }

    /// **N2.2.1.** Encode to canonical CBOR bytes for wire transmission.
    #[must_use]
    pub fn encode_cbor(&self) -> Vec<u8> {
        snp_cbor::encode(&self.to_cbor_map()).expect("CBOR encode never fails for RecursiveRouteResponse")
    }

    /// **N2.2.1.** Decode from canonical CBOR bytes.
    #[must_use]
    pub fn decode_cbor(bytes: &[u8]) -> Option<Self> {
        Self::from_cbor_map(&snp_cbor::decode(bytes).ok()?)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DistributedRouteResolutionError
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.2.** Errors that can occur when verifying a
/// `DistributedRouteResolution` or converting it to a `Route`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DistributedRouteResolutionError {
    /// The resolution chain is empty (no nodes).
    #[error("distributed resolution is empty")]
    Empty,
    /// The source NodeId does not match the first node in the chain.
    #[error("source mismatch: expected {expected:?}, got {actual:?}")]
    SourceMismatch {
        /// The expected source NodeId.
        expected: [u8; 32],
        /// The actual first node in the chain.
        actual: [u8; 32],
    },
    /// The destination NodeId does not match the last node in the chain.
    #[error("destination mismatch: expected {expected:?}, got {actual:?}")]
    DestinationMismatch {
        /// The expected destination NodeId.
        expected: [u8; 32],
        /// The actual last node in the chain.
        actual: [u8; 32],
    },
    /// The number of records does not match the number of hops.
    #[error("record count mismatch: expected {expected} records, got {actual}")]
    RecordCountMismatch {
        /// The expected number of records.
        expected: usize,
        /// The actual number of records.
        actual: usize,
    },
    /// The number of assertions does not match the number of queries.
    #[error("assertion count mismatch: expected {expected} assertions, got {actual}")]
    AssertionCountMismatch {
        /// The expected number of assertions.
        expected: usize,
        /// The actual number of assertions.
        actual: usize,
    },
    /// The hop order is incoherent: an assertion's responder or next_hop
    /// does not match the ordered_node_ids chain.
    #[error("hop order incoherent at index {index}: {reason}")]
    HopOrderIncoherent {
        /// The index of the incoherent assertion.
        index: usize,
        /// A human-readable reason.
        reason: String,
    },
    /// The chain contains a duplicate node (loop).
    #[error("duplicate node in chain at index {index}: {node_id:?}")]
    DuplicateNode {
        /// The index of the duplicate.
        index: usize,
        /// The duplicated NodeId.
        node_id: [u8; 32],
    },
    /// A node record's NodeId is inconsistent with its Ed25519 public key (I4).
    #[error("node record at index {index} has inconsistent NodeId (I4 violation)")]
    NodeRecordInconsistent {
        /// The index of the inconsistent record.
        index: usize,
    },
    /// A routing assertion is invalid (next_hop doesn't match the record).
    #[error("routing assertion at index {index} is invalid: {reason}")]
    InvalidAssertion {
        /// The index of the invalid assertion.
        index: usize,
        /// A human-readable reason.
        reason: String,
    },
    /// **N2.1.3.2-security.** A routing assertion's signature does not
    /// verify, OR the responder's NodeId is inconsistent with the
    /// embedded Ed25519 public key (I4 violation).
    ///
    /// Every assertion in `DistributedRouteResolution::ordered_assertions`
    /// MUST be individually signed by its claimed responder. This error
    /// indicates that assertion `index`'s signature is missing, malformed,
    /// or does not verify under the responder's public key.
    #[error("assertion at index {index} has an invalid signature")]
    AssertionSignatureInvalid {
        /// The index of the offending assertion.
        index: usize,
    },
    /// **N2.1.3.2-response-auth.** A `SignedResponseStep`'s signature does
    /// not verify, OR the responder's NodeId is inconsistent with the
    /// embedded Ed25519 public key (I4 violation).
    ///
    /// Every step in `DistributedRouteResolution::response_steps` MUST be
    /// individually signed by its claimed responder under
    /// `ROUTE_DISCOVERY_MSG_CONTEXT`. This error indicates that step
    /// `index`'s signature is missing, malformed, or does not verify under
    /// the responder's public key.
    #[error("response step at index {index} has an invalid signature")]
    ResponseStepSignatureInvalid {
        /// The index of the offending step.
        index: usize,
    },
    /// **N2.1.3.2-response-auth.** The chain of `SignedResponseStep`s is
    /// incoherent — a step's `sent_query_hash` does not match the next
    /// step's `received_query_hash`, a step's fields do not match the
    /// corresponding assertion, or a terminal step's fields are
    /// inconsistent.
    #[error("response step chain incoherent at index {index}: {reason}")]
    ResponseStepChainIncoherent {
        /// The index of the offending step.
        index: usize,
        /// A human-readable reason.
        reason: String,
    },
    /// The hop budget was exceeded.
    #[error("hop budget exceeded: {hops} hops with initial budget {budget}")]
    HopBudgetExceeded {
        /// The number of hops in the chain.
        hops: usize,
        /// The initial hop budget.
        budget: u8,
    },
    /// The destination does not have the Gateway capability.
    #[error("destination is not a gateway")]
    DestinationNotGateway,
    /// The gateway does not have an X25519 circuit public key.
    #[error("gateway missing X25519 circuit key")]
    GatewayMissingCircuitKey,
    /// A relay hop incorrectly advertises an X25519 circuit key.
    #[error("relay hop at index {index} incorrectly advertises an X25519 circuit key")]
    RelayHasCircuitKey {
        /// The index of the offending relay hop.
        index: usize,
    },
    /// The resolution has expired.
    #[error("resolution has expired (expires_at={expires_at}, now={now})")]
    Expired {
        /// When the resolution expires.
        expires_at: u64,
        /// The current time.
        now: u64,
    },
    /// Route validation failed during `into_route` conversion.
    #[error("route validation failed: {0}")]
    RouteValidationFailed(#[from] RouteError),
    /// A hop is missing an endpoint.
    #[error("hop at index {index} has no endpoints")]
    HopMissingEndpoint {
        /// The index of the offending hop.
        index: usize,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// DistributedRouteResolution
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.2.** The result of recursive multi-hop distributed route
/// discovery.
///
/// A `DistributedRouteResolution` captures the full chain of queries and
/// responses that led to a destination being reached, along with the
/// authenticated records and routing assertions accumulated along the way.
///
/// ## Structure
///
/// For a chain A → B → C → G (3 hops):
///
/// - `ordered_node_ids = [A, B, C, G]` (length 4, including source).
/// - `ordered_records = [B's record, C's record, G's record]` (length 3,
///   one per hop, excluding source A).
/// - `ordered_assertions = [B's assertion, C's assertion]` (length 2,
///   one per query/response — A queried B and C, but not G).
/// - `query_chain` has one entry per query (length 2).
///
/// ## Verification
///
/// `verify()` checks:
/// 1. Source is correct (first node in chain).
/// 2. Destination is correct (last node in chain).
/// 3. Hop order is coherent (each assertion's responder is the next hop,
///    each assertion's next_hop matches the following record).
/// 4. No duplicate/looped nodes.
/// 5. Every NodeAdvertisement is authenticated (NodeId ↔ Ed25519 consistency).
/// 6. Every RoutingAssertion is valid (next_hop matches the corresponding record).
/// 7. Hop budget was never exceeded.
/// 8. Destination has required capability (Gateway).
/// 9. Gateway has X25519 circuit identity.
///
/// ## Conversion to Route
///
/// `into_route()` calls `verify()`, constructs `RouteHop` entries from the
/// verified descriptors + endpoints, calls `Route::new_with_hop_details()`
/// and `Route::validate()`, and returns the validated `Route`.
#[derive(Debug, Clone)]
pub struct DistributedRouteResolution {
    /// The source NodeId (the local node that initiated the resolution).
    pub source: [u8; 32],
    /// The destination NodeId that was resolved.
    pub destination: [u8; 32],
    /// The ordered list of NodeIds in the chain, including the source.
    /// For A → B → C → G, this is `[A, B, C, G]`.
    pub ordered_node_ids: Vec<[u8; 32]>,
    /// The authenticated records for each hop (excluding the source).
    /// For A → B → C → G, this is `[B's record, C's record, G's record]`.
    pub ordered_records: Vec<AuthenticatedNodeRecord>,
    /// The routing assertions from each responder (one per query).
    /// For A → B → C → G, this is `[B's assertion, C's assertion]`.
    pub ordered_assertions: Vec<RoutingAssertion>,
    /// The provenance chain of query steps.
    pub query_chain: Vec<QueryStep>,
    /// The initial hop budget at the start of resolution.
    pub initial_hop_budget: u8,
    /// The remaining hop budget after resolution.
    /// Equal to `initial_hop_budget - (ordered_node_ids.len() - 1)`.
    pub remaining_hop_budget: u8,
    /// When this resolution expires (unix seconds).
    pub expiry: u64,
    /// **N2.1.3.2-response-auth.** Signed response steps from each
    /// forwarding hop. One per `ForwardingNode` that handled a query,
    /// ordered from the first forwarder to the last. The last step is
    /// always the terminal step (destination reached). Each step is
    /// signed by its responder, binding its contribution to the query
    /// it received and (if forwarding) the child query it sent.
    pub response_steps: Vec<SignedResponseStep>,
}

impl DistributedRouteResolution {
    /// Verify the resolution's structural invariants.
    ///
    /// See the type-level documentation for the full list of checks.
    ///
    /// # Errors
    /// Returns a `DistributedRouteResolutionError` describing the first
    /// violation encountered.
    pub fn verify(&self) -> Result<(), DistributedRouteResolutionError> {
        // 1. Non-empty chain.
        if self.ordered_node_ids.is_empty() {
            return Err(DistributedRouteResolutionError::Empty);
        }

        // 2. Source is correct (first node in chain).
        let first = self.ordered_node_ids[0];
        if first != self.source {
            return Err(DistributedRouteResolutionError::SourceMismatch {
                expected: self.source,
                actual: first,
            });
        }

        // 3. Destination is correct (last node in chain).
        let last = *self.ordered_node_ids.last().expect("non-empty");
        if last != self.destination {
            return Err(DistributedRouteResolutionError::DestinationMismatch {
                expected: self.destination,
                actual: last,
            });
        }

        // 4. Record count matches hop count (ordered_node_ids.len() - 1).
        let expected_records = self.ordered_node_ids.len().saturating_sub(1);
        if self.ordered_records.len() != expected_records {
            return Err(DistributedRouteResolutionError::RecordCountMismatch {
                expected: expected_records,
                actual: self.ordered_records.len(),
            });
        }

        // 5. Assertion count matches query count (ordered_node_ids.len() - 2).
        // For a chain of length N+1 (N hops), there are N-1 assertions.
        // Special case: a 1-hop chain (A → B, where B is the destination) has
        // 0 queries/assertions (A already has B's record).
        // For our recursive resolution, every hop except the destination
        // is queried, so assertions.len() = hops - 1 = (N+1-1) - 1 = N - 1.
        let expected_assertions = self.ordered_node_ids.len().saturating_sub(2);
        if self.ordered_assertions.len() != expected_assertions {
            return Err(DistributedRouteResolutionError::AssertionCountMismatch {
                expected: expected_assertions,
                actual: self.ordered_assertions.len(),
            });
        }

        // 6. No duplicate/looped nodes.
        let mut seen = HashSet::new();
        for (i, node_id) in self.ordered_node_ids.iter().enumerate() {
            if !seen.insert(*node_id) {
                return Err(DistributedRouteResolutionError::DuplicateNode {
                    index: i,
                    node_id: *node_id,
                });
            }
        }

        // 7. Every NodeAdvertisement is authenticated (NodeId ↔ Ed25519).
        for (i, record) in self.ordered_records.iter().enumerate() {
            if !record.descriptor.verify_node_id_consistency() {
                return Err(DistributedRouteResolutionError::NodeRecordInconsistent {
                    index: i,
                });
            }
            // 7b. Record's NodeId matches the corresponding node in the chain.
            let expected_node_id = self.ordered_node_ids.get(i + 1).copied();
            if expected_node_id != Some(record.node_id()) {
                return Err(DistributedRouteResolutionError::HopOrderIncoherent {
                    index: i,
                    reason: format!(
                        "record {} has node_id {:?} but chain expects {:?}",
                        i,
                        record.node_id(),
                        expected_node_id
                    ),
                });
            }
        }

        // 7c. **N2.1.3.2-response-auth.** Verify the signed response step chain.
        //
        // For a chain A → B → C → G, the response carries three
        // `SignedResponseStep`s:
        //   Step 0 (B): received Q1, sent Q2.
        //   Step 1 (C): received Q2, sent Q3.
        //   Step 2 (G): received Q3, sent [0;32] (terminal).
        //
        // The expected count is `ordered_assertions.len() + 1` (one step
        // per forwarder, plus one terminal step from the destination).
        //
        // For each step:
        //   1. `verify_signature()` returns true (signature + I4).
        //   2. The step's `responder_node_id` matches the corresponding
        //      assertion's `responder_node_id` (for non-terminal steps) or
        //      the destination (for the terminal step).
        //   3. The step's `destination_reached` matches the assertion's
        //      `is_destination` (for non-terminal steps) or is `true`
        //      (for the terminal step).
        //   4. The step's `next_hop_node_id` matches the assertion's
        //      `next_hop_node_id` (for non-terminal steps) or is `[0u8; 32]`
        //      (for the terminal step).
        //   5. The step's `received_query_hash` is non-zero (the first step
        //      is also non-zero — it binds to A's initial query).
        //   6. The step's `received_query_id` matches the corresponding
        //      `query_chain` step's `query_id` (the query the responder
        //      received is the query the previous hop sent).
        //   7. The chain of `sent_query_hash` → next step's
        //      `received_query_hash` is coherent (each step's
        //      `sent_query_hash` equals the next step's
        //      `received_query_hash`, or is all-zeros for the terminal step).
        let expected_steps = self.ordered_assertions.len().checked_add(1).expect("step count fits in usize");
        if self.response_steps.len() != expected_steps {
            return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                index: 0,
                reason: format!(
                    "expected {} response steps (assertions + 1 terminal), got {}",
                    expected_steps,
                    self.response_steps.len()
                ),
            });
        }
        for (i, step) in self.response_steps.iter().enumerate() {
            // 7c-1. Verify the step's signature + I4 consistency.
            if !step.verify_signature() {
                return Err(DistributedRouteResolutionError::ResponseStepSignatureInvalid {
                    index: i,
                });
            }

            // 7c-5. received_query_hash must be non-zero (binds to a real query).
            if step.received_query_hash == [0u8; 32] {
                return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                    index: i,
                    reason: "received_query_hash is all-zero (must bind to a real query)".to_string(),
                });
            }

            // 7c-6. received_query_id matches the corresponding query_chain step.
            // The i-th response step received the i-th query in the chain
            // (query_chain[i] is "the query SENT at step i", which is the
            // query the i-th responder received).
            let expected_query_id = self.query_chain.get(i).map(|qs| qs.query_id);
            if expected_query_id != Some(step.received_query_id) {
                return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                    index: i,
                    reason: format!(
                        "step {} received_query_id {:?} != query_chain[{}].query_id {:?}",
                        i,
                        step.received_query_id,
                        i,
                        expected_query_id
                    ),
                });
            }

            // 7c-7. Chain coherence: step[i].sent_query_hash == step[i+1].received_query_hash
            //       (or [0;32] for the terminal step).
            if i + 1 < self.response_steps.len() {
                let next_step = &self.response_steps[i + 1];
                if step.sent_query_hash != next_step.received_query_hash {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: format!(
                            "step {} sent_query_hash {:?} != step {} received_query_hash {:?}",
                            i,
                            step.sent_query_hash,
                            i + 1,
                            next_step.received_query_hash
                        ),
                    });
                }
                if step.sent_query_hash == [0u8; 32] {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: format!(
                            "non-terminal step {} has all-zero sent_query_hash (must forward)",
                            i
                        ),
                    });
                }
            } else {
                // Terminal step (last in the chain) — sent_query_hash MUST be all-zero.
                if step.sent_query_hash != [0u8; 32] {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: "terminal step's sent_query_hash must be all-zero".to_string(),
                    });
                }
            }

            // 7c-2/3/4. For non-terminal steps, the step's fields must match
            //           the corresponding assertion. For the terminal step,
            //           the step must have destination_reached=true,
            //           next_hop_node_id=[0u8;32].
            if i < self.ordered_assertions.len() {
                let assertion = &self.ordered_assertions[i];
                if step.responder_node_id != assertion.responder_node_id {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: format!(
                            "step {} responder {:?} != assertion responder {:?}",
                            i,
                            step.responder_node_id,
                            assertion.responder_node_id
                        ),
                    });
                }
                if step.destination_reached != assertion.is_destination {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: format!(
                            "step {} destination_reached {} != assertion is_destination {}",
                            i,
                            step.destination_reached,
                            assertion.is_destination
                        ),
                    });
                }
                if step.next_hop_node_id != assertion.next_hop_node_id {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: format!(
                            "step {} next_hop {:?} != assertion next_hop {:?}",
                            i,
                            step.next_hop_node_id,
                            assertion.next_hop_node_id
                        ),
                    });
                }
                if step.not_found {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: format!(
                            "non-terminal step {} has not_found=true (must be false)",
                            i
                        ),
                    });
                }
            } else {
                // Terminal step (destination reached) — check specific terminal fields.
                if !step.destination_reached {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: "terminal step must have destination_reached=true".to_string(),
                    });
                }
                if step.next_hop_node_id != [0u8; 32] {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: "terminal step's next_hop_node_id must be all-zero".to_string(),
                    });
                }
                if step.not_found {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: "terminal step has not_found=true (resolution succeeded)".to_string(),
                    });
                }
                // The terminal step's responder is the destination.
                if step.responder_node_id != self.destination {
                    return Err(DistributedRouteResolutionError::ResponseStepChainIncoherent {
                        index: i,
                        reason: format!(
                            "terminal step responder {:?} != destination {:?}",
                            step.responder_node_id,
                            self.destination
                        ),
                    });
                }
            }
        }

        // 8. Every RoutingAssertion is valid + hop order is coherent.
        // For assertion i:
        //   - responder_node_id == ordered_node_ids[i+1]
        //   - next_hop_node_id == ordered_node_ids[i+2]
        //   - next_hop_node_id == ordered_records[i+1].node_id()
        //   - destination_node_id == self.destination
        //   - the LAST assertion should have is_destination=true and
        //     next_hop_node_id == destination.
        //
        // **N2.1.3.2-security:** Every assertion MUST also have a valid
        // signature from its claimed responder. The signature covers the
        // assertion preimage (responder_node_id, destination_node_id,
        // next_hop_node_id, is_destination, query_id, timestamp,
        // responder_public_key) under ROUTE_DISCOVERY_MSG_CONTEXT. This
        // proves the responder actually authored the claim — A cannot
        // forge a claim from B, and a malicious transport cannot tamper
        // with the assertion fields.
        for (i, assertion) in self.ordered_assertions.iter().enumerate() {
            // 8a. Verify the assertion's signature + I4 consistency.
            if !assertion.verify_signature() {
                return Err(DistributedRouteResolutionError::AssertionSignatureInvalid {
                    index: i,
                });
            }
            let expected_responder = self
                .ordered_node_ids
                .get(i + 1)
                .copied();
            if expected_responder != Some(assertion.responder_node_id) {
                return Err(DistributedRouteResolutionError::HopOrderIncoherent {
                    index: i,
                    reason: format!(
                        "assertion {} responder {:?} != chain[{}] {:?}",
                        i, assertion.responder_node_id, i + 1, expected_responder
                    ),
                });
            }
            let expected_next_hop = self
                .ordered_node_ids
                .get(i + 2)
                .copied();
            if expected_next_hop != Some(assertion.next_hop_node_id) {
                return Err(DistributedRouteResolutionError::HopOrderIncoherent {
                    index: i,
                    reason: format!(
                        "assertion {} next_hop {:?} != chain[{}] {:?}",
                        i, assertion.next_hop_node_id, i + 2, expected_next_hop
                    ),
                });
            }
            // The next_hop's record must exist and match.
            if let Some(next_record) = self.ordered_records.get(i + 1) {
                if next_record.node_id() != assertion.next_hop_node_id {
                    return Err(DistributedRouteResolutionError::InvalidAssertion {
                        index: i,
                        reason: format!(
                            "assertion {} next_hop {:?} != record[{}].node_id() {:?}",
                            i, assertion.next_hop_node_id, i + 1, next_record.node_id()
                        ),
                    });
                }
            }
            if assertion.destination_node_id != self.destination {
                return Err(DistributedRouteResolutionError::InvalidAssertion {
                    index: i,
                    reason: format!(
                        "assertion {} destination {:?} != resolution destination {:?}",
                        i, assertion.destination_node_id, self.destination
                    ),
                });
            }
            // The last assertion should claim destination reached.
            if i == self.ordered_assertions.len() - 1 {
                if !assertion.is_destination {
                    return Err(DistributedRouteResolutionError::InvalidAssertion {
                        index: i,
                        reason: "last assertion should have is_destination=true".to_string(),
                    });
                }
                if assertion.next_hop_node_id != self.destination {
                    return Err(DistributedRouteResolutionError::InvalidAssertion {
                        index: i,
                        reason: "last assertion's next_hop should equal destination".to_string(),
                    });
                }
            } else {
                // Non-last assertions should NOT claim destination reached.
                if assertion.is_destination {
                    return Err(DistributedRouteResolutionError::InvalidAssertion {
                        index: i,
                        reason: "non-last assertion has is_destination=true".to_string(),
                    });
                }
            }
        }

        // 9. Hop budget was never exceeded.
        // The number of hops (links) is ordered_node_ids.len() - 1.
        // This must be ≤ initial_hop_budget.
        let num_hops = self.ordered_node_ids.len() - 1;
        if u8::try_from(num_hops).unwrap_or(u8::MAX) > self.initial_hop_budget {
            return Err(DistributedRouteResolutionError::HopBudgetExceeded {
                hops: num_hops,
                budget: self.initial_hop_budget,
            });
        }
        // remaining_hop_budget should equal initial - num_hops.
        let expected_remaining = self
            .initial_hop_budget
            .saturating_sub(u8::try_from(num_hops).unwrap_or(u8::MAX));
        if self.remaining_hop_budget != expected_remaining {
            return Err(DistributedRouteResolutionError::HopBudgetExceeded {
                hops: num_hops,
                budget: self.initial_hop_budget,
            });
        }

        // 10. Destination has required capability (Gateway).
        let dest_record = self
            .ordered_records
            .last()
            .ok_or(DistributedRouteResolutionError::Empty)?;
        if !dest_record.descriptor.is_gateway() {
            return Err(DistributedRouteResolutionError::DestinationNotGateway);
        }

        // 11. Gateway has X25519 circuit identity.
        if dest_record.descriptor.circuit_x25519_pub().is_none() {
            return Err(DistributedRouteResolutionError::GatewayMissingCircuitKey);
        }

        // 12. Relay hops must NOT have X25519 circuit keys.
        for (i, record) in self.ordered_records.iter().enumerate() {
            // Skip the last record (it's the destination/gateway).
            if i == self.ordered_records.len() - 1 {
                continue;
            }
            if record.descriptor.circuit_x25519_pub().is_some() {
                return Err(DistributedRouteResolutionError::RelayHasCircuitKey {
                    index: i,
                });
            }
        }

        // 13. Each hop has at least one endpoint.
        for (i, record) in self.ordered_records.iter().enumerate() {
            if record.endpoints.is_empty() {
                return Err(DistributedRouteResolutionError::HopMissingEndpoint {
                    index: i,
                });
            }
        }

        // 14. Not expired.
        let now = now_unix();
        if self.expiry <= now {
            return Err(DistributedRouteResolutionError::Expired {
                expires_at: self.expiry,
                now,
            });
        }

        Ok(())
    }

    /// Convert the resolution into a validated `Route`.
    ///
    /// This method:
    /// 1. Calls `verify()` to check all invariants.
    /// 2. Constructs `RouteHop` for each hop using the verified descriptor
    ///    and the record's endpoints.
    /// 3. Calls `Route::new_with_hop_details()`.
    /// 4. Calls `route.validate()`.
    /// 5. Returns the validated `Route`.
    ///
    /// # Errors
    /// Returns a `DistributedRouteResolutionError` if verification fails
    /// or if route validation fails.
    pub fn into_route(self) -> Result<Route, DistributedRouteResolutionError> {
        // 1. Verify all invariants.
        self.verify()?;

        // 2. Construct RouteHop entries.
        let mut hop_details = Vec::with_capacity(self.ordered_records.len());
        for record in &self.ordered_records {
            let hop = RouteHop::with_endpoints(
                record.descriptor.clone(),
                record.endpoints.clone(),
            );
            hop_details.push(hop);
        }

        // 3. Construct the Route.
        let route = Route::new_with_hop_details(self.source, self.destination, hop_details);

        // 4. Validate the route.
        route.validate()?;

        // 5. Return the validated Route.
        Ok(route)
    }

    /// Get the number of hops (links) in the chain.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.ordered_node_ids.len().saturating_sub(1)
    }

    /// Check if the resolution has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        now_unix() >= self.expiry
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NextHopResolver::resolve_route — recursive multi-hop distributed discovery
//
// **N2.1.3.2-fix:** `ForwardedQuery` is now the actual wire message. A
// sends ONE `ForwardedQuery` to its first hop (B) via
// `RecursiveNextHopTransport::forward_query`. B (a `ForwardingNode`)
// recursively forwards a NEW `ForwardedQuery` to C, and so on, until the
// destination is reached. The response propagates back with the full
// accumulated chain. A constructs the `DistributedRouteResolution` from
// the response — it does NOT loop over `resolve_step`.
// ════════════════════════════════════════════════════════════════════════════

impl<'a> NextHopResolver<'a> {
    /// **N2.1.3.2.** Recursively resolve a destination through multiple hops.
    ///
    /// This method performs recursive multi-hop distributed route discovery
    /// by sending ONE `ForwardedQuery` to the first hop and letting the
    /// `ForwardingNode` participants handle recursive forwarding:
    ///
    /// 1. A constructs `ForwardedQuery(budget=MAX_RESPONSE_HOPS,
    ///    visited=[A], parent=none)`.
    /// 2. A sends it to B via `RecursiveNextHopTransport::forward_query`.
    /// 3. B verifies the query, constructs a NEW `ForwardedQuery` with
    ///    decremented budget and updated `visited_nodes`, and forwards to C.
    /// 4. C repeats the process, forwarding to G (or responding if G is a
    ///    direct neighbor).
    /// 5. G (the destination) responds with `destination_reached=true`.
    /// 6. Each forwarder prepends its assertion + record to the response.
    /// 7. A receives the full `RecursiveRouteResponse` and constructs a
    ///    `DistributedRouteResolution`.
    ///
    /// A does NOT query C or G directly — the forwarding happens inside the
    /// transport's `ForwardingNode` participants.
    ///
    /// # Returns
    /// - `Some(DistributedRouteResolution)` if the destination was reached.
    /// - `None` if resolution failed (no recursive transport, budget
    ///   exhausted, loop detected, destination not reached, advertisement
    ///   verification failed, etc.).
    #[must_use]
    pub fn resolve_route(
        &mut self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
    ) -> Option<DistributedRouteResolution> {
        self.resolve_route_with_budget(destination, hint, MAX_RESPONSE_HOPS)
    }

    /// **N2.1.3.2.** Recursively resolve a destination with a custom initial
    /// hop budget.
    ///
    /// This is the same as `resolve_route` but allows the caller to specify
    /// the initial hop budget. Useful for testing budget exhaustion.
    ///
    /// # Panics
    /// Panics if `initial_budget` is 0.
    #[must_use]
    pub fn resolve_route_with_budget(
        &mut self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
        initial_budget: u8,
    ) -> Option<DistributedRouteResolution> {
        assert!(initial_budget > 0, "initial_budget must be > 0");

        // The recursive transport is REQUIRED for the new architecture.
        // Without it, A cannot send a ForwardedQuery to anyone.
        let recursive_transport = self.recursive_transport?;

        // The first hop is the hint's learned_from (A's direct neighbor).
        let first_hop = hint.learned_from;

        // 1. Construct the initial ForwardedQuery.
        //    - budget = initial_budget
        //    - visited_nodes = [A]
        //    - parent = none (all-zero parent_query_id, parent_responder_node_id,
        //      AND parent_query_hash — the initial query has no parent).
        let initial_query = ForwardedQuery::create_and_sign(
            &self.local_ed25519_secret,
            &self.local_ed25519_public,
            self.local_node_id,
            *destination,
            initial_budget,
            [0u8; 16],           // parent_query_id (none)
            [0u8; 32],           // parent_responder_node_id (none)
            [0u8; 32],           // parent_query_hash (none — initial query)
            vec![self.local_node_id], // visited_nodes = [A]
        );

        // 2. Send the ForwardedQuery to the first hop via the recursive transport.
        //    The first hop (a ForwardingNode) handles recursive forwarding.
        //    A receives the full accumulated RecursiveRouteResponse.
        let response = recursive_transport.forward_query(&first_hop, &initial_query)?;

        // 3. If the response indicates NotFound, resolution failed.
        if response.not_found || !response.destination_reached {
            return None;
        }

        // 3b. **N2.1.3.2-response-auth.** Verify the response_steps chain
        //     starts with the correct query. The first step's
        //     received_query_hash MUST equal `initial_query.compute_hash()`
        //     — this proves the first responder (B) actually received A's
        //     initial query, not a substituted query from a different chain.
        //     This check is done at resolution time (not in verify()) because
        //     the initial ForwardedQuery is not stored in
        //     DistributedRouteResolution.
        if response.response_steps.is_empty() {
            return None;
        }
        let expected_initial_hash = initial_query.compute_hash();
        if response.response_steps[0].received_query_hash != expected_initial_hash {
            return None;
        }
        if response.response_steps[0].received_query_id != initial_query.query_id {
            return None;
        }

        // 4. Verify the destination's advertisement independently.
        //    The destination's advert comes from the response.
        let dest_advert = response.destination_advertisement.as_ref()?;
        let dest_verified = dest_advert.verify_into_verified()?;
        if dest_verified.node_id() != *destination {
            return None;
        }

        // 5. Construct the ordered_node_ids chain.
        //    Chain: [A, first_hop, ...accumulated_records' node_ids, destination]
        //    But accumulated_records already includes the destination's record
        //    (added by the last forwarder). So:
        //    - ordered_node_ids = [A, first_hop] ++ accumulated_records.node_ids
        //      (but first_hop's record is NOT in accumulated_records — it's
        //      added by A from its topology below).
        //    - ordered_records = [first_hop's record (from topology)]
        //                       ++ accumulated_records
        //
        //    accumulated_records from the response:
        //    - For A→B→C→G: accumulated_records = [C's record, G's record]
        //      (B added C's record, C added G's record).
        //    - A adds B's record from its topology.
        //    - Final ordered_records = [B, C, G].

        // Look up the first hop's record in A's topology.
        let first_hop_record = self.topology.get_record(&first_hop).cloned()?;

        // Assemble ordered_records: [first_hop, ...accumulated_records].
        let mut ordered_records: Vec<AuthenticatedNodeRecord> =
            Vec::with_capacity(response.accumulated_records.len() + 1);
        ordered_records.push(first_hop_record);
        ordered_records.extend(response.accumulated_records.iter().cloned());

        // Assemble ordered_node_ids: [A, first_hop, ...accumulated_records.node_ids].
        let mut ordered_node_ids: Vec<[u8; 32]> =
            Vec::with_capacity(ordered_records.len() + 1);
        ordered_node_ids.push(self.local_node_id);
        ordered_node_ids.push(first_hop);
        for record in &response.accumulated_records {
            ordered_node_ids.push(record.node_id());
        }

        // 6. Assemble the query_chain.
        //    The response's query_chain has steps for B→C, C→G, etc.
        //    A prepends its own step (A→B) at the front.
        let mut query_chain: Vec<QueryStep> =
            Vec::with_capacity(response.query_chain.len() + 1);
        query_chain.push(QueryStep {
            source_node_id: self.local_node_id,
            responder_node_id: first_hop,
            query_id: initial_query.query_id,
            remaining_hops: initial_budget.saturating_sub(1),
        });
        query_chain.extend(response.query_chain.iter().cloned());

        // 7. The accumulated_assertions are already in order (B's, C's).
        let ordered_assertions = response.accumulated_assertions.clone();

        // 8. Compute the remaining hop budget.
        //    The response carries the budget at the destination.
        //    Verify it matches initial - num_hops.
        let num_hops = ordered_node_ids.len() - 1;
        let expected_remaining = initial_budget
            .saturating_sub(u8::try_from(num_hops).unwrap_or(u8::MAX));
        // Use the response's remaining_hop_budget if it matches; otherwise
        // compute from the chain length (defensive).
        let remaining_hop_budget = if response.remaining_hop_budget == expected_remaining {
            response.remaining_hop_budget
        } else {
            expected_remaining
        };

        // 9. Construct the DistributedRouteResolution.
        let expiry = now_unix().saturating_add(MAX_ROUTE_RESPONSE_AGE_SECS);
        Some(DistributedRouteResolution {
            source: self.local_node_id,
            destination: *destination,
            ordered_node_ids,
            ordered_records,
            ordered_assertions,
            query_chain,
            initial_hop_budget: initial_budget,
            remaining_hop_budget,
            expiry,
            response_steps: response.response_steps,
        })
    }

    /// **N2.1.3.2.** Get the local node's NodeId.
    #[must_use]
    pub fn local_node_id(&self) -> [u8; 32] {
        self.local_node_id
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.3.2-fix — InMemoryRecursiveTransport + ForwardingNode
//
// Test-only infrastructure that simulates REAL protocol participants.
// Each `ForwardingNode` (B, C, G) has its own NodeId, Ed25519 keypair, and
// neighbor map. When it receives a `ForwardedQuery`:
//   1. Verifies the query signature + parent binding.
//   2. Checks visited_nodes (loop prevention).
//   3. Checks remaining hop budget (> 0).
//   4. If IT is the destination → return RecursiveRouteResponse.
//   5. Otherwise → find next hop, construct a NEW ForwardedQuery with
//      decremented budget + updated visited_nodes + parent binding, and
//      forward via the shared `InMemoryRecursiveTransport`.
//   6. Receive RecursiveRouteResponse from next hop.
//   7. Prepend own assertion + record + query_step.
//   8. Return augmented response.
//
// NOTE: This creates a reference cycle (transport → nodes → transport).
// This is acceptable for test-only code — the leaked memory is reclaimed
// when the test process exits.
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.3.2-fix.** A shared in-memory `RecursiveNextHopTransport` that
/// routes `ForwardedQuery` messages to registered `ForwardingNode`
/// participants.
///
/// Multiple `ForwardingNode`s register with this transport. When a query
/// is forwarded to a NodeId, the transport looks up the registered
/// `ForwardingNode` for that NodeId and calls its `handle_query` method.
///
/// This is the recursive counterpart to `InMemoryNextHopTransport`. The
/// key difference: instead of closures that produce single `NextHopResponse`
/// values, this transport routes to real `ForwardingNode` participants that
/// recursively forward the query.
#[derive(Default)]
pub struct InMemoryRecursiveTransport {
    /// Map from NodeId → registered ForwardingNode.
    nodes: Arc<Mutex<HashMap<[u8; 32], Arc<ForwardingNode>>>>,
}

impl InMemoryRecursiveTransport {
    /// Create a new empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `ForwardingNode` with this transport.
    ///
    /// After registration, queries forwarded to `node.node_id()` will be
    /// routed to `node.handle_query()`.
    pub fn register_node(&self, node: Arc<ForwardingNode>) {
        let node_id = node.node_id();
        let mut nodes = self.nodes.lock().expect("nodes mutex poisoned");
        nodes.insert(node_id, node);
    }

    /// Get the inner `Arc<Mutex<...>>` so `ForwardingNode`s can hold a
    /// back-reference to this transport.
    #[must_use]
    pub fn shared_handle(&self) -> Arc<Mutex<HashMap<[u8; 32], Arc<ForwardingNode>>>> {
        Arc::clone(&self.nodes)
    }
}

impl RecursiveNextHopTransport for InMemoryRecursiveTransport {
    fn forward_query(
        &self,
        neighbor_node_id: &[u8; 32],
        query: &ForwardedQuery,
    ) -> Option<RecursiveRouteResponse> {
        let nodes = self.nodes.lock().expect("nodes mutex poisoned");
        let node = nodes.get(neighbor_node_id)?.clone();
        drop(nodes);
        node.handle_query(query)
    }
}

/// **N2.1.3.2-fix.** A test-only struct that simulates a REAL protocol
/// participant (B, C, or G in the A → B → C → G chain).
///
/// Each `ForwardingNode`:
/// - Has its own NodeId, Ed25519 keypair, and self-advertisement.
/// - Knows its neighbors (map: NodeId → NodeAdvertisement).
/// - When it receives a `ForwardedQuery`:
///   1. Verifies the query signature + parent binding.
///   2. Checks visited_nodes (loop prevention).
///   3. Checks remaining hop budget (> 0).
///   4. If IT is the destination → return RecursiveRouteResponse with
///      destination reached.
///   5. Otherwise → find next hop, construct a NEW ForwardedQuery with
///      decremented hop budget + updated visited_nodes + parent binding,
///      and forward via the shared transport.
///   6. Receive RecursiveRouteResponse from next hop.
///   7. Prepend own assertion + record + query_step.
///   8. Return augmented RecursiveRouteResponse.
pub struct ForwardingNode {
    /// This node's NodeId.
    node_id: [u8; 32],
    /// This node's Ed25519 secret key.
    ed25519_secret: [u8; 32],
    /// This node's Ed25519 public key.
    ed25519_public: [u8; 32],
    /// This node's own advertisement (signed). Used when this node IS the
    /// destination — returned in `RecursiveRouteResponse.destination_advertisement`.
    self_advert: NodeAdvertisement,
    /// Known neighbors: NodeId → NodeAdvertisement. Used to find next hops
    /// and to construct records for the accumulated chain.
    neighbors: HashMap<[u8; 32], NodeAdvertisement>,
    /// Transport to reach other nodes. **N2.2.1:** Generalised from
    /// `Arc<InMemoryRecursiveTransport>` to `Arc<dyn RecursiveNextHopTransport +
    /// Send + Sync>` so the SAME `ForwardingNode` logic works over either
    /// the in-memory transport (tests) or a real TCP transport
    /// (`TcpRecursiveTransport`, production).
    transport: Arc<dyn RecursiveNextHopTransport + Send + Sync>,
}

impl ForwardingNode {
    /// Create a new `ForwardingNode`.
    ///
    /// The node's `self_advert` is constructed from the provided keypair
    /// and capabilities.
    ///
    /// **N2.2.1:** The `transport` parameter is now `Arc<dyn
    /// RecursiveNextHopTransport + Send + Sync>` (was `Arc<InMemoryRecursiveTransport>`).
    /// Existing call sites that pass `Arc<InMemoryRecursiveTransport>` continue
    /// to compile via Rust's unsizing coercion.
    #[must_use]
    pub fn new(
        ed25519_secret: [u8; 32],
        ed25519_public: [u8; 32],
        capabilities: Vec<Capability>,
        endpoints: Vec<TransportEndpoint>,
        x25519_circuit_public: Option<[u8; 32]>,
        transport: Arc<dyn RecursiveNextHopTransport + Send + Sync>,
    ) -> Self {
        let node_id = derive_node_id(&ed25519_public);
        let self_advert = NodeAdvertisement::create_and_sign(
            &ed25519_secret,
            &ed25519_public,
            capabilities,
            endpoints,
            x25519_circuit_public,
            3600,
            1,
        );
        Self {
            node_id,
            ed25519_secret,
            ed25519_public,
            self_advert,
            neighbors: HashMap::new(),
            transport,
        }
    }

    /// Get this node's NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.node_id
    }

    /// **N2.2.1.** Get this node's Ed25519 secret key. Used by
    /// `TcpForwardingServer` to perform the SNP-IK handshake as responder.
    #[must_use]
    pub fn ed25519_secret(&self) -> &[u8; 32] {
        &self.ed25519_secret
    }

    /// **N2.2.1.** Get this node's Ed25519 public key. Used by
    /// `TcpForwardingServer` to perform the SNP-IK handshake as responder.
    #[must_use]
    pub fn ed25519_public(&self) -> &[u8; 32] {
        &self.ed25519_public
    }

    /// Get this node's own advertisement (signed). Used by tests to set up
    /// topology entries and neighbor maps.
    #[must_use]
    pub fn self_advert(&self) -> &NodeAdvertisement {
        &self.self_advert
    }

    /// Add a known neighbor.
    ///
    /// The neighbor's advertisement is stored and used to find next hops
    /// and to construct records for the accumulated chain.
    pub fn add_neighbor(&mut self, neighbor_id: [u8; 32], advert: NodeAdvertisement) {
        self.neighbors.insert(neighbor_id, advert);
    }

    /// **N2.1.3.2-fix.** Handle an incoming `ForwardedQuery`.
    ///
    /// This is the core forwarding logic. See the type-level documentation
    /// for the full algorithm.
    ///
    /// # Returns
    /// - `Some(RecursiveRouteResponse)` if the query was successfully
    ///   handled (either this node is the destination, or the query was
    ///   forwarded and a response was received).
    /// - `None` if the query was rejected (bad signature, loop detected,
    ///   hop budget exhausted, no path to destination, etc.).
    pub fn handle_query(&self, query: &ForwardedQuery) -> Option<RecursiveRouteResponse> {
        // 1. Verify the query signature + parent binding.
        if !query.verify_all() {
            return None;
        }

        // 2. Loop prevention — if we're already in visited_nodes, the query
        //    has come back to us. Reject.
        if query.has_visited(&self.node_id) {
            return None;
        }

        // 3. Check remaining hop budget (> 0).
        if query.max_hops == 0 {
            return None;
        }

        // 4. If we ARE the destination, return a terminal response.
        if query.destination_node_id == self.node_id {
            // **N2.1.3.2-response-auth:** Sign a terminal SignedResponseStep
            // binding this step to the query we received. sent_query_hash is
            // all-zeros (no child query was sent); next_hop_node_id is
            // all-zeros (we are the destination, no forward); not_found is
            // false; destination_reached is true.
            let received_query_hash = query.compute_hash();
            let terminal_step = SignedResponseStep::create_and_sign(
                &self.ed25519_secret,
                &self.ed25519_public,
                self.node_id,                       // responder (us — the destination)
                query.query_id,                     // received_query_id
                received_query_hash,                // received_query_hash
                [0u8; 32],                          // sent_query_hash (terminal — no child)
                true,                               // destination_reached
                [0u8; 32],                          // next_hop_node_id (terminal — no next hop)
                query.max_hops.saturating_sub(1),   // remaining_hop_budget after this step
                false,                              // not_found
            );
            return Some(RecursiveRouteResponse {
                destination_node_id: query.destination_node_id,
                destination_reached: true,
                destination_advertisement: Some(self.self_advert.clone()),
                accumulated_assertions: Vec::new(),
                accumulated_records: Vec::new(),
                query_chain: Vec::new(),
                remaining_hop_budget: query.max_hops.saturating_sub(1),
                not_found: false,
                response_steps: vec![terminal_step],
            });
        }

        // 5. Check budget: need max_hops > 1 to forward (the new query needs
        //    max_hops > 0, which means current max_hops must be > 1).
        if query.max_hops <= 1 {
            // Budget exhausted — can't forward. Return a not-found response.
            //
            // **N2.1.3.2-response-auth:** Sign a terminal SignedResponseStep
            // with not_found=true binding this step to the query we received.
            // sent_query_hash is all-zeros (no child query was sent);
            // next_hop_node_id is all-zeros (no forward); destination_reached
            // is false; not_found is true.
            let received_query_hash = query.compute_hash();
            let not_found_step = SignedResponseStep::create_and_sign(
                &self.ed25519_secret,
                &self.ed25519_public,
                self.node_id,           // responder (us — we can't forward)
                query.query_id,         // received_query_id
                received_query_hash,    // received_query_hash
                [0u8; 32],              // sent_query_hash (terminal — no child)
                false,                  // destination_reached
                [0u8; 32],              // next_hop_node_id (no forward)
                0,                      // remaining_hop_budget
                true,                   // not_found
            );
            return Some(RecursiveRouteResponse {
                destination_node_id: query.destination_node_id,
                destination_reached: false,
                destination_advertisement: None,
                accumulated_assertions: Vec::new(),
                accumulated_records: Vec::new(),
                query_chain: Vec::new(),
                remaining_hop_budget: 0,
                not_found: true,
                response_steps: vec![not_found_step],
            });
        }

        // 6. Find the next hop toward the destination.
        let next_hop_id = self.find_next_hop(
            &query.destination_node_id,
            &query.visited_nodes,
        )?;

        // 7. Loop prevention — next hop must not be in visited_nodes.
        if query.has_visited(&next_hop_id) {
            return None;
        }

        // 8. Get the next hop's advertisement (we must know it to forward).
        let next_hop_advert = self.neighbors.get(&next_hop_id)?.clone();

        // 9. Construct a NEW ForwardedQuery with:
        //    - Decremented hop budget (query.max_hops - 1)
        //    - Updated visited_nodes (add self)
        //    - Parent binding to the current query (parent_query_id =
        //      current query_id, parent_responder_node_id = self,
        //      parent_query_hash = SHA-256 of the COMPLETE current query).
        //
        //    **N2.1.3.2-security:** The parent_query_hash binds the new
        //    query to the ACTUAL parent message that was received and
        //    verified. A malicious forwarder cannot invent a parent_query_id
        //    for a query that was never sent — the hash would not match
        //    any real parent message.
        let mut new_visited = query.visited_nodes.clone();
        new_visited.push(self.node_id);
        let parent_query_hash = query.compute_hash();
        let new_query = ForwardedQuery::create_and_sign(
            &self.ed25519_secret,
            &self.ed25519_public,
            self.node_id,
            query.destination_node_id,
            query.max_hops - 1,
            query.query_id,        // parent_query_id (the query we received)
            self.node_id,          // parent_responder_node_id (us — we're forwarding)
            parent_query_hash,     // SHA-256 of the complete parent query
            new_visited,
        );

        // 10. Forward to next hop via the shared transport.
        let mut response = self.transport.forward_query(&next_hop_id, &new_query)?;

        // If the response is not_found, propagate it (don't add our assertion).
        if response.not_found {
            return Some(response);
        }

        // 11. Verify the next hop's advertisement and create a record.
        let verified = next_hop_advert.verify_into_verified()?;
        let record = verified.into_record();

        // 12. Construct our routing assertion.
        //     `is_destination` is true iff the next_hop IS the destination.
        //     B forwards to C (C != G) → is_destination=false.
        //     C forwards to G (G == G) → is_destination=true.
        //
        //     **N2.1.3.2-security:** The assertion is SIGNED by us (the
        //     responder). The signature covers the assertion preimage
        //     (responder_node_id, destination_node_id, next_hop_node_id,
        //     is_destination, query_id, timestamp, responder_public_key)
        //     under ROUTE_DISCOVERY_MSG_CONTEXT. A cannot forge our claim
        //     — any tampering with the assertion invalidates the signature.
        let is_destination = next_hop_id == query.destination_node_id;
        let our_assertion = RoutingAssertion::create_and_sign(
            &self.ed25519_secret,
            &self.ed25519_public,
            self.node_id,                 // responder_node_id (us)
            query.destination_node_id,
            next_hop_id,
            is_destination,
            new_query.query_id,
        );

        // 13. Prepend our assertion + record + query_step to the response.
        response.accumulated_assertions.insert(0, our_assertion);
        response.accumulated_records.insert(0, record);
        response.query_chain.insert(0, QueryStep {
            source_node_id: self.node_id,
            responder_node_id: next_hop_id,
            query_id: new_query.query_id,
            remaining_hops: new_query.max_hops.saturating_sub(1),
        });

        // 14. **N2.1.3.2-response-auth.** Prepend our SignedResponseStep.
        //     Bind our step to:
        //     - the query we RECEIVED (query.query_id, query.compute_hash())
        //     - the child query we SENT (new_query.compute_hash())
        //     - the destination state at THIS step (is_destination — same
        //       value as our assertion's is_destination, so the verify check
        //       `step.destination_reached == assertion.is_destination` holds)
        //     - the remaining_hop_budget from the child response
        //     - our next_hop (next_hop_id)
        //     - not_found = false (we successfully forwarded)
        //
        //     The signature covers all of these fields, so any tampering with
        //     destination_reached, next_hop_node_id, remaining_hop_budget, or
        //     not_found invalidates the signature. The chain of
        //     sent_query_hash → next step's received_query_hash proves the
        //     responders actually handled the queries they claim to have
        //     handled.
        let received_query_hash = parent_query_hash; // hash of the query we received
        let sent_query_hash = new_query.compute_hash(); // hash of the child query we sent
        let our_step = SignedResponseStep::create_and_sign(
            &self.ed25519_secret,
            &self.ed25519_public,
            self.node_id,                       // responder (us — the forwarder)
            query.query_id,                     // received_query_id
            received_query_hash,                // received_query_hash (query we received)
            sent_query_hash,                    // sent_query_hash (child query we sent)
            is_destination,                     // destination_reached (this step's claim — matches assertion)
            next_hop_id,                        // next_hop_node_id (the node we forwarded to)
            response.remaining_hop_budget,      // remaining_hop_budget (from child response)
            false,                              // not_found (we successfully forwarded)
        );
        response.response_steps.insert(0, our_step);

        Some(response)
    }

    /// Find the next hop toward the destination.
    ///
    /// Strategy:
    /// 1. If the destination is a direct neighbor, return it.
    /// 2. Otherwise, return any neighbor not in `visited` (and not self).
    /// 3. If no suitable neighbor is found, return `None`.
    fn find_next_hop(
        &self,
        destination: &[u8; 32],
        visited: &[[u8; 32]],
    ) -> Option<[u8; 32]> {
        // 1. If destination is a direct neighbor, return it.
        if self.neighbors.contains_key(destination) {
            return Some(*destination);
        }
        // 2. Return any unvisited neighbor (excluding self).
        for neighbor_id in self.neighbors.keys() {
            if *neighbor_id != self.node_id && !visited.contains(neighbor_id) {
                return Some(*neighbor_id);
            }
        }
        None
    }
}
