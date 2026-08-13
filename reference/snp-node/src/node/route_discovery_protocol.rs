//! N2.1.3 / N2.1.3.1 / N2.1.3.1.1 — Distributed Route Discovery Protocol Foundation.
//!
//! **This module implements a SINGLE-STEP distributed next-hop
//! query/response protocol foundation.** It does NOT yet implement
//! recursive multi-hop discovery (A → B → C → G). That is a future
//! milestone (N2.1.3.2).
//!
//! ## What is implemented
//!
//! - Signed `NextHopQuery` / `NextHopResponse` messages.
//! - `PendingRouteQuery` state for stateful response acceptance.
//! - Expected-responder binding (response must come from the queried neighbor).
//! - Replay protection (each query can only be consumed once).
//! - Freshness validation (MAX_ROUTE_QUERY_AGE, MAX_ROUTE_RESPONSE_AGE).
//! - `max_hops` validation (>0, reject invalid) + decrement semantics.
//! - `RoutingAssertion` type — distinguishes "B claims C is next hop" from
//!   "C is C" (identity proof).
//! - `DistributedRouteResolver` trait — stateful interface for distributed
//!   protocol resolution (separate from the stateless `DestinationResolver`).
//! - `QueryProvenance` — data structure for future recursive query chaining.
//! - `NextHopResolver` implementing `DistributedRouteResolver` for
//!   single-step resolution with persistent state.
//!
//! ## N2.1.3.1.1: Stateful composition
//!
//! The `DestinationResolver` trait is **stateless** (`&self`) and remains
//! for LOCAL/pure lookup. The `DistributedRouteResolver` trait is
//! **stateful** (`&mut self`) and owns `PendingRouteQuery` state across
//! query/response exchanges. The `NextHopResolver` no longer implements
//! `DestinationResolver` — callers must use `DistributedRouteResolver`
//! for distributed resolution.
//!
//! ## What is NOT implemented
//!
//! - Recursive multi-hop forwarding (A → B → C → G).
//! - Real network transport (only `InMemoryNextHopTransport`).
//! - Proof that the responder has a usable link to the next hop
//!   (the response is a routing assertion, not a link proof).
//!
//! ## Protocol overview (single-step)
//!
//! ```text
//! Client A (wants route to G)
//!     │
//!     │ 1. Creates PendingRouteQuery { destination: G, expected_responder: B }
//!     │ 2. Sends NextHopQuery { destination: G, query_id } to B
//!     ▼
//! Relay B (A's authenticated neighbor)
//!     │
//!     │ 3. B checks its local topology + hints.
//!     │    If B knows G → respond with G's advertisement.
//!     │    If B knows a next hop C → respond with C's advertisement.
//!     │    If B doesn't know → respond with NotFound.
//!     │
//!     │ 4. NextHopResponse { query_id, responder: B, result }
//!     ▼
//! Client A
//!     │
//!     │ 5. A verifies:
//!     │    - Response signature (B signed it).
//!     │    - responder_node_id == expected_responder (B).
//!     │    - query_id matches pending query.
//!     │    - Query not expired, not already consumed.
//!     │    - Response not expired, not future-dated.
//!     │    - Advertisement verifies independently.
//!     │ 6. A accepts the RoutingAssertion (B claims C/G is next hop).
//!     │ 7. A does NOT yet recursively query C. (Future: N2.1.3.2)
//! ```
//!
//! ## Security model
//!
//! - Every `NextHopQuery` and `NextHopResponse` is **signed** by the sender.
//! - The sender's NodeId is bound to the Ed25519 public key (I4 consistency).
//! - The `query_id` correlates query and response, but is NOT by itself a
//!   replay cache — `PendingRouteQuery` state is required.
//! - The response's `responder_node_id` MUST match the neighbor that was
//!   queried. A valid signature from a different node is rejected.
//! - The advertisement in a `NextHopResponse` is a full `NodeAdvertisement`
//!   that the receiver MUST verify independently via
//!   `verify_into_verified()`.
//! - A `RoutingAssertion` is a signed claim by the responder. It proves
//!   "B claims C is the next hop." It does NOT prove "B has a usable link
//!   to C" or "A can reach C."

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, sig_contexts};

/// The SIG_CONTEXT for route-discovery messages.
pub const ROUTE_DISCOVERY_MSG_CONTEXT: &[u8] = b"SNP/0.1 route-discovery\0";

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
/// A `RoutingAssertion` is constructed from a verified `NextHopResponse`
/// (signature verified, responder matches expected neighbor, query matches
/// pending state, freshness validated). The advertisement in the response
/// must be independently verified via `verify_into_verified()`.
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
}

impl RoutingAssertion {
    /// Construct a `RoutingAssertion` from a verified `NextHopResponse`.
    ///
    /// The caller MUST have already verified:
    /// - Response signature.
    /// - Responder matches expected neighbor.
    /// - Query matches pending state.
    /// - Response freshness.
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
            }),
            NextHopResult::NotFound => None,
        }
    }

    /// Check if this assertion claims the next hop is the destination.
    #[must_use]
    pub fn claims_destination_reached(&self) -> bool {
        self.is_destination && self.next_hop_node_id == self.destination_node_id
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
/// 2. It selects the hint's `learned_from` as the neighbor to query.
/// 3. It creates a `PendingRouteQuery` (stateful tracking).
/// 4. It sends a `NextHopQuery` to that neighbor.
/// 5. It receives a `NextHopResponse`.
/// 6. It verifies ALL of:
///    - Response signature + I4.
///    - Response freshness (not too old, not future-dated).
///    - Responder == expected neighbor (queried neighbor).
///    - query_id matches pending query.
///    - Pending query not expired, not consumed.
/// 7. It marks the pending query as consumed (replay protection).
/// 8. It verifies the advertisement via `verify_into_verified()`.
/// 9. It returns the `NextHopResolution` (assertion + record).
///
/// ## Security
///
/// - Expected-responder binding: response must come from the queried neighbor.
/// - Replay protection: each query can only be consumed once.
/// - Freshness: query and response have bounded age.
/// - max_hops validation: must be > 0.
/// - Advertisement verified independently.
/// - **State persists across calls** (N2.1.3.1.1).
pub struct NextHopResolver<'a> {
    /// The local topology (for finding authenticated neighbors to query).
    topology: &'a TopologyGraph,
    /// The transport for sending queries and receiving responses.
    transport: &'a dyn NextHopTransport,
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
            local_ed25519_secret,
            local_ed25519_public,
            local_node_id,
            pending_queries: HashMap::new(),
        }
    }

    /// Get a reference to the pending queries map.
    #[must_use]
    pub fn pending_queries(&self) -> &HashMap<[u8; 16], PendingRouteQuery> {
        &self.pending_queries
    }
}

/// **N2.1.3.1.2.** Maximum number of pending (unconsumed) route queries.
/// Prevents unbounded memory growth from route-discovery requests.
pub const MAX_PENDING_ROUTE_QUERIES: usize = 256;

impl<'a> DistributedRouteResolver for NextHopResolver<'a> {
    fn resolve_step(
        &mut self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
    ) -> Option<NextHopResolution> {
        // Step 0: Purge expired pending queries (resource management).
        self.purge_expired_pending_queries();

        // Step 0b: Check capacity — reject if too many pending queries.
        if self.pending_queries.values().filter(|p| !p.consumed).count() >= MAX_PENDING_ROUTE_QUERIES {
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
