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
    /// The source's signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖
    /// CBOR(parent_binding_preimage)`. Covers `parent_query_id`,
    /// `parent_responder_node_id`, `visited_nodes`, and `query_id` (to bind
    /// the parent relationship to this specific query).
    pub parent_signature: [u8; 64],
}

impl ForwardedQuery {
    /// Create and sign a `ForwardedQuery`.
    ///
    /// The `signature` field is the standard `NextHopQuery` signature (over
    /// the NextHopQuery preimage only). The `parent_signature` field covers
    /// the parent binding fields.
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
    fn parent_binding_preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("queryId".into()), CborValue::ByteString(self.query_id.to_vec())),
            (CborValue::TextString("parentQueryId".into()), CborValue::ByteString(self.parent_query_id.to_vec())),
            (CborValue::TextString("parentResponderNodeId".into()), CborValue::ByteString(self.parent_responder_node_id.to_vec())),
            (CborValue::TextString("visitedNodes".into()), CborValue::Array(
                self.visited_nodes.iter().map(|n| CborValue::ByteString(n.to_vec())).collect()
            )),
        ])
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
        self.parent_query_id == [0u8; 16] && self.parent_responder_node_id == [0u8; 32]
    }

    /// Check if a node has already been visited (loop prevention).
    #[must_use]
    pub fn has_visited(&self, node_id: &[u8; 32]) -> bool {
        self.visited_nodes.contains(node_id)
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

        // 8. Every RoutingAssertion is valid + hop order is coherent.
        // For assertion i:
        //   - responder_node_id == ordered_node_ids[i+1]
        //   - next_hop_node_id == ordered_node_ids[i+2]
        //   - next_hop_node_id == ordered_records[i+1].node_id()
        //   - destination_node_id == self.destination
        //   - the LAST assertion should have is_destination=true and
        //     next_hop_node_id == destination.
        for (i, assertion) in self.ordered_assertions.iter().enumerate() {
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
// ════════════════════════════════════════════════════════════════════════════

impl<'a> NextHopResolver<'a> {
    /// **N2.1.3.2.** Recursively resolve a destination through multiple hops.
    ///
    /// This method performs recursive multi-hop distributed route discovery:
    ///
    /// 1. A queries B (using `resolve_step`).
    /// 2. If B returns a next hop C (not the destination), A queries C.
    /// 3. If C returns a next hop G (destination), resolution is complete.
    ///
    /// At each step:
    /// - Decrement the hop budget.
    /// - Add the current responder to `visited_nodes` (loop prevention).
    /// - Verify the response (via `resolve_step`).
    /// - Accumulate the routing assertion + node record.
    ///
    /// # Loop prevention
    ///
    /// Before forwarding a query to a node, the resolver checks if that node
    /// is already in `visited_nodes`. If so, the resolution is rejected
    /// (loop detected).
    ///
    /// # Hop budget
    ///
    /// The hop budget starts at `MAX_RESPONSE_HOPS` (16). Each forward
    /// decrements it by 1. If the budget reaches 0 before the destination is
    /// reached, the resolution is rejected (budget exhausted). There is NO
    /// way to increase the budget.
    ///
    /// # Returns
    /// - `Some(DistributedRouteResolution)` if the destination was reached.
    /// - `None` if resolution failed (budget exhausted, loop detected,
    ///   responder returned NotFound, advertisement verification failed,
    ///   etc.).
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

        // Track resolution state.
        let mut remaining_budget = initial_budget;
        let mut visited_nodes: Vec<[u8; 32]> = vec![self.local_node_id];
        let mut ordered_node_ids: Vec<[u8; 32]> = vec![self.local_node_id];
        let mut ordered_records: Vec<AuthenticatedNodeRecord> = Vec::new();
        let mut ordered_assertions: Vec<RoutingAssertion> = Vec::new();
        let mut query_chain: Vec<QueryStep> = Vec::new();
        let mut parent_query_id: [u8; 16] = [0u8; 16];
        let mut parent_responder_node_id: [u8; 32] = [0u8; 32];

        // The current hint tells us which neighbor to query.
        let mut current_hint = hint.clone();

        loop {
            // 1. Hop budget check — if exhausted, reject.
            if remaining_budget == 0 {
                return None;
            }
            // Decrement the budget for this forward step.
            remaining_budget -= 1;

            // 2. Loop prevention — check if the responder is already visited.
            let next_responder = current_hint.learned_from;
            if visited_nodes.contains(&next_responder) {
                // Loop detected — reject.
                return None;
            }

            // 3. Construct a ForwardedQuery to track parent binding (internal
            //    metadata; the actual transport uses a NextHopQuery via
            //    resolve_step).
            let _forwarded = ForwardedQuery::create_and_sign(
                &self.local_ed25519_secret,
                &self.local_ed25519_public,
                self.local_node_id,
                *destination,
                MAX_RESPONSE_HOPS,
                parent_query_id,
                parent_responder_node_id,
                visited_nodes.clone(),
            );
            // The forwarded query's query_id will be DIFFERENT from the one
            // resolve_step generates (since both use getrandom). The
            // forwarded query is metadata only — it is NOT sent over the
            // transport. The parent binding is tracked via the assertion's
            // query_id (set below).

            // 4. Call resolve_step to do the actual query/response.
            let resolution = self.resolve_step(destination, &current_hint)?;
            let assertion = resolution.assertion.clone();
            let record = resolution.record.clone();

            // 5. Track the query step (using the assertion's query_id, which
            //    is the actual query_id used by resolve_step).
            query_chain.push(QueryStep {
                source_node_id: self.local_node_id,
                responder_node_id: next_responder,
                query_id: assertion.query_id,
                remaining_hops: remaining_budget,
            });

            // 6. Update parent binding for the next iteration.
            parent_query_id = assertion.query_id;
            parent_responder_node_id = next_responder;

            // 7. Add the responder to visited_nodes (loop prevention).
            visited_nodes.push(next_responder);

            // 8. Add the responder's record to ordered_records.
            //    The responder's record comes from the topology (if available)
            //    or is implicit (we queried them, so they must be authenticated).
            //    For the FIRST iteration, the responder is the hint's
            //    learned_from — A's neighbor, whose record should be in the
            //    topology. For subsequent iterations, the responder is the
            //    previous step's next_hop — whose record was returned in the
            //    previous step's response.
            let responder_record: Option<AuthenticatedNodeRecord> = if ordered_node_ids.len() == 1 {
                // First iteration: responder = hint.learned_from (A's neighbor).
                // Look up the responder's record in the topology.
                self.topology.get_record(&next_responder).cloned()
            } else {
                // Subsequent iteration: responder = previous step's next_hop.
                // Their record was the previous step's returned record.
                ordered_records.last().cloned()
            };

            // The record returned by resolve_step is the NEXT hop's record
            // (what the responder claims is the next hop). Add it to
            // ordered_records.
            //
            // But first, we need to add the responder's record (if not already
            // present). The responder's record is added BEFORE the next hop's
            // record to maintain the chain order.
            if let Some(r) = responder_record {
                // Add the responder's record if it's not already the last
                // record (which would happen if the responder was the
                // previous step's next_hop).
                let already_last = ordered_records
                    .last()
                    .map_or(false, |last| last.node_id() == r.node_id());
                if !already_last {
                    ordered_records.push(r);
                    ordered_node_ids.push(next_responder);
                }
            } else {
                // We don't have the responder's record (e.g., it's not in
                // the topology). This happens when the responder was the
                // previous step's next_hop. In that case, the responder's
                // record WAS the previous step's returned record, which is
                // already in ordered_records.
                //
                // Make sure the responder is in ordered_node_ids.
                if !ordered_node_ids.contains(&next_responder) {
                    ordered_node_ids.push(next_responder);
                }
            }

            // 9. Add the assertion + next hop's record.
            ordered_assertions.push(assertion.clone());
            ordered_node_ids.push(record.node_id());
            ordered_records.push(record.clone());

            // 10. Check if destination reached.
            if assertion.claims_destination_reached() {
                // Destination reached — construct the resolution.
                let num_hops = ordered_node_ids.len() - 1;
                let final_remaining = initial_budget
                    .saturating_sub(u8::try_from(num_hops).unwrap_or(u8::MAX));
                let expiry = now_unix().saturating_add(MAX_ROUTE_RESPONSE_AGE_SECS);
                return Some(DistributedRouteResolution {
                    source: self.local_node_id,
                    destination: *destination,
                    ordered_node_ids,
                    ordered_records,
                    ordered_assertions,
                    query_chain,
                    initial_hop_budget: initial_budget,
                    remaining_hop_budget: final_remaining,
                    expiry,
                });
            }

            // 11. Set up the next iteration.
            // The next responder is the current step's next_hop.
            current_hint = RemoteNodeHint {
                target_node_id: *destination,
                learned_from: assertion.next_hop_node_id,
                claimed_sequence: 0,
                claimed_capabilities: Vec::new(),
                claimed_visibility: String::new(),
                claimed_last_seen: 0,
                distance_hint: 0,
                received_at: 0,
                source_propagation_sequence: 0,
            };
        }
    }

    /// **N2.1.3.2.** Get the local node's NodeId.
    #[must_use]
    pub fn local_node_id(&self) -> [u8; 32] {
        self.local_node_id
    }
}
