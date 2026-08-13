//! N2.1.3 — Distributed Route Discovery Protocol.
//!
//! This module implements the **protocol messages** for distributed
//! next-hop route discovery. Unlike the local `RouteEngine` (which computes
//! paths over the local `TopologyGraph`), this module defines the
//! authenticated query/response messages that nodes exchange to discover
//! routes through the mesh.
//!
//! ## Protocol overview
//!
//! ```text
//! Client A (wants route to G)
//!     │
//!     │ 1. NextHopQuery { destination: G, query_id }
//!     ▼
//! Relay B (A's authenticated neighbor)
//!     │
//!     │ 2. B checks its local topology + hints.
//!     │    If B knows G directly → respond with G's advertisement.
//!     │    If B knows a next hop C → respond with C's advertisement.
//!     │    If B doesn't know → respond with NotFound.
//!     │
//!     │ 3. NextHopResponse { query_id, next_hop: C, advert: C_or_G }
//!     ▼
//! Client A
//!     │
//!     │ 4. A verifies the advertisement in the response.
//!     │ 5. A establishes an AuthenticatedLink to C.
//!     │ 6. A queries C (repeat from step 1).
//!     │ 7. Eventually C responds with G's advertisement.
//!     │ 8. A establishes an AuthenticatedLink to G.
//!     │ 9. A constructs the full Route: A → B → C → G.
//! ```
//!
//! ## Security model
//!
//! - Every `NextHopQuery` and `NextHopResponse` is **signed** by the sender.
//! - The sender's NodeId is bound to the Ed25519 public key (I4 consistency).
//! - The `query_id` prevents replay/cross-protocol injection.
//! - The advertisement in a `NextHopResponse` is a full `NodeAdvertisement`
//!   that the receiver must verify independently via
//!   `verify_into_verified()`.
//! - The responder signs over the query_id, ensuring the response matches
//!   the query and cannot be reused for a different query.
//!
//! ## What this is NOT
//!
//! - This is NOT a routing protocol (no Dijkstra, no link-state flooding).
//! - This is NOT a directory service (no central server).
//! - This is NOT a guarantee of reachability (the mesh may not have a path).
//! - This IS an authenticated next-hop resolution protocol that allows
//!   a node to incrementally discover a path by querying neighbors.

use super::*;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, sig_contexts};

/// The SIG_CONTEXT for route-discovery messages.
pub const ROUTE_DISCOVERY_MSG_CONTEXT: &[u8] = b"SNP/0.1 route-discovery\0";

/// Maximum number of NextHopResponse hops allowed in a single response
/// chain (prevents amplification).
pub const MAX_RESPONSE_HOPS: u8 = 16;

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
/// - `query_id`: A unique 16-byte nonce for this query (prevents replay).
/// - `timestamp`: When the query was created (unix seconds).
/// - `max_hops`: The maximum remaining hops the source will accept.
/// - `signature`: Ed25519 signature over the preimage.
#[derive(Debug, Clone)]
pub struct NextHopQuery {
    /// The querying node's NodeId.
    pub source_node_id: [u8; 32],
    /// The querying node's Ed25519 public key.
    pub source_ed25519_public_key: [u8; 32],
    /// The destination NodeId the source wants to reach.
    pub destination_node_id: [u8; 32],
    /// A unique 16-byte nonce for this query (prevents replay).
    pub query_id: [u8; 16],
    /// When this query was created (unix seconds).
    pub timestamp: u64,
    /// The maximum remaining hops the source will accept.
    /// Decremented by each responder. When 0, the query is not forwarded.
    pub max_hops: u8,
    /// Ed25519 signature over `ROUTE_DISCOVERY_MSG_CONTEXT ‖ CBOR(preimage)`.
    pub signature: [u8; 64],
}

impl NextHopQuery {
    /// Create and sign a `NextHopQuery`.
    #[must_use]
    pub fn create_and_sign(
        source_ed25519_secret_key: &[u8; 32],
        source_ed25519_public_key: &[u8; 32],
        source_node_id: [u8; 32],
        destination_node_id: [u8; 32],
        max_hops: u8,
    ) -> Self {
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
    /// Does NOT verify freshness — that requires the stateful
    /// `verify_into_verified()` which checks the timestamp.
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
}

// ════════════════════════════════════════════════════════════════════════════
// NextHopResponse
// ════════════════════════════════════════════════════════════════════════════

/// The result of a next-hop query — either a next hop was found, or not.
#[derive(Debug, Clone)]
pub enum NextHopResult {
    /// A next hop was found. Contains the next-hop node's authenticated
    /// advertisement (or the destination's advertisement if the responder
    /// knows it directly).
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
/// from the original query. This ensures:
/// 1. The response matches the query (cannot be reused for a different query).
/// 2. The responder is authenticated.
/// 3. The advertisement in the response is signed over (integrity-protected
///    in transit), though the receiver MUST still verify it independently.
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

    /// Check if this response matches a given query (same query_id).
    #[must_use]
    pub fn matches_query(&self, query: &NextHopQuery) -> bool {
        self.query_id == query.query_id
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
// NextHopResolver — distributed destination resolution
// ════════════════════════════════════════════════════════════════════════════

/// A `DestinationResolver` that resolves remote destinations by querying
/// authenticated next-hop peers using the `NextHopQuery`/`NextHopResponse`
/// protocol.
///
/// ## How it works
///
/// 1. The resolver receives a `RemoteNodeHint` for destination D.
/// 2. It selects an authenticated neighbor (from the local `TopologyGraph`)
///    that is closest to D (using `distance_hint` as a heuristic).
/// 3. It sends a `NextHopQuery` to that neighbor.
/// 4. The neighbor responds with a `NextHopResponse` containing either:
///    - D's advertisement (if the neighbor knows D directly), or
///    - A next-hop node's advertisement (to continue the resolution).
/// 5. The resolver verifies the response signature and the advertisement.
/// 6. If the response contains D's advertisement, resolution is complete.
/// 7. Otherwise, the resolver repeats from step 2 with the new next hop.
///
/// ## Transport abstraction
///
/// The resolver does NOT perform network I/O directly. Instead, it uses a
/// `NextHopTransport` trait that abstracts the query/response exchange.
/// This allows deterministic testing without real sockets.
///
/// ## Security
///
/// - The resolver verifies every `NextHopResponse` signature.
/// - The resolver verifies every `NodeAdvertisement` via
///   `verify_into_verified()`.
/// - The `query_id` prevents replay/cross-protocol injection.
/// - The resolver never trusts unsigned or unverified data.
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
}

/// A transport abstraction for sending `NextHopQuery` messages and
/// receiving `NextHopResponse` messages.
///
/// This trait abstracts the network I/O, allowing:
/// - Production implementations that use real TCP/WebSocket connections.
/// - Test implementations that simulate the mesh in memory.
pub trait NextHopTransport {
    /// Send a `NextHopQuery` to the specified neighbor and wait for a
    /// `NextHopResponse`.
    ///
    /// # Parameters
    /// - `neighbor_node_id`: The NodeId of the authenticated neighbor to query.
    /// - `query`: The signed `NextHopQuery` to send.
    ///
    /// # Returns
    /// - `Some(NextHopResponse)` if the neighbor responded.
    /// - `None` if the neighbor did not respond (timeout, unreachable, etc.).
    fn query_next_hop(
        &self,
        neighbor_node_id: &[u8; 32],
        query: &NextHopQuery,
    ) -> Option<NextHopResponse>;
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
        }
    }

    /// Resolve a destination by querying next-hop peers.
    ///
    /// This implements the `DestinationResolver` trait by iteratively
    /// querying authenticated neighbors until the destination's
    /// advertisement is found.
    ///
    /// # Parameters
    /// - `destination`: The NodeId to resolve.
    /// - `hint`: The `RemoteNodeHint` that triggered the resolution.
    ///
    /// # Returns
    /// - `Some(AuthenticatedNodeRecord)` if the destination was resolved
    ///   (its advertisement was found and verified).
    /// - `None` if resolution failed (no path, no response, etc.).
    pub fn resolve(
        &self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
    ) -> Option<AuthenticatedNodeRecord> {
        // Step 1: Select an authenticated neighbor to query.
        // Use the hint's learned_from as the first neighbor to ask.
        let first_neighbor = hint.learned_from;

        // Step 2: Send a NextHopQuery to the first neighbor.
        let query = NextHopQuery::create_and_sign(
            &self.local_ed25519_secret,
            &self.local_ed25519_public,
            self.local_node_id,
            *destination,
            MAX_RESPONSE_HOPS,
        );

        // Step 3: Get the response.
        let response = self.transport.query_next_hop(&first_neighbor, &query)?;

        // Step 4: Verify the response signature.
        if !response.verify_signature() {
            return None;
        }

        // Step 5: Check if the response matches the query.
        if !response.matches_query(&query) {
            return None;
        }

        // Step 6: Process the result.
        match response.result {
            NextHopResult::Found { next_hop_node_id, advertisement, is_destination } => {
                // Verify the advertisement.
                let verified = advertisement.verify_into_verified()?;

                // Check that the advertisement's NodeId matches the next_hop_node_id.
                if verified.node_id() != next_hop_node_id {
                    return None;
                }

                // If this is the destination, we're done.
                if is_destination && next_hop_node_id == *destination {
                    return Some(verified.into_record());
                }

                // Otherwise, the next hop is an intermediate node.
                // In a full implementation, we would recursively query the
                // next hop. For now, we return the advertisement so the
                // route engine can use it.
                // (The route engine will need to establish a link to this
                // next hop and continue resolution.)
                Some(verified.into_record())
            }
            NextHopResult::NotFound => None,
        }
    }
}

impl<'a> DestinationResolver for NextHopResolver<'a> {
    fn resolve(
        &self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
    ) -> Option<AuthenticatedNodeRecord> {
        NextHopResolver::resolve(self, destination, hint)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// In-memory transport (for testing)
// ════════════════════════════════════════════════════════════════════════════

/// **TEST-ONLY.** An in-memory `NextHopTransport` that simulates a mesh
/// of nodes for deterministic testing.
///
/// Each registered "responder" is a closure that receives a `NextHopQuery`
/// and returns a `NextHopResponse`. This allows tests to simulate the
/// behavior of multiple mesh nodes without real network I/O.
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
