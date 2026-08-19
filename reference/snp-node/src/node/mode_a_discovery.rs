//! Mode-A live candidate discovery + route construction (R4.5).
//!
//! R4.5 replaces the R4.4 **configured signed-descriptor bootstrap** with a
//! **live discovery** path: relay/gateway candidates are obtained at runtime
//! over the network, verified, and only THEN handed to the L6 route builder.
//!
//! ```text
//! bootstrap peer (TCP discovery address)
//!     ↓
//! live discovery query (1-byte request → length-prefixed CBOR advert)
//!     ↓
//! NodeAdvertisement::decode_cbor + verify_into_verified
//!     ↓
//! VerifiedNodeAdvertisement  (signature + NodeId↔pubkey + expiry + role/key)
//!     ↓
//! AdvertisementAcceptanceStore  (verified candidate set + replay prevention)
//!     ↓
//! build_mode_a_route  (L6 route builder: capability-gated, expiry-enforced)
//!     ↓
//! Route / RouteHop  (endpoint == signed advert listen_addr)
//!     ↓
//! BundleForwarder  (UNCHANGED — receives the immutable Route)
//! ```
//!
//! # Architectural separation (Steps 15–16)
//!
//! - **Discovery** (this module's serve + query) finds/advertises candidates
//!   and verifies them. It does NOT choose a route, order hops, or pick a
//!   gateway. It only populates the candidate store.
//! - **Routing** (`build_mode_a_route`) reads the candidate store, filters by
//!   capability + expiry + endpoint, selects the gateway by capability, and
//!   builds the immutable `Route` from verified descriptors.
//! - **L5** (`snp-sync`) is untouched — no discovery/routing/transport import.
//! - **L8** (`AuthenticatedBundleCarrier`) remains the authority for transport
//!   identity; a discovered candidate is only a candidate until the L8
//!   handshake authenticates it.
//!
//! # What is NOT done here (R4.5 boundaries)
//!
//! - No durable persistence (`AdvertisementAcceptanceStore::new()` is
//!   in-memory; `persist()` is a no-op with an empty path).
//! - No live route migration/repair (a route may remain fixed after
//!   construction — Step 13).
//! - No Civic / settlement.
//!
//! # Reused infrastructure (no new L4/L5/L6 types)
//!
//! - `NodeAdvertisement` (encode/decode/`verify_into_verified`/`is_expired`)
//! - `AdvertisementAcceptanceStore` (`accept`/`all_records`/`purge_expired`)
//! - `AuthenticatedNodeRecord` (descriptor + signed endpoints + expiry)
//! - The existing discovery wire framing: 1-byte request (`0x01`) +
//!   4-byte big-endian length prefix + canonical-CBOR advert body.
//! - `Route`/`RouteHop`/`Route::new_with_hop_details` (immutable route).
//! - `BundleForwarder` (UNCHANGED — operates on the route, never queries
//!   discovery).

use super::*;

use snp_identity::NodeId;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as TokioMutex;

use std::sync::Arc;

use crate::node::descriptor::TransportEndpoint;
use crate::node::identity::Capability;
use crate::node::node_advert::{
    AdvertisementAcceptanceStore, AuthenticatedNodeRecord, NodeAdvertisement,
    VerifiedNodeAdvertisement,
};
use crate::node::route::{Route, RouteHop};

/// Short hex representation of a byte slice (first 8 hex chars + "..") for
/// log/error messages. Defined locally to avoid depending on a private
/// helper in `mode_a_bundle.rs` (frozen R4.4).
fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{hex}..")
}

/// The discovery request byte. Reuses the existing discovery wire protocol
/// (`0x01` — same as `discovery::DISCOVERY_REQUEST_BYTE`). Redefined locally
/// to avoid a cross-module dependency on a private constant; the wire byte is
/// identical so a discovery server/client built here interoperate with the
/// existing framing.
const MODE_A_DISCOVERY_REQUEST_BYTE: u8 = 0x01;

/// Maximum accepted advertisement size on the wire (defence against a peer
/// that sends a runaway length prefix).
const MAX_ADVERTISEMENT_LEN: usize = 64 * 1024;

// ─── Errors ──────────────────────────────────────────────────────────────

/// Errors from Mode-A live discovery + route construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModeADiscoveryError {
    /// No candidates were discovered (discovery returned nothing, or the
    /// candidate store is empty). The route cannot be constructed. This is
    /// the "discovery matters" failure: without live discovery, there is no
    /// route.
    #[error("no eligible route: discovery produced no candidates")]
    NoEligibleRoute,
    /// No gateway candidate with `Capability::Gateway` + circuit key was
    /// discovered. A Mode-A route requires a gateway as its destination.
    #[error("no eligible gateway candidate (Capability::Gateway + circuit key required)")]
    NoGateway,
    /// A relay NodeId in the requested order was not discovered (not present
    /// in the verified candidate store).
    #[error("relay hop {hop} (NodeId {node_id}) was not discovered")]
    RelayNotDiscovered {
        /// 0-indexed position in the requested relay order.
        hop: usize,
        /// The missing relay's NodeId (hex).
        node_id: String,
    },
    /// A relay NodeId was discovered but is not eligible (wrong capability,
    /// expired, or no TCP endpoint).
    #[error("relay hop {hop} (NodeId {node_id}) is not an eligible relay: {reason}")]
    RelayIneligible {
        /// 0-indexed position in the requested relay order.
        hop: usize,
        /// The relay's NodeId (hex).
        node_id: String,
        /// Why the relay was rejected.
        reason: &'static str,
    },
    /// A discovered candidate has expired (`now >= expiry`). Stale descriptors
    /// are never silently used.
    #[error("candidate (NodeId {node_id}) has expired (expiry {expiry} <= now {now})")]
    ExpiredCandidate {
        /// The candidate's NodeId (hex).
        node_id: String,
        /// The candidate's expiry timestamp.
        expiry: u64,
        /// The current time.
        now: u64,
    },
    /// A discovered candidate has no usable TCP transport endpoint.
    #[error("candidate (NodeId {node_id}) has no TCP transport endpoint")]
    NoTcpEndpoint {
        /// The candidate's NodeId (hex).
        node_id: String,
    },
    /// The route failed structural validation after construction.
    #[error("route validation failed: {0}")]
    RouteValidationFailed(String),
}

/// Convenience alias.
pub type ModeADiscoveryResult<T> = Result<T, ModeADiscoveryError>;

// ─── Live discovery: serve side ──────────────────────────────────────────

/// Serve a signed `NodeAdvertisement` over the discovery wire protocol.
///
/// Binds a TCP listener on `discovery_addr`. For each incoming connection:
/// 1. Read 1-byte request (must equal `MODE_A_DISCOVERY_REQUEST_BYTE`).
/// 2. Respond with 4-byte big-endian length + canonical-CBOR advert body.
///
/// The served advertisement is the node's OWN signed advert — its
/// `endpoints` carry the node's transport `listen_addr` (where bundles are
/// delivered), which is DISTINCT from `discovery_addr` (where discovery
/// queries go). The route builder uses the signed `listen_addr`, NOT the
/// discovery address (Step 19: "discovery address != signed listen_addr →
/// route uses signed listen_addr").
///
/// Returns when the `shutdown` future resolves (graceful test teardown).
///
/// # Errors
/// Returns `ModeADiscoveryError` only if the listener fails to bind. Per-
/// connection errors are logged and skipped (the loop continues).
pub async fn serve_node_advertisement_async<F>(
    advert: NodeAdvertisement,
    discovery_addr: String,
    shutdown: F,
) where
    F: std::future::Future<Output = ()>,
{
    let listener = match TcpListener::bind(&discovery_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[mode-a-disc] bind {discovery_addr} failed: {e}");
            return;
        }
    };
    eprintln!(
        "[mode-a-disc {}] serving NodeAdvertisement on {discovery_addr} (transport listen_addr: {})",
        hex_short(&advert.node_id),
        advert
            .endpoints
            .first()
            .and_then(|ep| ep.as_tcp())
            .unwrap_or("?")
    );
    let advert_bytes = advert.encode_cbor();
    tokio::select! {
        _ = accept_loop(&listener, &advert_bytes) => {}
        _ = shutdown => {
            eprintln!("[mode-a-disc {}] shutting down discovery service", hex_short(&advert.node_id));
        }
    }
}

/// The connection-accept loop, factored out so `serve_node_advertisement_async`
/// can select it against a shutdown future.
async fn accept_loop(listener: &TcpListener, advert_bytes: &[u8]) {
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[mode-a-disc] accept error: {e}");
                continue;
            }
        };
        let advert_bytes = advert_bytes.to_vec();
        tokio::spawn(async move {
            // 1. Read 1-byte request.
            let mut req = [0u8; 1];
            if let Err(e) = stream.read_exact(&mut req).await {
                eprintln!("[mode-a-disc] recv request error: {e}");
                return;
            }
            if req[0] != MODE_A_DISCOVERY_REQUEST_BYTE {
                eprintln!("[mode-a-disc] unexpected request byte 0x{:02x}", req[0]);
                return;
            }
            // 2. Write 4-byte BE length + CBOR advert.
            let len = match u32::try_from(advert_bytes.len()) {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("[mode-a-disc] advert too large: {}", advert_bytes.len());
                    return;
                }
            };
            if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
                eprintln!("[mode-a-disc] send length error: {e}");
                return;
            }
            if let Err(e) = stream.write_all(&advert_bytes).await {
                eprintln!("[mode-a-disc] send advert error: {e}");
                return;
            }
            let _ = stream.flush().await;
        });
    }
}

// ─── Live discovery: client side ──────────────────────────────────────────

/// A live discovery client: queries a set of bootstrap discovery addresses,
/// receives signed `NodeAdvertisement`s, and verifies each before yielding it.
///
/// This is the "discover" side of the R4.5 lifecycle (Step 13):
/// ```text
/// bootstrap addrs → TCP query → decode → verify_into_verified
///     → Vec<VerifiedNodeAdvertisement>
/// ```
///
/// **Verification is mandatory.** A `NodeAdvertisement` received from the
/// wire is NEVER handed to the route builder raw. `verify_into_verified()`
/// checks: signature, NodeId↔Ed25519 consistency (I4), expiry (`expiry > now`),
/// and role/key consistency (gateway ⇒ circuit key, non-gateway ⇒ no circuit
/// key). Any advertisement failing ANY of these checks is silently dropped
/// (logged) and not returned.
///
/// This type does NOT choose a route, order hops, or pick a gateway. It only
/// produces the verified candidate set (Step 16: no routing in discovery).
#[derive(Debug, Clone)]
pub struct LiveNodeAdvertDiscovery {
    /// Bootstrap discovery addresses to query.
    bootstrap_addrs: Vec<String>,
}

impl LiveNodeAdvertDiscovery {
    /// Construct a new live discovery client with the given bootstrap
    /// discovery addresses.
    #[must_use]
    pub fn new(bootstrap_addrs: Vec<String>) -> Self {
        Self { bootstrap_addrs }
    }

    /// The bootstrap discovery addresses.
    #[must_use]
    pub fn bootstrap_addrs(&self) -> &[String] {
        &self.bootstrap_addrs
    }

    /// Discover candidates by querying every bootstrap address.
    ///
    /// Returns the verified `NodeAdvertisement` set. If a bootstrap address
    /// is unreachable, or returns a malformed/unsigned/expired advertisement,
    /// that address is skipped (logged). An empty result means no candidates
    /// could be discovered — the route builder will then report
    /// `NoEligibleRoute` (Step 14).
    pub async fn discover_candidates(&self) -> Vec<VerifiedNodeAdvertisement> {
        let mut out = Vec::new();
        for addr in &self.bootstrap_addrs {
            match discover_one_async(addr).await {
                Ok(verified) => {
                    eprintln!(
                        "[mode-a-disc] discovered {} from {addr}",
                        hex_short(&verified.node_id())
                    );
                    out.push(verified);
                }
                Err(e) => {
                    eprintln!("[mode-a-disc] {addr} failed: {e}");
                }
            }
        }
        out
    }
}

/// Query ONE bootstrap discovery address for a signed `NodeAdvertisement`,
/// decode it, and verify it.
///
/// Returns `Err` if: the connection fails, the wire framing is malformed,
/// the CBOR decode fails, OR `verify_into_verified()` rejects the advert
/// (bad signature, NodeId mismatch, expired, role/key inconsistency).
async fn discover_one_async(addr: &str) -> ModeADiscoveryResult<VerifiedNodeAdvertisement> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| ModeADiscoveryError::NoEligibleRoute)?;
    let _ = stream.set_nodelay(true);
    // 1. Send discovery request byte.
    stream
        .write_all(&[MODE_A_DISCOVERY_REQUEST_BYTE])
        .await
        .map_err(|_| ModeADiscoveryError::NoEligibleRoute)?;
    let _ = stream.flush().await;
    // 2. Read 4-byte BE length prefix.
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|_| ModeADiscoveryError::NoEligibleRoute)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_ADVERTISEMENT_LEN {
        return Err(ModeADiscoveryError::NoEligibleRoute);
    }
    // 3. Read CBOR advert body.
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|_| ModeADiscoveryError::NoEligibleRoute)?;
    // 4. Decode + verify. This is the critical step — a wire advert is NEVER
    //    trusted until verify_into_verified() passes (signature + NodeId +
    //    expiry + role/key).
    let advert =
        NodeAdvertisement::decode_cbor(&buf).ok_or(ModeADiscoveryError::NoEligibleRoute)?;
    advert
        .verify_into_verified()
        .ok_or(ModeADiscoveryError::NoEligibleRoute)
}

// ─── Candidate store population ──────────────────────────────────────────

/// Accept a batch of discovered+verified advertisements into the candidate
/// store. Deduplicates by NodeId + sequence (newer seq replaces older;
/// stale/duplicate seqs are no-ops). Returns the number of NEW records
/// actually accepted (not duplicates/stale).
///
/// The store is the verified candidate set the route builder reads. Using
/// the existing `AdvertisementAcceptanceStore` (with `new()` = in-memory,
/// `persist()` no-op) keeps R4.5 within the "no durable persistence" boundary
/// (Step 22) while reusing the existing replay-prevention authority.
pub fn accept_discovered(
    store: &mut AdvertisementAcceptanceStore,
    discovered: Vec<VerifiedNodeAdvertisement>,
) -> usize {
    let mut accepted = 0usize;
    for verified in discovered {
        match store.accept(verified) {
            Ok(crate::node::node_advert::AcceptanceResult::Accepted(_)) => {
                accepted += 1;
            }
            Ok(_) => {
                // Duplicate or stale — no state change.
            }
            Err(e) => {
                eprintln!("[mode-a-disc] accept error: {e:?}");
            }
        }
    }
    accepted
}

// ─── Route builder (pure composition over verified candidates) ────────────

/// Build a Mode-A `Route` from the verified candidate store.
///
/// This is the L6 route builder for Mode-A store-carry-forward. It does NOT
/// query discovery (Step 16) — it reads the candidate store that discovery
/// populated. It DOES decide the path: it selects the gateway by capability
/// (Step 9), validates each relay in `relay_order` against discovered
/// candidates (Step 10), enforces expiry/freshness (Step 6), and builds the
/// immutable `Route` from signed descriptors + signed `listen_addr` endpoints
/// (Step 11: `RouteHop.endpoint == signed advert listen_addr`).
///
/// # Parameters
/// - `source`: the route source NodeId (the client).
/// - `store`: the verified candidate store (populated by `accept_discovered`).
/// - `relay_order`: the desired ordered list of relay NodeIds (the routing
///   ordering decision — Step 16). Each MUST be a discovered, eligible relay
///   candidate (`Capability::Relay`, not expired, has a TCP endpoint).
///
/// # Returns
/// - `Ok(Route)` — the immutable route, ready for `BundleForwarder`.
/// - `Err(NoEligibleRoute)` — the store is empty (discovery produced nothing).
/// - `Err(NoGateway)` — no eligible gateway candidate was discovered.
/// - `Err(RelayNotDiscovered)` — a relay in `relay_order` is not in the store.
/// - `Err(RelayIneligible)` — a relay lacks `Capability::Relay`, has expired,
///   or has no TCP endpoint.
/// - `Err(ExpiredCandidate)` — the selected gateway has expired.
/// - `Err(NoTcpEndpoint)` — the selected gateway has no TCP endpoint.
/// - `Err(RouteValidationFailed)` — the constructed route failed
///   `Route::validate()` (e.g., a loop, destination mismatch).
///
/// # Routing decisions made here (Step 16)
///
/// - Path: source → relay_order[0] → ... → relay_order[n-1] → gateway.
/// - Ordering: `relay_order` (caller-supplied; deterministic for R4.5 —
///   live route optimization/migration is out of scope per Step 13).
/// - Next hop: `route.hop(position + 1)` for each forwarder position.
/// - Destination: the selected gateway NodeId (`Route.destination()`).
///
/// # What is NOT decided here
///
/// - Which candidates exist (discovery's job).
/// - Transport identity (L8's job — `AuthenticatedBundleCarrier.peer_id`).
/// - Bundle forwarding (the unchanged `BundleForwarder`'s job).
#[must_use]
pub fn build_mode_a_route(
    source: NodeId,
    store: &AdvertisementAcceptanceStore,
    relay_order: &[NodeId],
) -> ModeADiscoveryResult<Route> {
    // Purge expired records first so stale descriptors can never be selected.
    let now = snp_identity::now_unix();
    // NOTE: purge_expired_records takes &mut self; we have &self here. We do
    // NOT mutate the store from the route builder (separation of concerns +
    // borrow-checker safety). Instead, we apply a fresh read-time expiry
    // check below for every candidate we consider. This is the freshness
    // gate (Step 6): a candidate with `expiry <= now` is rejected even if it
    // has not been purged yet.
    let _ = now;

    // Collect ALL non-expired records (the candidate set discovery populated).
    let mut candidates: Vec<&AuthenticatedNodeRecord> =
        store.all_records().filter(|r| !r.is_expired(now)).collect();
    if candidates.is_empty() {
        return Err(ModeADiscoveryError::NoEligibleRoute);
    }

    // ── Step 9: gateway selection by Capability::Gateway + circuit key ──
    // Select the eligible gateway deterministically (lowest NodeId) so the
    // test is reproducible regardless of HashMap iteration order.
    let mut gateway_candidates: Vec<&&AuthenticatedNodeRecord> = candidates
        .iter()
        .filter(|r| r.descriptor.is_gateway())
        .filter(|r| r.descriptor.circuit_x25519_pub().is_some())
        .filter(|r| r.endpoints.iter().any(|ep| ep.as_tcp().is_some()))
        .collect();
    gateway_candidates.sort_by_key(|r| r.node_id());
    let gateway_record: &AuthenticatedNodeRecord = match gateway_candidates.first() {
        Some(r) => **r,
        None => return Err(ModeADiscoveryError::NoGateway),
    };
    let gateway_node_id = gateway_record.node_id();

    // ── Step 10: relay selection — validate each relay in relay_order ──
    let mut hop_details: Vec<RouteHop> = Vec::with_capacity(relay_order.len() + 1);
    for (hop_index, relay_node_id) in relay_order.iter().enumerate() {
        // Look up this relay in the discovered candidate set.
        let relay_record: &AuthenticatedNodeRecord =
            match candidates.iter().find(|r| r.node_id() == *relay_node_id) {
                Some(r) => *r,
                None => {
                    return Err(ModeADiscoveryError::RelayNotDiscovered {
                        hop: hop_index,
                        node_id: hex_short(relay_node_id),
                    });
                }
            };
        // Freshness (Step 6): already filtered above, but double-check.
        if relay_record.is_expired(now) {
            return Err(ModeADiscoveryError::ExpiredCandidate {
                node_id: hex_short(&relay_record.node_id()),
                expiry: relay_record.expiry,
                now,
            });
        }
        // Capability (Step 10): MUST have Relay capability. MUST NOT be the
        // gateway (a node cannot be both an intermediate relay and the
        // destination).
        if !relay_record.descriptor.is_relay() {
            return Err(ModeADiscoveryError::RelayIneligible {
                hop: hop_index,
                node_id: hex_short(relay_node_id),
                reason: "missing Capability::Relay",
            });
        }
        if relay_record.node_id() == gateway_node_id {
            return Err(ModeADiscoveryError::RelayIneligible {
                hop: hop_index,
                node_id: hex_short(relay_node_id),
                reason: "relay NodeId equals gateway NodeId (cannot be both)",
            });
        }
        // Transport endpoint (Step 11): use the SIGNED listen_addr from the
        // advert, NOT the discovery address.
        let endpoint = match relay_record
            .endpoints
            .iter()
            .find_map(|ep| ep.as_tcp().map(|s| s.to_string()))
        {
            Some(e) => TransportEndpoint::tcp(e),
            None => {
                return Err(ModeADiscoveryError::NoTcpEndpoint {
                    node_id: hex_short(&relay_record.node_id()),
                });
            }
        };
        hop_details.push(RouteHop::new(relay_record.descriptor.clone(), endpoint));
    }

    // ── Append the gateway hop (destination) ──
    if gateway_record.is_expired(now) {
        return Err(ModeADiscoveryError::ExpiredCandidate {
            node_id: hex_short(&gateway_record.node_id()),
            expiry: gateway_record.expiry,
            now,
        });
    }
    let gateway_endpoint = match gateway_record
        .endpoints
        .iter()
        .find_map(|ep| ep.as_tcp().map(|s| s.to_string()))
    {
        Some(e) => TransportEndpoint::tcp(e),
        None => {
            return Err(ModeADiscoveryError::NoTcpEndpoint {
                node_id: hex_short(&gateway_record.node_id()),
            });
        }
    };
    hop_details.push(RouteHop::new(
        gateway_record.descriptor.clone(),
        gateway_endpoint,
    ));

    // ── Construct the immutable Route ──
    let route = Route::new_with_hop_details(source, gateway_node_id, hop_details);
    if let Err(e) = route.validate() {
        return Err(ModeADiscoveryError::RouteValidationFailed(format!("{e:?}")));
    }
    Ok(route)
}

// ─── Test helpers (shared with integration tests) ────────────────────────

/// A handle to a running discovery service (for test teardown).
pub struct DiscoveryServiceHandle {
    /// The discovery address the service is listening on.
    pub discovery_addr: String,
    /// The transport `listen_addr` from the served advertisement (signed).
    pub transport_listen_addr: String,
    /// The advertised NodeId.
    pub node_id: NodeId,
    join: Option<tokio::task::JoinHandle<()>>,
    shutdown: Arc<TokioMutex<bool>>,
}

impl DiscoveryServiceHandle {
    /// Start a discovery service for the given advertisement. The service
    /// listens on `discovery_addr` and serves the advert's canonical CBOR.
    /// The transport `listen_addr` is taken from the advert's first TCP
    /// endpoint (it is distinct from `discovery_addr` by construction in
    /// tests — proving "route uses signed listen_addr, not discovery addr").
    pub async fn start(advert: NodeAdvertisement, discovery_addr: String) -> Self {
        let transport_listen_addr = advert
            .endpoints
            .first()
            .and_then(|ep| ep.as_tcp())
            .unwrap_or("")
            .to_string();
        let node_id = advert.node_id;
        let discovery_addr_for_task = discovery_addr.clone();
        let shutdown = Arc::new(TokioMutex::new(false));
        let shutdown_clone = shutdown.clone();
        let join = tokio::spawn(async move {
            let shutdown_future = async move {
                loop {
                    if *shutdown_clone.lock().await {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            };
            serve_node_advertisement_async(advert, discovery_addr_for_task, shutdown_future).await;
        });
        // Give the listener a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Self {
            discovery_addr,
            transport_listen_addr,
            node_id,
            join: Some(join),
            shutdown,
        }
    }

    /// Stop the discovery service.
    pub async fn stop(mut self) {
        *self.shutdown.lock().await = true;
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}
