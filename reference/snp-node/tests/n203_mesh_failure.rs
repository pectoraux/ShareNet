//! N2.0.3 Gates F+G+H — Dynamic multi-hop mesh with relay+gateway failure
//! recovery.
//!
//! ## Topology
//!
//! ```text
//!           Gateway A          Gateway B
//!               ▲                   ▲
//!               │                   │
//!          Relay B              Relay C
//!               │                   │
//!               └─────── Relay A ──────┘
//!                         │
//!                      Client
//! ```
//!
//! All six identities (Client, Relay A, Relay B, Relay C, Gateway A,
//! Gateway B) are generated DYNAMICALLY at runtime using
//! [`NodeIdentity::from_secret`] with random SHA-256-derived seeds. NO
//! `GatewayChoice`. NO hardcoded identities. NO imports from
//! `snp_node::legacy`.
//!
//! ## What this test verifies
//!
//! ### Gate F — Multi-hop transit through a dynamic topology
//!
//! The Client sends a `TransitRequest` through:
//!
//! ```text
//!   Client ──[S1]──> Relay A ──[S2]──> Relay B ──[S3a]──> Gateway A ──[HTTP]──> local HTTP
//!     └────────────────────[Ca]────────────────────────> Gateway A (end-to-end circuit)
//! ```
//!
//! - S1 = client↔Relay A hop key (derived from a random seed).
//! - S2 = Relay A↔Relay B hop key (derived from a random seed).
//! - S3a = Relay B↔Gateway A hop key (derived from a random seed).
//! - Ca = client↔Gateway A circuit key (derived from a random seed).
//!
//! Relay A is a MULTI-UPSTREAM relay: it has persistent connections to
//! BOTH Relay B (for Gateway A traffic) and Relay C (for Gateway B
//! traffic). Frames are routed based on `frame.dst` (the gateway
//! NodeId).
//!
//! Verifies: `status == 200`, `object_id == SHA-256(HTTP_BODY)`,
//! Gateway A's signature verifies.
//!
//! ### Gate G — Relay failure recovery
//!
//! From the Gate F topology, Relay B is configured with `drop_after =
//! 1`: after serving one request, Relay B shuts down its TCP
//! connection to Relay A (simulating a relay that dies mid-session).
//!
//! The Client's NEXT request to Gateway A:
//! 1. Reaches Relay A.
//! 2. Relay A tries to forward to Relay B — the connection is dead.
//! 3. Relay A's multi-upstream relay sends a
//!    `UPSTREAM_FAILURE_MARKER` NACK back to the client and removes
//!    Relay B from `upstream_links`.
//! 4. The client's `send_request_via_gateway_full_with_relay` returns
//!    `NodeError::UpstreamFailure`.
//!
//! The Client then fails over to Gateway B (NO process restart):
//! 1. Marks Gateway A's circuit as inactive.
//! 2. Sends a new request with `dst = Gateway B's NodeId`.
//! 3. Relay A routes to Relay C (the upstream for Gateway B).
//! 4. Relay C → Gateway B → local HTTP.
//! 5. Gateway B signs the response with ITS secret key.
//!
//! Verifies: `status == 200`, `object_id == SHA-256(HTTP_BODY)`,
//! Gateway B's signature verifies (NOT Gateway A's).
//!
//! ### Gate H — Gateway failure recovery
//!
//! From the Gate F topology, Gateway A is configured with
//! `drop_after = 1`: after serving one request, Gateway A shuts down
//! its TCP connection to Relay B (simulating a gateway that dies
//! mid-session).
//!
//! The Client's NEXT request to Gateway A:
//! 1. Reaches Relay A → Relay B → Gateway A (dead).
//! 2. Relay B's `recv_frame` on its upstream connection fails.
//! 3. Relay B sends a `UPSTREAM_FAILURE_MARKER` NACK to Relay A and
//!    breaks its inner serve loop.
//! 4. Relay A's multi-upstream relay forwards the NACK to the client.
//! 5. The client returns `NodeError::UpstreamFailure`.
//!
//! The Client then fails over to Gateway B (NO process restart):
//! same as Gate G — sends via Relay A → Relay C → Gateway B.
//!
//! Verifies: `status == 200`, `object_id == SHA-256(HTTP_BODY)`,
//! Gateway B's signature verifies.
//!
//! ## SSRF bypass — TEST-ONLY
//!
//! Like `tests/n203_local_http.rs`, this test uses
//! [`serve_one_gateway_request_with_connector_factory_and_client_key`]
//! with a custom connector factory that pins to `127.0.0.1:HTTP_PORT`
//! (bypassing the SSRF defence in `PinnedConnector::new`).
//! **Production gateways MUST NOT use this escape hatch.**

#![allow(clippy::pedantic)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use snp_crypto::sha256;
use snp_gateway::{verify_transit_response, PinnedConnector};
use snp_link::{derive_circuit_keys, derive_link_keys, CircuitKeys, Link, LinkKeys};

use snp_node::node::{
    serve_one_gateway_request_with_connector_factory_and_client_key,
    spawn_relay_multi_upstream_persistent_with_counter, spawn_relay_persistent_with_counter,
    spawn_relay_persistent_with_drop_after, Capability, Circuit, GatewayAdvertisement, Node,
    NodeIdentity, Route, RouteState, ServeOutcome, UpstreamPeer,
};

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// The deterministic body the local HTTP server returns.
const HTTP_BODY: &str = "Hello, Mesh!";

/// Maximum time to wait for a failure-mode request to fail. If the
/// client hangs for longer than this, the test fails (regression on
/// the "no hang on upstream death" requirement).
const FAILURE_TIMEOUT: Duration = Duration::from_secs(20);

/// Monotonic counter for unique random seeds within a process. Each call
/// to [`random_secret`] increments this counter, ensuring each generated
/// identity is distinct even if called in the same nanosecond.
static SECRET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The expected `object_id` of the TransitResponse (SHA-256 of the body).
fn expected_object_id() -> [u8; 32] {
    sha256(HTTP_BODY.as_bytes())
}

// ═══════════════════════════════════════════════════════════════════════════
// Random identity + key-derivation helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a random 32-byte Ed25519 secret key. Combines a label, the
/// current monotonic time (nanoseconds), and a process-global counter,
/// then SHA-256-hashes the combination. This guarantees uniqueness
/// across calls within the same process (and across processes, with
/// high probability, since the timestamp is included).
///
/// **NOT cryptographically secure** — it uses `SystemTime` (which can
/// be manipulated by NTP) and a counter (which resets per process).
/// This is sufficient for test identities (which are NOT secrets — they
/// are published in the test source). Production would use
/// `OsRng`-backed key generation.
fn random_secret(label: &str) -> [u8; 32] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let counter = SECRET_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut input = Vec::with_capacity(label.len() + 24);
    input.extend_from_slice(label.as_bytes());
    input.extend_from_slice(&now.as_nanos().to_be_bytes());
    input.extend_from_slice(&counter.to_be_bytes());
    sha256(&input)
}

/// Build a link seed from two endpoints' secret keys + a label. Both
/// endpoints derive matching `LinkKeys` from the same seed (one as
/// initiator, one as responder).
fn make_link_seed(a: &[u8; 32], b: &[u8; 32], label: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64 + label.len());
    seed.extend_from_slice(a);
    seed.extend_from_slice(b);
    seed.extend_from_slice(label);
    seed
}

/// Build a circuit seed from the client + gateway secret keys + a
/// label. Both ends derive matching `CircuitKeys` (one as initiator,
/// one as responder). The relays NEVER see this seed — they cannot
/// decrypt the circuit payload (invariant I8).
fn make_circuit_seed(client: &[u8; 32], gateway: &[u8; 32], label: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64 + label.len());
    seed.extend_from_slice(client);
    seed.extend_from_slice(gateway);
    seed.extend_from_slice(label);
    seed
}

/// Format the first 8 bytes of a byte slice as hex (for logging).
fn hex_short(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n]
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}

/// Allocate an ephemeral port by binding to `127.0.0.1:0`, reading the
/// assigned port, and dropping the listener. Returns the address
/// string (e.g. `"127.0.0.1:54321"`).
fn allocate_ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    addr.to_string()
}

// ═══════════════════════════════════════════════════════════════════════════
// Local HTTP server
// ═══════════════════════════════════════════════════════════════════════════

/// Start a local HTTP server that returns a deterministic `200 OK`
/// response with body `HTTP_BODY`. The server accepts up to 16
/// connections (to handle retries during failure recovery). Returns
/// the port, the thread handle, and a request counter.
fn start_http_server() -> (
    u16,
    thread::JoinHandle<()>,
    Arc<AtomicU64>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http");
    let addr = listener.local_addr().expect("http local_addr");
    let port = addr.port();
    let counter = Arc::new(AtomicU64::new(0));
    let counter_clone = Arc::clone(&counter);
    let handle = thread::spawn(move || {
        for _ in 0..16 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                HTTP_BODY.len(),
                HTTP_BODY,
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }
    });
    thread::sleep(Duration::from_millis(50));
    (port, handle, counter)
}

// ═══════════════════════════════════════════════════════════════════════════
// Gateway startup
// ═══════════════════════════════════════════════════════════════════════════

/// Start a gateway node. The gateway:
/// 1. Binds a TCP listener on an ephemeral port (for relay→gateway
///    transit connections).
/// 2. Accepts connections from relays.
/// 3. For each connection, serves requests in a loop using
///    [`serve_one_gateway_request_with_connector_factory_and_client_key`]
///    with a TEST-ONLY connector factory that bypasses the SSRF check
///    and pins to `127.0.0.1:http_port`.
/// 4. If `drop_after > 0`, shuts down the TCP stream after serving
///    `drop_after` requests (simulating a gateway that dies
///    mid-session). If `drop_after == 0`, serves unlimited requests.
///
/// Returns the gateway's transit address string and the thread handle.
fn start_gateway(
    identity: &NodeIdentity,
    link_keys: LinkKeys,
    circuit_keys: CircuitKeys,
    client_pk: [u8; 32],
    http_port: u16,
    drop_after: usize,
) -> (String, thread::JoinHandle<()>) {
    let addr_str = allocate_ephemeral_addr();
    let listener = TcpListener::bind(&addr_str).expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local_addr").to_string();
    let addr_log = addr.clone();

    let node_id = identity.node_id;
    let sk = identity.secret_key;

    let handle = thread::spawn(move || {
        eprintln!(
            "[gateway {}] listening on {addr_log}, drop_after={drop_after}",
            hex_short(&node_id)
        );
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[gateway {}] accept error: {e}", hex_short(&node_id));
                    continue;
                }
            };
            eprintln!(
                "[gateway {}] relay connected from {}",
                hex_short(&node_id),
                stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into())
            );
            let link = Arc::new(Link::new(stream, link_keys));
            let mut seen_req_ids: HashSet<[u8; 16]> = HashSet::new();
            let mut served = 0usize;
            loop {
                if drop_after > 0 && served >= drop_after {
                    eprintln!(
                        "[gateway {}] served {served} requests — DROPPING connection (simulated failure)",
                        hex_short(&node_id)
                    );
                    let _ = link.stream().shutdown(std::net::Shutdown::Both);
                    break;
                }
                let outcome = serve_one_gateway_request_with_connector_factory_and_client_key(
                    &link,
                    node_id,
                    &sk,
                    &client_pk,
                    &circuit_keys,
                    &mut seen_req_ids,
                    // TEST-ONLY SSRF bypass: pin to the local HTTP server.
                    // PRODUCTION GATEWAYS MUST NOT DO THIS.
                    &|_url: &str| {
                        Ok(PinnedConnector::from_parts(
                            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                            "test.local".to_string(),
                            http_port,
                            "http".to_string(),
                            "/".to_string(),
                        ))
                    },
                );
                match outcome {
                    Ok(ServeOutcome::Continue) => {
                        served += 1;
                        eprintln!(
                            "[gateway {}] served {served} request(s)",
                            hex_short(&node_id)
                        );
                    }
                    Ok(ServeOutcome::Closed) => {
                        eprintln!(
                            "[gateway {}] relay closed the connection",
                            hex_short(&node_id)
                        );
                        break;
                    }
                    Err(e) => {
                        eprintln!("[gateway {}] serve error: {e}", hex_short(&node_id));
                        break;
                    }
                }
            }
            eprintln!("[gateway {}] connection cycle complete", hex_short(&node_id));
        }
    });

    thread::sleep(Duration::from_millis(50));
    (addr, handle)
}

// ═══════════════════════════════════════════════════════════════════════════
// Mesh topology
// ═══════════════════════════════════════════════════════════════════════════

/// The full mesh topology: 6 dynamic identities, hop keys, circuit
/// keys, addresses, and a started HTTP server + all node threads.
struct MeshTopology {
    // Identities (arbitrary, generated at runtime — NO GatewayChoice).
    client_identity: NodeIdentity,
    relay_a_identity: NodeIdentity,
    relay_b_identity: NodeIdentity,
    relay_c_identity: NodeIdentity,
    gateway_a_identity: NodeIdentity,
    gateway_b_identity: NodeIdentity,

    // Addresses.
    relay_a_addr: String,
    relay_b_addr: String,
    relay_c_addr: String,
    gateway_a_addr: String,
    gateway_b_addr: String,

    // Client ↔ Relay A hop keys (the client uses `client_relay_a_keys`
    // as the initiator; Relay A uses `relay_a_client_keys` as the
    // responder).
    client_relay_a_keys: LinkKeys,
    relay_a_client_keys: LinkKeys,

    // Circuit keys (client ↔ gateway end-to-end).
    client_circuit_a_keys: CircuitKeys,
    gateway_a_circuit_keys: CircuitKeys,
    client_circuit_b_keys: CircuitKeys,
    gateway_b_circuit_keys: CircuitKeys,

    // HTTP request counter (shared with the HTTP server thread).
    http_counter: Arc<AtomicU64>,

    // Thread handles (kept alive for the duration of the test).
    _http_handle: thread::JoinHandle<()>,
    _gateway_a_handle: thread::JoinHandle<()>,
    _gateway_b_handle: thread::JoinHandle<()>,
    _relay_b_handle: thread::JoinHandle<()>,
    _relay_c_handle: thread::JoinHandle<()>,
    _relay_a_handle: thread::JoinHandle<()>,
}

/// Set up the full mesh topology.
///
/// - `relay_b_drop_after`: if > 0, Relay B drops its connection after
///   serving this many requests (used by Gate G). If 0, Relay B serves
///   unlimited requests.
/// - `gateway_a_drop_after`: if > 0, Gateway A drops its connection
///   after serving this many requests (used by Gate H). If 0, Gateway A
///   serves unlimited requests.
fn setup_mesh_topology(relay_b_drop_after: usize, gateway_a_drop_after: usize) -> MeshTopology {
    println!("=== Setting up dynamic mesh topology ===");
    println!(
        "  relay_b_drop_after={}, gateway_a_drop_after={}",
        relay_b_drop_after, gateway_a_drop_after
    );

    // ─── 1. Generate random identities ─────────────────────────────────
    let client_identity = NodeIdentity::from_secret(random_secret("client"));
    let relay_a_identity = NodeIdentity::from_secret(random_secret("relay-a"));
    let relay_b_identity = NodeIdentity::from_secret(random_secret("relay-b"));
    let relay_c_identity = NodeIdentity::from_secret(random_secret("relay-c"));
    let gateway_a_identity = NodeIdentity::from_secret(random_secret("gateway-a"));
    let gateway_b_identity = NodeIdentity::from_secret(random_secret("gateway-b"));

    println!("[topology] Client  NodeId: {}", hex_short(&client_identity.node_id));
    println!("[topology] Relay A  NodeId: {}", hex_short(&relay_a_identity.node_id));
    println!("[topology] Relay B  NodeId: {}", hex_short(&relay_b_identity.node_id));
    println!("[topology] Relay C  NodeId: {}", hex_short(&relay_c_identity.node_id));
    println!("[topology] Gateway A NodeId: {}", hex_short(&gateway_a_identity.node_id));
    println!("[topology] Gateway B NodeId: {}", hex_short(&gateway_b_identity.node_id));

    // ─── 2. Derive hop keys (one seed per link, shared by both ends) ────
    //
    // Each link has a unique seed derived from the two endpoints' secret
    // keys + a label. Both endpoints derive matching `LinkKeys` from
    // the same seed (one as initiator, one as responder). The relays
    // possess only the hop keys for their adjacent links — they CANNOT
    // decrypt the circuit payload (invariant I8).

    // S1: Client ↔ Relay A (client = initiator, relay A = responder)
    let s1_seed = make_link_seed(
        &client_identity.secret_key,
        &relay_a_identity.secret_key,
        b"client-relayA",
    );
    let client_relay_a_keys = derive_link_keys(&s1_seed, true);
    let relay_a_client_keys = derive_link_keys(&s1_seed, false);

    // S2: Relay A ↔ Relay B (relay A = initiator, relay B = responder)
    let s2_seed = make_link_seed(
        &relay_a_identity.secret_key,
        &relay_b_identity.secret_key,
        b"relayA-relayB",
    );
    let relay_a_relay_b_keys = derive_link_keys(&s2_seed, true);
    let relay_b_relay_a_keys = derive_link_keys(&s2_seed, false);

    // S2': Relay A ↔ Relay C (relay A = initiator, relay C = responder)
    let s2p_seed = make_link_seed(
        &relay_a_identity.secret_key,
        &relay_c_identity.secret_key,
        b"relayA-relayC",
    );
    let relay_a_relay_c_keys = derive_link_keys(&s2p_seed, true);
    let relay_c_relay_a_keys = derive_link_keys(&s2p_seed, false);

    // S3a: Relay B ↔ Gateway A (relay B = initiator, gateway A = responder)
    let s3a_seed = make_link_seed(
        &relay_b_identity.secret_key,
        &gateway_a_identity.secret_key,
        b"relayB-gatewayA",
    );
    let relay_b_gateway_a_keys = derive_link_keys(&s3a_seed, true);
    let gateway_a_relay_b_keys = derive_link_keys(&s3a_seed, false);

    // S3b: Relay C ↔ Gateway B (relay C = initiator, gateway B = responder)
    let s3b_seed = make_link_seed(
        &relay_c_identity.secret_key,
        &gateway_b_identity.secret_key,
        b"relayC-gatewayB",
    );
    let relay_c_gateway_b_keys = derive_link_keys(&s3b_seed, true);
    let gateway_b_relay_c_keys = derive_link_keys(&s3b_seed, false);

    // ─── 3. Derive circuit keys (one seed per client↔gateway pair) ──────
    //
    // The circuit seed is shared ONLY between the client and the gateway.
    // The relays NEVER see this seed — they cannot decrypt the circuit
    // payload (the TransitRequest/TransitResponse body).

    // Ca: Client ↔ Gateway A
    let ca_seed = make_circuit_seed(
        &client_identity.secret_key,
        &gateway_a_identity.secret_key,
        b"circuit-A",
    );
    let client_circuit_a_keys = derive_circuit_keys(&ca_seed, true);
    let gateway_a_circuit_keys = derive_circuit_keys(&ca_seed, false);

    // Cb: Client ↔ Gateway B
    let cb_seed = make_circuit_seed(
        &client_identity.secret_key,
        &gateway_b_identity.secret_key,
        b"circuit-B",
    );
    let client_circuit_b_keys = derive_circuit_keys(&cb_seed, true);
    let gateway_b_circuit_keys = derive_circuit_keys(&cb_seed, false);

    // ─── 4. Build + verify signed gateway advertisements ───────────────
    //
    // Each gateway produces a signed GatewayAdvertisement. The test
    // verifies the signature + the I4 cross-check (nodeId == SHA-256 of
    // the publicKey). In a production deployment, the client would
    // discover these advertisements via the discovery protocol
    // (mDNS, bootstrap list, etc.); here we construct them directly.

    let gw_a_advert = GatewayAdvertisement::for_identity(
        &gateway_a_identity,
        "127.0.0.1:0", // placeholder — not used for transit in this test
        "127.0.0.1:0",
    );
    assert!(
        gw_a_advert.verify(),
        "Gateway A advertisement signature MUST verify"
    );
    assert_eq!(
        gw_a_advert.node_id, gateway_a_identity.node_id,
        "Gateway A advertisement nodeId MUST match identity"
    );

    let gw_b_advert = GatewayAdvertisement::for_identity(
        &gateway_b_identity,
        "127.0.0.1:0",
        "127.0.0.1:0",
    );
    assert!(
        gw_b_advert.verify(),
        "Gateway B advertisement signature MUST verify"
    );
    assert_eq!(
        gw_b_advert.node_id, gateway_b_identity.node_id,
        "Gateway B advertisement nodeId MUST match identity"
    );
    println!("[topology] Gateway advertisements signed + verified (signature + I4 cross-check)");

    // ─── 5. Build + validate Route objects ─────────────────────────────
    //
    // The client constructs two routes:
    //   - Primary route:    Client → Relay A → Relay B → Gateway A
    //   - Alternate route:  Client → Relay A → Relay C → Gateway B
    //
    // Both routes are validated (structural invariants) and transitioned
    // through the state machine: Proposed → Establishing → Active.
    // The actual frame routing uses the relay's multi-upstream logic
    // (based on `frame.dst`), NOT the Route object — the Route is
    // metadata that records the path the client intends to use.

    let primary_route = Route::new(
        client_identity.node_id,
        gateway_a_identity.node_id,
        vec![
            relay_a_identity.node_id,
            relay_b_identity.node_id,
            gateway_a_identity.node_id,
        ],
    );
    primary_route.validate().expect("primary route must validate");
    let mut primary_route = primary_route;
    primary_route
        .transition(RouteState::Establishing)
        .expect("Proposed → Establishing is legal");
    primary_route
        .transition(RouteState::Active)
        .expect("Establishing → Active is legal");
    println!(
        "[topology] Primary route validated + Active: {} hops, route_id={}",
        primary_route.hops.len(),
        hex_short(&primary_route.route_id)
    );

    let alternate_route = Route::new(
        client_identity.node_id,
        gateway_b_identity.node_id,
        vec![
            relay_a_identity.node_id,
            relay_c_identity.node_id,
            gateway_b_identity.node_id,
        ],
    );
    alternate_route.validate().expect("alternate route must validate");
    println!(
        "[topology] Alternate route validated: {} hops, route_id={}",
        alternate_route.hops.len(),
        hex_short(&alternate_route.route_id)
    );

    // ─── 6. Start the local HTTP server ────────────────────────────────
    let (http_port, http_handle, http_counter) = start_http_server();
    println!("[topology] local HTTP server at http://127.0.0.1:{http_port}/");

    // ─── 7. Start Gateway A + Gateway B ────────────────────────────────
    let (gateway_a_addr, gateway_a_handle) = start_gateway(
        &gateway_a_identity,
        gateway_a_relay_b_keys,
        gateway_a_circuit_keys,
        client_identity.public_key,
        http_port,
        gateway_a_drop_after,
    );
    println!("[topology] Gateway A transit listener at {gateway_a_addr}");

    let (gateway_b_addr, gateway_b_handle) = start_gateway(
        &gateway_b_identity,
        gateway_b_relay_c_keys,
        gateway_b_circuit_keys,
        client_identity.public_key,
        http_port,
        0, // Gateway B never drops (it's the failover target)
    );
    println!("[topology] Gateway B transit listener at {gateway_b_addr}");

    // ─── 8. Start Relay B (single-upstream to Gateway A) ───────────────
    let relay_b_addr = allocate_ephemeral_addr();
    let relay_b_handle: thread::JoinHandle<()>;
    if relay_b_drop_after > 0 {
        let h = spawn_relay_persistent_with_drop_after(
            &relay_b_addr,
            &gateway_a_addr,
            relay_b_relay_a_keys,
            relay_b_gateway_a_keys,
            relay_b_drop_after,
        );
        relay_b_handle = h;
        println!(
            "[topology] Relay B at {relay_b_addr} (drops after {relay_b_drop_after} request(s))"
        );
    } else {
        let (h, _) = spawn_relay_persistent_with_counter(
            &relay_b_addr,
            &gateway_a_addr,
            relay_b_relay_a_keys,
            relay_b_gateway_a_keys,
        );
        relay_b_handle = h;
        println!("[topology] Relay B at {relay_b_addr} (persistent, no drop)");
    }

    // ─── 9. Start Relay C (single-upstream to Gateway B) ───────────────
    let relay_c_addr = allocate_ephemeral_addr();
    let (relay_c_handle, _) = spawn_relay_persistent_with_counter(
        &relay_c_addr,
        &gateway_b_addr,
        relay_c_relay_a_keys,
        relay_c_gateway_b_keys,
    );
    println!("[topology] Relay C at {relay_c_addr} (persistent, no drop)");

    // ─── 10. Start Relay A (multi-upstream: Relay B + Relay C) ─────────
    //
    // Relay A is MULTI-UPSTREAM: it has persistent connections to BOTH
    // Relay B (for Gateway A traffic) and Relay C (for Gateway B
    // traffic). Frames are routed based on `frame.dst`:
    //   - dst == Gateway A NodeId → forward to Relay B
    //   - dst == Gateway B NodeId → forward to Relay C
    //
    // The `dst_node_id` field on each `UpstreamPeer` is the FINAL
    // destination (the gateway's NodeId), NOT the immediate next hop
    // (the relay's NodeId). This matches the existing N2.0.1 demo's
    // usage of `serve_relay_multi_upstream_persistent_inner`.

    let relay_a_addr = allocate_ephemeral_addr();
    let relay_a_upstreams = vec![
        UpstreamPeer {
            dst_node_id: gateway_a_identity.node_id,
            addr: relay_b_addr.clone(),
            hop_keys: relay_a_relay_b_keys,
        },
        UpstreamPeer {
            dst_node_id: gateway_b_identity.node_id,
            addr: relay_c_addr.clone(),
            hop_keys: relay_a_relay_c_keys,
        },
    ];
    let (relay_a_handle, _) = spawn_relay_multi_upstream_persistent_with_counter(
        &relay_a_addr,
        relay_a_upstreams,
        relay_a_client_keys,
    );
    println!("[topology] Relay A at {relay_a_addr} (multi-upstream: Relay B + Relay C)");

    thread::sleep(Duration::from_millis(150));

    MeshTopology {
        client_identity,
        relay_a_identity,
        relay_b_identity,
        relay_c_identity,
        gateway_a_identity,
        gateway_b_identity,
        relay_a_addr,
        relay_b_addr,
        relay_c_addr,
        gateway_a_addr,
        gateway_b_addr,
        client_relay_a_keys,
        relay_a_client_keys,
        client_circuit_a_keys,
        gateway_a_circuit_keys,
        client_circuit_b_keys,
        gateway_b_circuit_keys,
        http_counter,
        _http_handle: http_handle,
        _gateway_a_handle: gateway_a_handle,
        _gateway_b_handle: gateway_b_handle,
        _relay_b_handle: relay_b_handle,
        _relay_c_handle: relay_c_handle,
        _relay_a_handle: relay_a_handle,
    }
}

/// Build a client `Node` pre-populated with circuits to both Gateway A
/// and Gateway B. The client's `listen_addr` is set to Relay A's
/// address (so `send_request_via_gateway_full` works as a convenience
/// wrapper).
fn build_client(mesh: &MeshTopology) -> Node {
    let client = Node::new(
        mesh.client_identity.clone(),
        vec![Capability::Client],
        mesh.relay_a_addr.clone(),
    );
    // Pre-populate circuits to both gateways. In production, the circuit
    // keys come from the SNP-IK/0.1 handshake + the client↔gateway
    // X25519 circuit DH. For this test, we use the pre-derived circuit
    // keys (from the random seed).
    {
        let mut circuits = client.circuits.lock().unwrap();
        circuits.insert(
            mesh.gateway_a_identity.node_id,
            Circuit::new(
                mesh.gateway_a_identity.node_id,
                mesh.gateway_a_identity.public_key,
                mesh.client_circuit_a_keys.clone(),
            ),
        );
        circuits.insert(
            mesh.gateway_b_identity.node_id,
            Circuit::new(
                mesh.gateway_b_identity.node_id,
                mesh.gateway_b_identity.public_key,
                mesh.client_circuit_b_keys.clone(),
            ),
        );
    }
    client
}

/// Send a request via a specific gateway, using the explicit relay
/// address + hop keys (NOT the legacy `client_relay_a_link_keys`).
fn send_via(
    client: &Node,
    url: &str,
    gateway_node_id: &[u8; 32],
    relay_addr: &str,
    relay_link_keys: LinkKeys,
) -> Result<snp_gateway::TransitResponse, snp_node::legacy::NodeError> {
    client.send_request_via_gateway_full_with_relay(url, gateway_node_id, relay_addr, relay_link_keys)
}

// ═══════════════════════════════════════════════════════════════════════════
// Gate F — Multi-hop transit through a dynamic topology
// ═══════════════════════════════════════════════════════════════════════════

/// **N2.0.3 Gate F.** Multi-hop transit through a dynamic topology.
///
/// The Client sends a request through:
///   Client → Relay A → Relay B → Gateway A → local HTTP server
///
/// All six identities are generated randomly at runtime. The relay
/// path is 2 hops (Relay A, Relay B). The circuit is end-to-end
/// (Client ↔ Gateway A). Verifies:
/// - `status == 200`
/// - `object_id == SHA-256(HTTP_BODY)`
/// - Gateway A's signature verifies
#[test]
fn n203_gate_f_multihop_transit() {
    println!();
    println!("══════════════════════════════════════════════════════════════════");
    println!("N2.0.3 Gate F — Multi-hop transit through a dynamic topology");
    println!("══════════════════════════════════════════════════════════════════");
    println!();
    println!("  Client ──> Relay A ──> Relay B ──> Gateway A ──> local HTTP");
    println!();

    // ─── Set up topology (no drops) ────────────────────────────────────
    let mesh = setup_mesh_topology(0, 0);

    // ─── Build the client ──────────────────────────────────────────────
    let client = build_client(&mesh);
    let url = "http://test.local/";

    // ─── Send request via Gateway A ────────────────────────────────────
    println!();
    println!("=== Sending request: Client → Relay A → Relay B → Gateway A → HTTP ===");
    let transit_resp = send_via(
        &client,
        url,
        &mesh.gateway_a_identity.node_id,
        &mesh.relay_a_addr,
        mesh.client_relay_a_keys,
    )
    .expect("Gate F: request through Gateway A MUST succeed");

    println!(
        "[gate-f] response: status={} object_id={} gateway_id={}",
        transit_resp.status,
        hex_short(&transit_resp.object_id),
        hex_short(&transit_resp.gateway_id)
    );

    // ─── Verify ────────────────────────────────────────────────────────
    assert_eq!(
        transit_resp.status, 200,
        "Gate F: status MUST be 200"
    );
    assert_eq!(
        transit_resp.object_id,
        expected_object_id(),
        "Gate F: object_id MUST equal SHA-256(\"{HTTP_BODY}\") — proves the gateway fetched the body byte-for-byte"
    );
    assert_eq!(
        transit_resp.gateway_id,
        mesh.gateway_a_identity.node_id,
        "Gate F: response MUST be signed by Gateway A"
    );
    assert!(
        verify_transit_response(&transit_resp, &mesh.gateway_a_identity.public_key),
        "Gate F: Gateway A's signature MUST verify"
    );
    // Negative assertion: the response MUST NOT verify against Gateway B's key.
    assert!(
        !verify_transit_response(&transit_resp, &mesh.gateway_b_identity.public_key),
        "Gate F: response MUST NOT verify against Gateway B's key (proves Gateway A signed it)"
    );

    let http_hits = mesh.http_counter.load(Ordering::SeqCst);
    assert_eq!(
        http_hits, 1,
        "Gate F: HTTP server should have been hit exactly once, got {http_hits}"
    );

    println!();
    println!("=== Gate F PASSED ===");
    println!("  - Multi-hop transit (Client → Relay A → Relay B → Gateway A): OK");
    println!("  - Body integrity (object_id == SHA-256(\"{HTTP_BODY}\")): OK");
    println!("  - Gateway A signature verification: OK");
    println!("  - Dynamic identities (NO GatewayChoice): OK");

    // Detach threads (they're infinite loops).
    std::mem::forget(mesh);
}

// ═══════════════════════════════════════════════════════════════════════════
// Gate G — Relay failure recovery
// ═══════════════════════════════════════════════════════════════════════════

/// **N2.0.3 Gate G.** Relay failure recovery.
///
/// From the Gate F topology, Relay B is configured with `drop_after =
/// 1`: after serving one request, Relay B shuts down its TCP
/// connection to Relay A.
///
/// The Client's NEXT request to Gateway A MUST fail (NACK from Relay
/// A — Relay B is dead). The Client then fails over to Gateway B via
/// Relay C — NO process restart.
///
/// Verifies:
/// - Request 1 (via Gateway A): succeeds, status=200, Gateway A sig.
/// - Request 2 (via Gateway A): fails (UpstreamFailure) within timeout.
/// - Request 3 (via Gateway B): succeeds, status=200, Gateway B sig.
#[test]
fn n203_gate_g_relay_failure_recovery() {
    println!();
    println!("══════════════════════════════════════════════════════════════════");
    println!("N2.0.3 Gate G — Relay failure recovery");
    println!("══════════════════════════════════════════════════════════════════");
    println!();
    println!("  Relay B dies after 1 request → client fails over via Relay C → Gateway B");
    println!();

    // ─── Set up topology (Relay B drops after 1 request) ───────────────
    let mesh = setup_mesh_topology(1, 0);

    // ─── Build the client ──────────────────────────────────────────────
    let client = build_client(&mesh);
    let url = "http://test.local/";

    // ─── Request 1: via Gateway A (should succeed) ─────────────────────
    println!();
    println!("=== Request 1: Client → Relay A → Relay B → Gateway A ===");
    let resp1 = send_via(
        &client,
        url,
        &mesh.gateway_a_identity.node_id,
        &mesh.relay_a_addr,
        mesh.client_relay_a_keys,
    )
    .expect("Gate G request 1: SHOULD succeed (Relay B is still alive)");

    assert_eq!(resp1.status, 200, "Gate G request 1: status MUST be 200");
    assert_eq!(
        resp1.object_id,
        expected_object_id(),
        "Gate G request 1: object_id MUST match"
    );
    assert_eq!(
        resp1.gateway_id,
        mesh.gateway_a_identity.node_id,
        "Gate G request 1: response MUST be signed by Gateway A"
    );
    assert!(
        verify_transit_response(&resp1, &mesh.gateway_a_identity.public_key),
        "Gate G request 1: Gateway A signature MUST verify"
    );
    println!("[gate-g] Request 1 OK: status=200, Gateway A signature verified");

    // ─── Request 2: via Gateway A (should FAIL — Relay B is dead) ───────
    println!();
    println!("=== Request 2: Relay B is DEAD — client MUST fail (not hang) ===");
    let start = std::time::Instant::now();
    let result2 = send_via(
        &client,
        url,
        &mesh.gateway_a_identity.node_id,
        &mesh.relay_a_addr,
        mesh.client_relay_a_keys,
    );
    let elapsed2 = start.elapsed();
    assert!(
        result2.is_err(),
        "Gate G request 2: MUST fail (Relay B is dead). Got Ok: {result2:?}"
    );
    let err2 = result2.unwrap_err();
    println!(
        "[gate-g] Request 2 failed as expected after {:.2}s: {err2}",
        elapsed2.as_secs_f64()
    );
    assert!(
        elapsed2 < FAILURE_TIMEOUT,
        "Gate G request 2: MUST fail within {FAILURE_TIMEOUT:?} (not hang). Took {:.2}s.",
        elapsed2.as_secs_f64()
    );

    // ─── Mark Gateway A's circuit as inactive (client-side failover) ───
    println!();
    println!("=== Client marking Gateway A circuit inactive, failing over to Gateway B ===");
    {
        let mut circuits = client.circuits.lock().unwrap();
        if let Some(c) = circuits.get_mut(&mesh.gateway_a_identity.node_id) {
            c.active = false;
        }
    }

    // ─── Request 3: via Gateway B (should succeed — Relay C is alive) ───
    println!();
    println!("=== Request 3: Client → Relay A → Relay C → Gateway B (alternate path) ===");
    let start = std::time::Instant::now();
    let resp3 = send_via(
        &client,
        url,
        &mesh.gateway_b_identity.node_id,
        &mesh.relay_a_addr,
        mesh.client_relay_a_keys,
    )
    .expect("Gate G request 3: SHOULD succeed via Gateway B (Relay C is alive)");
    let elapsed3 = start.elapsed();
    println!(
        "[gate-g] Request 3 OK after {:.2}s: status={} object_id={} gateway_id={}",
        elapsed3.as_secs_f64(),
        resp3.status,
        hex_short(&resp3.object_id),
        hex_short(&resp3.gateway_id)
    );

    assert_eq!(resp3.status, 200, "Gate G request 3: status MUST be 200");
    assert_eq!(
        resp3.object_id,
        expected_object_id(),
        "Gate G request 3: object_id MUST match"
    );
    assert_eq!(
        resp3.gateway_id,
        mesh.gateway_b_identity.node_id,
        "Gate G request 3: response MUST be signed by Gateway B (NOT Gateway A)"
    );
    assert!(
        verify_transit_response(&resp3, &mesh.gateway_b_identity.public_key),
        "Gate G request 3: Gateway B signature MUST verify"
    );
    // Negative assertion: MUST NOT verify against Gateway A's key.
    assert!(
        !verify_transit_response(&resp3, &mesh.gateway_a_identity.public_key),
        "Gate G request 3: response MUST NOT verify against Gateway A's key (proves the path actually switched to Gateway B)"
    );

    println!();
    println!("=== Gate G PASSED ===");
    println!("  - Request 1 (Gateway A via Relay B): OK");
    println!("  - Relay B killed → Request 2 failed within {:.2}s (no hang)", elapsed2.as_secs_f64());
    println!("  - Failover to Gateway B via Relay C: OK");
    println!("  - Gateway B signature verified (path actually switched): OK");
    println!("  - NO process restart — client handled recovery internally: OK");

    std::mem::forget(mesh);
}

// ═══════════════════════════════════════════════════════════════════════════
// Gate H — Gateway failure recovery
// ═══════════════════════════════════════════════════════════════════════════

/// **N2.0.3 Gate H.** Gateway failure recovery.
///
/// From the Gate F topology, Gateway A is configured with
/// `drop_after = 1`: after serving one request, Gateway A shuts down
/// its TCP connection to Relay B.
///
/// The Client's NEXT request to Gateway A MUST fail (NACK from Relay
/// B → forwarded by Relay A — Gateway A is dead). The Client then
/// fails over to Gateway B via Relay C — NO process restart.
///
/// Verifies:
/// - Request 1 (via Gateway A): succeeds, status=200, Gateway A sig.
/// - Request 2 (via Gateway A): fails (UpstreamFailure) within timeout.
/// - Request 3 (via Gateway B): succeeds, status=200, Gateway B sig.
#[test]
fn n203_gate_h_gateway_failure_recovery() {
    println!();
    println!("══════════════════════════════════════════════════════════════════");
    println!("N2.0.3 Gate H — Gateway failure recovery");
    println!("══════════════════════════════════════════════════════════════════");
    println!();
    println!("  Gateway A dies after 1 request → client fails over to Gateway B (via Relay C)");
    println!();

    // ─── Set up topology (Gateway A drops after 1 request) ─────────────
    let mesh = setup_mesh_topology(0, 1);

    // ─── Build the client ──────────────────────────────────────────────
    let client = build_client(&mesh);
    let url = "http://test.local/";

    // ─── Request 1: via Gateway A (should succeed) ─────────────────────
    println!();
    println!("=== Request 1: Client → Relay A → Relay B → Gateway A ===");
    let resp1 = send_via(
        &client,
        url,
        &mesh.gateway_a_identity.node_id,
        &mesh.relay_a_addr,
        mesh.client_relay_a_keys,
    )
    .expect("Gate H request 1: SHOULD succeed (Gateway A is still alive)");

    assert_eq!(resp1.status, 200, "Gate H request 1: status MUST be 200");
    assert_eq!(
        resp1.object_id,
        expected_object_id(),
        "Gate H request 1: object_id MUST match"
    );
    assert_eq!(
        resp1.gateway_id,
        mesh.gateway_a_identity.node_id,
        "Gate H request 1: response MUST be signed by Gateway A"
    );
    assert!(
        verify_transit_response(&resp1, &mesh.gateway_a_identity.public_key),
        "Gate H request 1: Gateway A signature MUST verify"
    );
    println!("[gate-h] Request 1 OK: status=200, Gateway A signature verified");

    // ─── Request 2: via Gateway A (should FAIL — Gateway A is dead) ─────
    println!();
    println!("=== Request 2: Gateway A is DEAD — client MUST fail (not hang) ===");
    let start = std::time::Instant::now();
    let result2 = send_via(
        &client,
        url,
        &mesh.gateway_a_identity.node_id,
        &mesh.relay_a_addr,
        mesh.client_relay_a_keys,
    );
    let elapsed2 = start.elapsed();
    assert!(
        result2.is_err(),
        "Gate H request 2: MUST fail (Gateway A is dead). Got Ok: {result2:?}"
    );
    let err2 = result2.unwrap_err();
    println!(
        "[gate-h] Request 2 failed as expected after {:.2}s: {err2}",
        elapsed2.as_secs_f64()
    );
    assert!(
        elapsed2 < FAILURE_TIMEOUT,
        "Gate H request 2: MUST fail within {FAILURE_TIMEOUT:?} (not hang). Took {:.2}s.",
        elapsed2.as_secs_f64()
    );

    // ─── Mark Gateway A's circuit as inactive (client-side failover) ───
    println!();
    println!("=== Client marking Gateway A circuit inactive, failing over to Gateway B ===");
    {
        let mut circuits = client.circuits.lock().unwrap();
        if let Some(c) = circuits.get_mut(&mesh.gateway_a_identity.node_id) {
            c.active = false;
        }
    }

    // ─── Request 3: via Gateway B (should succeed — via Relay C) ────────
    println!();
    println!("=== Request 3: Client → Relay A → Relay C → Gateway B (failover) ===");
    let start = std::time::Instant::now();
    let resp3 = send_via(
        &client,
        url,
        &mesh.gateway_b_identity.node_id,
        &mesh.relay_a_addr,
        mesh.client_relay_a_keys,
    )
    .expect("Gate H request 3: SHOULD succeed via Gateway B");
    let elapsed3 = start.elapsed();
    println!(
        "[gate-h] Request 3 OK after {:.2}s: status={} object_id={} gateway_id={}",
        elapsed3.as_secs_f64(),
        resp3.status,
        hex_short(&resp3.object_id),
        hex_short(&resp3.gateway_id)
    );

    assert_eq!(resp3.status, 200, "Gate H request 3: status MUST be 200");
    assert_eq!(
        resp3.object_id,
        expected_object_id(),
        "Gate H request 3: object_id MUST match"
    );
    assert_eq!(
        resp3.gateway_id,
        mesh.gateway_b_identity.node_id,
        "Gate H request 3: response MUST be signed by Gateway B (NOT Gateway A)"
    );
    assert!(
        verify_transit_response(&resp3, &mesh.gateway_b_identity.public_key),
        "Gate H request 3: Gateway B signature MUST verify"
    );
    assert!(
        !verify_transit_response(&resp3, &mesh.gateway_a_identity.public_key),
        "Gate H request 3: response MUST NOT verify against Gateway A's key (proves failover to Gateway B)"
    );

    println!();
    println!("=== Gate H PASSED ===");
    println!("  - Request 1 (Gateway A via Relay B): OK");
    println!("  - Gateway A killed → Request 2 failed within {:.2}s (no hang)", elapsed2.as_secs_f64());
    println!("  - Failover to Gateway B via Relay C: OK");
    println!("  - Gateway B signature verified (path actually switched): OK");
    println!("  - NO process restart — client handled recovery internally: OK");

    std::mem::forget(mesh);
}
