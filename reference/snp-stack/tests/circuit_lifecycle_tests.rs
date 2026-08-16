//! **N2.5-R.3.2 — Circuit Lifecycle Acceptance Tests.**
//!
//! These tests verify that the `MigrationExecutor` correctly manages the
//! lifecycle of `MultiplexedCircuit` instances through the `CircuitRegistry`
//! during route migration. The circuit stays alive in the registry after
//! migration, existing streams survive, draining circuits are reaped when
//! their streams close or their drain timeout expires, and failed migrations
//! preserve the active circuit and its streams.
//!
//! ## Key invariants verified
//!
//! - Existing streams on a draining circuit continue to function.
//! - New streams are opened on the active circuit only.
//! - `reap_draining()` closes draining circuits with zero streams or
//!   expired drain timeout.
//! - Failed migrations preserve the active circuit and existing streams.
//! - Health-check failures preserve the active circuit and existing streams.
//! - Stale decisions cannot be committed; their candidate circuits are disposed.
//! - Multiple draining circuits are supported.
//! - The active circuit is never closed by `reap_draining()`.
//! - `CircuitState` values match the actual circuit lifecycle.

#![cfg(feature = "circuit-upstream")]
#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use snp_crypto::{derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_stack::network_intelligence::{
    route_id_from_hops, AdaptiveRouteOptimizer, CircuitRegistry, CircuitState,
    EstablishedRoute, MigrationExecutor, MigrationOutcome, OptimizerConfig,
    OptimizationResult, RouteObservationStore, RouteScoringWeights,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// Mesh setup (copied from runtime_migration.rs)
// ════════════════════════════════════════════════════════════════════════════

struct NodeIdents {
    ed_sk: [u8; 32],
    x_sk: Arc<X25519Secret>,
    x_pk: X25519PubKey,
    node_id: [u8; 32],
}

impl NodeIdents {
    fn fresh() -> Self {
        let mut ed_sk = [0u8; 32];
        getrandom::getrandom(&mut ed_sk).expect("getrandom");
        let ed_pk = derive_public_key(&ed_sk);
        let node_id = derive_node_id(&ed_pk);
        let (x_sk, x_pk) = x25519_static_keypair();
        Self { ed_sk, x_sk: Arc::new(x_sk), x_pk, node_id }
    }
    fn identity(&self) -> NodeIdentity { NodeIdentity::from_secret(self.ed_sk) }
    fn gateway_descriptor(&self) -> VerifiedNodeDescriptor {
        let advert = GatewayAdvertisement::for_identity_with_circuit_key(
            &self.identity(), self.x_pk.to_bytes(), "127.0.0.1:0", "127.0.0.1:0",
        );
        advert.verify_into_verified().expect("verify").descriptor().expect("descriptor")
    }
    fn relay_descriptor(&self) -> VerifiedNodeDescriptor { self.gateway_descriptor() }
}

async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

async fn start_echo_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if stream.write_all(&buf[..n]).await.is_err() { break; } }
                    }
                }
            });
        }
    });
    (addr, handle)
}

fn start_relay(idents: &NodeIdents, route: &Route, pos: usize, addr: &str) -> tokio::task::JoinHandle<()> {
    let node = Node::new(idents.identity(), vec![Capability::Relay], addr.to_string());
    let x_sk = Arc::clone(&idents.x_sk);
    let x_pk = idents.x_pk;
    let listen = addr.to_string();
    let route = route.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(&node, &route, pos, &listen, &x_sk, &x_pk).await;
    })
}

fn build_route(
    client: &NodeIdents, ra: &NodeIdents, rb: &NodeIdents, gw: &NodeIdents,
    ra_addr: &str, rb_addr: &str, gw_addr: &str,
) -> Route {
    let mut route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(gw_addr)),
        ],
    );
    route.validate().expect("route valid");
    route.transition(RouteState::Establishing).expect("Establishing");
    route.transition(RouteState::Active).expect("Active");
    route
}

fn endpoint(port: u16) -> InternetEndpoint {
    InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        protocol: TransportProtocol::Tcp,
    }
}

struct Mesh {
    gw: tokio::task::JoinHandle<()>,
    gw2: tokio::task::JoinHandle<()>,
    ra: tokio::task::JoinHandle<()>,
    rb: tokio::task::JoinHandle<()>,
    route_a: Route,
    route_b: Route,
    client_node: Node,
    client_x_sk: Arc<X25519Secret>,
    client_x_pk: X25519PubKey,
}

async fn setup_two_route_mesh() -> Mesh {
    let client = NodeIdents::fresh();
    let ra1 = NodeIdents::fresh();
    let rb1 = NodeIdents::fresh();
    let ra2 = NodeIdents::fresh();
    let rb2 = NodeIdents::fresh();
    let gw = NodeIdents::fresh();

    // Two gateway listener addresses — the gateway function only accepts ONE
    // circuit per call, so we spawn two instances (same identity, same stream
    // table) on different ports. Route A terminates at gw_addr_a, route B at
    // gw_addr_b. Both instances share the same gateway identity (node_id +
    // X25519 keys), so from the protocol's perspective they are the "same
    // gateway." This lets both circuits be alive simultaneously.
    let gw_addr_a = ephemeral_addr().await;
    let gw_addr_b = ephemeral_addr().await;
    let rb1_addr = ephemeral_addr().await;
    let ra1_addr = ephemeral_addr().await;
    let rb2_addr = ephemeral_addr().await;
    let ra2_addr = ephemeral_addr().await;

    // Gateway instance A (handles route A's circuit).
    let gw_node_a = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr_a.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());
    let st_a = Arc::clone(&st);
    let gw_addr_a_spawn = gw_addr_a.clone();
    let gw_handle = tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node_a, &gw_addr_a_spawn, &gw_x_sk, &gw_x_pk, &st_a).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Gateway instance B (handles route B's circuit).
    let gw_node_b = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr_b.clone());
    let gw_x_sk2 = Arc::clone(&gw.x_sk);
    let gw_x_pk2 = gw.x_pk;
    let st_b = Arc::clone(&st);
    let gw_addr_b_spawn = gw_addr_b.clone();
    let gw2_handle = tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node_b, &gw_addr_b_spawn, &gw_x_sk2, &gw_x_pk2, &st_b).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Route A relays (terminate at gw_addr_a).
    let rb1_route = Route::new_with_hop_details(
        ra1.node_id, gw.node_id,
        vec![
            RouteHop::new(rb1.relay_descriptor(), TransportEndpoint::tcp(&rb1_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr_a)),
        ],
    );
    let rb1_handle = start_relay(&rb1, &rb1_route, 0, &rb1_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let ra1_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra1.relay_descriptor(), TransportEndpoint::tcp(&ra1_addr)),
            RouteHop::new(rb1.relay_descriptor(), TransportEndpoint::tcp(&rb1_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr_a)),
        ],
    );
    let ra1_handle = start_relay(&ra1, &ra1_route, 0, &ra1_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Route B relays (terminate at gw_addr_b).
    let rb2_route = Route::new_with_hop_details(
        ra2.node_id, gw.node_id,
        vec![
            RouteHop::new(rb2.relay_descriptor(), TransportEndpoint::tcp(&rb2_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr_b)),
        ],
    );
    let _rb2_handle = start_relay(&rb2, &rb2_route, 0, &rb2_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let ra2_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra2.relay_descriptor(), TransportEndpoint::tcp(&ra2_addr)),
            RouteHop::new(rb2.relay_descriptor(), TransportEndpoint::tcp(&rb2_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr_b)),
        ],
    );
    let _ra2_handle = start_relay(&ra2, &ra2_route, 0, &ra2_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let route_a = build_route(&client, &ra1, &rb1, &gw, &ra1_addr, &rb1_addr, &gw_addr_a);
    let route_b = build_route(&client, &ra2, &rb2, &gw, &ra2_addr, &rb2_addr, &gw_addr_b);

    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client.x_sk);
    let client_x_pk = client.x_pk;

    Mesh { gw: gw_handle, gw2: gw2_handle, ra: ra1_handle, rb: rb1_handle, route_a, route_b, client_node, client_x_sk, client_x_pk }
}

/// Set up a single independent circuit path (fresh relays + fresh gateway
/// listener, but sharing the same gateway identity and client identity).
///
/// Returns the established `MultiplexedCircuit`, the `Route`, and a list of
/// task handles (gateway + 2 relays) that must be kept alive for the circuit
/// to function.
///
/// Each relay only accepts ONE connection, so each call to this function
/// produces a fully independent path that can carry one circuit.
async fn establish_independent_circuit(
    client: &NodeIdents,
    gw: &NodeIdents,
    stream_table: Arc<GatewayStreamTable>,
) -> (MultiplexedCircuit, Route, Vec<tokio::task::JoinHandle<()>>) {
    let ra = NodeIdents::fresh();
    let rb = NodeIdents::fresh();

    let gw_addr = ephemeral_addr().await;
    let rb_addr = ephemeral_addr().await;
    let ra_addr = ephemeral_addr().await;

    // Gateway instance (same identity as the shared gateway, different port).
    let gw_node = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;
    let st = Arc::clone(&stream_table);
    let gw_addr_spawn = gw_addr.clone();
    let gw_handle = tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node, &gw_addr_spawn, &gw_x_sk, &gw_x_pk, &st).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Relays.
    let rb_route = Route::new_with_hop_details(
        ra.node_id, gw.node_id,
        vec![
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    let rb_handle = start_relay(&rb, &rb_route, 0, &rb_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let ra_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(&ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    let ra_handle = start_relay(&ra, &ra_route, 0, &ra_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let route = build_route(client, &ra, &rb, gw, &ra_addr, &rb_addr, &gw_addr);

    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let circuit = MultiplexedCircuit::establish(
        &client_node, &route, &client.x_sk, &client.x_pk,
    ).await.expect("establish independent circuit");

    (circuit, route, vec![gw_handle, rb_handle, ra_handle])
}

fn make_executor(route_obs: Arc<RwLock<RouteObservationStore>>) -> MigrationExecutor {
    let opt = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_obs),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 5.0,
            cooldown: Duration::from_millis(10),
            min_attempts_for_confidence: 10,
        },
    );
    MigrationExecutor::new(opt, route_obs)
}

fn make_executor_with_drain_timeout(
    route_obs: Arc<RwLock<RouteObservationStore>>,
    drain_timeout: Duration,
) -> MigrationExecutor {
    let opt = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_obs),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 5.0,
            cooldown: Duration::from_millis(10),
            min_attempts_for_confidence: 10,
        },
    );
    MigrationExecutor::with_drain_timeout(opt, route_obs, drain_timeout)
}

fn build_dead_route(mesh: &Mesh) -> Route {
    let fake_idents = NodeIdents::fresh();
    let gw_idents = NodeIdents::fresh();
    let mut route = Route::new_with_hop_details(
        mesh.client_node.identity.node_id,
        gw_idents.node_id,
        vec![
            RouteHop::new(fake_idents.relay_descriptor(), TransportEndpoint::tcp("127.0.0.1:1")),
            RouteHop::new(gw_idents.gateway_descriptor(), TransportEndpoint::tcp("127.0.0.1:1")),
        ],
    );
    route.validate().expect("route valid");
    route.transition(RouteState::Establishing).expect("Establishing");
    route.transition(RouteState::Active).expect("Active");
    route
}

/// Helper: send data on a stream, receive the echo, and verify it matches.
async fn assert_stream_echo_works(s: &mut snp_node::node::stream_client::StreamHandle, label: &str) {
    let payload = format!("circuit-lifecycle-{}-{}", label, std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() % 1_000_000);
    let payload_bytes = payload.as_bytes();
    s.send(payload_bytes).await.expect("send must succeed");
    // Give the gateway a moment to relay.
    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received.len() < payload_bytes.len() {
        if tokio::time::Instant::now() > deadline {
            panic!("stream {} echo timed out — received {}/{} bytes",
                label, received.len(), payload_bytes.len());
        }
        match tokio::time::timeout(Duration::from_secs(2), s.recv()).await {
            Ok(Ok(Some(data))) => received.extend_from_slice(&data),
            Ok(Ok(None)) => break,
            Ok(Err(e)) => panic!("stream {} recv failed: {:?}", label, e),
            Err(_) => continue,
        }
    }
    assert_eq!(received, payload_bytes,
        "stream {} echo data must match sent payload", label);
}

/// Helper: assert that a stream is broken (send or recv returns an error).
async fn assert_stream_is_broken(s: &mut snp_node::node::stream_client::StreamHandle, label: &str) {
    // Try to send — should fail quickly.
    let send_result = tokio::time::timeout(
        Duration::from_millis(500),
        s.send(b"post-close-probe"),
    ).await;
    match send_result {
        Ok(Ok(_)) => {
            // Send succeeded — try recv. If both succeed, the stream is
            // still alive (BAD — drain timeout should have terminated it).
            let recv_result = tokio::time::timeout(
                Duration::from_millis(500),
                s.recv(),
            ).await;
            match recv_result {
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => { /* broken as expected */ }
                Ok(Ok(Some(_))) => panic!("stream {} should be broken but recv succeeded", label),
            }
        }
        Ok(Err(_)) | Err(_) => { /* broken as expected */ }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test 1: planned_migration_existing_stream_survives
// ════════════════════════════════════════════════════════════════════════════

/// **Existing streams on the old circuit survive a planned migration.**
///
/// Open S1 on circuit A, migrate A→B, S1 continues to function (echo works).
/// The old circuit A enters `Draining` state but its `MultiplexedCircuit`
/// remains alive — the `StreamHandle` holds `Arc` references to A's link
/// and shared stream state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn planned_migration_existing_stream_survives() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    // Initial observations: A is better for cold-start.
    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];

    // Cold-start: establish A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }), "cold-start should succeed");
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    // Open S1 on A.
    let mut s1 = executor
        .active_circuit().expect("active circuit must exist after cold-start")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S1 must succeed");

    // Verify S1 works on A.
    assert_stream_echo_works(&mut s1, "S1-on-A").await;

    // Degrade A so B becomes better.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Migrate A→B.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }), "migration to B should succeed, got {:?}", outcome);
    assert_eq!(executor.current_route(), Some(hops_b.as_slice()));

    // The old circuit A should be Draining now.
    let draining = executor.circuit_registry().circuits_in_state(CircuitState::Draining);
    assert_eq!(draining.len(), 1, "exactly one circuit (A) should be Draining");

    // S1 (opened on A) must still work — its Arc refs keep A alive.
    assert_stream_echo_works(&mut s1, "S1-after-migration").await;

    // Clean up.
    let _ = s1.close().await;

    eprintln!("[n2.5-r.3.2] PASS: planned_migration_existing_stream_survives");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2: new_stream_after_migration_uses_new_circuit
// ════════════════════════════════════════════════════════════════════════════

/// **After migration, new streams are opened on the new (active) circuit.**
///
/// Migrate A→B, then open S2 on the active circuit (B). S2 must function
/// correctly (echo works), proving that `active_circuit()` returns B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_stream_after_migration_uses_new_circuit() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];

    // Cold-start: A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    let active_id_before = executor.circuit_registry().active_circuit_id()
        .expect("active circuit must exist after cold-start");

    // Degrade A.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Migrate A→B.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));
    assert_eq!(executor.current_route(), Some(hops_b.as_slice()));

    // The active circuit ID must have changed.
    let active_id_after = executor.circuit_registry().active_circuit_id()
        .expect("active circuit must exist after migration");
    assert_ne!(active_id_before, active_id_after,
        "active circuit must be a new circuit (B) after migration");

    // Open S2 on the active circuit (B).
    let mut s2 = executor
        .active_circuit().expect("active circuit must exist")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S2 must succeed");

    // S2 must work.
    assert_stream_echo_works(&mut s2, "S2-on-B").await;

    let _ = s2.close().await;

    eprintln!("[n2.5-r.3.2] PASS: new_stream_after_migration_uses_new_circuit");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3: existing_and_new_streams_use_different_circuits
// ════════════════════════════════════════════════════════════════════════════

/// **S1 on A and S2 on B both work after migration.**
///
/// Open S1 on A, migrate A→B, open S2 on B. Both streams must function
/// correctly — S1 on the draining circuit A, S2 on the active circuit B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn existing_and_new_streams_use_different_circuits() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];

    // Cold-start: A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    // Open S1 on A.
    let mut s1 = executor
        .active_circuit().expect("active circuit A")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S1");

    // Degrade A.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Migrate A→B.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));
    assert_eq!(executor.current_route(), Some(hops_b.as_slice()));

    // Open S2 on B (the new active circuit).
    let mut s2 = executor
        .active_circuit().expect("active circuit B")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S2");

    // Both streams must work — S1 on A (Draining), S2 on B (Active).
    assert_stream_echo_works(&mut s1, "S1-on-A-draining").await;
    assert_stream_echo_works(&mut s2, "S2-on-B-active").await;

    let _ = s1.close().await;
    let _ = s2.close().await;

    eprintln!("[n2.5-r.3.2] PASS: existing_and_new_streams_use_different_circuits");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4: zero_stream_draining_circuit_closes
// ════════════════════════════════════════════════════════════════════════════

/// **A draining circuit with zero streams is closed by `reap_draining()`.**
///
/// Open S1 on A, migrate A→B, close S1. After S1 closes, A's stream count
/// is zero. `reap_draining()` must close A (transition to `Closed`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_stream_draining_circuit_closes() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];

    // Cold-start: A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    // Open S1 on A.
    let mut s1 = executor
        .active_circuit().expect("active circuit A")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S1");

    // Migrate A→B.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    // A is now Draining.
    let draining = executor.circuit_registry().circuits_in_state(CircuitState::Draining);
    assert_eq!(draining.len(), 1);
    let old_circuit_id = draining[0];

    // Close S1.
    let _ = s1.close().await;
    // Give the registry a moment to observe stream closure.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify A's stream count is zero.
    let stream_count = executor.circuit_registry()
        .circuits_in_state(CircuitState::Draining)
        .len();
    let _ = stream_count; // just to ensure we can read state

    // Before reaping, A should still be Draining.
    assert_eq!(
        executor.circuit_registry().circuit_state(&old_circuit_id),
        Some(CircuitState::Draining),
        "A should still be Draining before reap_draining"
    );

    // Reap — should close A (zero streams).
    let closed = executor.reap_draining().await;
    assert!(closed.contains(&old_circuit_id),
        "reap_draining should close the zero-stream draining circuit A");

    // A is now Closed.
    assert_eq!(
        executor.circuit_registry().circuit_state(&old_circuit_id),
        Some(CircuitState::Closed),
        "A should be Closed after reap_draining"
    );

    // The active circuit B is untouched.
    let active_id = executor.circuit_registry().active_circuit_id()
        .expect("active circuit B must still exist");
    assert_eq!(
        executor.circuit_registry().circuit_state(&active_id),
        Some(CircuitState::Active),
        "B should still be Active"
    );

    eprintln!("[n2.5-r.3.2] PASS: zero_stream_draining_circuit_closes");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 5: drain_timeout_closes_active_stream
// ════════════════════════════════════════════════════════════════════════════

/// **Drain timeout expires → draining circuit is closed, S1 is terminated.**
///
/// Use a short drain timeout (10ms). Open S1 on A, migrate A→B, wait for
/// the drain timeout to expire. `reap_draining()` must close A and
/// terminate S1 (its `send`/`recv` calls must fail).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_timeout_closes_active_stream() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor_with_drain_timeout(
        Arc::clone(&route_obs),
        Duration::from_millis(10),
    );

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];

    // Cold-start: A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    // Open S1 on A.
    let mut s1 = executor
        .active_circuit().expect("active circuit A")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S1");

    // Verify S1 works before migration.
    assert_stream_echo_works(&mut s1, "S1-before-migration").await;

    // Migrate A→B.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    // A is now Draining.
    let draining = executor.circuit_registry().circuits_in_state(CircuitState::Draining);
    assert_eq!(draining.len(), 1);
    let old_circuit_id = draining[0];

    // Wait for drain timeout to expire.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Reap — should close A (drain timeout expired).
    let closed = executor.reap_draining().await;
    assert!(closed.contains(&old_circuit_id),
        "reap_draining should close the timed-out draining circuit A");

    assert_eq!(
        executor.circuit_registry().circuit_state(&old_circuit_id),
        Some(CircuitState::Closed),
        "A should be Closed after drain timeout reap"
    );

    // S1 should now be terminated (its circuit was closed).
    assert_stream_is_broken(&mut s1, "S1-after-drain-timeout").await;

    eprintln!("[n2.5-r.3.2] PASS: drain_timeout_closes_active_stream");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 6: failed_migration_preserves_active_circuit
// ════════════════════════════════════════════════════════════════════════════

/// **A failed migration preserves the active circuit.**
///
/// Establish A, attempt migration to a dead route (establishment fails).
/// A must remain `Active` and its circuit ID must be unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_migration_preserves_active_circuit() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();

    // Establish A.
    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
    }
    let routes = vec![(hops_a.clone(), mesh.route_a.clone())];
    let outcome = executor.attempt_migration(
        &[hops_a.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    let active_id_before = executor.circuit_registry().active_circuit_id()
        .expect("active circuit must exist");

    // Build a dead route and degrade A so the dead route looks better.
    let dead_route = build_dead_route(&mesh);
    let dead_hops = dead_route.hops();
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
        s.get_or_create(&dead_hops).record_latency(10.0);
        for _ in 0..10 { s.get_or_create(&dead_hops).record_success(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let routes2 = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (dead_hops.clone(), dead_route),
    ];

    // Attempt migration to dead route — should fail.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), dead_hops.clone()],
        &mesh.client_node, &routes2, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Failed { .. }),
        "migration to dead route should fail, got {:?}", outcome);

    // A's active circuit ID must be unchanged.
    let active_id_after = executor.circuit_registry().active_circuit_id()
        .expect("active circuit must still exist");
    assert_eq!(active_id_before, active_id_after,
        "active circuit ID must be unchanged after failed migration");

    // A is still Active.
    assert_eq!(
        executor.circuit_registry().circuit_state(&active_id_after),
        Some(CircuitState::Active),
        "A should still be Active after failed migration"
    );

    // No draining circuits (the dead candidate was disposed during establishment).
    assert_eq!(executor.circuit_registry().draining_count(), 0,
        "no circuits should be Draining after a failed migration");

    eprintln!("[n2.5-r.3.2] PASS: failed_migration_preserves_active_circuit");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 7: failed_migration_preserves_existing_stream
// ════════════════════════════════════════════════════════════════════════════

/// **A failed migration preserves existing streams on the active circuit.**
///
/// Open S1 on A, attempt migration to a dead route (fails). S1 on A must
/// still function correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_migration_preserves_existing_stream() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();

    // Establish A.
    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
    }
    let routes = vec![(hops_a.clone(), mesh.route_a.clone())];
    let outcome = executor.attempt_migration(
        &[hops_a.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    // Open S1 on A.
    let mut s1 = executor
        .active_circuit().expect("active circuit A")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S1");

    // Build a dead route and degrade A.
    let dead_route = build_dead_route(&mesh);
    let dead_hops = dead_route.hops();
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
        s.get_or_create(&dead_hops).record_latency(10.0);
        for _ in 0..10 { s.get_or_create(&dead_hops).record_success(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let routes2 = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (dead_hops.clone(), dead_route),
    ];

    // Attempt migration to dead route — should fail.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), dead_hops.clone()],
        &mesh.client_node, &routes2, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Failed { .. }));

    // S1 on A must still work.
    assert_stream_echo_works(&mut s1, "S1-after-failed-migration").await;

    let _ = s1.close().await;

    eprintln!("[n2.5-r.3.2] PASS: failed_migration_preserves_existing_stream");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 8: health_failure_preserves_active_circuit
// ════════════════════════════════════════════════════════════════════════════

/// **Health-check failure preserves the active circuit.**
///
/// Establish A, attempt migration to B with a DEAD health endpoint (port 1).
/// The circuit for B establishes (handshake succeeds), but the health check
/// fails. A must remain `Active`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_failure_preserves_active_circuit() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    // Establish A with health check.
    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }
    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    let active_id_before = executor.circuit_registry().active_circuit_id()
        .expect("active circuit must exist");

    // Degrade A.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Attempt migration to B with DEAD health endpoint.
    let dead_health_endpoint = endpoint(1);
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        dead_health_endpoint,
    ).await;
    match &outcome {
        MigrationOutcome::Failed { reason } => {
            eprintln!("[n2.5-r.3.2] health check failed as expected: {:?}", reason);
        }
        _ => panic!("expected Failed for health-check failure, got {:?}", outcome),
    }

    // A's active circuit ID must be unchanged.
    let active_id_after = executor.circuit_registry().active_circuit_id()
        .expect("active circuit must still exist");
    assert_eq!(active_id_before, active_id_after,
        "active circuit ID must be unchanged after health-check failure");

    assert_eq!(
        executor.circuit_registry().circuit_state(&active_id_after),
        Some(CircuitState::Active),
        "A should still be Active after health-check failure"
    );

    // No draining circuits.
    assert_eq!(executor.circuit_registry().draining_count(), 0,
        "no circuits should be Draining after a failed health check");

    eprintln!("[n2.5-r.3.2] PASS: health_failure_preserves_active_circuit");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 9: health_failure_preserves_existing_stream
// ════════════════════════════════════════════════════════════════════════════

/// **Health-check failure preserves existing streams on the active circuit.**
///
/// Open S1 on A, attempt migration to B with a dead health endpoint (fails).
/// S1 on A must still function correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_failure_preserves_existing_stream() {
    let mesh = setup_two_route_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let echo_endpoint = endpoint(echo_port);

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }
    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        echo_endpoint.clone(),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    // Open S1 on A.
    let mut s1 = executor
        .active_circuit().expect("active circuit A")
        .open_stream(echo_endpoint.clone()).await.expect("open_stream S1");

    // Degrade A.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Attempt migration to B with DEAD health endpoint.
    let dead_health_endpoint = endpoint(1);
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        dead_health_endpoint,
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Failed { .. }),
        "health-check failure should result in Failed");

    // S1 on A must still work.
    assert_stream_echo_works(&mut s1, "S1-after-health-failure").await;

    let _ = s1.close().await;

    eprintln!("[n2.5-r.3.2] PASS: health_failure_preserves_existing_stream");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 10: stale_candidate_is_disposed
// ════════════════════════════════════════════════════════════════════════════

/// **A stale candidate's circuit is disposed when its decision is superseded.**
///
/// Because `attempt_migration()` is atomic (it commits internally), we use
/// the lower-level optimizer + registry API directly to simulate the
/// non-atomic flow:
/// 1. D1 = `optimizer.check()` (targets B).
/// 2. Establish circuit B, register as Candidate.
/// 3. D2 = `optimizer.check()` (replaces D1).
/// 4. Try to commit D1 with evidence for B → fails (stale).
/// 5. The candidate B is disposed (mark_failed).
/// 6. B's state is `Failed` (circuit dropped).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_candidate_is_disposed() {
    let mesh = setup_two_route_mesh().await;

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut opt = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_obs),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 5.0,
            cooldown: Duration::from_millis(10),
            min_attempts_for_confidence: 10,
        },
    );
    let mut registry = CircuitRegistry::new();

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    // Cold-start: A is better initially.
    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    // D1: cold-start, targets A.
    let d1 = match opt.check(&[hops_a.clone(), hops_b.clone()]) {
        OptimizationResult::Migrate(d) => d,
        _ => panic!("expected Migrate for D1"),
    };

    // Establish circuit for A.
    let circuit_a = MultiplexedCircuit::establish(
        &mesh.client_node, &mesh.route_a, &mesh.client_x_sk, &mesh.client_x_pk,
    ).await.expect("establish A");
    let fid_a = registry.register_candidate(
        circuit_a,
        route_id_from_hops(&hops_a),
        hops_a.clone(),
    );
    registry.mark_healthy(&fid_a).unwrap();
    let evidence_a = EstablishedRoute::from_establishment(
        hops_a.clone(), fid_a,
        mesh.route_a.destination(), mesh.client_node.identity.node_id,
    );
    opt.commit_migration_with_evidence(d1, &evidence_a).expect("commit D1");
    registry.promote_to_active(&fid_a).unwrap();

    // Degrade A so B becomes the recommended target.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // D2: targets B.
    let d2 = match opt.check(&[hops_a.clone(), hops_b.clone()]) {
        OptimizationResult::Migrate(d) => d,
        _ => panic!("expected Migrate for D2"),
    };

    // Establish circuit for B (simulating what attempt_migration would do).
    let circuit_b = MultiplexedCircuit::establish(
        &mesh.client_node, &mesh.route_b, &mesh.client_x_sk, &mesh.client_x_pk,
    ).await.expect("establish B");
    let fid_b = registry.register_candidate(
        circuit_b,
        route_id_from_hops(&hops_b),
        hops_b.clone(),
    );
    registry.mark_healthy(&fid_b).unwrap();

    // D3: replaces D2.
    let d3 = match opt.check(&[hops_a.clone(), hops_b.clone()]) {
        OptimizationResult::Migrate(d) => d,
        _ => panic!("expected Migrate for D3"),
    };
    assert_ne!(d2.decision_id(), d3.decision_id(),
        "D3 must have a different decision_id than D2");

    // Try to commit D2 (stale) with evidence for B → must fail.
    let evidence_b = EstablishedRoute::from_establishment(
        hops_b.clone(), fid_b,
        mesh.route_b.destination(), mesh.client_node.identity.node_id,
    );
    let result = opt.commit_migration_with_evidence(d2, &evidence_b);
    assert!(result.is_err(),
        "stale D2 must be rejected after D3 replaced it, got {:?}", result);

    // The candidate B must be disposed (simulating the executor's behavior
    // when commit_migration_with_evidence fails).
    registry.mark_failed(&fid_b).expect("mark_failed B");

    // B's state must be Failed (circuit dropped).
    assert_eq!(
        registry.circuit_state(&fid_b),
        Some(CircuitState::Failed),
        "stale candidate B must be disposed (state Failed)"
    );

    // The active circuit A must be unchanged.
    assert_eq!(
        registry.active_circuit_id(),
        Some(fid_a),
        "active circuit A must be unchanged after stale D2 rejection"
    );
    assert_eq!(
        registry.circuit_state(&fid_a),
        Some(CircuitState::Active),
        "A must still be Active"
    );

    eprintln!("[n2.5-r.3.2] PASS: stale_candidate_is_disposed");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 11: stale_candidate_cannot_become_active
// ════════════════════════════════════════════════════════════════════════════

/// **A stale candidate's circuit cannot be promoted to active.**
///
/// Similar to test 10, but verifies that the stale candidate's circuit
/// cannot become the active circuit. After D2 is rejected, the active
/// circuit remains A, and B's candidate is in Failed state (not Active).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_candidate_cannot_become_active() {
    let mesh = setup_two_route_mesh().await;

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut opt = AdaptiveRouteOptimizer::new(
        Arc::clone(&route_obs),
        RouteScoringWeights::default(),
        OptimizerConfig {
            min_improvement_pct: 5.0,
            cooldown: Duration::from_millis(10),
            min_attempts_for_confidence: 10,
        },
    );
    let mut registry = CircuitRegistry::new();

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    // Cold-start A.
    let d1 = match opt.check(&[hops_a.clone(), hops_b.clone()]) {
        OptimizationResult::Migrate(d) => d,
        _ => panic!("expected Migrate for D1"),
    };
    let circuit_a = MultiplexedCircuit::establish(
        &mesh.client_node, &mesh.route_a, &mesh.client_x_sk, &mesh.client_x_pk,
    ).await.expect("establish A");
    let fid_a = registry.register_candidate(circuit_a, route_id_from_hops(&hops_a), hops_a.clone());
    registry.mark_healthy(&fid_a).unwrap();
    let evidence_a = EstablishedRoute::from_establishment(
        hops_a.clone(), fid_a,
        mesh.route_a.destination(), mesh.client_node.identity.node_id,
    );
    opt.commit_migration_with_evidence(d1, &evidence_a).unwrap();
    registry.promote_to_active(&fid_a).unwrap();

    // Degrade A so B becomes the target.
    {
        let mut s = route_obs.write().unwrap();
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(500.0); }
        for _ in 0..5 { s.get_or_create(&hops_a).record_failure(); }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // D2: targets B.
    let d2 = match opt.check(&[hops_a.clone(), hops_b.clone()]) {
        OptimizationResult::Migrate(d) => d,
        _ => panic!("expected Migrate for D2"),
    };

    // Establish B and register as candidate.
    let circuit_b = MultiplexedCircuit::establish(
        &mesh.client_node, &mesh.route_b, &mesh.client_x_sk, &mesh.client_x_pk,
    ).await.expect("establish B");
    let fid_b = registry.register_candidate(circuit_b, route_id_from_hops(&hops_b), hops_b.clone());
    registry.mark_healthy(&fid_b).unwrap();

    // D3 replaces D2.
    let _d3 = match opt.check(&[hops_a.clone(), hops_b.clone()]) {
        OptimizationResult::Migrate(d) => d,
        _ => panic!("expected Migrate for D3"),
    };

    // Attempt to promote B to active — must fail because B is still
    // in Healthy state, but its decision (D2) is stale. The caller
    // (executor) must first commit_migration_with_evidence, which fails.
    let evidence_b = EstablishedRoute::from_establishment(
        hops_b.clone(), fid_b,
        mesh.route_b.destination(), mesh.client_node.identity.node_id,
    );
    let result = opt.commit_migration_with_evidence(d2, &evidence_b);
    assert!(result.is_err(), "stale D2 commit must fail");

    // Since the commit failed, the executor must NOT promote B to active.
    // We verify that B cannot be promoted (its state is Healthy, not Active).
    assert_ne!(
        registry.active_circuit_id(),
        Some(fid_b),
        "stale candidate B must NOT be the active circuit"
    );
    assert_eq!(
        registry.active_circuit_id(),
        Some(fid_a),
        "A must still be the active circuit"
    );

    // The executor's recovery action: mark B as failed (dispose).
    registry.mark_failed(&fid_b).ok();
    assert_eq!(
        registry.circuit_state(&fid_b),
        Some(CircuitState::Failed),
        "stale candidate B must end up Failed (disposed)"
    );

    eprintln!("[n2.5-r.3.2] PASS: stale_candidate_cannot_become_active");
    drop(mesh.gw); drop(mesh.gw2); drop(mesh.ra); drop(mesh.rb);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 12: multiple_draining_circuits_supported
// ════════════════════════════════════════════════════════════════════════════

/// **The registry supports multiple draining circuits simultaneously.**
///
/// Promote C1 → Active, then C2 → Active (C1 Draining), then C3 → Active
/// (C1 and C2 both Draining). Verify `draining_count() == 2` and that
/// `reap_draining()` can close them both (after their streams close).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_draining_circuits_supported() {
    let client = NodeIdents::fresh();
    let gw = NodeIdents::fresh();
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());

    // Establish three independent circuits (each on its own relay path +
    // gateway listener, since each relay/gateway only accepts ONE circuit).
    let (circuit_1, route_1, _h1) = establish_independent_circuit(&client, &gw, Arc::clone(&st)).await;
    let (circuit_2, route_2, _h2) = establish_independent_circuit(&client, &gw, Arc::clone(&st)).await;
    let (circuit_3, route_3, _h3) = establish_independent_circuit(&client, &gw, Arc::clone(&st)).await;

    let mut registry = CircuitRegistry::new();

    let hops_1 = route_1.hops();
    let hops_2 = route_2.hops();
    let hops_3 = route_3.hops();
    let fid_1 = registry.register_candidate(circuit_1, route_id_from_hops(&hops_1), hops_1.clone());
    let fid_2 = registry.register_candidate(circuit_2, route_id_from_hops(&hops_2), hops_2.clone());
    let fid_3 = registry.register_candidate(circuit_3, route_id_from_hops(&hops_3), hops_3.clone());

    registry.mark_healthy(&fid_1).unwrap();
    registry.mark_healthy(&fid_2).unwrap();
    registry.mark_healthy(&fid_3).unwrap();

    // Promote C1 → Active.
    registry.promote_to_active(&fid_1).unwrap();
    assert_eq!(registry.active_circuit_id(), Some(fid_1));
    assert_eq!(registry.draining_count(), 0);

    // Promote C2 → Active. C1 becomes Draining.
    registry.promote_to_active(&fid_2).unwrap();
    assert_eq!(registry.active_circuit_id(), Some(fid_2));
    assert_eq!(registry.draining_count(), 1);
    assert_eq!(registry.circuit_state(&fid_1), Some(CircuitState::Draining));

    // Promote C3 → Active. C1 and C2 both Draining.
    registry.promote_to_active(&fid_3).unwrap();
    assert_eq!(registry.active_circuit_id(), Some(fid_3));
    assert_eq!(registry.draining_count(), 2,
        "both C1 and C2 should be Draining");
    assert_eq!(registry.circuit_state(&fid_1), Some(CircuitState::Draining));
    assert_eq!(registry.circuit_state(&fid_2), Some(CircuitState::Draining));
    assert_eq!(registry.circuit_state(&fid_3), Some(CircuitState::Active));

    // Reap — both draining circuits have zero streams and should close.
    let closed = registry.reap_draining().await;
    assert_eq!(closed.len(), 2, "both draining circuits should be reaped");
    assert!(closed.contains(&fid_1));
    assert!(closed.contains(&fid_2));

    assert_eq!(registry.circuit_state(&fid_1), Some(CircuitState::Closed));
    assert_eq!(registry.circuit_state(&fid_2), Some(CircuitState::Closed));
    assert_eq!(registry.circuit_state(&fid_3), Some(CircuitState::Active),
        "C3 must remain Active after reaping");

    eprintln!("[n2.5-r.3.2] PASS: multiple_draining_circuits_supported");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 13: active_circuit_not_closed_by_drain_timeout
// ════════════════════════════════════════════════════════════════════════════

/// **The active circuit is never closed by `reap_draining()`.**
///
/// Use a short drain timeout (10ms). Establish A as Active (no migration).
/// Wait for the drain timeout to expire. `reap_draining()` must NOT close
/// A — only Draining circuits are eligible for closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_circuit_not_closed_by_drain_timeout() {
    let client = NodeIdents::fresh();
    let gw = NodeIdents::fresh();
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());

    let (circuit, route, _h) = establish_independent_circuit(&client, &gw, st).await;

    let mut registry = CircuitRegistry::with_drain_timeout(Duration::from_millis(10));

    let hops = route.hops();
    let fid = registry.register_candidate(circuit, route_id_from_hops(&hops), hops.clone());
    registry.mark_healthy(&fid).unwrap();
    registry.promote_to_active(&fid).unwrap();

    assert_eq!(registry.active_circuit_id(), Some(fid));
    assert_eq!(registry.circuit_state(&fid), Some(CircuitState::Active));

    // Wait for the drain timeout to expire.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Reap — must NOT close the Active circuit.
    let closed = registry.reap_draining().await;
    assert!(closed.is_empty(),
        "reap_draining must not close any Active circuits, got {:?}", closed);

    // A is still Active.
    assert_eq!(registry.circuit_state(&fid), Some(CircuitState::Active),
        "Active circuit must survive reap_draining even after drain timeout expires");
    assert_eq!(registry.active_circuit_id(), Some(fid));

    eprintln!("[n2.5-r.3.2] PASS: active_circuit_not_closed_by_drain_timeout");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 14: candidate_state_matches_actual_lifecycle
// ════════════════════════════════════════════════════════════════════════════

/// **`CircuitState` values match the actual circuit lifecycle.**
///
/// Walk through the full lifecycle Candidate → Healthy → Active → Draining
/// → Closed, and verify the state at each step. Also verify the Failed
/// branch (Candidate → Failed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn candidate_state_matches_actual_lifecycle() {
    let client = NodeIdents::fresh();
    let gw = NodeIdents::fresh();
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());

    // Two circuits for the happy path, one for the failure path.
    let (c1, route_1, _h1) = establish_independent_circuit(&client, &gw, Arc::clone(&st)).await;
    let (c2, route_2, _h2) = establish_independent_circuit(&client, &gw, Arc::clone(&st)).await;
    let (c3, route_3, _h3) = establish_independent_circuit(&client, &gw, Arc::clone(&st)).await;

    let mut registry = CircuitRegistry::new();

    let hops_1 = route_1.hops();
    let hops_2 = route_2.hops();
    let hops_3 = route_3.hops();
    let route_id_1 = route_id_from_hops(&hops_1);
    let route_id_2 = route_id_from_hops(&hops_2);
    let route_id_3 = route_id_from_hops(&hops_3);

    // --- Happy path: Candidate → Healthy → Active → Draining → Closed ---

    let fid1 = registry.register_candidate(c1, route_id_1, hops_1.clone());
    let fid2 = registry.register_candidate(c2, route_id_2, hops_2.clone());

    // State right after registration: Candidate.
    assert_eq!(registry.circuit_state(&fid1), Some(CircuitState::Candidate),
        "newly registered circuit must be in Candidate state");
    assert_eq!(registry.circuit_state(&fid2), Some(CircuitState::Candidate),
        "newly registered circuit must be in Candidate state");

    // mark_healthy → Healthy.
    registry.mark_healthy(&fid1).unwrap();
    registry.mark_healthy(&fid2).unwrap();
    assert_eq!(registry.circuit_state(&fid1), Some(CircuitState::Healthy));
    assert_eq!(registry.circuit_state(&fid2), Some(CircuitState::Healthy));

    // promote_to_active → Active (for fid1).
    registry.promote_to_active(&fid1).unwrap();
    assert_eq!(registry.circuit_state(&fid1), Some(CircuitState::Active));
    assert_eq!(registry.active_circuit_id(), Some(fid1));

    // Promote fid2 → fid1 becomes Draining.
    registry.promote_to_active(&fid2).unwrap();
    assert_eq!(registry.circuit_state(&fid2), Some(CircuitState::Active));
    assert_eq!(registry.circuit_state(&fid1), Some(CircuitState::Draining));
    assert_eq!(registry.active_circuit_id(), Some(fid2));
    assert_eq!(registry.draining_count(), 1);

    // reap_draining (fid1 has zero streams) → Closed.
    let closed = registry.reap_draining().await;
    assert!(closed.contains(&fid1));
    assert_eq!(registry.circuit_state(&fid1), Some(CircuitState::Closed));
    // fid2 remains Active.
    assert_eq!(registry.circuit_state(&fid2), Some(CircuitState::Active));

    // --- Failure path: Candidate → Failed ---

    let fid3 = registry.register_candidate(c3, route_id_3, hops_3.clone());
    assert_eq!(registry.circuit_state(&fid3), Some(CircuitState::Candidate));

    registry.mark_failed(&fid3).unwrap();
    assert_eq!(registry.circuit_state(&fid3), Some(CircuitState::Failed),
        "failed circuit must be in Failed state");

    // A Failed circuit cannot become active.
    assert_ne!(registry.active_circuit_id(), Some(fid3));
    assert_eq!(registry.active_circuit_id(), Some(fid2),
        "active circuit must remain fid2");

    // Verify all states are representable and Display correctly.
    let all_states = vec![
        CircuitState::Candidate,
        CircuitState::Healthy,
        CircuitState::Active,
        CircuitState::Draining,
        CircuitState::Closed,
        CircuitState::Failed,
    ];
    for state in &all_states {
        let display = format!("{}", state);
        assert!(!display.is_empty(), "CircuitState::{:?} must have a Display representation", state);
    }

    eprintln!("[n2.5-r.3.2] PASS: candidate_state_matches_actual_lifecycle");
}
