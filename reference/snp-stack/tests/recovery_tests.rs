//! **N2.5-R.4 — Unexpected Active-Circuit Failure and Automatic Recovery.**
//!
//! These tests verify that when the active circuit fails unexpectedly,
//! the runtime detects it, marks it as failed, and recovers by
//! establishing a new active circuit.

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
    AdaptiveRouteOptimizer, CircuitState, MigrationExecutor, MigrationOutcome,
    OptimizerConfig, RouteObservationStore, RouteScoringWeights,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

struct DualMesh {
    handles: Vec<tokio::task::JoinHandle<()>>,
    route_a: Route,
    route_b: Route,
    client_node: Node,
    client_x_sk: Arc<X25519Secret>,
    client_x_pk: X25519PubKey,
}

async fn setup_dual_mesh() -> DualMesh {
    let client = NodeIdents::fresh();
    let ra1 = NodeIdents::fresh();
    let rb1 = NodeIdents::fresh();
    let ra2 = NodeIdents::fresh();
    let rb2 = NodeIdents::fresh();
    let gw = NodeIdents::fresh();

    let gw_addr1 = ephemeral_addr().await;
    let gw_addr2 = ephemeral_addr().await;
    let rb1_addr = ephemeral_addr().await;
    let ra1_addr = ephemeral_addr().await;
    let rb2_addr = ephemeral_addr().await;
    let ra2_addr = ephemeral_addr().await;

    let mut handles = Vec::new();

    // Two gateway listeners (same identity, shared stream table).
    let gw_node = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr1.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());
    let gw_addr1_spawn = gw_addr1.clone();
    let st1 = Arc::clone(&st);
    handles.push(tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node, &gw_addr1_spawn, &gw_x_sk, &gw_x_pk, &st1).await;
    }));

    let gw_node2 = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr2.clone());
    let gw_x_sk2 = Arc::clone(&gw.x_sk);
    let gw_x_pk2 = gw.x_pk;
    let st2 = Arc::clone(&st);
    let gw_addr2_spawn = gw_addr2.clone();
    handles.push(tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node2, &gw_addr2_spawn, &gw_x_sk2, &gw_x_pk2, &st2).await;
    }));
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Route A relays.
    let rb1_route = Route::new_with_hop_details(
        ra1.node_id, gw.node_id,
        vec![
            RouteHop::new(rb1.relay_descriptor(), TransportEndpoint::tcp(&rb1_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr1)),
        ],
    );
    handles.push(start_relay(&rb1, &rb1_route, 0, &rb1_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    let ra1_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra1.relay_descriptor(), TransportEndpoint::tcp(&ra1_addr)),
            RouteHop::new(rb1.relay_descriptor(), TransportEndpoint::tcp(&rb1_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr1)),
        ],
    );
    handles.push(start_relay(&ra1, &ra1_route, 0, &ra1_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Route B relays.
    let rb2_route = Route::new_with_hop_details(
        ra2.node_id, gw.node_id,
        vec![
            RouteHop::new(rb2.relay_descriptor(), TransportEndpoint::tcp(&rb2_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr2)),
        ],
    );
    handles.push(start_relay(&rb2, &rb2_route, 0, &rb2_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    let ra2_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra2.relay_descriptor(), TransportEndpoint::tcp(&ra2_addr)),
            RouteHop::new(rb2.relay_descriptor(), TransportEndpoint::tcp(&rb2_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr2)),
        ],
    );
    handles.push(start_relay(&ra2, &ra2_route, 0, &ra2_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    let route_a = build_route(&client, &ra1, &rb1, &gw, &ra1_addr, &rb1_addr, &gw_addr1);
    let route_b = build_route(&client, &ra2, &rb2, &gw, &ra2_addr, &rb2_addr, &gw_addr2);

    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client.x_sk);
    let client_x_pk = client.x_pk;

    DualMesh { handles, route_a, route_b, client_node, client_x_sk, client_x_pk }
}

// ════════════════════════════════════════════════════════════════════════════
// Test 1: fail_active_circuit marks circuit as Failed and resets optimizer
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fail_active_circuit_marks_failed_and_resets() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    // Establish route A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));

    let active_id = executor.circuit_registry().active_circuit_id().unwrap();

    // Simulate failure detection — mark active circuit as failed.
    executor.fail_active_circuit().unwrap();

    // The circuit should be Failed.
    assert_eq!(
        executor.circuit_registry().circuit_state(&active_id),
        Some(CircuitState::Failed)
    );

    // No active circuit.
    assert!(executor.circuit_registry().active_circuit_id().is_none());

    eprintln!("[n2.5-r.4] PASS: fail_active_circuit_marks_failed_and_resets");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2: After failure, recovery establishes new active circuit
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_after_failure_establishes_new_active() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    // Establish route A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;
    assert!(matches!(outcome, MigrationOutcome::Success { .. }));
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    // Simulate failure.
    executor.fail_active_circuit().unwrap();
    assert!(executor.circuit_registry().active_circuit_id().is_none());

    // Wait for cooldown to expire.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Attempt migration to a new route (recovery).
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    match &outcome {
        MigrationOutcome::Success { .. } => {
            assert_eq!(executor.current_route(), Some(hops_b.as_slice()),
                "recovery should establish route B");
        }
        _ => panic!("expected recovery Success, got {:?}", outcome),
    }

    eprintln!("[n2.5-r.4] PASS: recovery_after_failure_establishes_new_active");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3: New streams work on recovered circuit
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_streams_work_on_recovered_circuit() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    // Establish route A.
    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    // Fail and recover.
    executor.fail_active_circuit().unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await; // cooldown
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    assert!(matches!(outcome, MigrationOutcome::Success { .. }),
        "recovery should succeed, got {:?}", outcome);

    // Open a new stream on the recovered circuit.
    let mut stream = executor.active_circuit().unwrap()
        .open_stream(endpoint(echo_port)).await.unwrap();
    let data = b"recovery-stream-works";
    stream.send(data).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = stream.recv().await.unwrap().unwrap();
    assert_eq!(resp, data);

    eprintln!("[n2.5-r.4] PASS: new_streams_work_on_recovered_circuit");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4: Healthy circuit is not detected as failed
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_circuit_not_detected_as_failed() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    // Detect failure on healthy circuit — should return false.
    let failed = executor.detect_active_circuit_failure(
        endpoint(echo_port),
        Duration::from_secs(15),
    ).await;

    assert!(!failed, "healthy circuit should not be detected as failed");

    eprintln!("[n2.5-r.4] PASS: healthy_circuit_not_detected_as_failed");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 5: Failed circuit streams are terminated
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_circuit_streams_terminated() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    // Open a stream on A.
    let mut stream = executor.active_circuit().unwrap()
        .open_stream(endpoint(echo_port)).await.unwrap();
    stream.send(b"test").await.unwrap();

    // Mark active circuit as failed.
    executor.fail_active_circuit().unwrap();

    // The stream should fail (circuit closed, background reader aborted).
    let recv_result = tokio::time::timeout(
        Duration::from_secs(5),
        stream.recv(),
    ).await;

    assert!(
        recv_result.is_err() || matches!(recv_result, Ok(Err(_)) | Ok(Ok(None))),
        "stream on failed circuit should terminate"
    );

    eprintln!("[n2.5-r.4] PASS: failed_circuit_streams_terminated");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 6: Recovery failure when no routes available
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_failure_when_no_routes_available() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    // Establish route A.
    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    // Fail the active circuit.
    executor.fail_active_circuit().unwrap();

    // Kill ALL mesh infrastructure.
    for h in &mesh.handles {
        h.abort();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Attempt recovery — should fail (all routes dead).
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    assert!(matches!(outcome, MigrationOutcome::Failed { .. }),
        "recovery should fail when no routes are available");

    eprintln!("[n2.5-r.4] PASS: recovery_failure_when_no_routes_available");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.5-R.4.1 — Recovery route exclusion + quarantine tests
// ════════════════════════════════════════════════════════════════════════════

/// **Failed route is excluded from recovery candidates.**
///
/// After A fails and is quarantined, the optimizer's `check()` excludes
/// A from the candidate set. Recovery selects B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_route_is_excluded_from_recovery() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    // Establish route A.
    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    // Fail A.
    executor.fail_active_circuit().unwrap();

    // A should be quarantined.
    use snp_stack::network_intelligence::route_id_from_hops;
    let route_a_id = route_id_from_hops(&hops_a);
    assert!(
        executor.optimizer().is_quarantined(&route_a_id),
        "failed route A should be quarantined"
    );

    // Wait for cooldown.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Recovery — should select B, not A.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    match &outcome {
        MigrationOutcome::Success { .. } => {
            assert_eq!(
                executor.current_route(),
                Some(hops_b.as_slice()),
                "recovery should select B, not quarantined A"
            );
        }
        _ => panic!("expected recovery Success with B, got {:?}", outcome),
    }

    eprintln!("[n2.5-r.4.1] PASS: failed_route_is_excluded_from_recovery");
    drop(mesh.handles);
}

/// **Recovery does not reselect the failed active route.**
///
/// Even if A has better observations, after failure + quarantine,
/// A cannot be selected for recovery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_does_not_reselect_failed_active_route() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();

    // A has MUCH better observations than B — normally A would win.
    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(10.0);
        for _ in 0..20 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(100.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    let routes = vec![
        (hops_a.clone(), mesh.route_a.clone()),
        (hops_b.clone(), mesh.route_b.clone()),
    ];

    // Establish route A.
    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    // Fail A.
    executor.fail_active_circuit().unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Recovery — must select B, NOT A (A is quarantined even though it
    // has better observations).
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    match &outcome {
        MigrationOutcome::Success { .. } => {
            assert_ne!(
                executor.current_route(),
                Some(hops_a.as_slice()),
                "recovery must NOT reselect quarantined route A"
            );
            assert_eq!(
                executor.current_route(),
                Some(hops_b.as_slice()),
                "recovery should select B"
            );
        }
        _ => panic!("expected recovery Success with B, got {:?}", outcome),
    }

    eprintln!("[n2.5-r.4.1] PASS: recovery_does_not_reselect_failed_active_route");
    drop(mesh.handles);
}

/// **Only failed route available → returns NoRoutes.**
///
/// If the only available route is quarantined, recovery returns NoRoutes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_failed_route_available_returns_no_routes() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
    }

    let routes = vec![(hops_a.clone(), mesh.route_a.clone())];

    // Establish route A.
    executor.attempt_migration(
        &[hops_a.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    // Fail A.
    executor.fail_active_circuit().unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Recovery with only A as candidate — A is quarantined, so NoRoutes.
    let outcome = executor.attempt_migration(
        &[hops_a.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    assert!(
        matches!(outcome, MigrationOutcome::NoRoutes),
        "recovery with only quarantined route should return NoRoutes, got {:?}",
        outcome
    );

    eprintln!("[n2.5-r.4.1] PASS: only_failed_route_available_returns_no_routes");
    drop(mesh.handles);
}

/// **Failed route can be reintroduced after explicit retry policy.**
///
/// After quarantining A and recovering to B, the runtime can explicitly
/// reintroduce A (e.g., after a backoff period). A becomes eligible again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_route_can_be_reintroduced() {
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

    let hops_a = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let hops_b = vec![[1u8; 32], [4u8; 32], [5u8; 32], [3u8; 32]];

    {
        let mut s = route_obs.write().unwrap();
        s.get_or_create(&hops_a).record_latency(20.0);
        for _ in 0..10 { s.get_or_create(&hops_a).record_success(); }
        s.get_or_create(&hops_b).record_latency(30.0);
        for _ in 0..10 { s.get_or_create(&hops_b).record_success(); }
    }

    use snp_stack::network_intelligence::route_id_from_hops;
    let route_a_id = route_id_from_hops(&hops_a);

    // Quarantine A.
    opt.quarantine_route(route_a_id, Duration::from_secs(60));
    assert!(opt.is_quarantined(&route_a_id));

    // check() should not select A (only B is eligible).
    let result = opt.check(&[hops_a.clone(), hops_b.clone()]);
    match result {
        snp_stack::network_intelligence::OptimizationResult::Migrate(d) => {
            assert_eq!(d.target_route(), hops_b.as_slice(),
                "should select B, not quarantined A");
        }
        _ => panic!("expected Migrate"),
    }

    // Explicitly reintroduce A.
    opt.reintroduce_route(&route_a_id);
    assert!(!opt.is_quarantined(&route_a_id));

    eprintln!("[n2.5-r.4.1] PASS: failed_route_can_be_reintroduced");
}

/// **Epoch increments on fail_active_circuit.**
///
/// After failing the active circuit, the optimizer epoch increments,
/// invalidating all prior decisions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fail_active_circuit_increments_epoch() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

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

    // Establish route A.
    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    let epoch_before = executor.epoch();

    // Fail A.
    executor.fail_active_circuit().unwrap();

    let epoch_after = executor.epoch();
    assert!(
        epoch_after > epoch_before,
        "epoch must increment after fail_active_circuit ({} → {})",
        epoch_before, epoch_after
    );

    eprintln!("[n2.5-r.4.1] PASS: fail_active_circuit_increments_epoch");
    drop(mesh.handles);
}
