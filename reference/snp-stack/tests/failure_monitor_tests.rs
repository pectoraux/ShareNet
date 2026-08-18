//! **N2.5-R.5 — Failure Detection Integration / Recovery Triggering.**
//!
//! These tests verify that the background failure monitor detects
//! active-circuit failures and signals recovery, and that the runtime
//! can use the signal to trigger automatic recovery.

#![cfg(feature = "circuit-upstream")]
#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use snp_crypto::{derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_stack::network_intelligence::{
    AdaptiveRouteOptimizer, CircuitState, FailureMonitor, FailureMonitorConfig,
    MigrationExecutor, MigrationOutcome, OptimizerConfig, ProbeContext, RecoveryChannel,
    RecoveryRequest, RouteObservationStore, RouteScoringWeights,
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

/// A "black hole" TCP server: accepts connections and reads data but never
/// writes back. Used to make a failure-monitor probe hang on `recv` until
/// the probe timeout fires (so we can observe the probe being in flight).
async fn start_black_hole() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => { /* discard, never echo */ }
                    }
                }
            });
        }
    });
    (port, handle)
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
// Test 1: Failure monitor detects failure and signals recovery
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failure_monitor_detects_and_signals() {
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

    // Wrap executor in Arc<Mutex> for the monitor.
    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    // Start failure monitor with short probe interval.
    let mut monitor = FailureMonitor::new();
    monitor.start(
        Arc::clone(&executor),
        endpoint(echo_port),
        FailureMonitorConfig {
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(10),
        },
    );

    assert!(monitor.is_running(), "monitor should be running");
    assert!(!monitor.channel().peek(), "no failure yet");

    // Kill route A's relays.
    mesh.handles[0].abort(); // gw1
    mesh.handles[2].abort(); // rb1
    mesh.handles[3].abort(); // ra1

    // Wait for the monitor to detect the failure.
    let detected = tokio::time::timeout(
        Duration::from_secs(30),
        async {
            loop {
                if monitor.channel().peek() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        },
    )
    .await;

    assert!(detected.is_ok(), "failure monitor should detect failure within 30s");
    assert!(monitor.channel().take().is_some(), "recovery request should be present");

    eprintln!("[n2.5-r.5] PASS: failure_monitor_detects_and_signals");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2: Healthy circuit — monitor does not signal
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_circuit_monitor_does_not_signal() {
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

    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    let mut monitor = FailureMonitor::new();
    monitor.start(
        Arc::clone(&executor),
        endpoint(echo_port),
        FailureMonitorConfig {
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(10),
        },
    );

    // Wait for a few probe cycles — no failure should be detected.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(!monitor.channel().peek(), "healthy circuit should not trigger recovery request");
    assert!(monitor.is_running(), "monitor should still be running");

    eprintln!("[n2.5-r.5] PASS: healthy_circuit_monitor_does_not_signal");
    monitor.stop();
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3: Recovery signal triggers successful recovery
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_signal_triggers_successful_recovery() {
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
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    // Simulate failure detection (direct call, not via monitor).
    executor.fail_active_circuit().unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await; // cooldown

    // Recovery — should establish B.
    let outcome = executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    assert!(matches!(outcome, MigrationOutcome::Success { .. }));
    assert_eq!(executor.current_route(), Some(hops_b.as_slice()));

    // New streams should work on B.
    let circuit = executor.active_circuit().unwrap();
    let mut stream = circuit.lock().await.open_stream(endpoint(echo_port)).await.unwrap();
    stream.send(b"post-recovery").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = stream.recv().await.unwrap().unwrap();
    assert_eq!(resp, b"post-recovery");

    eprintln!("[n2.5-r.5] PASS: recovery_signal_triggers_successful_recovery");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4: Monitor stops after detecting failure
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn monitor_stops_after_detecting_failure() {
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

    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    let mut monitor = FailureMonitor::new();
    monitor.start(
        Arc::clone(&executor),
        endpoint(echo_port),
        FailureMonitorConfig {
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(10),
        },
    );

    // Kill route A.
    mesh.handles[0].abort();
    mesh.handles[2].abort();
    mesh.handles[3].abort();

    // Wait for the monitor to detect and exit.
    let detected = tokio::time::timeout(
        Duration::from_secs(30),
        async {
            loop {
                if monitor.channel().peek() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        },
    )
    .await;

    assert!(detected.is_ok(), "monitor should detect failure");

    // Give the task time to exit.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Monitor should no longer be running (it exits after detecting failure).
    assert!(!monitor.is_running(), "monitor should stop after detecting failure");

    eprintln!("[n2.5-r.5] PASS: monitor_stops_after_detecting_failure");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// Test 5: RecoveryChannel peek / take semantics + provenance round-trip
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn recovery_channel_peek_take_and_provenance() {
    let channel = RecoveryChannel::new();

    // A fresh channel has no pending request.
    assert!(!channel.peek(), "fresh channel should have no pending request");
    assert!(channel.take().is_none(), "take on fresh channel returns None");
    assert!(channel.peek_request().is_none(), "peek_request on fresh channel is None");

    // Simulate the monitor emitting a provenance-bound request.
    let ctx = ProbeContext {
        circuit_id: [0xAA; 8],
        route_id: [0xBB; 32],
        epoch: 42,
    };
    let request = RecoveryRequest::from(ctx);
    channel.emit_for_test(request);

    // peek does NOT clear.
    assert!(channel.peek(), "channel should have a pending request after emit");
    let peeked = channel.peek_request().expect("peek_request should return the request");
    assert_eq!(peeked.circuit_id, [0xAA; 8]);
    assert_eq!(peeked.route_id, [0xBB; 32]);
    assert_eq!(peeked.epoch, 42);

    // take() returns the request and clears.
    let taken = channel.take().expect("take should return the request");
    assert_eq!(taken.circuit_id, [0xAA; 8]);
    assert_eq!(taken.route_id, [0xBB; 32]);
    assert_eq!(taken.epoch, 42);

    // After take, the channel is empty.
    assert!(!channel.peek(), "channel should be empty after take");
    assert!(channel.take().is_none(), "second take returns None");

    eprintln!("[n2.5-r.5.1] PASS: recovery_channel_peek_take_and_provenance");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.5-R.5.1 Test 1: Probe does NOT hold the executor-wide mutex over I/O
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_does_not_hold_executor_lock() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let (bh_port, _bh) = start_black_hole().await;

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

    // Establish A (health-checked via the real echo server).
    executor.attempt_migration(
        &[hops_a.clone(), hops_b.clone()],
        &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
        endpoint(echo_port),
    ).await;

    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    // Monitor probes the BLACK-HOLE through A. The probe hangs on recv
    // until probe_timeout — during that window the per-circuit mutex is
    // held but the executor mutex must NOT be.
    let mut monitor = FailureMonitor::new();
    monitor.start(
        Arc::clone(&executor),
        endpoint(bh_port),
        FailureMonitorConfig {
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(4),
        },
    );

    // Wait until the probe is in flight (per-circuit mutex held by monitor).
    let probe_in_flight = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let exec = executor.lock().await;
            if let Some(handle) = exec.active_circuit() {
                if handle.try_lock().is_err() {
                    return true;
                }
            }
            drop(exec);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    assert!(probe_in_flight.is_ok(), "probe should be in flight within 8s");

    // The probe is in flight (per-circuit mutex held). Acquire the EXECUTOR
    // mutex and do a quick op. If the monitor held the executor mutex over
    // the probe, this would block ~4s.
    let start = Instant::now();
    {
        let exec = executor.lock().await;
        let _ = exec.epoch();
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "executor lock must be acquirable while a probe is in flight (took {:?})",
        elapsed
    );

    eprintln!("[n2.5-r.5.1] PASS: probe_does_not_hold_executor_lock");
    monitor.stop();
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// N2.5-R.5.1 Test 2: RecoveryRequest carries full provenance
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_request_carries_provenance() {
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

    // Capture the expected provenance of the active circuit (A).
    let expected_circuit_id = executor.circuit_registry().active_circuit_id()
        .expect("active circuit A");
    let expected_route_id = executor.circuit_registry()
        .circuit_route_id(&expected_circuit_id)
        .expect("route id for A");
    let expected_epoch = executor.epoch();

    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    let mut monitor = FailureMonitor::new();
    monitor.start(
        Arc::clone(&executor),
        endpoint(echo_port),
        FailureMonitorConfig {
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(10),
        },
    );

    // Kill A's relays so the probe fails.
    mesh.handles[0].abort();
    mesh.handles[2].abort();
    mesh.handles[3].abort();

    // Wait for the monitor to emit a RecoveryRequest.
    let request = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(r) = monitor.channel().take() { return r; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await;

    let request = request.expect("monitor should emit a recovery request");

    assert_eq!(request.circuit_id, expected_circuit_id,
        "request circuit_id must match the probed (active) circuit");
    assert_eq!(request.route_id, expected_route_id,
        "request route_id must match the probed circuit's route");
    assert_eq!(request.epoch, expected_epoch,
        "request epoch must match the optimizer epoch at probe-start");

    eprintln!("[n2.5-r.5.1] PASS: recovery_request_carries_provenance");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// N2.5-R.5.1 Test 3: Stale request (migration race) is rejected
// ════════════════════════════════════════════════════════════════════════════
//
// Reproduces the exact race from the R.5 audit:
//   A active → monitor probes A → A→B migration completes →
//   probe of A fails → RecoveryRequest{A, old_epoch} →
//   runtime verifies it no longer matches ACTIVE → STALE → discard.
//
// Without the ProbeContext binding, the boolean signal would be
// misattributed to circuit B, causing a spurious failure of the healthy
// new circuit. With the binding, the request is rejected.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_request_after_migration_rejected() {
    let mesh = setup_dual_mesh().await;
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();
    let (bh_port, _bh) = start_black_hole().await;

    let route_obs = Arc::new(RwLock::new(RouteObservationStore::new()));
    let mut executor = make_executor(Arc::clone(&route_obs));

    let hops_a = mesh.route_a.hops();
    let hops_b = mesh.route_b.hops();
    // A better initially (latency 20 < B's 30) → cold-start picks A.
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
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    // Monitor probes the BLACK-HOLE through A — the probe hangs on recv
    // until probe_timeout, giving a window to migrate A→B mid-probe.
    let mut monitor = FailureMonitor::new();
    monitor.start(
        Arc::clone(&executor),
        endpoint(bh_port),
        FailureMonitorConfig {
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(4),
        },
    );

    // Wait until the probe of A is in flight (per-circuit mutex held).
    let probe_in_flight = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let exec = executor.lock().await;
            if let Some(handle) = exec.active_circuit() {
                if handle.try_lock().is_err() { return true; }
            }
            drop(exec);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    assert!(probe_in_flight.is_ok(), "probe of A should start within 8s");

    // While the probe is in flight, migrate A→B by making B clearly better
    // than A. The route-observation latency is an EWMA (alpha=0.3); to clear
    // the optimizer's 5%-improvement threshold under the default scoring
    // weights (latency is only 25% of the total), we must BOTH lower B's
    // latency EWMA well below A's AND push A's latency EWMA up. We record
    // many samples so each EWMA converges close to its target.
    {
        let mut s = route_obs.write().unwrap();
        // Drive B's latency EWMA down to ~5ms (20 samples of 5.0 starting
        // from 30.0 converges close to 5.0: 5.0 + 0.7^20 * 25.0 ≈ 5.02).
        for _ in 0..20 { s.get_or_create(&hops_b).record_latency(5.0); }
        // Drive A's latency EWMA up to ~100ms (20 samples of 100.0 starting
        // from 20.0 converges close to 100.0).
        for _ in 0..20 { s.get_or_create(&hops_a).record_latency(100.0); }
    }
    tokio::time::sleep(Duration::from_millis(30)).await; // pass cooldown
    let outcome = {
        let mut exec = executor.lock().await;
        exec.attempt_migration(
            &[hops_a.clone(), hops_b.clone()],
            &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
            endpoint(echo_port),
        ).await
    };
    assert!(matches!(outcome, MigrationOutcome::Success { .. }),
        "A→B migration should succeed while the probe is in flight (got {:?})", outcome);

    // B is now active; epoch incremented.
    let active_b_id;
    let epoch_after;
    {
        let exec = executor.lock().await;
        active_b_id = exec.circuit_registry().active_circuit_id()
            .expect("B active after migration");
        epoch_after = exec.epoch();
        assert_eq!(exec.current_route(), Some(hops_b.as_slice()));
    }

    // The monitor's probe of A eventually fails (black-hole timeout) and
    // emits RecoveryRequest{A, route_A, old_epoch}.
    let request = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(r) = monitor.channel().take() { return r; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await;
    let request = request.expect("monitor should emit a request after probing A");

    // The request carries A's provenance — NOT B's.
    assert_ne!(request.circuit_id, active_b_id,
        "request must be for A (the probed circuit), not B (the current active)");
    assert_ne!(request.epoch, epoch_after,
        "request epoch must be stale (pre-migration)");

    // handle_recovery_request must REJECT the stale request (NotNeeded),
    // leaving B active and untouched.
    let outcome = {
        let mut exec = executor.lock().await;
        exec.handle_recovery_request(
            &request,
            &[hops_a.clone(), hops_b.clone()],
            &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
            endpoint(echo_port),
        ).await
    };
    assert!(matches!(outcome, MigrationOutcome::NotNeeded),
        "stale recovery request must be rejected, not acted upon");

    // B is STILL active — not failed, not recovered away.
    {
        let exec = executor.lock().await;
        assert_eq!(exec.current_route(), Some(hops_b.as_slice()),
            "B must remain active after a stale request is rejected");
        assert_eq!(exec.circuit_registry().circuit_state(&active_b_id),
            Some(CircuitState::Active),
            "B must still be in Active state");
    }

    eprintln!("[n2.5-r.5.1] PASS: stale_request_after_migration_rejected");
    monitor.stop();
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// N2.5-R.5.1 Test 4: start() is idempotent (at most one monitor task)
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_is_idempotent() {
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

    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    let mut monitor = FailureMonitor::new();
    let config = FailureMonitorConfig {
        probe_interval: Duration::from_millis(50),
        probe_timeout: Duration::from_secs(10),
    };

    // First start.
    monitor.start(Arc::clone(&executor), endpoint(echo_port), config.clone());
    assert!(monitor.is_running(), "monitor should be running after first start");

    // Second start — must be a no-op (idempotent), NOT spawn a second task.
    monitor.start(Arc::clone(&executor), endpoint(echo_port), config.clone());
    assert!(monitor.is_running(), "monitor should still be running after second start");

    // Stop the monitor. With idempotency, there is exactly one task, so
    // stop() fully halts probing.
    monitor.stop();
    assert!(!monitor.is_running(), "monitor should be stopped");

    // Kill A's relays. If a second (orphaned) task were still running, it
    // would detect the failure and emit a request. With idempotent start(),
    // no request appears.
    mesh.handles[0].abort();
    mesh.handles[2].abort();
    mesh.handles[3].abort();
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert!(!monitor.channel().peek(),
        "no orphaned monitor task should emit a recovery request after stop()");

    eprintln!("[n2.5-r.5.1] PASS: start_is_idempotent");
    drop(mesh.handles);
}

// ════════════════════════════════════════════════════════════════════════════
// N2.5-R.5.1 Test 5: A current (non-stale) request triggers recovery
// ════════════════════════════════════════════════════════════════════════════
//
// The happy path of the monitor→runtime contract:
//   A active → monitor detects failure → RecoveryRequest{A, epoch N} →
//   runtime verifies it still matches ACTIVE → fail A + migrate to B.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_request_triggers_recovery() {
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
    assert_eq!(executor.current_route(), Some(hops_a.as_slice()));

    let executor = Arc::new(tokio::sync::Mutex::new(executor));

    let mut monitor = FailureMonitor::new();
    monitor.start(
        Arc::clone(&executor),
        endpoint(echo_port),
        FailureMonitorConfig {
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(10),
        },
    );

    // Kill A's relays so the probe fails.
    mesh.handles[0].abort();
    mesh.handles[2].abort();
    mesh.handles[3].abort();

    // Wait for the monitor to emit a RecoveryRequest for A.
    let request = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(r) = monitor.channel().take() { return r; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await;
    let request = request.expect("monitor should emit a recovery request");

    // The request is current (A is still the active circuit, epoch unchanged).
    let outcome = {
        let mut exec = executor.lock().await;
        exec.handle_recovery_request(
            &request,
            &[hops_a.clone(), hops_b.clone()],
            &mesh.client_node, &routes, &mesh.client_x_sk, &mesh.client_x_pk,
            endpoint(echo_port),
        ).await
    };
    assert!(matches!(outcome, MigrationOutcome::Success { .. }),
        "current recovery request should trigger successful recovery to B");

    // B is now active.
    {
        let exec = executor.lock().await;
        assert_eq!(exec.current_route(), Some(hops_b.as_slice()),
            "B must be active after recovery");
    }

    // New streams work on B.
    {
        let exec = executor.lock().await;
        let circuit = exec.active_circuit().expect("B active");
        let mut guard = circuit.lock().await;
        let mut stream = guard.open_stream(endpoint(echo_port)).await.unwrap();
        stream.send(b"post-recovery").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let resp = stream.recv().await.unwrap().unwrap();
        assert_eq!(resp, b"post-recovery");
    }

    eprintln!("[n2.5-r.5.1] PASS: current_request_triggers_recovery");
    drop(mesh.handles);
}
