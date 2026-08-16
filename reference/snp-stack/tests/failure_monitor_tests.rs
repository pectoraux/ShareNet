//! **N2.5-R.5 — Failure Detection Integration / Recovery Triggering.**
//!
//! These tests verify that the background failure monitor detects
//! active-circuit failures and signals recovery, and that the runtime
//! can use the signal to trigger automatic recovery.

#![cfg(feature = "circuit-upstream")]
#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use snp_crypto::{derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_stack::network_intelligence::{
    AdaptiveRouteOptimizer, FailureMonitor, FailureMonitorConfig, MigrationExecutor,
    MigrationOutcome, OptimizerConfig, RouteObservationStore, RouteScoringWeights,
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
    assert!(!monitor.signal().peek(), "no failure yet");

    // Kill route A's relays.
    mesh.handles[0].abort(); // gw1
    mesh.handles[2].abort(); // rb1
    mesh.handles[3].abort(); // ra1

    // Wait for the monitor to detect the failure.
    let detected = tokio::time::timeout(
        Duration::from_secs(30),
        async {
            loop {
                if monitor.signal().peek() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        },
    )
    .await;

    assert!(detected.is_ok(), "failure monitor should detect failure within 30s");
    assert!(monitor.signal().should_recover(), "recovery signal should be set");

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

    assert!(!monitor.signal().peek(), "healthy circuit should not trigger recovery signal");
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
    let mut stream = executor.active_circuit().unwrap()
        .open_stream(endpoint(echo_port)).await.unwrap();
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
                if monitor.signal().peek() {
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
// Test 5: Recovery signal can be polled without clearing
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn recovery_signal_peek_and_should_recover() {
    let signal = snp_stack::network_intelligence::RecoverySignal::new();

    assert!(!signal.peek(), "new signal should not need recovery");
    assert!(!signal.should_recover(), "should_recover on new signal returns false");

    // Simulate failure detection.
    // signal_failure is private, but we can test through the public API
    // by checking that should_recover() returns false initially.
    // The actual signal_failure is called by the monitor, tested above.

    // Test that should_recover() clears the flag.
    // Since we can't set the flag directly, we test the clear semantics:
    // should_recover() on a fresh signal returns false (no flag to clear).
    assert!(!signal.should_recover(), "should_recover on fresh signal returns false");
    assert!(!signal.peek(), "peek after should_recover should be false");

    eprintln!("[n2.5-r.5] PASS: recovery_signal_peek_and_should_recover");
}
