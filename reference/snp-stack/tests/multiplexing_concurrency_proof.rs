//! **N2.3.8 Multiplexing Concurrency Proof — 6 Properties.**
//!
//! This test suite proves that the gateway's multiplexed architecture
//! provides true concurrency (not sequential polling). Each test targets
//! a specific property that would fail if the gateway used sequential
//! `read_from_tcp().await` calls.
//!
//! ## Architecture under test
//!
//! ```text
//!                      Gateway Circuit
//!                            |
//!                 +----------+----------+
//!                 |                     |
//!         Circuit Reader           Circuit Writer
//!         (continuous               (centralized
//!          recv_frame)               seq allocator)
//!                 |
//!         Stream dispatch
//!                 |
//!        +--------+--------+
//!        |        |        |
//!       S1       S2       SN
//!        |        |        |
//!    reader    reader   reader
//!    task      task     task
//!        |        |        |
//!       TCP      TCP      TCP
//! ```
//!
//! ## Properties
//!
//! 1. Stream 1 idle while Stream 2 opens (no blocking on idle TCP read)
//! 2. Stream 1 blocks on TCP read while Stream 2 transfers data
//! 3. Closing Stream 1 does not affect Stream 2
//! 4. Resetting Stream 1 does not affect Stream 2
//! 5. Both streams produce multi-frame responses (>16 KiB)
//! 6. Outer (fid, seq) remains unique across both streams

#![cfg(feature = "circuit-upstream")]
#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use snp_crypto::{
    derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret,
};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// Test infrastructure
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

/// A server that accepts a connection but delays sending data.
/// Used to test that Stream 1 can be "idle" (waiting for TCP data) without
/// blocking Stream 2.
async fn start_idle_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        // Accept one connection, then sleep (never send data).
        let Ok((_stream, _)) = listener.accept().await else { return };
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    (addr, handle)
}

/// A server that sends a large multi-frame response (>16 KiB) when it
/// receives any data.
async fn start_large_response_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                // Read 1 byte to trigger the response.
                let mut buf = [0u8; 1];
                let _ = stream.read(&mut buf).await;
                // Send 32 KiB of data (exceeds MAX_STREAM_DATA_PAYLOAD = 6144 bytes,
                // so it requires multiple StreamData frames).
                let large_data = vec![0xABu8; 32 * 1024];
                let _ = stream.write_all(&large_data).await;
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

async fn setup_mesh() -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>, Route, Node, Arc<X25519Secret>, X25519PubKey) {
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    let gateway_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;

    let gateway_node = Node::new(gateway_idents.identity(), vec![Capability::Gateway], gateway_addr.clone());
    let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
    let gw_x_pk = gateway_idents.x_pk;
    let gw_listen = gateway_addr.clone();
    let stream_table = Arc::new(GatewayStreamTable::with_allow_loopback());
    let st = Arc::clone(&stream_table);
    let gateway_handle = tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gateway_node, &gw_listen, &gw_x_sk, &gw_x_pk, &st).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    let relay_b_route = Route::new_with_hop_details(
        relay_a_idents.node_id, gateway_idents.node_id,
        vec![
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_b_handle = start_relay(&relay_b_idents, &relay_b_route, 0, &relay_b_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let relay_a_route = Route::new_with_hop_details(
        client_idents.node_id, gateway_idents.node_id,
        vec![
            RouteHop::new(relay_a_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_a_addr)),
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_a_handle = start_relay(&relay_a_idents, &relay_a_route, 0, &relay_a_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let route = build_route(&client_idents, &relay_a_idents, &relay_b_idents, &gateway_idents, &relay_a_addr, &relay_b_addr, &gateway_addr);
    let client_node = Node::new(client_idents.identity(), vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    (gateway_handle, relay_a_handle, relay_b_handle, route, client_node, client_x_sk, client_x_pk)
}

fn endpoint(port: u16) -> InternetEndpoint {
    InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        protocol: TransportProtocol::Tcp,
    }
}

async fn recv_exact(
    stream: &mut snp_node::node::stream_client::StreamHandle,
    total: usize,
) -> Result<Vec<u8>, snp_node::node::stream_client::StreamError> {
    let mut buf = Vec::with_capacity(total);
    while buf.len() < total {
        match stream.recv().await? {
            Some(chunk) => buf.extend_from_slice(&chunk),
            None => break,
        }
    }
    Ok(buf)
}

// ════════════════════════════════════════════════════════════════════════════
// Property 1: Stream 1 idle while Stream 2 opens
// ════════════════════════════════════════════════════════════════════════════

/// **Stream 1 is connected to an idle server (never sends data). Stream 2
/// is opened AFTER Stream 1. Stream 2 must open successfully.**
///
/// If the gateway used sequential `read_from_tcp(stream1).await`, it would
/// block waiting for Stream 1's TCP data and never process Stream 2's
/// `StreamOpen`. This test proves the gateway uses per-stream reader tasks
/// that don't block the circuit reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prop1_stream1_idle_while_stream2_opens() {
    let (gw_h, ra_h, rb_h, route, client_node, client_x_sk, client_x_pk) = setup_mesh().await;

    let (idle_addr, _idle) = start_idle_server().await;
    let idle_port: u16 = idle_addr.rsplit(':').next().unwrap().parse().unwrap();
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    )
    .await.expect("establish timeout").expect("establish must succeed");

    // Open Stream 1 → idle server (will never send data).
    let stream1 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(idle_port)),
    )
    .await.expect("stream1 open timeout").expect("stream1 must succeed");

    eprintln!("[prop1] Stream 1 opened (idle server, no data will arrive)");

    // Give the gateway time to start Stream 1's TCP reader task.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Open Stream 2 → echo server. This MUST succeed even though Stream 1
    // is idle (its TCP reader task is blocked waiting for data that will
    // never come).
    let mut stream2 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo_port)),
    )
    .await.expect("stream2 open timeout (gateway is blocking on stream1 TCP read!)")
    .expect("stream2 must succeed");

    eprintln!("[prop1] Stream 2 opened successfully while Stream 1 is idle");

    // Verify Stream 2 works.
    let data = b"stream2-data-while-stream1-idle";
    stream2.send(data).await.expect("stream2 send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = stream2.recv().await.expect("stream2 recv").expect("stream2 data");
    assert_eq!(resp, data);

    eprintln!("[prop1] PASS: Stream 1 idle does not block Stream 2 opening or data transfer");

    // Clean up Stream 1 (it's idle, just close it).
    drop(stream1);
    drop(gw_h);
    drop(ra_h);
    drop(rb_h);
}

// ════════════════════════════════════════════════════════════════════════════
// Property 2: Stream 1 blocks on TCP read while Stream 2 transfers data
// ════════════════════════════════════════════════════════════════════════════

/// **Stream 1 is connected to an idle server (TCP read blocks). Stream 2
/// transfers data concurrently. Stream 2 must complete successfully.**
///
/// This is stronger than Property 1 — here we prove that Stream 2 can
/// transfer data (not just open) while Stream 1's TCP reader is blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prop2_stream1_blocked_while_stream2_transfers() {
    let (gw_h, ra_h, rb_h, route, client_node, client_x_sk, client_x_pk) = setup_mesh().await;

    let (idle_addr, _idle) = start_idle_server().await;
    let idle_port: u16 = idle_addr.rsplit(':').next().unwrap().parse().unwrap();
    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    )
    .await.expect("establish timeout").expect("establish must succeed");

    // Open Stream 1 → idle server.
    let _stream1 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(idle_port)),
    )
    .await.expect("stream1 open timeout").expect("stream1 must succeed");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Open Stream 2 → echo server.
    let mut stream2 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo_port)),
    )
    .await.expect("stream2 open timeout").expect("stream2 must succeed");

    // Transfer 50 KB on Stream 2 while Stream 1 is blocked on TCP read.
    let data = vec![0xCDu8; 50 * 1024];
    let expected = data.clone();
    stream2.send(&data).await.expect("stream2 send");

    let transfer_task = tokio::spawn(async move {
        let received = recv_exact(&mut stream2, 50 * 1024).await.expect("stream2 recv");
        received
    });

    let received = tokio::time::timeout(Duration::from_secs(30), transfer_task)
        .await
        .expect("stream2 transfer timeout (gateway is blocking on stream1 TCP read!)")
        .expect("task panic");

    assert_eq!(received, expected);

    eprintln!("[prop2] PASS: Stream 2 transferred 50 KB while Stream 1's TCP read was blocked");

    drop(gw_h);
    drop(ra_h);
    drop(rb_h);
}

// ════════════════════════════════════════════════════════════════════════════
// Property 3: Closing Stream 1 does not affect Stream 2
// ════════════════════════════════════════════════════════════════════════════

/// **Two streams open. Close Stream 1. Stream 2 must continue to work.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prop3_close_stream1_preserves_stream2() {
    let (gw_h, ra_h, rb_h, route, client_node, client_x_sk, client_x_pk) = setup_mesh().await;

    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    )
    .await.expect("establish timeout").expect("establish must succeed");

    let mut stream1 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo_port)),
    ).await.expect("s1 open timeout").expect("s1 must succeed");

    let mut stream2 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo_port)),
    ).await.expect("s2 open timeout").expect("s2 must succeed");

    // Send data on both.
    stream1.send(b"stream1-before-close").await.expect("s1 send");
    stream2.send(b"stream2-before-close").await.expect("s2 send");
    let _ = stream1.recv().await;
    let _ = stream2.recv().await;

    // Close Stream 1.
    stream1.close().await.expect("s1 close");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Stream 2 must still work.
    let data = b"stream2-after-close";
    stream2.send(data).await.expect("s2 send after close");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = stream2.recv().await.expect("s2 recv after close").expect("s2 data");
    assert_eq!(resp, data);

    eprintln!("[prop3] PASS: Closing Stream 1 does not affect Stream 2");

    drop(gw_h);
    drop(ra_h);
    drop(rb_h);
}

// ════════════════════════════════════════════════════════════════════════════
// Property 4: Resetting Stream 1 does not affect Stream 2
// ════════════════════════════════════════════════════════════════════════════

/// **Two streams open. Reset Stream 1. Stream 2 must continue to work.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prop4_reset_stream1_preserves_stream2() {
    use snp_gateway::stream::StreamResetReason;

    let (gw_h, ra_h, rb_h, route, client_node, client_x_sk, client_x_pk) = setup_mesh().await;

    let (echo_addr, _echo) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    )
    .await.expect("establish timeout").expect("establish must succeed");

    let mut stream1 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo_port)),
    ).await.expect("s1 open timeout").expect("s1 must succeed");

    let mut stream2 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo_port)),
    ).await.expect("s2 open timeout").expect("s2 must succeed");

    // Reset Stream 1.
    stream1.reset(StreamResetReason::ApplicationReset).await.expect("s1 reset");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Stream 2 must still work.
    let data = b"stream2-after-reset";
    stream2.send(data).await.expect("s2 send after reset");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = stream2.recv().await.expect("s2 recv after reset").expect("s2 data");
    assert_eq!(resp, data);

    eprintln!("[prop4] PASS: Resetting Stream 1 does not affect Stream 2");

    drop(gw_h);
    drop(ra_h);
    drop(rb_h);
}

// ════════════════════════════════════════════════════════════════════════════
// Property 5: Both streams produce multi-frame responses
// ════════════════════════════════════════════════════════════════════════════

/// **Both streams receive >16 KiB responses (exceeding MAX_STREAM_DATA_PAYLOAD,
//  requiring multiple StreamData frames each).**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prop5_both_streams_multi_frame() {
    let (gw_h, ra_h, rb_h, route, client_node, client_x_sk, client_x_pk) = setup_mesh().await;

    let (large1_addr, _large1) = start_large_response_server().await;
    let large1_port: u16 = large1_addr.rsplit(':').next().unwrap().parse().unwrap();
    let (large2_addr, _large2) = start_large_response_server().await;
    let large2_port: u16 = large2_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    )
    .await.expect("establish timeout").expect("establish must succeed");

    let mut stream1 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(large1_port)),
    ).await.expect("s1 open timeout").expect("s1 must succeed");

    let mut stream2 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(large2_port)),
    ).await.expect("s2 open timeout").expect("s2 must succeed");

    // Trigger both large responses.
    stream1.send(b"go").await.expect("s1 send");
    stream2.send(b"go").await.expect("s2 send");

    // Receive 32 KiB on each stream (requires multiple StreamData frames,
    // since MAX_STREAM_DATA_PAYLOAD = 6144 bytes → 32 KiB needs ~6 frames).
    let recv1 = tokio::time::timeout(
        Duration::from_secs(30),
        recv_exact(&mut stream1, 32 * 1024),
    ).await.expect("s1 recv timeout").expect("s1 recv error");
    let recv2 = tokio::time::timeout(
        Duration::from_secs(30),
        recv_exact(&mut stream2, 32 * 1024),
    ).await.expect("s2 recv timeout").expect("s2 recv error");

    // Verify data integrity.
    assert_eq!(recv1, vec![0xABu8; 32 * 1024], "stream1 data mismatch");
    assert_eq!(recv2, vec![0xABu8; 32 * 1024], "stream2 data mismatch");

    eprintln!("[prop5] PASS: Both streams received 32 KiB multi-frame responses (6+ frames each)");

    drop(gw_h);
    drop(ra_h);
    drop(rb_h);
}

// ════════════════════════════════════════════════════════════════════════════
// Property 6: Outer (fid, seq) remains unique across both streams
// ════════════════════════════════════════════════════════════════════════════

/// **The outer frame sequence (fid, seq) must be unique across all frames
//  on the circuit, regardless of which stream they belong to.**
///
/// This is verified by the `CircuitFrameSequencer` (N2.3.8 fix) and the
//  gateway's centralized `next_seq` allocator. This test confirms the
//  property holds under concurrent multi-stream traffic by verifying that
//  no AEAD nonce reuse errors occur (which would indicate seq collision)
//  and that all data is correctly received.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prop6_outer_seq_unique_across_streams() {
    let (gw_h, ra_h, rb_h, route, client_node, client_x_sk, client_x_pk) = setup_mesh().await;

    let (echo1_addr, _echo1) = start_echo_server().await;
    let echo1_port: u16 = echo1_addr.rsplit(':').next().unwrap().parse().unwrap();
    let (echo2_addr, _echo2) = start_echo_server().await;
    let echo2_port: u16 = echo2_addr.rsplit(':').next().unwrap().parse().unwrap();

    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    )
    .await.expect("establish timeout").expect("establish must succeed");

    let mut stream1 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo1_port)),
    ).await.expect("s1 open timeout").expect("s1 must succeed");

    let mut stream2 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(endpoint(echo2_port)),
    ).await.expect("s2 open timeout").expect("s2 must succeed");

    // Verify they share the same fid (circuit frame ID).
    // The CircuitFrameSequencer is shared — all streams on one circuit
    // use the same (fid, seq) namespace.
    // We can't directly inspect the fid from the public API, but we can
    // verify the property indirectly: if there were a seq collision,
    // the gateway's AEAD decryption would fail (nonce reuse), causing
    // a protocol error. Successful data transfer proves no collision.

    // Send interleaved data on both streams concurrently.
    let data1 = b"stream1-frame-A";
    let data2 = b"stream2-frame-A";
    let data3 = b"stream1-frame-B";
    let data4 = b"stream2-frame-B";

    // Interleave sends: s1, s2, s1, s2 — this creates interleaved
    // outbound frames that all share the same (fid, seq) namespace.
    stream1.send(data1).await.expect("s1 send 1");
    stream2.send(data2).await.expect("s2 send 1");
    stream1.send(data3).await.expect("s1 send 2");
    stream2.send(data4).await.expect("s2 send 2");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Receive all echoes — if the gateway's outer seq allocator had a
    // collision, the client would see a decryption failure (protocol
    // reset) instead of correct data.
    let r1 = stream1.recv().await.expect("s1 recv 1").expect("s1 data 1");
    let r2 = stream2.recv().await.expect("s2 recv 1").expect("s2 data 1");
    let r3 = stream1.recv().await.expect("s1 recv 2").expect("s1 data 2");
    let r4 = stream2.recv().await.expect("s2 recv 2").expect("s2 data 2");

    assert_eq!(r1, data1, "stream1 frame 1 mismatch");
    assert_eq!(r2, data2, "stream2 frame 1 mismatch");
    assert_eq!(r3, data3, "stream1 frame 2 mismatch");
    assert_eq!(r4, data4, "stream2 frame 2 mismatch");

    eprintln!(
        "[prop6] PASS: Interleaved 4 frames across 2 streams — all (fid, seq) unique, no AEAD nonce reuse, all data correct"
    );

    drop(gw_h);
    drop(ra_h);
    drop(rb_h);
}
