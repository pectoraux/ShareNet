//! **N3 SOCKS5 Demo** — Standalone ShareNet mesh + SOCKS5 proxy.
//!
//! Sets up a complete ShareNet mesh (gateway + 2 relays) and an N3-A
//! SOCKS5 proxy in a single process. An echo server simulates an Internet
//! endpoint.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example n3_socks5_demo --features "circuit-upstream test-utils"
//! ```
//!
//! Then connect via SOCKS5:
//! ```bash
//! curl --socks5 127.0.0.1:1080 http://127.0.0.1:8080/
//! ```
//!
//! ## Network isolation test
//!
//! To prove the client has no direct Internet path:
//!
//! ```bash
//! # Start the demo
//! cargo run --example n3_socks5_demo --features "circuit-upstream test-utils" &
//!
//! # In a network namespace with no Internet:
//! unshare -Urn sh -c '
//!   ip link set lo up
//!   # Try direct connection — fails (namespace can't reach host loopback)
//!   curl --connect-timeout 2 http://127.0.0.1:8080/ && echo "DIRECT: OK" || echo "DIRECT: FAIL"
//!   # Try via SOCKS5 — also fails from namespace (can't reach 127.0.0.1 on host)
//!   # Need veth pair for true isolation test — see test script.
//! '
//! ```

#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use snp_crypto::{derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_stack::n3a_client::{N3AClient, N3AClientConfig};
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

async fn start_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
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
    (port, handle)
}

/// Start a simple HTTP server that responds "Hello from ShareNet!" to any GET.
async fn start_http_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                // Read the HTTP request (don't care about content).
                let _ = stream.read(&mut buf).await;
                // Send a simple HTTP response.
                let body = "Hello from ShareNet!\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
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

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    eprintln!("[n3-demo] starting ShareNet mesh + SOCKS5 proxy...");

    // 1. Start HTTP server (simulated Internet endpoint).
    let (http_port, _http) = start_http_server().await;
    eprintln!("[n3-demo] HTTP server (simulated Internet) on port {}", http_port);

    // Also start a raw echo server for non-HTTP tests.
    let (echo_port, _echo) = start_echo_server().await;
    eprintln!("[n3-demo] echo server (raw TCP) on port {}", echo_port);

    // 2. Generate identities.
    let client = NodeIdents::fresh();
    let ra = NodeIdents::fresh();
    let rb = NodeIdents::fresh();
    let gw = NodeIdents::fresh();

    // 3. Start gateway.
    let gw_addr = ephemeral_addr().await;
    let gw_node = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());
    let gw_addr_spawn = gw_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node, &gw_addr_spawn, &gw_x_sk, &gw_x_pk, &st).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 4. Start relay B.
    let rb_addr = ephemeral_addr().await;
    let rb_route = Route::new_with_hop_details(
        ra.node_id, gw.node_id,
        vec![
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    let rb_idents = NodeIdents {
        ed_sk: rb.ed_sk,
        x_sk: Arc::clone(&rb.x_sk),
        x_pk: rb.x_pk,
        node_id: rb.node_id,
    };
    let rb_addr_clone = rb_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(
            &Node::new(rb_idents.identity(), vec![Capability::Relay], rb_addr_clone.clone()),
            &rb_route, 0, &rb_addr_clone, &rb_idents.x_sk, &rb_idents.x_pk,
        ).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // 5. Start relay A.
    let ra_addr = ephemeral_addr().await;
    let ra_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(&ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    let ra_idents = NodeIdents {
        ed_sk: ra.ed_sk,
        x_sk: Arc::clone(&ra.x_sk),
        x_pk: ra.x_pk,
        node_id: ra.node_id,
    };
    let ra_addr_clone = ra_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(
            &Node::new(ra_idents.identity(), vec![Capability::Relay], ra_addr_clone.clone()),
            &ra_route, 0, &ra_addr_clone, &ra_idents.x_sk, &ra_idents.x_pk,
        ).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // 6. Build the route.
    let route = build_route(&client, &ra, &rb, &gw, &ra_addr, &rb_addr, &gw_addr);

    // 7. Start N3-A SOCKS5 client.
    let socks5_addr = "0.0.0.0:1080".to_string();
    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let config = N3AClientConfig {
        listen_addr: socks5_addr.clone(),
        route: route.clone(),
        node: client_node,
        client_x25519_secret: Arc::clone(&client.x_sk),
        client_x25519_public: client.x_pk,
        default_destination: None, // SOCKS5 mode
    };

    eprintln!("[n3-demo] SOCKS5 proxy listening on {}", socks5_addr);
    eprintln!("[n3-demo] HTTP server (Internet endpoint) at 127.0.0.1:{}", http_port);
    eprintln!("[n3-demo] echo server (raw TCP) at 127.0.0.1:{}", echo_port);
    eprintln!();
    // Machine-readable output for test scripts.
    println!("SOCKS5_PORT=1080");
    println!("HTTP_PORT={}", http_port);
    println!("ECHO_PORT={}", echo_port);
    eprintln!();
    eprintln!("  Test with curl:");
    eprintln!("    curl --socks5 127.0.0.1:1080 http://127.0.0.1:{}/", http_port);
    eprintln!();

    let mut n3a_client = N3AClient::create(config).await.expect("N3-A create");

    // Run forever.
    n3a_client.run().await.expect("N3-A run");
}
