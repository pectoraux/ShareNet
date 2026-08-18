//! **N3-B TUN Demo — Production Composition Root for Transparent TUN Networking.**
//!
//! This binary is the PRODUCTION composition root for transparent TUN
//! networking on Linux. It starts a real ShareNet mesh (gateway + 2 relays)
//! using the production async runtime and wires a real `TunClient` to a real
//! kernel TUN interface.
//!
//! ## This is NOT SOCKS5
//!
//! Unlike `n3_socks5_demo` (which uses `N3AClient` + SOCKS5), this binary
//! uses `TunClient` — a real TUN device that intercepts OS TCP SYNs at the
//! IP layer. Ordinary OS applications (curl, browsers, SSH, etc.) route
//! through the TUN interface *without any SOCKS5 configuration* — the kernel
//! TCP/IP stack hands SYNs directly to the TUN, and `TunClient` extracts
//! the original destination from each SYN's 5-tuple.
//!
//! ## Architecture
//!
//! ```text
//! ordinary OS application (curl)
//!     ↓ kernel TCP/IP stack
//! TUN interface (snp0, 10.0.0.1/24, default route)
//!     ↓ read_packet()
//! TunClient (intercepts SYN, extracts destination, opens ShareNet stream)
//!     ↓ MultiplexedCircuit::open_stream()
//! ShareNet circuit (authenticated SNP-IK + X25519)
//!     ↓
//! Relay A → Relay B
//!     ↓
//! Gateway (serve_gateway_mode_b_multiplexed)
//!     ↓ real TCP socket
//! external Internet
//! ```
//!
//! ## Production-grade components
//!
//! - `async_node::serve_gateway_mode_b_multiplexed` — real Mode B gateway
//!   that opens real outbound TCP sockets to the destination extracted
//!   from each SYN.
//! - `async_node::serve_relay_via_route` — real relay forwarding (two
//!   relays: client → relay A → relay B → gateway).
//! - `MultiplexedCircuit::establish` — real SNP-IK + X25519 circuit DH.
//! - `TunClient` — real transparent TUN device + smoltcp stack with
//!   `any_ip` enabled (accepts SYNs for any destination IP).
//!
//! ## Test-only deviations (DOCUMENTED)
//!
//! This binary is built with `--features "circuit-upstream test-utils"`.
//! The `test-utils` feature is REQUIRED because the gateway uses
//! `GatewayStreamTable::with_allow_loopback()` — this disables the
//! production SSRF defence that blocks loopback/private addresses.
//!
//! **Why this is needed here:** the simulated Internet endpoint (the HTTP
//! server started inside this binary) listens on `0.0.0.0`, which means it
//! is reachable on `127.0.0.1`. To prove the end-to-end TUN path WITHOUT
//! requiring a real external Internet host, we let the gateway dial back
//! to loopback. **This is the ONLY test-only deviation.** When the
//! production CLI is wired (N3B-PROD-CLI), the production gateway will use
//! `GatewayStreamTable::new()` (allow_loopback=false) and only dial real
//! routable Internet addresses.
//!
//! ## Usage
//!
//! ```bash
//! # Build (requires Linux + the circuit-upstream + test-utils features)
//! cargo build --example n3b_tun_demo -p snp-stack \
//!     --features "circuit-upstream test-utils"
//!
//! # Run (REQUIRES root / CAP_NET_ADMIN to create the TUN device + install
//! # the default route). The binary prints the TUN interface name and the
//! # HTTP server port for the acceptance test harness.
//! sudo ./target/debug/examples/n3b_tun_demo
//!
//! # Optional CLI flags:
//! sudo ./target/debug/examples/n3b_tun_demo --tun-name tun9 --tun-ip 10.0.0.1
//! ```
//!
//! Once running, from the SAME host (or from a network namespace whose
//! default route points at the TUN), an ordinary application transparently
//! flows through ShareNet:
//!
//! ```bash
//! # The HTTP server prints "Hello from ShareNet (N3-B TUN)!" on any GET.
//! curl http://127.0.0.1:<HTTP_PORT>/
//! # Or, transparently — kernel routes the SYN through snp0:
//! curl http://<any-address>:<any-port>/
//! ```
//!
//! Press Ctrl+C to shut down — the binary cleans up the OS routes it
//! installed.

#![cfg(feature = "circuit-upstream")]
#![cfg(target_os = "linux")]

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
use snp_stack::tun_client::{TunClient, TunClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// CLI configuration parsed from command-line flags.
struct CliConfig {
    /// The TUN interface name (default "snp0"). Max 15 chars. If empty,
    /// the kernel auto-assigns (e.g. "tun0").
    tun_name: String,
    /// The virtual IP address assigned to the TUN interface (default 10.0.0.1).
    tun_ip: Ipv4Addr,
}

/// Parse command-line flags. Unknown flags are rejected.
fn parse_args() -> Result<CliConfig, String> {
    let mut tun_name = "snp0".to_string();
    let mut tun_ip: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--tun-name" => {
                let Some(v) = iter.next() else {
                    return Err(format!("{} requires a value", arg));
                };
                if v.len() > 15 {
                    return Err(format!("--tun-name '{}' exceeds 15 chars (kernel limit)", v));
                }
                tun_name = v;
            }
            "--tun-ip" => {
                let Some(v) = iter.next() else {
                    return Err(format!("{} requires a value", arg));
                };
                tun_ip = v
                    .parse::<Ipv4Addr>()
                    .map_err(|e| format!("--tun-ip '{}' invalid: {}", v, e))?;
            }
            "--help" | "-h" => {
                println!("n3b_tun_demo — Production N3-B TUN composition root\n");
                println!("Usage: n3b_tun_demo [--tun-name <NAME>] [--tun-ip <IPv4>]\n");
                println!("Options:");
                println!("  --tun-name <NAME>   TUN interface name (default: snp0, max 15 chars)");
                println!("  --tun-ip <IPv4>     TUN interface IP (default: 10.0.0.1)");
                println!("  -h, --help          Print this help and exit");
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {} (try --help)", other));
            }
        }
    }

    Ok(CliConfig { tun_name, tun_ip })
}

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

/// Start a simple HTTP server on `0.0.0.0:0` (NOT 127.0.0.1).
///
/// **Why 0.0.0.0:** the gateway (which dials the destination extracted
/// from each SYN) is a separate async task. It needs to reach the HTTP
/// server via a real IP address that is NOT the TUN's own IP. Binding to
/// `0.0.0.0` makes the HTTP server reachable on all of the host's IPs
/// (including 127.0.0.1 — which the `with_allow_loopback()` test-utils
/// gateway permits).
///
/// Responds "Hello from ShareNet (N3-B TUN)!" to any GET. This is the
/// simulated Internet endpoint for the acceptance test harness.
async fn start_http_server() -> (u16, tokio::task::JoinHandle<()>) {
    // CRITICAL: bind to 0.0.0.0, NOT 127.0.0.1 — the gateway needs to
    // reach it via a real IP.
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                // Read the HTTP request (don't care about content).
                let _ = stream.read(&mut buf).await;
                // Send a simple HTTP response.
                let body = "Hello from ShareNet (N3-B TUN)!\n";
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

/// Build an `InternetEndpoint` at 127.0.0.1:`port` (Tcp).
///
/// Used for the `health_endpoint` field of `TunClientConfig`. NOTE: in
/// the current `TunClient` implementation, `health_endpoint` is NOT used
/// to determine the destination — the destination is extracted from each
/// SYN's 5-tuple. It is retained only for a future optional health-check
/// on startup.
fn endpoint(port: u16) -> InternetEndpoint {
    InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        protocol: TransportProtocol::Tcp,
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // ---- 0. Parse CLI flags ----
    let cli = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[n3b-tun] argument error: {}", e);
            eprintln!("[n3b-tun] try --help for usage");
            std::process::exit(2);
        }
    };

    eprintln!("[n3b-tun] starting production TUN composition root...");
    eprintln!("[n3b-tun] tun_name='{}' tun_ip={}", cli.tun_name, cli.tun_ip);

    // ---- 1. Start the simulated Internet HTTP server on 0.0.0.0:0 ----
    let (http_port, _http) = start_http_server().await;
    eprintln!(
        "[n3b-tun] HTTP server (simulated Internet) listening on 0.0.0.0:{}",
        http_port
    );

    // ---- 2. Generate fresh identities for the mesh ----
    let client = NodeIdents::fresh();
    let ra = NodeIdents::fresh();
    let rb = NodeIdents::fresh();
    let gw = NodeIdents::fresh();

    // ---- 3. Start the gateway (real Mode B, multiplexed) ----
    let gw_addr = ephemeral_addr().await;
    let gw_node = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;

    // TEST-ONLY DEVIATION: `with_allow_loopback()` is gated behind the
    // `test-utils` feature. It disables the production SSRF defence that
    // blocks loopback/private addresses. This is REQUIRED for the demo
    // because the HTTP server is on 0.0.0.0 (reachable via 127.0.0.1).
    // Production deployments MUST use `GatewayStreamTable::new()`.
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());
    let gw_addr_spawn = gw_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(
            &gw_node, &gw_addr_spawn, &gw_x_sk, &gw_x_pk, &st,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    // ---- 4. Start relay B ----
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

    // ---- 5. Start relay A ----
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

    // ---- 6. Build the production route: client → A → B → gateway ----
    let route = build_route(&client, &ra, &rb, &gw, &ra_addr, &rb_addr, &gw_addr);

    // ---- 7. Construct the TunClient ----
    let client_node = Node::new(
        client.identity(),
        vec![Capability::Client],
        String::new(),
    );

    // `health_endpoint` is NOT used for destination in the current TunClient
    // (destination is extracted from each SYN's 5-tuple). It is retained for
    // a future optional startup health-check; we point it at the HTTP server
    // for semantic clarity.
    let config = TunClientConfig {
        tun_name: cli.tun_name.clone(),
        tun_ip: cli.tun_ip,
        mtu: 1500,
        route: route.clone(),
        node: client_node,
        client_x25519_secret: Arc::clone(&client.x_sk),
        client_x25519_public: client.x_pk,
        health_endpoint: endpoint(http_port),
    };

    eprintln!("[n3b-tun] creating TUN device + establishing ShareNet circuit...");
    let mut tun_client = match TunClient::create(config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[n3b-tun] TunClient::create failed: {}", e);
            std::process::exit(1);
        }
    };

    let actual_tun_name = tun_client.tun_name().to_string();
    eprintln!(
        "[n3b-tun] TUN device '{}' created (requested name='{}', ip={})",
        actual_tun_name, cli.tun_name, cli.tun_ip
    );

    // ---- 8. Configure OS routes (assign TUN IP + install default route) ----
    // REQUIRES root / CAP_NET_ADMIN.
    if let Err(e) = tun_client.configure_os_routes() {
        eprintln!("[n3b-tun] OS route config failed: {}", e);
        eprintln!("[n3b-tun] (this requires root or CAP_NET_ADMIN)");
        // Best-effort cleanup before exit.
        let _ = tun_client.cleanup_os_routes();
        std::process::exit(1);
    }
    eprintln!(
        "[n3b-tun] OS routes installed: {} assigned {}, default route via {}",
        actual_tun_name, cli.tun_ip, actual_tun_name
    );

    // ---- 9. Print machine-readable output for the acceptance test harness ----
    println!("TUN_NAME={}", actual_tun_name);
    println!("TUN_IP={}", cli.tun_ip);
    println!("HTTP_PORT={}", http_port);
    println!("GATEWAY_ADDR={}", gw_addr);
    println!("RELAY_A_ADDR={}", ra_addr);
    println!("RELAY_B_ADDR={}", rb_addr);

    eprintln!();
    eprintln!("  ════════════════════════════════════════════════════════════");
    eprintln!("  N3-B TUN composition root is READY");
    eprintln!("    TUN interface : {} ({})", actual_tun_name, cli.tun_ip);
    eprintln!("    HTTP server   : 0.0.0.0:{} (simulated Internet)", http_port);
    eprintln!("    Mesh          : client → A({}) → B({}) → gateway({})",
        ra_addr, rb_addr, gw_addr);
    eprintln!("  ════════════════════════════════════════════════════════════");
    eprintln!();
    eprintln!("  Test with curl (kernel routes SYN through TUN):");
    eprintln!("    curl http://127.0.0.1:{}/", http_port);
    eprintln!();
    eprintln!("  Press Ctrl+C to shut down (OS routes will be cleaned up).");
    eprintln!();

    // ---- 10. Run the TUN packet pump, with Ctrl+C graceful shutdown ----
    //
    // `tun_client.run()` borrows `tun_client` mutably for the duration of
    // the future. `tokio::select!` drops that future when Ctrl+C arrives,
    // releasing the borrow so we can call `cleanup_os_routes()` below.
    tokio::select! {
        res = tun_client.run() => {
            // The TUN pump exited on its own (TUN device closed or fatal error).
            eprintln!();
            eprintln!("[n3b-tun] TUN client exited: {:?}", res);
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!();
            eprintln!("[n3b-tun] Ctrl+C received — shutting down");
        }
    }

    // ---- 11. Cleanup: remove the OS routes we installed ----
    // Best-effort — if this fails (e.g. partial setup), we still exit.
    eprintln!("[n3b-tun] cleaning up OS routes...");
    match tun_client.cleanup_os_routes() {
        Ok(()) => eprintln!("[n3b-tun] OS routes cleaned up"),
        Err(e) => eprintln!("[n3b-tun] OS route cleanup error (non-fatal): {}", e),
    }

    eprintln!("[n3b-tun] shutdown complete");
}
