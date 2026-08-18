//! **N3-B TUN Demo — Production transparent TCP via real TUN + ShareNet.**
//!
//! This binary is the PRODUCTION composition root for N3-B transparent TUN
//! networking. It supports TWO subcommands:
//!
//! - `n3b_tun_demo mesh` — starts the ShareNet mesh (gateway + 2 relays)
//!   with **production SSRF defence** (`GatewayStreamTable::new()`, NO
//!   loopback exception). Binds to a configurable IP (NOT 127.0.0.1).
//!   Does NOT start a TUN device or an HTTP server.
//!
//! - `n3b_tun_demo tun` — starts a TunClient that connects to the mesh
//!   started by `mesh`. Creates a real TUN device, configures split-tunnel
//!   OS routes, and runs the packet pump. Ordinary `curl` routes through
//!   the TUN → ShareNet → gateway → real Internet.
//!
//! ## Architecture
//!
//! ```text
//! ordinary curl
//!     ↓ OS kernel TCP/IP stack
//! TUN interface (snp0, 10.0.0.1/24, default route)
//!     ↓ read_packet()
//! TunClient (intercepts SYN, extracts destination, opens ShareNet stream)
//!     ↓ MultiplexedCircuit::open_stream()
//! ShareNet circuit (authenticated SNP-IK + X25519)
//!     ↓
//! Relay A → Relay B
//!     ↓
//! Gateway (serve_gateway_mode_b_multiplexed, GatewayStreamTable::new)
//!     ↓ real TCP socket (production SSRF defence — NO loopback exception)
//! external Internet (separately-started HTTP server or real Internet host)
//! ```
//!
//! ## What this is NOT
//!
//! - NOT SOCKS5 (no N3AClient, no SOCKS5 listener, no `curl --socks5`).
//! - NOT a test composition (no `with_allow_loopback()`, no same-process HTTP server).
//! - NOT legacy code (uses the production async runtime).
//!
//! ## Usage
//!
//! ```bash
//! # Build (requires Linux + circuit-upstream)
//! cargo build --example n3b_tun_demo -p snp-stack --features circuit-upstream
//!
//! # 1. Start the mesh in the HOST namespace (has Internet access):
//! ./target/debug/examples/n3b_tun_demo mesh \
//!     --bind-ip 10.0.1.1 \
//!     --gateway-port 7003 --relay-a-port 7002 --relay-b-port 7001
//!
//! # 2. Start the TUN client in the CLIENT namespace (no direct Internet):
//! ip netns exec snp_n3b ./target/debug/examples/n3b_tun_demo tun \
//!     --config /tmp/sharenet-mesh-config.json \
//!     --tun-name snp0 --tun-ip 10.0.0.1 \
//!     --physical-interface veth_client
//! ```

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

// ════════════════════════════════════════════════════════════════════════════
// Identity + helpers (shared by both subcommands)
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
    fn gateway_descriptor(&self, advert_addr: &str, circuit_addr: &str) -> VerifiedNodeDescriptor {
        let advert = GatewayAdvertisement::for_identity_with_circuit_key(
            &self.identity(), self.x_pk.to_bytes(), advert_addr, circuit_addr,
        );
        advert.verify_into_verified().expect("verify").descriptor().expect("descriptor")
    }
    fn relay_descriptor(&self) -> VerifiedNodeDescriptor {
        self.gateway_descriptor("0.0.0.0:0", "0.0.0.0:0")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_hex32(s: &str, name: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("{} must be 64 hex chars, got {}", name, s.len()));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk).map_err(|e| format!("{}: invalid utf8: {}", name, e))?;
        bytes[i] = u8::from_str_radix(hex_str, 16).map_err(|e| format!("{}: invalid hex: {}", name, e))?;
    }
    Ok(bytes)
}

/// Serialized mesh configuration (written by `mesh`, read by `tun`).
///
/// ## Security invariant (N3-B blocker fix)
///
/// This config contains **ONLY public/signed information**:
/// - SIGNED `GatewayAdvertisement` CBOR bytes (hex-encoded) for each hop.
///   These contain the node's Ed25519 PUBLIC key, X25519 PUBLIC key,
///   endpoints, and a signature made with the node's Ed25519 PRIVATE key.
/// - The TUN client verifies the signatures using the embedded PUBLIC keys.
///
/// It contains **NO private keys** of any kind. The TUN client must NEVER
/// possess the relay or gateway private keys. The client generates its OWN
/// identity (Ed25519 + X25519) independently — the mesh does not generate or
/// transfer client credentials.
///
/// ## Configuration ownership
///
/// ```text
/// Who generates client identity?     → The TUN client process (run_tun).
/// Who stores client private key?    → The TUN client process.
/// Who generates relay identities?    → The mesh process (run_mesh).
/// Who stores relay private keys?     → The mesh process (never exported).
/// Who generates gateway identity?    → The mesh process (run_mesh).
/// Who stores gateway private key?    → The mesh process (never exported).
/// Who distributes signed route data? → The mesh process (writes this config).
/// ```
#[derive(serde::Serialize, serde::Deserialize)]
struct MeshConfig {
    /// Relay A's signed GatewayAdvertisement (CBOR bytes, hex-encoded).
    /// Contains relay A's PUBLIC Ed25519 key, X25519 public key, node_id,
    /// and signature. The TUN client verifies the signature using the
    /// embedded public key — NO private key needed.
    relay_a_advert_cbor_hex: String,
    /// Relay B's signed GatewayAdvertisement (CBOR bytes, hex-encoded).
    relay_b_advert_cbor_hex: String,
    /// The gateway's signed GatewayAdvertisement (CBOR bytes, hex-encoded).
    /// Contains the gateway's PUBLIC Ed25519 key, X25519 circuit public key,
    /// node_id, and signature.
    gateway_advert_cbor_hex: String,
    /// Relay A's TCP listen address (for the RouteHop endpoint).
    relay_a_addr: String,
    /// Relay B's TCP listen address.
    relay_b_addr: String,
    /// The gateway's TCP listen address.
    gateway_addr: String,
}

/// Decode a hex-encoded CBOR GatewayAdvertisement, verify its signature
/// using the embedded PUBLIC key, and return the VerifiedNodeDescriptor.
///
/// This function does NOT need any private key. The signature was made by
/// the mesh process with the node's private key; we verify it here using
/// only the public key embedded in the advertisement.
fn verify_advert_to_descriptor(advert_cbor_hex: &str, name: &str) -> Result<VerifiedNodeDescriptor, String> {
    let cbor_bytes = hex_decode(advert_cbor_hex, name)?;
    let advert = GatewayAdvertisement::decode_cbor(&cbor_bytes)
        .map_err(|e| format!("decode {} advert: {:?}", name, e))?;
    let verified = advert.verify_into_verified()
        .ok_or_else(|| format!("verify {} advert: signature invalid", name))?;
    let descriptor = verified.descriptor()
        .ok_or_else(|| format!("extract {} descriptor: no circuit key", name))?;
    eprintln!("[n3b-tun] verified {} advert: node_id={} (signature valid, no private key used)",
        name, hex(&descriptor.node_id()));
    Ok(descriptor)
}

/// Decode a hex string into bytes.
fn hex_decode(hex_str: &str, name: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err(format!("{} hex length {} is odd", name, hex_str.len()));
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i+2], 16)
                .map_err(|e| format!("{} hex byte at offset {}: {}", name, i, e))
        })
        .collect()
}

/// Build the Route from the verified public descriptors + the client's node_id.
///
/// The client generates its OWN identity — this function only uses the
/// client's node_id (a PUBLIC value) and the verified descriptors from
/// the mesh config. NO private keys are needed.
fn build_route_from_config(cfg: &MeshConfig, client_node_id: [u8; 32]) -> Result<Route, String> {
    // Verify each advert using ONLY the embedded public keys.
    let ra_descriptor = verify_advert_to_descriptor(&cfg.relay_a_advert_cbor_hex, "relay A")?;
    let rb_descriptor = verify_advert_to_descriptor(&cfg.relay_b_advert_cbor_hex, "relay B")?;
    let gw_descriptor = verify_advert_to_descriptor(&cfg.gateway_advert_cbor_hex, "gateway")?;
    let gw_node_id = gw_descriptor.node_id();

    let mut route = Route::new_with_hop_details(
        client_node_id, gw_node_id,
        vec![
            RouteHop::new(ra_descriptor, TransportEndpoint::tcp(&cfg.relay_a_addr)),
            RouteHop::new(rb_descriptor, TransportEndpoint::tcp(&cfg.relay_b_addr)),
            RouteHop::new(gw_descriptor, TransportEndpoint::tcp(&cfg.gateway_addr)),
        ],
    );
    route.validate().expect("route valid");
    route.transition(RouteState::Establishing).expect("Establishing");
    route.transition(RouteState::Active).expect("Active");
    eprintln!("[n3b-tun] route built: client → relay A → relay B → gateway (all descriptors verified)");
    Ok(route)
}

// ════════════════════════════════════════════════════════════════════════════
// `mesh` subcommand: gateway + 2 relays, production SSRF defence
// ════════════════════════════════════════════════════════════════════════════

struct MeshCli {
    bind_ip: Ipv4Addr,
    gateway_port: u16,
    relay_a_port: u16,
    relay_b_port: u16,
    /// Where to write the mesh config (for the `tun` subcommand to read).
    config_path: String,
}

fn parse_mesh_args(args: &[String]) -> Result<MeshCli, String> {
    let mut cli = MeshCli {
        bind_ip: Ipv4Addr::new(10, 0, 1, 1),
        gateway_port: 7003,
        relay_a_port: 7002,
        relay_b_port: 7001,
        config_path: "/tmp/sharenet-mesh-config.json".to_string(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--bind-ip" => { cli.bind_ip = iter.next().ok_or("--bind-ip requires a value")?.parse().map_err(|e| format!("--bind-ip: {}", e))?; }
            "--gateway-port" => { cli.gateway_port = iter.next().ok_or("--gateway-port requires a value")?.parse().map_err(|e| format!("--gateway-port: {}", e))?; }
            "--relay-a-port" => { cli.relay_a_port = iter.next().ok_or("--relay-a-port requires a value")?.parse().map_err(|e| format!("--relay-a-port: {}", e))?; }
            "--relay-b-port" => { cli.relay_b_port = iter.next().ok_or("--relay-b-port requires a value")?.parse().map_err(|e| format!("--relay-b-port: {}", e))?; }
            "--config" => { cli.config_path = iter.next().ok_or("--config requires a value")?.clone(); }
            _ => return Err(format!("unknown arg: {} (try --help)", arg)),
        }
    }
    Ok(cli)
}

async fn run_mesh(cli: MeshCli) -> Result<(), String> {
    eprintln!("[n3b-mesh] starting production ShareNet mesh...");
    eprintln!("[n3b-mesh] bind_ip={} gateway_port={} relay_a_port={} relay_b_port={}",
        cli.bind_ip, cli.gateway_port, cli.relay_a_port, cli.relay_b_port);

    // Generate relay/gateway identities. The mesh process OWNS these private
    // keys — they NEVER leave this process. The client generates its OWN
    // identity independently (see run_tun).
    let ra = NodeIdents::fresh();
    let rb = NodeIdents::fresh();
    let gw = NodeIdents::fresh();

    let gw_addr = format!("{}:{}", cli.bind_ip, cli.gateway_port);
    let ra_addr = format!("{}:{}", cli.bind_ip, cli.relay_a_port);
    let rb_addr = format!("{}:{}", cli.bind_ip, cli.relay_b_port);

    // Start gateway with PRODUCTION SSRF defence (NO with_allow_loopback).
    let gw_node = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;
    let st = Arc::new(GatewayStreamTable::new()); // PRODUCTION
    let gw_addr_spawn = gw_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(
            &gw_node, &gw_addr_spawn, &gw_x_sk, &gw_x_pk, &st,
        ).await;
    });
    eprintln!("[n3b-mesh] gateway on {} (GatewayStreamTable::new — NO loopback exception)", gw_addr);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Start relay B.
    // The relay needs a route to the gateway. The route's source is the relay
    // A's node_id (the relay above relay B), and the destination is the gateway.
    // For relay B's own route, the source is relay A and the destination is gateway.
    let rb_route = Route::new_with_hop_details(
        ra.node_id, gw.node_id,
        vec![
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(&gw_addr, &gw_addr), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    let rb_idents = NodeIdents { ed_sk: rb.ed_sk, x_sk: Arc::clone(&rb.x_sk), x_pk: rb.x_pk, node_id: rb.node_id };
    let rb_addr_clone = rb_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(
            &Node::new(rb_idents.identity(), vec![Capability::Relay], rb_addr_clone.clone()),
            &rb_route, 0, &rb_addr_clone, &rb_idents.x_sk, &rb_idents.x_pk,
        ).await;
    });
    eprintln!("[n3b-mesh] relay B on {}", rb_addr);
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Start relay A.
    // Relay A's route source is a placeholder client node_id (the real client
    // will have its own). The relay accepts connections from any client that
    // knows the route. The route's hop_details carry the verified descriptors.
    let placeholder_client_node_id = [0u8; 32]; // The real client generates its own.
    let ra_route = Route::new_with_hop_details(
        placeholder_client_node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(&ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(&gw_addr, &gw_addr), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    let ra_idents = NodeIdents { ed_sk: ra.ed_sk, x_sk: Arc::clone(&ra.x_sk), x_pk: ra.x_pk, node_id: ra.node_id };
    let ra_addr_clone = ra_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(
            &Node::new(ra_idents.identity(), vec![Capability::Relay], ra_addr_clone.clone()),
            &ra_route, 0, &ra_addr_clone, &ra_idents.x_sk, &ra_idents.x_pk,
        ).await;
    });
    eprintln!("[n3b-mesh] relay A on {}", ra_addr);
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Create SIGNED GatewayAdvertisements for each hop. These contain ONLY
    // public keys + signatures — NO private keys. The mesh signs with the
    // private keys (kept internal); the client verifies with the public keys.
    let ra_advert = GatewayAdvertisement::for_identity_with_circuit_key(
        &ra.identity(), ra.x_pk.to_bytes(), &ra_addr, &ra_addr,
    );
    let rb_advert = GatewayAdvertisement::for_identity_with_circuit_key(
        &rb.identity(), rb.x_pk.to_bytes(), &rb_addr, &rb_addr,
    );
    let gw_advert = GatewayAdvertisement::for_identity_with_circuit_key(
        &gw.identity(), gw.x_pk.to_bytes(), &gw_addr, &gw_addr,
    );

    // Encode the signed adverts to CBOR, then hex-encode for JSON.
    let ra_cbor = ra_advert.encode_cbor().map_err(|e| format!("encode relay A advert: {:?}", e))?;
    let rb_cbor = rb_advert.encode_cbor().map_err(|e| format!("encode relay B advert: {:?}", e))?;
    let gw_cbor = gw_advert.encode_cbor().map_err(|e| format!("encode gateway advert: {:?}", e))?;

    // Write the mesh config — ONLY signed/public information, NO private keys.
    let mesh_config = MeshConfig {
        relay_a_advert_cbor_hex: hex(&ra_cbor),
        relay_b_advert_cbor_hex: hex(&rb_cbor),
        gateway_advert_cbor_hex: hex(&gw_cbor),
        relay_a_addr: ra_addr.clone(),
        relay_b_addr: rb_addr.clone(),
        gateway_addr: gw_addr.clone(),
    };
    let json = serde_json::to_string_pretty(&mesh_config).map_err(|e| format!("serialize: {}", e))?;

    // Write with restrictive permissions (0600) — even though the config
    // contains no private keys, it contains signed identity metadata that
    // should not be world-readable in production.
    std::fs::write(&cli.config_path, json).map_err(|e| format!("write {}: {}", cli.config_path, e))?;
    // Set restrictive permissions (owner-only read/write).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cli.config_path, std::fs::Permissions::from_mode(0o600));
    }

    // Print machine-readable output.
    println!("GATEWAY_ADDR={}", gw_addr);
    println!("RELAY_A_ADDR={}", ra_addr);
    println!("RELAY_B_ADDR={}", rb_addr);
    println!("CONFIG_PATH={}", cli.config_path);

    eprintln!();
    eprintln!("  ════════════════════════════════════════════════════════════");
    eprintln!("  N3-B mesh READY (production gateway — NO loopback exception)");
    eprintln!("    gateway : {} (GatewayStreamTable::new)", gw_addr);
    eprintln!("    relay A : {}", ra_addr);
    eprintln!("    relay B : {}", rb_addr);
    eprintln!("    config  : {}", cli.config_path);
    eprintln!("  ════════════════════════════════════════════════════════════");
    eprintln!();
    eprintln!("  The gateway REJECTS loopback/private destinations.");
    eprintln!("  Use a separately-started HTTP server on a routable IP.");
    eprintln!();
    eprintln!("  Press Ctrl+C to shut down.");
    eprintln!();

    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[n3b-mesh] Ctrl+C — shutting down");
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// `tun` subcommand: TunClient only
// ════════════════════════════════════════════════════════════════════════════

struct TunCli {
    config_path: String,
    tun_name: String,
    tun_ip: Ipv4Addr,
    physical_interface: Option<String>,
}

fn parse_tun_args(args: &[String]) -> Result<TunCli, String> {
    let mut cli = TunCli {
        config_path: "/tmp/sharenet-mesh-config.json".to_string(),
        tun_name: "snp0".to_string(),
        tun_ip: Ipv4Addr::new(10, 0, 0, 1),
        physical_interface: None,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => { cli.config_path = iter.next().ok_or("--config requires a value")?.clone(); }
            "--tun-name" => { cli.tun_name = iter.next().ok_or("--tun-name requires a value")?.clone(); }
            "--tun-ip" => { cli.tun_ip = iter.next().ok_or("--tun-ip requires a value")?.parse().map_err(|e| format!("--tun-ip: {}", e))?; }
            "--physical-interface" => { cli.physical_interface = Some(iter.next().ok_or("--physical-interface requires a value")?.clone()); }
            _ => return Err(format!("unknown arg: {} (try --help)", arg)),
        }
    }
    Ok(cli)
}

async fn run_tun(cli: TunCli) -> Result<(), String> {
    eprintln!("[n3b-tun] starting production TUN client...");

    // 1. Read the mesh config (contains ONLY signed/public advertisements —
    //    NO private keys).
    let config_json = std::fs::read_to_string(&cli.config_path)
        .map_err(|e| format!("read {}: {} (did you run `mesh` first?)", cli.config_path, e))?;
    let mesh_cfg: MeshConfig = serde_json::from_str(&config_json)
        .map_err(|e| format!("parse config: {}", e))?;

    eprintln!("[n3b-tun] loaded mesh config from {}", cli.config_path);
    eprintln!("[n3b-tun] relay_a={} relay_b={} gateway={}",
        mesh_cfg.relay_a_addr, mesh_cfg.relay_b_addr, mesh_cfg.gateway_addr);

    // 2. Generate the CLIENT'S OWN identity. The client owns its private keys
    //    — they are NEVER received from the mesh process. This is the identity
    //    separation invariant.
    eprintln!("[n3b-tun] generating client identity (client owns its private keys)...");
    let client = NodeIdents::fresh();
    let client_identity = client.identity();
    let client_node = Node::new(client_identity, vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client.x_sk);
    let client_x_pk = client.x_pk;
    let client_node_id = client.node_id;

    // 3. Build the route using ONLY the client's node_id + the verified public
    //    descriptors from the mesh config. No relay/gateway private keys are
    //    needed — the descriptors are verified via the embedded public keys.
    let route = build_route_from_config(&mesh_cfg, client_node_id)?;

    // 4. Extract control-plane endpoints for split-tunnel routing.
    let control_plane_endpoints: Vec<IpAddr> = [
        &mesh_cfg.relay_a_addr, &mesh_cfg.relay_b_addr, &mesh_cfg.gateway_addr,
    ].iter()
     .filter_map(|addr| addr.parse::<std::net::SocketAddr>().ok().map(|s| s.ip()))
     .collect();

    let config = TunClientConfig {
        tun_name: cli.tun_name.clone(),
        tun_ip: cli.tun_ip,
        mtu: 1500,
        route,
        node: client_node,
        client_x25519_secret: client_x_sk,
        client_x25519_public: client_x_pk,
        health_endpoint: InternetEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
            protocol: TransportProtocol::Tcp,
        },
        control_plane_endpoints,
        physical_interface: cli.physical_interface.clone(),
    };

    eprintln!("[n3b-tun] creating TUN device + establishing ShareNet circuit...");
    let mut tun_client = TunClient::create(config).await
        .map_err(|e| format!("TunClient::create: {:?}", e))?;

    let actual_tun_name = tun_client.tun_name().to_string();
    eprintln!("[n3b-tun] TUN device '{}' created (ip={})", actual_tun_name, cli.tun_ip);

    // 5. Configure OS routes (split-tunnel).
    if let Err(e) = tun_client.configure_os_routes() {
        eprintln!("[n3b-tun] OS route config failed: {:?} (requires root/CAP_NET_ADMIN)", e);
        let _ = tun_client.cleanup_os_routes();
        return Err(format!("OS route config: {:?}", e));
    }
    eprintln!("[n3b-tun] split-tunnel routes installed (control-plane → {}, default → {})",
        cli.physical_interface.as_deref().unwrap_or("auto"), actual_tun_name);

    println!("TUN_NAME={}", actual_tun_name);
    println!("TUN_IP={}", cli.tun_ip);

    eprintln!();
    eprintln!("  ════════════════════════════════════════════════════════════");
    eprintln!("  N3-B TUN client READY");
    eprintln!("    TUN interface : {} ({})", actual_tun_name, cli.tun_ip);
    eprintln!("    Routing       : split-tunnel (control-plane bypasses TUN)");
    eprintln!("  ════════════════════════════════════════════════════════════");
    eprintln!();
    eprintln!("  Ordinary curl now routes through ShareNet:");
    eprintln!("    curl http://EXTERNAL_IP:PORT/");
    eprintln!();
    eprintln!("  Press Ctrl+C to shut down.");
    eprintln!();

    tokio::select! {
        res = tun_client.run() => {
            eprintln!("[n3b-tun] TUN client exited: {:?}", res);
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[n3b-tun] Ctrl+C — shutting down");
        }
    }

    eprintln!("[n3b-tun] cleaning up OS routes...");
    match tun_client.cleanup_os_routes() {
        Ok(()) => eprintln!("[n3b-tun] OS routes cleaned up"),
        Err(e) => eprintln!("[n3b-tun] cleanup error (non-fatal): {:?}", e),
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// main: dispatch on subcommand
// ════════════════════════════════════════════════════════════════════════════

fn print_usage() {
    eprintln!("Usage: n3b_tun_demo <subcommand> [options]\n");
    eprintln!("Subcommands:");
    eprintln!("  mesh    Start the ShareNet mesh (gateway + 2 relays, production SSRF)");
    eprintln!("  tun     Start the TUN client (connects to mesh, creates TUN, configures routes)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  n3b_tun_demo mesh --bind-ip 10.0.1.1 --config /tmp/cfg.json");
    eprintln!("  n3b_tun_demo tun --config /tmp/cfg.json --tun-name snp0 --tun-ip 10.0.0.1");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(2);
    }

    let sub_args: Vec<String> = args[2..].to_vec();
    let result = match args[1].as_str() {
        "mesh" => {
            let cli = match parse_mesh_args(&sub_args) {
                Ok(c) => c,
                Err(e) => { eprintln!("[n3b] mesh arg error: {}", e); std::process::exit(2); }
            };
            run_mesh(cli).await
        }
        "tun" => {
            let cli = match parse_tun_args(&sub_args) {
                Ok(c) => c,
                Err(e) => { eprintln!("[n3b] tun arg error: {}", e); std::process::exit(2); }
            };
            run_tun(cli).await
        }
        "help" | "--help" | "-h" => {
            print_usage();
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown subcommand: {}", other);
            print_usage();
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("[n3b] error: {}", e);
        std::process::exit(1);
    }
}
