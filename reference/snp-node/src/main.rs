//! snp-node — the ShareNet reference daemon.
//!
//! ## Subcommands
//!
//! ### Production (async runtime, real SNP-IK + X25519)
//!
//! ```text
//! snp-node gateway-prod --listen-addr 0.0.0.0:7003
//! ```
//!
//! ### Legacy (synchronous, deterministic keys, backward-compat)
//!
//! ```text
//! snp-node client   --relay-addr 127.0.0.1:7002 [--url https://example.com/]
//! snp-node relay    --listen-addr 127.0.0.1:7002 --gateway-addr 127.0.0.1:7003
//! snp-node gateway  --listen-addr 127.0.0.1:7003
//! snp-node mesh-demo [--url https://example.com/]
//! snp-node mesh-demo-multihop [--url https://example.com/]
//! snp-node mesh-demo-failover [--url https://example.com/]
//! snp-node mesh-session-demo [--url https://example.com/]
//! ```
//!
//! Legacy subcommands use `snp_node::legacy::*` (synchronous `std::net`,
//! deterministic test seeds, NOT production code). Production subcommands
//! use `snp_node::node::async_node::*` (real SNP-IK handshake, real X25519
//! key agreement, tokio async runtime).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        return ExitCode::from(2);
    }
    let result = match args[1].as_str() {
        // ── Production subcommands (async runtime) ──────────────────────────
        "gateway-prod" => cmd_gateway_prod(&args[2..]),
        "relay-prod" => cmd_relay_prod(&args[2..]),
        "client-prod" => cmd_client_prod(&args[2..]),
        // ── Legacy subcommands (synchronous, backward-compat) ───────────────
        "client" => cmd_client(&args[2..]),
        "relay" => cmd_relay(&args[2..]),
        "gateway" => cmd_gateway(&args[2..]),
        "mesh-demo" => cmd_mesh_demo(&args[2..]),
        "mesh-demo-multihop" => cmd_mesh_demo_multihop(&args[2..]),
        "mesh-demo-failover" => cmd_mesh_demo_failover(&args[2..]),
        "mesh-session-demo" => cmd_mesh_session_demo(&args[2..]),
        "help" | "--help" | "-h" => {
            usage(&args[0]);
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            usage(&args[0]);
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Production subcommands (async runtime, real SNP-IK + X25519)
// ════════════════════════════════════════════════════════════════════════════

/// `snp-node gateway-prod` — production Mode B gateway.
///
/// Starts a real ShareNet gateway using:
/// - `async_node::serve_gateway_mode_b_multiplexed` (real Mode B, multiplexed)
/// - `GatewayStreamTable::new()` (production SSRF defence — NO loopback exception)
/// - Fresh Ed25519 + X25519 keys (generated on startup)
///
/// The gateway accepts authenticated ShareNet circuits, opens real outbound
/// TCP sockets to the destinations specified in StreamOpen messages, and
/// enforces SSRF defence (blocks loopback/private/link-local).
fn cmd_gateway_prod(args: &[String]) -> snp_node::NodeResult<()> {
    let mut listen_addr = String::from("0.0.0.0:7003");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen-addr" | "--listen-port" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--listen-addr requires a value".into(),
                    ));
                }
                if args[i - 1] == "--listen-port" {
                    listen_addr = format!("0.0.0.0:{}", args[i]);
                } else {
                    listen_addr = args[i].clone();
                }
            }
            "--help" | "-h" => {
                eprintln!("snp-node gateway-prod — production Mode B gateway");
                eprintln!();
                eprintln!("Usage: snp-node gateway-prod [--listen-addr <addr>]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --listen-addr <addr>  Listen address (default: 0.0.0.0:7003)");
                eprintln!("  --listen-port <port>  Convenience: 0.0.0.0:<port>");
                eprintln!();
                eprintln!("Uses:");
                eprintln!("  - async_node::serve_gateway_mode_b_multiplexed (real Mode B)");
                eprintln!("  - GatewayStreamTable::new() (production SSRF defence)");
                eprintln!("  - Fresh Ed25519 + X25519 keys (generated on startup)");
                return Ok(());
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }

    // Generate fresh identity keys.
    let mut ed_sk = [0u8; 32];
    getrandom::getrandom(&mut ed_sk).expect("getrandom");
    let ed_pk = snp_crypto::derive_public_key(&ed_sk);
    let node_id = snp_crypto::derive_node_id(&ed_pk);
    let (x_sk, x_pk) = snp_crypto::x25519_static_keypair();

    let identity = snp_node::node::NodeIdentity::from_secret(ed_sk);
    let node = snp_node::node::Node::new(
        identity,
        vec![snp_node::node::Capability::Gateway],
        listen_addr.clone(),
    );

    eprintln!("[gateway-prod] starting production Mode B gateway...");
    eprintln!("[gateway-prod] listen: {}", listen_addr);
    eprintln!("[gateway-prod] node_id: {}", hex_short(&node_id));
    eprintln!("[gateway-prod] ed25519 pub: {}", hex_short(&ed_pk));
    eprintln!("[gateway-prod] x25519 pub: {}", hex_short(&x_pk.to_bytes()));
    eprintln!("[gateway-prod] GatewayStreamTable::new() — production SSRF defence (NO loopback exception)");

    // Production gateway stream table — enforces SSRF defence.
    let st = std::sync::Arc::new(snp_node::node::gateway_stream::GatewayStreamTable::new());

    // Create a multi-threaded tokio runtime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| snp_node::NodeError::Other(format!("tokio runtime: {e}")))?;

    runtime.block_on(async move {
        let _ = tokio::signal::ctrl_c();
        eprintln!("[gateway-prod] Ctrl+C received — shutting down");
        snp_node::node::async_node::serve_gateway_mode_b_multiplexed(
            &node,
            &listen_addr,
            &x_sk,
            &x_pk,
            &st,
        )
        .await
    })
}

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    } else {
        format!(
            "{}…",
            bytes[..4]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}

/// `snp-node relay-prod` — production relay.
///
/// Starts a real ShareNet relay using `async_node::serve_relay_via_route`.
/// The relay generates its OWN identity (Ed25519 + X25519) locally.
/// It reads a config file containing signed advertisements for the route
/// (next-hop descriptors, verified via embedded public keys).
///
/// NO other role's private keys are present in the config.
fn cmd_relay_prod(args: &[String]) -> snp_node::NodeResult<()> {
    let mut config_path = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--config requires a value".into(),
                    ));
                }
                config_path = args[i].clone();
            }
            "--help" | "-h" => {
                eprintln!("snp-node relay-prod — production relay");
                eprintln!();
                eprintln!("Usage: snp-node relay-prod --config <PATH>");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  --config <PATH>  Path to JSON config file (signed adverts + role metadata)"
                );
                eprintln!();
                eprintln!("The config contains ONLY signed/public information:");
                eprintln!("  - Signed CBOR advertisements for each hop");
                eprintln!("  - Role metadata (listen_addr, position, node_ids)");
                eprintln!("  - NO private keys (the relay generates its own identity)");
                return Ok(());
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }

    if config_path.is_empty() {
        return Err(snp_node::NodeError::Other("--config is required".into()));
    }

    // Load the config (signed adverts only — no private keys).
    let config = snp_node::prod_config::load_config(&config_path)
        .map_err(|e| snp_node::NodeError::Other(format!("load config: {e}")))?;

    // Build the route from verified signed adverts.
    let route = snp_node::prod_config::build_route_from_config(&config)
        .map_err(|e| snp_node::NodeError::Other(format!("build route: {e}")))?;

    // Generate the relay's OWN identity.
    let mut ed_sk = [0u8; 32];
    getrandom::getrandom(&mut ed_sk).expect("getrandom");
    let identity = snp_node::node::NodeIdentity::from_secret(ed_sk);
    let node_id = identity.node_id;
    let (x_sk, x_pk) = snp_crypto::x25519_static_keypair();
    let node = snp_node::node::Node::new(
        identity,
        vec![snp_node::node::Capability::Relay],
        config.listen_addr.clone(),
    );

    eprintln!("[relay-prod] starting production relay...");
    eprintln!("[relay-prod] listen: {}", config.listen_addr);
    eprintln!("[relay-prod] position: {}", config.position);
    eprintln!("[relay-prod] node_id: {}", hex_short(&node_id));

    let listen_addr = config.listen_addr.clone();
    let position = config.position;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| snp_node::NodeError::Other(format!("tokio runtime: {e}")))?;

    runtime.block_on(async move {
        let _ = tokio::signal::ctrl_c();
        eprintln!("[relay-prod] Ctrl+C received — shutting down");
        snp_node::node::async_node::serve_relay_via_route(
            &node,
            &route,
            position,
            &listen_addr,
            &x_sk,
            &x_pk,
        )
        .await
    })
}

/// `snp-node client-prod` — production protocol client.
///
/// Starts a real ShareNet client that establishes a MultiplexedCircuit
/// through the route described in the config. The client generates its OWN
/// identity locally and verifies all signed advertisements.
///
/// This is the protocol client — NOT transparent TUN networking.
/// Transparent Mode C requires snp-stack (platform-specific) and is a
/// separate composition.
fn cmd_client_prod(args: &[String]) -> snp_node::NodeResult<()> {
    use std::net::{IpAddr, SocketAddr};

    let mut config_path = String::new();
    let mut destination_addr = String::new();
    let mut destination_port: u16 = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--config requires a value".into(),
                    ));
                }
                config_path = args[i].clone();
            }
            "--dest-ip" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--dest-ip requires a value".into(),
                    ));
                }
                destination_addr = args[i].clone();
            }
            "--dest-port" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--dest-port requires a value".into(),
                    ));
                }
                destination_port = args[i].parse().map_err(|_| {
                    snp_node::NodeError::Other(format!("invalid port: {}", args[i]))
                })?;
            }
            "--help" | "-h" => {
                eprintln!("snp-node client-prod — production protocol client");
                eprintln!();
                eprintln!(
                    "Usage: snp-node client-prod --config <PATH> --dest-ip <IP> --dest-port <PORT>"
                );
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --config <PATH>      Path to JSON config (signed adverts)");
                eprintln!("  --dest-ip <IP>       Destination IP address");
                eprintln!("  --dest-port <PORT>  Destination TCP port");
                eprintln!();
                eprintln!("This is the protocol client (Mode B circuit establishment).");
                eprintln!("Transparent TUN (Mode C) is a separate composition in snp-stack.");
                return Ok(());
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }

    if config_path.is_empty() {
        return Err(snp_node::NodeError::Other("--config is required".into()));
    }
    if destination_addr.is_empty() {
        return Err(snp_node::NodeError::Other("--dest-ip is required".into()));
    }
    if destination_port == 0 {
        return Err(snp_node::NodeError::Other("--dest-port is required".into()));
    }

    // Load the config (signed adverts only — no private keys).
    let config = snp_node::prod_config::load_config(&config_path)
        .map_err(|e| snp_node::NodeError::Other(format!("load config: {e}")))?;

    // Build the route from verified signed adverts.
    let route = snp_node::prod_config::build_route_from_config(&config)
        .map_err(|e| snp_node::NodeError::Other(format!("build route: {e}")))?;

    // Generate the client's OWN identity.
    let mut ed_sk = [0u8; 32];
    getrandom::getrandom(&mut ed_sk).expect("getrandom");
    let identity = snp_node::node::NodeIdentity::from_secret(ed_sk);
    let node_id = identity.node_id;
    let (x_sk, x_pk) = snp_crypto::x25519_static_keypair();
    let node = snp_node::node::Node::new_client();

    // Parse the destination.
    let dest_ip: IpAddr = destination_addr
        .parse()
        .map_err(|e| snp_node::NodeError::Other(format!("invalid dest-ip: {e}")))?;
    let destination = snp_gateway::stream::InternetEndpoint {
        address: dest_ip,
        port: destination_port,
        protocol: snp_gateway::stream::TransportProtocol::Tcp,
    };

    eprintln!("[client-prod] starting production protocol client...");
    eprintln!(
        "[client-prod] destination: {}:{}",
        dest_ip, destination_port
    );
    eprintln!("[client-prod] node_id: {}", hex_short(&node_id));
    eprintln!("[client-prod] This is Mode B circuit client, NOT transparent TUN (Mode C).");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| snp_node::NodeError::Other(format!("tokio runtime: {e}")))?;

    runtime.block_on(async move {
        // Establish the multiplexed circuit.
        let mut circuit = snp_node::node::stream_client::MultiplexedCircuit::establish(
            &node, &route, &x_sk, &x_pk,
        )
        .await
        .map_err(|e| snp_node::NodeError::Other(format!("circuit establish: {e:?}")))?;

        eprintln!(
            "[client-prod] circuit established (fid={:?})",
            circuit.circuit_fid()
        );

        // Open a stream to the destination.
        let mut stream = circuit
            .open_stream(destination)
            .await
            .map_err(|e| snp_node::NodeError::Other(format!("open stream: {e:?}")))?;

        eprintln!(
            "[client-prod] stream opened to {}:{}",
            dest_ip, destination_port
        );

        // Wait for Ctrl+C to close.
        let _ = tokio::signal::ctrl_c();
        eprintln!("[client-prod] Ctrl+C received — closing");
        let _ = stream.close().await;
        let _ = circuit.close().await;
        Ok(())
    })
}

// ════════════════════════════════════════════════════════════════════════════
// Legacy subcommands (synchronous, backward-compat — DEPRECATED)
// ════════════════════════════════════════════════════════════════════════════

fn cmd_client(args: &[String]) -> snp_node::NodeResult<()> {
    let mut relay_addr = String::from("127.0.0.1:7002");
    let mut url = String::from("https://example.com/");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--relay-addr" | "--relay-port" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--relay-addr requires a value".into(),
                    ));
                }
                if args[i - 1] == "--relay-port" {
                    relay_addr = format!("127.0.0.1:{}", args[i]);
                } else {
                    relay_addr = args[i].clone();
                }
            }
            "--url" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other("--url requires a value".into()));
                }
                url = args[i].clone();
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }
    let (status, verified) = snp_node::legacy::run_client(&relay_addr, &url)?;
    println!(
        "Internet request succeeded. Status: {status}. Gateway: {}.",
        if verified { "verified" } else { "NOT verified" }
    );
    Ok(())
}

fn cmd_relay(args: &[String]) -> snp_node::NodeResult<()> {
    let mut listen_addr = String::from("127.0.0.1:7002");
    let mut gateway_addr = String::from("127.0.0.1:7003");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen-addr" | "--listen-port" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--listen-addr requires a value".into(),
                    ));
                }
                if args[i - 1] == "--listen-port" {
                    listen_addr = format!("127.0.0.1:{}", args[i]);
                } else {
                    listen_addr = args[i].clone();
                }
            }
            "--gateway-addr" | "--gateway-port" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--gateway-addr requires a value".into(),
                    ));
                }
                if args[i - 1] == "--gateway-port" {
                    gateway_addr = format!("127.0.0.1:{}", args[i]);
                } else {
                    gateway_addr = args[i].clone();
                }
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }
    snp_node::legacy::run_relay(&listen_addr, &gateway_addr)
}

fn cmd_gateway(args: &[String]) -> snp_node::NodeResult<()> {
    let mut listen_addr = String::from("127.0.0.1:7003");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen-addr" | "--listen-port" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other(
                        "--listen-addr requires a value".into(),
                    ));
                }
                if args[i - 1] == "--listen-port" {
                    listen_addr = format!("127.0.0.1:{}", args[i]);
                } else {
                    listen_addr = args[i].clone();
                }
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }
    snp_node::legacy::run_gateway(&listen_addr)
}

fn cmd_mesh_demo(args: &[String]) -> snp_node::NodeResult<()> {
    let mut url = String::from("https://example.com/");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other("--url requires a value".into()));
                }
                url = args[i].clone();
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }
    snp_node::legacy::run_mesh_demo(&url)
}

fn cmd_mesh_demo_multihop(args: &[String]) -> snp_node::NodeResult<()> {
    let mut url = String::from("https://example.com/");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other("--url requires a value".into()));
                }
                url = args[i].clone();
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }
    snp_node::legacy::run_mesh_demo_multihop(&url)
}

fn cmd_mesh_demo_failover(args: &[String]) -> snp_node::NodeResult<()> {
    let mut url = String::from("https://example.com/");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other("--url requires a value".into()));
                }
                url = args[i].clone();
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }
    snp_node::legacy::run_mesh_demo_failover(&url)
}

fn cmd_mesh_session_demo(args: &[String]) -> snp_node::NodeResult<()> {
    let mut url = String::from("https://example.com/");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                if i >= args.len() {
                    return Err(snp_node::NodeError::Other("--url requires a value".into()));
                }
                url = args[i].clone();
            }
            other => return Err(snp_node::NodeError::Other(format!("unknown arg: {other}"))),
        }
        i += 1;
    }
    snp_node::legacy::run_mesh_session_demo(&url)
}

fn usage(prog: &str) {
    eprintln!("Usage: {prog} <subcommand> [options]");
    eprintln!();
    eprintln!("Production (async runtime, real SNP-IK + X25519):");
    eprintln!(
        "  gateway-prod         Production Mode B gateway (GatewayStreamTable::new, real SSRF)"
    );
    eprintln!("  relay-prod           Production relay (serve_relay_via_route, verified adverts)");
    eprintln!("  client-prod          Production protocol client (MultiplexedCircuit, NOT TUN)");
    eprintln!();
    eprintln!("Legacy (synchronous, backward-compat — DEPRECATED):");
    eprintln!("  client               Run as client: send a TransitRequest via the relay");
    eprintln!("  relay               Run as relay: forward encrypted frame blobs (never decrypts)");
    eprintln!("  gateway             Run as gateway: fetch the real URL and sign the response");
    eprintln!("  mesh-demo           Run all three roles in-process (N1.9 single-hop)");
    eprintln!("  mesh-demo-multihop  Run Client → Relay A → Relay B → Gateway → example.com (N2.0 multi-hop)");
    eprintln!("  mesh-demo-failover  Run failover demo: Gateway A killed, traffic continues via Gateway B");
    eprintln!(
        "  mesh-session-demo   N2.0.1: persistent sessions + gateway discovery + genuine failover"
    );
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {prog} gateway-prod --listen-addr 0.0.0.0:7003");
    eprintln!("  {prog} relay-prod --config /tmp/relay-config.json");
    eprintln!("  {prog} client-prod --config /tmp/client-config.json --dest-ip 93.184.216.34 --dest-port 80");
    eprintln!("  {prog} mesh-demo");
}
