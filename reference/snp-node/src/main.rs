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
                    return Err(snp_node::NodeError::Other("--listen-addr requires a value".into()));
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
        format!("{}…", bytes[..4].iter().map(|b| format!("{:02x}", b)).collect::<String>())
    }
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
                    return Err(snp_node::NodeError::Other("--relay-addr requires a value".into()));
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
                    return Err(snp_node::NodeError::Other("--listen-addr requires a value".into()));
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
                    return Err(snp_node::NodeError::Other("--gateway-addr requires a value".into()));
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
                    return Err(snp_node::NodeError::Other("--listen-addr requires a value".into()));
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
    eprintln!("  gateway-prod         Production Mode B gateway (GatewayStreamTable::new, real SSRF)");
    eprintln!();
    eprintln!("Legacy (synchronous, backward-compat — DEPRECATED):");
    eprintln!("  client               Run as client: send a TransitRequest via the relay");
    eprintln!("  relay               Run as relay: forward encrypted frame blobs (never decrypts)");
    eprintln!("  gateway             Run as gateway: fetch the real URL and sign the response");
    eprintln!("  mesh-demo           Run all three roles in-process (N1.9 single-hop)");
    eprintln!("  mesh-demo-multihop  Run Client → Relay A → Relay B → Gateway → example.com (N2.0 multi-hop)");
    eprintln!("  mesh-demo-failover  Run failover demo: Gateway A killed, traffic continues via Gateway B");
    eprintln!("  mesh-session-demo   N2.0.1: persistent sessions + gateway discovery + genuine failover");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {prog} gateway-prod --listen-addr 0.0.0.0:7003");
    eprintln!("  {prog} mesh-demo");
    eprintln!("  {prog} mesh-demo-multihop");
    eprintln!("  {prog} gateway --listen-port 7003");
    eprintln!("  {prog} relay  --listen-port 7002 --gateway-port 7003");
    eprintln!("  {prog} client --relay-port 7002 --url https://example.com/");
}
