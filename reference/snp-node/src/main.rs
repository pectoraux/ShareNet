//! snp-node — the ShareNet reference daemon.
//!
//! Subcommands:
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

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        return ExitCode::from(2);
    }
    let result = match args[1].as_str() {
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
    snp_node::node::run_mesh_session_demo(&url)
}

fn usage(prog: &str) {
    eprintln!("Usage: {prog} <subcommand> [options]");
    eprintln!();
    eprintln!("Subcommands:");
    eprintln!("  client              Run as client: send a TransitRequest via the relay");
    eprintln!("  relay               Run as relay: forward encrypted frame blobs (never decrypts)");
    eprintln!("  gateway             Run as gateway: fetch the real URL and sign the response");
    eprintln!("  mesh-demo           Run all three roles in-process (N1.9 single-hop)");
    eprintln!("  mesh-demo-multihop  Run Client → Relay A → Relay B → Gateway → example.com (N2.0 multi-hop)");
    eprintln!("  mesh-demo-failover  Run failover demo: Gateway A killed, traffic continues via Gateway B");
    eprintln!("  mesh-session-demo   N2.0.1: persistent sessions + gateway discovery + genuine failover");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {prog} mesh-demo");
    eprintln!("  {prog} mesh-demo-multihop");
    eprintln!("  {prog} mesh-demo-failover");
    eprintln!("  {prog} mesh-session-demo");
    eprintln!("  {prog} mesh-demo --url https://example.com/");
    eprintln!("  {prog} gateway --listen-port 7003");
    eprintln!("  {prog} relay  --listen-port 7002 --gateway-port 7003");
    eprintln!("  {prog} client --relay-port 7002 --url https://example.com/");
}
