//! N2.0.1 mesh session demo — standalone binary wrapper.
//!
//! This is a thin wrapper around [`snp_node::node::run_mesh_session_demo`].
//! It exists so the demo can be run as:
//!
//! ```bash
//! cargo run -p snp-node --bin mesh-session-demo
//! ```
//!
//! or (via the `mesh-session-demo` subcommand in `main.rs`):
//!
//! ```bash
//! cargo run -p snp-node -- mesh-session-demo
//! ```
//!
//! Both forms invoke the same underlying demo function. The demo:
//!
//! 1. Starts Gateway A and Gateway B as persistent nodes (each with a
//!    transit listener AND a discovery listener).
//! 2. Starts Relay B (multi-upstream: persistent connections to BOTH
//!    gateways).
//! 3. Starts Relay A (single-upstream: persistent connection to Relay B).
//! 4. Client discovers gateways via signed advertisements (not hardcoded).
//! 5. Client sends Request 1 → succeeds via Gateway A.
//! 6. Client sends Request 2 → succeeds via Gateway A (SAME persistent
//!    session — no reconnection).
//! 7. Gateway A's connection drops (simulated failure — the gateway closes
//!    its TCP stream after the 2nd request).
//! 8. Client sends Request 3 → fails over to Gateway B (new circuit, same
//!    client process — NO NODE RESTART).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut url = String::from("https://example.com/");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --url requires a value");
                    return ExitCode::from(2);
                }
                url = args[i].clone();
            }
            "--help" | "-h" => {
                eprintln!("Usage: mesh-session-demo [--url URL]");
                eprintln!();
                eprintln!("Runs the N2.0.1 mesh session demo: persistent sessions + gateway");
                eprintln!("discovery + genuine failover. Fetches the given URL (default:");
                eprintln!("https://example.com/) three times — twice via Gateway A, then once");
                eprintln!("via Gateway B after Gateway A's connection drops.");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unknown argument: {other}");
                eprintln!("Usage: mesh-session-demo [--url URL]");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    match snp_node::node::run_mesh_session_demo(&url) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
