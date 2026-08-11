//! snp-node library — daemon internals for the ShareNet reference node (N1.8).
//!
//! For N1.8 (the Rust minimal Internet bridge) this crate provides:
//!
//! - [`run_gateway`] — TCP server that decrypts frames, decodes the
//!   TransitRequest, fetches the real URL via HTTP, signs and returns the
//!   TransitResponse.
//! - [`run_relay`] — TCP server that accepts a client connection, opens a
//!   connection to the gateway, and forwards encrypted frame BLOBS verbatim
//!   in both directions. The relay NEVER decrypts (Class B invariant I8).
//! - [`run_client`] — TCP client that builds a TransitRequest for
//!   `https://example.com/`, signs it, wraps it in a Class B frame,
//!   AEAD-encrypts it, sends it via the relay, waits for the response,
//!   decrypts, verifies the gateway's signature.
//! - [`run_mesh_demo`] — convenience wrapper that spins up all three roles
//!   in threads on ephemeral ports and runs the full round-trip in-process.
//!
//! ## Pre-shared link keys (N1.8 simplification)
//!
//! The full SNP-IK/0.1 Noise-based handshake is OUT OF SCOPE for N1.8.
//! All three nodes derive the SAME 32-byte AEAD link key from the
//! deterministic seed `b"SNP/0.1 N1.8 mesh link seed"` via
//! [`snp_link::derive_link_key`]. The key is NOT secret — it is a known test
//! key. This is enough to demonstrate real ChaCha20-Poly1305 AEAD over real
//! TCP; production ShareNet uses SNP-IK/0.1 to derive fresh per-link keys.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use snp_crypto::{derive_node_id, derive_public_key, sha256};
use snp_frames::{should_drop, Frame};
use snp_gateway::{
    decode_transit_request, decode_transit_response, encode_transit_request,
    encode_transit_response, handle_transit_request, sign_transit_request,
    verify_transit_response, TransitRequest, TransitResponse,
};
use snp_link::{derive_link_key, Link};
use thiserror::Error;

/// Errors from the N1.8 daemon.
#[derive(Debug, Error)]
pub enum NodeError {
    /// IO error from the TCP layer.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Link-layer error.
    #[error("link error: {0}")]
    Link(#[from] snp_link::LinkError),
    /// Frame-layer error.
    #[error("frame error: {0}")]
    Frame(#[from] snp_frames::FrameError),
    /// Gateway-layer error.
    #[error("gateway error: {0}")]
    Gateway(#[from] snp_gateway::GatewayError),
    /// The gateway signature on the response did not verify.
    #[error("gateway signature verification failed")]
    GatewaySignatureFailed,
    /// CBOR error.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Configuration or runtime error not covered above.
    #[error("{0}")]
    Other(String),
}

/// Convenience `Result` alias.
pub type NodeResult<T> = Result<T, NodeError>;

/// The pre-shared link-key seed used by all three N1.8 mesh roles.
///
/// All three nodes derive the SAME 32-byte AEAD link key from this seed via
/// [`snp_link::derive_link_key`]. This is the simplified N1.8 model —
/// production ShareNet uses SNP-IK/0.1 to derive fresh per-link keys.
const LINK_KEY_SEED: &[u8] = b"SNP/0.1 N1.8 mesh link seed";

/// Derive the N1.8 mesh link key (same on all three nodes).
#[must_use]
pub fn mesh_link_key() -> [u8; 32] {
    derive_link_key(LINK_KEY_SEED)
}

/// Gateway secret key (deterministic for N1.8 demo).
const GATEWAY_SECRET: [u8; 32] = {
    let mut sk = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        sk[i as usize] = ((i.wrapping_mul(31)).wrapping_add(1)) as u8;
        i += 1;
    }
    sk
};

/// Client secret key (deterministic for N1.8 demo).
const CLIENT_SECRET: [u8; 32] = {
    let mut sk = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        sk[i as usize] = ((i.wrapping_mul(41)).wrapping_add(7)) as u8;
        i += 1;
    }
    sk
};

/// The gateway's Ed25519 public key (derived from [`GATEWAY_SECRET`]).
#[must_use]
pub fn gateway_public_key() -> [u8; 32] {
    derive_public_key(&GATEWAY_SECRET)
}

/// The gateway's NodeId (SHA-256("SNP/0.1 node\0" || pk)).
#[must_use]
pub fn gateway_node_id() -> [u8; 32] {
    derive_node_id(&gateway_public_key())
}

/// The client's Ed25519 public key.
#[must_use]
pub fn client_public_key() -> [u8; 32] {
    derive_public_key(&CLIENT_SECRET)
}

/// The client's NodeId.
#[must_use]
pub fn client_node_id() -> [u8; 32] {
    derive_node_id(&client_public_key())
}

/// Run the GATEWAY role: listen on `listen_addr` (e.g. "127.0.0.1:7003"),
/// accept one relay connection, serve one Mode A request, return the response.
///
/// For N1.8 the gateway serves a single request then exits (the mesh_demo
/// orchestrator can call it once per request).
pub fn run_gateway(listen_addr: &str) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!("[gateway] listening on {listen_addr}");
    let key = mesh_link_key();
    let gateway_sk = GATEWAY_SECRET;

    for stream in listener.incoming() {
        let stream = stream?;
        eprintln!("[gateway] relay connected from {}", stream.peer_addr()?);
        let link = Link::new(stream, key);
        match serve_one_request(&link, &gateway_sk) {
            Ok(()) => {
                eprintln!("[gateway] request served, exiting");
                return Ok(());
            }
            Err(e) => {
                eprintln!("[gateway] error: {e}");
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Serve one Mode A request on the given link.
fn serve_one_request(link: &Link, gateway_sk: &[u8; 32]) -> NodeResult<()> {
    // Recv a frame from the relay (the relay forwards the encrypted blob
    // verbatim — the gateway is the endpoint that decrypts).
    let req_frame = link.recv_frame()?;
    eprintln!(
        "[gateway] recv frame: cls={} ttl={} body={} bytes",
        req_frame.cls as char,
        req_frame.ttl,
        req_frame.body.len()
    );
    if should_drop(&req_frame) {
        eprintln!("[gateway] frame TTL=0, dropping");
        return Ok(());
    }
    // Decode the TransitRequest from the frame body.
    let transit_req = decode_transit_request(&req_frame.body)?;
    eprintln!(
        "[gateway] transit request: method={} url={}",
        transit_req.method, transit_req.url
    );

    // Handle the request: validate, resolve DNS, SSRF check, fetch, sign.
    let fetched = handle_transit_request(&transit_req, gateway_sk)?;
    eprintln!(
        "[gateway] fetched: status={} body={} bytes object_id={}",
        fetched.response.status,
        fetched.body.len(),
        hex_short(&fetched.response.object_id)
    );

    // Build the response frame. dst = original frame's src (the client).
    // src = gateway NodeId. cls = B (transit). ttl = 16. fid = same as request.
    // seq = request seq + 1.
    let resp_bytes = encode_transit_response(&fetched.response)?;
    let resp_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_node_id(),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: resp_bytes,
    };
    link.send_frame(&resp_frame)?;
    eprintln!("[gateway] response frame sent");
    Ok(())
}

/// Run the RELAY role: listen on `listen_addr` (e.g. "127.0.0.1:7002"),
/// accept one client connection, open a connection to `gateway_addr`,
/// forward encrypted blobs verbatim in both directions. NEVER decrypt.
pub fn run_relay(listen_addr: &str, gateway_addr: &str) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!("[relay] listening on {listen_addr}, gateway={gateway_addr}");
    let key = mesh_link_key();

    for stream in listener.incoming() {
        let client_stream = stream?;
        eprintln!("[relay] client connected from {}", client_stream.peer_addr()?);
        let client_link = Arc::new(Link::new(client_stream, key));
        let gateway_link = Arc::new(Link::connect(gateway_addr, key)?);
        eprintln!("[relay] connected to gateway at {gateway_addr}");

        // Forward ONE round-trip synchronously: client → gateway → client.
        // This is the N1.8 demo's "one request, one response" semantics.
        // The relay NEVER decrypts — it forwards raw encrypted blobs (I8).
        match client_link.recv_raw() {
            Ok(blob) => {
                eprintln!(
                    "[relay] client→gateway: forwarding {} bytes (encrypted, untouched)",
                    blob.len()
                );
                if let Err(e) = gateway_link.send_raw(&blob) {
                    eprintln!("[relay] client→gateway: send error: {e}");
                    return Err(e.into());
                }
            }
            Err(e) => {
                eprintln!("[relay] client→gateway: recv error: {e}");
                return Err(e.into());
            }
        }
        match gateway_link.recv_raw() {
            Ok(blob) => {
                eprintln!(
                    "[relay] gateway→client: forwarding {} bytes (encrypted, untouched)",
                    blob.len()
                );
                if let Err(e) = client_link.send_raw(&blob) {
                    eprintln!("[relay] gateway→client: send error: {e}");
                    return Err(e.into());
                }
            }
            Err(e) => {
                eprintln!("[relay] gateway→client: recv error: {e}");
                return Err(e.into());
            }
        }
        eprintln!("[relay] round-trip complete, exiting");
        return Ok(());
    }
    Ok(())
}

/// Run the CLIENT role: connect to `relay_addr` (e.g. "127.0.0.1:7002"),
/// build a TransitRequest for `url`, sign it, wrap in a Class B frame,
/// AEAD-encrypt, send to relay, wait for response, decrypt, verify gateway
/// signature. Returns the (status, gateway_verified) tuple on success.
pub fn run_client(relay_addr: &str, url: &str) -> NodeResult<(u16, bool)> {
    let key = mesh_link_key();
    eprintln!("[client] connecting to relay at {relay_addr}");
    let link = Link::connect(relay_addr, key)?;
    eprintln!("[client] connected");

    // Build the TransitRequest.
    let mut req = TransitRequest {
        req_id: random_req_id(),
        method: "GET".into(),
        url: url.to_string(),
        tls_termination: "GATEWAY_PLAINTEXT".into(),
        max_response_bytes: 65536,
        deadline: now_unix() + 60,
        reply_to: [0u8; 32], // N1.8: not used; gateway replies via the frame
        client_sig: [0u8; 64],
    };
    sign_transit_request(&mut req, &CLIENT_SECRET);
    let req_bytes = encode_transit_request(&req)?;
    eprintln!("[client] transit request: {} bytes (url={url})", req_bytes.len());

    // Wrap in a Class B frame addressed to the gateway NodeId.
    let req_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: gateway_node_id(),
        src: client_node_id(),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: random_fid(),
        seq: 1,
        body: req_bytes,
    };
    link.send_frame(&req_frame)?;
    eprintln!("[client] request frame sent (cls=B, dst=gateway, ttl=16)");

    // Wait for the response frame.
    let resp_frame = link.recv_frame()?;
    eprintln!(
        "[client] recv response frame: cls={} ttl={} body={} bytes",
        resp_frame.cls as char,
        resp_frame.ttl,
        resp_frame.body.len()
    );
    if resp_frame.cls != b'B' {
        return Err(NodeError::Other(format!(
            "expected Class B response, got Class {}",
            resp_frame.cls as char
        )));
    }
    // Decode the TransitResponse from the frame body.
    let transit_resp: TransitResponse = decode_transit_response(&resp_frame.body)?;
    eprintln!(
        "[client] transit response: status={} gateway_sig={} bytes",
        transit_resp.status,
        transit_resp.gateway_sig.len()
    );

    // Verify the gateway's signature.
    let gw_pub = gateway_public_key();
    let verified = verify_transit_response(&transit_resp, &gw_pub);
    if !verified {
        return Err(NodeError::GatewaySignatureFailed);
    }

    // Optionally re-derive objectId to confirm the body hash chain (the body
    // is not transported in the response — only the objectId is — so we just
    // log the objectId).
    let object_id_hex: String = transit_resp.object_id.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("[client] objectId: {object_id_hex}");
    eprintln!("[client] gateway signature: VERIFIED");

    Ok((transit_resp.status, verified))
}

/// Run the in-process mesh demo: spawn gateway + relay in threads, then run
/// the client in the main thread. Prints the success line on success.
pub fn run_mesh_demo(url: &str) -> NodeResult<()> {
    eprintln!("=== ShareNet 2.0 — N1.8 Rust minimal Internet bridge ===");
    eprintln!("=== Client → Relay → Gateway → {url} → back ===");

    // Pick ephemeral ports for the gateway and relay.
    let gateway_listener = TcpListener::bind("127.0.0.1:0")?;
    let gateway_addr = gateway_listener.local_addr()?;
    let relay_listener = TcpListener::bind("127.0.0.1:0")?;
    let relay_addr = relay_listener.local_addr()?;
    drop(gateway_listener);
    drop(relay_listener);

    let gateway_addr_str = gateway_addr.to_string();
    let relay_addr_str = relay_addr.to_string();

    // Start the gateway thread.
    let gw_handle = std::thread::spawn(move || {
        let _ = run_gateway(&gateway_addr_str);
    });

    // Wait briefly for the gateway to start listening.
    std::thread::sleep(Duration::from_millis(100));

    // Start the relay thread.
    let gateway_addr_for_relay = gateway_addr.to_string();
    let relay_handle = std::thread::spawn(move || {
        let _ = run_relay(&relay_addr_str, &gateway_addr_for_relay);
    });

    // Wait briefly for the relay to start listening.
    std::thread::sleep(Duration::from_millis(100));

    // Run the client in the main thread.
    let start = Instant::now();
    let (status, verified) = run_client(&relay_addr.to_string(), url)?;
    let elapsed = start.elapsed();

    // Give the gateway and relay threads a moment to finish, then signal
    // them to stop (they exit after one request).
    let _ = gw_handle.join();
    let _ = relay_handle.join();

    println!();
    println!("Internet request succeeded. Status: {status}. Gateway: {}.",
        if verified { "verified" } else { "NOT verified" });
    println!("Round-trip time: {:.2}s", elapsed.as_secs_f64());
    Ok(())
}

// ─── Utilities ──────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_req_id() -> [u8; 16] {
    // Deterministic-ish for N1.8: hash the current time + a counter.
    let now = now_unix().to_be_bytes();
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&now);
    seed.extend_from_slice(&now);
    let h = sha256(&seed);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

fn random_fid() -> [u8; 8] {
    let now = now_unix().to_be_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&now[..8]);
    out
}

fn hex_short(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n].iter().map(|x| format!("{x:02x}")).collect::<String>() + "…"
}
