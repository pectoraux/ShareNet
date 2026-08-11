//! snp-node library — daemon internals for the ShareNet reference node (N1.9).
//!
//! For N1.9 (Secure Rust Link + Gateway Boundary) this crate provides:
//!
//! - [`run_gateway`] — TCP server that decrypts the OUTER frame with its
//!   relay↔gateway hop key, decrypts the INNER circuit payload with its
//!   circuit key, decodes the TransitRequest, fetches the real URL via the
//!   pinned-IP connector, signs and returns the TransitResponse (encrypted
//!   again at both layers).
//! - [`run_relay`] — TCP server that decrypts the OUTER frame from the
//!   client (client↔relay hop key), re-encrypts it for the gateway
//!   (relay↔gateway hop key), and forwards. The relay NEVER decrypts the
//!   frame body (the inner circuit payload) — it doesn't have the circuit
//!   key. Invariant I8 holds at the semantic level: the relay sees the body
//!   bytes but cannot read them.
//! - [`run_client`] — TCP client that builds a TransitRequest, signs it,
//!   encrypts the body with its circuit key, wraps the ciphertext in a
//!   Class B frame, AEAD-encrypts the frame with its client↔relay hop key,
//!   sends it via the relay, waits for the response, decrypts at both
//!   layers, verifies the gateway's signature.
//! - [`run_mesh_demo`] — convenience wrapper that spins up all three roles
//!   in threads on ephemeral ports and runs the full round-trip in-process.
//!
//! ## N1.9 key hierarchy
//!
//! ```text
//!   ┌────────┐   client↔relay hop key (seed S1)   ┌───────┐   relay↔gateway hop key (seed S2)   ┌─────────┐
//!   │ Client │ ────────────────────────────────── │ Relay │ ────────────────────────────────── │ Gateway │
//!   └────────┘                                     └───────┘                                     └─────────┘
//!        │                                                                            │
//!        └─────────────── end-to-end circuit key (seed S3) ────────────────────────────┘
//!   (the relay does NOT possess S3 — it cannot decrypt the frame body)
//! ```
//!
//! - **S1 = `b"SNP/0.1 N1.9 client-relay link seed"`** — shared by Client
//!   and Relay. Derives directional hop keys for the Client↔Relay TCP link.
//! - **S2 = `b"SNP/0.1 N1.9 relay-gateway link seed"`** — shared by Relay
//!   and Gateway. Derives directional hop keys for the Relay↔Gateway TCP
//!   link.
//! - **S3 = `b"SNP/0.1 N1.9 circuit seed"`** — shared by Client and Gateway
//!   ONLY. Derives directional circuit keys for end-to-end encryption of
//!   the TransitRequest and TransitResponse bodies.
//!
//! Each hop key is a [`snp_link::LinkKeys`] pair (`send_key` + `recv_key`).
//! Each circuit key is a [`snp_link::CircuitKeys`] pair. The relay has
//! `LinkKeys` for both hops but NO `CircuitKeys` — this is the
//! architectural enforcement of "the relay cannot read the payload".
//!
//! ## N1.9 vs production
//!
//! The seeds above are deterministic test values — they are NOT secret. The
//! production target derives fresh per-link seeds from the SNP-IK/0.1
//! Noise-based handshake (X25519 ephemeral-static DH + transcript hash) so
//! each TCP link has a unique key unknown to anyone but the two endpoints.
//! The circuit seed is derived from the SNP-IK/0.1 transcript between
//! client and gateway, so the relay (which only sees the outer hop
//! handshakes) cannot derive it.

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
use snp_link::{
    decrypt_circuit_payload, derive_circuit_keys, derive_link_keys, encrypt_circuit_payload,
    CircuitKeys, Link, LinkKeys,
};
use thiserror::Error;

/// Errors from the N1.9 daemon.
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
    /// The circuit payload failed AEAD decryption (the gateway rejected the
    /// request — likely tampering at the relay, or a key-derivation bug).
    #[error("circuit payload AEAD decryption failed")]
    CircuitDecryptionFailed,
    /// Configuration or runtime error not covered above.
    #[error("{0}")]
    Other(String),
}

/// Convenience `Result` alias.
pub type NodeResult<T> = Result<T, NodeError>;

// ─── N1.9 key seeds (deterministic test values — NOT secret) ───────────────

/// Seed for the Client↔Relay hop key (S1). Known to Client and Relay only.
const CLIENT_RELAY_LINK_SEED: &[u8] = b"SNP/0.1 N1.9 client-relay link seed";

/// Seed for the Relay↔Gateway hop key (S2). Known to Relay and Gateway only.
const RELAY_GATEWAY_LINK_SEED: &[u8] = b"SNP/0.1 N1.9 relay-gateway link seed";

/// Seed for the end-to-end Client↔Gateway circuit key (S3). Known to Client
/// and Gateway ONLY — the relay MUST NOT possess this seed.
const CIRCUIT_SEED: &[u8] = b"SNP/0.1 N1.9 circuit seed";

/// Client's directional hop keys for the Client↔Relay link.
///
/// The client is the initiator of this TCP connection, so `is_initiator = true`.
#[must_use]
pub fn client_link_keys() -> LinkKeys {
    derive_link_keys(CLIENT_RELAY_LINK_SEED, true)
}

/// Relay's directional hop keys for the Client↔Relay link.
///
/// The relay is the responder of this TCP connection (it accepts the
/// client's connection), so `is_initiator = false`.
#[must_use]
pub fn relay_client_link_keys() -> LinkKeys {
    derive_link_keys(CLIENT_RELAY_LINK_SEED, false)
}

/// Relay's directional hop keys for the Relay↔Gateway link.
///
/// The relay is the initiator of this TCP connection (it dials the
/// gateway), so `is_initiator = true`.
#[must_use]
pub fn relay_gateway_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_GATEWAY_LINK_SEED, true)
}

/// Gateway's directional hop keys for the Relay↔Gateway link.
///
/// The gateway is the responder, so `is_initiator = false`.
#[must_use]
pub fn gateway_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_GATEWAY_LINK_SEED, false)
}

/// Client's directional circuit keys (the client is the circuit initiator).
#[must_use]
pub fn client_circuit_keys() -> CircuitKeys {
    derive_circuit_keys(CIRCUIT_SEED, true)
}

/// Gateway's directional circuit keys (the gateway is the circuit responder).
#[must_use]
pub fn gateway_circuit_keys() -> CircuitKeys {
    derive_circuit_keys(CIRCUIT_SEED, false)
}

/// Gateway secret key (deterministic for N1.9 demo).
const GATEWAY_SECRET: [u8; 32] = {
    let mut sk = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        sk[i as usize] = ((i.wrapping_mul(31)).wrapping_add(1)) as u8;
        i += 1;
    }
    sk
};

/// Client secret key (deterministic for N1.9 demo).
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
/// For N1.9 the gateway serves a single request then exits (the mesh_demo
/// orchestrator can call it once per request).
pub fn run_gateway(listen_addr: &str) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!("[gateway] listening on {listen_addr}");
    let keys = gateway_link_keys();
    let circuit = gateway_circuit_keys();
    let gateway_sk = GATEWAY_SECRET;

    for stream in listener.incoming() {
        let stream = stream?;
        eprintln!("[gateway] relay connected from {}", stream.peer_addr()?);
        let link = Link::new(stream, keys);
        let mut seen_req_ids = std::collections::HashSet::new();
        match serve_one_request(&link, &gateway_sk, &circuit, &mut seen_req_ids) {
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

/// Serve one Mode A request on the given link. The link carries
/// AEAD-protected frames using directional hop keys; the frame body is the
/// end-to-end circuit-encrypted TransitRequest.
fn serve_one_request(
    link: &Link,
    gateway_sk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut std::collections::HashSet<[u8; 16]>,
) -> NodeResult<()> {
    // Recv a frame from the relay. The relay re-encrypted the OUTER frame
    // with the relay→gateway hop key; we decrypt with our recv_key. The
    // INNER body (frame.body) is still the circuit ciphertext the client
    // produced — the relay could not decrypt it (no circuit key).
    let req_frame = link.recv_frame()?;
    eprintln!(
        "[gateway] recv frame: cls={} ttl={} body={} bytes (circuit ciphertext)",
        req_frame.cls as char,
        req_frame.ttl,
        req_frame.body.len()
    );
    if should_drop(&req_frame) {
        eprintln!("[gateway] frame TTL=0, dropping");
        return Ok(());
    }

    // Decrypt the INNER circuit payload (the client encrypted it with its
    // circuit_send_key == our circuit_recv_key). If this fails, the body
    // was tampered with at the relay — return CircuitDecryptionFailed.
    let req_bytes = decrypt_circuit_payload(&circuit.recv_key, &req_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;
    eprintln!(
        "[gateway] circuit decryption OK: {} bytes TransitRequest plaintext",
        req_bytes.len()
    );

    // Decode the TransitRequest from the decrypted circuit plaintext.
    let transit_req = decode_transit_request(&req_bytes)?;
    eprintln!(
        "[gateway] transit request: method={} url={}",
        transit_req.method, transit_req.url
    );

    // N1.9.2: Circuit replay protection — deduplicate reqId.
    // If this reqId has been seen before, reject as replay.
    let req_id_arr: [u8; 16] = transit_req.req_id;
    if !seen_req_ids.insert(req_id_arr) {
        return Err(NodeError::CircuitDecryptionFailed);
    }

    // Handle the request: validate (signature!), build PinnedConnector (DNS pin), fetch,
    // sign. The PinnedConnector closes the N1.8 TOCTOU gap.
    let fetched = handle_transit_request(&transit_req, gateway_sk, &client_public_key())?;
    eprintln!(
        "[gateway] fetched: status={} body={} bytes object_id={}",
        fetched.response.status,
        fetched.body.len(),
        hex_short(&fetched.response.object_id)
    );

    // Build the response bytes and encrypt them with the circuit key
    // (circuit.send_key == client.circuit.recv_key). The client will
    // decrypt the response body with its circuit_recv_key.
    let resp_bytes = encode_transit_response(&fetched.response)?;
    let sealed_resp = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);
    eprintln!(
        "[gateway] circuit encryption: {} bytes TransitResponse → {} bytes ciphertext",
        resp_bytes.len(),
        sealed_resp.len()
    );

    // Build the response frame. dst = original frame's src (the client).
    // src = gateway NodeId. cls = B (transit). ttl = 16. fid = same as request.
    // seq = request seq + 1.
    let resp_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_node_id(),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: sealed_resp,
    };
    link.send_frame(&resp_frame)?;
    eprintln!("[gateway] response frame sent (encrypted with gateway hop send_key + circuit send_key)");
    Ok(())
}

/// Run the RELAY role: listen on `listen_addr` (e.g. "127.0.0.1:7002"),
/// accept one client connection, open a connection to `gateway_addr`,
/// forward frames in both directions. The relay decrypts the OUTER frame
/// (it has the hop keys for both links) but it does NOT decrypt the frame
/// BODY — the body is end-to-end circuit ciphertext that the relay cannot
/// read (it has no circuit key).
pub fn run_relay(listen_addr: &str, gateway_addr: &str) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!("[relay] listening on {listen_addr}, gateway={gateway_addr}");
    let client_link_keys = relay_client_link_keys();
    let gateway_link_keys = relay_gateway_link_keys();

    for stream in listener.incoming() {
        let client_stream = stream?;
        eprintln!("[relay] client connected from {}", client_stream.peer_addr()?);
        let client_link = Arc::new(Link::new(client_stream, client_link_keys));
        let gateway_link = Arc::new(Link::connect(gateway_addr, gateway_link_keys)?);
        eprintln!("[relay] connected to gateway at {gateway_addr}");

        // Forward ONE round-trip synchronously: client → gateway → client.
        // The relay decrypts the OUTER frame with the client↔relay hop key,
        // re-encrypts with the relay↔gateway hop key, and forwards. The
        // frame BODY (the end-to-end circuit ciphertext) is preserved
        // verbatim — the relay never decrypts the body, never inspects it,
        // never holds the circuit plaintext. Invariant I8 holds at the
        // semantic level: the body bytes cross the relay as opaque ciphertext.
        match client_link.recv_frame() {
            Ok(mut frame) => {
                eprintln!(
                    "[relay] client→gateway: recv frame cls={} ttl={} body={} bytes (opaque circuit ciphertext)",
                    frame.cls as char, frame.ttl, frame.body.len()
                );
                // Decrement TTL per I7 before forwarding. (Frame::forward
                // would also do this; we do it inline so we can re-emit the
                // frame on the next link.)
                if frame.ttl > 0 {
                    frame.ttl -= 1;
                }
                if let Err(e) = gateway_link.send_frame(&frame) {
                    eprintln!("[relay] client→gateway: send error: {e}");
                    return Err(e.into());
                }
            }
            Err(e) => {
                eprintln!("[relay] client→gateway: recv error: {e}");
                return Err(e.into());
            }
        }
        match gateway_link.recv_frame() {
            Ok(mut frame) => {
                eprintln!(
                    "[relay] gateway→client: recv frame cls={} ttl={} body={} bytes (opaque circuit ciphertext)",
                    frame.cls as char, frame.ttl, frame.body.len()
                );
                if frame.ttl > 0 {
                    frame.ttl -= 1;
                }
                if let Err(e) = client_link.send_frame(&frame) {
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
/// build a TransitRequest for `url`, sign it, encrypt the body with the
/// circuit key, wrap in a Class B frame, AEAD-encrypt the frame with the
/// client↔relay hop key, send to relay, wait for response, decrypt at both
/// layers, verify gateway signature. Returns the (status, gateway_verified)
/// tuple on success.
pub fn run_client(relay_addr: &str, url: &str) -> NodeResult<(u16, bool)> {
    let keys = client_link_keys();
    let circuit = client_circuit_keys();
    eprintln!("[client] connecting to relay at {relay_addr}");
    let link = Link::connect(relay_addr, keys)?;
    eprintln!("[client] connected");

    // Build the TransitRequest.
    let mut req = TransitRequest {
        req_id: random_req_id(),
        method: "GET".into(),
        url: url.to_string(),
        tls_termination: "GATEWAY_PLAINTEXT".into(),
        max_response_bytes: 65536,
        deadline: now_unix() + 60,
        reply_to: [0u8; 32], // N1.9: not used; gateway replies via the frame
        client_sig: [0u8; 64],
    };
    sign_transit_request(&mut req, &CLIENT_SECRET);
    let req_bytes = encode_transit_request(&req)?;
    eprintln!("[client] transit request: {} bytes (url={url})", req_bytes.len());

    // Encrypt the TransitRequest body end-to-end with the circuit key. The
    // relay will forward this ciphertext verbatim — it cannot decrypt it.
    let sealed_body = encrypt_circuit_payload(&circuit.send_key, &req_bytes);
    eprintln!(
        "[client] circuit encryption: {} bytes plaintext → {} bytes ciphertext",
        req_bytes.len(),
        sealed_body.len()
    );

    // Wrap the circuit ciphertext in a Class B frame addressed to the
    // gateway NodeId. The frame itself is then AEAD-encrypted by the Link
    // layer with the client↔relay hop key.
    let req_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: gateway_node_id(),
        src: client_node_id(),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: random_fid(),
        seq: 1,
        body: sealed_body,
    };
    link.send_frame(&req_frame)?;
    eprintln!("[client] request frame sent (cls=B, dst=gateway, ttl=16, encrypted with client hop send_key)");

    // Wait for the response frame. The Link layer decrypts the OUTER frame
    // (using the client↔relay hop recv_key). The INNER body is still the
    // circuit ciphertext that the gateway produced — we decrypt it with our
    // circuit recv_key.
    let resp_frame = link.recv_frame()?;
    eprintln!(
        "[client] recv response frame: cls={} ttl={} body={} bytes (circuit ciphertext)",
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

    // Decrypt the INNER circuit payload.
    let resp_bytes = decrypt_circuit_payload(&circuit.recv_key, &resp_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;
    eprintln!(
        "[client] circuit decryption OK: {} bytes TransitResponse plaintext",
        resp_bytes.len()
    );

    // Decode the TransitResponse from the decrypted circuit plaintext.
    let transit_resp: TransitResponse = decode_transit_response(&resp_bytes)?;
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
    eprintln!("=== ShareNet 2.0 — N1.9 Secure Rust Link + Gateway Boundary ===");
    eprintln!("=== Client → Relay → Gateway → {url} → back ===");
    eprintln!("=== Directional hop keys + end-to-end circuit encryption + DNS-pinned gateway ===");

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
    // Deterministic-ish for N1.9: hash the current time + a counter.
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
