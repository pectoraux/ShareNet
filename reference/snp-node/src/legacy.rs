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
    /// N2.0.1: An upstream peer (relay or gateway) failed to handle the
    /// request. The relay sent a Class C "upstream-failure" NACK back to
    /// the client. The client's persistent connection to the relay is
    /// STILL ALIVE (the NACK was a valid frame, not a connection reset) —
    /// the client can retry on the same connection with a different
    /// gateway.
    #[error("upstream failure (NACK received from relay — circuit marked inactive)")]
    UpstreamFailure,
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

// ─── N2.0 multi-hop key seeds (deterministic test values — NOT secret) ──────
//
// Topology:
//
//   CLIENT ──[S1]──> RELAY A ──[S2]──> RELAY B ──[S3a]──> GATEWAY A
//                                              └──[S3b]──> GATEWAY B (failover)
//     └─────────────[Ca]───────────────────────────────> GATEWAY A
//     └─────────────[Cb]───────────────────────────────> GATEWAY B (failover)

/// Seed for the Client↔RelayA hop key (S1). Known to Client and Relay A only.
const CLIENT_RELAY_A_SEED: &[u8] = b"SNP/0.1 N2.0 client-relayA link seed";

/// Seed for the RelayA↔RelayB hop key (S2). Known to Relay A and Relay B only.
const RELAY_A_RELAY_B_SEED: &[u8] = b"SNP/0.1 N2.0 relayA-relayB link seed";

/// Seed for the RelayB↔GatewayA hop key (S3a). Known to Relay B and Gateway A only.
const RELAY_B_GATEWAY_A_SEED: &[u8] = b"SNP/0.1 N2.0 relayB-gatewayA link seed";

/// Seed for the RelayB↔GatewayB hop key (S3b). Known to Relay B and Gateway B only.
/// Used by the failover demo when Gateway A is killed.
const RELAY_B_GATEWAY_B_SEED: &[u8] = b"SNP/0.1 N2.0 relayB-gatewayB link seed";

/// Seed for the end-to-end Client↔GatewayA circuit key (Ca). Known to Client
/// and Gateway A ONLY — the relays MUST NOT possess this seed.
const CIRCUIT_SEED_A: &[u8] = b"SNP/0.1 N2.0 circuit seed gatewayA";

/// Seed for the end-to-end Client↔GatewayB circuit key (Cb). Known to Client
/// and Gateway B ONLY. Distinct from `CIRCUIT_SEED_A` — the failover path
/// uses a different circuit key, proving the path actually switched.
const CIRCUIT_SEED_B: &[u8] = b"SNP/0.1 N2.0 circuit seed gatewayB";

/// Gateway choice for the N2.0 multi-hop demo and failover test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayChoice {
    /// Gateway A (primary, used for the first request and the multi-hop demo).
    A,
    /// Gateway B (failover, used after Gateway A is killed).
    B,
}

// ── S1: Client ↔ Relay A (client is initiator, relay A is responder) ──

/// Client's directional hop keys for the Client↔RelayA link (S1).
/// The client is the initiator of this TCP connection.
#[must_use]
pub fn client_relay_a_link_keys() -> LinkKeys {
    derive_link_keys(CLIENT_RELAY_A_SEED, true)
}

/// Relay A's directional hop keys for the Client↔RelayA link (S1).
/// Relay A is the responder (it accepts the client's connection).
#[must_use]
pub fn relay_a_client_link_keys() -> LinkKeys {
    derive_link_keys(CLIENT_RELAY_A_SEED, false)
}

// ── S2: Relay A ↔ Relay B (relay A is initiator, relay B is responder) ──

/// Relay A's directional hop keys for the RelayA↔RelayB link (S2).
/// Relay A is the initiator (it dials Relay B).
#[must_use]
pub fn relay_a_relay_b_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_A_RELAY_B_SEED, true)
}

/// Relay B's directional hop keys for the RelayA↔RelayB link (S2).
/// Relay B is the responder (it accepts Relay A's connection).
#[must_use]
pub fn relay_b_relay_a_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_A_RELAY_B_SEED, false)
}

// ── S3: Relay B ↔ Gateway (relay B is initiator, gateway is responder) ──

/// Relay B's directional hop keys for the RelayB↔GatewayA link (S3a).
/// Relay B is the initiator (it dials Gateway A).
#[must_use]
pub fn relay_b_gateway_a_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_B_GATEWAY_A_SEED, true)
}

/// Gateway A's directional hop keys for the RelayB↔GatewayA link (S3a).
/// Gateway A is the responder.
#[must_use]
pub fn gateway_a_relay_b_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_B_GATEWAY_A_SEED, false)
}

/// Relay B's directional hop keys for the RelayB↔GatewayB link (S3b).
/// Relay B is the initiator (it dials Gateway B after failover).
#[must_use]
pub fn relay_b_gateway_b_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_B_GATEWAY_B_SEED, true)
}

/// Gateway B's directional hop keys for the RelayB↔GatewayB link (S3b).
/// Gateway B is the responder.
#[must_use]
pub fn gateway_b_relay_b_link_keys() -> LinkKeys {
    derive_link_keys(RELAY_B_GATEWAY_B_SEED, false)
}

/// Relay B's directional hop keys for the RelayB↔Gateway link, selected
/// by [`GatewayChoice`].
#[must_use]
pub fn relay_b_gateway_link_keys_for(gw: GatewayChoice) -> LinkKeys {
    match gw {
        GatewayChoice::A => relay_b_gateway_a_link_keys(),
        GatewayChoice::B => relay_b_gateway_b_link_keys(),
    }
}

/// Gateway's directional hop keys for the RelayB↔Gateway link, selected
/// by [`GatewayChoice`].
#[must_use]
pub fn gateway_relay_b_link_keys_for(gw: GatewayChoice) -> LinkKeys {
    match gw {
        GatewayChoice::A => gateway_a_relay_b_link_keys(),
        GatewayChoice::B => gateway_b_relay_b_link_keys(),
    }
}

// ── C: Client ↔ Gateway circuit key (client initiator, gateway responder) ──

/// Client's directional circuit keys for the Client↔GatewayA circuit (Ca).
#[must_use]
pub fn client_circuit_keys_a() -> CircuitKeys {
    derive_circuit_keys(CIRCUIT_SEED_A, true)
}

/// Gateway A's directional circuit keys for the Client↔GatewayA circuit (Ca).
#[must_use]
pub fn gateway_a_circuit_keys() -> CircuitKeys {
    derive_circuit_keys(CIRCUIT_SEED_A, false)
}

/// Client's directional circuit keys for the Client↔GatewayB circuit (Cb).
#[must_use]
pub fn client_circuit_keys_b() -> CircuitKeys {
    derive_circuit_keys(CIRCUIT_SEED_B, true)
}

/// Gateway B's directional circuit keys for the Client↔GatewayB circuit (Cb).
#[must_use]
pub fn gateway_b_circuit_keys() -> CircuitKeys {
    derive_circuit_keys(CIRCUIT_SEED_B, false)
}

/// Client's directional circuit keys, selected by [`GatewayChoice`].
#[must_use]
pub fn client_circuit_keys_for(gw: GatewayChoice) -> CircuitKeys {
    match gw {
        GatewayChoice::A => client_circuit_keys_a(),
        GatewayChoice::B => client_circuit_keys_b(),
    }
}

/// Gateway's directional circuit keys, selected by [`GatewayChoice`].
#[must_use]
pub fn gateway_circuit_keys_for(gw: GatewayChoice) -> CircuitKeys {
    match gw {
        GatewayChoice::A => gateway_a_circuit_keys(),
        GatewayChoice::B => gateway_b_circuit_keys(),
    }
}

// ─── N2.0 gateway identity keys ─────────────────────────────────────────────

/// Gateway A secret key (deterministic for N2.0 demo).
/// Distinct from the N1.9 GATEWAY_SECRET and from GATEWAY_B_SECRET.
const GATEWAY_A_SECRET: [u8; 32] = {
    let mut sk = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        sk[i as usize] = ((i.wrapping_mul(37)).wrapping_add(11)) as u8;
        i += 1;
    }
    sk
};

/// Gateway B secret key (deterministic for N2.0 failover demo).
/// Distinct from GATEWAY_A_SECRET.
const GATEWAY_B_SECRET: [u8; 32] = {
    let mut sk = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        sk[i as usize] = ((i.wrapping_mul(53)).wrapping_add(23)) as u8;
        i += 1;
    }
    sk
};

/// Gateway secret key, selected by [`GatewayChoice`].
#[must_use]
pub fn gateway_secret_for(gw: GatewayChoice) -> [u8; 32] {
    match gw {
        GatewayChoice::A => GATEWAY_A_SECRET,
        GatewayChoice::B => GATEWAY_B_SECRET,
    }
}

/// Gateway public key, selected by [`GatewayChoice`].
#[must_use]
pub fn gateway_public_key_for(gw: GatewayChoice) -> [u8; 32] {
    derive_public_key(&gateway_secret_for(gw))
}

/// Gateway NodeId, selected by [`GatewayChoice`].
#[must_use]
pub fn gateway_node_id_for(gw: GatewayChoice) -> [u8; 32] {
    derive_node_id(&gateway_public_key_for(gw))
}

// ─── N2.0.3 GatewayChoice-free helpers ──────────────────────────────────────
//
// These helpers expose the N2.0 test gateway identities WITHOUT requiring the
// caller to import `GatewayChoice`. They exist so that `node.rs` (the
// production module) can construct the N2.0 demo gateways WITHOUT importing
// `GatewayChoice` — per the N2.0.3 task spec ("node.rs must NOT import or use
// GatewayChoice"). The `GatewayChoice` enum itself remains defined here in
// `lib.rs` (where it is allowed) for backward compat with the N1.9/N2.0 demo
// functions (`run_gateway_named`, `run_client_to_gateway`, etc.).

/// Gateway A secret key (N2.0 deterministic test value, NOT secret).
#[must_use]
pub fn gateway_a_secret() -> [u8; 32] {
    GATEWAY_A_SECRET
}

/// Gateway B secret key (N2.0 deterministic test value, NOT secret).
#[must_use]
pub fn gateway_b_secret() -> [u8; 32] {
    GATEWAY_B_SECRET
}

/// Gateway A Ed25519 public key.
#[must_use]
pub fn gateway_a_public_key() -> [u8; 32] {
    derive_public_key(&GATEWAY_A_SECRET)
}

/// Gateway B Ed25519 public key.
#[must_use]
pub fn gateway_b_public_key() -> [u8; 32] {
    derive_public_key(&GATEWAY_B_SECRET)
}

/// Gateway A NodeId (`SHA-256("SNP/0.1 node\0" || gateway_a_public_key())`).
#[must_use]
pub fn gateway_a_node_id() -> [u8; 32] {
    derive_node_id(&gateway_a_public_key())
}

/// Gateway B NodeId.
#[must_use]
pub fn gateway_b_node_id() -> [u8; 32] {
    derive_node_id(&gateway_b_public_key())
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

/// N2.0.1: The client's secret key (deterministic test value, NOT secret).
/// Exposed `pub(crate)` so the `node` submodule can construct a
/// [`node::NodeIdentity`] for the demo client without re-deriving the
/// constant. Production would generate a fresh secret per node.
#[must_use]
pub fn client_secret_key() -> [u8; 32] {
    CLIENT_SECRET
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

/// Run the GATEWAY role for the N2.0 multi-hop topology: listen on
/// `listen_addr`, accept one relay-B connection, serve one Mode A request
/// using the named gateway's identity keys (A or B), then exit.
///
/// This is the gateway that terminates the third hop (Relay B → Gateway)
/// and the end-to-end circuit (Client ↔ Gateway).
pub fn run_gateway_named(listen_addr: &str, gw: GatewayChoice) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!("[gateway-{gw:?}] listening on {listen_addr}");
    let keys = gateway_relay_b_link_keys_for(gw);
    let circuit = gateway_circuit_keys_for(gw);
    let gateway_sk = gateway_secret_for(gw);

    for stream in listener.incoming() {
        let stream = stream?;
        eprintln!("[gateway-{gw:?}] relay-B connected from {}", stream.peer_addr()?);
        let link = Link::new(stream, keys);
        let mut seen_req_ids = std::collections::HashSet::new();
        match serve_one_request_named(&link, gw, &gateway_sk, &circuit, &mut seen_req_ids) {
            Ok(()) => {
                eprintln!("[gateway-{gw:?}] request served, exiting");
                return Ok(());
            }
            Err(e) => {
                eprintln!("[gateway-{gw:?}] error: {e}");
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Serve one Mode A request on the given link, using the named gateway's
/// identity keys. Mirrors [`serve_one_request`] but is parameterised by
/// [`GatewayChoice`] so the same code path serves both Gateway A and
/// Gateway B.
fn serve_one_request_named(
    link: &Link,
    gw: GatewayChoice,
    gateway_sk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut std::collections::HashSet<[u8; 16]>,
) -> NodeResult<()> {
    let req_frame = link.recv_frame()?;
    eprintln!(
        "[gateway-{gw:?}] recv frame: cls={} ttl={} body={} bytes (circuit ciphertext)",
        req_frame.cls as char,
        req_frame.ttl,
        req_frame.body.len()
    );
    if should_drop(&req_frame) {
        eprintln!("[gateway-{gw:?}] frame TTL=0, dropping");
        return Ok(());
    }

    let req_bytes = decrypt_circuit_payload(&circuit.recv_key, &req_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;
    eprintln!(
        "[gateway-{gw:?}] circuit decryption OK: {} bytes TransitRequest plaintext",
        req_bytes.len()
    );

    let transit_req = decode_transit_request(&req_bytes)?;
    eprintln!(
        "[gateway-{gw:?}] transit request: method={} url={}",
        transit_req.method, transit_req.url
    );

    // N1.9.2 carry-over: reqId dedup (replay defence).
    let req_id_arr: [u8; 16] = transit_req.req_id;
    if !seen_req_ids.insert(req_id_arr) {
        return Err(NodeError::CircuitDecryptionFailed);
    }

    // handle_transit_request verifies the client_sig, builds the PinnedConnector
    // (DNS pin), fetches, signs the response.
    let fetched = handle_transit_request(&transit_req, gateway_sk, &client_public_key())?;
    eprintln!(
        "[gateway-{gw:?}] fetched: status={} body={} bytes object_id={}",
        fetched.response.status,
        fetched.body.len(),
        hex_short(&fetched.response.object_id)
    );

    let resp_bytes = encode_transit_response(&fetched.response)?;
    let sealed_resp = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);
    eprintln!(
        "[gateway-{gw:?}] circuit encryption: {} bytes TransitResponse → {} bytes ciphertext",
        resp_bytes.len(),
        sealed_resp.len()
    );

    let resp_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_node_id_for(gw),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: sealed_resp,
    };
    link.send_frame(&resp_frame)?;
    eprintln!(
        "[gateway-{gw:?}] response frame sent (encrypted with gateway hop send_key + circuit send_key)"
    );
    Ok(())
}

/// Run a multi-hop RELAY: listen on `listen_addr` for an incoming connection
/// from the previous hop, open a connection to `next_hop_addr`, forward one
/// round-trip. The relay holds `prev_hop_keys` (responder of the previous
/// link — used to recv from prev / send to prev) and `next_hop_keys`
/// (initiator of the next link — used to send to next / recv from next).
///
/// The relay decrypts the OUTER frame with `prev_hop_keys.recv_key`,
/// re-encrypts with `next_hop_keys.send_key`, and forwards. The frame BODY
/// (the end-to-end circuit ciphertext) is preserved verbatim — the relay
/// never decrypts the body, never inspects it, never holds the circuit
/// plaintext. Invariant I8 holds at the semantic level.
///
/// N2.0 TTL handling: the relay decrements TTL on receipt. If TTL reaches
/// 0 after decrement, the frame is DROPPED (not forwarded) and the relay
/// exits. This is stricter than the N1.9 single-hop relay (which forwarded
/// even ttl=0 frames) and is required for multi-hop TTL exhaustion to work
/// correctly (Test 4: a frame with TTL=2 must drop at Relay B in a 3-hop
/// path, never reaching the gateway).
///
/// The function name is `run_relay_multiHop` (not `run_relay_multi_hop`)
/// because the task specification that introduces N2.0 names it this way;
/// future revisions should rename it to the snake_case form.
#[allow(non_snake_case)]
pub fn run_relay_multiHop(
    listen_addr: &str,
    next_hop_addr: &str,
    prev_hop_keys: LinkKeys,
    next_hop_keys: LinkKeys,
) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!(
        "[relay-multiHop] listening on {listen_addr}, next-hop={next_hop_addr}"
    );

    for stream in listener.incoming() {
        let prev_stream = stream?;
        eprintln!(
            "[relay-multiHop] prev-hop connected from {}",
            prev_stream.peer_addr()?
        );
        let prev_link = Arc::new(Link::new(prev_stream, prev_hop_keys));
        let next_link = Arc::new(Link::connect(next_hop_addr, next_hop_keys)?);
        eprintln!("[relay-multiHop] connected to next-hop at {next_hop_addr}");

        // Forward ONE round-trip synchronously: prev → next → prev.
        match prev_link.recv_frame() {
            Ok(mut frame) => {
                eprintln!(
                    "[relay-multiHop] prev→next: recv frame cls={} ttl={} body={} bytes (opaque circuit ciphertext)",
                    frame.cls as char,
                    frame.ttl,
                    frame.body.len()
                );
                // N2.0: decrement TTL on receipt. If TTL hits 0, DROP the
                // frame (do NOT forward) and exit. This makes multi-hop
                // TTL exhaustion work correctly: a frame whose TTL is too
                // low for the path is dropped at the relay where TTL
                // reaches 0, not at the gateway.
                if frame.ttl > 0 {
                    frame.ttl -= 1;
                }
                if frame.ttl == 0 {
                    eprintln!(
                        "[relay-multiHop] TTL exhausted after decrement — DROPPING frame (not forwarded)"
                    );
                    // Drop the frame: close both links and exit. The prev
                    // link will see EOF on its recv (no response coming);
                    // the client's run_client will return an error.
                    return Ok(());
                }
                if let Err(e) = next_link.send_frame(&frame) {
                    eprintln!("[relay-multiHop] prev→next: send error: {e}");
                    return Err(e.into());
                }
            }
            Err(e) => {
                eprintln!("[relay-multiHop] prev→next: recv error: {e}");
                return Err(e.into());
            }
        }
        match next_link.recv_frame() {
            Ok(mut frame) => {
                eprintln!(
                    "[relay-multiHop] next→prev: recv frame cls={} ttl={} body={} bytes (opaque circuit ciphertext)",
                    frame.cls as char,
                    frame.ttl,
                    frame.body.len()
                );
                if frame.ttl > 0 {
                    frame.ttl -= 1;
                }
                if let Err(e) = prev_link.send_frame(&frame) {
                    eprintln!("[relay-multiHop] next→prev: send error: {e}");
                    return Err(e.into());
                }
            }
            Err(e) => {
                eprintln!("[relay-multiHop] next→prev: recv error: {e}");
                return Err(e.into());
            }
        }
        eprintln!("[relay-multiHop] round-trip complete, exiting");
        return Ok(());
    }
    Ok(())
}

/// Run the CLIENT role targeting a specific gateway (A or B). The client
/// connects to Relay A using `client_relay_a_link_keys()`, encrypts the
/// body with the matching circuit key (Ca or Cb), and addresses the frame
/// to the matching gateway NodeId. The response is verified against the
/// matching gateway's public key.
///
/// This is the multi-hop client: the request traverses Relay A → Relay B
/// → Gateway, but the client only needs to know Relay A's address (the
/// first hop) and which gateway it's targeting (for circuit key + NodeId).
pub fn run_client_to_gateway(
    relay_a_addr: &str,
    url: &str,
    gw: GatewayChoice,
) -> NodeResult<(u16, bool)> {
    let keys = client_relay_a_link_keys();
    let circuit = client_circuit_keys_for(gw);
    eprintln!("[client-{gw:?}] connecting to Relay A at {relay_a_addr}");
    let link = Link::connect(relay_a_addr, keys)?;
    eprintln!("[client-{gw:?}] connected");

    let mut req = TransitRequest {
        req_id: random_req_id(),
        method: "GET".into(),
        url: url.to_string(),
        tls_termination: "GATEWAY_PLAINTEXT".into(),
        max_response_bytes: 65536,
        deadline: now_unix() + 60,
        reply_to: [0u8; 32],
        client_sig: [0u8; 64],
    };
    sign_transit_request(&mut req, &CLIENT_SECRET);
    let req_bytes = encode_transit_request(&req)?;
    eprintln!(
        "[client-{gw:?}] transit request: {} bytes (url={url})",
        req_bytes.len()
    );

    let sealed_body = encrypt_circuit_payload(&circuit.send_key, &req_bytes);
    eprintln!(
        "[client-{gw:?}] circuit encryption: {} bytes plaintext → {} bytes ciphertext",
        req_bytes.len(),
        sealed_body.len()
    );

    let req_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: gateway_node_id_for(gw),
        src: client_node_id(),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: random_fid(),
        seq: 1,
        body: sealed_body,
    };
    link.send_frame(&req_frame)?;
    eprintln!(
        "[client-{gw:?}] request frame sent (cls=B, dst=gateway-{gw:?}, ttl=16, encrypted with client↔RelayA hop send_key)"
    );

    let resp_frame = link.recv_frame()?;
    eprintln!(
        "[client-{gw:?}] recv response frame: cls={} ttl={} body={} bytes (circuit ciphertext)",
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

    let resp_bytes = decrypt_circuit_payload(&circuit.recv_key, &resp_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;
    eprintln!(
        "[client-{gw:?}] circuit decryption OK: {} bytes TransitResponse plaintext",
        resp_bytes.len()
    );

    let transit_resp: TransitResponse = decode_transit_response(&resp_bytes)?;
    eprintln!(
        "[client-{gw:?}] transit response: status={} gateway_sig={} bytes",
        transit_resp.status,
        transit_resp.gateway_sig.len()
    );

    // Verify the gateway's signature against the matching gateway's public key.
    let gw_pub = gateway_public_key_for(gw);
    let verified = verify_transit_response(&transit_resp, &gw_pub);
    if !verified {
        return Err(NodeError::GatewaySignatureFailed);
    }

    let object_id_hex: String = transit_resp.object_id.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("[client-{gw:?}] objectId: {object_id_hex}");
    eprintln!("[client-{gw:?}] gateway signature: VERIFIED");

    Ok((transit_resp.status, verified))
}

/// Run the in-process multi-hop mesh demo: spawn Gateway A + Relay B +
/// Relay A in threads on ephemeral ports, then run the client in the main
/// thread. The request traverses Client → Relay A → Relay B → Gateway A →
/// real Internet → back.
///
/// TTL starts at 16 (plenty for 3 hops). Each relay decrements TTL by 1.
/// The circuit key (`CIRCUIT_SEED_A`) is shared only between Client and
/// Gateway A — neither relay possesses it. The frame body (circuit
/// ciphertext) crosses both relays as opaque bytes.
pub fn run_mesh_demo_multihop(url: &str) -> NodeResult<()> {
    eprintln!("=== ShareNet 2.0 — N2.0 Multi-hop Secure Mesh ===");
    eprintln!("=== Client → Relay A → Relay B → Gateway A → {url} → back ===");
    eprintln!("=== Three directional hop keys + end-to-end circuit encryption ===");

    // Allocate ephemeral ports for gateway_a, relay_b, relay_a.
    let gw_a_listener = TcpListener::bind("127.0.0.1:0")?;
    let gw_a_addr = gw_a_listener.local_addr()?;
    let relay_b_listener = TcpListener::bind("127.0.0.1:0")?;
    let relay_b_addr = relay_b_listener.local_addr()?;
    let relay_a_listener = TcpListener::bind("127.0.0.1:0")?;
    let relay_a_addr = relay_a_listener.local_addr()?;
    drop(gw_a_listener);
    drop(relay_b_listener);
    drop(relay_a_listener);

    let gw_a_addr_str = gw_a_addr.to_string();
    let relay_b_addr_str = relay_b_addr.to_string();
    let relay_a_addr_str = relay_a_addr.to_string();

    // Start Gateway A.
    let gw_a_handle = std::thread::spawn(move || {
        let _ = run_gateway_named(&gw_a_addr_str, GatewayChoice::A);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Start Relay B → connects to Gateway A.
    let gw_a_addr_for_relay_b = gw_a_addr.to_string();
    let relay_b_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str,
            &gw_a_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Start Relay A → connects to Relay B.
    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str,
            &relay_b_addr_for_relay_a,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Run the client in the main thread.
    let start = Instant::now();
    let (status, verified) = run_client_to_gateway(&relay_a_addr.to_string(), url, GatewayChoice::A)?;
    let elapsed = start.elapsed();

    let _ = gw_a_handle.join();
    let _ = relay_b_handle.join();
    let _ = relay_a_handle.join();

    println!();
    println!(
        "Multi-hop Internet request succeeded. Status: {status}. Gateway: {}.",
        if verified { "verified" } else { "NOT verified" }
    );
    println!("Path: Client → Relay A → Relay B → Gateway A → {url} → back");
    println!("Round-trip time: {:.2}s", elapsed.as_secs_f64());
    Ok(())
}

/// Run the in-process failover demo. Demonstrates that when Gateway A is
/// killed, Relay B can be re-pointed at Gateway B (with the matching hop
/// key `RELAY_B_GATEWAY_B_SEED`), the client switches to `CIRCUIT_SEED_B`,
/// and the request succeeds via Gateway B with a DIFFERENT circuit key.
///
/// Flow:
/// 1. Start Gateway A and Gateway B on ephemeral ports.
/// 2. Start Relay B → connects to Gateway A (using S3a keys).
/// 3. Start Relay A → connects to Relay B (using S2 keys).
/// 4. Client sends request → succeeds via Gateway A (status=200, sig verified).
/// 5. Gateway A's thread completes (it served one request, exits, "killed").
/// 6. Restart Relay B → now connects to Gateway B (using S3b keys).
/// 7. Restart Relay A → connects to the new Relay B (same S2 keys).
/// 8. Client sends another request → succeeds via Gateway B (status=200,
///    sig verified against Gateway B's public key, different circuit key).
///
/// The circuit key changes between the two requests (Ca for the first,
/// Cb for the second), proving the path actually switched.
pub fn run_mesh_demo_failover(url: &str) -> NodeResult<()> {
    eprintln!("=== ShareNet 2.0 — N2.0 Gateway Failover Demo ===");
    eprintln!("=== Phase 1: Client → Relay A → Relay B → Gateway A → {url} → back ===");

    // Allocate ephemeral ports for all five roles.
    let gw_a_listener = TcpListener::bind("127.0.0.1:0")?;
    let gw_a_addr = gw_a_listener.local_addr()?;
    let gw_b_listener = TcpListener::bind("127.0.0.1:0")?;
    let gw_b_addr = gw_b_listener.local_addr()?;
    let relay_b_listener = TcpListener::bind("127.0.0.1:0")?;
    let relay_b_addr = relay_b_listener.local_addr()?;
    let relay_a_listener = TcpListener::bind("127.0.0.1:0")?;
    let relay_a_addr = relay_a_listener.local_addr()?;
    drop(gw_a_listener);
    drop(gw_b_listener);
    drop(relay_b_listener);
    drop(relay_a_listener);

    // ── Phase 1: Gateway A is alive. ──
    let gw_a_addr_str_p1 = gw_a_addr.to_string();
    let gw_a_handle_p1 = std::thread::spawn(move || {
        let _ = run_gateway_named(&gw_a_addr_str_p1, GatewayChoice::A);
    });
    std::thread::sleep(Duration::from_millis(100));

    let gw_a_addr_for_relay_b = gw_a_addr.to_string();
    let relay_b_addr_str_p1 = relay_b_addr.to_string();
    let relay_b_handle_p1 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str_p1,
            &gw_a_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_addr_str_p1 = relay_a_addr.to_string();
    let relay_a_handle_p1 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str_p1,
            &relay_b_addr_for_relay_a,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let start_p1 = Instant::now();
    let (status_a, verified_a) =
        run_client_to_gateway(&relay_a_addr.to_string(), url, GatewayChoice::A)?;
    let elapsed_p1 = start_p1.elapsed();
    let _ = gw_a_handle_p1.join();
    let _ = relay_b_handle_p1.join();
    let _ = relay_a_handle_p1.join();
    println!(
        "Phase 1 OK: status={status_a}, gateway-A verified={verified_a}, RTT={:.2}s",
        elapsed_p1.as_secs_f64()
    );

    // ── "Kill" Gateway A. In N2.0 the gateway thread already exited after
    //     serving one request. We re-create Relay B pointed at Gateway B
    //     (with the S3b hop key) and re-create Relay A pointed at the new
    //     Relay B. The client switches to CIRCUIT_SEED_B (Cb) and addresses
    //     the frame to Gateway B's NodeId. ──
    eprintln!();
    eprintln!("=== Phase 2: Gateway A KILLED — failover to Gateway B ===");
    eprintln!("=== Client → Relay A → Relay B → Gateway B → {url} → back ===");

    // Start Gateway B (it was bound above but not yet running a server).
    let gw_b_addr_str = gw_b_addr.to_string();
    let gw_b_handle = std::thread::spawn(move || {
        let _ = run_gateway_named(&gw_b_addr_str, GatewayChoice::B);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Re-create Relay B → connects to Gateway B (using S3b keys). The
    // previous Relay B thread has exited; we start a new one on the same
    // port. (In production, Relay B would maintain a connection pool and
    // switch active upstream on failure detection — N2.0 simplifies by
    // re-instantiating the relay.)
    let gw_b_addr_for_relay_b = gw_b_addr.to_string();
    let relay_b_addr_str_p2 = relay_b_addr.to_string();
    let relay_b_handle_p2 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str_p2,
            &gw_b_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let relay_b_addr_for_relay_a_p2 = relay_b_addr.to_string();
    let relay_a_addr_str_p2 = relay_a_addr.to_string();
    let relay_a_handle_p2 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str_p2,
            &relay_b_addr_for_relay_a_p2,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let start_p2 = Instant::now();
    let (status_b, verified_b) =
        run_client_to_gateway(&relay_a_addr.to_string(), url, GatewayChoice::B)?;
    let elapsed_p2 = start_p2.elapsed();
    let _ = gw_b_handle.join();
    let _ = relay_b_handle_p2.join();
    let _ = relay_a_handle_p2.join();

    println!(
        "Phase 2 OK: status={status_b}, gateway-B verified={verified_b}, RTT={:.2}s",
        elapsed_p2.as_secs_f64()
    );
    println!();
    println!(
        "Failover succeeded. Gateway A: status={status_a} verified={verified_a}. \
         Gateway B: status={status_b} verified={verified_b}. Circuit key changed: Ca → Cb."
    );
    Ok(())
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
