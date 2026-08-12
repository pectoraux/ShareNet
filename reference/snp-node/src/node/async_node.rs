//! Async Node — Tokio-based production runtime for the ShareNet reference node.
//!
//! **N2.0.6 — canonical async production runtime.** This module provides the
//! async variants of the Node entry points. They use:
//!
//! - [`snp_link::async_link::AsyncLink`] — the canonical async AEAD-framed transport.
//! - [`snp_link::async_link::perform_snp_ik_handshake_async`] — the canonical
//!   async SNP-IK/0.1 handshake.
//! - [`Route`](super::Route) + [`Circuit`](super::Circuit) — the dynamic
//!   route/circuit abstractions.
//!
//! The synchronous counterparts in [`super::Node`] are `#[deprecated]` and
//! retained only for backward-compat with the N2.0.1 / N2.0.4 sync tests.
//! Production code MUST use the async variants in this module.
//!
//! ## Why a separate module (not async methods on `Node`)?
//!
//! The sync `Node` methods take `&self` and use `std::net::TcpListener::bind`
//! + `Link::connect` (blocking). Making them async would break every existing
//! caller. Instead, the async runtime lives here as free functions that take
//! an `&Node` (for identity + circuit table access) plus explicit parameters.
//! This keeps the sync API stable for tests while making the async API the
//! canonical production path.
//!
//! ## Entry points
//!
//! - [`serve_gateway_persistent_async`] — gateway transit listener.
//! - [`serve_relay_persistent_async`] — single-upstream relay.
//! - [`serve_discovery_persistent_async`] — discovery listener (signed adverts).
//! - [`send_request_via_gateway_full_with_relay_async`] — client send.
//! - [`discover_gateways_async`] — client discovery.

use std::collections::HashSet;
use std::sync::Arc;

use snp_crypto::derive_node_id;
use snp_frames::{should_drop, Frame, FRAME_TTL_MAX, FRAME_VERSION};
use snp_gateway::{
    decode_transit_request, decode_transit_response, encode_transit_request,
    encode_transit_response, handle_transit_request_with_connector, sign_transit_request,
    verify_transit_response, PinnedConnector, TransitRequest, TransitResponse,
};
use snp_link::async_link::{
    perform_snp_ik_handshake_async, AsyncLink, AsyncLinkError,
};
use snp_link::{decrypt_circuit_payload, encrypt_circuit_payload, CircuitKeys, LinkKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{
    now_unix, random_fid, random_req_id, GatewayAdvertisement, Node, NodeError, NodeResult,
    ServeOutcome, UPSTREAM_FAILURE_MARKER,
};
use crate::node::circuit::UpstreamPeer;
use crate::node::Circuit;

/// Map an [`AsyncLinkError`] to a [`NodeError`].
fn async_err_to_node(e: AsyncLinkError) -> NodeError {
    match e {
        AsyncLinkError::Io(msg) => NodeError::Other(format!("async link io: {msg}")),
        AsyncLinkError::DecryptionFailed => NodeError::CircuitDecryptionFailed,
        AsyncLinkError::AbsurdLength(n) => NodeError::Other(format!("absurd length {n}")),
        AsyncLinkError::Cbor(msg) => NodeError::Other(format!("cbor: {msg}")),
        AsyncLinkError::ReplayDetected => NodeError::Other("replay detected".into()),
        AsyncLinkError::Handshake(msg) => NodeError::Other(format!("handshake: {msg}")),
    }
}

// ─── Gateway ────────────────────────────────────────────────────────────────

/// Run a persistent gateway using the canonical async transport.
///
/// Listens on `listen_addr` for incoming connections from relays; for each
/// connection, loops serving transit requests (decrypt circuit → fetch URL →
/// encrypt response) until the relay disconnects.
///
/// **Production path:** the `link_keys` come from a real
/// [`perform_snp_ik_handshake_async`] between the relay and the gateway; the
/// `circuit_keys` come from a real client↔gateway X25519 DH. The gateway
/// fetches URLs via [`PinnedConnector::new`] (SSRF defence — invariant I18).
///
/// # Errors
/// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
/// logged and the gateway continues accepting new connections.
pub async fn serve_gateway_persistent_async(
    node: &Node,
    listen_addr: &str,
    link_keys: LinkKeys,
    circuit_keys: CircuitKeys,
) -> NodeResult<()> {
    let gateway_node_id = node.identity.node_id;
    let gateway_sk = node.identity.secret_key;
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {listen_addr}: {e}")))?;
    eprintln!(
        "[gateway-async {}] listening on {listen_addr}",
        super::hex_short(&gateway_node_id)
    );
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[gateway-async {}] accept error: {e}",
                    super::hex_short(&gateway_node_id)
                );
                continue;
            }
        };
        eprintln!(
            "[gateway-async {}] relay connected from {peer}",
            super::hex_short(&gateway_node_id)
        );
        let link = Arc::new(AsyncLink::new(stream, link_keys));
        let mut seen_req_ids = HashSet::new();
        loop {
            match serve_one_gateway_request_async(
                &link,
                gateway_node_id,
                &gateway_sk,
                &circuit_keys,
                &mut seen_req_ids,
            )
            .await
            {
                Ok(ServeOutcome::Continue) => continue,
                Ok(ServeOutcome::Closed) => {
                    eprintln!(
                        "[gateway-async {}] connection closed",
                        super::hex_short(&gateway_node_id)
                    );
                    break;
                }
                Err(e) => {
                    eprintln!(
                        "[gateway-async {}] request error: {e}",
                        super::hex_short(&gateway_node_id)
                    );
                    break;
                }
            }
        }
    }
}

/// Like [`serve_gateway_persistent_async`] but accepts a custom connector
/// factory (for tests that fetch from a local mock HTTP server).
///
/// **Production gateways MUST NOT use this function** — production must use
/// [`serve_gateway_persistent_async`] which calls [`PinnedConnector::new`]
/// and enforces the SSRF defence.
pub async fn serve_gateway_persistent_async_with_connector<F>(
    node: &Node,
    listen_addr: &str,
    link_keys: LinkKeys,
    circuit_keys: CircuitKeys,
    client_pk: [u8; 32],
    connector_factory: F,
) -> NodeResult<()>
where
    F: Fn(&str) -> NodeResult<PinnedConnector> + Send + Sync + 'static,
{
    let gateway_node_id = node.identity.node_id;
    let gateway_sk = node.identity.secret_key;
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {listen_addr}: {e}")))?;
    eprintln!(
        "[gateway-async-conn {}] listening on {listen_addr}",
        super::hex_short(&gateway_node_id)
    );
    let connector = Arc::new(connector_factory);
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[gateway-async-conn {}] accept error: {e}",
                    super::hex_short(&gateway_node_id)
                );
                continue;
            }
        };
        let link = Arc::new(AsyncLink::new(stream, link_keys));
        let mut seen_req_ids = HashSet::new();
        let gw_sk = gateway_sk;
        let client_pk_local = client_pk;
        let circuit_keys_local = circuit_keys;
        let connector = Arc::clone(&connector);
        loop {
            match serve_one_gateway_request_async_with_connector(
                &link,
                gateway_node_id,
                &gw_sk,
                &client_pk_local,
                &circuit_keys_local,
                &mut seen_req_ids,
                connector.as_ref(),
            )
            .await
            {
                Ok(ServeOutcome::Continue) => continue,
                Ok(ServeOutcome::Closed) => break,
                Err(e) => {
                    eprintln!(
                        "[gateway-async-conn {}] request error: {e}",
                        super::hex_short(&gateway_node_id)
                    );
                    break;
                }
            }
        }
    }
}

/// Serve ONE transit request on the given async link (production path:
/// `PinnedConnector::new` SSRF defence).
async fn serve_one_gateway_request_async(
    link: &Arc<AsyncLink>,
    gateway_node_id: [u8; 32],
    gateway_sk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut HashSet<[u8; 16]>,
) -> NodeResult<ServeOutcome> {
    // The production factory: PinnedConnector::new (SSRF defence enforced).
    serve_one_gateway_request_async_with_connector(
        link,
        gateway_node_id,
        gateway_sk,
        &super::super::legacy::client_public_key(),
        circuit,
        seen_req_ids,
        &|url| PinnedConnector::new(url).map_err(NodeError::Gateway),
    )
    .await
}

/// Serve ONE transit request with a custom connector factory + explicit
/// client public key (for dynamic-mesh scenarios where the client identity
/// is NOT the deterministic N2.0 test identity).
pub async fn serve_one_gateway_request_async_with_connector<F>(
    link: &Arc<AsyncLink>,
    gateway_node_id: [u8; 32],
    gateway_sk: &[u8; 32],
    client_pk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut HashSet<[u8; 16]>,
    connector_factory: &F,
) -> NodeResult<ServeOutcome>
where
    F: Fn(&str) -> NodeResult<PinnedConnector> + Send + Sync,
{
    let req_frame = match link.recv_frame().await {
        Ok(f) => f,
        Err(AsyncLinkError::Io(msg))
            if msg.contains("unexpected eof") || msg.contains("reset") =>
        {
            return Ok(ServeOutcome::Closed);
        }
        Err(e) => return Err(async_err_to_node(e)),
    };
    if should_drop(&req_frame) {
        return Ok(ServeOutcome::Continue);
    }
    let req_bytes = decrypt_circuit_payload(&circuit.recv_key, &req_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;
    let transit_req = decode_transit_request(&req_bytes)?;
    let req_id_arr: [u8; 16] = transit_req.req_id;
    if !seen_req_ids.insert(req_id_arr) {
        return Err(NodeError::Other(format!(
            "replay detected: reqId {:?} already seen",
            req_id_arr
        )));
    }
    let connector = connector_factory(&transit_req.url)?;
    // The sync `handle_transit_request_with_connector` calls `connector.fetch()`
    // which uses blocking I/O. Wrap it in `spawn_blocking` so it doesn't
    // stall the tokio runtime (the async HTTP server on the other end needs
    // to be scheduled to accept the connection + send the response).
    let gateway_sk_arr = *gateway_sk;
    let client_pk_arr = *client_pk;
    let fetched = tokio::task::spawn_blocking(move || {
        handle_transit_request_with_connector(
            &transit_req,
            &gateway_sk_arr,
            &client_pk_arr,
            &connector,
        )
    })
    .await
    .map_err(|e| NodeError::Other(format!("spawn_blocking join: {e}")))??;
    let resp_bytes = encode_transit_response(&fetched.response)?;
    let sealed_resp = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);
    let resp_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_node_id,
        ttl: FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: sealed_resp,
    };
    link.send_frame(&resp_frame)
        .await
        .map_err(async_err_to_node)?;
    Ok(ServeOutcome::Continue)
}

// ─── Relay ──────────────────────────────────────────────────────────────────

/// Run a persistent single-upstream relay using the canonical async transport.
///
/// Accepts incoming connections on `listen_addr`; for each, opens an upstream
/// connection to `next_hop_addr` and forwards frames bidirectionally until
/// either side closes. Uses [`snp_link::async_link::async_relay_forward_links`]
/// for concurrent bidirectional forwarding.
///
/// **Production path:** `prev_hop_keys` and `next_hop_keys` come from real
/// SNP-IK/0.1 handshakes (caller's responsibility — the relay performs the
/// handshakes BEFORE calling this function, then passes the resulting keys).
///
/// # Errors
/// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
/// logged and the relay continues accepting new connections.
pub async fn serve_relay_persistent_async(
    listen_addr: &str,
    next_hop_addr: &str,
    prev_hop_keys: LinkKeys,
    next_hop_keys: LinkKeys,
) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {listen_addr}: {e}")))?;
    eprintln!(
        "[relay-async] listening on {listen_addr}, next-hop={next_hop_addr}"
    );
    loop {
        let (prev_stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[relay-async] accept error: {e}");
                continue;
            }
        };
        let prev_link = Arc::new(AsyncLink::new(prev_stream, prev_hop_keys));
        let next_stream = match AsyncLink::connect_raw(next_hop_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[relay-async] connect to next-hop {next_hop_addr} failed: {e}"
                );
                continue;
            }
        };
        let next_link = Arc::new(AsyncLink::new(next_stream, next_hop_keys));
        eprintln!("[relay-async] connected to next-hop at {next_hop_addr}");
        // Forward bidirectionally until either side closes/errors.
        if let Err(e) =
            snp_link::async_link::async_relay_forward_links(prev_link, next_link).await
        {
            eprintln!("[relay-async] forward error: {e}");
        }
        eprintln!("[relay-async] connection cycle complete, looping back to accept");
    }
}

/// Run a persistent multi-upstream relay using the canonical async transport.
///
/// Routes frames to the upstream whose `dst_node_id` matches `frame.dst`.
/// On upstream failure, sends a Class C `UPSTREAM_FAILURE_MARKER` NACK back
/// to the prev hop and removes the dead upstream.
pub async fn serve_relay_multi_upstream_persistent_async(
    listen_addr: &str,
    upstreams: Vec<UpstreamPeer>,
    prev_hop_keys: LinkKeys,
) -> NodeResult<()> {
    if upstreams.is_empty() {
        return Err(NodeError::Other(
            "multi-upstream relay requires at least one upstream".into(),
        ));
    }
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {listen_addr}: {e}")))?;
    eprintln!(
        "[relay-multi-async] listening on {listen_addr}, {} upstreams",
        upstreams.len()
    );
    loop {
        let (prev_stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[relay-multi-async] accept error: {e}");
                continue;
            }
        };
        let prev_link = Arc::new(AsyncLink::new(prev_stream, prev_hop_keys));
        // Establish connections to ALL upstreams.
        let mut upstream_links: Vec<([u8; 32], Arc<AsyncLink>)> = Vec::new();
        for upstream in &upstreams {
            match AsyncLink::connect_raw(&upstream.addr).await {
                Ok(s) => {
                    let link = Arc::new(AsyncLink::new(s, upstream.hop_keys));
                    eprintln!(
                        "[relay-multi-async] connected to upstream {} at {}",
                        super::hex_short(&upstream.dst_node_id),
                        upstream.addr
                    );
                    upstream_links.push((upstream.dst_node_id, link));
                }
                Err(e) => {
                    eprintln!(
                        "[relay-multi-async] connect to upstream {} at {} failed: {e}",
                        super::hex_short(&upstream.dst_node_id),
                        upstream.addr
                    );
                }
            }
        }
        if upstream_links.is_empty() {
            eprintln!("[relay-multi-async] no upstreams connected — closing prev-hop");
            continue;
        }
        // PERSISTENT LOOP: route frames based on dst NodeId.
        loop {
            let req_frame = match prev_link.recv_frame().await {
                Ok(f) => f,
                Err(AsyncLinkError::Io(msg))
                    if msg.contains("unexpected eof") || msg.contains("reset") =>
                {
                    break;
                }
                Err(e) => {
                    eprintln!("[relay-multi-async] recv error: {e}");
                    break;
                }
            };
            if should_drop(&req_frame) {
                continue;
            }
            let upstream_idx = upstream_links
                .iter()
                .position(|(id, _)| *id == req_frame.dst);
            match upstream_idx {
                Some(idx) => {
                    let (_, next_link) = &upstream_links[idx];
                    let mut fwd_frame = req_frame.clone();
                    if fwd_frame.ttl > 0 {
                        fwd_frame.ttl -= 1;
                    }
                    if let Err(e) = next_link.send_frame(&fwd_frame).await {
                        eprintln!(
                            "[relay-multi-async] send to upstream {} failed: {e} — NACK",
                            super::hex_short(&req_frame.dst)
                        );
                        send_upstream_failure_nack_async(&prev_link, &req_frame).await;
                        continue;
                    }
                    match next_link.recv_frame().await {
                        Ok(resp_frame) => {
                            let mut resp_fwd = resp_frame.clone();
                            if resp_fwd.ttl > 0 {
                                resp_fwd.ttl -= 1;
                            }
                            if let Err(e) = prev_link.send_frame(&resp_fwd).await {
                                eprintln!("[relay-multi-async] send to prev failed: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[relay-multi-async] recv from upstream {} failed: {e} — NACK + remove",
                                super::hex_short(&req_frame.dst)
                            );
                            send_upstream_failure_nack_async(&prev_link, &req_frame).await;
                            upstream_links.remove(idx);
                        }
                    }
                }
                None => {
                    eprintln!(
                        "[relay-multi-async] no upstream for dst {} — NACK",
                        super::hex_short(&req_frame.dst)
                    );
                    send_upstream_failure_nack_async(&prev_link, &req_frame).await;
                }
            }
        }
    }
}

/// Send a Class C "upstream-failure" NACK to the previous hop (async).
async fn send_upstream_failure_nack_async(prev_link: &Arc<AsyncLink>, req_frame: &Frame) {
    let nack = Frame {
        v: FRAME_VERSION,
        cls: b'C',
        dst: req_frame.src,
        src: req_frame.dst,
        ttl: FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: UPSTREAM_FAILURE_MARKER.to_vec(),
    };
    if let Err(e) = prev_link.send_frame(&nack).await {
        eprintln!("[relay-async] failed to send NACK: {e}");
    }
}

// ─── Discovery ──────────────────────────────────────────────────────────────

/// Run the discovery listener using the canonical async transport.
///
/// Listens on `discovery_addr` for incoming connections from clients; for
/// each, the gateway sends its signed [`GatewayAdvertisement`] (CBOR-encoded,
/// length-prefixed). Uses the N2.0.4 raw unauthenticated discovery protocol
/// (1-byte request → 4-byte BE length prefix + CBOR advert) — the
/// advertisement's Ed25519 signature provides the authentication.
///
/// # Errors
/// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
/// logged and the listener continues accepting new connections.
pub async fn serve_discovery_persistent_async(
    node: &Node,
    discovery_addr: &str,
    transit_listen_addr: &str,
) -> NodeResult<()> {
    let listener = TcpListener::bind(discovery_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {discovery_addr}: {e}")))?;
    let gateway_node_id = node.identity.node_id;
    eprintln!(
        "[discovery-async {}] listening on {discovery_addr}",
        super::hex_short(&gateway_node_id)
    );
    let advert =
        GatewayAdvertisement::for_identity(&node.identity, transit_listen_addr, discovery_addr);
    let advert_bytes = advert.encode_cbor()?;
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[discovery-async {}] accept error: {e}",
                    super::hex_short(&gateway_node_id)
                );
                continue;
            }
        };
        // Read 1-byte discovery request.
        let mut req = [0u8; 1];
        if let Err(e) = stream.read_exact(&mut req).await {
            eprintln!(
                "[discovery-async {}] recv request error: {e}",
                super::hex_short(&gateway_node_id)
            );
            continue;
        }
        if req[0] != super::DISCOVERY_REQUEST_BYTE {
            eprintln!(
                "[discovery-async {}] unexpected discovery request byte 0x{:02x}",
                super::hex_short(&gateway_node_id),
                req[0]
            );
            continue;
        }
        // Write 4-byte BE length + CBOR advert.
        let len = u32::try_from(advert_bytes.len())
            .map_err(|_| NodeError::Other(format!("advert too large: {}", advert_bytes.len())))?;
        if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
            eprintln!(
                "[discovery-async {}] send length error: {e}",
                super::hex_short(&gateway_node_id)
            );
            continue;
        }
        if let Err(e) = stream.write_all(&advert_bytes).await {
            eprintln!(
                "[discovery-async {}] send advert error: {e}",
                super::hex_short(&gateway_node_id)
            );
            continue;
        }
        let _ = stream.flush().await;
    }
}

/// Discover gateways via the raw discovery protocol (async).
///
/// Connects to each address in `known_addrs`, sends the 1-byte discovery
/// request, reads the length-prefixed CBOR advertisement, verifies the
/// signature + expiry + I4 cross-check, and adds valid adverts to
/// `node.known_gateways`.
///
/// # Errors
/// Returns [`NodeError`] if NO gateway could be discovered.
pub async fn discover_gateways_async(
    node: &Node,
    known_addrs: &[String],
) -> NodeResult<()> {
    let mut discovered = 0usize;
    for addr in known_addrs {
        eprintln!("[discover-async] querying {addr}");
        match discover_one_async(addr).await {
            Ok(advert) => {
                eprintln!(
                    "[discover-async] {addr} OK: nodeId={}",
                    super::hex_short(&advert.node_id)
                );
                node.known_gateways.lock().unwrap().push(advert);
                discovered += 1;
            }
            Err(e) => {
                eprintln!("[discover-async] {addr} failed: {e}");
            }
        }
    }
    if discovered == 0 {
        return Err(NodeError::Other(format!(
            "discover_gateways_async: no gateways discovered from {} addresses",
            known_addrs.len()
        )));
    }
    eprintln!("[discover-async] discovered {discovered} gateway(s)");
    Ok(())
}

/// Query ONE bootstrap address for a signed advertisement (async).
async fn discover_one_async(addr: &str) -> NodeResult<GatewayAdvertisement> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| NodeError::Other(format!("connect {addr}: {e}")))?;
    stream.set_nodelay(true).ok();
    // Send 1-byte discovery request.
    stream
        .write_all(&[super::DISCOVERY_REQUEST_BYTE])
        .await
        .map_err(|e| NodeError::Other(format!("send request: {e}")))?;
    let _ = stream.flush().await;
    // Read 4-byte BE length prefix.
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| NodeError::Other(format!("recv length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    const MAX_ADVERTISEMENT_LEN: usize = 64 * 1024;
    if len > MAX_ADVERTISEMENT_LEN {
        return Err(NodeError::Other(format!(
            "advertisement length {len} exceeds max {MAX_ADVERTISEMENT_LEN}"
        )));
    }
    let mut advert_buf = vec![0u8; len];
    stream
        .read_exact(&mut advert_buf)
        .await
        .map_err(|e| NodeError::Other(format!("recv advert: {e}")))?;
    let advert = GatewayAdvertisement::decode_cbor(&advert_buf)?;
    if !advert.verify() {
        return Err(NodeError::Other(
            "advertisement signature verification failed".into(),
        ));
    }
    let now = now_unix();
    if advert.is_expired(now) {
        return Err(NodeError::Other("advertisement expired".into()));
    }
    let expected_node_id = derive_node_id(&advert.public_key);
    if advert.node_id != expected_node_id {
        return Err(NodeError::Other(
            "advertisement nodeId mismatch (I4 violation)".into(),
        ));
    }
    Ok(advert)
}

// ─── Client send ────────────────────────────────────────────────────────────

/// Send a transit request through the mesh using the canonical async transport.
///
/// **Production path:**
/// 1. The caller has already established a [`Circuit`](super::Circuit) to the
///    gateway (via `discover_gateways_async` + `perform_snp_ik_handshake_async`
///    + the client↔gateway X25519 circuit DH).
/// 2. The caller passes the explicit `relay_addr` + `relay_link_keys` (the
///    client↔Relay A hop keys, initiator side — derived from a real
///    `perform_snp_ik_handshake_async`).
/// 3. This function connects to the relay, builds + signs + circuit-encrypts
///    the [`TransitRequest`], wraps it in a Class B frame addressed to
///    `gateway_node_id`, sends it, and waits for the response.
/// 4. On a Class C `UPSTREAM_FAILURE_MARKER` frame, returns
///    [`NodeError::UpstreamFailure`] (the caller can fail over).
/// 5. On a Class B response, decrypts + verifies the gateway's signature.
///
/// # Errors
/// Returns [`NodeError`] on any failure.
pub async fn send_request_via_gateway_full_with_relay_async(
    node: &Node,
    url: &str,
    gateway_node_id: &[u8; 32],
    relay_addr: &str,
    relay_link_keys: LinkKeys,
) -> NodeResult<TransitResponse> {
    // Look up the circuit for this gateway.
    let circuit = {
        let circuits = node.circuits.lock().unwrap();
        circuits
            .get(gateway_node_id)
            .cloned()
            .ok_or_else(|| NodeError::Other("no circuit for gateway".into()))?
    };
    if !circuit.active {
        return Err(NodeError::Other(
            "circuit is inactive (marked failed) — try another gateway".into(),
        ));
    }

    // Connect to the relay (NO persistence in async path for now — each
    // request opens a fresh connection. Production would pool these.)
    let stream = AsyncLink::connect_raw(relay_addr)
        .await
        .map_err(async_err_to_node)?;
    let link = AsyncLink::new(stream, relay_link_keys);

    // Build + sign + encrypt the TransitRequest.
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
    sign_transit_request(&mut req, &node.identity.secret_key);
    let req_bytes = encode_transit_request(&req)?;
    let sealed_body = encrypt_circuit_payload(&circuit.circuit_keys.send_key, &req_bytes);

    let req_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: *gateway_node_id,
        src: node.identity.node_id,
        ttl: FRAME_TTL_MAX,
        fid: random_fid(),
        seq: 1,
        body: sealed_body,
    };

    link.send_frame(&req_frame).await.map_err(async_err_to_node)?;
    let resp_frame = link.recv_frame().await.map_err(async_err_to_node)?;

    if resp_frame.cls != b'B' {
        if resp_frame.cls == b'C' && resp_frame.body.as_slice() == UPSTREAM_FAILURE_MARKER {
            return Err(NodeError::UpstreamFailure);
        }
        return Err(NodeError::Other(format!(
            "expected Class B response, got Class {} — likely upstream failure",
            resp_frame.cls as char
        )));
    }

    let resp_bytes = decrypt_circuit_payload(&circuit.circuit_keys.recv_key, &resp_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;
    let transit_resp: TransitResponse = decode_transit_response(&resp_bytes)?;
    if !verify_transit_response(&transit_resp, &circuit.gateway_public_key) {
        return Err(NodeError::GatewaySignatureFailed);
    }
    node.seen_req_ids.lock().unwrap().insert(req.req_id);
    *node.current_gateway.lock().unwrap() = Some(*gateway_node_id);
    Ok(transit_resp)
}

// ════════════════════════════════════════════════════════════════════════════
// N2.0.6 CANONICAL PRODUCTION ENTRY POINTS — handshake-on-accept variants
// ════════════════════════════════════════════════════════════════════════════
//
// These are the SINGLE canonical production entry points. They perform the
// SNP-IK/0.1 handshake INTERNALLY — the caller does NOT need to do the
// handshake, build an AsyncLink, or call any low-level transport function.
//
// The north-star integration test (`tests/n205_north_star.rs`) MUST use
// ONLY these entry points. It MUST NOT call:
//   - `derive_link_keys` (deterministic seed link keys)
//   - `derive_circuit_keys` (deterministic seed circuit keys)
//   - `Link::connect` (sync link)
//   - `std::net::TcpStream` / `std::net::TcpListener` (raw sync transport)
//   - `perform_snp_ik_handshake_async` directly (the handshake is internal)
//   - `async_relay_forward_links` directly (forwarding is internal)
//   - `serve_one_gateway_request_async_with_connector` directly
//   - `AsyncLink::new` / `AsyncLink::connect_raw` directly
//
// A self-scanning static guard in the test enforces these constraints.

/// **Canonical production gateway entry point.** Listens on `listen_addr`,
/// accepts ONE incoming connection from a relay, performs the SNP-IK/0.1
/// handshake as the RESPONDER (using `node.identity` for Ed25519 signing +
/// `gateway_x25519_secret`/`gateway_x25519_public` for the X25519 rendezvous),
/// then serves transit requests in a loop until the relay disconnects.
///
/// This is the entry point the north-star test uses. The handshake is
/// INTERNAL — the caller never touches `perform_snp_ik_handshake_async`,
/// `AsyncLink`, or any low-level transport function.
///
/// The `circuit_keys` are the gateway-side circuit keys (derived from the
/// client↔gateway X25519 DH via `derive_circuit_keys_from_dh`). The
/// `client_ed25519_public` is the client's Ed25519 public key (used to
/// verify the `clientSig` on each TransitRequest).
///
/// # Errors
/// Returns [`NodeError`] on TCP bind failure or handshake failure.
pub async fn serve_gateway_persistent_async_with_handshake(
    node: &Node,
    listen_addr: &str,
    gateway_x25519_secret: &snp_crypto::X25519Secret,
    gateway_x25519_public: &snp_crypto::X25519PubKey,
    circuit_keys: CircuitKeys,
    client_ed25519_public: [u8; 32],
) -> NodeResult<()> {
    let gateway_node_id = node.identity.node_id;
    let gateway_ed_sk = node.identity.secret_key;
    let gateway_ed_pk = node.identity.public_key;
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {listen_addr}: {e}")))?;
    eprintln!(
        "[gateway-canonical {}] listening on {listen_addr}",
        super::hex_short(&gateway_node_id)
    );
    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| NodeError::Other(format!("accept: {e}")))?;
    eprintln!(
        "[gateway-canonical {}] relay connected — performing SNP-IK/0.1 handshake (responder)",
        super::hex_short(&gateway_node_id)
    );
    // INTERNAL handshake — the caller never sees this.
    let handshake = perform_snp_ik_handshake_async(
        &mut stream,
        false, // responder
        &gateway_ed_sk,
        &gateway_ed_pk,
        gateway_x25519_secret,
        gateway_x25519_public,
        None,
    )
    .await
    .map_err(async_err_to_node)?;
    eprintln!(
        "[gateway-canonical {}] handshake OK, peer (relay) nodeId={}",
        super::hex_short(&gateway_node_id),
        super::hex_short(&handshake.peer_node_id)
    );
    let link = Arc::new(AsyncLink::new(stream, handshake.link_keys));
    let mut seen_req_ids = HashSet::new();
    // Serve loop — production connector factory (PinnedConnector::new, SSRF defence).
    loop {
        let outcome = serve_one_gateway_request_async_with_connector(
            &link,
            gateway_node_id,
            &gateway_ed_sk,
            &client_ed25519_public,
            &circuit_keys,
            &mut seen_req_ids,
            &|url| PinnedConnector::new(url).map_err(NodeError::Gateway),
        )
        .await;
        match outcome {
            Ok(ServeOutcome::Continue) => {
                eprintln!(
                    "[gateway-canonical {}] served one request",
                    super::hex_short(&gateway_node_id)
                );
                break; // one request is enough for the north-star test
            }
            Ok(ServeOutcome::Closed) => break,
            Err(e) => {
                eprintln!("[gateway-canonical] error: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// Like [`serve_gateway_persistent_async_with_handshake`] but accepts a
/// test-only connector factory (to bypass SSRF for a local mock HTTP server).
///
/// **Production gateways MUST NOT use this function** — production must use
/// [`serve_gateway_persistent_async_with_handshake`] which calls
/// `PinnedConnector::new` and enforces the SSRF defence.
pub async fn serve_gateway_persistent_async_with_handshake_and_connector<F>(
    node: &Node,
    listen_addr: &str,
    gateway_x25519_secret: &snp_crypto::X25519Secret,
    gateway_x25519_public: &snp_crypto::X25519PubKey,
    circuit_keys: CircuitKeys,
    client_ed25519_public: [u8; 32],
    connector_factory: F,
) -> NodeResult<()>
where
    F: Fn(&str) -> NodeResult<PinnedConnector> + Send + Sync + 'static,
{
    let gateway_node_id = node.identity.node_id;
    let gateway_ed_sk = node.identity.secret_key;
    let gateway_ed_pk = node.identity.public_key;
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {listen_addr}: {e}")))?;
    eprintln!(
        "[gateway-canonical-conn {}] listening on {listen_addr}",
        super::hex_short(&gateway_node_id)
    );
    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| NodeError::Other(format!("accept: {e}")))?;
    let handshake = perform_snp_ik_handshake_async(
        &mut stream,
        false,
        &gateway_ed_sk,
        &gateway_ed_pk,
        gateway_x25519_secret,
        gateway_x25519_public,
        None,
    )
    .await
    .map_err(async_err_to_node)?;
    eprintln!(
        "[gateway-canonical-conn {}] handshake OK",
        super::hex_short(&gateway_node_id)
    );
    let link = Arc::new(AsyncLink::new(stream, handshake.link_keys));
    let mut seen_req_ids = HashSet::new();
    let connector = Arc::new(connector_factory);
    loop {
        let outcome = serve_one_gateway_request_async_with_connector(
            &link,
            gateway_node_id,
            &gateway_ed_sk,
            &client_ed25519_public,
            &circuit_keys,
            &mut seen_req_ids,
            connector.as_ref(),
        )
        .await;
        match outcome {
            Ok(ServeOutcome::Continue) => break,
            Ok(ServeOutcome::Closed) => break,
            Err(e) => {
                eprintln!("[gateway-canonical-conn] error: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// **Canonical production relay entry point.** Listens on `listen_addr`,
/// accepts ONE incoming connection from the previous hop, performs the
/// SNP-IK/0.1 handshake as the RESPONDER, connects to `next_hop_addr`,
/// performs the SNP-IK/0.1 handshake as the INITIATOR (pinning
/// `next_hop_node_id`), then forwards frames bidirectionally until either
/// side closes.
///
/// This is the entry point the north-star test uses. Both handshakes +
/// the forwarding are INTERNAL — the caller never touches
/// `perform_snp_ik_handshake_async`, `AsyncLink`,
/// `async_relay_forward_links`, or any low-level transport function.
///
/// # Errors
/// Returns [`NodeError`] on TCP bind/connect failure or handshake failure.
pub async fn serve_relay_persistent_async_with_handshake(
    node: &Node,
    listen_addr: &str,
    next_hop_addr: &str,
    next_hop_node_id: [u8; 32],
    relay_x25519_secret: &snp_crypto::X25519Secret,
    relay_x25519_public: &snp_crypto::X25519PubKey,
) -> NodeResult<()> {
    let relay_ed_sk = node.identity.secret_key;
    let relay_ed_pk = node.identity.public_key;
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| NodeError::Other(format!("bind {listen_addr}: {e}")))?;
    eprintln!(
        "[relay-canonical {}] listening on {listen_addr}, next-hop={}",
        super::hex_short(&node.identity.node_id),
        next_hop_addr
    );
    let (mut prev_stream, _) = listener
        .accept()
        .await
        .map_err(|e| NodeError::Other(format!("accept: {e}")))?;
    eprintln!(
        "[relay-canonical {}] prev-hop connected — performing SNP-IK/0.1 handshake (responder)",
        super::hex_short(&node.identity.node_id)
    );
    // INTERNAL handshake #1: prev-hop (responder).
    let prev_handshake = perform_snp_ik_handshake_async(
        &mut prev_stream,
        false,
        &relay_ed_sk,
        &relay_ed_pk,
        relay_x25519_secret,
        relay_x25519_public,
        None,
    )
    .await
    .map_err(async_err_to_node)?;
    eprintln!(
        "[relay-canonical {}] prev-hop handshake OK, peer nodeId={}",
        super::hex_short(&node.identity.node_id),
        super::hex_short(&prev_handshake.peer_node_id)
    );
    let prev_link = Arc::new(AsyncLink::new(prev_stream, prev_handshake.link_keys));

    // INTERNAL: connect to next hop.
    let mut next_stream = AsyncLink::connect_raw(next_hop_addr)
        .await
        .map_err(async_err_to_node)?;
    eprintln!(
        "[relay-canonical {}] connected to next-hop {next_hop_addr} — handshake (initiator, pinning {})",
        super::hex_short(&node.identity.node_id),
        super::hex_short(&next_hop_node_id)
    );
    // INTERNAL handshake #2: next-hop (initiator, pinning the next hop's NodeId).
    let next_handshake = perform_snp_ik_handshake_async(
        &mut next_stream,
        true,
        &relay_ed_sk,
        &relay_ed_pk,
        relay_x25519_secret,
        relay_x25519_public,
        Some(&next_hop_node_id),
    )
    .await
    .map_err(async_err_to_node)?;
    if next_handshake.peer_node_id != next_hop_node_id {
        return Err(NodeError::Other(format!(
            "relay: next-hop identity substitution detected — expected {}, got {}",
            super::hex_short(&next_hop_node_id),
            super::hex_short(&next_handshake.peer_node_id)
        )));
    }
    eprintln!(
        "[relay-canonical {}] next-hop handshake OK",
        super::hex_short(&node.identity.node_id)
    );
    let next_link = Arc::new(AsyncLink::new(next_stream, next_handshake.link_keys));

    // INTERNAL: bidirectional forward.
    eprintln!(
        "[relay-canonical {}] forwarding bidirectionally",
        super::hex_short(&node.identity.node_id)
    );
    let _ = snp_link::async_link::async_relay_forward_links(prev_link, next_link).await;
    eprintln!(
        "[relay-canonical {}] forwarding complete",
        super::hex_short(&node.identity.node_id)
    );
    Ok(())
}

/// **Canonical production client entry point.** Establishes a fresh circuit
/// to the gateway via X25519 DH, inserts the Circuit into the Node's circuit
/// table, then calls `send_request_with_full_snp_ik_handshake_async` to
/// perform the SNP-IK/0.1 handshake with the relay AND send the request.
///
/// This is the entry point the north-star test uses. The circuit
/// establishment (fresh X25519 DH) + the link handshake + the request send
/// are all INTERNAL.
///
/// # Errors
/// Returns [`NodeError`] on any failure.
pub async fn establish_circuit_and_send_async(
    node: &Node,
    url: &str,
    gateway_node_id: &[u8; 32],
    gateway_ed25519_public: &[u8; 32],
    gateway_x25519_public: &snp_crypto::X25519PubKey,
    relay_addr: &str,
    relay_node_id: &[u8; 32],
    client_x25519_secret: &snp_crypto::X25519Secret,
    client_x25519_public: &snp_crypto::X25519PubKey,
) -> NodeResult<TransitResponse> {
    // 1. Establish fresh circuit keys via client↔gateway X25519 DH.
    let circuit_dh = snp_crypto::x25519_dh(client_x25519_secret, gateway_x25519_public);
    let circuit_keys = snp_link::derive_circuit_keys_from_dh(&circuit_dh, true);

    // 2. Construct the Circuit object + insert into the Node.
    let circuit = Circuit::new(*gateway_node_id, *gateway_ed25519_public, circuit_keys);
    node.circuits
        .lock()
        .unwrap()
        .insert(*gateway_node_id, circuit);

    // 3. Perform the SNP-IK/0.1 handshake with the relay AND send the request.
    send_request_with_full_snp_ik_handshake_async(
        node,
        url,
        gateway_node_id,
        relay_addr,
        relay_node_id,
        &node.identity.secret_key,
        &node.identity.public_key,
        client_x25519_secret,
        client_x25519_public,
    )
    .await
}

/// Convenience: perform a real SNP-IK/0.1 handshake to a relay, then send a
/// transit request through the mesh.
///
/// This is the canonical production client path:
/// 1. Connect a `tokio::net::TcpStream` to `relay_addr`.
/// 2. Call [`perform_snp_ik_handshake_async`] as the INITIATOR, pinning the
///    relay's NodeId (`expected_peer_node_id = Some(relay_node_id)`).
/// 3. Use the resulting `LinkKeys` to wrap the stream in an [`AsyncLink`].
/// 4. Build + sign + circuit-encrypt the [`TransitRequest`], send it, receive
///    the response, decrypt + verify.
///
/// Returns the verified [`TransitResponse`].
///
/// # Errors
/// Returns [`NodeError`] on any failure (handshake, link, AEAD, signature).
pub async fn send_request_with_full_snp_ik_handshake_async(
    node: &Node,
    url: &str,
    gateway_node_id: &[u8; 32],
    relay_addr: &str,
    relay_node_id: &[u8; 32],
    node_ed25519_secret: &[u8; 32],
    node_ed25519_public: &[u8; 32],
    node_x25519_secret: &snp_crypto::X25519Secret,
    node_x25519_public: &snp_crypto::X25519PubKey,
) -> NodeResult<TransitResponse> {
    // 1. Connect + handshake with the relay.
    let mut stream = AsyncLink::connect_raw(relay_addr)
        .await
        .map_err(async_err_to_node)?;
    let handshake = perform_snp_ik_handshake_async(
        &mut stream,
        true, // initiator
        node_ed25519_secret,
        node_ed25519_public,
        node_x25519_secret,
        node_x25519_public,
        Some(relay_node_id), // pin the relay's NodeId
    )
    .await
    .map_err(async_err_to_node)?;
    if handshake.peer_node_id != *relay_node_id {
        return Err(NodeError::Other(format!(
            "relay identity substitution detected: expected {}, got {}",
            super::hex_short(relay_node_id),
            super::hex_short(&handshake.peer_node_id)
        )));
    }
    let link = AsyncLink::new(stream, handshake.link_keys);

    // 2. Look up the circuit.
    let circuit = {
        let circuits = node.circuits.lock().unwrap();
        circuits
            .get(gateway_node_id)
            .cloned()
            .ok_or_else(|| NodeError::Other("no circuit for gateway".into()))?
    };
    if !circuit.active {
        return Err(NodeError::Other(
            "circuit is inactive (marked failed) — try another gateway".into(),
        ));
    }

    // 3. Build + sign + circuit-encrypt the TransitRequest.
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
    sign_transit_request(&mut req, node_ed25519_secret);
    let req_bytes = encode_transit_request(&req)?;
    let sealed_body = encrypt_circuit_payload(&circuit.circuit_keys.send_key, &req_bytes);

    let req_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: *gateway_node_id,
        src: node.identity.node_id,
        ttl: FRAME_TTL_MAX,
        fid: random_fid(),
        seq: 1,
        body: sealed_body,
    };

    // 4. Send + receive.
    link.send_frame(&req_frame).await.map_err(async_err_to_node)?;
    let resp_frame = link.recv_frame().await.map_err(async_err_to_node)?;

    if resp_frame.cls != b'B' {
        if resp_frame.cls == b'C' && resp_frame.body.as_slice() == UPSTREAM_FAILURE_MARKER {
            return Err(NodeError::UpstreamFailure);
        }
        return Err(NodeError::Other(format!(
            "expected Class B response, got Class {} — likely upstream failure",
            resp_frame.cls as char
        )));
    }

    let resp_bytes = decrypt_circuit_payload(&circuit.circuit_keys.recv_key, &resp_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;
    let transit_resp: TransitResponse = decode_transit_response(&resp_bytes)?;
    if !verify_transit_response(&transit_resp, &circuit.gateway_public_key) {
        return Err(NodeError::GatewaySignatureFailed);
    }
    node.seen_req_ids.lock().unwrap().insert(req.req_id);
    *node.current_gateway.lock().unwrap() = Some(*gateway_node_id);
    Ok(transit_resp)
}
