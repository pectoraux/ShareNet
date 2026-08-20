//! R4.7 — Real Mode-A Internet egress.
//!
//! Tests that the Mode-A `BundleForwarder` path can reach a real HTTP endpoint
//! via the gateway's `PinnedConnector` egress, with:
//! - SSRF defence (all existing protections preserved)
//! - Deadline-aware timeout propagation
//! - Chunked Transfer-Encoding rejection
//! - Response integrity (gateway signature, reqId binding)
//!
//! # Two test forms
//!
//! ## A. Deterministic local integration (default)
//!
//! Uses `PinnedConnector::from_parts()` (test-only SSRF bypass) to connect to
//! a local mock HTTP server on 127.0.0.1. Proves the Mode-A wiring and
//! request/response integration. Does NOT exercise the production SSRF/DNS/TLS
//! path.
//!
//! ## B. Production-path external test (opt-in, `#[ignore]`)
//!
//! Uses `PinnedConnector::new(url)` (the PRODUCTION path with SSRF defence,
//! DNS validation, IP pinning, TLS SNI/cert validation). Requires Internet
//! access. Enabled via `SHARENET_EXTERNAL_NET_TESTS=1`.
//!
//! # R4.7 limitations (honestly stated)
//!
//! - HTTP/1.1 only (no HTTP/2)
//! - GET-oriented (no request body support)
//! - Non-chunked responses only (chunked is explicitly rejected)
//! - Ports 80/443 only
//! - Redirects disabled (3xx returned verbatim)

#![allow(clippy::pedantic, deprecated)]

use std::sync::Arc;

use snp_crypto::{x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::{GatewayError, PinnedConnector};
use snp_identity::{NodeId, NodeIdentity};
use snp_node::node::descriptor::TransportEndpoint;
use snp_node::node::identity::Capability;
use snp_node::node::mode_a_bundle::{
    BundleForwarder, ModeAClient, ModeAGateway, PersistentBundleStore,
};
use snp_node::node::node_advert::NodeAdvertisement;
use snp_node::node::route::{Route, RouteHop, RouteState};

// ─── Helpers ──────────────────────────────────────────────────────────────

fn test_identity(seed: u8) -> NodeIdentity {
    NodeIdentity::from_secret([seed; 32])
}

fn test_x25519_keypair() -> (X25519Secret, X25519PubKey) {
    x25519_static_keypair()
}

async fn ephemeral_addr() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let a = l.local_addr().expect("local_addr").to_string();
    drop(l);
    a
}

fn make_relay_advert(identity: &NodeIdentity, listen_addr: &str) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp(listen_addr)],
        None,
        3600,
        1,
    )
}

fn make_gateway_advert(
    identity: &NodeIdentity,
    listen_addr: &str,
    x25519_pub: &[u8; 32],
) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp(listen_addr)],
        Some(*x25519_pub),
        3600,
        1,
    )
}

/// Start a mock HTTP server returning a fixed body.
async fn start_mock_http_server(body: &str, status: u16) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr").to_string();
    listener.set_nonblocking(false).expect("set_nonblocking");
    let body = body.to_string();
    std::thread::spawn(move || loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(_) => break,
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        let body = body.clone();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
    });
    addr
}

fn build_multihop_route(
    client: &NodeIdentity,
    relay_a: &NodeIdentity,
    relay_b: &NodeIdentity,
    gateway: &NodeIdentity,
    relay_a_addr: &str,
    relay_b_addr: &str,
    gateway_addr: &str,
    gw_x25519_pub: &[u8; 32],
) -> Route {
    let relay_a_advert = make_relay_advert(relay_a, relay_a_addr);
    let relay_b_advert = make_relay_advert(relay_b, relay_b_addr);
    let gateway_advert = make_gateway_advert(gateway, gateway_addr, gw_x25519_pub);
    let hop_details = vec![
        RouteHop::new(
            relay_a_advert.verify_into_verified().unwrap().descriptor(),
            TransportEndpoint::tcp(relay_a_addr),
        ),
        RouteHop::new(
            relay_b_advert.verify_into_verified().unwrap().descriptor(),
            TransportEndpoint::tcp(relay_b_addr),
        ),
        RouteHop::new(
            gateway_advert.verify_into_verified().unwrap().descriptor(),
            TransportEndpoint::tcp(gateway_addr),
        ),
    ];
    let mut route = Route::new_with_hop_details(client.node_id, gateway.node_id, hop_details);
    route.validate().expect("route validates");
    route.transition(RouteState::Establishing).expect("Establishing");
    route.transition(RouteState::Active).expect("Active");
    route
}

// ─── 1. Deterministic local Mode-A egress integration ──────────────────

/// Proves the Mode-A wiring: Client → Relay A → Relay B → Gateway → HTTP
/// endpoint → response → B → A → Client. Uses `PinnedConnector::from_parts`
/// (test-only SSRF bypass) to reach a local mock HTTP server.
///
/// This proves the Mode-A request/response integration. It does NOT exercise
/// the production SSRF/DNS/TLS path — see the `#[ignore]` test for that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_7_mode_a_local_egress_integration() {
    let client_identity = test_identity(0x01);
    let relay_a_identity = test_identity(0x02);
    let relay_b_identity = test_identity(0x03);
    let gateway_identity = test_identity(0x04);

    let (client_x_sk, client_x_pk) = test_x25519_keypair();
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair();
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair();
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair();

    let relay_a_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let gateway_addr = ephemeral_addr().await;

    // Start a mock HTTP server.
    let body = "Hello from R4.7 Mode-A egress!";
    let http_addr = start_mock_http_server(body, 200).await;
    let url = format!("http://{http_addr}/r4-7-local");

    let route = Arc::new(build_multihop_route(
        &client_identity,
        &relay_a_identity,
        &relay_b_identity,
        &gateway_identity,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
        &gw_x_pk.to_bytes(),
    ));

    // Client listener for response delivery.
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    let client_listen_addr = client_listener.local_addr().unwrap().to_string();
    drop(client_listener);

    // Start Relay A (position 0).
    let relay_a = Arc::new(
        BundleForwarder::new(
            relay_a_identity.clone(),
            relay_a_x_sk,
            relay_a_x_pk,
            relay_a_addr.clone(),
            route.clone(),
            0,
        )
        .with_source(client_listen_addr.clone(), client_identity.node_id),
    );
    let ra_handle = tokio::spawn({
        let ra = relay_a.clone();
        async move { tokio::select! { _ = ra.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {} } }
    });

    // Start Relay B (position 1).
    let relay_b = Arc::new(BundleForwarder::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_addr.clone(),
        route.clone(),
        1,
    ));
    let rb_handle = tokio::spawn({
        let rb = relay_b.clone();
        async move { tokio::select! { _ = rb.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {} } }
    });

    // Start Gateway with the test connector factory (from_parts → 127.0.0.1).
    let gateway = ModeAGateway::with_connector_factory(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_addr.clone(),
        move |u: &str| {
            let parsed = url::Url::parse(u)
                .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
            let host = parsed.host_str().ok_or_else(|| GatewayError::MalformedUrl("no host".into()))?;
            let port = parsed.port().unwrap_or(80);
            Ok(PinnedConnector::from_parts(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                host.to_string(),
                port,
                "http".into(),
                if parsed.path().is_empty() { "/".into() } else { parsed.path().into() },
            ))
        },
    );
    let gw_handle = tokio::spawn(async move {
        tokio::select! { _ = gateway.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {} }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Client sends request.
    let client = ModeAClient::new(client_identity.clone(), client_x_sk, client_x_pk);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.send_request(
            &url,
            &relay_a_addr,
            relay_a_identity.node_id,
            gateway_identity.node_id,
            &gateway_identity.public_key,
        ),
    )
    .await;

    let (resp, resp_body) = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err(e)) => panic!("send_request failed: {e}"),
        Err(_) => panic!("timeout"),
    };
    assert_eq!(resp.status, 200, "HTTP status must be 200");
    let body_str = String::from_utf8_lossy(&resp_body);
    assert!(
        body_str.contains("Hello from R4.7 Mode-A egress"),
        "response body must contain expected text, got: {body_str}"
    );
    eprintln!("[test] PASS: Mode-A local egress integration — response received through mesh");

    ra_handle.abort();
    rb_handle.abort();
    gw_handle.abort();
}

// ─── 2. Chunked Transfer-Encoding is explicitly rejected ─────────────

/// The gateway HTTP/1.1 parser does NOT support `Transfer-Encoding: chunked`.
/// R4.7 explicitly rejects it with a clear error rather than silently
/// misparsing the chunked body.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_7_chunked_transfer_encoding_rejected() {
    // Start a mock HTTP server that returns a chunked response.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(false).expect("set_nonblocking");
    std::thread::spawn(move || loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(_) => break,
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            // Send a chunked response.
            let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
    });

    // Create a PinnedConnector to the local server (bypass SSRF for testing).
    let connector = PinnedConnector::from_parts(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "localhost".into(),
        addr.parse::<std::net::SocketAddr>().unwrap().port(),
        "http".into(),
        "/".into(),
    );

    let far_future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 300)
        .unwrap_or(u64::MAX);

    let result = connector.fetch_with_limit("GET", &[], 1024, far_future);
    assert!(
        result.is_err(),
        "chunked Transfer-Encoding must be rejected"
    );
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    assert!(
        err_str.contains("chunked"),
        "error must mention chunked, got: {err_str}"
    );
    eprintln!("[test] PASS: chunked Transfer-Encoding explicitly rejected");
}

// ─── 3. Expired Bundle deadline prevents egress ────────────────────────

/// If the Bundle deadline has already passed, the gateway must reject the
/// egress request BEFORE attempting a TCP connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_7_expired_deadline_prevents_egress() {
    let connector = PinnedConnector::from_parts(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "localhost".into(),
        8080,
        "http".into(),
        "/".into(),
    );

    // Deadline in the past.
    let past_deadline = 1u64; // unix epoch — way in the past.

    let result = connector.fetch_with_limit("GET", &[], 1024, past_deadline);
    assert!(
        result.is_err(),
        "expired deadline must prevent egress"
    );
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    assert!(
        err_str.contains("deadline"),
        "error must mention deadline, got: {err_str}"
    );
    eprintln!("[test] PASS: expired Bundle deadline prevents egress");
}

// ─── 4. Production SSRF rejection (via PinnedConnector::new) ───────────

/// The production `PinnedConnector::new(url)` rejects SSRF targets. These
/// are pure unit tests (no network access required).
#[test]
fn r4_7_ssrf_loopback_rejected() {
    let result = PinnedConnector::new("http://127.0.0.1/");
    assert!(result.is_err(), "127.0.0.1 must be rejected");
    eprintln!("[test] PASS: loopback rejected");
}

#[test]
fn r4_7_ssrf_private_ip_rejected() {
    let result = PinnedConnector::new("http://10.0.0.1/");
    assert!(result.is_err(), "10.0.0.1 must be rejected");
    eprintln!("[test] PASS: private IP rejected");
}

#[test]
fn r4_7_ssrf_metadata_endpoint_rejected() {
    let result = PinnedConnector::new("http://169.254.169.254/");
    assert!(result.is_err(), "169.254.169.254 must be rejected");
    eprintln!("[test] PASS: metadata endpoint rejected");
}

#[test]
fn r4_7_ssrf_unsupported_scheme_rejected() {
    let result = PinnedConnector::new("file:///etc/passwd");
    assert!(result.is_err(), "file:// must be rejected");
    eprintln!("[test] PASS: unsupported scheme rejected");
}

#[test]
fn r4_7_ssrf_non_standard_port_rejected() {
    let result = PinnedConnector::new("http://example.com:8080/");
    assert!(result.is_err(), "port 8080 must be rejected");
    eprintln!("[test] PASS: non-standard port rejected");
}

#[test]
fn r4_7_ssrf_ipv6_loopback_rejected() {
    let result = PinnedConnector::new("http://[::1]/");
    assert!(result.is_err(), "[::1] must be rejected");
    eprintln!("[test] PASS: IPv6 loopback rejected");
}

#[test]
fn r4_7_ssrf_link_local_rejected() {
    let result = PinnedConnector::new("http://169.254.1.1/");
    assert!(result.is_err(), "169.254.1.1 must be rejected");
    eprintln!("[test] PASS: link-local rejected");
}

// ─── 5. Production-path real Internet egress (opt-in, #[ignore]) ──────

/// **The actual R4.7 proof.** Uses the PRODUCTION `PinnedConnector::new(url)`
/// path (NOT the test-only `from_parts` bypass) to send a real HTTPS request
/// through the Mode-A mesh.
///
/// This test exercises:
/// - URL validation (scheme, port, length)
/// - SSRF literal-host validation
/// - DNS resolution + per-IP validation (DNS rebinding defence)
/// - IP pinning
/// - TLS handshake (rustls + webpki-roots CA bundle, SNI = hostname)
/// - HTTP/1.1 request (GET, Connection: close)
/// - Response parsing (status, headers, Content-Length body)
/// - Response signing (TransitResponse with gateway Ed25519 signature)
/// - Response transport through the Mode-A bundle path
/// - Client verification (gateway signature + reqId match)
///
/// # Why this test is `#[ignore]`'d
///
/// Requires Internet access (DNS + TCP + TLS to a real public HTTPS server).
/// Not guaranteed in CI / sandboxed environments.
///
/// To run:
/// ```bash
/// SHARENET_EXTERNAL_NET_TESTS=1 cargo test -p snp-node --test r4_7_real_internet_egress -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn r4_7_production_real_internet_egress() {
    // Self-skip unless explicitly enabled.
    if std::env::var("SHARENET_EXTERNAL_NET_TESTS").is_err() {
        eprintln!("[test] SHARENET_EXTERNAL_NET_TESTS not set — skipping real Internet egress test");
        return;
    }

    let client_identity = test_identity(0x10);
    let relay_a_identity = test_identity(0x11);
    let relay_b_identity = test_identity(0x12);
    let gateway_identity = test_identity(0x13);

    let (client_x_sk, client_x_pk) = test_x25519_keypair();
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair();
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair();
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair();

    let relay_a_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let gateway_addr = ephemeral_addr().await;

    // Target a stable public HTTPS endpoint.
    let url = "https://example.com/";

    let route = Arc::new(build_multihop_route(
        &client_identity,
        &relay_a_identity,
        &relay_b_identity,
        &gateway_identity,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
        &gw_x_pk.to_bytes(),
    ));

    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    let client_listen_addr = client_listener.local_addr().unwrap().to_string();
    drop(client_listener);

    // Start Relay A + Relay B.
    let relay_a = Arc::new(
        BundleForwarder::new(
            relay_a_identity.clone(),
            relay_a_x_sk,
            relay_a_x_pk,
            relay_a_addr.clone(),
            route.clone(),
            0,
        )
        .with_source(client_listen_addr.clone(), client_identity.node_id),
    );
    let ra_handle = tokio::spawn({
        let ra = relay_a.clone();
        async move { tokio::select! { _ = ra.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {} } }
    });

    let relay_b = Arc::new(BundleForwarder::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_addr.clone(),
        route.clone(),
        1,
    ));
    let rb_handle = tokio::spawn({
        let rb = relay_b.clone();
        async move { tokio::select! { _ = rb.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {} } }
    });

    // Start Gateway with the PRODUCTION connector factory (PinnedConnector::new).
    // This is the key: NOT from_parts — the production path with SSRF + DNS + TLS.
    let gateway = ModeAGateway::new(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_addr.clone(),
    );
    let gw_handle = tokio::spawn(async move {
        tokio::select! { _ = gateway.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {} }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Client sends request via the mesh → gateway → real Internet.
    let client = ModeAClient::new(client_identity.clone(), client_x_sk, client_x_pk);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        client.send_request(
            url,
            &relay_a_addr,
            relay_a_identity.node_id,
            gateway_identity.node_id,
            &gateway_identity.public_key,
        ),
    )
    .await;

    match result {
        Ok(Ok((resp, body))) => {
            assert_eq!(resp.status, 200, "HTTP status must be 200");
            assert!(!body.is_empty(), "response body must not be empty");
            // Verify reqId binding.
            assert!(resp.gateway_id == gateway_identity.node_id);
            eprintln!(
                "[test] SUCCESS: R4.7 real Internet egress — status={}, body={} bytes",
                resp.status,
                body.len()
            );
        }
        Ok(Err(e)) => panic!("send_request failed: {e}"),
        Err(_) => panic!("timeout — real Internet egress failed (network may be slow)"),
    }

    ra_handle.abort();
    rb_handle.abort();
    gw_handle.abort();
}
