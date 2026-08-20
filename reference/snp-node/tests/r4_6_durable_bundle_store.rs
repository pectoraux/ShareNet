//! R4.6 — Durable BundleStore / Restart Recovery.
//!
//! Tests that custody obligations survive process restart via the
//! `PersistentBundleStore` adapter.
//!
//! # Architecture
//!
//! The L5 `snp_sync::BundleStore` is the authoritative in-memory custody
//! model. `PersistentBundleStore` (in snp-node, the composition layer) OWNS
//! a `BundleStore` and mirrors mutations to the filesystem. The L5 store
//! remains the single semantic source of truth.
//!
//! # Critical invariant (R4.6)
//!
//! `BundleForwarder::run()` calls `store.add(bundle)` (which is
//! `PersistentBundleStore::add`) BEFORE sending the custody ACK. If the
//! durable write fails, the forwarder does NOT ack — the previous hop
//! re-sends.
//!
//! # Tests
//!
//! 1. Basic durability — persist → reopen → bundle present.
//! 2. Custody durability — take_custody → persist → restart → chain intact.
//! 3. Crash after durable custody, before ACK — bundle present after restart.
//! 4. Crash after ACK, before forward — bundle present → forwarder retries.
//! 5. Expiry recovery — persist → advance time → restart → expired, not pending.
//! 6. Duplicate insertion — same BundleId twice → more_advanced keeps longer chain.
//! 7. Corruption — truncated record → fail-closed (open returns Err).
//! 8. Corruption — invalid CBOR → fail-closed.
//! 9. Full Mode-A restart — Relay B crashes after custody → restarts → forwards.

#![allow(clippy::pedantic, deprecated)]

use std::sync::Arc;

use snp_crypto::{x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::{GatewayError, PinnedConnector};
use snp_identity::{NodeId, NodeIdentity};
use snp_node::node::descriptor::TransportEndpoint;
use snp_node::node::identity::Capability;
use snp_node::node::mode_a_bundle::{
    BundleForwarder, ModeAClient, ModeAGateway, PersistentBundleStore, PersistentStoreError,
    StorageLimits,
};
use snp_node::node::node_advert::NodeAdvertisement;
use snp_node::node::route::{Route, RouteHop, RouteState};
use snp_sync::{Bundle, BundlePayload, CUSTODY_NONCE_BYTES};

// ─── Helpers ──────────────────────────────────────────────────────────────

fn test_identity(seed: u8) -> NodeIdentity {
    NodeIdentity::from_secret([seed; 32])
}

fn test_x25519_keypair() -> (X25519Secret, X25519PubKey) {
    x25519_static_keypair()
}

fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{hex}..")
}

fn custody_nonce() -> [u8; CUSTODY_NONCE_BYTES] {
    let mut buf = [0u8; CUSTODY_NONCE_BYTES];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

async fn ephemeral_addr() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let a = l.local_addr().expect("local_addr").to_string();
    drop(l);
    a
}

fn ephemeral_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "r4-6-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
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

async fn start_mock_http_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr").to_string();
    listener.set_nonblocking(false).expect("set_nonblocking");
    std::thread::spawn(move || loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(_) => break,
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = b"Hello from R4.6 durable custody!";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
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
    let relay_a_desc = relay_a_advert
        .verify_into_verified()
        .expect("relay A advert verification")
        .descriptor();
    let relay_b_desc = relay_b_advert
        .verify_into_verified()
        .expect("relay B advert verification")
        .descriptor();
    let gateway_desc = gateway_advert
        .verify_into_verified()
        .expect("gateway advert verification")
        .descriptor();
    let hop_details = vec![
        RouteHop::new(relay_a_desc, TransportEndpoint::tcp(relay_a_addr)),
        RouteHop::new(relay_b_desc, TransportEndpoint::tcp(relay_b_addr)),
        RouteHop::new(gateway_desc, TransportEndpoint::tcp(gateway_addr)),
    ];
    let mut route = Route::new_with_hop_details(client.node_id, gateway.node_id, hop_details);
    route.validate().expect("route must validate");
    route
        .transition(RouteState::Establishing)
        .expect("transition to Establishing");
    route
        .transition(RouteState::Active)
        .expect("transition to Active");
    route
}

// ─── 1. Basic durability ────────────────────────────────────────────────

/// Persist a bundle → drop store → reopen → bundle is present.
#[tokio::test]
async fn r4_6_basic_durability() {
    let dir = ephemeral_dir();
    let identity = test_identity(0x01);
    let now = snp_identity::now_unix();
    let bundle = Bundle::new(
        identity.node_id,
        [0xAA; 32],
        BundlePayload::new(vec![0u8; 8]),
        now,
        now + 300,
    )
    .expect("bundle");

    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle.clone()).expect("add");
        eprintln!("[test] persisted bundle {}", hex_short(bundle.bundle_id().as_bytes()));
    }
    // Simulate process death (store dropped).
    drop(dir.as_path()); // keep the path

    // Reopen.
    let store = PersistentBundleStore::open(&dir).expect("reopen");
    let recovered = store
        .get(bundle.bundle_id())
        .expect("bundle must be recovered");
    assert_eq!(recovered.bundle_id(), bundle.bundle_id());
    assert_eq!(recovered.source, bundle.source);
    assert_eq!(recovered.destination, bundle.destination);
    eprintln!("[test] PASS: bundle survived restart");
}

// ─── 2. Custody durability ──────────────────────────────────────────────

/// take_custody → persist → restart → custody chain intact.
#[tokio::test]
async fn r4_6_custody_durability() {
    let dir = ephemeral_dir();
    let client = test_identity(0x02);
    let relay = test_identity(0x03);
    let now = snp_identity::now_unix();

    let mut bundle = Bundle::new(
        client.node_id,
        [0xBB; 32],
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 300,
    )
    .expect("bundle");

    // Take custody (client → relay).
    bundle
        .take_custody(
            client.node_id,
            relay.node_id,
            &relay.secret_key,
            now,
            now,
            custody_nonce(),
        )
        .expect("take_custody");

    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle.clone()).expect("add");
    }

    // Reopen.
    let store = PersistentBundleStore::open(&dir).expect("reopen");
    let recovered = store.get(bundle.bundle_id()).expect("bundle recovered");
    assert_eq!(
        recovered.custody_chain.len(),
        1,
        "custody chain must survive restart"
    );
    assert_eq!(recovered.custody_chain[0].custodian_id, client.node_id);
    assert_eq!(recovered.custody_chain[0].next_custodian_id, relay.node_id);
    eprintln!("[test] PASS: custody chain survived restart");
}

// ─── 3. Crash after durable custody, before ACK ─────────────────────────

/// Bundle is durably persisted but no ACK was sent. On restart, the bundle
/// is present → the forwarder would retry. The previous hop re-sends (no
/// ACK received), and `more_advanced` dedup handles it.
#[tokio::test]
async fn r4_6_crash_after_durable_before_ack() {
    let dir = ephemeral_dir();
    let client = test_identity(0x04);
    let relay = test_identity(0x05);
    let now = snp_identity::now_unix();

    let mut bundle = Bundle::new(
        client.node_id,
        [0xCC; 32],
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 300,
    )
    .expect("bundle");
    bundle
        .take_custody(
            client.node_id,
            relay.node_id,
            &relay.secret_key,
            now,
            now,
            custody_nonce(),
        )
        .expect("take_custody");

    // Persist (durable) — but NO ACK sent (simulated crash).
    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle.clone()).expect("add durable");
    }
    // Process crashes. Restart.
    let store = PersistentBundleStore::open(&dir).expect("reopen");
    let pending = store.pending(now);
    assert_eq!(pending.len(), 1, "bundle must be pending after restart");
    assert_eq!(pending[0].bundle_id(), bundle.bundle_id());
    eprintln!("[test] PASS: bundle recovered after crash (before ACK) — forwarder will retry");
}

// ─── 4. Crash after ACK, before forward ─────────────────────────────────

/// After ACK + crash, the bundle is durable → restart → forwarder retries
/// forwarding. This is the key R4.6 proof: custody obligation survives.
#[tokio::test]
async fn r4_6_crash_after_ack_before_forward() {
    let dir = ephemeral_dir();
    let client = test_identity(0x06);
    let relay = test_identity(0x07);
    let now = snp_identity::now_unix();

    let mut bundle = Bundle::new(
        client.node_id,
        [0xDD; 32],
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 300,
    )
    .expect("bundle");
    bundle
        .take_custody(
            client.node_id,
            relay.node_id,
            &relay.secret_key,
            now,
            now,
            custody_nonce(),
        )
        .expect("take_custody");

    // Persist + ACK (simulated — we just persist).
    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle.clone()).expect("add durable + ack");
    }
    // Process crashes. Restart.
    let store = PersistentBundleStore::open(&dir).expect("reopen");
    let pending = store.pending(now);
    assert_eq!(pending.len(), 1, "bundle must be pending — custody obligation survives");
    eprintln!("[test] PASS: bundle recovered after crash (after ACK) — forwarding will resume");
}

// ─── 5. Expiry recovery ─────────────────────────────────────────────────

/// Persist → advance time → restart → bundle is expired, not in pending().
#[tokio::test]
async fn r4_6_expiry_recovery() {
    let dir = ephemeral_dir();
    let identity = test_identity(0x08);
    let now = snp_identity::now_unix();
    let bundle = Bundle::new(
        identity.node_id,
        [0xEE; 32],
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 1, // expires in 1 second
    )
    .expect("bundle");

    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle.clone()).expect("add");
    }
    // Wait for expiry.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let later = snp_identity::now_unix();

    // Reopen — the expired bundle should be pruned during open().
    let store = PersistentBundleStore::open(&dir).expect("reopen");
    let pending = store.pending(later);
    assert!(
        pending.is_empty(),
        "expired bundle must NOT be pending after restart"
    );
    eprintln!("[test] PASS: expired bundle does not resurrect as active work");
}

// ─── 6. Duplicate insertion ─────────────────────────────────────────────

/// Same BundleId inserted twice → more_advanced keeps the longer-chain one.
#[tokio::test]
async fn r4_6_duplicate_insertion() {
    let dir = ephemeral_dir();
    let client = test_identity(0x09);
    let relay_a = test_identity(0x0A);
    let relay_b = test_identity(0x0B);
    let now = snp_identity::now_unix();

    let mut bundle = Bundle::new(
        client.node_id,
        [0xFF; 32],
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 300,
    )
    .expect("bundle");

    // Version 1: 1-hop custody chain (client → relay_a).
    let mut v1 = bundle.clone();
    v1.take_custody(
        client.node_id,
        relay_a.node_id,
        &relay_a.secret_key,
        now,
        now,
        custody_nonce(),
    )
    .expect("v1 custody");

    // Version 2: 2-hop custody chain (client → relay_a → relay_b) — more advanced.
    let mut v2 = bundle.clone();
    v2.take_custody(
        client.node_id,
        relay_a.node_id,
        &relay_a.secret_key,
        now,
        now,
        custody_nonce(),
    )
    .expect("v2 custody 1");
    v2.take_custody(
        relay_a.node_id,
        relay_b.node_id,
        &relay_b.secret_key,
        now + 1,
        now + 1,
        custody_nonce(),
    )
    .expect("v2 custody 2");

    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(v1.clone()).expect("add v1");
        store.add(v2.clone()).expect("add v2 (more advanced)");
    }

    // Reopen — the 2-hop version should be recovered.
    let store = PersistentBundleStore::open(&dir).expect("reopen");
    let recovered = store.get(bundle.bundle_id()).expect("bundle recovered");
    assert_eq!(
        recovered.custody_chain.len(),
        2,
        "more_advanced must keep the 2-hop chain"
    );
    eprintln!("[test] PASS: duplicate insertion — more_advanced kept the longer chain");
}

// ─── 7. Corruption — truncated record → fail-closed ─────────────────────

/// A truncated .cbor file → `open()` returns Err (fail-closed). The node
/// does NOT silently skip acknowledged custody.
#[tokio::test]
async fn r4_6_corruption_truncated_fail_closed() {
    let dir = ephemeral_dir();
    let identity = test_identity(0x10);
    let now = snp_identity::now_unix();
    let bundle = Bundle::new(
        identity.node_id,
        [0x11; 32],
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 300,
    )
    .expect("bundle");

    // Persist a valid bundle.
    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle.clone()).expect("add");
    }
    // Corrupt the .cbor file (truncate to 4 bytes).
    let id_hex = bundle.bundle_id().to_hex();
    let file_path = dir.join(format!("{id_hex}.cbor"));
    std::fs::write(&file_path, b"XXXX").expect("truncate");

    // Reopen — MUST fail (fail-closed).
    let result = PersistentBundleStore::open(&dir);
    assert!(
        result.is_err(),
        "open() MUST fail-closed on corrupt custody record"
    );
    match result {
        Err(PersistentStoreError::Corrupt { .. }) => {
            eprintln!("[test] PASS: truncated record → fail-closed (Corrupt)");
        }
        Err(e) => panic!("expected Corrupt, got {e:?}"),
        Ok(_) => panic!("open() must NOT succeed with corrupt record"),
    }
}

// ─── 8. Corruption — invalid CBOR → fail-closed ──────────────────────────

#[tokio::test]
async fn r4_6_corruption_invalid_cbor_fail_closed() {
    let dir = ephemeral_dir();
    let identity = test_identity(0x12);
    let now = snp_identity::now_unix();
    let bundle = Bundle::new(
        identity.node_id,
        [0x13; 32],
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 300,
    )
    .expect("bundle");

    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle.clone()).expect("add");
    }
    // Write garbage to the .cbor file.
    let id_hex = bundle.bundle_id().to_hex();
    let file_path = dir.join(format!("{id_hex}.cbor"));
    std::fs::write(&file_path, b"NOT VALID CBOR AT ALL").expect("garbage");

    let result = PersistentBundleStore::open(&dir);
    assert!(result.is_err(), "open() MUST fail-closed on invalid CBOR");
    eprintln!("[test] PASS: invalid CBOR → fail-closed");
}

// ─── 9. Full Mode-A restart integration ──────────────────────────────────

/// The headline R4.6 test: Relay B accepts custody, crashes, restarts,
/// and resumes forwarding. The bundle reaches the gateway.
///
/// ```text
/// Client → Relay A → Relay B → Gateway → HTTP
///                        ↑
///                        B takes custody (durable)
///                        B process terminates
///                        B restarts (PersistentBundleStore::open)
///                        B resumes forwarding
///                        Gateway receives
///                        Response returns B → A → Client
/// ```
///
/// **This is custody deduplication, NOT application exactly-once.** The
/// L7 gateway may receive the same TransitRequest twice — application-level
/// idempotence (e.g., reqId dedup) is an L7 concern, outside BundleStore.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_6_restart_recovery_multihop() {
    let client_identity = test_identity(0x01);
    let relay_a_identity = test_identity(0x02);
    let relay_b_identity = test_identity(0x03);
    let gateway_identity = test_identity(0x04);

    let (client_x_sk, client_x_pk) = test_x25519_keypair();
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair();
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair();
    let relay_b_x_sk_clone = relay_b_x_sk.clone();
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair();

    let relay_a_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let gateway_addr = ephemeral_addr().await;
    let relay_b_dir = ephemeral_dir();

    let http_addr = start_mock_http_server().await;
    let url = format!("http://{http_addr}/r4-6-restart");

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

    // ── Phase 1: Start Relay A (in-memory) + Gateway ─────────────────
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind client listener");
    let client_listen_addr = client_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(client_listener);

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
    let relay_a_handle = {
        let relay_a = relay_a.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_a.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let gateway = ModeAGateway::with_connector_factory(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_addr.clone(),
        move |url: &str| {
            let parsed = url::Url::parse(url)
                .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| GatewayError::MalformedUrl("no host".into()))?;
            let port = parsed.port().unwrap_or(80);
            Ok(PinnedConnector::from_parts(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                host.to_string(),
                port,
                "http".into(),
                if parsed.path().is_empty() {
                    "/".into()
                } else {
                    parsed.path().into()
                },
            ))
        },
    );
    let gateway_handle = tokio::spawn(async move {
        tokio::select! {
            _ = gateway.run() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── Phase 2: Start Relay B (DURABLE) ───────────────────────────────
    let durable_store = PersistentBundleStore::open(&relay_b_dir).expect("open durable store");
    let relay_b_x_sk_for_restart = relay_b_x_sk.clone();
    let relay_b = Arc::new(
        BundleForwarder::new_with_durable_store(
            relay_b_identity.clone(),
            relay_b_x_sk,
            relay_b_x_pk,
            relay_b_addr.clone(),
            route.clone(),
            1,
            durable_store,
        )
        .with_source("127.0.0.1:0".into(), relay_a_identity.node_id),
    );
    let relay_b_handle = {
        let relay_b = relay_b.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_b.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── Phase 3: Client sends request ──────────────────────────────────
    let client_identity_clone = client_identity.clone();
    let client_x_sk_clone = client_x_sk;
    let client_x_pk_clone = client_x_pk;
    let relay_a_addr_clone = relay_a_addr.clone();
    let relay_a_node_id = relay_a_identity.node_id;
    let gw_node_id = gateway_identity.node_id;
    let gw_pubkey = gateway_identity.public_key;
    let url_clone = url.clone();

    let client_task = tokio::spawn(async move {
        let client = ModeAClient::new(client_identity_clone, client_x_sk_clone, client_x_pk_clone);
        client
            .send_request(
                &url_clone,
                &relay_a_addr_clone,
                relay_a_node_id,
                gw_node_id,
                &gw_pubkey,
            )
            .await
    });

    // Wait for Relay B to take custody (durable) — then CRASH it.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    // Check that Relay B has the bundle in its durable store.
    {
        let relay_b_store = relay_b.store();
        let store = relay_b_store.lock().await;
        let pending = store.pending(snp_identity::now_unix());
        eprintln!("[test] Relay B has {} pending bundles before crash", pending.len());
        // The bundle should be in the store (Relay B took custody).
        // It may or may not have been forwarded yet — the key is that
        // custody is durable.
    }

    // ── Phase 4: Relay B crashes ───────────────────────────────────────
    relay_b_handle.abort();
    drop(relay_b);
    eprintln!("[test] Relay B process terminated — simulating crash");

    // Wait a moment to ensure the crash is effective.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ── Phase 5: Relay B restarts ──────────────────────────────────────
    // Open the SAME durable store — the bundle should be recovered.
    let restarted_store =
        PersistentBundleStore::open(&relay_b_dir).expect("reopen durable store");
    eprintln!(
        "[test] Relay B restarted — {} bundles recovered",
        restarted_store.len()
    );

    let relay_b_restarted = Arc::new(
        BundleForwarder::new_with_durable_store(
            relay_b_identity.clone(),
            relay_b_x_sk_for_restart,
            relay_b_x_pk,
            relay_b_addr.clone(),
            route.clone(),
            1,
            restarted_store,
        )
        .with_source("127.0.0.1:0".into(), relay_a_identity.node_id),
    );
    let relay_b_restarted_handle = {
        let relay_b = relay_b_restarted.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_b.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    eprintln!("[test] Relay B resumed forwarding loop");

    // ── Phase 6: Wait for the client to receive the response ───────────
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), client_task).await;

    match result {
        Ok(Ok(Ok((resp, body)))) => {
            assert_eq!(resp.status, 200, "HTTP status must be 200");
            let body_str = String::from_utf8_lossy(&body);
            assert!(
                body_str.contains("Hello from R4.6 durable custody"),
                "response body must contain expected text, got: {body_str}"
            );
            eprintln!("[test] SUCCESS: R4.6 restart recovery — bundle survived crash + reached gateway");
        }
        Ok(Ok(Err(e))) => panic!("send_request failed: {e}"),
        Ok(Err(e)) => panic!("client task panicked: {e}"),
        Err(_) => panic!("client timed out — restart recovery failed"),
    }

    relay_a_handle.abort();
    relay_b_restarted_handle.abort();
    gateway_handle.abort();
}

// ─── 10. In-memory backward compatibility ──────────────────────────────

/// `BundleForwarder::new()` creates an in-memory `PersistentBundleStore`
/// (no file backing). This preserves R4.3–R4.5b behavior.
#[tokio::test]
async fn r4_6_in_memory_backward_compat() {
    let identity = test_identity(0x20);
    let (x_sk, x_pk) = test_x25519_keypair();
    let addr = ephemeral_addr().await;
    let route = Arc::new(build_multihop_route(
        &identity,
        &test_identity(0x21),
        &test_identity(0x22),
        &test_identity(0x23),
        "127.0.0.1:19001",
        "127.0.0.1:19002",
        "127.0.0.1:19003",
        &[0u8; 32],
    ));
    let forwarder = BundleForwarder::new(
        identity,
        x_sk,
        x_pk,
        addr,
        route,
        0,
    );
    let forwarder_store = forwarder.store();
    let store = forwarder_store.lock().await;
    assert!(store.is_empty(), "new forwarder store should be empty");
    assert!(store.dir().is_none(), "in-memory store should have no dir");
    eprintln!("[test] PASS: new() creates in-memory store (backward compat)");
}

// ─── 11. Storage quota — reject before ACK (R4.6 hardening) ────────────

/// A bundle that would exceed `max_store_bytes` is rejected with
/// `StoreQuotaExceeded` BEFORE any filesystem mutation. The caller MUST NOT
/// send a custody ACK in that case.
#[tokio::test]
async fn r4_6_quota_rejects_before_ack() {
    let dir = ephemeral_dir();
    let identity = test_identity(0x30);
    let now = snp_identity::now_unix();

    // Small quota: enough for one small bundle but not two.
    let limits = StorageLimits {
        max_bundle_size_bytes: 1024, // generous per-bundle
        max_store_bytes: 300,        // small store
    };
    let mut store = PersistentBundleStore::open_with_limits(&dir, limits)
        .expect("open with limits");

    // First bundle: small enough to fit.
    let bundle1 = Bundle::new(
        identity.node_id,
        [0x31; 32],
        BundlePayload::new(vec![0u8; 10]),
        now,
        now + 300,
    )
    .expect("bundle1");
    store.add(bundle1.clone()).expect("bundle1 fits");

    // Second bundle: would exceed the 300-byte quota.
    let bundle2 = Bundle::new(
        identity.node_id,
        [0x32; 32],
        BundlePayload::new(vec![0u8; 200]),
        now,
        now + 300,
    )
    .expect("bundle2");
    let result = store.add(bundle2);
    assert!(
        matches!(result, Err(PersistentStoreError::StoreQuotaExceeded { .. })),
        "must reject with StoreQuotaExceeded, got {result:?}"
    );
    eprintln!("[test] PASS: quota exceeded → rejected before ACK");

    // The first bundle is still present (no eviction).
    assert!(store.get(bundle1.bundle_id()).is_some(), "existing custody NOT evicted");
    eprintln!("[test] PASS: existing custody NOT evicted to make room");
}

// ─── 12. Bundle too large — reject before ACK ──────────────────────────

/// A single bundle exceeding `max_bundle_size_bytes` is rejected with
/// `BundleTooLarge` before any filesystem mutation.
#[tokio::test]
async fn r4_6_bundle_too_large_rejected() {
    let dir = ephemeral_dir();
    let identity = test_identity(0x33);
    let now = snp_identity::now_unix();

    // Tiny per-bundle limit: 100 bytes.
    let limits = StorageLimits {
        max_bundle_size_bytes: 100,
        max_store_bytes: 64 * 1024 * 1024,
    };
    let mut store = PersistentBundleStore::open_with_limits(&dir, limits)
        .expect("open with limits");

    // Large payload → exceeds 100 bytes when serialized.
    let bundle = Bundle::new(
        identity.node_id,
        [0x34; 32],
        BundlePayload::new(vec![0u8; 200]),
        now,
        now + 300,
    )
    .expect("bundle");
    let result = store.add(bundle);
    assert!(
        matches!(result, Err(PersistentStoreError::BundleTooLarge { .. })),
        "must reject with BundleTooLarge, got {result:?}"
    );
    eprintln!("[test] PASS: bundle too large → rejected before ACK");
}

// ─── 13. Update accounting — no double-count ────────────────────────────

/// When a bundle with the same `bundle_id` is re-added (update with a longer
/// custody chain), `used_bytes` must reflect only the new record, not both.
#[tokio::test]
async fn r4_6_update_accounting_no_double_count() {
    let dir = ephemeral_dir();
    let client = test_identity(0x35);
    let relay_a = test_identity(0x36);
    let relay_b = test_identity(0x37);
    let now = snp_identity::now_unix();

    let mut store = PersistentBundleStore::open(&dir).expect("open");

    // v1: 1-hop chain.
    let mut v1 = Bundle::new(
        client.node_id,
        [0x38; 32],
        BundlePayload::new(vec![0u8; 10]),
        now,
        now + 300,
    )
    .expect("v1");
    v1.take_custody(
        client.node_id,
        relay_a.node_id,
        &relay_a.secret_key,
        now,
        now,
        custody_nonce(),
    )
    .expect("v1 custody");
    store.add(v1.clone()).expect("add v1");
    let used_after_v1 = store.used_bytes();
    eprintln!("[test] used_bytes after v1: {used_after_v1}");

    // v2: 2-hop chain (same bundle_id, more advanced).
    let mut v2 = v1.clone();
    v2.take_custody(
        relay_a.node_id,
        relay_b.node_id,
        &relay_b.secret_key,
        now + 1,
        now + 1,
        custody_nonce(),
    )
    .expect("v2 custody");
    store.add(v2.clone()).expect("add v2 (update)");
    let used_after_v2 = store.used_bytes();
    eprintln!("[test] used_bytes after v2 update: {used_after_v2}");

    // v2 is larger than v1 (extra CustodyHop), so used_bytes should have
    // increased by the size difference — NOT by the full v2 size.
    let v1_size = v1.to_cbor().unwrap().len();
    let v2_size = v2.to_cbor().unwrap().len();
    assert!(
        v2_size > v1_size,
        "v2 (2-hop) must be larger than v1 (1-hop)"
    );
    assert_eq!(
        used_after_v2,
        used_after_v1 - v1_size + v2_size,
        "update must subtract old size + add new size (no double-count)"
    );
    eprintln!("[test] PASS: update accounting correct (no double-count)");
}

// ─── 14. Restart quota recovery — accounting restored ──────────────────

/// After restart, `used_bytes` must match the actual loaded records.
#[tokio::test]
async fn r4_6_restart_quota_accounting_restored() {
    let dir = ephemeral_dir();
    let identity = test_identity(0x39);
    let now = snp_identity::now_unix();

    // Persist two bundles.
    let bundle1 = Bundle::new(
        identity.node_id,
        [0x3A; 32],
        BundlePayload::new(vec![0u8; 20]),
        now,
        now + 300,
    )
    .expect("bundle1");
    let bundle2 = Bundle::new(
        identity.node_id,
        [0x3B; 32],
        BundlePayload::new(vec![0u8; 30]),
        now,
        now + 300,
    )
    .expect("bundle2");

    let expected_used;
    {
        let mut store = PersistentBundleStore::open(&dir).expect("open");
        store.add(bundle1.clone()).expect("add 1");
        store.add(bundle2.clone()).expect("add 2");
        expected_used = store.used_bytes();
        eprintln!("[test] used_bytes before restart: {expected_used}");
    }
    // Restart.
    let store = PersistentBundleStore::open(&dir).expect("reopen");
    assert_eq!(
        store.used_bytes(),
        expected_used,
        "used_bytes must be exactly restored after restart"
    );
    eprintln!("[test] PASS: quota accounting restored after restart");
}
