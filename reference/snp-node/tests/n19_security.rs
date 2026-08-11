//! N1.9 security tests — verify the three findings:
//!
//! 1. **Nonce collision** — `(fid=X, seq=1)` in both directions does NOT
//!    reuse the same AEAD key+nonce (directional-key derivation).
//! 2. **Malicious relay** — the relay tries to decrypt the circuit payload
//!    using its hop key; this MUST fail. The relay then forwards the
//!    ciphertext unchanged, and the request succeeds.
//! 3. **Tampering relay** — modifying one byte of the encrypted circuit
//!    payload at the relay MUST cause the gateway to reject (AEAD auth
//!    failure). The client receives no valid response.
//! 4. **DNS pinning** — the `PinnedConnector` connects to the validated IP,
//!    not a re-resolved hostname.
//! 5. **Redirect SSRF** — a redirect from a public URL to a private IP is
//!    NOT followed.
//!
//! These tests do NOT require real Internet access (Test 2/3 use a mocked
//! gateway; Test 4/5 use local mock HTTP servers).

#![allow(clippy::pedantic)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use snp_crypto::aead_decrypt;
use snp_frames::Frame;
use snp_gateway::{HttpResponse, PinnedConnector};
use snp_link::{
    decrypt_circuit_payload, derive_circuit_keys, derive_link_keys, encrypt_circuit_payload, Link,
};

// ════════════════════════════════════════════════════════════════════════════
// Test 1: Nonce collision — directional keys prevent (key, nonce) reuse
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_1_nonce_collision_directional_keys_prevent_reuse() {
    // The N1.9 invariant: even if (fid, seq) is the SAME in both directions
    // of a link, the AEAD (key, nonce) pair differs because the directional
    // keys differ. Encrypting the same plaintext under each direction MUST
    // produce different ciphertexts. If directional separation were removed
    // (single bidirectional key), the two ciphertexts would be IDENTICAL —
    // the test would fail.

    let initiator_keys = derive_link_keys(b"nonce-collision-test-seed", true);
    let responder_keys = derive_link_keys(b"nonce-collision-test-seed", false);

    // Sanity: directional swap.
    assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
    assert_eq!(initiator_keys.recv_key, responder_keys.send_key);
    // The two keys MUST differ from each other.
    assert_ne!(
        initiator_keys.send_key, initiator_keys.recv_key,
        "send_key and recv_key MUST differ — directional separation broken"
    );

    // Build a frame with fid=X, seq=1 (the "collision" scenario: both
    // directions would use this same (fid, seq)).
    let mut frame = Frame::new(b'B', [1u8; 32], [2u8; 32]);
    frame.fid = [0xAA; 8];
    frame.seq = 1;
    frame.body = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
    let plaintext = frame.encode_cbor().expect("encode frame");
    let nonce = snp_crypto::aead_nonce(&frame.fid, frame.seq);

    // Direction 1: initiator → responder (uses initiator.send_key).
    let (ct_i2r, tag_i2r) =
        snp_crypto::aead_encrypt(&initiator_keys.send_key, &nonce, &plaintext, b"");
    // Direction 2: responder → initiator (uses responder.send_key, SAME nonce).
    let (ct_r2i, tag_r2i) =
        snp_crypto::aead_encrypt(&responder_keys.send_key, &nonce, &plaintext, b"");

    // THE CORE ASSERTION: the two ciphertexts MUST differ.
    assert_ne!(
        ct_i2r, ct_r2i,
        "DIRECTIONAL SEPARATION BROKEN: same (fid, seq) in both directions \
         produced identical ciphertext — nonce reuse occurred"
    );
    assert_ne!(tag_i2r, tag_r2i, "tags MUST differ too");

    // Each direction's ciphertext MUST decrypt with the matching recv_key.
    let pt_i2r = aead_decrypt(&responder_keys.recv_key, &nonce, &ct_i2r, &tag_i2r, b"")
        .expect("responder must decrypt initiator→responder direction");
    let pt_r2i = aead_decrypt(&initiator_keys.recv_key, &nonce, &ct_r2i, &tag_r2i, b"")
        .expect("initiator must decrypt responder→initiator direction");
    assert_eq!(pt_i2r, plaintext);
    assert_eq!(pt_r2i, plaintext);

    // Cross-direction decryption MUST fail (the recv_key for one direction
    // cannot decrypt the other direction's ciphertext).
    assert!(
        aead_decrypt(&responder_keys.send_key, &nonce, &ct_i2r, &tag_i2r, b"").is_none(),
        "wrong-direction key MUST NOT decrypt"
    );
    assert!(
        aead_decrypt(&initiator_keys.send_key, &nonce, &ct_r2i, &tag_r2i, b"").is_none(),
        "wrong-direction key MUST NOT decrypt"
    );

    println!("Test 1 PASSED: directional keys prevent (key, nonce) reuse across directions");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2: Malicious relay — relay tries to decrypt circuit payload, fails,
// then forwards the ciphertext unchanged; the request succeeds.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_2_malicious_relay_cannot_decrypt_circuit_payload() {
    // Set up the mesh: client → (malicious) relay → (stub) gateway. The
    // malicious relay, after decrypting the OUTER frame, attempts to decrypt
    // the body (the circuit ciphertext) using its hop key. This MUST fail.
    // The relay then forwards the frame unchanged, and the end-to-end
    // request MUST succeed.
    //
    // We use a STUB gateway (not the real run_gateway) so the test does not
    // need Internet access or a mock HTTP server — the stub decrypts the
    // circuit payload, builds a fixed TransitResponse, encrypts it with the
    // circuit key, and sends it back. This tests the CRYPTOGRAPHIC property
    // (relay can't decrypt body) and the END-TO-END property (response can
    // be decrypted by client).

    let gateway_listener = TcpListener::bind("127.0.0.1:0").expect("bind gateway");
    let gateway_addr = gateway_listener.local_addr().expect("local_addr");
    let relay_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr");

    let gateway_thread = std::thread::spawn(move || {
        stub_gateway_round_trip(&gateway_listener);
    });
    std::thread::sleep(Duration::from_millis(100));

    let gateway_addr_for_relay = gateway_addr.to_string();
    let relay_thread = std::thread::spawn(move || {
        malicious_relay_round_trip(&relay_listener, &gateway_addr_for_relay);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Client: send a request, expect a valid response.
    let (status, verified) =
        snp_node::run_client(&relay_addr.to_string(), "http://stub.example/")
            .expect("client round-trip should succeed");
    assert_eq!(status, 200);
    assert!(verified);

    gateway_thread.join().expect("gw join");
    relay_thread.join().expect("relay join");

    println!("Test 2 PASSED: relay cannot decrypt circuit payload; round-trip succeeds");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3: Tampering relay — modifying one byte of the encrypted circuit
// payload at the relay causes the gateway to reject (AEAD auth failure).
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_3_tampering_relay_gateway_rejects() {
    // Mesh: client → (tampering) relay → stub gateway. The tampering relay
    // flips one byte of the frame BODY (the circuit ciphertext) before
    // forwarding. The gateway MUST fail to decrypt the body
    // (CircuitDecryptionFailed). The client receives no valid response
    // (the gateway closes the connection without sending a response).

    let gateway_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gateway_addr = gateway_listener.local_addr().expect("local_addr");
    let relay_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr");

    let gateway_thread = std::thread::spawn(move || {
        // The stub gateway attempts to decrypt the body. With tampering, the
        // decryption MUST fail. The gateway then closes the connection
        // WITHOUT sending a response (which the client observes as a recv
        // error or EOF).
        let (stream, _) = gateway_listener.accept().expect("accept");
        let link = Link::new(stream, snp_node::gateway_link_keys());
        let circuit = snp_node::gateway_circuit_keys();
        // recv_frame should succeed (the OUTER frame was re-encrypted by the
        // relay with the correct relay→gateway hop key).
        let frame = link.recv_frame().expect("recv_frame");
        eprintln!(
            "[stub-gw] got frame: cls={} body={} bytes",
            frame.cls as char,
            frame.body.len()
        );
        // Decrypt the body — with tampering this MUST fail.
        let result = decrypt_circuit_payload(&circuit.recv_key, &frame.body);
        assert!(
            result.is_none(),
            "GATEWAY ACCEPTED TAMPERED PAYLOAD — AEAD auth failed to detect the modification"
        );
        eprintln!("[stub-gw] circuit decryption FAILED (correct — tampering detected)");
        // Do NOT send a response. The connection drops. The relay's
        // recv_frame on the gateway→client direction will fail; the client's
        // recv_frame will also fail. This is the expected "no valid response"
        // outcome.
    });
    std::thread::sleep(Duration::from_millis(100));

    let gateway_addr_for_relay = gateway_addr.to_string();
    let relay_thread = std::thread::spawn(move || {
        // TAMPERING RELAY: same as the malicious relay, but instead of
        // attempting to decrypt the body, it flips one byte of the body
        // before forwarding.
        let (client_stream, _) = relay_listener.accept().expect("accept");
        let client_link = Link::new(client_stream, snp_node::relay_client_link_keys());
        let gw_link =
            Link::connect(&gateway_addr_for_relay, snp_node::relay_gateway_link_keys())
                .expect("connect gw");

        let mut frame = client_link.recv_frame().expect("recv_frame");
        eprintln!(
            "[tampering-relay] got frame: body={} bytes, flipping one byte",
            frame.body.len()
        );
        // Flip one byte in the MIDDLE of the body (avoid the first 12 bytes
        // which are the nonce — flipping the nonce also breaks decryption,
        // but flipping a ciphertext byte specifically tests the AEAD tag).
        let flip_idx = frame.body.len() / 2;
        frame.body[flip_idx] ^= 0xFF;
        if frame.ttl > 0 {
            frame.ttl -= 1;
        }
        gw_link.send_frame(&frame).expect("send_frame to gw");

        // Try to recv the response — this will fail (the gateway drops the
        // connection without sending). We don't care about the result; we
        // just need to not block forever.
        let _ = gw_link.recv_frame();
        // Also drop the client_link without sending a response — the client
        // will see EOF.
        drop(client_link);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Client: send a request, expect NO valid response (the gateway rejected
    // the tampered payload, so no response comes back).
    let result = snp_node::run_client(&relay_addr.to_string(), "http://stub.example/");
    assert!(
        result.is_err(),
        "CLIENT RECEIVED A VALID RESPONSE — tampering was NOT detected. \
         Expected the client to error out because the gateway rejected the \
         tampered payload. Got: {:?}",
        result
    );
    eprintln!("[client] correctly received no valid response: {:?}", result);

    gateway_thread.join().expect("gw join");
    relay_thread.join().expect("relay join");

    println!("Test 3 PASSED: gateway rejects tampered circuit payload (AEAD auth failure)");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4: DNS pinning — PinnedConnector connects to the validated IP, not a
// re-resolved hostname.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_4_dns_pinning_connects_to_validated_ip() {
    // Set up a mock HTTP server on 127.0.0.1:port. We use
    // PinnedConnector::from_parts to construct a connector that points at
    // 127.0.0.1:port BUT claims its hostname is
    // "nonexistent-host-zzz-12345.example" — a name that does NOT resolve
    // in DNS. If the connector tries to re-resolve the hostname, it will
    // fail (NXDOMAIN). If it uses the pinned IP, it will connect to our
    // mock and succeed.

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let addr = listener.local_addr().expect("local_addr");
    let port = addr.port();

    // The mock records the Host header it received so we can verify the
    // connector sent the ORIGINAL hostname (not the IP).
    let host_header_received = Arc::new(std::sync::Mutex::new(None::<String>));
    let host_clone = host_header_received.clone();
    let mock_thread = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        // Read the request.
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).expect("read");
        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
        // Extract the Host header.
        for line in req_str.split("\r\n") {
            if line.to_ascii_lowercase().starts_with("host:") {
                let value = line.split(':').nth(1).unwrap_or("").trim().to_string();
                *host_clone.lock().unwrap() = Some(value);
                break;
            }
        }
        // Send a minimal 200 response.
        let body = b"hello-from-pinned-mock";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
            body.len()
        );
        sock.write_all(resp.as_bytes()).expect("write");
        sock.write_all(body).expect("write body");
        sock.flush().expect("flush");
    });

    // Construct a PinnedConnector pointing at 127.0.0.1:port, but with a
    // hostname that does NOT resolve in DNS. If the connector re-resolves
    // the hostname, fetch() will fail with NXDOMAIN. If it uses the pinned
    // IP, it will connect to our mock.
    let connector = PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "nonexistent-host-zzz-12345.example".to_string(),
        port,
        "http".to_string(),
        "/".to_string(),
    );

    let response: HttpResponse = connector
        .fetch("GET", &[])
        .expect("fetch should succeed — the connector MUST use the pinned IP, not re-resolve DNS");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello-from-pinned-mock");

    mock_thread.join().expect("mock join");

    // Verify the Host header was the ORIGINAL hostname, not the pinned IP.
    let host = host_header_received.lock().unwrap().clone();
    assert_eq!(
        host.as_deref(),
        Some("nonexistent-host-zzz-12345.example"),
        "Host header MUST be the original hostname, not the pinned IP"
    );

    println!("Test 4 PASSED: PinnedConnector connects to the validated IP and sends the original hostname in the Host header");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 5: Redirect SSRF — a redirect from a public URL to a private IP is
// NOT followed.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_5_redirect_to_private_ip_not_followed() {
    // Set up TWO mock HTTP servers:
    //   - port1: returns a 301 redirect to http://127.0.0.1:port2/
    //   - port2: records if any connection was made (it SHOULD NOT be)
    //
    // The connector fetches port1. It MUST return the 301 response (not
    // follow the redirect). port2 MUST receive NO connections.

    let redirect_target_listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
    let redirect_target_port = redirect_target_listener.local_addr().expect("local_addr").port();
    let redirect_target_hit = Arc::new(AtomicBool::new(false));
    let hit_clone = redirect_target_hit.clone();
    let redirect_target_thread = std::thread::spawn(move || {
        // Accept at most one connection; if any arrives, set the flag.
        redirect_target_listener.set_nonblocking(true).ok();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if let Ok((mut sock, _)) = redirect_target_listener.accept() {
                hit_clone.store(true, Ordering::SeqCst);
                // Send a minimal response (the test asserts no connection
                // was made; this is defensive in case one was).
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(resp);
                let _ = sock.flush();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let redirect_source_listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect source");
    let redirect_source_port = redirect_source_listener.local_addr().expect("local_addr").port();
    let redirect_source_thread = std::thread::spawn(move || {
        let (mut sock, _) = redirect_source_listener.accept().expect("accept");
        // Drain the request.
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        // Send a 301 redirect to 127.0.0.1:redirect_target_port.
        let location = format!("http://127.0.0.1:{redirect_target_port}/");
        let resp = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        sock.write_all(resp.as_bytes()).expect("write");
        sock.flush().expect("flush");
    });

    // Construct a PinnedConnector pointing at 127.0.0.1:redirect_source_port
    // with a fake "public" hostname. The connector fetches this URL. The
    // server returns a 301 to a PRIVATE IP. The connector MUST NOT follow
    // the redirect — it returns the 301 response to the caller verbatim.
    let connector = PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "public-looking-host.example".to_string(),
        redirect_source_port,
        "http".to_string(),
        "/".to_string(),
    );

    let response = connector
        .fetch("GET", &[])
        .expect("fetch should return the 301 response, not follow it");

    // The connector MUST return the 301 status (NOT followed the redirect).
    assert_eq!(
        response.status, 301,
        "connector must return 301, not follow the redirect"
    );
    // The Location header MUST be present and point to the private IP.
    let location = response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .expect("Location header must be present");
    assert!(
        location.contains("127.0.0.1"),
        "Location header should point to 127.0.0.1, got: {location}"
    );

    redirect_source_thread.join().expect("source join");
    redirect_target_thread.join().expect("target join");

    // CRITICAL ASSERTION: the redirect target (127.0.0.1:port2) MUST NOT
    // have been contacted. If it was, the connector followed the redirect
    // — an SSRF vulnerability.
    assert!(
        !redirect_target_hit.load(Ordering::SeqCst),
        "SSRF VULNERABILITY: the connector followed the redirect to a private IP (127.0.0.1). \
         The redirect target should NOT have been contacted."
    );

    println!("Test 5 PASSED: redirect from public URL to private IP is NOT followed");
}

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

/// Stub gateway: accept one connection, decrypt the OUTER frame with the
/// gateway's hop recv_key, decrypt the INNER body with the circuit recv_key,
/// build a fixed TransitResponse, encrypt with circuit send_key, wrap in a
/// response frame, encrypt with hop send_key, send.
fn stub_gateway_round_trip(listener: &TcpListener) {
    let (stream, _) = listener.accept().expect("accept");
    let link = Link::new(stream, snp_node::gateway_link_keys());
    let circuit = snp_node::gateway_circuit_keys();
    let req_frame = link.recv_frame().expect("recv_frame");
    eprintln!(
        "[stub-gw] got frame: cls={} body={} bytes",
        req_frame.cls as char,
        req_frame.body.len()
    );
    let req_bytes = decrypt_circuit_payload(&circuit.recv_key, &req_frame.body)
        .expect("circuit decryption must succeed for legitimate traffic");
    eprintln!("[stub-gw] circuit decryption OK: {} bytes", req_bytes.len());

    // Build a fixed TransitResponse (status 200, gateway signature).
    let gateway_sk = {
        // Mirror the deterministic GATEWAY_SECRET in snp-node.
        let mut sk = [0u8; 32];
        let mut i = 0u32;
        while i < 32 {
            sk[i as usize] = ((i.wrapping_mul(31)).wrapping_add(1)) as u8;
            i += 1;
        }
        sk
    };
    let gateway_pk = snp_crypto::derive_public_key(&gateway_sk);
    let gateway_id = snp_crypto::derive_node_id(&gateway_pk);
    let object_id = snp_crypto::sha256(b"stub-response-body");
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut resp = snp_gateway::TransitResponse {
        req_id: [1u8; 16],
        status: 200,
        headers: vec![("content-type".into(), "text/plain".into())],
        object_id,
        fetched_at,
        gateway_id,
        gateway_sig: [0u8; 64],
    };
    snp_gateway::sign_transit_response(&mut resp, &gateway_sk);
    let resp_bytes = snp_gateway::encode_transit_response(&resp).expect("encode");
    let sealed = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);

    let resp_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_id,
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: sealed,
    };
    link.send_frame(&resp_frame).expect("send_frame");
}

/// Malicious relay (Test 2): tries to decrypt the body with hop keys, fails,
/// then forwards unchanged.
fn malicious_relay_round_trip(listener: &TcpListener, gateway_addr: &str) {
    let (client_stream, _) = listener.accept().expect("accept");
    let client_link = Link::new(client_stream, snp_node::relay_client_link_keys());
    let gw_link = Link::connect(gateway_addr, snp_node::relay_gateway_link_keys()).expect("connect");

    let mut frame = client_link.recv_frame().expect("recv_frame");

    // Attempt to decrypt the body with the relay's hop key — MUST fail.
    let hop_key = snp_node::relay_client_link_keys().recv_key;
    let attempt = decrypt_circuit_payload(&hop_key, &frame.body);
    assert!(
        attempt.is_none(),
        "MALICIOUS RELAY SUCCEEDED — relay must not be able to decrypt circuit payload"
    );
    let other_hop_key = snp_node::relay_gateway_link_keys().send_key;
    let attempt2 = decrypt_circuit_payload(&other_hop_key, &frame.body);
    assert!(
        attempt2.is_none(),
        "MALICIOUS RELAY SUCCEEDED with other hop key"
    );
    eprintln!("[malicious-relay] both decryption attempts FAILED (correct)");

    if frame.ttl > 0 {
        frame.ttl -= 1;
    }
    gw_link.send_frame(&frame).expect("send to gw");

    let mut resp = gw_link.recv_frame().expect("recv from gw");
    if resp.ttl > 0 {
        resp.ttl -= 1;
    }
    client_link.send_frame(&resp).expect("send to client");
}

// Silence unused-import warnings for helpers that are conditionally used.
#[allow(dead_code)]
fn _unused() {
    let _ = AtomicUsize::new(0);
    let _ = derive_circuit_keys(b"x", true);
    let _ = TcpStream::connect("127.0.0.1:0");
}
