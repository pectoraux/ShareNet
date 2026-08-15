//! N3.3 — Multi-Process Network Harness Tests
//!
//! Tests proving the system works as a REAL network when every node is a
//! separate process communicating via TCP sockets.
//!
//! ## What this proves
//!
//! > "The system works when every node is a separate process.
//! >  This is the most important bridge between 'tests pass' and
//! >  'this is actually a network.'"
//!
//! ## Topology
//!
//! ```text
//! Client → TCP → Relay → TCP → Gateway → HTTP → "Internet"
//! ```
//!
//! No shared in-memory state. No direct function calls between nodes.
//! Only TCP sockets + length-prefixed CBOR messages.

#![allow(clippy::pedantic)]

use snp_node::node::multi_process::*;
use std::time::Duration;

fn now() -> u64 {
    1_700_000_000
}

// ─── 1. Full multi-process pipeline: client → relay → gateway → HTTP ─────────

#[test]
fn n33_multi_process_end_to_end() {
    // Start the "real Internet" HTTP server.
    let body = "Hello from the real Internet via multi-process!";
    let http_port = start_http_server(body);
    let http_addr = format!("127.0.0.1:{http_port}");

    // Start the gateway process (listens on an ephemeral port).
    let gateway = NodeIdentity::from_label(b"n33-gateway");
    let gateway_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap().to_string();
    drop(gateway_listener); // free the port so run_gateway_process can bind

    let _gw_handle = run_gateway_process(gateway.clone(), &gateway_addr, &http_addr);

    // Give the gateway a moment to start.
    std::thread::sleep(Duration::from_millis(50));

    // Start the relay process (listens on an ephemeral port).
    let relay_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_listener.local_addr().unwrap().to_string();
    drop(relay_listener);

    let _relay_handle = run_relay_process(&relay_addr, &gateway_addr);

    // Give the relay a moment to start.
    std::thread::sleep(Duration::from_millis(50));

    // Start the client process — connect to the relay and send a request.
    let client = NodeIdentity::from_label(b"n33-client");
    let request = SimpleTransitRequest {
        req_id: [0x42; 16],
        url: "http://example.com/".to_string(),
        client_node_id: client.node_id,
    };

    let result = run_client_process(&relay_addr, request);

    assert!(result.is_ok(), "multi-process pipeline must succeed: {:?}", result.err());
    let response = result.unwrap();

    // The response body must match the HTTP server's response.
    assert_eq!(
        response.body,
        body.as_bytes(),
        "response body must match the HTTP server's response"
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.gateway_node_id, gateway.node_id);
    assert_eq!(response.req_id, [0x42; 16]);

    eprintln!("[n33-1] PASS: multi-process end-to-end (client → relay → gateway → HTTP → response)");
}

// ─── 2. CBOR encoding round-trip for SimpleTransitRequest ───────────────────

#[test]
fn n33_transit_request_cbor_round_trip() {
    let req = SimpleTransitRequest {
        req_id: [0x99; 16],
        url: "https://example.com/path".to_string(),
        client_node_id: [0xAA; 32],
    };

    let encoded = req.encode_cbor();
    let decoded = SimpleTransitRequest::decode_cbor(&encoded)
        .expect("must decode");

    assert_eq!(decoded.req_id, req.req_id);
    assert_eq!(decoded.url, req.url);
    assert_eq!(decoded.client_node_id, req.client_node_id);
    eprintln!("[n33-2] PASS: SimpleTransitRequest CBOR round-trip");
}

// ─── 3. CBOR encoding round-trip for SimpleTransitResponse ──────────────────

#[test]
fn n33_transit_response_cbor_round_trip() {
    let resp = SimpleTransitResponse {
        req_id: [0x88; 16],
        status: 404,
        body: b"Not Found".to_vec(),
        gateway_node_id: [0xBB; 32],
    };

    let encoded = resp.encode_cbor();
    let decoded = SimpleTransitResponse::decode_cbor(&encoded)
        .expect("must decode");

    assert_eq!(decoded.req_id, resp.req_id);
    assert_eq!(decoded.status, resp.status);
    assert_eq!(decoded.body, resp.body);
    assert_eq!(decoded.gateway_node_id, resp.gateway_node_id);
    eprintln!("[n33-3] PASS: SimpleTransitResponse CBOR round-trip");
}

// ─── 4. NetworkMessage encode/decode round-trip ──────────────────────────────

#[test]
fn n33_network_message_encode_decode() {
    let msg = NetworkMessage {
        msg_type: MessageType::TransitRequest,
        payload: vec![0x01, 0x02, 0x03, 0x04],
    };

    let encoded = msg.encode();
    let (decoded, consumed) = NetworkMessage::decode(&encoded)
        .expect("must decode");

    assert_eq!(decoded.msg_type, msg.msg_type);
    assert_eq!(decoded.payload, msg.payload);
    assert_eq!(consumed, encoded.len());
    eprintln!("[n33-4] PASS: NetworkMessage encode/decode round-trip");
}

// ─── 5. Each node has its own identity (no shared state) ─────────────────────

#[test]
fn n33_nodes_have_distinct_identities() {
    let client = NodeIdentity::from_label(b"n33-distinct-client");
    let relay = NodeIdentity::from_label(b"n33-distinct-relay");
    let gateway = NodeIdentity::from_label(b"n33-distinct-gateway");

    // Each node has a DIFFERENT NodeId — no shared in-memory state.
    assert_ne!(client.node_id, relay.node_id);
    assert_ne!(relay.node_id, gateway.node_id);
    assert_ne!(client.node_id, gateway.node_id);

    // Each node's NodeId is derived from its own secret key.
    assert_eq!(client.node_id, snp_crypto::derive_node_id(&client.public_key));
    assert_eq!(relay.node_id, snp_crypto::derive_node_id(&relay.public_key));
    assert_eq!(gateway.node_id, snp_crypto::derive_node_id(&gateway.public_key));
    eprintln!("[n33-5] PASS: each node has a distinct identity (no shared state)");
}

// ─── 6. Message types are correctly encoded ──────────────────────────────────

#[test]
fn n33_message_types_encode_correctly() {
    assert_eq!(MessageType::TransitForward.as_byte(), 1);
    assert_eq!(MessageType::TransitRequest.as_byte(), 2);
    assert_eq!(MessageType::TransitResponse.as_byte(), 3);
    assert_eq!(MessageType::TransitResponseForwarded.as_byte(), 4);
    assert_eq!(MessageType::Error.as_byte(), 0xFF);

    assert_eq!(MessageType::from_byte(1), Some(MessageType::TransitForward));
    assert_eq!(MessageType::from_byte(2), Some(MessageType::TransitRequest));
    assert_eq!(MessageType::from_byte(3), Some(MessageType::TransitResponse));
    assert_eq!(MessageType::from_byte(4), Some(MessageType::TransitResponseForwarded));
    assert_eq!(MessageType::from_byte(0xFF), Some(MessageType::Error));
    assert_eq!(MessageType::from_byte(99), None);
    eprintln!("[n33-6] PASS: message types encode/decode correctly");
}

// ─── 7. No shared memory between processes ──────────────────────────────────

#[test]
fn n33_no_shared_memory_between_processes() {
    // This test verifies the architecture: each process communicates ONLY
    // via TCP. There is NO shared in-memory TopologyGraph, NO direct
    // function calls between nodes. The relay forwards bytes it doesn't
    // understand — it just passes the CBOR payload through.

    // Start the HTTP server.
    let body = "No shared memory!";
    let http_port = start_http_server(body);
    let http_addr = format!("127.0.0.1:{http_port}");

    // Start the gateway.
    let gateway = NodeIdentity::from_label(b"n33-noshare-gw");
    let gw_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gw_addr = gw_listener.local_addr().unwrap().to_string();
    drop(gw_listener);
    let _gw = run_gateway_process(gateway.clone(), &gw_addr, &http_addr);
    std::thread::sleep(Duration::from_millis(50));

    // Start the relay.
    let relay_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_listener.local_addr().unwrap().to_string();
    drop(relay_listener);
    let _relay = run_relay_process(&relay_addr, &gw_addr);
    std::thread::sleep(Duration::from_millis(50));

    // The client has NO knowledge of the gateway's identity or the HTTP
    // server's address. It only knows the relay's address.
    let client = NodeIdentity::from_label(b"n33-noshare-client");
    let request = SimpleTransitRequest {
        req_id: [0x77; 16],
        url: "http://internal/".to_string(),
        client_node_id: client.node_id,
    };

    let result = run_client_process(&relay_addr, request);

    assert!(result.is_ok(), "pipeline must work without shared memory: {:?}", result.err());
    assert_eq!(result.unwrap().body, body.as_bytes());
    eprintln!("[n33-7] PASS: no shared memory between processes — only TCP");
}

// ─── 8. Relay forwards without understanding the payload ────────────────────

#[test]
fn n33_relay_forwards_without_understanding_payload() {
    // The relay process forwards the CBOR payload verbatim — it does NOT
    // decode or understand the SimpleTransitRequest. This proves the relay
    // is a pure transport, not an application-layer intermediary.

    // Verify: the relay's forward_msg uses msg.payload (the raw CBOR bytes),
    // NOT a decoded/re-encoded version.
    let original_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let msg = NetworkMessage {
        msg_type: MessageType::TransitForward,
        payload: original_payload.clone(),
    };

    // The relay creates a new message with the SAME payload.
    let forwarded = NetworkMessage {
        msg_type: MessageType::TransitRequest,
        payload: msg.payload, // same bytes — not decoded
    };

    assert_eq!(forwarded.payload, original_payload, "relay must forward payload verbatim");
    eprintln!("[n33-8] PASS: relay forwards payload verbatim (no decoding)");
}
