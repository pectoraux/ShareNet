//! **N3-B Step 1 — Placeholder client node ID verification.**
//!
//! Proves that the relay does NOT require the route source node ID to equal
//! the actual connecting client's node ID. The placeholder `[0u8; 32]` used
//! by the mesh's relay-A runtime configuration is metadata only — the actual
//! authentication is the SNP-IK handshake.
//!
//! ## What this tests
//!
//! A relay started with `Route::new_with_hop_details(placeholder_source=[0u8;32], ...)`
//! accepts a real client with a DIFFERENT node_id. The SNP-IK handshake
//! authenticates the real client identity independently of the route source.
//!
//! ## Why this is safe
//!
//! `serve_relay_via_route()` (async_node.rs:2411) extracts only the NEXT hop
//! from the route (`route.hop(my_position + 1)`). It does NOT read or check
//! `route.src`. The relay delegates to `serve_relay_persistent_async_with_handshake()`,
//! which performs SNP-IK as the responder. The handshake authenticates the
//! peer via Ed25519 signatures — the peer's `node_id` comes from the
//! handshake, NOT from the route.
//!
//! The route source is metadata for route CONSTRUCTION (used by the client to
//! build the route object). It is not enforced at the relay.

#![cfg(feature = "circuit-upstream")]

use std::sync::Arc;
use std::time::Duration;

use snp_crypto::{derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use tokio::net::TcpListener;

struct NodeIdents {
    ed_sk: [u8; 32],
    x_sk: Arc<X25519Secret>,
    x_pk: X25519PubKey,
    node_id: [u8; 32],
}

impl NodeIdents {
    fn fresh() -> Self {
        let mut ed_sk = [0u8; 32];
        getrandom::getrandom(&mut ed_sk).expect("getrandom");
        let ed_pk = derive_public_key(&ed_sk);
        let node_id = derive_node_id(&ed_pk);
        let (x_sk, x_pk) = x25519_static_keypair();
        Self { ed_sk, x_sk: Arc::new(x_sk), x_pk, node_id }
    }
    fn identity(&self) -> NodeIdentity { NodeIdentity::from_secret(self.ed_sk) }
    fn gateway_descriptor(&self, addr: &str) -> VerifiedNodeDescriptor {
        let advert = GatewayAdvertisement::for_identity_with_circuit_key(
            &self.identity(), self.x_pk.to_bytes(), addr, addr,
        );
        advert.verify_into_verified().expect("verify").descriptor().expect("descriptor")
    }
    fn relay_descriptor(&self) -> VerifiedNodeDescriptor { self.gateway_descriptor("0.0.0.0:0") }
}

async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_relay_accepts_real_client_despite_placeholder_route_source() {
    // This test proves the placeholder route source is metadata only.
    //
    // The relay is started with route.src = [0u8; 32] (the placeholder).
    // A real client with a DIFFERENT node_id connects through the relay.
    // The SNP-IK handshake authenticates the real client — the relay does
    // NOT reject it for having a different identity than the route source.

    let client = NodeIdents::fresh();
    let relay = NodeIdents::fresh();
    let gateway = NodeIdents::fresh();

    let gw_addr = ephemeral_addr().await;
    let relay_addr = ephemeral_addr().await;

    // The client's node_id is NOT [0u8; 32] — it's a real fresh identity.
    assert_ne!(client.node_id, [0u8; 32], "client must have a real node_id");

    // Start gateway.
    let gw_node = Node::new(gateway.identity(), vec![Capability::Gateway], gw_addr.clone());
    let gw_x_sk = Arc::clone(&gateway.x_sk);
    let gw_x_pk = gateway.x_pk;
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());
    let gw_addr_spawn = gw_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(
            &gw_node, &gw_addr_spawn, &gw_x_sk, &gw_x_pk, &st,
        ).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Start relay with a PLACEHOLDER route source ([0u8; 32]).
    // This mirrors the n3b_tun_demo mesh subcommand's relay-A configuration.
    let placeholder_source: [u8; 32] = [0u8; 32];
    let relay_route = Route::new_with_hop_details(
        placeholder_source, gateway.node_id,
        vec![
            RouteHop::new(relay.relay_descriptor(), TransportEndpoint::tcp(&relay_addr)),
            RouteHop::new(gateway.gateway_descriptor(&gw_addr), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    let relay_node = Node::new(relay.identity(), vec![Capability::Relay], relay_addr.clone());
    let relay_x_sk = Arc::clone(&relay.x_sk);
    let relay_x_pk = relay.x_pk;
    let relay_addr_spawn = relay_addr.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(
            &relay_node, &relay_route, 0, &relay_addr_spawn, &relay_x_sk, &relay_x_pk,
        ).await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Build the CLIENT'S route — the source is the REAL client node_id.
    let mut client_route = Route::new_with_hop_details(
        client.node_id, gateway.node_id,
        vec![
            RouteHop::new(relay.relay_descriptor(), TransportEndpoint::tcp(&relay_addr)),
            RouteHop::new(gateway.gateway_descriptor(&gw_addr), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    client_route.validate().expect("route valid");
    client_route.transition(RouteState::Establishing).expect("Establishing");
    client_route.transition(RouteState::Active).expect("Active");

    // The client establishes a MultiplexedCircuit to the gateway via the relay.
    // This performs the SNP-IK handshake. If the relay checked route.src
    // against the client's node_id, this would fail.
    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let circuit_result = snp_node::node::stream_client::MultiplexedCircuit::establish(
        &client_node,
        &client_route,
        &client.x_sk,
        &client.x_pk,
    ).await;

    match circuit_result {
        Ok(mut circuit) => {
            let fid = circuit.circuit_fid();
            eprintln!("[placeholder_test] PASS: circuit established (fid={:?})", fid);
            eprintln!("[placeholder_test] client node_id={} (NOT [0u8;32])",
                node_id_hex(&client.node_id));
            eprintln!("[placeholder_test] relay route.src=[0u8;32] (placeholder)");
            eprintln!("[placeholder_test] relay ACCEPTED the real client — route.src is not enforced");
            // Clean up.
            let _ = circuit.close().await;
        }
        Err(e) => {
            panic!("Circuit establishment failed: {:?} — the relay may be checking route.src against the client identity", e);
        }
    }
}

fn node_id_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
