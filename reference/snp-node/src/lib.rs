//! snp-node library — daemon internals for the ShareNet reference node.
//!
//! ## N2.0 — Multi-hop secure mesh (this revision)
//!
//! N2.0 extends the N1.9.2 single-hop path to a real **multi-hop** mesh:
//!
//! ```text
//!   CLIENT ──[S1 hop]──> RELAY A ──[S2 hop]──> RELAY B ──[S3 hop]──> GATEWAY
//!     └──────────────────────── [C circuit] ──────────────────────────┘
//! ```
//!
//! - `S1` = Client ↔ Relay A hop key (directional) — `CLIENT_RELAY_A_SEED`
//! - `S2` = Relay A ↔ Relay B hop key (directional) — `RELAY_A_RELAY_B_SEED`
//! - `S3` = Relay B ↔ Gateway hop key (directional) — `RELAY_B_GATEWAY_A_SEED`
//!   (or `RELAY_B_GATEWAY_B_SEED` for the failover gateway)
//! - `C`  = Client ↔ Gateway circuit key (directional) — `CIRCUIT_SEED_A`
//!   (or `CIRCUIT_SEED_B` for the failover gateway)
//!
//! Each relay has only its two adjacent hop keys. The circuit key `C` is
//! shared only between Client and Gateway — NO relay possesses it. The
//! frame body (circuit ciphertext) crosses both relays as opaque bytes.
//!
//! N2.0 also demonstrates **gateway failover**: Gateway A is killed after
//! serving one request, Relay B is re-pointed at Gateway B (with the
//! matching hop key `RELAY_B_GATEWAY_B_SEED`), and the client switches to
//! `CIRCUIT_SEED_B`. The request succeeds via Gateway B with a DIFFERENT
//! circuit key — proving the path actually switched.
//!
//! ## N1.9 — Secure Rust Link + Gateway Boundary (prior revision)
//!
//! For N1.9 (Secure Rust Link + Gateway Boundary) this crate provided:
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
//! ## N1.9 key hierarchy (preserved for backward compat)
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
//!
//! ## N2.0 vs production
//!
//! N2.0 adds a SECOND relay hop and gateway failover, but still uses
//! pre-shared deterministic seeds. Production ShareNet will derive the
//! multi-hop topology from SNP-IK/0.1 handshakes at each hop and from
//! path-vector routing advertisements (gateway discovery + failover is
//! automatic, not driven by the orchestrator).

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod node;

// ═══════════════════════════════════════════════════════════════════════════
// LEGACY DEMO / TEST-ONLY CODE
// ═══════════════════════════════════════════════════════════════════════════
// Everything in this module is N1.9/N2.0 legacy demo code that uses
// GatewayChoice and deterministic test seeds. It is NOT production code.
// Production code lives in `node.rs` which does NOT use GatewayChoice.
//
// The deprecated constructors in `node.rs` (NodeIdentity::gateway,
// Circuit::for_gateway, GatewayAdvertisement::for_gateway) reference
// this module via `crate::legacy::GatewayChoice`. They are marked
// `#[deprecated]` and should not be used by new code.
// ═══════════════════════════════════════════════════════════════════════════
#[allow(clippy::pedantic, clippy::all, missing_docs)]
pub mod legacy;

// Re-export legacy types that node.rs production code still references
// (deprecated constructors + mesh session demo). These are test-only
// deterministic seeds/keys — NOT production secrets.
pub use legacy::{
    client_circuit_keys_a, client_circuit_keys_b, client_public_key, client_relay_a_link_keys,
    client_secret_key, gateway_a_circuit_keys, gateway_a_node_id, gateway_a_public_key,
    gateway_a_relay_b_link_keys, gateway_a_secret, gateway_b_circuit_keys, gateway_b_node_id,
    gateway_b_public_key, gateway_b_relay_b_link_keys, gateway_b_secret,
    relay_a_client_link_keys, relay_a_relay_b_link_keys, relay_b_gateway_a_link_keys,
    relay_b_gateway_b_link_keys, relay_b_relay_a_link_keys, NodeError, NodeResult,
};
