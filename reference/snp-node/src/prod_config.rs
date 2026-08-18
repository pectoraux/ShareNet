//! **R1 — Production configuration for relay-prod and client-prod.**
//!
//! Defines the JSON config format for production relay and client roles.
//! The config contains ONLY signed/public information — NO private keys
//! belonging to other roles. This preserves the identity separation
//! invariant established in N3-B.
//!
//! ## Config format
//!
//! ```json
//! {
//!   "role": "relay",
//!   "listen_addr": "0.0.0.0:7002",
//!   "position": 0,
//!   "source_node_id_hex": "...",
//!   "destination_node_id_hex": "...",
//!   "hop_adverts_cbor_hex": ["...", "...", "..."],
//!   "hop_endpoints": ["1.2.3.4:7002", "1.2.3.4:7001", "1.2.3.4:7003"]
//! }
//! ```
//!
//! Each `hop_adverts_cbor_hex` entry is a hex-encoded CBOR
//! `GatewayAdvertisement` (signed by the hop's Ed25519 private key).
//! The relay/client verifies each signature using the embedded public key
//! and extracts the authenticated `listen_addr` from the verified advert.
//!
//! The relay/client generates its OWN identity locally — it does NOT
//! receive any private key from the config.

use serde::{Deserialize, Serialize};

/// Production relay/client configuration.
///
/// Contains ONLY signed/public information:
/// - Signed CBOR advertisements for each hop (verified by the consumer)
/// - Endpoint addresses (used for route construction)
/// - Role metadata (listen address, position)
///
/// Contains NO private keys of any kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProdConfig {
    /// The role: "relay" or "client".
    pub role: String,
    /// For relay: the address to listen on. For client: not used.
    #[serde(default)]
    pub listen_addr: String,
    /// For relay: the relay's position in the route (0-indexed).
    /// For client: not used.
    #[serde(default)]
    pub position: usize,
    /// The source NodeId (hex, 64 chars). For relay: the relay's own NodeId.
    /// For client: the client's own NodeId.
    pub source_node_id_hex: String,
    /// The destination NodeId (hex, 64 chars) — the gateway's NodeId.
    pub destination_node_id_hex: String,
    /// Signed CBOR GatewayAdvertisements for each hop (hex-encoded).
    /// Each contains the hop's PUBLIC Ed25519 key, X25519 public key,
    /// NodeId, SIGNED listen_addr, and signature.
    pub hop_adverts_cbor_hex: Vec<String>,
    /// TCP endpoints for each hop (used for RouteHop construction).
    /// These must match the signed listen_addr in the corresponding advert.
    /// If empty, the authenticated listen_addr from the advert is used.
    #[serde(default)]
    pub hop_endpoints: Vec<String>,
}

/// Errors from production config parsing.
#[derive(Debug)]
pub enum ProdConfigError {
    /// JSON parse error.
    Json(String),
    /// Hex decode error.
    Hex(String),
    /// CBOR decode error.
    Cbor(String),
    /// Signature verification failed.
    Signature(String),
    /// Missing required field.
    Missing(String),
}

impl std::fmt::Display for ProdConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(msg) => write!(f, "config JSON error: {msg}"),
            Self::Hex(msg) => write!(f, "hex decode error: {msg}"),
            Self::Cbor(msg) => write!(f, "CBOR decode error: {msg}"),
            Self::Signature(msg) => write!(f, "signature verification failed: {msg}"),
            Self::Missing(msg) => write!(f, "missing field: {msg}"),
        }
    }
}

impl std::error::Error for ProdConfigError {}

/// Load a ProdConfig from a JSON file.
pub fn load_config(path: &str) -> Result<ProdConfig, ProdConfigError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| ProdConfigError::Json(format!("read {path}: {e}")))?;
    serde_json::from_str(&json).map_err(|e| ProdConfigError::Json(format!("parse: {e}")))
}

/// Decode a hex string into bytes.
fn hex_decode(hex_str: &str, name: &str) -> Result<Vec<u8>, ProdConfigError> {
    if hex_str.len() % 2 != 0 {
        return Err(ProdConfigError::Hex(format!(
            "{name} length {} is odd",
            hex_str.len()
        )));
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|e| ProdConfigError::Hex(format!("{name} byte at {i}: {e}")))
        })
        .collect()
}

/// Decode a 32-byte hex string.
fn hex_decode_32(hex_str: &str, name: &str) -> Result<[u8; 32], ProdConfigError> {
    let bytes = hex_decode(hex_str, name)?;
    if bytes.len() != 32 {
        return Err(ProdConfigError::Hex(format!(
            "{name} must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Verify a signed advertisement and extract the VerifiedNodeDescriptor +
/// authenticated endpoint.
///
/// This function does NOT need any private key. The signature was made by
/// the mesh/gateway process with the hop's private key; we verify it here
/// using only the public key embedded in the advertisement.
fn verify_advert(
    advert_cbor_hex: &str,
    name: &str,
) -> Result<
    (
        crate::node::VerifiedNodeDescriptor,
        String, // authenticated endpoint (signed listen_addr)
    ),
    ProdConfigError,
> {
    let cbor_bytes = hex_decode(advert_cbor_hex, name)?;
    let advert = crate::node::GatewayAdvertisement::decode_cbor(&cbor_bytes)
        .map_err(|e| ProdConfigError::Cbor(format!("decode {name}: {e:?}")))?;
    let verified = advert
        .verify_into_verified()
        .ok_or_else(|| ProdConfigError::Signature(format!("verify {name}: signature invalid")))?;
    let descriptor = verified
        .descriptor()
        .ok_or_else(|| ProdConfigError::Signature(format!("{name}: no circuit key")))?;
    let endpoint = verified.listen_addr().to_string();
    eprintln!(
        "[prod-config] verified {name}: node_id={} endpoint={}",
        hex_short(&descriptor.node_id()),
        endpoint
    );
    Ok((descriptor, endpoint))
}

/// Build a Route from the production config.
///
/// The route is constructed from:
/// - The source NodeId (the relay's or client's own NodeId — a PUBLIC value)
/// - The destination NodeId (the gateway's NodeId — from the last advert)
/// - The verified descriptors + authenticated endpoints from each signed advert
///
/// NO private keys are needed. The endpoints come from the SIGNED listen_addr
/// in the verified advertisements.
pub fn build_route_from_config(config: &ProdConfig) -> Result<crate::node::Route, ProdConfigError> {
    let source = hex_decode_32(&config.source_node_id_hex, "source_node_id")?;

    // Verify each advert and extract the authenticated descriptor + endpoint.
    let mut hops = Vec::new();
    let mut destination = [0u8; 32];

    for (i, advert_hex) in config.hop_adverts_cbor_hex.iter().enumerate() {
        let name = format!("hop {i}");
        let (descriptor, auth_endpoint) = verify_advert(advert_hex, &name)?;
        destination = descriptor.node_id();

        // Use the endpoint from the config if provided, otherwise use the
        // authenticated endpoint from the signed advert.
        let endpoint = if i < config.hop_endpoints.len() && !config.hop_endpoints[i].is_empty() {
            // Verify the config endpoint matches the signed endpoint.
            if config.hop_endpoints[i] != auth_endpoint {
                eprintln!(
                    "[prod-config] WARNING: config endpoint {} differs from signed endpoint {} — using SIGNED endpoint",
                    config.hop_endpoints[i], auth_endpoint
                );
            }
            auth_endpoint
        } else {
            auth_endpoint
        };

        hops.push(crate::node::RouteHop::new(
            descriptor,
            crate::node::TransportEndpoint::Tcp(endpoint),
        ));
    }

    // If destination_node_id_hex is provided, verify it matches the last hop.
    if !config.destination_node_id_hex.is_empty() {
        let config_dest = hex_decode_32(&config.destination_node_id_hex, "destination_node_id")?;
        if config_dest != destination {
            return Err(ProdConfigError::Signature(format!(
                "destination NodeId mismatch: config={}, last hop={}",
                hex_short(&config_dest),
                hex_short(&destination)
            )));
        }
    }

    let mut route = crate::node::Route::new_with_hop_details(source, destination, hops);
    route
        .validate()
        .map_err(|e| ProdConfigError::Cbor(format!("route validate: {e:?}")))?;
    route
        .transition(crate::node::RouteState::Establishing)
        .map_err(|e| ProdConfigError::Cbor(format!("route Establishing: {e:?}")))?;
    route
        .transition(crate::node::RouteState::Active)
        .map_err(|e| ProdConfigError::Cbor(format!("route Active: {e:?}")))?;

    eprintln!(
        "[prod-config] route built: {} hops, source={}, dest={}",
        config.hop_adverts_cbor_hex.len(),
        hex_short(&source),
        hex_short(&destination)
    );

    Ok(route)
}

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    } else {
        format!(
            "{}…",
            bytes[..4]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}
