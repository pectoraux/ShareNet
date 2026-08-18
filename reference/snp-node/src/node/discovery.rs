//! Discovery — runtime discovery provider implementations.
//!
//! R2.4 extraction: DiscoveredNode, DiscoveryProvider, and StaticDiscovery
//! have been moved to the snp-discovery crate (L4 layer). This file
//! re-exports them and keeps BootstrapDiscovery (which uses TCP I/O)
//! in snp-node (runtime code).
//!
//! The dependency direction is:
//!   snp-discovery (owns discovery types)
//!       ↓
//!   snp-node (re-exports + runtime implementations)

// Re-export the types that were extracted to snp-discovery.
pub use snp_discovery::{DiscoveredNode, DiscoveryProvider, StaticDiscovery};

use super::*;
use std::io::{Read, Write};
use std::time::Duration;

// ─── BootstrapDiscovery (runtime, TCP I/O — stays in snp-node) ─────────────

/// A bootstrap-list discovery provider: holds a list of TCP addresses and
/// queries each for a signed advertisement. Used for the first-run case
/// (no cached gateways).
///
/// **N2.0.6: DEPRECATED** — use the async equivalent
/// `async_node::discover_gateways_async`.
pub struct BootstrapDiscovery {
    addrs: Vec<String>,
}

impl BootstrapDiscovery {
    /// Construct a new `BootstrapDiscovery` with the given list of TCP
    /// addresses.
    #[must_use]
    pub fn new(addrs: Vec<String>) -> Self {
        Self { addrs }
    }

    /// Return the bootstrap addresses.
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addrs
    }
}

/// The discovery request byte sent to a bootstrap address.
const DISCOVERY_REQUEST_BYTE: u8 = 0x01;

impl DiscoveryProvider for BootstrapDiscovery {
    fn discover(&self) -> Vec<DiscoveredNode> {
        let mut results = Vec::new();
        for addr in &self.addrs {
            match self.discover_one(addr) {
                Ok(node) => results.push(node),
                Err(e) => {
                    eprintln!("[discovery] bootstrap {addr} failed: {e}");
                }
            }
        }
        results
    }
}

impl BootstrapDiscovery {
    /// Query ONE bootstrap address for a signed advertisement.
    ///
    /// **N2.0.6: DEPRECATED** — use the async equivalent.
    #[deprecated(since = "N2.0.6", note = "use `async_node::discover_gateways_async`")]
    fn discover_one(&self, addr: &str) -> Result<DiscoveredNode, String> {
        // 1. Connect.
        let mut stream = std::net::TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("parse {addr}: {e}"))?,
            Duration::from_secs(5),
        )
        .map_err(|e| format!("connect {addr}: {e}"))?;

        // 2. Send discovery request byte.
        stream
            .write_all(&[DISCOVERY_REQUEST_BYTE])
            .map_err(|e| format!("write request: {e}"))?;

        // 3. Read 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read length: {e}"))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // 4. Read CBOR advertisement.
        let mut cbor_buf = vec![0u8; len];
        stream
            .read_exact(&mut cbor_buf)
            .map_err(|e| format!("read advert: {e}"))?;

        // 5. Decode advertisement.
        let advert = GatewayAdvertisement::decode_cbor(&cbor_buf)
            .map_err(|e| format!("decode advert: {e:?}"))?;

        // 6. Verify signature.
        if !advert.verify() {
            return Err("advert signature verification failed".into());
        }

        // 7. Check expiry.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if advert.is_expired(now) {
            return Err("advert expired".into());
        }

        Ok(DiscoveredNode {
            advertisement: advert,
            endpoint: addr.to_string(),
        })
    }
}
