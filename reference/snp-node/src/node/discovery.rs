//! Discovery — platform-independent DiscoveryProvider abstraction.
//!
//! Extracted from node.rs for N2.0.3 Gate J (Node decomposition).
//! Updated for N2.0.4 Gate A (real BootstrapDiscovery I/O).

use super::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;


// ─── Discovery (Phase 6 — N2.0.3 Gate C: DiscoveryProvider abstraction) ──────

/// A discovered peer or gateway advertisement, paired with the TCP endpoint
/// it can be reached at.
///
/// The protocol does not care whether discovery came from:
/// - configured bootstrap peers ([`BootstrapDiscovery`])
/// - LAN discovery (mDNS)
/// - Bluetooth
/// - Wi-Fi Direct
/// - another ShareNet peer ([`StaticDiscovery`] for tests)
///
/// The `endpoint` is the TCP address (e.g. `"127.0.0.1:7001"` or
/// `"gateway1.example:7001"`) at which the advertising node can be reached
/// for transit. The `advertisement` is the signed [`GatewayAdvertisement`]
/// (which itself contains `listen_addr` and `discovery_addr`); the
/// `endpoint` field here lets a discovery provider carry a separately-resolved
/// address (e.g. an mDNS-resolved LAN address) without overwriting the
/// advertisement's signed fields.
#[derive(Debug, Clone)]
pub struct DiscoveredNode {
    /// The signed advertisement (caller MUST verify the signature before use).
    pub advertisement: GatewayAdvertisement,
    /// The TCP address at which this node can be reached for transit.
    pub endpoint: String,
}

/// Platform-independent discovery abstraction.
///
/// A [`DiscoveryProvider`] is a SOURCE of [`DiscoveredNode`]s — it knows how
/// to find peers/gateways but does NOT verify advertisements (that is the
/// caller's responsibility, see [`GatewayAdvertisement::verify`]) and does
/// NOT maintain routing state (that is the caller's responsibility, see
/// [`GatewayDirectory`]).
///
/// The trait is `Send + Sync` so a provider can be shared across threads
/// (e.g. an mDNS provider that runs a background listener thread).
///
/// ## Implementations
///
/// - [`BootstrapDiscovery`] — reads a configured list of TCP addresses and
///   queries each for a signed advertisement. Used for the first-run case.
/// - [`StaticDiscovery`] — a deterministic, in-memory list. Used for tests
///   and for "bring your own topology" scenarios.
///
/// ## N2.0.3 (Gate C)
///
/// This trait is the N2.0.3 abstraction over the discovery layer. The N2.0.1
/// `Node::discover_gateways` method is the production caller; it loops over
/// a `Vec<String>` of addresses and verifies each advertisement. The trait
/// lets the SAME caller logic drive mDNS / Bluetooth / Wi-Fi Direct / etc.
/// discovery without changes — only the provider implementation changes.
///
/// ## N2.0.4 (Gate A)
///
/// [`BootstrapDiscovery::discover`] NOW performs actual TCP I/O — it
/// connects to each bootstrap address, sends a single-byte `0x01` discovery
/// request, reads a 4-byte big-endian length-prefixed CBOR advertisement,
/// verifies the signature, and checks expiry. Previously (N2.0.3) it
/// returned an empty `Vec` as a placeholder.
pub trait DiscoveryProvider: Send + Sync {
    /// Discover peers/gateways. Returns a list of [`DiscoveredNode`]s.
    ///
    /// The caller is responsible for:
    /// 1. Verifying each `advertisement`'s signature
    ///    ([`GatewayAdvertisement::verify`]).
    /// 2. Checking each `advertisement`'s expiry
    ///    ([`GatewayAdvertisement::is_expired`]).
    /// 3. Cross-checking each `advertisement`'s `node_id` against
    ///    `SHA-256("SNP/0.1 node\0" || public_key)` (invariant I4).
    /// 4. Adding the verified advertisements to a [`GatewayDirectory`].
    ///
    /// **N2.0.4 (Gate A):** [`BootstrapDiscovery`] performs steps 1-2
    /// inside `discover()` (so the returned [`DiscoveredNode`]s have
    /// verified signatures and are non-expired). The caller STILL MUST
    /// perform step 3 (the I4 cross-check) — this is a defence-in-depth
    /// measure so a future BootstrapDiscovery implementation that forgets
    /// signature verification does not cause a security regression.
    fn discover(&self) -> Vec<DiscoveredNode>;

    /// Advertise this node's presence. Called by a node that wants to be
    /// discoverable by other nodes (e.g. a gateway advertising itself on the
    /// LAN via mDNS, or registering with a directory service).
    ///
    /// The default implementation is a no-op (some providers — e.g.
    /// [`BootstrapDiscovery`] and [`StaticDiscovery`] — do not support
    /// outbound advertising).
    fn advertise(&self, _advertisement: &GatewayAdvertisement, _endpoint: &str) {
        // Default no-op: providers that don't support outbound advertising
        // (bootstrap list, static list) silently ignore the call.
    }
}

/// A bootstrap-list discovery provider: holds a list of TCP addresses and
/// queries each for a signed advertisement. Used for the first-run case
/// (no cached gateways).
///
/// **N2.0.3 (Gate C).** The trait now returns [`DiscoveredNode`]s (with an
/// `endpoint` field) instead of bare [`GatewayAdvertisement`]s. The
/// `endpoint` is set to the bootstrap address that produced the
/// advertisement (so a caller can reach the gateway for transit without
/// parsing the advertisement's `listen_addr`).
///
/// **N2.0.4 (Gate A).** `discover()` NOW performs actual TCP I/O. The
/// discovery protocol is intentionally simple:
///
/// 1. Connect to the bootstrap address via raw TCP.
/// 2. Send a single byte `0x01` ([`DISCOVERY_REQUEST_BYTE`]) — the
///    "give me your advertisement" marker.
/// 3. Read a 4-byte big-endian length prefix.
/// 4. Read that many bytes of CBOR-encoded [`GatewayAdvertisement`].
/// 5. Decode the advertisement.
/// 6. Verify the advertisement's Ed25519 signature under
///    `SIG_CONTEXTS::GATEWAY_ADVERT`.
/// 7. Check the advertisement's `expiry` against the current time.
/// 8. If both checks pass, return `Ok(DiscoveredNode { advertisement, endpoint })`.
///
/// ### Why is the discovery link UNAUTHENTICATED?
///
/// The advertisement itself is **signed** by the gateway's Ed25519 secret
/// key under `SIG_CONTEXTS::GATEWAY_ADVERT`. A network attacker can
/// substitute their own advertisement, but the signature check at step 6
/// rejects it (the attacker cannot forge a signature under the gateway's
/// public key). The attacker can also DROP or REPLAY a real advertisement,
/// but replay is bounded by the `expiry` field (a stale advertisement is
/// rejected at step 7).
///
/// The DELIBERATE SIMPLIFICATION for N2.0.4 is that an attacker can OBSERVE
/// the advertisement request (and learn the gateway's `node_id`,
/// `public_key`, `listen_addr`, etc. — though these are already public).
/// Production would use an anonymous X25519 ephemeral handshake for the
/// discovery link to prevent eavesdropping on the advertisement request
/// itself. See `docs/n2.0.3-android-platform-contract.md` for the production
/// design.
pub struct BootstrapDiscovery {
    addrs: Vec<String>,
}

impl BootstrapDiscovery {
    /// Construct a new `BootstrapDiscovery` with the given list of TCP
    /// addresses (e.g. `["gateway1.example:7001", "gateway2.example:7001"]`).
    #[must_use]
    pub fn new(addrs: Vec<String>) -> Self {
        Self { addrs }
    }

    /// Return the bootstrap addresses (for inspection / debugging).
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addrs
    }

    /// Query ONE bootstrap address for a signed advertisement.
    ///
    /// Implements the raw discovery protocol (see the struct doc). Returns
    /// an error string (NOT a [`NodeError`]) so the caller can log it
    /// alongside the failing address — `discover()` does exactly this.
    fn discover_one(&self, addr: &str) -> Result<DiscoveredNode, String> {
        // 1. Connect.
        let mut stream =
            TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
        // Disable Nagle — the discovery request is 1 byte.
        let _ = stream.set_nodelay(true);
        // Set a read timeout so we don't hang on unresponsive gateways.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        // 2. Send the 1-byte discovery request.
        stream
            .write_all(&[DISCOVERY_REQUEST_BYTE])
            .map_err(|e| format!("send request: {e}"))?;
        stream.flush().map_err(|e| format!("flush request: {e}"))?;

        // 3. Read the 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("recv length: {e}"))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        // Sanity-check the length — advertisements are < 4 KiB. Anything
        // larger is either a malformed gateway or an attack.
        const MAX_ADVERTISEMENT_LEN: usize = 64 * 1024;
        if len > MAX_ADVERTISEMENT_LEN {
            return Err(format!(
                "advertisement length {len} exceeds max {MAX_ADVERTISEMENT_LEN}"
            ));
        }

        // 4. Read `len` bytes of CBOR-encoded advertisement.
        let mut advert_buf = vec![0u8; len];
        stream
            .read_exact(&mut advert_buf)
            .map_err(|e| format!("recv advert: {e}"))?;

        // 5. Decode the advertisement.
        let advert = GatewayAdvertisement::decode_cbor(&advert_buf)
            .map_err(|e| format!("decode advert: {e}"))?;

        // 6. VERIFY THE SIGNATURE. This is the security check that makes
        //    the unauthenticated discovery link safe — a network attacker
        //    cannot forge a signature under the gateway's public key.
        if !advert.verify() {
            return Err("advertisement signature verification failed".to_string());
        }

        // 7. Check expiry.
        let now = super::now_unix();
        if advert.is_expired(now) {
            return Err("advertisement expired".to_string());
        }

        // 8. (Step 3 of the caller's responsibility — the I4 cross-check —
        //    is NOT done here. The caller (`Node::discover_gateways` or
        //    equivalent) is expected to perform it. This is a
        //    defence-in-depth measure so a future BootstrapDiscovery
        //    implementation that forgets signature verification does not
        //    cause a security regression.)
        Ok(DiscoveredNode {
            advertisement: advert,
            endpoint: addr.to_string(),
        })
    }
}

impl DiscoveryProvider for BootstrapDiscovery {
    fn discover(&self) -> Vec<DiscoveredNode> {
        let mut results = Vec::with_capacity(self.addrs.len());
        for addr in &self.addrs {
            eprintln!("[bootstrap-discovery] querying {addr}");
            match self.discover_one(addr) {
                Ok(node) => {
                    eprintln!(
                        "[bootstrap-discovery] {addr} OK: nodeId={}",
                        hex_short(&node.advertisement.node_id)
                    );
                    results.push(node);
                }
                Err(e) => {
                    eprintln!("[bootstrap-discovery] {addr} failed: {e}");
                }
            }
        }
        results
    }
    // advertise() uses the default no-op implementation (a bootstrap list
    // does not support outbound advertising).
}

/// A deterministic, in-memory discovery provider. Holds a pre-configured
/// list of [`DiscoveredNode`]s and returns them verbatim from `discover()`.
///
/// **N2.0.3 (Gate C).** This is the reference implementation for tests:
/// it lets a test construct a discovery scenario (e.g. "the client
/// discovers these three gateways") without running any I/O. It is also
/// useful for "bring your own topology" scenarios where the caller already
/// knows the gateway addresses (e.g. from a configuration file or a prior
/// discovery run).
///
/// `advertise()` is a no-op (a static list does not support outbound
/// advertising — the list is configured at construction time).
pub struct StaticDiscovery {
    nodes: Vec<DiscoveredNode>,
}

impl StaticDiscovery {
    /// Construct an empty `StaticDiscovery`.
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Add a [`DiscoveredNode`] to the static list. The node is appended
    /// (duplicates are NOT deduplicated — the caller is responsible for
    /// uniqueness if it matters).
    pub fn add(&mut self, node: DiscoveredNode) {
        self.nodes.push(node);
    }

    /// Return the number of nodes in the static list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Return `true` if the static list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl Default for StaticDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryProvider for StaticDiscovery {
    fn discover(&self) -> Vec<DiscoveredNode> {
        self.nodes.clone()
    }
    // advertise() uses the default no-op implementation.
}
