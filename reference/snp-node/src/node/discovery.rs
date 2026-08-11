//! Discovery — platform-independent DiscoveryProvider abstraction.
//!
//! Extracted from node.rs for N2.0.3 Gate J (Node decomposition).

use super::*;


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
/// The actual discovery I/O (TCP connect + SNP-IK/0.1 handshake + fetch
/// advertisement) is deferred to a future revision — for now, `discover()`
/// returns an empty list (callers that need actual discovery should use
/// [`Node::discover_gateways`], which performs the legacy N2.0.1 discovery
/// flow). The trait abstraction is the N2.0.3 deliverable; wiring the
/// underlying I/O into the trait is the N2.0.4 deliverable.
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
}

impl DiscoveryProvider for BootstrapDiscovery {
    fn discover(&self) -> Vec<DiscoveredNode> {
        // The actual discovery I/O is the same as Node::discover_gateways
        // (legacy N2.0.1 implementation). For N2.0.3 we wrap the result in
        // the new trait — the underlying TCP fetch is unchanged.
        // This is a placeholder: production code would call the new
        // SNP-IK/0.1-based discovery (a single anonymous X25519 handshake
        // to each address, fetching the advertisement over the established
        // link). For now we return an empty list — callers that need
        // actual discovery should use Node::discover_gateways.
        let _ = &self.addrs;
        Vec::new()
    }
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

