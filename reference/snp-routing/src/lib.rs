//! SNP-ROUTING — L6 gateway-anchored routing for ShareNet 2.0
//!
//! Implements the SNP/0.1 L6 routing layer — **the heart of the new thesis**
//! (per `01-ARCHITECTURE.md` §2.4 and `02-PROTOCOL-SPEC.md` §8):
//!
//! - **Gateway-anchored proactive advertisements** — every gateway periodically
//!   floods a Route Advertisement (RA) announcing its presence and the routes
//!   it offers. Non-gateway nodes propagate RAs but do not originate them.
//! - **Path-vector loop detection** — each RA carries the full path of NodeIds
//!   it has traversed. A node receiving an RA containing its own NodeId drops
//!   it. This is the same technique BGP uses; it is the simplest loop
//!   prevention that works under arbitrary topology churn.
//! - **Metric computation** — each link contributes a metric (latency, loss,
//!   battery cost). The route's total metric is the sum of link metrics, and
//!   nodes pick the lowest-metric route to each destination prefix.
//! - **Dual-route maintenance** — every node maintains a primary and a backup
//!   route to each gateway, so that killing the primary triggers migration
//!   within 5 s (the N4 DoD).
//! - **Migration** — when the primary route fails, the backup is promoted
//!   atomically and a new backup is sought.
//!
//! This is the Rust equivalent of `/src/lib/snp/routing.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/10-routing.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the L6 routing layer.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// A route advertisement contained a loop (the receiving NodeId was in
    /// the path).
    #[error("loop detected in route advertisement")]
    LoopDetected,
    /// No route exists to the requested destination.
    #[error("no route to {0}")]
    NoRoute(String),
    /// A route advertisement's signature failed verification.
    #[error("invalid route advertisement signature")]
    InvalidSignature,
    /// A route advertisement is stale.
    #[error("stale route advertisement")]
    StaleAdvertisement,
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] snp_crypto::CryptoError),
}

/// Convenience `Result` alias.
pub type RoutingResult<T> = Result<T, RoutingError>;

/// A gateway-anchored Route Advertisement (RA).
#[derive(Debug, Clone)]
pub struct RouteAdvertisement {
    /// The originating gateway's NodeId.
    pub origin: snp_identity::NodeId,
    /// Sequence number, incremented by the origin on every RA.
    pub seq: u64,
    /// Unix timestamp (seconds) at which the RA was originated.
    pub originated_at: u64,
    /// Time-to-live in hops. Decremented at each forwarding node; dropped at 0.
    pub ttl: u8,
    /// Path of NodeIds the RA has traversed, in order. Origin is `path[0]`.
    pub path: Vec<snp_identity::NodeId>,
    /// Aggregated metric from origin to current node.
    pub metric: RouteMetric,
    /// Originating gateway's signature over canonical CBOR of all fields above.
    pub signature: snp_crypto::Signature,
}

/// A route metric: sum of per-link contributions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteMetric {
    /// Estimated one-way latency in milliseconds.
    pub latency_ms: u32,
    /// Estimated packet loss in parts per million.
    pub loss_ppm: u32,
    /// Battery cost score (0–255, 0 = plugged in, 255 = critical).
    pub battery_cost: u8,
    /// Hop count.
    pub hops: u8,
}

impl RouteMetric {
    /// Combine two metrics (sum the components).
    pub fn combine(self, _other: Self) -> Self {
        todo!("Sum two RouteMetrics")
    }

    /// A total ordering over metrics — lower is better.
    pub fn total(self) -> u64 {
        todo!("Compute a single comparable total from the components")
    }
}

impl RouteAdvertisement {
    /// Originate a new RA as a gateway.
    pub fn originate(
        _origin: &snp_identity::NodeId,
        _seq: u64,
        _now: u64,
        _initial_ttl: u8,
        _origin_secret: &snp_crypto::SecretKey,
    ) -> RoutingResult<Self> {
        todo!("Build and sign the first hop of a RouteAdvertisement")
    }

    /// Forward an RA: append `next_hop` to the path, decrement TTL, recompute
    /// metric. The signature is preserved (only the origin signs).
    pub fn forward(
        &mut self,
        _next_hop: &snp_identity::NodeId,
        _link_metric: RouteMetric,
    ) -> RoutingResult<()> {
        todo!("Append to path, decrement TTL, combine metric, drop on loop/TTL=0")
    }

    /// Verify the origin's signature.
    pub fn verify(&self, _origin_public: &snp_crypto::PublicKey) -> RoutingResult<()> {
        todo!("Verify RouteAdvertisement signature via snp_crypto::ed25519_verify")
    }
}

/// The routing table: per-destination primary and backup routes.
#[derive(Debug, Default)]
pub struct RoutingTable {
    /// Primary route per origin gateway.
    pub primary: Vec<RouteEntry>,
    /// Backup route per origin gateway (different first-hop than primary).
    pub backup: Vec<RouteEntry>,
}

/// One entry in the routing table.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// The originating gateway's NodeId.
    pub origin: snp_identity::NodeId,
    /// Next-hop NodeId for this route.
    pub next_hop: snp_identity::NodeId,
    /// Full path to the origin.
    pub path: Vec<snp_identity::NodeId>,
    /// Aggregated metric.
    pub metric: RouteMetric,
    /// Sequence number of the last RA that updated this entry.
    pub seq: u64,
    /// Unix timestamp (seconds) at which the entry was last refreshed.
    pub refreshed_at: u64,
}

impl RoutingTable {
    /// Install a new RA into the table. Returns whether the primary route
    /// changed (which triggers a migration event).
    pub fn install(&mut self, _ra: &RouteAdvertisement, _now: u64) -> RoutingResult<bool> {
        todo!("Install an RA into the routing table, maintaining primary/backup")
    }

    /// Promote the backup route to primary when the primary fails.
    pub fn migrate(&mut self, _origin: &snp_identity::NodeId, _now: u64) -> RoutingResult<()> {
        todo!("Promote backup to primary; emit a migration event")
    }

    /// Look up the next hop for `origin`, preferring the primary route.
    pub fn next_hop(&self, _origin: &snp_identity::NodeId) -> Option<&snp_identity::NodeId> {
        todo!("Return the next-hop NodeId for the given origin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/10-routing.json (RA wire format, loop
        // detection, metric combination, primary/backup installation,
        // migration events).
        let _ = RoutingTable::default();
    }
}
