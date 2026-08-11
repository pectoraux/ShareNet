//! SNP-ROUTING — Simple route table for the N1.8 minimal Internet bridge
//!
//! The full SNP/0.1 L6 routing layer is gateway-anchored, path-vector based,
//! with dual-route maintenance and migration (see the TypeScript reference
//! at `/src/lib/snp/routing.ts`). That is OUT OF SCOPE for N1.8.
//!
//! For N1.8, this crate provides a SIMPLE static `RouteTable`:
//!
//! - Stores one route per destination NodeId: `(destination, next_hop,
//!   hop_count, metric)`.
//! - [`add_route`] installs a route (replacing any existing route to the
//!   same destination if the new one has a lower metric).
//! - [`best_gateway`] returns the gateway with the lowest metric.
//! - [`next_hop`] returns the next hop for a destination.
//!
//! The relay uses this to know "to forward a frame to gateway NodeId G, send
//! it on the TCP link to peer N". The route is configured at startup; there
//! is no dynamic route advertisement, no path-vector loop detection, no
//! migration. This is the minimum needed for the N1.8 demonstration.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use thiserror::Error;

/// Errors from the routing layer.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// No route exists to the requested destination.
    #[error("no route to {0}")]
    NoRoute(String),
}

/// Convenience `Result` alias.
pub type RoutingResult<T> = Result<T, RoutingError>;

/// A NodeId is a 32-byte SHA-256 hash (I4).
pub type NodeId = [u8; 32];

/// A route advertisement: one hop in the routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteAdvert {
    /// The destination NodeId this route reaches (typically a gateway).
    pub destination: NodeId,
    /// The next-hop NodeId for this route. For a directly-connected gateway
    /// this is the gateway's own NodeId.
    pub next_hop: NodeId,
    /// Number of hops to reach `destination`.
    pub hop_count: u8,
    /// Aggregate metric (lower is better). For N1.8 this is just `hop_count`.
    pub metric: u64,
}

/// A simple static routing table: `destination → RouteAdvert`.
#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    routes: HashMap<NodeId, RouteAdvert>,
}

/// Backward-compatible alias — the skeleton `snp-node` daemon referenced
/// `snp_routing::RoutingTable`. New code should prefer `RouteTable`.
pub type RoutingTable = RouteTable;

impl RouteTable {
    /// Construct an empty route table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a route advertisement.
    ///
    /// If a route to `route.destination` already exists, it is replaced only
    /// if the new route has a strictly lower metric. This is the simplest
    /// "best-route-wins" policy.
    pub fn add_route(&mut self, route: RouteAdvert) {
        match self.routes.get(&route.destination) {
            Some(existing) if existing.metric <= route.metric => {
                // Keep the existing (better or equal) route.
            }
            _ => {
                self.routes.insert(route.destination, route);
            }
        }
    }

    /// Return the best gateway NodeId (lowest-metric route whose destination
    /// is reachable). Returns `None` if the table is empty.
    #[must_use]
    pub fn best_gateway(&self) -> Option<NodeId> {
        self.routes
            .values()
            .min_by_key(|r| r.metric)
            .map(|r| r.destination)
    }

    /// Return the next-hop NodeId for `destination`, or `None` if no route.
    #[must_use]
    pub fn next_hop(&self, destination: &NodeId) -> Option<NodeId> {
        self.routes.get(destination).map(|r| r.next_hop)
    }

    /// Return the route for `destination`, or `None` if no route.
    #[must_use]
    pub fn route(&self, destination: &NodeId) -> Option<&RouteAdvert> {
        self.routes.get(destination)
    }

    /// Number of routes in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Is the table empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(byte: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn add_route_and_lookup() {
        let mut table = RouteTable::new();
        let gw = node_id(1);
        let next = node_id(2);
        table.add_route(RouteAdvert {
            destination: gw,
            next_hop: next,
            hop_count: 1,
            metric: 10,
        });
        assert_eq!(table.next_hop(&gw), Some(next));
        assert_eq!(table.best_gateway(), Some(gw));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn lower_metric_replaces() {
        let mut table = RouteTable::new();
        let gw = node_id(1);
        let next_a = node_id(2);
        let next_b = node_id(3);
        table.add_route(RouteAdvert {
            destination: gw,
            next_hop: next_a,
            hop_count: 2,
            metric: 20,
        });
        table.add_route(RouteAdvert {
            destination: gw,
            next_hop: next_b,
            hop_count: 1,
            metric: 10,
        });
        assert_eq!(table.next_hop(&gw), Some(next_b));
    }

    #[test]
    fn higher_metric_does_not_replace() {
        let mut table = RouteTable::new();
        let gw = node_id(1);
        let next_a = node_id(2);
        let next_b = node_id(3);
        table.add_route(RouteAdvert {
            destination: gw,
            next_hop: next_a,
            hop_count: 1,
            metric: 10,
        });
        table.add_route(RouteAdvert {
            destination: gw,
            next_hop: next_b,
            hop_count: 2,
            metric: 20,
        });
        assert_eq!(table.next_hop(&gw), Some(next_a));
    }

    #[test]
    fn best_gateway_picks_lowest_metric() {
        let mut table = RouteTable::new();
        let gw1 = node_id(1);
        let gw2 = node_id(2);
        table.add_route(RouteAdvert {
            destination: gw1,
            next_hop: gw1,
            hop_count: 1,
            metric: 50,
        });
        table.add_route(RouteAdvert {
            destination: gw2,
            next_hop: gw2,
            hop_count: 1,
            metric: 10,
        });
        assert_eq!(table.best_gateway(), Some(gw2));
    }

    #[test]
    fn missing_route_returns_none() {
        let table = RouteTable::new();
        assert_eq!(table.next_hop(&node_id(99)), None);
        assert_eq!(table.best_gateway(), None);
    }
}
