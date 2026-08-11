//! snp-node library — daemon internals for the ShareNet reference node.
//!
//! This crate exists so that `main.rs` stays a thin shell. The actual daemon
//! wiring (config loading, transport spawning, lifecycle) lives here as
//! library functions that `main.rs` calls.
//!
//! SKELETON — not yet implemented. See the TypeScript reference in
//! `/src/lib/snp/` for the working implementation (ADR-0001). When this
//! crate is complete, the daemon will:
//!
//! 1. Load or generate an identity (`snp-identity`).
//! 2. Open platform links (`platform/linux`, never in this crate).
//! 3. Authenticate peers via Noise_IK (`snp-link`).
//! 4. Discover peers via L4 beacons (`snp-discovery`).
//! 5. Sync objects via anti-entropy (`snp-sync`).
//! 6. Maintain routes via L6 advertisements (`snp-routing`).
//! 7. Open circuits via the L6/L7 circuit layer (`snp-circuit`).
//! 8. (If a gateway) egress to the Internet under policy (`snp-gateway`).
//! 9. Attest to contributions and compute reputation (`snp-civic`).

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the daemon.
#[derive(Debug, Error)]
pub enum NodeError {
    /// Configuration was missing or invalid.
    #[error("config error: {0}")]
    Config(String),
    /// Identity file was missing or unreadable.
    #[error("identity error: {0}")]
    Identity(#[from] snp_identity::IdentityError),
    /// Underlying IO error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience `Result` alias.
pub type NodeResult<T> = Result<T, NodeError>;

/// Daemon configuration: paths, ports, gateway-vs-relay role, etc.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to the identity file (secret key + descriptor).
    pub identity_path: std::path::PathBuf,
    /// Path to the CAS directory.
    pub cas_path: std::path::PathBuf,
    /// Whether this node acts as a gateway.
    pub is_gateway: bool,
    /// Egress policy (only used if `is_gateway`).
    pub egress: snp_gateway::EgressPolicy,
}

impl Config {
    /// Load config from the default path (`~/.config/sharenet/config.toml`).
    pub fn load_default() -> NodeResult<Self> {
        todo!("Load daemon config from TOML")
    }
}

/// The running daemon. Constructed by [`run`] and torn down on signal.
pub struct Daemon {
    /// Our identity descriptor.
    pub identity: snp_identity::NodeDescriptor,
    /// The CAS. `Send + Sync` is required so the daemon can move it across
    /// async tasks; the bound is on the trait, so `dyn Cas + Send + Sync` is
    /// the right object type.
    pub cas: std::sync::Arc<dyn snp_object::Cas + Send + Sync>,
    /// The descriptor store.
    pub descriptors: snp_discovery::DescriptorStore,
    /// The routing table.
    pub routes: snp_routing::RoutingTable,
}

impl Daemon {
    /// Construct a daemon from a config (does not start it).
    pub async fn from_config(_config: Config) -> NodeResult<Self> {
        todo!("Wire identity + CAS + descriptor store + routing table from config")
    }

    /// Run the daemon until shutdown. Spawns link, discovery, sync, routing,
    /// and (if gateway) gateway tasks.
    pub async fn run(self) -> NodeResult<()> {
        todo!("Spawn the daemon task tree and await shutdown signal")
    }
}

/// Subcommand entry: run the daemon.
pub async fn cmd_run(_config: Config) -> NodeResult<()> {
    todo!("`snp-node run` — start the daemon")
}

/// Subcommand entry: run the conformance suite.
pub fn cmd_conformance() -> NodeResult<()> {
    todo!("`snp-node conformance` — load /public/conformance/vectors/*.json and assert pass")
}

/// Subcommand entry: generate a new node identity.
pub fn cmd_keygen(_out_path: &std::path::Path) -> NodeResult<()> {
    todo!("`snp-node keygen` — generate Ed25519 keypair + initial NodeDescriptor")
}

/// Subcommand entry: scan for peers (one-shot).
pub async fn cmd_discover(_config: Config) -> NodeResult<()> {
    todo!("`snp-node discover` — listen for L4 beacons for 10 s and print peers")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will spin up two `Daemon`s in-process
        // and assert that they discover each other, authenticate, and sync
        // a 1 KiB object (the N3 DoD scaled down for unit tests).
        let _ = NodeError::Config("test".into());
    }
}
