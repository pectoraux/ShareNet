//! SNP-TUN — Linux TUN packet boundary for ShareNet transparent networking.
//!
//! **N2.3.1 — Linux TUN Packet Boundary Foundation.**
//!
//! This crate provides the kernel packet entry/exit boundary for the
//! ShareNet transparent networking pipeline (N2.3+). It is an ADAPTER LAYER
//! on top of the existing ShareNet stack — it does NOT introduce routing
//! decisions, gateway selection, encryption, peer discovery, transport, or
//! application-specific handling.
//!
//! ## Architecture
//!
//! ```text
//! Linux Kernel
//!      |
//!     TUN fd (/dev/net/tun)
//!      |
//! LinuxTunDevice  ──implements──►  PacketDevice
//!                                      |
//!                               (future N2.3.2+)
//!                               ShareNet stack
//! ```
//!
//! The [`PacketDevice`] trait is the seam: production code uses
//! [`LinuxTunDevice`] (real TUN), tests use [`MockPacketDevice`] (in-memory).
//! Both implement the same async API, so upper layers can be developed and
//! tested without root privileges.
//!
//! ## Scope (N2.3.1)
//!
//! - Create a TUN interface via `/dev/net/tun` + `ioctl(TUNSETIFF)`.
//! - Async read/write IP packets (Tokio-compatible, `AsyncFd`-based).
//! - Parse IPv4/IPv6 headers into [`PacketMetadata`].
//! - Trait seam for testability.
//!
//! ## Out of scope (future milestones)
//!
//! - TCP/UDP proxying.
//! - DNS interception.
//! - smoltcp integration.
//! - macOS utun / Windows wintun / Android VpnService.
//! - OS routing table changes.
//! - Application-specific handling.
//!
//! ## Platform support
//!
//! `LinuxTunDevice` is only available on Linux (`#[cfg(target_os = "linux")]`).
//! On other platforms, only `MockPacketDevice` and packet parsing are available
//! (for development/CI on non-Linux workstations).
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # {
//! use snp_tun::{LinuxTunDevice, PacketDevice};
//!
//! # async fn example() -> Result<(), snp_tun::TunError> {
//! let mut tun = LinuxTunDevice::create("snp0")?;
//!
//! loop {
//!     let packet = tun.read_packet().await?;
//!     println!(
//!         "packet: {} -> {} (proto={}, len={})",
//!         packet.metadata().source,
//!         packet.metadata().destination,
//!         packet.metadata().protocol,
//!         packet.metadata().length,
//!     );
//! }
//! # }
//! # }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::pedantic)]

pub mod device;
pub mod error;
pub mod packet;

pub use device::{MockPacketDevice, PacketDevice};
#[cfg(target_os = "linux")]
pub use device::LinuxTunDevice;
pub use error::TunError;
pub use packet::{
    build_test_ipv4_packet, build_test_ipv6_packet, IpPacket, Ipv4Packet, Ipv6Packet,
    PacketMetadata, MAX_PACKET_SIZE,
};
