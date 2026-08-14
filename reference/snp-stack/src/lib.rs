//! SNP-STACK — Packet flow classification + userspace TCP/IP engine for
//! ShareNet transparent networking.
//!
//! **N2.3.2 — Packet Flow Classification.** ✅
//! **N2.3.3 — Userspace TCP/IP Handling (smoltcp).** (this milestone)
//!
//! This crate sits above [`snp-tun`] (the kernel packet boundary) and below
//! the future ShareNet circuit integration (N2.3.4+). It provides:
//!
//! 1. **Flow classification** (N2.3.2) — converts raw IP packets into tracked
//!    network flows via [`FlowKey`] + [`FlowTable`].
//! 2. **Userspace TCP/IP engine** (N2.3.3) — wraps [`smoltcp`] to provide a
//!    real TCP/IP stack that can complete handshakes (SYN → SYN-ACK → ACK)
//!    through the TUN boundary. See [`TcpEngine`].
//!
//! ```text
//! TUN (snp-tun)
//!      |
//!      v
//! IpPacket (raw IP)
//!      |
//!      v
//! transport parsing (TCP/UDP headers)
//!      |
//!      v
//! FlowKey (5-tuple)
//!      |
//!      v
//! FlowTable (connection tracking + idle expiration)
//!      |
//!      v
//! TcpEngine (smoltcp — SYN/SYN-ACK/ACK handshake)
//!      |
//!      v
//! (future N2.3.4+ — ShareNet circuit integration)
//! ```
//!
//! ## Flow Ownership Invariant (FROZEN)
//!
//! **This invariant is FROZEN as of N2.3.2. Future milestones MUST NOT violate it.**
//!
//! A [`FlowKey`] and [`FlowTable`] are **observational state only**. They
//! classify packets; they do NOT participate in transport behavior.
//!
//! The `FlowTable` MUST NOT:
//!
//! - Generate packets (no SYN-ACK, no RST, no ACK generation).
//! - Acknowledge packets (no TCP acknowledgment logic).
//! - Modify sequence numbers.
//! - Terminate connections (no RST injection).
//! - Select routes (no gateway/relay selection).
//! - Create circuits (no ShareNet circuit integration).
//! - Send data to the network (no write to any `PacketDevice`).
//!
//! The `FlowTable` exists ONLY to associate kernel packets with future
//! transport handlers (the [`TcpEngine`] in [`tcp_engine`]).
//!
//! ## Architectural boundary
//!
//! ```text
//!              TUN (snp-tun)
//!                  |
//!              IpPacket
//!                  |
//!          FlowClassifier (snp-stack)
//!                  |
//!          TCP/IP Engine (TcpEngine, N2.3.3)
//!                  |
//!          ShareNet Socket (future)
//!                  |
//!              Circuit
//!                  |
//!              Gateway
//! ```
//!
//! The `FlowTable` sits ABOVE the packet boundary and BELOW the transport
//! engine. It must never grow into a half-TCP implementation. Future changes
//! should WRAP these APIs, not modify them:
//!
//! - [`FlowKey`] — frozen (N2.3.2).
//! - [`snp_tun::PacketMetadata`] — frozen (N2.3.1).
//! - [`snp_tun::IpPacket`] — frozen (N2.3.1).
//! - [`snp_tun::PacketDevice`] trait — frozen (N2.3.1).
//!
//! ## Out of scope (future milestones)
//!
//! - DNS interception (N2.3.4).
//! - HTTPS / HTTP proxy.
//! - Circuit creation / gateway routing (the frozen ShareNet stack is unchanged).
//! - Actual packet forwarding to the Internet.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::pedantic)]

pub mod dns;
pub mod flow_table;
pub mod smol_device;
pub mod tcp_engine;
pub mod transport;

pub use dns::{
    intercept_dns_query, is_dns_query, parse_dns_query, DnsError, DnsQclass, DnsQuestion,
    DnsQuery, DnsQtype, DnsResolver, DnsResponse, DNS_PORT,
};
pub use flow_table::{FlowEntry, FlowState, FlowTable, TcpState, UdpState};
pub use tcp_engine::{TcpEngine, TcpEngineError};
pub use transport::{
    flow_key, parse_transport, FlowKey, TcpFlags, TcpHeader, TransportError, TransportHeader,
    UdpHeader, PROTO_TCP, UDP,
};
