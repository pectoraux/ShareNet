//! SNP-STACK — Packet flow classification for ShareNet transparent networking.
//!
//! **N2.3.2 — Packet Flow Classification.**
//!
//! This crate sits above [`snp-tun`] (the kernel packet boundary) and below
//! the future transparent networking layers (N2.3.3+). It converts raw IP
//! packets into tracked network flows:
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
//! (future N2.3.3+ — userspace TCP/IP handling)
//! ```
//!
//! ## Scope (N2.3.2)
//!
//! - TCP header parsing (ports, flags, sequence/ack numbers, data offset).
//! - UDP header parsing (ports, length).
//! - [`FlowKey`] extraction (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol).
//! - [`FlowTable`] — thread-safe flow tracking with TCP state machine
//!   (SynSent → Established → Closing → Closed) and idle expiration.
//! - TCP SYN/SYN-ACK/FIN/RST detection for connection tracking.
//! - UDP flow detection (New → Established).
//!
//! ## Out of scope (future milestones)
//!
//! - TCP proxy / userspace TCP stack (N2.3.3).
//! - smoltcp integration.
//! - DNS interception (N2.3.4).
//! - Circuit creation / gateway routing (the frozen ShareNet stack is unchanged).
//! - Actual packet forwarding.
//!
//! ## Architecture
//!
//! `snp-stack` depends on `snp-tun` (for [`IpPacket`]) but NOT on any other
//! ShareNet crate. The frozen architecture (Identity, Discovery, Route,
//! Circuit, Gateway, Internet) is UNTOUCHED — this crate is a pure
//! classification layer.
//!
//! ## Example
//!
//! ```no_run
//! use snp_stack::{FlowTable, TransportHeader, parse_transport, flow_key};
//! use snp_tun::{IpPacket, PacketDevice, MockPacketDevice};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let table = FlowTable::new();
//! let mut device = MockPacketDevice::new();
//!
//! loop {
//!     match device.read_packet().await {
//!         Ok(packet) => {
//!             if let Some(transport) = parse_transport(&packet)? {
//!                 let key = flow_key(&packet, &transport)?;
//!                 let tcp_flags = match &transport {
//!                     TransportHeader::Tcp(tcp) => Some(tcp.flags),
//!                     TransportHeader::Udp(_) => None,
//!                 };
//!                 let entry = table.process_packet(
//!                     &key, tcp_flags, std::time::Instant::now(),
//!                     packet.metadata().length,
//!                 ).await;
//!                 # let _ = entry;
//!             }
//!         }
//!         Err(_) => break,
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::pedantic)]

pub mod flow_table;
pub mod transport;

pub use flow_table::{FlowEntry, FlowState, FlowTable, TcpState, UdpState};
pub use transport::{
    flow_key, parse_transport, FlowKey, TcpFlags, TcpHeader, TransportError, TransportHeader,
    UdpHeader, PROTO_TCP, UDP,
};
