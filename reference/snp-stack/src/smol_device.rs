//! smoltcp `Device` implementation for the TUN packet boundary.
//!
//! This module bridges between ShareNet's [`PacketDevice`](snp_tun::PacketDevice)
//! (async, queue-based) and smoltcp's [`Device`](smoltcp::phy::Device) trait
//! (synchronous, token-based). It provides a simple queue-based adapter that
//! smoltcp can poll for incoming/outgoing packets.
//!
//! ## How it works
//!
//! ```text
//! Incoming packets:          Outgoing packets:
//!   TUN/Mock → push_rx()       pop_tx() → TUN/Mock
//!                  |               ^
//!                  v               |
//!              rx_queue        tx_queue
//!                  |               ^
//!                  v               |
//!           smoltcp Device::receive() / transmit()
//!                  |               |
//!                  v               v
//!              smoltcp TCP/IP stack (TcpEngine)
//! ```
//!
//! The [`TunSmolDevice`] holds two queues:
//! - `rx_queue` — packets pushed by the upper layer (from the TUN) and
//!   consumed by smoltcp's `receive()`.
//! - `tx_queue` — packets produced by smoltcp's `transmit()` and popped by
//!   the upper layer (to write to the TUN).

use std::collections::VecDeque;

use smoltcp::phy::{Device as SmolDevice, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;

/// A queue-based smoltcp `Device` adapter. Holds incoming packets (from the
/// TUN) and outgoing packets (from smoltcp) in two FIFO queues.
#[derive(Debug)]
pub struct TunSmolDevice {
    /// Incoming packets (from TUN → smoltcp).
    rx_queue: VecDeque<Vec<u8>>,
    /// Outgoing packets (from smoltcp → TUN).
    tx_queue: VecDeque<Vec<u8>>,
    /// Maximum transmission unit (default 1500 for TUN).
    mtu: usize,
}

impl TunSmolDevice {
    /// Create a new device with the given MTU.
    #[must_use]
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    /// Push an incoming packet into the RX queue (for smoltcp to consume).
    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    /// Pop an outgoing packet from the TX queue (produced by smoltcp).
    /// Returns `None` if no packets are available.
    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    /// Returns true if there are outgoing packets ready to be drained.
    #[must_use]
    pub fn has_tx(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    /// Returns true if there are incoming packets waiting to be consumed.
    #[must_use]
    pub fn has_rx(&self) -> bool {
        !self.rx_queue.is_empty()
    }
}

/// smoltcp RX token — holds one incoming packet for smoltcp to consume.
pub struct TunRxToken {
    packet: Vec<u8>,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.packet;
        f(&mut packet)
    }
}

/// smoltcp TX token — holds a mutable reference to the TX queue. When
/// consumed, the packet buffer is pushed into the queue.
pub struct TunTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for TunTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.queue.push_back(buf);
        result
    }
}

impl SmolDevice for TunSmolDevice {
    type RxToken<'a> = TunRxToken where Self: 'a;
    type TxToken<'a> = TunTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Pop the next incoming packet. If none, return None (smoltcp will
        // retry on the next poll).
        let packet = self.rx_queue.pop_front()?;
        // Return both an RxToken (with the packet) and a TxToken (for smoltcp
        // to send a response in the same poll cycle). The TxToken borrows
        // &mut self.tx_queue — this is safe because the RxToken owns its
        // packet (no borrow of self).
        Some((
            TunRxToken { packet },
            TunTxToken { queue: &mut self.tx_queue },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        // Always return a TxToken — smoltcp will call consume() only if it
        // has a packet to send. The TxToken borrows &mut self.tx_queue.
        Some(TunTxToken { queue: &mut self.tx_queue })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_push_and_pop() {
        let mut device = TunSmolDevice::new(1500);
        assert!(!device.has_rx());
        assert!(!device.has_tx());

        device.push_rx(vec![1, 2, 3]);
        assert!(device.has_rx());

        // Simulate smoltcp receiving the packet.
        let (rx, _tx) = device
            .receive(SmolInstant::now())
            .expect("must have a packet");
        rx.consume(|data| {
            assert_eq!(data, &[1, 2, 3]);
        });
        assert!(!device.has_rx());
    }

    #[test]
    fn device_transmit_pushes_to_tx_queue() {
        let mut device = TunSmolDevice::new(1500);

        // Simulate smoltcp transmitting a packet.
        let tx = device
            .transmit(SmolInstant::now())
            .expect("must return a TxToken");
        tx.consume(5, |buf| {
            buf.copy_from_slice(&[10, 20, 30, 40, 50]);
        });

        assert!(device.has_tx());
        let pkt = device.pop_tx().expect("must have a packet");
        assert_eq!(pkt, vec![10, 20, 30, 40, 50]);
    }

    #[test]
    fn device_capabilities() {
        let device = TunSmolDevice::new(9000);
        let caps = device.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 9000);
    }

    #[test]
    fn device_receive_returns_none_when_empty() {
        let mut device = TunSmolDevice::new(1500);
        assert!(device.receive(SmolInstant::now()).is_none());
    }
}
