//! Packet device abstraction — the trait seam between the TUN kernel
//! boundary and the ShareNet stack.
//!
//! The [`PacketDevice`] trait is the integration point:
//!
//! ```text
//! Linux Kernel
//!      |
//!     TUN fd
//!      |
//! LinuxTunDevice  ──implements──►  PacketDevice
//!                                      |
//!                               ShareNet stack
//!                               (future N2.3.2+)
//! ```
//!
//! Production uses [`LinuxTunDevice`] (real `/dev/net/tun`). Tests use
//! [`MockPacketDevice`] (in-memory, no root privileges required).

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::error::TunError;
use crate::packet::IpPacket;

// ─── PacketDevice trait ─────────────────────────────────────────────────────

/// A device that reads and writes IP packets asynchronously.
///
/// This is the trait seam: production code uses [`LinuxTunDevice`] (backed by
/// a real Linux TUN interface), while tests use [`MockPacketDevice`] (backed
/// by an in-memory queue). Both implement the same async API, so the upper
/// ShareNet layers can be developed and tested without root privileges.
///
/// ## Async contract
///
/// - `read_packet` awaits until a packet is available. Returns
///   [`TunError::Closed`] when the device has no more packets (EOF or empty
///   mock queue).
/// - `write_packet` awaits until the packet can be written. For TUN, writes
///   are typically immediate (the kernel buffer accepts the packet).
///
/// ## Concurrency
///
/// The trait takes `&mut self`, so a single device instance is NOT shared
/// across tasks. For concurrent access, wrap the device in `Arc<Mutex<...>>`
/// or (for [`MockPacketDevice`]) clone it — clones share the same internal
/// state.
#[async_trait]
pub trait PacketDevice: Send {
    /// Read one IP packet from the device. Awaits until a packet is available.
    ///
    /// # Errors
    /// - [`TunError::Closed`] — device EOF or empty queue.
    /// - [`TunError::InvalidPacket`] — the bytes read are not a valid IP packet.
    /// - [`TunError::Io`] — underlying I/O error.
    async fn read_packet(&mut self) -> Result<IpPacket, TunError>;

    /// Write one IP packet to the device.
    ///
    /// # Errors
    /// - [`TunError::PartialWrite`] — the device accepted fewer bytes than the
    ///   packet size.
    /// - [`TunError::Io`] — underlying I/O error.
    async fn write_packet(&mut self, packet: IpPacket) -> Result<(), TunError>;
}

// ─── LinuxTunDevice (Linux only) ────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_tun {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use tokio::io::unix::AsyncFd;

    use super::*;
    use crate::error::TunError;
    use crate::packet::{IpPacket, MAX_PACKET_SIZE};

    // TUN ioctl constants (from <linux/if_tun.h>). Defined here to avoid
    // depending on the libc crate's version exposing them.
    //
    // TUNSETIFF = _IOW('T', 202, int) = 0x400454ca
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    // IFF_TUN = 0x0001 (layer-3 TUN, not layer-2 TAP)
    const IFF_TUN: libc::c_short = 0x0001;
    // IFF_NO_PI = 0x1000 (no 4-byte packet info prefix — raw IP packets)
    const IFF_NO_PI: libc::c_short = 0x1000;

    // IFNAMSIZ = 16 (from <net/if.h>). Interface names are max 15 bytes + NUL.
    const IFNAMSIZ: usize = 16;

    /// A Linux TUN device backed by `/dev/net/tun`.
    ///
    /// Created via [`LinuxTunDevice::create`], which opens `/dev/net/tun`,
    /// configures the interface via `ioctl(TUNSETIFF)`, and wraps the fd in
    /// a Tokio `AsyncFd` for non-blocking async I/O.
    ///
    /// The device reads/writes raw IP packets (no 4-byte packet-info prefix —
    /// `IFF_NO_PI` is set). Each `read_packet` returns one complete IP packet;
    /// each `write_packet` sends one complete IP packet.
    ///
    /// ## Permissions
    ///
    /// Creating a TUN interface requires `CAP_NET_ADMIN`. If the process lacks
    /// this capability, [`create`](Self::create) returns
    /// [`TunError::PermissionDenied`] (not a panic).
    ///
    /// ## Drop
    ///
    /// When the device is dropped, the fd is closed, which automatically
    /// destroys the TUN interface (the kernel destroys a TUN interface when
    /// its last fd is closed).
    pub struct LinuxTunDevice {
        /// The async-wrapped TUN fd. `AsyncFd<OwnedFd>` owns the fd and closes
        /// it on drop.
        fd: AsyncFd<OwnedFd>,
        /// The actual interface name (may differ from the requested name if
        /// the caller passed an empty string — the kernel auto-assigns).
        name: String,
    }

    impl std::fmt::Debug for LinuxTunDevice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxTunDevice")
                .field("name", &self.name)
                .field("fd", &self.fd.get_ref().as_raw_fd())
                .finish()
        }
    }

    impl LinuxTunDevice {
        /// Create a new TUN interface with the given name.
        ///
        /// Opens `/dev/net/tun`, calls `ioctl(TUNSETIFF)` with `IFF_TUN |
        /// IFF_NO_PI` (layer-3 TUN, no packet-info prefix), and wraps the fd
        /// in `AsyncFd` for Tokio-compatible async I/O.
        ///
        /// ## Name rules
        ///
        /// - Max 15 bytes (IFNAMSIZ - 1 = 15).
        /// - If empty (`""`), the kernel auto-assigns a name (e.g. `tun0`).
        ///
        /// # Errors
        /// - [`TunError::NameTooLong`] — name exceeds 15 bytes.
        /// - [`TunError::PermissionDenied`] — process lacks `CAP_NET_ADMIN` or
        ///   `/dev/net/tun` is not accessible.
        /// - [`TunError::DeviceNotFound`] — `/dev/net/tun` does not exist.
        /// - [`TunError::Io`] — other I/O error (epoll registration, etc.).
        pub fn create(name: &str) -> Result<Self, TunError> {
            // Validate name length BEFORE opening the device.
            if name.len() >= IFNAMSIZ {
                return Err(TunError::NameTooLong(name.to_string()));
            }

            // Open /dev/net/tun with O_RDWR | O_NONBLOCK | O_CLOEXEC.
            // O_NONBLOCK is required for AsyncFd (epoll-based readiness).
            let path = CString::new("/dev/net/tun").expect("path is a valid CString");
            // SAFETY: `path` is a valid NUL-terminated CString. `open()` is a
            // standard POSIX syscall. The returned fd is valid if >= 0.
            let fd: RawFd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(TunError::from_io("open(/dev/net/tun)", std::io::Error::last_os_error()));
            }
            // SAFETY: `fd` is a valid open file descriptor (we just checked >= 0).
            // We are the sole owner — no other code will close it. `from_raw_fd`
            // takes ownership and will close the fd on drop.
            let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

            // Set up the ifreq for TUNSETIFF.
            let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
            // Copy the interface name into ifr.ifr_name (NUL-terminated).
            if !name.is_empty() {
                let name_bytes = name.as_bytes();
                // SAFETY: ifr_name is [c_char; 16], we copy at most 15 bytes.
                // The struct was zeroed, so ifr_name is already NUL-terminated.
                for (i, &b) in name_bytes.iter().enumerate() {
                    ifr.ifr_name[i] = b as libc::c_char;
                }
            }
            // Set flags: IFF_TUN (layer-3) | IFF_NO_PI (no packet-info prefix).
            // SAFETY: Accessing a union field. The ifreq union is designed for
            // this — ifru_flags is the correct variant for TUNSETIFF.
            ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

            // Call ioctl(TUNSETIFF) to create/configure the TUN interface.
            // SAFETY: `fd` is valid, TUNSETIFF is a valid ioctl request, `&mut ifr`
            // is a valid mutable pointer to the ifreq struct.
            let ret = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr) };
            if ret < 0 {
                let e = std::io::Error::last_os_error();
                return Err(TunError::from_io("ioctl(TUNSETIFF)", e));
            }

            // Read back the actual interface name (the kernel may have
            // auto-assigned it if the caller passed "").
            let actual_name = unsafe {
                let cstr = std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr());
                cstr.to_string_lossy().into_owned()
            };

            // Wrap the fd in AsyncFd for Tokio-compatible async readiness
            // notification (epoll-based, not threadpool-based).
            let async_fd = AsyncFd::new(owned_fd).map_err(|e| {
                TunError::Io(std::io::Error::new(
                    e.kind(),
                    format!("AsyncFd::new (epoll registration): {e}"),
                ))
            })?;

            Ok(Self {
                fd: async_fd,
                name: actual_name,
            })
        }

        /// Returns the actual interface name (may differ from the requested
        /// name if the caller passed an empty string).
        #[must_use]
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Returns the raw file descriptor (for advanced use — e.g. setting
        /// interface MTU via additional ioctls).
        #[must_use]
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.get_ref().as_raw_fd()
        }
    }

    #[async_trait]
    impl PacketDevice for LinuxTunDevice {
        async fn read_packet(&mut self) -> Result<IpPacket, TunError> {
            // Allocate a buffer large enough for any IP packet (65535 bytes).
            // TUN read returns one complete packet per syscall.
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                // Wait for the fd to become readable (epoll readiness).
                let mut guard = self.fd.readable().await.map_err(TunError::Io)?;
                // Try the read. `try_io` handles the WouldBlock case internally.
                match guard.try_io(|inner| {
                    let fd = inner.get_ref().as_raw_fd();
                    // SAFETY: `fd` is valid, `buf` is a valid mutable pointer
                    // with `buf.len()` bytes. `read()` returns the number of
                    // bytes read or -1 on error.
                    let n = unsafe {
                        libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len())
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) => {
                        // Got a packet. Truncate the buffer to the actual size
                        // and parse it.
                        buf.truncate(n);
                        return IpPacket::parse(&buf);
                    }
                    Ok(Err(e)) => {
                        // I/O error (not WouldBlock — that's handled by try_io).
                        return Err(TunError::Io(e));
                    }
                    Err(_would_block) => {
                        // The fd was reported readable but read() returned
                        // EAGAIN. Loop back to readable().await.
                        continue;
                    }
                }
            }
        }

        async fn write_packet(&mut self, packet: IpPacket) -> Result<(), TunError> {
            let bytes = packet.as_bytes();
            loop {
                // Wait for the fd to become writable (epoll readiness).
                let mut guard = self.fd.writable().await.map_err(TunError::Io)?;
                match guard.try_io(|inner| {
                    let fd = inner.get_ref().as_raw_fd();
                    // SAFETY: `fd` is valid, `bytes` is a valid const pointer
                    // with `bytes.len()` bytes. `write()` returns the number
                    // of bytes written or -1 on error.
                    let n = unsafe {
                        libc::write(fd, bytes.as_ptr() as *const _, bytes.len())
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) => {
                        // TUN writes are atomic — the kernel writes the whole
                        // packet or returns an error. A partial write indicates
                        // a problem.
                        if n == bytes.len() {
                            return Ok(());
                        }
                        return Err(TunError::PartialWrite {
                            written: n,
                            expected: bytes.len(),
                        });
                    }
                    Ok(Err(e)) => {
                        return Err(TunError::Io(e));
                    }
                    Err(_would_block) => {
                        continue;
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_tun::LinuxTunDevice;

// ─── MockPacketDevice (all platforms) ───────────────────────────────────────

/// Internal state for `MockPacketDevice`, shared across clones via `Arc`.
#[derive(Debug)]
struct MockState {
    /// Packets queued for `read_packet` to return (FIFO order).
    pending: VecDeque<IpPacket>,
    /// Packets received via `write_packet` (in write order).
    written: Vec<IpPacket>,
}

/// An in-memory `PacketDevice` for testing — no TUN interface, no root
/// privileges required.
///
/// Pre-load packets via [`MockPacketDevice::with_packets`]; `read_packet`
/// returns them one at a time (FIFO). When the queue is empty, `read_packet`
/// returns [`TunError::Closed`].
///
/// `write_packet` stores packets in an internal buffer; inspect them via
/// [`MockPacketDevice::written_packets`].
///
/// ## Clone semantics
///
/// `MockPacketDevice` is `Clone` — clones share the same internal state
/// (via `Arc<Mutex<...>>`). This allows multiple async tasks to read/write
/// concurrently on separate clones, testing for packet corruption or race
/// conditions.
#[derive(Debug, Clone)]
pub struct MockPacketDevice {
    inner: Arc<Mutex<MockState>>,
}

impl MockPacketDevice {
    /// Create an empty mock device (no packets to read, no written packets).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockState {
                pending: VecDeque::new(),
                written: Vec::new(),
            })),
        }
    }

    /// Create a mock device pre-loaded with the given packets (in read order).
    ///
    /// This function is NOT async (it's a constructor). It creates the
    /// internal state directly without locking the tokio mutex — the mutex
    /// is created in the pre-loaded state.
    #[must_use]
    pub fn with_packets(packets: Vec<IpPacket>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockState {
                pending: packets.into_iter().collect(),
                written: Vec::new(),
            })),
        }
    }

    /// Returns a clone of all packets written via `write_packet` (in write
    /// order). Useful for verifying that the upper layers sent the expected
    /// packets.
    pub async fn written_packets(&self) -> Vec<IpPacket> {
        self.inner.lock().await.written.clone()
    }

    /// Returns the number of packets still pending (not yet read).
    pub async fn pending_count(&self) -> usize {
        self.inner.lock().await.pending.len()
    }
}

impl Default for MockPacketDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PacketDevice for MockPacketDevice {
    async fn read_packet(&mut self) -> Result<IpPacket, TunError> {
        let mut state = self.inner.lock().await;
        state.pending.pop_front().ok_or(TunError::Closed)
    }

    async fn write_packet(&mut self, packet: IpPacket) -> Result<(), TunError> {
        let mut state = self.inner.lock().await;
        state.written.push(packet);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_test_ipv4_packet, build_test_ipv6_packet};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn mock_device_read_write_roundtrip() {
        // Pre-load a packet, read it back, verify it matches.
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let raw = build_test_ipv4_packet(src, dst, 6, b"hello");
        let packet = IpPacket::parse(&raw).expect("parse");

        let mut device = MockPacketDevice::with_packets(vec![packet.clone()]);
        let read = device.read_packet().await.expect("read must succeed");
        assert_eq!(read, packet, "read packet must match pre-loaded packet");

        // Second read must return Closed (queue is empty).
        let result = device.read_packet().await;
        assert!(
            matches!(result, Err(TunError::Closed)),
            "read from empty mock must return Closed, got {:?}",
            result
        );

        // Write a packet, verify it's stored.
        let raw2 = build_test_ipv4_packet(src, dst, 17, b"udp");
        let packet2 = IpPacket::parse(&raw2).expect("parse");
        device.write_packet(packet2.clone()).await.expect("write");
        let written = device.written_packets().await;
        assert_eq!(written.len(), 1);
        assert_eq!(written[0], packet2);
    }

    #[tokio::test]
    async fn mock_device_returns_closed_when_empty() {
        let mut device = MockPacketDevice::new();
        let result = device.read_packet().await;
        assert!(
            matches!(result, Err(TunError::Closed)),
            "read from empty mock must return Closed, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn mock_device_concurrent_reads_no_corruption() {
        // Pre-load 10 distinct packets. Spawn 5 concurrent readers, each
        // reading 2 packets. Verify all 10 are read exactly once (no
        // duplication, no loss, no corruption).
        let mut packets = Vec::new();
        for i in 0u8..10 {
            let raw = build_test_ipv4_packet(
                Ipv4Addr::new(10, 0, 0, i),
                Ipv4Addr::new(93, 184, 216, 34),
                6,
                &[i; 1],
            );
            packets.push(IpPacket::parse(&raw).expect("parse"));
        }
        let device = MockPacketDevice::with_packets(packets.clone());

        // Spawn 5 readers, each reading 2 packets.
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let mut dev = device.clone();
            tasks.push(tokio::spawn(async move {
                let mut received = Vec::new();
                for _ in 0..2 {
                    match dev.read_packet().await {
                        Ok(p) => received.push(p),
                        Err(TunError::Closed) => break,
                        Err(e) => panic!("unexpected error: {e:?}"),
                    }
                }
                received
            }));
        }

        // Collect all received packets.
        let mut all_received = Vec::new();
        for task in tasks {
            let received = task.await.expect("task join");
            all_received.extend(received);
        }

        // Verify all 10 packets were read exactly once.
        assert_eq!(all_received.len(), 10, "must read exactly 10 packets");
        for packet in &packets {
            let count = all_received.iter().filter(|p| **p == *packet).count();
            assert_eq!(count, 1, "each packet must be read exactly once");
        }
    }

    #[tokio::test]
    async fn mock_device_concurrent_writes_no_corruption() {
        // Spawn 5 concurrent writers, each writing 2 packets. Verify all 10
        // are stored (no loss).
        let device = MockPacketDevice::new();

        let mut tasks = Vec::new();
        for i in 0u8..5 {
            let mut dev = device.clone();
            tasks.push(tokio::spawn(async move {
                for j in 0u8..2 {
                    let raw = build_test_ipv4_packet(
                        Ipv4Addr::new(10, i, j, 1),
                        Ipv4Addr::new(93, 184, 216, 34),
                        6,
                        &[i, j],
                    );
                    let packet = IpPacket::parse(&raw).expect("parse");
                    dev.write_packet(packet).await.expect("write");
                }
            }));
        }

        for task in tasks {
            task.await.expect("task join");
        }

        let written = device.written_packets().await;
        assert_eq!(written.len(), 10, "must have 10 written packets");
    }

    #[tokio::test]
    async fn mock_device_ipv6_packet_roundtrip() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let raw = build_test_ipv6_packet(src, dst, 6, b"ipv6-data");
        let packet = IpPacket::parse(&raw).expect("parse");

        let mut device = MockPacketDevice::with_packets(vec![packet.clone()]);
        let read = device.read_packet().await.expect("read");
        assert_eq!(read, packet);
        assert_eq!(read.metadata().source, std::net::IpAddr::V6(src));
    }
}
