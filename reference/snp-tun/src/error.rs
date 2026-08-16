//! Errors from the TUN packet boundary.
//!
//! The error types are designed to be distinguishable: a caller can match
//! on [`TunError::PermissionDenied`] to detect missing `CAP_NET_ADMIN`,
//! [`TunError::InvalidPacket`] to detect malformed IP data, and
//! [`TunError::Closed`] to detect device EOF — without string matching.

use std::io;

/// Errors from the TUN device or packet parser.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// **Permission denied.** The process lacks `CAP_NET_ADMIN` (required to
    /// create a TUN interface via `ioctl(TUNSETIFF)`), or `/dev/net/tun` is
    /// not accessible (`open()` returned `EACCES`).
    ///
    /// This is the expected error when running without root privileges. The
    /// caller MUST handle this gracefully — it is NOT a panic condition.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// **Device not found.** `/dev/net/tun` does not exist on this system.
    /// This typically means the kernel was compiled without TUN support, or
    /// the container/runtime does not expose the device.
    #[error("TUN device not found: {0}")]
    DeviceNotFound(String),

    /// **Invalid packet.** The bytes do not form a valid IPv4 or IPv6 packet.
    /// The detail string describes the specific validation failure (wrong
    /// version, truncated header, declared length mismatch, etc.).
    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    /// **Interface name too long.** TUN interface names are limited to 15
    /// bytes (`IFNAMSIZ - 1 = 15`). The provided name exceeded this limit.
    #[error("interface name too long: {0} (max 15 bytes)")]
    NameTooLong(String),

    /// **Partial write.** The TUN device accepted fewer bytes than the
    /// packet size. This should not happen for TUN writes (the kernel writes
    /// whole packets atomically), but if it does, the caller knows the packet
    /// was not fully delivered.
    #[error("partial write: wrote {written} of {expected} bytes")]
    PartialWrite {
        /// Number of bytes actually written.
        written: usize,
        /// Expected number of bytes (the full packet size).
        expected: usize,
    },

    /// **Device closed.** The TUN device has been closed or the read end
    /// returned EOF (no more packets available). For [`crate::MockPacketDevice`],
    /// this means the pre-loaded packet queue is empty.
    #[error("device closed (no more packets)")]
    Closed,

    /// **Unsupported platform.** `LinuxTunDevice` is only available on Linux.
    /// On other platforms, [`crate::LinuxTunDevice::create`] returns this
    /// error.
    #[error("TUN device not supported on this platform (Linux only)")]
    UnsupportedPlatform,

    /// **I/O error.** A generic I/O error from the underlying file descriptor
    /// (read, write, ioctl, epoll registration). The caller can inspect the
    /// inner `io::Error` for the raw OS error code.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl TunError {
    /// Map an `io::Error` from a TUN-related syscall to the most specific
    /// [`TunError`] variant. This maps `EPERM`/`EACCES` to
    /// [`TunError::PermissionDenied`] and `ENOENT` to
    /// [`TunError::DeviceNotFound`], leaving other errors as
    /// [`TunError::Io`].
    #[must_use]
    pub fn from_io(context: &str, e: io::Error) -> Self {
        match e.raw_os_error() {
            Some(libc_eperm) if libc_eperm == 1 => {
                // EPERM = 1 (operation not permitted — lacks CAP_NET_ADMIN)
                TunError::PermissionDenied(format!("{context}: {e}"))
            }
            Some(libc_eacces) if libc_eacces == 13 => {
                // EACCES = 13 (permission denied — can't open /dev/net/tun)
                TunError::PermissionDenied(format!("{context}: {e}"))
            }
            Some(libc_enoent) if libc_enoent == 2 => {
                // ENOENT = 2 (no such file or directory — /dev/net/tun missing)
                TunError::DeviceNotFound(format!("{context}: {e}"))
            }
            _ => TunError::Io(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_io_maps_eperm_to_permission_denied() {
        let e = io::Error::from_raw_os_error(1); // EPERM
        let tun_err = TunError::from_io("ioctl(TUNSETIFF)", e);
        assert!(
            matches!(tun_err, TunError::PermissionDenied(_)),
            "EPERM must map to PermissionDenied, got {:?}",
            tun_err
        );
    }

    #[test]
    fn from_io_maps_eacces_to_permission_denied() {
        let e = io::Error::from_raw_os_error(13); // EACCES
        let tun_err = TunError::from_io("open(/dev/net/tun)", e);
        assert!(
            matches!(tun_err, TunError::PermissionDenied(_)),
            "EACCES must map to PermissionDenied, got {:?}",
            tun_err
        );
    }

    #[test]
    fn from_io_maps_enoent_to_device_not_found() {
        let e = io::Error::from_raw_os_error(2); // ENOENT
        let tun_err = TunError::from_io("open(/dev/net/tun)", e);
        assert!(
            matches!(tun_err, TunError::DeviceNotFound(_)),
            "ENOENT must map to DeviceNotFound, got {:?}",
            tun_err
        );
    }

    #[test]
    fn from_io_preserves_other_errors() {
        let e = io::Error::from_raw_os_error(22); // EINVAL
        let tun_err = TunError::from_io("ioctl", e);
        assert!(
            matches!(tun_err, TunError::Io(_)),
            "EINVAL must map to Io, got {:?}",
            tun_err
        );
    }
}
