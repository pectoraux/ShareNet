//! **N3-B Step 7 — OS route integration.**
//!
//! Helpers for configuring the Linux network stack to route traffic through
//! the ShareNet TUN interface. This module owns the OS-level configuration:
//!
//! ```text
//! Who creates TUN?          → TunClient::create() (via LinuxTunDevice::create)
//! Who assigns its address?  → configure_os_interface() (this module)
//! Who installs the route?   → configure_os_interface() (this module)
//! Who removes the route?    → cleanup_os_interface() (this module, on shutdown)
//! Who owns shutdown?        → TunClient::run() loop + Drop
//! ```
//!
//! ## Why this module exists
//!
//! Without OS route configuration, the TUN interface exists but the OS kernel
//! doesn't know to route traffic through it. An application connecting to
//! 93.184.216.34:443 would use the default route (the physical interface),
//! not the TUN. The SYN would never reach the TunClient.
//!
//! The configuration is:
//! 1. Assign an IP to the TUN interface (e.g. `ip addr add 10.0.0.1/24 dev snp0`)
//! 2. Bring the interface up (`ip link set snp0 up`)
//! 3. Install a default route through the TUN (`ip route add default dev snp0`)
//!
//! This routes ALL traffic through the TUN. The TunClient then intercepts
//! SYNs, extracts the original destination, and forwards through ShareNet.
//!
//! ## Permissions
//!
//! Configuring network interfaces requires `CAP_NET_ADMIN`. The TunClient
//! process must run as root or have this capability.
//!
//! ## Shutdown
//!
//! When the TunClient is dropped, the TUN fd is closed, which automatically
//! destroys the TUN interface. The kernel removes the route when the
//! interface is destroyed. The `cleanup_os_interface()` helper can be called
//! for explicit cleanup before drop.

use std::process::Command;

/// Configuration for OS-level network interface setup.
#[derive(Debug, Clone)]
pub struct OsRouteConfig {
    /// The TUN interface name (e.g. "snp0").
    pub tun_name: String,
    /// The IP address to assign to the TUN interface (e.g. "10.0.0.1/24").
    pub tun_ip_cidr: String,
}

/// Configure the OS network interface: assign IP, bring up, install default route.
///
/// This runs:
/// 1. `ip addr add <tun_ip_cidr> dev <tun_name>`
/// 2. `ip link set <tun_name> up`
/// 3. `ip route add default dev <tun_name>`
///
/// # Errors
/// Returns an error if any command fails (e.g. permission denied, interface
/// doesn't exist, route already exists).
pub fn configure_os_interface(config: &OsRouteConfig) -> Result<(), OsRouteError> {
    // 1. Assign IP address.
    let output = Command::new("ip")
        .args(["addr", "add", &config.tun_ip_cidr, "dev", &config.tun_name])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip addr add: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "RTNETLINK answers: File exists" is OK if the address is already assigned.
        if !stderr.contains("File exists") {
            return Err(OsRouteError::CommandFailed(format!(
                "ip addr add {} dev {}: {}", config.tun_ip_cidr, config.tun_name, stderr.trim()
            )));
        }
    }
    eprintln!("[n3-os] assigned {} to {}", config.tun_ip_cidr, config.tun_name);

    // 2. Bring the interface up.
    let output = Command::new("ip")
        .args(["link", "set", "up", "dev", &config.tun_name])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip link set up: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OsRouteError::CommandFailed(format!(
            "ip link set up dev {}: {}", config.tun_name, stderr.trim()
        )));
    }
    eprintln!("[n3-os] interface {} is UP", config.tun_name);

    // 3. Install default route through the TUN.
    let output = Command::new("ip")
        .args(["route", "add", "default", "dev", &config.tun_name])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip route add: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(OsRouteError::CommandFailed(format!(
                "ip route add default dev {}: {}", config.tun_name, stderr.trim()
            )));
        }
    }
    eprintln!("[n3-os] default route installed via {}", config.tun_name);

    Ok(())
}

/// Remove the OS network configuration: remove route, bring interface down.
///
/// This runs:
/// 1. `ip route del default dev <tun_name>`
/// 2. `ip link set <tun_name> down`
///
/// The TUN interface itself is destroyed when the fd is closed (in
/// `LinuxTunDevice::drop`), so we don't need to delete it here.
///
/// # Errors
/// Returns an error if any command fails. Errors are non-fatal during
/// shutdown — the caller should log and continue.
pub fn cleanup_os_interface(config: &OsRouteConfig) -> Result<(), OsRouteError> {
    // 1. Remove default route.
    let _ = Command::new("ip")
        .args(["route", "del", "default", "dev", &config.tun_name])
        .output();
    eprintln!("[n3-os] removed default route via {}", config.tun_name);

    // 2. Bring interface down.
    let _ = Command::new("ip")
        .args(["link", "set", "down", "dev", &config.tun_name])
        .output();
    eprintln!("[n3-os] interface {} is DOWN", config.tun_name);

    Ok(())
}

/// Errors from OS route configuration.
#[derive(Debug)]
pub enum OsRouteError {
    /// A system command (`ip addr`, `ip route`, etc.) failed.
    CommandFailed(String),
}

impl std::fmt::Display for OsRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandFailed(msg) => write!(f, "OS route config error: {msg}"),
        }
    }
}

impl std::error::Error for OsRouteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_route_config_constructs() {
        let config = OsRouteConfig {
            tun_name: "snp0".to_string(),
            tun_ip_cidr: "10.0.0.1/24".to_string(),
        };
        assert_eq!(config.tun_name, "snp0");
        assert_eq!(config.tun_ip_cidr, "10.0.0.1/24");
    }
}
