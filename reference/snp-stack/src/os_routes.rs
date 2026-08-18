//! **N3-B Step 7 — OS route integration with split-tunnel support.**
//!
//! Helpers for configuring the Linux network stack to route traffic through
//! the ShareNet TUN interface while preserving reachability to the
//! ShareNet control-plane endpoints (relay/gateway).
//!
//! ## Ownership (explicit)
//!
//! ```text
//! Who creates TUN?          → TunClient::create() (via LinuxTunDevice::create)
//! Who assigns its address?  → configure_tun_interface() (this module)
//! Who installs the TUN default route?
//!                           → install_tun_default_route() (this module)
//! Who installs the control-plane exclusion routes?
//!                           → install_control_plane_routes() (this module)
//! Who removes the routes?   → cleanup() (this module, on shutdown)
//! Who owns shutdown?        → TunClient::run() loop + Drop
//! ```
//!
//! ## Split-tunnel design
//!
//! A production ShareNet client must route ordinary Internet traffic through
//! the TUN while keeping the ShareNet control-plane (relay/gateway TCP
//! endpoints) reachable via the physical network interface. Without this,
//! the TunClient's own ShareNet circuit traffic would loop back into the TUN.
//!
//! The routing table after `configure_os_interface()`:
//!
//! ```text
//! control-plane endpoints → physical interface (specific routes)
//! default route           → TUN interface
//! ```
//!
//! Specific routes are more specific than the default route, so the kernel
//! prefers them for control-plane traffic. The TUN gets everything else.
//!
//! ## What gets restored on shutdown
//!
//! `cleanup()` removes ONLY the routes ShareNet installed:
//! - The TUN default route.
//! - The control-plane exclusion routes.
//!
//! It does NOT remove the physical interface's pre-existing default route
//! (that was never changed). The physical interface remains reachable via
//! its original configuration.

use std::process::Command;

/// Configuration for OS-level network interface setup.
#[derive(Debug, Clone)]
pub struct OsRouteConfig {
    /// The TUN interface name (e.g. "snp0").
    pub tun_name: String,
    /// The IP address + prefix to assign to the TUN interface (e.g. "10.0.0.1/24").
    pub tun_ip_cidr: String,
    /// The ShareNet control-plane endpoints that must bypass the TUN.
    /// These are the relay/gateway TCP listen addresses. The runtime installs
    /// specific routes for them via the physical interface so the ShareNet
    /// circuit traffic doesn't loop into the TUN.
    pub control_plane_endpoints: Vec<std::net::IpAddr>,
    /// The physical interface name to route control-plane traffic through
    /// (e.g. "eth0"). If None, the runtime uses the existing default route's
    /// interface (queried via `ip route show default`).
    pub physical_interface: Option<String>,
}

/// Result of a successful `configure_os_interface()` call. Pass to `cleanup()`
/// to remove exactly what was installed.
#[derive(Debug, Clone, Default)]
pub struct InstalledRoutes {
    /// The TUN interface name (for removing the default route).
    pub tun_name: String,
    /// The control-plane endpoints that got specific routes.
    pub control_plane_endpoints: Vec<std::net::IpAddr>,
    /// The physical interface used for control-plane routes.
    pub physical_interface: Option<String>,
}

/// Configure the OS network interface with split-tunnel routing.
///
/// This performs three steps:
/// 1. Assign the TUN IP address + bring the interface up.
/// 2. Install specific routes for each control-plane endpoint via the
///    physical interface (so ShareNet circuit traffic bypasses the TUN).
/// 3. Install the TUN default route (so ordinary traffic enters the TUN).
///
/// # Arguments
/// * `config` — The TUN + control-plane configuration.
///
/// # Returns
/// An `InstalledRoutes` record to pass to `cleanup()`.
///
/// # Errors
/// Returns an error if any `ip` command fails (e.g. permission denied).
pub fn configure_os_interface(config: &OsRouteConfig) -> Result<InstalledRoutes, OsRouteError> {
    // 1. Assign IP + bring up the TUN interface.
    assign_tun_ip(&config.tun_name, &config.tun_ip_cidr)?;
    bring_up(&config.tun_name)?;

    // 2. Determine the physical interface for control-plane routes.
    let physical: Option<String> = match &config.physical_interface {
        Some(iface) => Some(iface.clone()),
        None => detect_default_interface()?,
    };

    // 3. Install control-plane exclusion routes (BEFORE the TUN default route,
    //    so the kernel has them available when the default route is added).
    for endpoint in &config.control_plane_endpoints {
        if let Some(ref iface) = physical {
            install_control_plane_route(endpoint, iface)?;
        }
    }

    // 4. Install the TUN default route (ordinary traffic → TUN).
    install_default_route(&config.tun_name)?;

    Ok(InstalledRoutes {
        tun_name: config.tun_name.clone(),
        control_plane_endpoints: config.control_plane_endpoints.clone(),
        physical_interface: physical,
    })
}

/// Clean up the OS routes installed by `configure_os_interface()`.
///
/// Removes ONLY what ShareNet installed:
/// - The TUN default route.
/// - The control-plane exclusion routes.
///
/// Does NOT touch the physical interface's pre-existing configuration.
///
/// # Errors
/// Non-fatal during shutdown — the caller should log and continue.
pub fn cleanup(installed: &InstalledRoutes) -> Result<(), OsRouteError> {
    // 1. Remove the TUN default route.
    let _ = Command::new("ip")
        .args(["route", "del", "default", "dev", &installed.tun_name])
        .output();
    eprintln!("[n3-os] removed default route via {}", installed.tun_name);

    // 2. Remove control-plane exclusion routes.
    if let Some(ref iface) = installed.physical_interface {
        for endpoint in &installed.control_plane_endpoints {
            let ip_str = endpoint.to_string();
            let _ = Command::new("ip")
                .args(["route", "del", &ip_str, "dev", iface])
                .output();
        }
        eprintln!(
            "[n3-os] removed {} control-plane route(s) via {}",
            installed.control_plane_endpoints.len(),
            iface
        );
    }

    // 3. Bring the TUN interface down (the interface itself is destroyed when
    //    the fd is closed in LinuxTunDevice::drop, so we don't need to delete it).
    let _ = Command::new("ip")
        .args(["link", "set", "down", "dev", &installed.tun_name])
        .output();
    eprintln!("[n3-os] interface {} is DOWN", installed.tun_name);

    Ok(())
}

// ─── Internal helpers ──────────────────────────────────────────────────────

fn assign_tun_ip(tun_name: &str, ip_cidr: &str) -> Result<(), OsRouteError> {
    let output = Command::new("ip")
        .args(["addr", "add", ip_cidr, "dev", tun_name])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip addr add: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(OsRouteError::CommandFailed(format!(
                "ip addr add {} dev {}: {}", ip_cidr, tun_name, stderr.trim()
            )));
        }
    }
    eprintln!("[n3-os] assigned {} to {}", ip_cidr, tun_name);
    Ok(())
}

fn bring_up(tun_name: &str) -> Result<(), OsRouteError> {
    let output = Command::new("ip")
        .args(["link", "set", "up", "dev", tun_name])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip link set up: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OsRouteError::CommandFailed(format!(
            "ip link set up dev {}: {}", tun_name, stderr.trim()
        )));
    }
    eprintln!("[n3-os] interface {} is UP", tun_name);
    Ok(())
}

fn install_control_plane_route(endpoint: &std::net::IpAddr, iface: &str) -> Result<(), OsRouteError> {
    let ip_str = endpoint.to_string();
    let output = Command::new("ip")
        .args(["route", "add", &ip_str, "dev", iface])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip route add control-plane: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(OsRouteError::CommandFailed(format!(
                "ip route add {} dev {}: {}", ip_str, iface, stderr.trim()
            )));
        }
    }
    eprintln!("[n3-os] control-plane route: {} → {}", ip_str, iface);
    Ok(())
}

fn install_default_route(tun_name: &str) -> Result<(), OsRouteError> {
    let output = Command::new("ip")
        .args(["route", "add", "default", "dev", tun_name])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip route add default: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            return Err(OsRouteError::CommandFailed(format!(
                "ip route add default dev {}: {}", tun_name, stderr.trim()
            )));
        }
    }
    eprintln!("[n3-os] default route installed via {}", tun_name);
    Ok(())
}

/// Detect the interface used by the current default route.
///
/// Runs `ip route show default` and parses the `dev <iface>` field.
/// Returns `None` if there is no default route (which is unusual but possible
/// in a network namespace that hasn't been configured yet).
fn detect_default_interface() -> Result<Option<String>, OsRouteError> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| OsRouteError::CommandFailed(format!("ip route show default: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output looks like: "default via 10.0.2.2 dev eth0 proto dhcp metric 100"
    for part in stdout.split_whitespace() {
        if part == "dev" {
            // The next token is the interface name.
            // We need to find it in the iterator — re-split.
            let tokens: Vec<&str> = stdout.split_whitespace().collect();
            for (i, tok) in tokens.iter().enumerate() {
                if *tok == "dev" {
                    if let Some(iface) = tokens.get(i + 1) {
                        eprintln!("[n3-os] detected default-route interface: {}", iface);
                        return Ok(Some(iface.to_string()));
                    }
                }
            }
        }
    }
    eprintln!("[n3-os] no default route found — control-plane routes will need manual configuration");
    Ok(None)
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
    fn os_route_config_constructs_with_control_plane() {
        let config = OsRouteConfig {
            tun_name: "snp0".to_string(),
            tun_ip_cidr: "10.0.0.1/24".to_string(),
            control_plane_endpoints: vec![
                "10.0.1.1".parse().unwrap(), // relay A
                "10.0.1.2".parse().unwrap(), // relay B
                "10.0.1.3".parse().unwrap(), // gateway
            ],
            physical_interface: Some("eth0".to_string()),
        };
        assert_eq!(config.tun_name, "snp0");
        assert_eq!(config.tun_ip_cidr, "10.0.0.1/24");
        assert_eq!(config.control_plane_endpoints.len(), 3);
        assert_eq!(config.physical_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn os_route_config_allows_no_control_plane_endpoints() {
        // A config with no control-plane endpoints is valid (the TUN gets all
        // traffic). This is used for testing where the mesh is in-process.
        let config = OsRouteConfig {
            tun_name: "snp0".to_string(),
            tun_ip_cidr: "10.0.0.1/24".to_string(),
            control_plane_endpoints: vec![],
            physical_interface: None,
        };
        assert!(config.control_plane_endpoints.is_empty());
    }

    #[test]
    fn installed_routes_default_is_empty() {
        let installed = InstalledRoutes::default();
        assert!(installed.tun_name.is_empty());
        assert!(installed.control_plane_endpoints.is_empty());
        assert!(installed.physical_interface.is_none());
    }
}
