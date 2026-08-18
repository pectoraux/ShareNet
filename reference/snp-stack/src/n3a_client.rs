//! **N3-A — TCP Stream Bridge Client.**
//!
//! A client-side data plane that accepts connections from OS applications
//! via a real TCP listener and forwards them through the ShareNet circuit
//! mesh to the Internet.
//!
//! ## Classification
//!
//! This is **N3-A — first end-to-end bridge**, NOT full L3 virtual
//! networking. It uses the OS's own TCP stack on the client side (a
//! listening TCP socket) rather than a TUN interface. This is explicitly
//! classified as a temporary TCP-stream bridge per the sprint spec:
//!
//! > "If the current implementation only has a robust stream abstraction,
//! > a temporary TCP-stream bridge may be acceptable for the first proof,
//! > but it must be explicitly classified as: N3-A — first end-to-end bridge"
//!
//! ## Architecture
//!
//! ```text
//! OS Application (e.g. curl)
//!     ↓ TCP connect to 127.0.0.1:8080
//! N3AClient (TcpListener)
//!     ↓ accept()
//! MultiplexedCircuit::open_stream(destination)
//!     ↓ encrypted circuit
//! Relay mesh
//!     ↓
//! Gateway
//!     ↓ real TCP socket
//! Internet
//! ```
//!
//! ## What this proves
//!
//! - An ordinary OS application can communicate with a real Internet
//!   endpoint through ShareNet.
//! - The ShareNet circuit carries real application traffic.
//! - The gateway opens a real Internet TCP connection.
//! - Responses flow back through ShareNet to the application.
//!
//! ## What this does NOT prove
//!
//! - Transparent L3 networking (no TUN, no IP packets).
//! - Application transparency (the application must connect to the
//!   bridge's listening address, not directly to the Internet).
//! - DNS resolution through ShareNet (IP addresses only for now).

#![cfg(feature = "circuit-upstream")]

use snp_crypto::{X25519PubKey, X25519Secret};
use snp_gateway::stream::InternetEndpoint;
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_node::node::{Node, Route};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Configuration for the N3-A TCP stream bridge client.
pub struct N3AClientConfig {
    /// The address to listen on for OS application connections
    /// (e.g. "127.0.0.1:8080").
    pub listen_addr: String,
    /// The ShareNet route to the gateway.
    pub route: Route,
    /// The client node.
    pub node: Node,
    /// The client's X25519 secret.
    pub client_x25519_secret: Arc<X25519Secret>,
    /// The client's X25519 public.
    pub client_x25519_public: X25519PubKey,
    /// The default destination for connections that don't specify one
    /// (if None, the client uses the SOCKS-like protocol to determine
    /// the destination from the first bytes).
    pub default_destination: Option<InternetEndpoint>,
}

/// The N3-A TCP stream bridge client.
///
/// Accepts TCP connections from OS applications and forwards them
/// through ShareNet to the Internet.
pub struct N3AClient {
    config: N3AClientConfig,
    circuit: MultiplexedCircuit,
}

impl N3AClient {
    /// Create the N3-A client.
    ///
    /// Establishes the multiplexed circuit to the gateway.
    pub async fn create(config: N3AClientConfig) -> Result<Self, N3AError> {
        let circuit = MultiplexedCircuit::establish(
            &config.node,
            &config.route,
            &config.client_x25519_secret,
            &config.client_x25519_public,
        )
        .await
        .map_err(|e| N3AError::CircuitEstablish(format!("{:?}", e)))?;

        eprintln!(
            "[n3-a] multiplexed circuit established (fid={:?})",
            circuit.circuit_fid()
        );

        Ok(Self { config, circuit })
    }

    /// Run the TCP stream bridge.
    ///
    /// Listens for incoming TCP connections and forwards each one
    /// through ShareNet. Runs forever.
    ///
    /// If `default_destination` is set, all connections are forwarded
    /// to that destination (fixed-destination bridge).
    ///
    /// If `default_destination` is `None`, the client speaks SOCKS5
    /// (RFC 1928) to determine the destination dynamically. This allows
    /// real applications (curl, wget, browsers) to use the bridge via
    /// `--socks5 127.0.0.1:PORT`.
    pub async fn run(&mut self) -> Result<(), N3AError> {
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| N3AError::Bind(e))?;

        eprintln!(
            "[n3-a] listening for application connections on {} (SOCKS5: {})",
            self.config.listen_addr,
            self.config.default_destination.is_none()
        );

        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("[n3-a] accept error: {}", e);
                    continue;
                }
            };

            eprintln!("[n3-a] accepted connection from {}", peer_addr);

            // Determine the destination.
            let (destination, tcp_stream) = match self.config.default_destination {
                Some(ref dest) => {
                    // Fixed-destination mode — no SOCKS5 handshake.
                    (dest.clone(), tcp_stream)
                }
                None => {
                    // SOCKS5 mode — perform the handshake to determine destination.
                    match socks5_handshake(tcp_stream).await {
                        Ok((dest, stream)) => (dest, stream),
                        Err(e) => {
                            eprintln!("[n3-a] SOCKS5 handshake failed: {:?}", e);
                            continue;
                        }
                    }
                }
            };

            let circuit_fid = self.circuit.circuit_fid();

            // Open a ShareNet stream to the destination.
            match self.circuit.open_stream(destination.clone()).await {
                Ok(mut stream) => {
                    eprintln!(
                        "[n3-a] opened stream to {:?} on circuit {:?}",
                        destination, circuit_fid
                    );
                    tokio::spawn(async move {
                        if let Err(e) = pump_bidirectionally(tcp_stream, &mut stream).await {
                            eprintln!("[n3-a] connection error: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!(
                        "[n3-a] failed to open stream to {:?}: {:?}",
                        destination, e
                    );
                    drop(tcp_stream);
                }
            }
        }
    }
}

/// **SOCKS5 handshake (RFC 1928).**
///
/// Performs the SOCKS5 greeting + CONNECT request, returning the
/// destination endpoint and the TCP stream (ready for data transfer).
///
/// ```text
/// Client → Server: [VER=5, NMETHODS, METHODS...]
/// Server → Client: [VER=5, METHOD=0 (no auth)]
/// Client → Server: [VER=5, CMD=1 (CONNECT), RSV=0, ATYP, DST.ADDR, DST.PORT]
/// Server → Client: [VER=5, REP=0 (success), RSV=0, ATYP, BND.ADDR, BND.PORT]
/// ```
async fn socks5_handshake(
    mut tcp: TcpStream,
) -> Result<(InternetEndpoint, TcpStream), N3AError> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // 1. Read greeting: [VER, NMETHODS, METHODS...]
    let mut header = [0u8; 2];
    tcp.read_exact(&mut header).await.map_err(N3AError::Io)?;
    if header[0] != 0x05 {
        return Err(N3AError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SOCKS5: bad version {}", header[0]),
        )));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods).await.map_err(N3AError::Io)?;

    // 2. Reply: no authentication required.
    tcp.write_all(&[0x05, 0x00]).await.map_err(N3AError::Io)?;

    // 3. Read CONNECT request: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
    let mut req_header = [0u8; 4];
    tcp.read_exact(&mut req_header).await.map_err(N3AError::Io)?;
    if req_header[0] != 0x05 {
        return Err(N3AError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SOCKS5: bad version in request {}", req_header[0]),
        )));
    }
    if req_header[1] != 0x01 {
        // Only CONNECT is supported.
        // Reply with "command not supported".
        let _ = tcp.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(N3AError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("SOCKS5: only CONNECT (1) supported, got CMD={}", req_header[1]),
        )));
    }

    let atyp = req_header[3];
    let address = match atyp {
        0x01 => {
            // IPv4: 4 bytes.
            let mut addr = [0u8; 4];
            tcp.read_exact(&mut addr).await.map_err(N3AError::Io)?;
            IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
        }
        0x03 => {
            // Domain name: 1-byte length + domain.
            let mut len_buf = [0u8; 1];
            tcp.read_exact(&mut len_buf).await.map_err(N3AError::Io)?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len];
            tcp.read_exact(&mut domain_buf).await.map_err(N3AError::Io)?;
            let domain = String::from_utf8_lossy(&domain_buf).to_string();
            // Resolve the domain to an IP address.
            // For the first proof, we resolve via the OS DNS resolver.
            // Future: resolve through ShareNet's DnsResolver.
            match tokio::net::lookup_host(format!("{}:0", domain)).await {
                Ok(mut iter) => {
                    match iter.next() {
                        Some(addr) => addr.ip(),
                        None => {
                            let _ = tcp.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                            return Err(N3AError::Io(std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                format!("SOCKS5: DNS resolution failed for {}", domain),
                            )));
                        }
                    }
                }
                Err(e) => {
                    let _ = tcp.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return Err(N3AError::Io(e));
                }
            }
        }
        0x04 => {
            // IPv6: 16 bytes.
            let mut addr = [0u8; 16];
            tcp.read_exact(&mut addr).await.map_err(N3AError::Io)?;
            IpAddr::V6(Ipv6Addr::from(addr))
        }
        _ => {
            let _ = tcp.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(N3AError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SOCKS5: unsupported ATYP {}", atyp),
            )));
        }
    };

    // Read destination port (2 bytes, big-endian).
    let mut port_buf = [0u8; 2];
    tcp.read_exact(&mut port_buf).await.map_err(N3AError::Io)?;
    let port = u16::from_be_bytes(port_buf);

    let destination = InternetEndpoint {
        address,
        port,
        protocol: snp_gateway::stream::TransportProtocol::Tcp,
    };

    eprintln!("[n3-a] SOCKS5 CONNECT to {:?}:{}", address, port);

    // 4. Reply: success.
    //    BND.ADDR and BND.PORT are not meaningful for a proxy — set to 0.0.0.0:0.
    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(N3AError::Io)?;

    Ok((destination, tcp))
}

/// Pump data bidirectionally between a TCP stream and a ShareNet stream.
///
/// This is the core data-transfer loop:
/// - TCP → ShareNet (application → Internet)
/// - ShareNet → TCP (Internet → application)
async fn pump_bidirectionally(
    mut tcp: TcpStream,
    stream: &mut snp_node::node::stream_client::StreamHandle,
) -> Result<(), N3AError> {
    // We can't do true bidirectional select with &mut stream in two tasks
    // because StreamHandle is not Send+Sync for split. Instead, we do
    // alternating read/write in a loop.
    //
    // This is less efficient than true bidirectional pumping but works
    // for the first proof. A production implementation would use
    // tokio::join! with split streams.
    let mut tcp_buf = vec![0u8; 8192];
    let mut sn_buf = vec![0u8; 8192];

    loop {
        // Try to read from TCP (with a short timeout).
        let tcp_read = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            tcp.read(&mut tcp_buf),
        )
        .await;

        match tcp_read {
            Ok(Ok(0)) => {
                // TCP connection closed by the application.
                eprintln!("[n3-a] application closed connection");
                break;
            }
            Ok(Ok(n)) => {
                // Forward application data → ShareNet.
                if let Err(e) = stream.send(&tcp_buf[..n]).await {
                    eprintln!("[n3-a] stream send error: {:?}", e);
                    break;
                }
            }
            Ok(Err(e)) => {
                eprintln!("[n3-a] tcp read error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout — no data from application. Check ShareNet.
            }
        }

        // Try to read from ShareNet (with a short timeout).
        let sn_read = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            stream.recv(),
        )
        .await;

        match sn_read {
            Ok(Ok(Some(data))) => {
                if data.is_empty() {
                    continue;
                }
                // Forward ShareNet data → application.
                if let Err(e) = tcp.write_all(&data).await {
                    eprintln!("[n3-a] tcp write error: {}", e);
                    break;
                }
            }
            Ok(Ok(None)) => {
                // ShareNet stream closed.
                eprintln!("[n3-a] ShareNet stream closed");
                break;
            }
            Ok(Err(e)) => {
                eprintln!("[n3-a] stream recv error: {:?}", e);
                break;
            }
            Err(_) => {
                // Timeout — no data from ShareNet. Continue.
            }
        }
    }

    // Clean up.
    let _ = stream.close().await;
    let _ = tcp.shutdown().await;
    Ok(())
}

/// Errors for the N3-A client.
#[derive(Debug)]
pub enum N3AError {
    /// Failed to establish the multiplexed circuit.
    CircuitEstablish(String),
    /// Failed to bind the TCP listener.
    Bind(std::io::Error),
    /// I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for N3AError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CircuitEstablish(e) => write!(f, "circuit establish error: {}", e),
            Self::Bind(e) => write!(f, "bind error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for N3AError {}
