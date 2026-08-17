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
    pub async fn run(&mut self) -> Result<(), N3AError> {
        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| N3AError::Bind(e))?;

        eprintln!(
            "[n3-a] listening for application connections on {}",
            self.config.listen_addr
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
            let destination = match self.config.default_destination {
                Some(ref dest) => dest.clone(),
                None => {
                    // TODO: implement SOCKS5 protocol to determine destination.
                    // For now, reject connections without a default destination.
                    eprintln!("[n3-a] no default destination configured — closing");
                    drop(tcp_stream);
                    continue;
                }
            };

            // Clone the circuit handle. MultiplexedCircuit uses interior
            // Arc<Mutex<>> so we can share it across tasks.
            let circuit_fid = self.circuit.circuit_fid();

            // Spawn a task to handle this connection.
            // We need to open a stream on the circuit — since MultiplexedCircuit
            // is behind a mutex in the circuit handle, we need to share it.
            // Actually, MultiplexedCircuit is not Clone. We need a different
            // approach — open the stream before spawning the task.
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
