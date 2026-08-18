//! Async transport — Tokio-based async I/O for the ShareNet reference node.
//!
//! **N2.0.5: This is the SINGLE CANONICAL PRODUCTION network path.** All
//! production runtime networking goes through this module. The synchronous
//! transport (`transport.rs`) is `#[deprecated]` and retained only for
//! tests / backward compatibility.
//!
//! N2.0.4 Gate D: genuine async networking using Tokio.
//! This module provides async versions of TransportProvider, TransportConnection,
//! and TransportListener using `tokio::net::TcpStream` / `tokio::net::TcpListener`.
//!
//! ## Design (N2.0.5 — concrete types, no async-trait)
//!
//! Per the N2.0.5 task spec, we do NOT define an async-trait abstraction
//! here (avoiding the `async_trait` crate dependency + the object-safety
//! rabbit hole of native async traits). Instead, the canonical production
//! transport is the concrete `AsyncTcpConnection` / `AsyncTcpListener` /
//! `AsyncTcpTransportProvider` types. The Node uses these types directly;
//! the Android platform implements equivalent concrete types (a
//! `BleAsyncConnection` etc.) behind the same shape.
//!
//! A trait abstraction (`AsyncTransportConnection` / `AsyncTransportListener`
//! / `AsyncTransportProvider`) can be formalized when a non-TCP transport is
//! actually implemented (e.g. BLE GATT for Android peer-to-peer discovery).
//! Until then, the concrete types are the abstraction — a caller that wants
//! to swap transports replaces the type, not a trait object.
//!
//! ## Why async?
//!
//! The production node MUST handle concurrent connections — a relay
//! forwards between many client/gateway pairs in parallel; a gateway
//! serves many relays concurrently. Synchronous I/O (one thread per
//! connection) does not scale to the production workload. Tokio's
//! lightweight task scheduler + `tokio::io::split` for bidirectional
//! relay forwarding is the production design.

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Errors from the async transport layer.
#[derive(Debug, Error)]
pub enum AsyncTransportError {
    /// `connect()` failed — the address and the underlying OS error are
    /// included for diagnostics.
    #[error("connect to {0}: {1}")]
    Connect(String, String),
    /// `listen()` / `bind()` failed — the address and the underlying OS
    /// error are included for diagnostics.
    #[error("bind {0}: {1}")]
    Bind(String, String),
    /// A read or write on an established connection failed. The underlying
    /// OS error is included.
    #[error("io: {0}")]
    Io(String),
    /// The peer closed the connection cleanly. Returned by `recv_framed`
    /// when the peer has shut down their write side (EOF).
    #[error("connection closed")]
    Closed,
}

/// An async transport connection backed by Tokio TCP.
pub struct AsyncTcpConnection {
    stream: TcpStream,
    alive: bool,
}

impl AsyncTcpConnection {
    /// Create from an existing TcpStream.
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            alive: true,
        }
    }

    /// Send raw bytes asynchronously.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), AsyncTransportError> {
        if !self.alive {
            return Err(AsyncTransportError::Closed);
        }
        self.stream.write_all(data).await.map_err(|e| {
            self.alive = false;
            AsyncTransportError::Io(e.to_string())
        })?;
        self.stream.flush().await.ok();
        Ok(())
    }

    /// Send a length-prefixed message (4-byte big-endian length + payload).
    pub async fn send_framed(&mut self, data: &[u8]) -> Result<(), AsyncTransportError> {
        let len = u32::try_from(data.len())
            .map_err(|_| AsyncTransportError::Io("frame too large".to_string()))?;
        self.send(&len.to_be_bytes()).await?;
        self.send(data).await
    }

    /// Receive a length-prefixed message.
    pub async fn recv_framed(&mut self) -> Result<Vec<u8>, AsyncTransportError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await.map_err(|e| {
            self.alive = false;
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                AsyncTransportError::Closed
            } else {
                AsyncTransportError::Io(e.to_string())
            }
        })?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(AsyncTransportError::Io("frame too large".to_string()));
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await.map_err(|e| {
            self.alive = false;
            AsyncTransportError::Io(e.to_string())
        })?;
        Ok(buf)
    }

    /// Check if the connection is alive.
    pub fn is_alive(&self) -> bool {
        self.alive
    }

    /// Close the connection.
    pub fn close(&mut self) {
        self.alive = false;
        let _ = self.stream.shutdown();
    }
}

/// An async transport listener backed by Tokio TCP.
pub struct AsyncTcpListener {
    listener: TcpListener,
}

impl AsyncTcpListener {
    /// Bind to an address.
    pub async fn bind(addr: &str) -> Result<Self, AsyncTransportError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| AsyncTransportError::Bind(addr.to_string(), e.to_string()))?;
        Ok(Self { listener })
    }

    /// Get the local address.
    pub fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    /// Accept an incoming connection.
    pub async fn accept(&self) -> Result<AsyncTcpConnection, AsyncTransportError> {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|e| AsyncTransportError::Io(e.to_string()))?;
        stream.set_nodelay(true).ok();
        Ok(AsyncTcpConnection::new(stream))
    }
}

/// Async transport provider using Tokio TCP.
#[derive(Clone)]
pub struct AsyncTcpTransportProvider;

impl AsyncTcpTransportProvider {
    /// Connect to a remote endpoint.
    pub async fn connect(&self, addr: &str) -> Result<AsyncTcpConnection, AsyncTransportError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| AsyncTransportError::Connect(addr.to_string(), e.to_string()))?;
        stream.set_nodelay(true).ok();
        Ok(AsyncTcpConnection::new(stream))
    }

    /// Listen on a local address.
    pub async fn listen(&self, addr: &str) -> Result<AsyncTcpListener, AsyncTransportError> {
        AsyncTcpListener::bind(addr).await
    }
}

/// An async relay that forwards framed messages between two connections.
///
/// This is the async equivalent of the synchronous `serve_relay_persistent`.
/// It spawns two tasks: one forwarding client→gateway, one forwarding gateway→client.
pub async fn async_relay_forward(
    client: AsyncTcpConnection,
    gateway: AsyncTcpConnection,
) -> Result<(), AsyncTransportError> {
    // Use tokio::io::split to get separate read/write halves
    let (client_read, client_write) = tokio::io::split(client.stream);
    let (gw_read, gw_write) = tokio::io::split(gateway.stream);

    let c2g = forward_split(client_read, gw_write);
    let g2c = forward_split(gw_read, client_write);

    tokio::select! {
        res = c2g => res,
        res = g2c => res,
    }
}

/// Forward framed messages from a read half to a write half.
async fn forward_split<R, W>(mut read: R, mut write: W) -> Result<(), AsyncTransportError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        read.read_exact(&mut len_buf).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                AsyncTransportError::Closed
            } else {
                AsyncTransportError::Io(e.to_string())
            }
        })?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(AsyncTransportError::Io("frame too large".to_string()));
        }
        // Read payload
        let mut buf = vec![0u8; len];
        read.read_exact(&mut buf)
            .await
            .map_err(|e| AsyncTransportError::Io(e.to_string()))?;
        // Write length prefix + payload
        write
            .write_all(&len_buf)
            .await
            .map_err(|e| AsyncTransportError::Io(e.to_string()))?;
        write
            .write_all(&buf)
            .await
            .map_err(|e| AsyncTransportError::Io(e.to_string()))?;
        write.flush().await.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn async_tcp_roundtrip() {
        let provider = AsyncTcpTransportProvider;
        let listener = provider.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            let msg = conn.recv_framed().await.unwrap();
            conn.send_framed(&msg).await.unwrap(); // echo
        });

        let mut client = provider.connect(&addr).await.unwrap();
        client.send_framed(b"hello async").await.unwrap();
        let echo = client.recv_framed().await.unwrap();
        assert_eq!(echo, b"hello async");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn async_concurrent_connections() {
        // Prove 10 concurrent connections work simultaneously
        let provider = AsyncTcpTransportProvider;
        let listener = provider.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();

        let server = tokio::spawn(async move {
            let mut handles = Vec::new();
            for _ in 0..10 {
                let mut conn = listener.accept().await.unwrap();
                handles.push(tokio::spawn(async move {
                    let msg = conn.recv_framed().await.unwrap();
                    conn.send_framed(&msg).await.unwrap();
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        });

        let mut client_handles = Vec::new();
        for i in 0..10u32 {
            let addr = addr.clone();
            client_handles.push(tokio::spawn(async move {
                let provider = AsyncTcpTransportProvider;
                let mut conn = provider.connect(&addr).await.unwrap();
                let msg = format!("concurrent-{i}");
                conn.send_framed(msg.as_bytes()).await.unwrap();
                let echo = conn.recv_framed().await.unwrap();
                assert_eq!(echo, msg.as_bytes());
            }));
        }

        for h in client_handles {
            h.await.unwrap();
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn async_relay_bidirectional() {
        let provider = AsyncTcpTransportProvider;

        // Gateway listener
        let gw_listener = provider.listen("127.0.0.1:0").await.unwrap();
        let gw_addr = gw_listener.local_addr();

        // Relay listener (client-facing)
        let relay_listener = provider.listen("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr();

        // Start relay: accept client, connect to gateway, forward
        let relay_handle = tokio::spawn(async move {
            let client = relay_listener.accept().await.unwrap();
            let gateway = AsyncTcpTransportProvider.connect(&gw_addr).await.unwrap();
            async_relay_forward(client, gateway).await
        });

        // Start gateway: echo
        let gw_handle = tokio::spawn(async move {
            let mut conn = gw_listener.accept().await.unwrap();
            let msg = conn.recv_framed().await.unwrap();
            conn.send_framed(&msg).await.unwrap();
        });

        // Client sends through relay → gateway → relay → client
        let mut client = provider.connect(&relay_addr).await.unwrap();
        client.send_framed(b"through relay").await.unwrap();
        let response = client.recv_framed().await.unwrap();
        assert_eq!(response, b"through relay");

        // Clean up
        client.close();
        relay_handle.await.unwrap();
        gw_handle.await.unwrap();
    }
}
