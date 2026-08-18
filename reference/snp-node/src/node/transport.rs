//! Transport — platform-independent TransportProvider abstraction.
//!
//! **N2.0.5: DEPRECATED for production runtime.** This module provides the
//! SYNCHRONOUS transport abstraction (`std::net::TcpStream`-backed). The
//! production runtime now uses the ASYNC transport abstraction in
//! [`super::async_transport`] (Tokio-backed, supports concurrent connections,
//! is the single canonical network path). This module is kept for tests and
//! backward compatibility with code that still needs synchronous I/O (e.g.
//! `tests/n204_runtime.rs`'s `gate_b_transport_provider_tcp_roundtrip` test).
//!
//! ## Historical context
//!
//! Extracted for N2.0.4 Gate B. The [`TransportProvider`] trait abstracts
//! over the underlying network transport (TCP, BLE GATT, Wi-Fi Direct, etc.)
//! so the same SNP-Node logic can run on platforms that do not expose POSIX
//! sockets (e.g. Android, where BLE GATT is the transport for peer-to-peer
//! discovery).
//!
//! ## Design (N2.0.4 — "connection-establishment level" abstraction)
//!
//! The TransportProvider abstraction sits at the **connection-establishment**
//! level — it knows how to create a connected byte stream and how to listen
//! for incoming streams. Once a stream exists, the existing [`Link`] layer
//! (snp-link) takes over: it does length-prefixed framing, ChaCha20-Poly1305
//! AEAD, and replay protection on top of the raw byte stream.
//!
//! This keeps the transport trait simple: `connect` returns a
//! `Box<dyn TransportConnection>`, `listen` returns a
//! `Box<dyn TransportListener>`, and the connection itself just exposes raw
//! `send`/`recv` of byte buffers.
//!
//! For the Rust reference implementation ([`TcpTransportProvider`]) the
//! `TransportConnection` wraps a `std::net::TcpStream` and the
//! `TransportListener` wraps a `std::net::TcpListener`.
//!
//! ## Why not abstract the I/O too?
//!
//! An alternative design would have `TransportConnection::recv` use
//! `read_exact` on a 4-byte length prefix, then read that many bytes — i.e.
//! push the framing into the transport. We reject this for two reasons:
//!
//! 1. The Link layer ALREADY does length-prefixed framing (with AEAD). Moving
//!    the framing into the transport would duplicate it.
//! 2. The framing format is protocol-specific (SNP frames). A transport
//!    abstraction should be protocol-agnostic so it can be reused by other
//!    SNP sub-protocols (e.g. the N2.0.4 raw discovery handshake) without
//!    dragging in SNP-frame semantics.
//!
//! ## Production readiness (N2.0.5)
//!
//! The [`TcpTransportProvider`] IS functionally production-ready — it is a
//! thin wrapper around `std::net::TcpStream` / `std::net::TcpListener` that
//! sets `TCP_NODELAY` (disables Nagle, since SNP frames are small and we want
//! low latency) and exposes a `Send + Sync` trait object. However, the
//! PRODUCTION RUNTIME uses the async transport (`AsyncTcpTransportProvider`)
//! because the production node needs to handle concurrent connections (relays
//! forwarding between many client/gateway pairs in parallel). This sync
//! transport is retained for tests + backward compatibility.
//!
//! The trait abstraction is the N2.0.4 deliverable: the Android platform
//! (see `docs/n2.0.3-android-platform-contract.md`) implements a
//! `BleTransportProvider` (BLE GATT) and a `WifiDirectTransportProvider`
//! (Wi-Fi Direct) behind the same trait, so the SNP-Node logic does not
//! change between platforms.

// N2.0.5: The sync transport is `#[deprecated]` for production runtime.
// The module itself uses `#[allow(deprecated)]` so the trait definitions
// can reference each other (e.g. `TransportListener::accept` returns
// `Box<dyn TransportConnection>`) without triggering the deprecation
// warning at the trait-definition level. External callers (production code)
// will still see the deprecation warning if they use these types.
#![allow(deprecated)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Errors returned by the transport layer.
///
/// Each variant carries enough context for the caller to log a useful
/// diagnostic (e.g. which address failed to connect, which I/O error
/// occurred). The errors are intentionally NOT `Clone` (some variants carry
/// `String`s and we want to discourage casual propagation of large error
/// contexts).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
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

    /// The peer closed the connection cleanly. Returned by `recv` when the
    /// peer has shut down their write side (EOF).
    #[error("connection closed")]
    Closed,
}

// ─── Traits ─────────────────────────────────────────────────────────────────

/// A platform-independent transport connection.
///
/// Wraps a TCP stream (or BLE GATT, Wi-Fi Direct, etc.) and provides raw
/// byte-level `send` / `recv`. Framing, AEAD, and replay protection are
/// handled by the [`Link`](snp_link::Link) layer on top.
///
/// ## Send semantics
///
/// `send` writes the entire buffer to the underlying transport. A `Ok(())`
/// return means all bytes were written. A `Err` return means the connection
/// is dead — the caller MUST drop it.
///
/// ## Recv semantics
///
/// `recv` reads ONE chunk of data from the underlying transport. The chunk
/// size is transport-defined (for TCP, it is whatever the kernel returns
/// from `read` — typically one MSS or less). Callers that need framed reads
/// (e.g. SNP frames) MUST use the `Link` layer, which calls `recv` in a
/// loop until it has a complete length-prefixed frame.
///
/// For the N2.0.4 raw discovery handshake (which does NOT use the Link
/// layer), the caller reads the 4-byte length prefix with two `recv` calls
/// (or one — the trait guarantees at least one byte per `recv` if the
/// connection is alive, but does NOT guarantee a specific chunk size).
///
/// Returns `Err(TransportError::Closed)` when the peer has shut down their
/// write side (EOF).
///
/// ## Object safety
///
/// The trait is object-safe — `Box<dyn TransportConnection>` is the
/// intended usage. `Send` is required so the connection can be moved
/// between threads (e.g. handed off to a relay forwarder thread).
///
/// **N2.0.5: DEPRECATED for production runtime.** Use the async
/// [`super::async_transport::AsyncTcpConnection`] instead — the production
/// runtime is async (Tokio-based). This sync trait is retained for tests
/// and backward compatibility.
#[deprecated(
    since = "N2.0.5",
    note = "Use the async transport (super::async_transport::AsyncTcpConnection) instead. \
            The production runtime is async (Tokio-based); this sync trait is retained \
            for tests and backward compatibility."
)]
pub trait TransportConnection: Send {
    /// Send raw bytes. Returns `Ok(())` if all bytes were written, or
    /// `Err` if the connection is dead.
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Receive raw bytes. Returns `Ok(buf)` with at least one byte (if the
    /// connection is alive), or `Err(TransportError::Closed)` on EOF.
    fn recv(&mut self) -> Result<Vec<u8>, TransportError>;

    /// Check if the connection is alive (no I/O errors seen yet, no
    /// explicit `close`). A `true` return does NOT guarantee the next I/O
    /// will succeed — it is a hint for connection-pool heuristics.
    fn is_alive(&self) -> bool;

    /// Close the connection. Subsequent `send`/`recv` calls will return
    /// `Err`. This is idempotent.
    fn close(&mut self);
}

/// A platform-independent transport listener.
///
/// Wraps a `TcpListener` (or BLE advertise handle, Wi-Fi Direct group
/// owner socket, etc.) and accepts incoming connections.
///
/// **N2.0.5: DEPRECATED for production runtime.** Use the async
/// [`super::async_transport::AsyncTcpListener`] instead — the production
/// runtime is async (Tokio-based).
#[deprecated(
    since = "N2.0.5",
    note = "Use the async transport (super::async_transport::AsyncTcpListener) instead. \
            The production runtime is async (Tokio-based); this sync trait is retained \
            for tests and backward compatibility."
)]
pub trait TransportListener: Send {
    /// Accept one incoming connection. Blocks until a connection arrives.
    fn accept(&mut self) -> Result<Box<dyn TransportConnection>, TransportError>;

    /// Get the address this listener is bound to. For TCP this is
    /// `"ip:port"`. For BLE/Wi-Fi Direct it may be a device-specific
    /// identifier. Returns the empty string if the address cannot be
    /// determined (e.g. the listener was closed).
    fn local_addr(&self) -> String;

    /// Stop listening. Subsequent `accept` calls will return `Err`. This
    /// is idempotent.
    fn close(&mut self);
}

/// A platform-independent transport provider.
///
/// Creates connections and listeners. The provider is `Send + Sync` so it
/// can be shared across threads (e.g. an Android `BleTransportProvider`
/// holds a `BluetoothManager` that is shared across all BLE connections).
///
/// ## Implementations
///
/// - [`TcpTransportProvider`] — the Rust reference implementation. Wraps
///   `std::net::TcpStream` / `std::net::TcpListener`.
/// - (Android) `BleTransportProvider` — BLE GATT. Implemented in the
///   Android port (see `docs/n2.0.3-android-platform-contract.md`).
/// - (Android) `WifiDirectTransportProvider` — Wi-Fi Direct group owner.
///   Implemented in the Android port.
///
/// **N2.0.5: DEPRECATED for production runtime.** Use the async
/// [`super::async_transport::AsyncTcpTransportProvider`] instead — the
/// production runtime is async (Tokio-based) and supports concurrent
/// connections.
#[deprecated(
    since = "N2.0.5",
    note = "Use the async transport (super::async_transport::AsyncTcpTransportProvider) instead. \
            The production runtime is async (Tokio-based) and supports concurrent connections; \
            this sync trait is retained for tests and backward compatibility."
)]
pub trait TransportProvider: Send + Sync {
    /// Connect to a remote endpoint. The address format is
    /// transport-defined (for TCP, `"host:port"`; for BLE, a MAC address
    /// or UUID; for Wi-Fi Direct, a group owner address).
    fn connect(&self, addr: &str) -> Result<Box<dyn TransportConnection>, TransportError>;

    /// Listen on a local address. Returns a [`TransportListener`] that
    /// accepts incoming connections.
    fn listen(&self, addr: &str) -> Result<Box<dyn TransportListener>, TransportError>;
}

// ─── TCP implementation (the Rust reference) ────────────────────────────────

/// TCP transport provider (the Rust reference implementation).
///
/// Wraps `std::net::TcpStream` / `std::net::TcpListener` behind the
/// [`TransportProvider`] trait. Sets `TCP_NODELAY` (disables Nagle) on
/// every connection — SNP frames are small and we want low latency.
///
/// ## Production-ready (N2.0.4)
///
/// This IS functionally production-ready — it is a thin wrapper around the
/// standard library's TCP types. The trait abstraction (not this impl) is
/// the N2.0.4 deliverable.
///
/// **N2.0.5: DEPRECATED for production runtime.** Use the async
/// [`super::async_transport::AsyncTcpTransportProvider`] instead. The
/// production runtime is async (Tokio-based) and supports concurrent
/// connections; this sync impl is retained for tests and backward
/// compatibility.
#[deprecated(
    since = "N2.0.5",
    note = "Use AsyncTcpTransportProvider (super::async_transport) instead. \
            The production runtime is async (Tokio-based); this sync impl is retained \
            for tests and backward compatibility."
)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpTransportProvider;

#[allow(deprecated)]
impl TcpTransportProvider {
    /// Construct a new `TcpTransportProvider`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[allow(deprecated)]
impl TransportProvider for TcpTransportProvider {
    fn connect(&self, addr: &str) -> Result<Box<dyn TransportConnection>, TransportError> {
        let stream = TcpStream::connect(addr)
            .map_err(|e| TransportError::Connect(addr.to_string(), e.to_string()))?;
        // Disable Nagle — SNP frames are small and we want low latency.
        // `set_nodelay` failing is non-fatal (the stream still works, just
        // with Nagle's algorithm enabled).
        let _ = stream.set_nodelay(true);
        Ok(Box::new(TcpTransportConnection {
            stream,
            alive: true,
        }))
    }

    fn listen(&self, addr: &str) -> Result<Box<dyn TransportListener>, TransportError> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| TransportError::Bind(addr.to_string(), e.to_string()))?;
        Ok(Box::new(TcpTransportListener { listener }))
    }
}

/// A TCP connection implementing [`TransportConnection`].
///
/// Wraps a `std::net::TcpStream`. The `alive` flag is set to `false` on
/// any I/O error — callers SHOULD check [`is_alive`](TransportConnection::is_alive)
/// before reusing a connection from a pool, but the trait methods are
/// safe to call even after an error (they will return `Err`).
///
/// **N2.0.5: DEPRECATED for production runtime.** Use the async
/// [`super::async_transport::AsyncTcpConnection`] instead.
#[deprecated(
    since = "N2.0.5",
    note = "Use AsyncTcpConnection (super::async_transport) instead. \
            The production runtime is async (Tokio-based); this sync impl is retained \
            for tests and backward compatibility."
)]
pub struct TcpTransportConnection {
    stream: TcpStream,
    alive: bool,
}

#[allow(deprecated)]
impl TransportConnection for TcpTransportConnection {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.alive {
            return Err(TransportError::Closed);
        }
        self.stream.write_all(data).map_err(|e| {
            self.alive = false;
            TransportError::Io(e.to_string())
        })?;
        self.stream.flush().map_err(|e| {
            self.alive = false;
            TransportError::Io(e.to_string())
        })?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.alive {
            return Err(TransportError::Closed);
        }
        // Read whatever the kernel has buffered. A 64 KiB buffer is large
        // enough to hold a typical SNP frame in one read, while small
        // enough to not waste memory on idle connections.
        let mut buf = vec![0u8; 64 * 1024];
        let n = self.stream.read(&mut buf).map_err(|e| {
            self.alive = false;
            TransportError::Io(e.to_string())
        })?;
        if n == 0 {
            // EOF — peer closed their write side.
            self.alive = false;
            return Err(TransportError::Closed);
        }
        buf.truncate(n);
        Ok(buf)
    }

    fn is_alive(&self) -> bool {
        self.alive
    }

    fn close(&mut self) {
        self.alive = false;
        // `Shutdown::Both` is best-effort — if the peer has already gone
        // away, this returns an error that we ignore.
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// A TCP listener implementing [`TransportListener`].
///
/// Wraps a `std::net::TcpListener`. Accepting a connection returns a
/// `Box<dyn TransportConnection>` (a [`TcpTransportConnection`] under the
/// hood).
///
/// **N2.0.5: DEPRECATED for production runtime.** Use the async
/// [`super::async_transport::AsyncTcpListener`] instead.
#[deprecated(
    since = "N2.0.5",
    note = "Use AsyncTcpListener (super::async_transport) instead."
)]
pub struct TcpTransportListener {
    listener: TcpListener,
}

#[allow(deprecated)]
impl TransportListener for TcpTransportListener {
    fn accept(&mut self) -> Result<Box<dyn TransportConnection>, TransportError> {
        let (stream, _peer_addr) = self
            .listener
            .accept()
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(TcpTransportConnection {
            stream,
            alive: true,
        }))
    }

    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    fn close(&mut self) {
        // `TcpListener` does not have an explicit `close` method — dropping
        // it closes the socket. There is nothing to do here except let the
        // field go out of scope (the caller drops `self` after calling
        // `close`).
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// N2.0.4 (Gate B): `TcpTransportProvider` can `listen` on an
    /// ephemeral port, and `local_addr` returns the bound address.
    #[test]
    fn tcp_transport_provider_listen_returns_local_addr() {
        let provider = TcpTransportProvider::new();
        let listener = provider
            .listen("127.0.0.1:0")
            .expect("listen on ephemeral port must succeed");
        let addr = listener.local_addr();
        assert!(
            !addr.is_empty(),
            "local_addr must return the bound address, got empty string"
        );
        assert!(
            addr.starts_with("127.0.0.1:"),
            "local_addr must be 127.0.0.1:port, got {addr}"
        );
    }

    /// N2.0.4 (Gate B): `connect` to a non-existent address returns
    /// `Err(TransportError::Connect(..))`. The address and OS error are
    /// captured for diagnostics.
    #[test]
    fn tcp_transport_connect_to_dead_address_returns_error() {
        let provider = TcpTransportProvider::new();
        // Bind + immediately drop to get a definitely-unbound port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let addr_str = addr.to_string();
        drop(listener);
        // The port may have been reused by the OS in the meantime — retry
        // a few times to find a definitely-unbound port. In practice this
        // is unlikely on a single test run, but the retry loop makes the
        // test robust.
        let mut last_err = None;
        for _ in 0..5 {
            match provider.connect(&addr_str) {
                Ok(_) => {
                    // Another process grabbed the port between the drop
                    // and our connect — try again with a different port.
                    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    let a = l.local_addr().unwrap().to_string();
                    drop(l);
                    continue;
                }
                Err(e) => {
                    last_err = Some(e);
                    break;
                }
            }
        }
        let err = last_err.expect("connect to a definitely-unbound port must fail");
        assert!(
            matches!(err, TransportError::Connect(_, _)),
            "expected TransportError::Connect, got {err:?}"
        );
    }

    /// N2.0.4 (Gate B): a `connect` / `accept` round-trip delivers bytes
    /// in both directions. This is the core TransportProvider contract:
    /// `connect` returns a connection, `accept` returns a connection,
    /// and the two connections are bidirectionally linked.
    #[test]
    fn tcp_transport_provider_connect_accept_round_trip() {
        let provider = Arc::new(TcpTransportProvider::new());
        let mut listener = provider
            .listen("127.0.0.1:0")
            .expect("listen on ephemeral port must succeed");
        let bound_addr = listener.local_addr();

        // Spawn a thread that accepts one connection, reads 4 bytes, and
        // echoes them back uppercase.
        let server_thread = thread::spawn(move || {
            let mut conn = listener.accept().expect("accept must succeed");
            let buf = conn.recv().expect("recv must succeed");
            // Echo uppercase.
            let upper: Vec<u8> = buf.iter().map(|b| b.to_ascii_uppercase()).collect();
            conn.send(&upper).expect("send must succeed");
        });

        // Client connects, sends lowercase, expects uppercase back.
        let mut client = provider.connect(&bound_addr).expect("connect must succeed");
        assert!(client.is_alive());
        client.send(b"ping").expect("send ping");
        let response = client.recv().expect("recv response");
        assert_eq!(response, b"PING");

        server_thread.join().expect("server thread must not panic");
    }

    /// N2.0.4 (Gate B): `TransportProvider` is `Send + Sync` — it can be
    /// shared across threads via `Arc<dyn TransportProvider>`. This is the
    /// shape a long-lived Node would hold.
    #[test]
    fn transport_provider_is_send_sync() {
        let provider: Arc<dyn TransportProvider> = Arc::new(TcpTransportProvider::new());
        // Spawn a thread that uses the provider — this compiles only if
        // `dyn TransportProvider` is `Send + Sync`.
        let p = Arc::clone(&provider);
        let handle = thread::spawn(move || {
            let _listener = p.listen("127.0.0.1:0").expect("listen must succeed");
        });
        handle.join().expect("thread must not panic");
    }

    /// N2.0.4 (Gate B): `close` on a connection marks it not-alive and
    /// subsequent `send`/`recv` return `Err(Closed)`.
    #[test]
    fn transport_connection_close_marks_not_alive() {
        let provider = TcpTransportProvider::new();
        let mut listener = provider.listen("127.0.0.1:0").expect("listen");
        let bound = listener.local_addr();
        let server = thread::spawn(move || {
            let _ = listener.accept();
        });
        let mut conn = provider.connect(&bound).expect("connect");
        assert!(conn.is_alive());
        conn.close();
        assert!(!conn.is_alive());
        let send_result = conn.send(b"x");
        assert!(send_result.is_err(), "send after close must err");
        let recv_result = conn.recv();
        assert!(recv_result.is_err(), "recv after close must err");
        server.join().expect("server thread must not panic");
    }

    /// N2.0.4 (Gate B): `recv` on a connection whose peer has shut down
    /// returns `Err(TransportError::Closed)`. This is how the discovery
    /// client detects that a gateway has gone away mid-handshake.
    #[test]
    fn transport_connection_recv_on_peer_eof_returns_closed() {
        let provider = TcpTransportProvider::new();
        let mut listener = provider.listen("127.0.0.1:0").expect("listen");
        let bound = listener.local_addr();
        let server = thread::spawn(move || {
            let mut conn = listener.accept().expect("accept");
            // Immediately close — no data sent.
            conn.close();
        });
        let mut conn = provider.connect(&bound).expect("connect");
        // The peer closed — recv must return Err(Closed).
        let result = conn.recv();
        assert!(
            matches!(result, Err(TransportError::Closed)),
            "expected Err(Closed) on peer EOF, got {result:?}"
        );
        assert!(!conn.is_alive());
        server.join().expect("server thread must not panic");
    }
}
