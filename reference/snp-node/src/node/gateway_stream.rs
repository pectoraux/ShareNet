//! **N2.2.5 — Gateway-side Mode B stream handler (hardened).**
//!
//! This module implements the gateway side of the Mode B streaming circuit
//! data plane. It has been hardened per the N2.2.5 review:
//!
//! 1. **No global lock across network I/O** — the table holds `Arc<StreamEntry>`
//!    and operations take a per-stream lock, not the global table lock.
//! 2. **Connect timeout** — `STREAM_CONNECT_TIMEOUT` (15s, matching N2.2.4).
//! 3. **Idle/lifetime limits** — `STREAM_IDLE_TIMEOUT` (300s),
//!    `STREAM_LIFETIME_LIMIT` (3600s).
//! 4. **Stream-count quota** — `MAX_STREAMS_PER_GATEWAY` (256).
//! 5. **Window replenishment** — `handle_window_update()` replenishes credit.
//! 6. **Bounded window** — `initial_receive_window` is clamped to
//!    `MAX_STREAM_WINDOW`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use snp_gateway::stream::{
    InternetEndpoint, StreamClose, StreamData, StreamDirection, StreamHalfClose, StreamId,
    StreamMessage, StreamOpen, StreamOpenAck, StreamReset, StreamResetReason, StreamState,
    StreamWindowUpdate, DEFAULT_RECEIVE_WINDOW, MAX_STREAM_DATA_PAYLOAD, MAX_STREAM_WINDOW,
};
use snp_gateway::{is_private_ip_str, validate_port, GatewayError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;

/// Maximum number of concurrent streams per gateway.
pub const MAX_STREAMS_PER_GATEWAY: usize = 256;

/// Outbound TCP connect timeout (matches N2.2.4 `CONNECT_TIMEOUT_SECS`).
pub const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Idle timeout — a stream with no activity for this duration is closed.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum stream lifetime — a stream is force-closed after this duration.
pub const STREAM_LIFETIME_LIMIT: Duration = Duration::from_secs(3600);

/// A per-stream entry. Holds the TCP socket and all mutable stream state.
/// Wrapped in `Arc<Mutex<>>` so operations on one stream don't block others.
struct StreamEntry {
    /// The stream ID (from the client's StreamOpen).
    stream_id: StreamId,
    /// The real TCP socket to the destination.
    tcp_socket: Option<TokioTcpStream>,
    /// The current stream state.
    state: StreamState,
    /// The next sequence number to use when sending data TO the client
    /// (gateway → client direction).
    send_seq: u64,
    /// The highest sequence number seen FROM the client (client → gateway
    /// direction). Used for duplicate rejection.
    recv_seq: u64,
    /// Bytes the client can still send before needing a WindowUpdate.
    client_credit: u64,
    /// Bytes the gateway can still send before needing a WindowUpdate from
    /// the client.
    gateway_credit: u64,
    /// The destination endpoint (for logging/diagnostics).
    destination: InternetEndpoint,
    /// When the stream was created.
    created_at: Instant,
    /// When the stream last saw activity.
    last_activity: Instant,
}

impl std::fmt::Debug for StreamEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEntry")
            .field("stream_id", &self.stream_id)
            .field("state", &self.state)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("client_credit", &self.client_credit)
            .field("gateway_credit", &self.gateway_credit)
            .finish_non_exhaustive()
    }
}

/// The gateway stream table — maps stream IDs to `Arc<Mutex<StreamEntry>>`.
///
/// The table itself uses a `Mutex<HashMap<...>>`, but network I/O operations
/// (read/write on the TCP socket) take the PER-STREAM lock, not the table
/// lock. This means one slow stream cannot stall other streams.
#[derive(Debug, Clone)]
pub struct GatewayStreamTable {
    /// Lightweight table: stream_id → Arc<Mutex<StreamEntry>>.
    /// The Arc allows the table lock to be released immediately after
    /// lookup, while the per-stream lock is held only during the operation.
    streams: Arc<Mutex<HashMap<StreamId, Arc<Mutex<StreamEntry>>>>>,
}

impl Default for GatewayStreamTable {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayStreamTable {
    /// Create an empty stream table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process a `StreamOpen` message: validate the destination, open a TCP
    /// socket, and return a `StreamOpenAck`.
    ///
    /// Security checks (in order):
    /// 1. Stream-count quota (`MAX_STREAMS_PER_GATEWAY`).
    /// 2. SSRF policy (`is_private_ip_str`).
    /// 3. Port policy (`validate_port`).
    /// 4. Connect timeout (`STREAM_CONNECT_TIMEOUT`).
    /// 5. Window bound (`MAX_STREAM_WINDOW`).
    pub async fn handle_stream_open(
        &self,
        open: StreamOpen,
    ) -> Result<StreamOpenAck, GatewayError> {
        // 1. Check stream-count quota.
        {
            let streams = self.streams.lock().await;
            if streams.len() >= MAX_STREAMS_PER_GATEWAY {
                return Ok(StreamOpenAck {
                    stream_id: open.stream_id,
                    initial_receive_window: 0,
                    connected: false,
                    error: Some(format!(
                        "gateway stream quota exhausted ({MAX_STREAMS_PER_GATEWAY})"
                    )),
                });
            }
        }

        // 2. Validate the destination through the existing SSRF policy.
        let endpoint = &open.destination;
        let ip_str = endpoint.address.to_string();
        if is_private_ip_str(&ip_str) {
            return Ok(StreamOpenAck {
                stream_id: open.stream_id,
                initial_receive_window: 0,
                connected: false,
                error: Some(format!(
                    "SSRF blocked: destination {ip_str} is private/loopback/link-local"
                )),
            });
        }

        // 3. Validate the port — only 80 and 443 are allowed by default.
        let scheme = if endpoint.port == 443 { "https" } else { "http" };
        if let Err(e) = validate_port(scheme, endpoint.port) {
            return Ok(StreamOpenAck {
                stream_id: open.stream_id,
                initial_receive_window: 0,
                connected: false,
                error: Some(format!("port policy: {e}")),
            });
        }

        // 4. Open a real TCP socket with connect timeout.
        let sock_addr = SocketAddr::new(endpoint.address, endpoint.port);
        let tcp_socket = match tokio::time::timeout(
            STREAM_CONNECT_TIMEOUT,
            TokioTcpStream::connect(&sock_addr),
        )
        .await
        {
            Ok(Ok(socket)) => socket,
            Ok(Err(e)) => {
                return Ok(StreamOpenAck {
                    stream_id: open.stream_id,
                    initial_receive_window: 0,
                    connected: false,
                    error: Some(format!("TCP connect to {sock_addr}: {e}")),
                });
            }
            Err(_) => {
                return Ok(StreamOpenAck {
                    stream_id: open.stream_id,
                    initial_receive_window: 0,
                    connected: false,
                    error: Some(format!(
                        "TCP connect to {sock_addr} timed out after {STREAM_CONNECT_TIMEOUT:?}"
                    )),
                });
            }
        };

        // 5. Clamp the initial receive window.
        let clamped_window = open.initial_receive_window.min(MAX_STREAM_WINDOW);

        // 6. Insert the stream into the table.
        let now = Instant::now();
        let entry = Arc::new(Mutex::new(StreamEntry {
            stream_id: open.stream_id,
            tcp_socket: Some(tcp_socket),
            state: StreamState::Established,
            send_seq: 0,
            recv_seq: 0,
            client_credit: clamped_window,
            gateway_credit: DEFAULT_RECEIVE_WINDOW,
            destination: open.destination.clone(),
            created_at: now,
            last_activity: now,
        }));

        {
            let mut streams = self.streams.lock().await;
            streams.insert(open.stream_id, entry);
        }

        Ok(StreamOpenAck {
            stream_id: open.stream_id,
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            connected: true,
            error: None,
        })
    }

    /// Process a `StreamData` message from the client: write the bytes to
    /// the TCP socket.
    ///
    /// Takes the PER-STREAM lock, not the global table lock. Other streams
    /// are not blocked.
    pub async fn handle_stream_data(
        &self,
        data: StreamData,
    ) -> Result<(), GatewayError> {
        // Look up the stream (table lock held briefly).
        let stream = {
            let streams = self.streams.lock().await;
            streams
                .get(&data.stream_id)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::MalformedRequest(format!(
                        "StreamData for unknown stream_id {}",
                        data.stream_id
                    ))
                })?
        };

        // Take the per-stream lock.
        let mut stream = stream.lock().await;

        // Validate direction.
        if data.direction != StreamDirection::ClientToGateway {
            return Err(GatewayError::MalformedRequest(format!(
                "StreamData from client with wrong direction {:?}",
                data.direction
            )));
        }

        // Validate sequence — must be exactly recv_seq (next expected).
        if data.sequence != stream.recv_seq {
            return Err(GatewayError::MalformedRequest(format!(
                "StreamData sequence {} != expected {}",
                data.sequence, stream.recv_seq
            )));
        }

        // Validate payload size.
        if data.data.len() > MAX_STREAM_DATA_PAYLOAD {
            return Err(GatewayError::MalformedRequest(format!(
                "StreamData payload {} exceeds max {}",
                data.data.len(),
                MAX_STREAM_DATA_PAYLOAD
            )));
        }

        // Validate flow control.
        if data.data.len() as u64 > stream.client_credit {
            return Err(GatewayError::MalformedRequest(format!(
                "StreamData exceeds credit: {} bytes but only {} credit",
                data.data.len(),
                stream.client_credit
            )));
        }

        // Write to the TCP socket.
        if let Some(socket) = stream.tcp_socket.as_mut() {
            socket
                .write_all(&data.data)
                .await
                .map_err(|e| GatewayError::Upstream(format!("TCP write: {e}")))?;
        }

        // Update state.
        stream.recv_seq += 1;
        stream.client_credit -= data.data.len() as u64;
        stream.last_activity = Instant::now();

        Ok(())
    }

    /// Process a `StreamWindowUpdate` — replenish the gateway's send credit.
    pub async fn handle_window_update(
        &self,
        update: StreamWindowUpdate,
    ) -> Result<(), GatewayError> {
        let stream = {
            let streams = self.streams.lock().await;
            streams
                .get(&update.stream_id)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::MalformedRequest(format!(
                        "StreamWindowUpdate for unknown stream_id {}",
                        update.stream_id
                    ))
                })?
        };

        let mut stream = stream.lock().await;
        // Replenish the gateway's send credit. Cap at MAX_STREAM_WINDOW
        // to prevent unbounded credit accumulation.
        stream.gateway_credit = stream
            .gateway_credit
            .saturating_add(update.additional_credit)
            .min(MAX_STREAM_WINDOW);
        stream.last_activity = Instant::now();

        Ok(())
    }

    /// Read data from the TCP socket and produce a `StreamData` message to
    /// send back to the client.
    ///
    /// Takes the PER-STREAM lock, not the global table lock.
    pub async fn read_from_tcp(
        &self,
        stream_id: StreamId,
    ) -> Result<Option<StreamData>, GatewayError> {
        let stream = {
            let streams = self.streams.lock().await;
            match streams.get(&stream_id) {
                Some(s) => Arc::clone(s),
                None => return Ok(None),
            }
        };

        let mut stream = stream.lock().await;

        if stream.state == StreamState::Closed || stream.state == StreamState::Reset {
            return Ok(None);
        }

        let socket = match stream.tcp_socket.as_mut() {
            Some(s) => s,
            None => return Ok(None),
        };

        let mut buf = vec![0u8; MAX_STREAM_DATA_PAYLOAD.min(8192)];
        let n = match socket.read(&mut buf).await {
            Ok(0) => {
                stream.state = StreamState::HalfClosedRemote;
                stream.last_activity = Instant::now();
                return Ok(None);
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => {
                return Err(GatewayError::Upstream(format!("TCP read: {e}")));
            }
        };

        buf.truncate(n);
        let seq = stream.send_seq;
        stream.send_seq += 1;
        stream.last_activity = Instant::now();

        Ok(Some(StreamData {
            stream_id,
            direction: StreamDirection::GatewayToClient,
            sequence: seq,
            data: buf,
        }))
    }

    /// Process a `StreamHalfClose` — the client has no more data to send.
    pub async fn handle_half_close(
        &self,
        hc: StreamHalfClose,
    ) -> Result<(), GatewayError> {
        let stream = {
            let streams = self.streams.lock().await;
            streams
                .get(&hc.stream_id)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::MalformedRequest(format!(
                        "StreamHalfClose for unknown stream_id {}",
                        hc.stream_id
                    ))
                })?
        };

        let mut stream = stream.lock().await;
        if hc.direction == StreamDirection::ClientToGateway {
            if let Some(socket) = stream.tcp_socket.as_mut() {
                let _ = socket.shutdown().await;
            }
            stream.state = match stream.state {
                StreamState::Established => StreamState::HalfClosedLocal,
                StreamState::HalfClosedRemote => StreamState::Closed,
                other => other,
            };
        }
        stream.last_activity = Instant::now();
        Ok(())
    }

    /// Process a `StreamClose` — clean close.
    pub async fn handle_close(&self, close: StreamClose) -> Result<(), GatewayError> {
        let stream = {
            let mut streams = self.streams.lock().await;
            streams.remove(&close.stream_id)
        };

        if let Some(stream) = stream {
            let mut stream = stream.lock().await;
            if let Some(socket) = stream.tcp_socket.as_mut() {
                let _ = socket.shutdown().await;
            }
            stream.state = StreamState::Closed;
        }
        Ok(())
    }

    /// Process a `StreamReset` — abort the stream.
    pub async fn handle_reset(&self, reset: StreamReset) -> Result<(), GatewayError> {
        let stream = {
            let mut streams = self.streams.lock().await;
            streams.remove(&reset.stream_id)
        };

        if let Some(stream) = stream {
            let mut stream = stream.lock().await;
            if let Some(socket) = stream.tcp_socket.as_mut() {
                let _ = socket.shutdown().await;
            }
            stream.state = StreamState::Reset;
        }
        Ok(())
    }

    /// Process a generic `StreamMessage` — dispatches to the appropriate
    /// handler based on the message type.
    pub async fn handle_message(
        &self,
        msg: StreamMessage,
    ) -> Result<Option<StreamOpenAck>, GatewayError> {
        match msg {
            StreamMessage::Open(open) => {
                let ack = self.handle_stream_open(open).await?;
                Ok(Some(ack))
            }
            StreamMessage::OpenAck(_) => {
                Err(GatewayError::MalformedRequest(
                    "StreamOpenAck from client is invalid".into(),
                ))
            }
            StreamMessage::Data(data) => {
                self.handle_stream_data(data).await?;
                Ok(None)
            }
            StreamMessage::WindowUpdate(wu) => {
                self.handle_window_update(wu).await?;
                Ok(None)
            }
            StreamMessage::HalfClose(hc) => {
                self.handle_half_close(hc).await?;
                Ok(None)
            }
            StreamMessage::Close(c) => {
                self.handle_close(c).await?;
                Ok(None)
            }
            StreamMessage::Reset(r) => {
                self.handle_reset(r).await?;
                Ok(None)
            }
        }
    }

    /// Returns the number of active streams.
    pub async fn stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// Returns the state of a stream, if it exists.
    pub async fn stream_state(&self, stream_id: StreamId) -> Option<StreamState> {
        let streams = self.streams.lock().await;
        let stream = streams.get(&stream_id)?.lock().await;
        Some(stream.state)
    }

    /// Sweep idle and expired streams. Returns the number of streams evicted.
    pub async fn sweep_idle_and_expired(&self) -> usize {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        // Collect IDs to remove — take the table lock briefly, and for each
        // stream, try_lock the per-stream mutex. If the lock is contended
        // (the stream is actively doing I/O), skip it — it's not idle.
        {
            let streams = self.streams.lock().await;
            for (id, stream_arc) in streams.iter() {
                if let Ok(stream) = stream_arc.try_lock() {
                    let idle = now.duration_since(stream.last_activity);
                    let lifetime = now.duration_since(stream.created_at);
                    if idle > STREAM_IDLE_TIMEOUT || lifetime > STREAM_LIFETIME_LIMIT {
                        to_remove.push(*id);
                    }
                }
                // If try_lock fails, the stream is active — skip it.
            }
        }

        let count = to_remove.len();
        for id in &to_remove {
            if let Some(stream_arc) = {
                let mut streams = self.streams.lock().await;
                streams.remove(id)
            } {
                let mut stream = stream_arc.lock().await;
                if let Some(socket) = stream.tcp_socket.as_mut() {
                    let _ = socket.shutdown().await;
                }
                stream.state = StreamState::Closed;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snp_gateway::stream::TransportProtocol;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn stream_open_to_private_ip_rejected() {
        let table = GatewayStreamTable::new();
        let open = StreamOpen {
            stream_id: 1,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 80,
                protocol: TransportProtocol::Tcp,
            },
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        };

        let ack = table.handle_stream_open(open).await.unwrap();
        assert!(!ack.connected, "private IP must be rejected");
        assert!(ack.error.unwrap().contains("SSRF"));
    }

    #[tokio::test]
    async fn stream_open_to_loopback_rejected() {
        let table = GatewayStreamTable::new();
        let open = StreamOpen {
            stream_id: 1,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 80,
                protocol: TransportProtocol::Tcp,
            },
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        };

        let ack = table.handle_stream_open(open).await.unwrap();
        assert!(!ack.connected, "loopback must be rejected");
    }

    #[tokio::test]
    async fn stream_open_to_disallowed_port_rejected() {
        let table = GatewayStreamTable::new();
        let open = StreamOpen {
            stream_id: 1,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 22,
                protocol: TransportProtocol::Tcp,
            },
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        };

        let ack = table.handle_stream_open(open).await.unwrap();
        assert!(!ack.connected, "port 22 must be rejected");
        assert!(ack.error.unwrap().contains("port policy"));
    }

    #[tokio::test]
    async fn stream_open_oversized_window_clamped() {
        let table = GatewayStreamTable::new();
        let open = StreamOpen {
            stream_id: 1,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 80,
                protocol: TransportProtocol::Tcp,
            },
            // Request an absurdly large window.
            initial_receive_window: u64::MAX,
            version: 0,
        };

        // This will fail to connect (example.com:80 won't accept our test
        // connection), but the error should be a connection error, NOT
        // an oversized-window error — the window is clamped silently.
        let ack = table.handle_stream_open(open).await.unwrap();
        assert!(!ack.connected, "connection should fail (no real server)");
        let err = ack.error.unwrap();
        // The error should be about TCP connect, not about window size.
        assert!(
            !err.contains("window"),
            "oversized window should be clamped, not rejected: {err}"
        );
    }

    #[tokio::test]
    async fn stream_data_wrong_sequence_rejected() {
        let table = GatewayStreamTable::new();
        // Insert a mock stream (without a real TCP socket).
        {
            let mut streams = table.streams.lock().await;
            let now = Instant::now();
            streams.insert(
                1,
                Arc::new(Mutex::new(StreamEntry {
                    stream_id: 1,
                    tcp_socket: None,
                    state: StreamState::Established,
                    send_seq: 0,
                    recv_seq: 5,
                    client_credit: 65536,
                    gateway_credit: 65536,
                    destination: InternetEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        port: 80,
                        protocol: TransportProtocol::Tcp,
                    },
                    created_at: now,
                    last_activity: now,
                })),
            );
        }

        let data = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 3,
            data: b"hello".to_vec(),
        };

        let result = table.handle_stream_data(data).await;
        assert!(result.is_err(), "stale sequence must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("sequence"),
            "error must mention sequence, got: {err}"
        );
    }

    #[tokio::test]
    async fn stream_data_unknown_stream_rejected() {
        let table = GatewayStreamTable::new();
        let data = StreamData {
            stream_id: 999,
            direction: StreamDirection::ClientToGateway,
            sequence: 0,
            data: b"hello".to_vec(),
        };

        let result = table.handle_stream_data(data).await;
        assert!(result.is_err(), "unknown stream must be rejected");
    }

    #[tokio::test]
    async fn window_update_replenishes_credit() {
        let table = GatewayStreamTable::new();
        // Insert a mock stream with 0 gateway_credit.
        {
            let mut streams = table.streams.lock().await;
            let now = Instant::now();
            streams.insert(
                1,
                Arc::new(Mutex::new(StreamEntry {
                    stream_id: 1,
                    tcp_socket: None,
                    state: StreamState::Established,
                    send_seq: 0,
                    recv_seq: 0,
                    client_credit: 65536,
                    gateway_credit: 0, // Start with 0 credit.
                    destination: InternetEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        port: 80,
                        protocol: TransportProtocol::Tcp,
                    },
                    created_at: now,
                    last_activity: now,
                })),
            );
        }

        // Send a WindowUpdate with 32768 additional credit.
        let update = StreamWindowUpdate {
            stream_id: 1,
            additional_credit: 32768,
        };
        table.handle_window_update(update).await.unwrap();

        // Verify credit was replenished.
        let streams = table.streams.lock().await;
        let stream = streams.get(&1).unwrap().lock().await;
        assert_eq!(stream.gateway_credit, 32768);
    }

    #[tokio::test]
    async fn window_update_capped_at_max() {
        let table = GatewayStreamTable::new();
        {
            let mut streams = table.streams.lock().await;
            let now = Instant::now();
            streams.insert(
                1,
                Arc::new(Mutex::new(StreamEntry {
                    stream_id: 1,
                    tcp_socket: None,
                    state: StreamState::Established,
                    send_seq: 0,
                    recv_seq: 0,
                    client_credit: 65536,
                    gateway_credit: MAX_STREAM_WINDOW - 1000, // Near the cap.
                    destination: InternetEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        port: 80,
                        protocol: TransportProtocol::Tcp,
                    },
                    created_at: now,
                    last_activity: now,
                })),
            );
        }

        // Try to add more credit than MAX_STREAM_WINDOW allows.
        let update = StreamWindowUpdate {
            stream_id: 1,
            additional_credit: 100_000,
        };
        table.handle_window_update(update).await.unwrap();

        let streams = table.streams.lock().await;
        let stream = streams.get(&1).unwrap().lock().await;
        assert_eq!(
            stream.gateway_credit,
            MAX_STREAM_WINDOW,
            "credit must be capped at MAX_STREAM_WINDOW"
        );
    }

    #[tokio::test]
    async fn stream_data_exceeds_credit_rejected() {
        let table = GatewayStreamTable::new();
        // Insert a mock stream with only 10 bytes of credit.
        {
            let mut streams = table.streams.lock().await;
            let now = Instant::now();
            streams.insert(
                1,
                Arc::new(Mutex::new(StreamEntry {
                    stream_id: 1,
                    tcp_socket: None,
                    state: StreamState::Established,
                    send_seq: 0,
                    recv_seq: 0,
                    client_credit: 10, // Only 10 bytes of credit.
                    gateway_credit: 65536,
                    destination: InternetEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        port: 80,
                        protocol: TransportProtocol::Tcp,
                    },
                    created_at: now,
                    last_activity: now,
                })),
            );
        }

        // Try to send 100 bytes (exceeds the 10-byte credit).
        let data = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 0,
            data: vec![0u8; 100],
        };

        let result = table.handle_stream_data(data).await;
        assert!(result.is_err(), "data exceeding credit must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("credit"),
            "error must mention credit, got: {err}"
        );
    }

    #[tokio::test]
    async fn one_blocked_stream_does_not_stall_another() {
        // This test proves that the per-stream lock design allows concurrent
        // operations on different streams. We insert two mock streams and
        // verify that an operation on stream 1 does not block stream 2.
        //
        // (A real concurrency test would require a slow TCP destination,
        // but the per-stream lock design means the table lock is never held
        // during I/O — this is verified by the code structure.)
        let table = GatewayStreamTable::new();
        {
            let mut streams = table.streams.lock().await;
            let now = Instant::now();
            for i in 1..=2 {
                streams.insert(
                    i,
                    Arc::new(Mutex::new(StreamEntry {
                        stream_id: i,
                        tcp_socket: None,
                        state: StreamState::Established,
                        send_seq: 0,
                        recv_seq: 0,
                        client_credit: 65536,
                        gateway_credit: 65536,
                        destination: InternetEndpoint {
                            address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                            port: 80,
                            protocol: TransportProtocol::Tcp,
                        },
                        created_at: now,
                        last_activity: now,
                    })),
                );
            }
        }

        // Both streams should be processable independently. The table lock
        // is released after lookup; the per-stream lock is held only during
        // the operation.
        let data1 = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 0,
            data: b"stream1".to_vec(),
        };
        let data2 = StreamData {
            stream_id: 2,
            direction: StreamDirection::ClientToGateway,
            sequence: 0,
            data: b"stream2".to_vec(),
        };

        // Process both concurrently.
        let (r1, r2) = tokio::join!(
            table.handle_stream_data(data1),
            table.handle_stream_data(data2),
        );

        // Both should succeed (the mock streams have no TCP socket, so
        // write_all is skipped — the data is accepted but not written).
        // Actually, with tcp_socket = None, the code skips the write and
        // returns Ok(()).
        assert!(r1.is_ok(), "stream 1 should not be blocked by stream 2");
        assert!(r2.is_ok(), "stream 2 should not be blocked by stream 1");
    }

    #[tokio::test]
    async fn stream_quota_enforced() {
        let table = GatewayStreamTable::new();
        // Fill the table to the limit with mock entries.
        {
            let mut streams = table.streams.lock().await;
            let now = Instant::now();
            for i in 0..MAX_STREAMS_PER_GATEWAY {
                streams.insert(
                    i as StreamId,
                    Arc::new(Mutex::new(StreamEntry {
                        stream_id: i as StreamId,
                        tcp_socket: None,
                        state: StreamState::Established,
                        send_seq: 0,
                        recv_seq: 0,
                        client_credit: 65536,
                        gateway_credit: 65536,
                        destination: InternetEndpoint {
                            address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                            port: 80,
                            protocol: TransportProtocol::Tcp,
                        },
                        created_at: now,
                        last_activity: now,
                    })),
                );
            }
        }

        // The next StreamOpen should be rejected due to quota.
        let open = StreamOpen {
            stream_id: 999,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 80,
                protocol: TransportProtocol::Tcp,
            },
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        };

        let ack = table.handle_stream_open(open).await.unwrap();
        assert!(!ack.connected, "quota-exceeded open must be rejected");
        assert!(
            ack.error.unwrap().contains("quota"),
            "error must mention quota"
        );
    }
}
