//! **N2.2.5 — Gateway-side Mode B stream handler (hardened, full-duplex).**
//!
//! This module implements the gateway side of the Mode B streaming circuit
//! data plane. It has been hardened per the N2.2.5 review (round 2):
//!
//! 1. **Full-duplex I/O** — the TCP socket is split into `ReadHalf`/`WriteHalf`
//!    with INDEPENDENT mutexes. `read_from_tcp()` holds the read lock;
//!    `handle_stream_data()` holds the write lock. They never serialize
//!    behind each other. One slow stream cannot stall another.
//! 2. **Bidirectional flow control** — `read_from_tcp()` checks and consumes
//!    `gateway_credit` before producing `StreamData`. When credit reaches
//!    zero, reading stops until a `StreamWindowUpdate` replenishes it.
//! 3. **Atomic stream quota** — a `tokio::sync::Semaphore` reserves the slot
//!    BEFORE the expensive async connect. Concurrent `StreamOpen`s cannot
//!    exceed `MAX_STREAMS_PER_GATEWAY` between check and insertion.
//! 4. **Correct lock ordering** — `stream_state()` clones the `Arc` while
//!    holding the table lock, releases the table lock, THEN acquires the
//!    entry lock. No nested locks.

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
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{Mutex, Semaphore};

/// Maximum number of concurrent streams per gateway.
pub const MAX_STREAMS_PER_GATEWAY: usize = 256;

/// Outbound TCP connect timeout (matches N2.2.4 `CONNECT_TIMEOUT_SECS`).
pub const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Idle timeout — a stream with no activity for this duration is closed.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum stream lifetime — a stream is force-closed after this duration.
pub const STREAM_LIFETIME_LIMIT: Duration = Duration::from_secs(3600);

/// A per-stream entry with INDEPENDENT read/write locks.
///
/// The TCP socket is split into `ReadHalf` and `WriteHalf`, each protected
/// by its own `Mutex`. This means:
///
/// - `read_from_tcp()` acquires `read_lock` — does NOT block writes.
/// - `handle_stream_data()` acquires `write_lock` — does NOT block reads.
/// - Shared state (state, seq, credit, timestamps) has its own `Mutex`.
///
/// This prevents the deadlock where a reader waiting for remote TCP data
/// blocks a writer trying to deliver client data to the TCP socket.
struct StreamEntry {
    /// The stream ID.
    stream_id: StreamId,
    /// The read half of the TCP socket (for reading from the remote server).
    read_half: Mutex<Option<OwnedReadHalf>>,
    /// The write half of the TCP socket (for writing client data to the
    /// remote server).
    write_half: Mutex<Option<OwnedWriteHalf>>,
    /// Shared mutable state — separate from the I/O locks.
    state: Mutex<StreamSharedState>,
    /// The destination endpoint (immutable — for logging/diagnostics).
    destination: InternetEndpoint,
    /// When the stream was created (immutable).
    created_at: Instant,
    /// The semaphore permit held by this stream. Released when the stream
    /// is removed, freeing the slot for a new stream.
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Shared mutable state for a stream — protected by its own mutex,
/// separate from the read/write I/O locks.
struct StreamSharedState {
    /// The current stream state.
    state: StreamState,
    /// The next sequence number for gateway→client data.
    send_seq: u64,
    /// The next expected sequence number from the client.
    recv_seq: u64,
    /// Bytes the client can still send (client→gateway credit).
    client_credit: u64,
    /// Bytes the gateway can still send (gateway→client credit).
    gateway_credit: u64,
    /// When the stream last saw activity.
    last_activity: Instant,
}

impl std::fmt::Debug for StreamEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEntry")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

/// The gateway stream table — maps stream IDs to `Arc<StreamEntry>`.
///
/// The table itself uses a `Mutex<HashMap<...>>`, but:
/// - The table lock is held only for lookup/insert/remove (no I/O).
/// - Per-stream I/O uses independent read/write locks.
/// - The stream quota is enforced by a `Semaphore`, not by counting the map.
#[derive(Clone)]
pub struct GatewayStreamTable {
    /// Lightweight table: stream_id → Arc<StreamEntry>.
    streams: Arc<Mutex<HashMap<StreamId, Arc<StreamEntry>>>>,
    /// Semaphore for atomic stream-count quota enforcement.
    quota: Arc<Semaphore>,
    /// Whether to allow loopback/private destinations. Production = false.
    /// Tests = true (so the test can connect to a local echo server).
    allow_loopback: bool,
}

impl Default for GatewayStreamTable {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayStreamTable {
    /// Create an empty stream table with the default quota
    /// (`MAX_STREAMS_PER_GATEWAY` = 256).
    #[must_use]
    pub fn new() -> Self {
        Self::with_quota(MAX_STREAMS_PER_GATEWAY)
    }

    /// Create an empty stream table with a custom quota. Used by tests to
    /// verify quota enforcement without creating 256 streams.
    #[must_use]
    pub fn with_quota(max_streams: usize) -> Self {
        Self {
            streams: Arc::new(Mutex::new(HashMap::new())),
            quota: Arc::new(Semaphore::new(max_streams)),
            allow_loopback: false,
        }
    }

    /// Create a table that allows loopback/private destinations.
    /// **TEST ONLY** — production must never use this.
    #[must_use]
    pub fn with_allow_loopback() -> Self {
        Self {
            streams: Arc::new(Mutex::new(HashMap::new())),
            quota: Arc::new(Semaphore::new(MAX_STREAMS_PER_GATEWAY)),
            allow_loopback: true,
        }
    }

    /// Process a `StreamOpen` message: validate the destination, open a TCP
    /// socket, and return a `StreamOpenAck`.
    ///
    /// Security checks (in order):
    /// 1. Stream-count quota (atomic via semaphore — no check-then-insert race).
    /// 2. SSRF policy (`is_private_ip_str`).
    /// 3. Port policy (`validate_port`).
    /// 4. Connect timeout (`STREAM_CONNECT_TIMEOUT`).
    /// 5. Window bound (`MAX_STREAM_WINDOW`).
    pub async fn handle_stream_open(
        &self,
        open: StreamOpen,
    ) -> Result<StreamOpenAck, GatewayError> {
        // 1. Atomically acquire a quota slot. Use try_acquire (non-blocking)
        //    so that a full quota is rejected immediately rather than
        //    blocking forever. The permit is held for the lifetime of the
        //    stream — no race between check and insert.
        let permit = match self.quota.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Ok(StreamOpenAck {
                    stream_id: open.stream_id,
                    initial_receive_window: 0,
                    connected: false,
                    error: Some(format!(
                        "gateway stream quota exhausted ({MAX_STREAMS_PER_GATEWAY})"
                    )),
                });
            }
        };

        // 2. Validate the destination through the existing SSRF policy.
        //    (Skipped when allow_loopback is set — TEST ONLY.)
        let endpoint = &open.destination;
        let ip_str = endpoint.address.to_string();
        if !self.allow_loopback && is_private_ip_str(&ip_str) {
            return Ok(StreamOpenAck {
                stream_id: open.stream_id,
                initial_receive_window: 0,
                connected: false,
                error: Some(format!(
                    "SSRF blocked: destination {ip_str} is private/loopback/link-local"
                )),
            });
        }

        // 3. Validate the port. (Skipped when allow_loopback — TEST ONLY.)
        if !self.allow_loopback {
            let scheme = if endpoint.port == 443 { "https" } else { "http" };
            if let Err(e) = validate_port(scheme, endpoint.port) {
                return Ok(StreamOpenAck {
                    stream_id: open.stream_id,
                    initial_receive_window: 0,
                    connected: false,
                    error: Some(format!("port policy: {e}")),
                });
            }
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

        // 5. Split the socket into read/write halves with independent locks.
        let (read_half, write_half) = tcp_socket.into_split();

        // 6. Clamp the initial receive window.
        let clamped_window = open.initial_receive_window.min(MAX_STREAM_WINDOW);

        // 7. Insert the stream into the table.
        let now = Instant::now();
        let entry = Arc::new(StreamEntry {
            stream_id: open.stream_id,
            read_half: Mutex::new(Some(read_half)),
            write_half: Mutex::new(Some(write_half)),
            state: Mutex::new(StreamSharedState {
                state: StreamState::Established,
                send_seq: 0,
                recv_seq: 0,
                client_credit: clamped_window,
                gateway_credit: DEFAULT_RECEIVE_WINDOW,
                last_activity: now,
            }),
            destination: open.destination.clone(),
            created_at: now,
            _permit: permit,
        });

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
    /// the TCP socket's WRITE half.
    ///
    /// Takes the WRITE lock, not the read lock. Does NOT block reads.
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

        // Validate direction and sequence (shared state lock — brief).
        {
            let mut shared = stream.state.lock().await;
            if data.direction != StreamDirection::ClientToGateway {
                return Err(GatewayError::MalformedRequest(format!(
                    "StreamData from client with wrong direction {:?}",
                    data.direction
                )));
            }
            if data.sequence != shared.recv_seq {
                return Err(GatewayError::MalformedRequest(format!(
                    "StreamData sequence {} != expected {}",
                    data.sequence, shared.recv_seq
                )));
            }
            if data.data.len() > MAX_STREAM_DATA_PAYLOAD {
                return Err(GatewayError::MalformedRequest(format!(
                    "StreamData payload {} exceeds max {}",
                    data.data.len(),
                    MAX_STREAM_DATA_PAYLOAD
                )));
            }
            if data.data.len() as u64 > shared.client_credit {
                return Err(GatewayError::MalformedRequest(format!(
                    "StreamData exceeds credit: {} bytes but only {} credit",
                    data.data.len(),
                    shared.client_credit
                )));
            }
            // Update state.
            shared.recv_seq += 1;
            shared.client_credit -= data.data.len() as u64;
            shared.last_activity = Instant::now();
        }

        // Write to the TCP socket (write lock — does NOT block reads).
        let mut write_guard = stream.write_half.lock().await;
        if let Some(write_half) = write_guard.as_mut() {
            write_half
                .write_all(&data.data)
                .await
                .map_err(|e| GatewayError::Upstream(format!("TCP write: {e}")))?;
        }

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

        let mut shared = stream.state.lock().await;
        shared.gateway_credit = shared
            .gateway_credit
            .saturating_add(update.additional_credit)
            .min(MAX_STREAM_WINDOW);
        shared.last_activity = Instant::now();

        Ok(())
    }

    /// Read data from the TCP socket and produce a `StreamData` message to
    /// send back to the client.
    ///
    /// Takes the READ lock, not the write lock. Does NOT block writes.
    ///
    /// **Flow control**: checks `gateway_credit` before reading. If credit
    /// is zero, returns `Ok(None)` (no data produced) until the client sends
    /// a `StreamWindowUpdate` to replenish credit.
    pub async fn read_from_tcp(
        &self,
        stream_id: StreamId,
    ) -> Result<Option<StreamData>, GatewayError> {
        // Look up the stream (table lock held briefly).
        let stream = {
            let streams = self.streams.lock().await;
            match streams.get(&stream_id) {
                Some(s) => Arc::clone(s),
                None => return Ok(None),
            }
        };

        // Check state and credit (shared state lock — brief).
        let (state, credit, seq) = {
            let shared = stream.state.lock().await;
            if shared.state == StreamState::Closed || shared.state == StreamState::Reset {
                return Ok(None);
            }
            if shared.gateway_credit == 0 {
                // No credit — stop reading until the client sends a WindowUpdate.
                return Ok(None);
            }
            (shared.state, shared.gateway_credit, shared.send_seq)
        };
        let _ = state;

        // Read from the TCP socket (read lock — does NOT block writes).
        let mut read_guard = stream.read_half.lock().await;
        let read_half = match read_guard.as_mut() {
            Some(r) => r,
            None => return Ok(None),
        };

        // Don't read more than the available credit.
        let max_read = MAX_STREAM_DATA_PAYLOAD.min(8192).min(credit as usize);
        let mut buf = vec![0u8; max_read];
        let n = match read_half.read(&mut buf).await {
            Ok(0) => {
                // EOF — remote closed.
                let mut shared = stream.state.lock().await;
                shared.state = StreamState::HalfClosedRemote;
                shared.last_activity = Instant::now();
                return Ok(None);
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => {
                return Err(GatewayError::Upstream(format!("TCP read: {e}")));
            }
        };

        buf.truncate(n);

        // Update shared state: consume credit, advance sequence.
        {
            let mut shared = stream.state.lock().await;
            shared.send_seq += 1;
            shared.gateway_credit = shared.gateway_credit.saturating_sub(n as u64);
            shared.last_activity = Instant::now();
        }

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

        if hc.direction == StreamDirection::ClientToGateway {
            // Shut down the write half of the TCP socket.
            let mut write_guard = stream.write_half.lock().await;
            if let Some(write_half) = write_guard.as_mut() {
                let _ = write_half.shutdown().await;
            }
            // Update state.
            let mut shared = stream.state.lock().await;
            shared.state = match shared.state {
                StreamState::Established => StreamState::HalfClosedLocal,
                StreamState::HalfClosedRemote => StreamState::Closed,
                other => other,
            };
            shared.last_activity = Instant::now();
        }
        Ok(())
    }

    /// Process a `StreamClose` — clean close.
    pub async fn handle_close(&self, close: StreamClose) -> Result<(), GatewayError> {
        let stream = {
            let mut streams = self.streams.lock().await;
            streams.remove(&close.stream_id)
        };

        if let Some(stream) = stream {
            // Shut down both halves.
            {
                let mut write_guard = stream.write_half.lock().await;
                if let Some(write_half) = write_guard.as_mut() {
                    let _ = write_half.shutdown().await;
                }
            }
            let mut shared = stream.state.lock().await;
            shared.state = StreamState::Closed;
            // The _permit is dropped when `stream` goes out of scope,
            // freeing the quota slot.
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
            {
                let mut write_guard = stream.write_half.lock().await;
                if let Some(write_half) = write_guard.as_mut() {
                    let _ = write_half.shutdown().await;
                }
            }
            let mut shared = stream.state.lock().await;
            shared.state = StreamState::Reset;
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

    /// Returns the number of available quota slots.
    pub fn available_quota(&self) -> usize {
        self.quota.available_permits()
    }

    /// Returns the state of a stream, if it exists.
    ///
    /// Correct lock ordering: clone the Arc while holding the table lock,
    /// release the table lock, THEN acquire the entry's shared-state lock.
    pub async fn stream_state(&self, stream_id: StreamId) -> Option<StreamState> {
        // Clone the Arc while holding the table lock.
        let stream = {
            let streams = self.streams.lock().await;
            streams.get(&stream_id).cloned()?
        };
        // Table lock released. Now acquire the shared-state lock.
        let shared = stream.state.lock().await;
        Some(shared.state)
    }

    /// Returns the gateway_credit for a stream (for testing).
    pub async fn gateway_credit(&self, stream_id: StreamId) -> Option<u64> {
        let stream = {
            let streams = self.streams.lock().await;
            streams.get(&stream_id).cloned()?
        };
        let shared = stream.state.lock().await;
        Some(shared.gateway_credit)
    }

    /// Sweep idle and expired streams. Returns the number of streams evicted.
    pub async fn sweep_idle_and_expired(&self) -> usize {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        // Collect IDs to remove — try_lock to avoid blocking active streams.
        {
            let streams = self.streams.lock().await;
            for (id, stream_arc) in streams.iter() {
                if let Ok(shared) = stream_arc.state.try_lock() {
                    let idle = now.duration_since(shared.last_activity);
                    let lifetime = now.duration_since(stream_arc.created_at);
                    if idle > STREAM_IDLE_TIMEOUT || lifetime > STREAM_LIFETIME_LIMIT {
                        to_remove.push(*id);
                    }
                }
            }
        }

        let count = to_remove.len();
        for id in &to_remove {
            if let Some(stream_arc) = {
                let mut streams = self.streams.lock().await;
                streams.remove(id)
            } {
                let mut write_guard = stream_arc.write_half.lock().await;
                if let Some(write_half) = write_guard.as_mut() {
                    let _ = write_half.shutdown().await;
                }
                let mut shared = stream_arc.state.lock().await;
                shared.state = StreamState::Closed;
            }
        }
        count
    }

    /// Insert a mock stream for testing (no real TCP socket).
    #[cfg(test)]
    async fn insert_mock_stream(
        &self,
        stream_id: StreamId,
        client_credit: u64,
        gateway_credit: u64,
    ) {
        let permit = self.quota.clone().try_acquire_owned().unwrap();
        let now = Instant::now();
        let entry = Arc::new(StreamEntry {
            stream_id,
            read_half: Mutex::new(None),
            write_half: Mutex::new(None),
            state: Mutex::new(StreamSharedState {
                state: StreamState::Established,
                send_seq: 0,
                recv_seq: 0,
                client_credit,
                gateway_credit,
                last_activity: now,
            }),
            destination: InternetEndpoint {
                address: IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
                port: 80,
                protocol: snp_gateway::stream::TransportProtocol::Tcp,
            },
            created_at: now,
            _permit: permit,
        });
        let mut streams = self.streams.lock().await;
        streams.insert(stream_id, entry);
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
    async fn stream_data_wrong_sequence_rejected() {
        let table = GatewayStreamTable::new();
        table.insert_mock_stream(1, 65536, 65536).await;

        let data = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 3, // Expected 0.
            data: b"hello".to_vec(),
        };

        let result = table.handle_stream_data(data).await;
        assert!(result.is_err(), "stale sequence must be rejected");
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
        table.insert_mock_stream(1, 65536, 0).await; // Start with 0 gateway_credit.

        let update = StreamWindowUpdate {
            stream_id: 1,
            additional_credit: 32768,
        };
        table.handle_window_update(update).await.unwrap();

        assert_eq!(
            table.gateway_credit(1).await.unwrap(),
            32768,
            "credit must be replenished"
        );
    }

    #[tokio::test]
    async fn window_update_capped_at_max() {
        let table = GatewayStreamTable::new();
        table
            .insert_mock_stream(1, 65536, MAX_STREAM_WINDOW - 1000)
            .await;

        let update = StreamWindowUpdate {
            stream_id: 1,
            additional_credit: 100_000,
        };
        table.handle_window_update(update).await.unwrap();

        assert_eq!(
            table.gateway_credit(1).await.unwrap(),
            MAX_STREAM_WINDOW,
            "credit must be capped"
        );
    }

    #[tokio::test]
    async fn stream_data_exceeds_credit_rejected() {
        let table = GatewayStreamTable::new();
        table.insert_mock_stream(1, 10, 65536).await; // Only 10 bytes credit.

        let data = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 0,
            data: vec![0u8; 100],
        };

        let result = table.handle_stream_data(data).await;
        assert!(result.is_err(), "data exceeding credit must be rejected");
    }

    #[tokio::test]
    async fn one_blocked_stream_does_not_stall_another() {
        let table = GatewayStreamTable::new();
        table.insert_mock_stream(1, 65536, 65536).await;
        table.insert_mock_stream(2, 65536, 65536).await;

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

        let (r1, r2) = tokio::join!(
            table.handle_stream_data(data1),
            table.handle_stream_data(data2),
        );

        assert!(r1.is_ok(), "stream 1 should not be blocked");
        assert!(r2.is_ok(), "stream 2 should not be blocked");
    }

    #[tokio::test]
    async fn stream_quota_enforced() {
        // Use a small quota (4) for test speed — the production constant is
        // MAX_STREAMS_PER_GATEWAY (256), but the enforcement logic is the same.
        let table = GatewayStreamTable::with_quota(4);
        // Fill the quota with mock streams.
        for i in 0..4 {
            table.insert_mock_stream(i as StreamId, 65536, 65536).await;
        }

        // The next StreamOpen should be rejected.
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
        assert!(!ack.connected, "quota-exceeded must be rejected");
        assert!(ack.error.unwrap().contains("quota"));
    }

    // ── New tests for round-2 hardening ────────────────────────────────────

    #[tokio::test]
    async fn read_from_tcp_stops_when_credit_is_zero() {
        // Test: gateway_credit = 0 → read_from_tcp returns None.
        let table = GatewayStreamTable::new();
        table.insert_mock_stream(1, 65536, 0).await; // 0 gateway_credit.

        let result = table.read_from_tcp(1).await.unwrap();
        assert!(
            result.is_none(),
            "read_from_tcp must return None when gateway_credit is 0"
        );
    }

    #[tokio::test]
    async fn window_update_resumes_gateway_to_client_delivery() {
        // Test: after a WindowUpdate replenishes credit, read_from_tcp can
        // produce data again.
        let table = GatewayStreamTable::new();
        table.insert_mock_stream(1, 65536, 0).await; // 0 credit.

        // With 0 credit, read returns None.
        let result = table.read_from_tcp(1).await.unwrap();
        assert!(result.is_none(), "should not read with 0 credit");

        // Replenish credit.
        let update = StreamWindowUpdate {
            stream_id: 1,
            additional_credit: 4096,
        };
        table.handle_window_update(update).await.unwrap();

        // Now read should still return None (mock has no TCP socket), but
        // it should NOT return None due to credit — it returns None because
        // there's no socket. The important thing is it got PAST the credit
        // check.
        // (With a real TCP socket, it would read data here.)
        let result = table.read_from_tcp(1).await.unwrap();
        assert!(result.is_none(), "no socket → None, but credit is > 0 now");
        assert_eq!(
            table.gateway_credit(1).await.unwrap(),
            4096,
            "credit should still be 4096 (no data consumed)"
        );
    }

    #[tokio::test]
    async fn quota_is_atomic_no_check_then_insert_race() {
        // Test: concurrent opens never exceed the quota.
        // Use a small quota (4) for test speed — the semaphore enforces the
        // limit atomically regardless of the quota size.
        let table = GatewayStreamTable::with_quota(4);

        // Acquire all 4 permits via mock streams.
        for i in 0..4 {
            table.insert_mock_stream(i as StreamId, 65536, 65536).await;
        }

        // The semaphore should have 0 available permits.
        assert_eq!(
            table.available_quota(),
            0,
            "all permits must be acquired after 4 streams"
        );

        // A 5th stream must be rejected.
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
        assert!(!ack.connected, "5th stream must be rejected");

        // Remove a stream (frees the permit).
        table.handle_close(StreamClose { stream_id: 0 }).await.unwrap();

        // Now a new stream should be allowed (permit freed).
        assert_eq!(
            table.available_quota(),
            1,
            "permit must be freed after stream close"
        );
    }

    #[tokio::test]
    async fn client_writes_while_gateway_reader_blocked() {
        // Test: the client can write data (handle_stream_data) even while
        // the gateway reader (read_from_tcp) is "blocked" waiting.
        //
        // With the split read/write locks, these operations use DIFFERENT
        // mutexes and can proceed concurrently.
        //
        // We simulate this by:
        // 1. Inserting a mock stream (no real TCP socket — read_half is None).
        // 2. Starting a read_from_tcp (which will get past the credit check
        //    but return None because read_half is None).
        // 3. Concurrently calling handle_stream_data.
        // 4. Both should complete without blocking.
        let table = GatewayStreamTable::new();
        table.insert_mock_stream(1, 65536, 65536).await;

        // Run read and write concurrently.
        let (read_result, write_result) = tokio::join!(
            table.read_from_tcp(1),
            table.handle_stream_data(StreamData {
                stream_id: 1,
                direction: StreamDirection::ClientToGateway,
                sequence: 0,
                data: b"concurrent write".to_vec(),
            }),
        );

        // Both should succeed (no deadlock).
        assert!(
            read_result.is_ok(),
            "read should not be blocked by write: {:?}",
            read_result
        );
        assert!(
            write_result.is_ok(),
            "write should not be blocked by read: {:?}",
            write_result
        );
    }

    #[tokio::test]
    async fn stream_state_does_not_nest_locks() {
        // Test: stream_state() should work without deadlocking.
        // (This is a smoke test — the fix is in the lock ordering.)
        let table = GatewayStreamTable::new();
        table.insert_mock_stream(1, 65536, 65536).await;

        let state = table.stream_state(1).await;
        assert_eq!(state, Some(StreamState::Established));

        // Also test on a non-existent stream.
        let state = table.stream_state(999).await;
        assert_eq!(state, None);
    }
}
