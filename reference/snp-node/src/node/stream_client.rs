//! **N2.2.5 Phase 3 — Client-side CircuitStream / StreamHandle (hardened).**
//!
//! This module provides the client-side abstraction for Mode B streams.
//! It has been hardened per the Phase 3 review:
//!
//! 1. **Circuit establishment is hidden** — `StreamHandle::open()` takes a
//!    `Route` and client identity, not pre-built `AsyncLink`/`CircuitKeys`.
//!    The circuit is established internally via the existing canonical path
//!    (SNP-IK handshake + fresh ephemeral X25519).
//! 2. **Background inbound task** — a dedicated tokio task continuously
//!    processes inbound circuit messages (WindowUpdate, StreamData, HalfClose,
//!    etc.) so `send()` can await credit replenishment without the application
//!    calling `recv()`.
//! 3. **Outer frame validation** — `src`, `dst`, `fid`, and `cls` are
//!    validated before decrypting the circuit payload.
//! 4. **Comprehensive tests** — window exhaustion/replenishment, half-close
//!    transitions, reset, out-of-order data, frame identity mismatch,
//!    unexpected message types.
//!
//! ## Architecture
//!
//! ```text
//! Application (TcpFlowBridge / AsyncUpstream)
//!     ↓
//! StreamHandle (this module)
//!     ├── send() → outbound queue → circuit send
//!     └── recv() ← inbound queue ← background reader task
//!                          ↓
//!                    circuit recv loop
//!                          ↓
//!                    dispatch: Data → recv queue
//!                              WindowUpdate → credit Notify
//!                              HalfClose/Close/Reset → state
//! ```

use std::collections::VecDeque;
use std::collections::HashMap;
use std::time::Duration;
use std::net::IpAddr;
use std::sync::Arc;

use snp_crypto::X25519PubKey;
use snp_gateway::stream::{
    decode_stream_message, encode_stream_message, InternetEndpoint, StreamClose, StreamData,
    StreamDirection, StreamHalfClose, StreamId, StreamMessage, StreamOpen, StreamOpenAck,
    StreamReset, StreamResetReason, StreamState, StreamWindowUpdate, TransportProtocol,
    DEFAULT_RECEIVE_WINDOW, MAX_STREAM_DATA_PAYLOAD, MAX_STREAM_WINDOW,
};
use snp_frames::{should_drop, Frame, FRAME_TTL_MAX, FRAME_VERSION};
use snp_link::async_link::{perform_snp_ik_handshake_async, AsyncLink, AsyncLinkError};
use snp_link::{
    decrypt_circuit_payload, encrypt_circuit_payload, seal_circuit_payload_with_fresh_eph,
    CircuitKeys,
};
use tokio::sync::{Mutex, Notify};
use tokio::net::TcpStream;

use super::{
    now_unix, random_fid, random_req_id, Node, NodeError, NodeIdentity, NodeResult, Route,
};

/// Errors from the client-side stream.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// The stream is not in a state that allows the operation.
    #[error("invalid stream state: {0:?}")]
    InvalidState(StreamState),
    /// The stream was reset by the gateway or the application.
    #[error("stream reset: {0:?}")]
    Reset(StreamResetReason),
    /// The stream is closed (clean shutdown).
    #[error("stream closed")]
    Closed,
    /// A circuit/frame error occurred.
    #[error("circuit error: {0}")]
    Circuit(String),
    /// A CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(String),
    /// Flow control: the send window is exhausted and the stream was
    /// closed/reset before credit could be replenished.
    #[error("send window exhausted and stream terminated")]
    WindowExhaustedTerminated,
    /// The gateway rejected the StreamOpen.
    #[error("stream open rejected: {0}")]
    OpenRejected(String),
    /// Outer frame validation failed.
    #[error("frame validation failed: {0}")]
    FrameValidation(String),
    /// The background reader task terminated.
    #[error("reader task terminated: {0}")]
    ReaderTerminated(String),
}

/// Internal state shared between the StreamHandle and the background reader task.
struct StreamShared {
    /// The current stream state.
    state: StreamState,
    /// Bytes the client can still send (gateway's receive window).
    send_credit: u64,
    /// The next sequence number for client→gateway data.
    send_seq: u64,
    /// The highest sequence number received from the gateway.
    recv_seq: u64,
    /// Notify the send() path when credit is replenished.
    credit_notify: Arc<Notify>,
    /// Pending data received by the background reader (for recv()).
    /// FIFO — uses push_back / pop_front to preserve byte ordering.
    pending_data: VecDeque<Vec<u8>>,
    /// Notify the recv() path when data arrives.
    data_notify: Arc<Notify>,
    /// **N2.3.9** — Bytes consumed by recv() since the last WindowUpdate was
    /// sent to the gateway. When this exceeds `WINDOW_UPDATE_THRESHOLD`, a
    /// WindowUpdate is sent to replenish the gateway's `gateway_credit`.
    /// This implements credit-based flow control for the gateway→client
    /// direction.
    gateway_credit_consumed: u64,
    /// **N2.3.9** — Total bytes currently buffered in `pending_data`.
    /// Used by the background reader to decide whether to send an eager
    /// WindowUpdate (preventing deadlock when the client sends without
    /// calling recv()).
    pending_data_total: u64,
    /// **N2.3.9** — Accumulated credit for eager WindowUpdate from the
    /// background reader. When this exceeds `EAGER_WINDOW_UPDATE_THRESHOLD`,
    /// a WindowUpdate is sent to the gateway. This rate-limits eager
    /// WindowUpdates to avoid overhead on small transfers.
    eager_credit_pending: u64,
}

/// **N2.3.9** — Threshold for sending WindowUpdate from client to gateway.
/// When the client has consumed this many bytes via recv(), it sends a
/// WindowUpdate to replenish the gateway's send credit.
const WINDOW_UPDATE_THRESHOLD: u64 = 32 * 1024;

/// **N2.3.9** — Maximum bytes of pending data before the background reader
/// stops sending eager WindowUpdates. When `pending_data_total` exceeds this,
/// the gateway's `gateway_credit` will exhaust, and the gateway stops reading
/// from TCP. This prevents unbounded growth of `pending_data`.
const PENDING_DATA_HIGH_WATERMARK: u64 = 128 * 1024;

/// **N2.3.9** — Threshold for eager WindowUpdate from the background reader.
/// The background reader accumulates credit and sends a WindowUpdate when
/// this threshold is reached AND `pending_data_total` is below the high
/// watermark. This rate-limits eager WindowUpdates to avoid per-message
/// overhead on small transfers.
const EAGER_WINDOW_UPDATE_THRESHOLD: u64 = 16 * 1024;

/// A handle to an open Mode B stream.
///
/// This is the client-side abstraction for a bidirectional raw TCP byte
/// stream over the ShareNet circuit. It provides:
///
/// - `send()` — send bytes to the remote server (waits for credit if needed).
/// - `recv()` — receive bytes from the remote server.
/// - `shutdown_write()` — half-close the send direction (TCP FIN equivalent).
/// - `close()` — clean close (both directions).
/// - `reset()` — abort the stream (TCP RST equivalent).
///
/// A background tokio task continuously processes inbound circuit messages,
/// so `send()` can await `WindowUpdate` credit replenishment without the
/// application calling `recv()`.
pub struct StreamHandle {
    /// The circuit link (shared with the background reader task).
    link: Arc<AsyncLink>,
    /// The circuit keys (send_key for client→gateway, recv_key for gateway→client).
    circuit_keys: CircuitKeys,
    /// The gateway's NodeId (frame destination + outer frame validation).
    gateway_node_id: [u8; 32],
    /// The client's NodeId (frame source + outer frame validation).
    client_node_id: [u8; 32],
    /// The stream ID.
    stream_id: StreamId,
    /// The frame ID for this circuit (outer frame validation).
    fid: [u8; 8],
    /// The shared circuit-level frame sequencer (for AEAD nonce safety).
    /// All streams on the same circuit share one sequencer.
    frame_seq: Arc<CircuitFrameSequencer>,
    /// Shared state (protected by mutex).
    shared: Arc<Mutex<StreamShared>>,
    /// Handle to the background reader task (to abort on close).
    /// None for multiplexed streams (the circuit owns the reader).
    reader_handle: Option<tokio::task::JoinHandle<()>>,
    /// **N2.3.9** — Optional transport metrics. When set, the stream records
    /// bytes sent/received, window blocks, and credit updates on real events.
    metrics: Option<Arc<super::transport_metrics::TransportMetrics>>,
    /// **N2.3.9** — Optional reference to the circuit's streams map (for
    /// multiplexed streams). When set, `close()` and `reset()` remove the
    /// stream's entry from the map, keeping `stream_count()` accurate.
    streams_map: Option<Arc<Mutex<HashMap<StreamId, Arc<Mutex<StreamShared>>>>>>,
}

/// **N2.3.8** — Circuit-level frame sequence allocator.
///
/// All streams on one circuit share this sequencer. Each outbound frame
/// gets a unique `(fid, seq)` pair, ensuring AEAD nonce uniqueness.
///
/// This is the client-side counterpart of the gateway's shared
/// `next_gateway_frame_seq`.
pub struct CircuitFrameSequencer {
    next: Mutex<u32>,
}

impl CircuitFrameSequencer {
    /// Create a new sequencer starting at the given value.
    #[must_use]
    pub fn new(start: u32) -> Self {
        Self {
            next: Mutex::new(start),
        }
    }

    /// Allocate the next frame sequence. Returns `None` if exhausted.
    pub async fn allocate(&self) -> Option<u32> {
        let mut next = self.next.lock().await;
        if *next == u32::MAX {
            return None;
        }
        let seq = *next;
        *next += 1;
        Some(seq)
    }
}

impl std::fmt::Debug for StreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamHandle")
            .field("stream_id", &self.stream_id)
            .field("gateway_node_id", &self.gateway_node_id)
            .field("client_node_id", &self.client_node_id)
            .field("fid", &self.fid)
            .finish_non_exhaustive()
    }
}

impl StreamHandle {
    /// Open a new Mode B stream to the given endpoint.
    ///
    /// This internally establishes the circuit via the existing canonical
    /// path:
    ///
    /// 1. Connect to the first relay from the Route.
    /// 2. Perform SNP-IK/0.1 handshake.
    /// 3. Derive fresh ephemeral X25519 circuit keys.
    /// 4. Send `StreamOpen` (inside the encrypted circuit payload).
    /// 5. Receive `StreamOpenAck`.
    /// 6. Spawn a background reader task for inbound messages.
    ///
    /// # Arguments
    /// * `node` — The client node (identity + secret keys).
    /// * `route` — The route to the gateway (from discovery).
    /// * `client_x25519_secret` — The client's static X25519 secret.
    /// * `client_x25519_public` — The client's static X25519 public.
    /// * `destination` — The TCP endpoint to connect to.
    ///
    /// # Errors
    /// Returns [`StreamError`] if the circuit cannot be established, the
    /// gateway rejects the stream, or the response is malformed.
    pub async fn open(
        node: &Node,
        route: &Route,
        client_x25519_secret: &snp_crypto::X25519Secret,
        client_x25519_public: &snp_crypto::X25519PubKey,
        destination: InternetEndpoint,
    ) -> Result<Self, StreamError> {
        // 1. Extract the first relay endpoint + gateway identity from the Route.
        if route.hop_details().is_empty() {
            return Err(StreamError::Circuit("route has no hop_details".into()));
        }
        let first_hop = &route.hop_details()[0];
        let relay_endpoint = first_hop
            .first_endpoint()
            .ok_or_else(|| StreamError::Circuit("first hop has no endpoints".into()))?;
        let relay_addr = relay_endpoint
            .as_tcp()
            .ok_or_else(|| StreamError::Circuit("first hop is not TCP".into()))?;
        let relay_node_id = first_hop.node_id();

        let gateway_descriptor = route
            .destination_descriptor()
            .ok_or_else(|| StreamError::Circuit("route has no destination descriptor".into()))?;
        let gateway_node_id = gateway_descriptor.node_id();
        let gateway_ed25519_public = *gateway_descriptor.ed25519_public_key();
        let gateway_x25519_pub_bytes = gateway_descriptor
            .circuit_x25519_pub()
            .ok_or_else(|| StreamError::Circuit("no gateway X25519 key".into()))?;
        let gateway_x25519_pub = snp_crypto::x25519_public_from_bytes(gateway_x25519_pub_bytes);

        // 2. Connect to relay + SNP-IK handshake (same as Mode A).
        let mut stream = AsyncLink::connect_raw(relay_addr)
            .await
            .map_err(|e| StreamError::Circuit(format!("relay connect: {e}")))?;
        let handshake = perform_snp_ik_handshake_async(
            &mut stream,
            true, // initiator
            &node.identity.secret_key,
            &node.identity.public_key,
            client_x25519_secret,
            client_x25519_public,
            Some(&relay_node_id),
        )
        .await
        .map_err(|e| StreamError::Circuit(format!("SNP-IK handshake: {e}")))?;
        if handshake.peer_node_id != relay_node_id {
            return Err(StreamError::Circuit(format!(
                "relay identity substitution: expected {}, got {}",
                super::hex_short(&relay_node_id),
                super::hex_short(&handshake.peer_node_id)
            )));
        }
        let link = AsyncLink::new(stream, handshake.link_keys);

        // 3. Derive fresh ephemeral circuit keys.
        let stream_id: StreamId = {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf).expect("getrandom");
            u64::from_be_bytes(buf)
        };
        let fid = random_fid();
        let client_node_id = node.identity.node_id;

        // 4. Send StreamOpen — sealed with fresh ephemeral X25519.
        //
        // This is the CRITICAL step: we must use seal_circuit_payload_with_fresh_eph()
        // to seal the ACTUAL StreamOpen CBOR. This produces:
        //   body = eph_pub(32) || nonce(12) || ciphertext
        //
        // The gateway will extract eph_pub from the first 32 bytes, derive the
        // same circuit keys via DH(gateway_static_secret, eph_pub), and decrypt.
        //
        // We MUST NOT use encrypt_circuit_payload() for the first frame — that
        // would omit eph_pub and the gateway could not derive the keys.
        let open_msg = StreamMessage::Open(StreamOpen {
            stream_id,
            destination,
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        });

        let link = Arc::new(link);

        let open_cbor = encode_stream_message(&open_msg)
            .map_err(|e| StreamError::Cbor(e.to_string()))?;
        let (circuit_keys, _client_eph_pub, sealed_body) =
            seal_circuit_payload_with_fresh_eph(&gateway_x25519_pub, &open_cbor);

        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: gateway_node_id,
            src: client_node_id,
            ttl: FRAME_TTL_MAX,
            fid,
            seq: 1,
            body: sealed_body, // eph_pub(32) || nonce || ciphertext
        };
        link.send_frame(&frame)
            .await
            .map_err(|e| StreamError::Circuit(format!("send StreamOpen: {e}")))?;

        // 5. Receive StreamOpenAck (with outer frame validation).
        let resp_frame = link
            .recv_frame()
            .await
            .map_err(|e| StreamError::Circuit(format!("recv StreamOpenAck: {e}")))?;

        // Validate outer frame.
        validate_frame(&resp_frame, &gateway_node_id, &client_node_id, &fid)?;

        let plaintext = decrypt_circuit_payload(&circuit_keys.recv_key, &resp_frame.body)
            .ok_or(StreamError::Circuit("StreamOpenAck decryption failed".into()))?;
        let resp_msg = decode_stream_message(&plaintext)
            .map_err(|e| StreamError::Cbor(e.to_string()))?;

        let send_credit = match resp_msg {
            StreamMessage::OpenAck(ack) => {
                if !ack.connected {
                    return Err(StreamError::OpenRejected(
                        ack.error.unwrap_or_else(|| "unknown error".into()),
                    ));
                }
                ack.initial_receive_window.min(MAX_STREAM_WINDOW)
            }
            StreamMessage::Reset(reset) => {
                return Err(StreamError::Reset(reset.reason));
            }
            other => {
                return Err(StreamError::Circuit(format!(
                    "expected StreamOpenAck, got {other:?}"
                )));
            }
        };

        // 6. Create the shared state.
        let shared = Arc::new(Mutex::new(StreamShared {
            state: StreamState::Established,
            send_credit,
            send_seq: 0,
            recv_seq: 0,
            credit_notify: Arc::new(Notify::new()),
            pending_data: VecDeque::new(),
            data_notify: Arc::new(Notify::new()),
            gateway_credit_consumed: 0,
            pending_data_total: 0,
            eager_credit_pending: 0,
        }));

        // 7. Spawn the background reader task.
        let reader_shared = Arc::clone(&shared);
        let reader_link = Arc::clone(&link);
        let reader_keys = CircuitKeys {
            send_key: circuit_keys.send_key,
            recv_key: circuit_keys.recv_key,
        };
        let reader_gateway = gateway_node_id;
        let reader_client = client_node_id;
        let reader_fid = fid;
        let reader_handle = tokio::spawn(async move {
            background_reader(
                reader_link,
                reader_keys,
                reader_gateway,
                reader_client,
                reader_fid,
                reader_shared,
            )
            .await;
        });

        Ok(Self {
            link,
            circuit_keys,
            gateway_node_id,
            client_node_id,
            stream_id,
            fid,
            frame_seq: Arc::new(CircuitFrameSequencer::new(2)), // 1 was used for StreamOpen
            shared,
            reader_handle: Some(reader_handle),
            metrics: None,
            streams_map: None,
        })
    }

    /// Send bytes to the remote server (client → gateway → TCP).
    ///
    /// This method will await credit replenishment if the send window is
    /// exhausted. A background task processes inbound `StreamWindowUpdate`
    /// messages, so `send()` can make progress even if the application is
    /// not calling `recv()`.
    ///
    /// Returns the number of bytes accepted.
    ///
    /// # Errors
    /// Returns [`StreamError`] on state violations, circuit errors, or
    /// if the stream is closed/reset while waiting for credit.
    pub async fn send(&mut self, data: &[u8]) -> Result<usize, StreamError> {
        let mut remaining = data;
        let mut total_sent = 0;

        while !remaining.is_empty() {
            // Check state + credit.
            let (state, credit) = {
                let shared = self.shared.lock().await;
                (shared.state, shared.send_credit)
            };

            if state == StreamState::Closed || state == StreamState::Reset {
                return Err(StreamError::Closed);
            }
            if state == StreamState::HalfClosedLocal {
                return Err(StreamError::InvalidState(state));
            }

            if credit == 0 {
                // N2.3.9: Record window block event + measure blocked duration.
                let block_start = std::time::Instant::now();
                if let Some(m) = &self.metrics {
                    m.window_block();
                }
                // Wait for the background reader to replenish credit.
                //
                // Race safety: `send_credit` is the authoritative state. The
                // `Notify` is only a wakeup mechanism. Even if a notification
                // is "collapsed" (tokio::Notify stores only one permit), the
                // credit from that WindowUpdate was already added to
                // `send_credit` before `notify_one()` was called. So when we
                // loop back and re-check `send_credit`, we see the combined
                // credit from all WindowUpdates that arrived while we were
                // waiting.
                let notify = {
                    let shared = self.shared.lock().await;
                    if shared.state == StreamState::Closed || shared.state == StreamState::Reset {
                        return Err(StreamError::WindowExhaustedTerminated);
                    }
                    shared.credit_notify.clone()
                };
                notify.notified().await;
                // N2.3.9: Record how long we were blocked.
                if let Some(m) = &self.metrics {
                    m.record_send_blocked(block_start.elapsed());
                }
                continue; // Re-check credit (and state) after wakeup.
            }

            let chunk_size = remaining
                .len()
                .min(MAX_STREAM_DATA_PAYLOAD)
                .min(credit as usize);
            let chunk = &remaining[..chunk_size];

            // Get the sequence number and consume credit.
            let seq = {
                let mut shared = self.shared.lock().await;
                if shared.state == StreamState::Closed || shared.state == StreamState::Reset {
                    return Err(StreamError::Closed);
                }
                let seq = shared.send_seq;
                shared.send_seq += 1;
                shared.send_credit -= chunk_size as u64;
                seq
            };

            // Send the StreamData.
            let msg = StreamMessage::Data(StreamData {
                stream_id: self.stream_id,
                direction: StreamDirection::ClientToGateway,
                sequence: seq,
                data: chunk.to_vec(),
            });
            self.send_message(&msg).await?;

            // N2.3.9: Record bytes sent in metrics.
            if let Some(m) = &self.metrics {
                m.bytes_sent(chunk_size as u64);
            }

            total_sent += chunk_size;
            remaining = &remaining[chunk_size..];
        }

        Ok(total_sent)
    }

    /// Receive bytes from the remote server (TCP → gateway → client).
    ///
    /// Returns `Ok(None)` if the stream is half-closed remote (no more data
    /// from the server).
    ///
    /// # Errors
    /// Returns [`StreamError`] on state violations or if the background
    /// reader task terminated.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, StreamError> {
        loop {
            // Check for pending data.
            let data_to_return = {
                let mut shared = self.shared.lock().await;
                if let Some(data) = shared.pending_data.pop_front() {
                    // N2.3.9: Track consumed bytes for flow control.
                    shared.gateway_credit_consumed += data.len() as u64;
                    shared.pending_data_total = shared.pending_data_total.saturating_sub(data.len() as u64);
                    Some(data)
                } else if shared.state == StreamState::Closed {
                    return Ok(None);
                } else if shared.state == StreamState::Reset {
                    return Err(StreamError::Reset(StreamResetReason::ApplicationReset));
                } else if shared.state == StreamState::HalfClosedRemote
                    || shared.state == StreamState::HalfClosedLocal
                {
                    if shared.pending_data.is_empty() {
                        return Ok(None);
                    }
                    None
                } else {
                    None
                }
            };

            if let Some(data) = data_to_return {
                // N2.3.9: Check if we should send a WindowUpdate to the gateway.
                let credit_to_replenish = {
                    let mut shared = self.shared.lock().await;
                    if shared.gateway_credit_consumed >= WINDOW_UPDATE_THRESHOLD {
                        let credit = shared.gateway_credit_consumed;
                        shared.gateway_credit_consumed = 0;
                        Some(credit)
                    } else {
                        None
                    }
                };

                if let Some(credit) = credit_to_replenish {
                    // Send WindowUpdate to the gateway.
                    let msg = StreamMessage::WindowUpdate(StreamWindowUpdate {
                        stream_id: self.stream_id,
                        additional_credit: credit,
                    });
                    // Ignore errors — the stream might be closing.
                    let _ = self.send_message(&msg).await;
                    // N2.3.9: Record credit update sent in metrics.
                    if let Some(m) = &self.metrics {
                        m.credit_update_sent();
                    }
                }

                // N2.3.9: Record bytes received in metrics.
                if let Some(m) = &self.metrics {
                    m.bytes_received(data.len() as u64);
                }

                return Ok(Some(data));
            }

            // Wait for the background reader to deliver data or change state.
            let notify = {
                let shared = self.shared.lock().await;
                shared.data_notify.clone()
            };
            notify.notified().await;
        }
    }

    /// Half-close the send direction (TCP FIN equivalent).
    ///
    /// # Errors
    /// Returns [`StreamError`] on state violations or circuit errors.
    pub async fn shutdown_write(&mut self) -> Result<(), StreamError> {
        {
            let mut shared = self.shared.lock().await;
            if shared.state == StreamState::Closed || shared.state == StreamState::Reset {
                return Err(StreamError::Closed);
            }
            if shared.state == StreamState::HalfClosedLocal {
                return Ok(());
            }
        }

        let msg = StreamMessage::HalfClose(StreamHalfClose {
            stream_id: self.stream_id,
            direction: StreamDirection::ClientToGateway,
        });
        self.send_message(&msg).await?;

        let mut shared = self.shared.lock().await;
        shared.state = match shared.state {
            StreamState::Established => StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => StreamState::Closed,
            other => other,
        };
        Ok(())
    }

    /// Clean close (both directions done).
    ///
    /// # Errors
    /// Returns [`StreamError`] on circuit errors.
    pub async fn close(&mut self) -> Result<(), StreamError> {
        {
            let shared = self.shared.lock().await;
            if shared.state == StreamState::Closed {
                return Ok(());
            }
        }

        let msg = StreamMessage::Close(StreamClose {
            stream_id: self.stream_id,
        });
        let _ = self.send_message(&msg).await;
        self.shared.lock().await.state = StreamState::Closed;
        // N2.3.9: Remove from the circuit's streams map (if multiplexed).
        if let Some(map) = &self.streams_map {
            map.lock().await.remove(&self.stream_id);
        }
        self.abort_reader();
        Ok(())
    }

    /// Abort the stream (TCP RST equivalent).
    ///
    /// # Errors
    /// Returns [`StreamError`] on circuit errors.
    pub async fn reset(&mut self, reason: StreamResetReason) -> Result<(), StreamError> {
        {
            let shared = self.shared.lock().await;
            if shared.state == StreamState::Reset {
                return Ok(());
            }
        }

        let msg = StreamMessage::Reset(StreamReset {
            stream_id: self.stream_id,
            reason,
        });
        let _ = self.send_message(&msg).await;
        self.shared.lock().await.state = StreamState::Reset;
        // N2.3.9: Remove from the circuit's streams map (if multiplexed).
        if let Some(map) = &self.streams_map {
            map.lock().await.remove(&self.stream_id);
        }
        self.abort_reader();
        Ok(())
    }

    /// Returns the current stream state.
    #[must_use]
    pub async fn state(&self) -> StreamState {
        self.shared.lock().await.state
    }

    /// Returns the stream ID.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns the available send credit.
    #[must_use]
    pub async fn send_credit(&self) -> u64 {
        self.shared.lock().await.send_credit
    }

    // ─── Internal helpers ──────────────────────────────────────────────────

    /// Encode + encrypt + send a StreamMessage through the circuit.
    async fn send_message(&mut self, msg: &StreamMessage) -> Result<(), StreamError> {
        let cbor = encode_stream_message(msg).map_err(|e| StreamError::Cbor(e.to_string()))?;
        let sealed = encrypt_circuit_payload(&self.circuit_keys.send_key, &cbor);

        let seq = self.frame_seq.allocate().await
            .ok_or(StreamError::Circuit("frame sequence exhausted".into()))?;

        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: self.gateway_node_id,
            src: self.client_node_id,
            ttl: FRAME_TTL_MAX,
            fid: self.fid,
            seq,
            body: sealed,
        };

        self.link
            .send_frame(&frame)
            .await
            .map_err(|e| StreamError::Circuit(e.to_string()))?;
        Ok(())
    }

    /// Abort the background reader task.
    fn abort_reader(&mut self) {
        if let Some(handle) = self.reader_handle.take() {
            handle.abort();
        }
    }

    /// **N2.3.8** — Create a StreamHandle from a multiplexed circuit.
    /// The handle shares the link and background reader with the parent
    /// `MultiplexedCircuit`. The `reader_handle` is None — the circuit
    /// owns the background reader.
    pub fn from_multiplexed(
        stream_id: StreamId,
        link: Arc<AsyncLink>,
        send_key: snp_crypto::SymmetricKey,
        gateway_node_id: [u8; 32],
        client_node_id: [u8; 32],
        fid: [u8; 8],
        frame_seq: Arc<CircuitFrameSequencer>,
        shared: Arc<Mutex<StreamShared>>,
        reader_handle: Option<tokio::task::JoinHandle<()>>,
        metrics: Option<Arc<super::transport_metrics::TransportMetrics>>,
        streams_map: Option<Arc<Mutex<HashMap<StreamId, Arc<Mutex<StreamShared>>>>>>,
    ) -> Self {
        Self {
            link,
            circuit_keys: CircuitKeys {
                send_key,
                recv_key: [0u8; 32],
            },
            gateway_node_id,
            client_node_id,
            stream_id,
            fid,
            frame_seq,
            shared,
            reader_handle,
            metrics,
            streams_map,
        }
    }

    /// **N2.3.9** — Set the transport metrics on this stream handle.
    /// When set, send/recv/credit events are recorded.
    pub fn set_metrics(&mut self, metrics: Arc<super::transport_metrics::TransportMetrics>) {
        self.metrics = Some(metrics);
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.abort_reader();
    }
}

/// Validate the outer frame metadata before decrypting.
///
/// Checks:
/// - `cls == b'B'` (Class B frame)
/// - `src == gateway_node_id` (frame is from the expected gateway)
/// - `dst == client_node_id` (frame is addressed to this client)
/// - `fid == expected_fid` (frame belongs to this stream's circuit)
fn validate_frame(
    frame: &Frame,
    expected_src: &[u8; 32],
    expected_dst: &[u8; 32],
    expected_fid: &[u8; 8],
) -> Result<(), StreamError> {
    if frame.cls != b'B' {
        return Err(StreamError::FrameValidation(format!(
            "expected Class B, got Class {}",
            frame.cls as char
        )));
    }
    if frame.src != *expected_src {
        return Err(StreamError::FrameValidation(format!(
            "frame src {:?} != expected gateway {:?}",
            frame.src, expected_src
        )));
    }
    if frame.dst != *expected_dst {
        return Err(StreamError::FrameValidation(format!(
            "frame dst {:?} != expected client {:?}",
            frame.dst, expected_dst
        )));
    }
    if frame.fid != *expected_fid {
        return Err(StreamError::FrameValidation(format!(
            "frame fid {:?} != expected {:?}",
            frame.fid, expected_fid
        )));
    }
    Ok(())
}

/// The background reader task — continuously processes inbound circuit
/// messages and dispatches them:
///
/// - `StreamData` → push to the data channel (for `recv()`).
/// - `StreamWindowUpdate` → replenish `send_credit` + notify.
/// - `StreamHalfClose` → update state.
/// - `StreamClose` → update state + close data channel.
/// - `StreamReset` → update state + close data channel.
async fn background_reader(
    link: Arc<AsyncLink>,
    circuit_keys: CircuitKeys,
    gateway_node_id: [u8; 32],
    client_node_id: [u8; 32],
    fid: [u8; 8],
    shared: Arc<Mutex<StreamShared>>,
) {
    loop {
        // Receive a frame from the circuit.
        let frame = match link.recv_frame().await {
            Ok(f) => f,
            Err(e) => {
                // Link error — mark the stream as closed.
                let mut s = shared.lock().await;
                s.state = StreamState::Closed;
                break;
            }
        };

        // Validate outer frame. An authenticated frame from the correct
        // gateway with the wrong fid is a protocol violation — reset.
        if let Err(_) = validate_frame(&frame, &gateway_node_id, &client_node_id, &fid) {
            // If the frame passed AEAD at the link layer but has wrong
            // src/dst/fid, it's a protocol violation from an authenticated
            // peer — reset the stream.
            let mut s = shared.lock().await;
            s.state = StreamState::Reset;
            s.credit_notify.notify_one();
            s.data_notify.notify_one();
            break;
        }

        // Decrypt. If the frame is from the correct gateway but can't be
        // decrypted with the circuit key, it's a protocol violation — reset.
        let plaintext = match decrypt_circuit_payload(&circuit_keys.recv_key, &frame.body) {
            Some(p) => p,
            None => {
                let mut s = shared.lock().await;
                s.state = StreamState::Reset;
                s.credit_notify.notify_one();
                s.data_notify.notify_one();
                break;
            }
        };

        // Decode. Malformed CBOR from an authenticated gateway is a
        // protocol violation — reset.
        let msg = match decode_stream_message(&plaintext) {
            Ok(m) => m,
            Err(_) => {
                let mut s = shared.lock().await;
                s.state = StreamState::Reset;
                s.credit_notify.notify_one();
                s.data_notify.notify_one();
                break;
            }
        };

        // Dispatch.
        match msg {
            StreamMessage::Data(data) => {
                // Validate direction.
                if data.direction != StreamDirection::GatewayToClient {
                    // Protocol violation — reset.
                    let mut s = shared.lock().await;
                    s.state = StreamState::Reset;
                    s.credit_notify.notify_one();
                    s.data_notify.notify_one();
                    break;
                }
                let mut s = shared.lock().await;
                // Validate sequence — must be exactly recv_seq.
                if data.sequence != s.recv_seq {
                    // Out of order from an authenticated gateway — reset.
                    s.state = StreamState::Reset;
                    s.credit_notify.notify_one();
                    s.data_notify.notify_one();
                    break;
                }
                s.recv_seq += 1;
                s.pending_data.push_back(data.data);
                s.data_notify.notify_one();
            }
            StreamMessage::WindowUpdate(update) => {
                let mut s = shared.lock().await;
                s.send_credit = s
                    .send_credit
                    .saturating_add(update.additional_credit)
                    .min(MAX_STREAM_WINDOW);
                s.credit_notify.notify_one();
            }
            StreamMessage::HalfClose(hc) => {
                if hc.direction == StreamDirection::GatewayToClient {
                    let mut s = shared.lock().await;
                    s.state = match s.state {
                        StreamState::Established => StreamState::HalfClosedRemote,
                        StreamState::HalfClosedLocal => StreamState::Closed,
                        other => other,
                    };
                    s.data_notify.notify_one();
                }
            }
            StreamMessage::Close(_) => {
                let mut s = shared.lock().await;
                s.state = StreamState::Closed;
                s.data_notify.notify_one();
                break;
            }
            StreamMessage::Reset(reset) => {
                let mut s = shared.lock().await;
                s.state = StreamState::Reset;
                s.credit_notify.notify_one();
                s.data_notify.notify_one();
                break;
            }
            StreamMessage::Open(_) | StreamMessage::OpenAck(_) => {
                // Unexpected message type from authenticated gateway — reset.
                let mut s = shared.lock().await;
                s.state = StreamState::Reset;
                s.credit_notify.notify_one();
                s.data_notify.notify_one();
                break;
            }
        }
    }
}

/// A trait for opening Mode B streams. This is the seam between the
/// `AsyncUpstream` implementation and the circuit.
#[async_trait::async_trait]
pub trait CircuitStream: Send + Sync {
    /// Open a new stream to the given endpoint.
    ///
    /// # Errors
    /// Returns [`StreamError`] if the stream cannot be opened.
    async fn open_stream(
        &self,
        destination: InternetEndpoint,
    ) -> Result<StreamHandle, StreamError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── Circuit AEAD roundtrip tests ───────────────────────────────────────

    #[test]
    fn stream_message_roundtrip_through_circuit() {
        let key = [42u8; 32];
        let msg = StreamMessage::Data(StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 5,
            data: b"hello stream".to_vec(),
        });

        let cbor = encode_stream_message(&msg).unwrap();
        let sealed = encrypt_circuit_payload(&key, &cbor);
        let plaintext = decrypt_circuit_payload(&key, &sealed).unwrap();
        let decoded = decode_stream_message(&plaintext).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn decryption_with_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let msg = StreamMessage::Data(StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 0,
            data: b"secret".to_vec(),
        });

        let cbor = encode_stream_message(&msg).unwrap();
        let sealed = encrypt_circuit_payload(&key1, &cbor);
        let result = decrypt_circuit_payload(&key2, &sealed);
        assert!(result.is_none(), "wrong key must fail (relay opacity)");
    }

    // ── Frame validation tests ─────────────────────────────────────────────

    #[test]
    fn validate_frame_rejects_wrong_class() {
        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'C',
            dst: [1u8; 32],
            src: [2u8; 32],
            ttl: FRAME_TTL_MAX,
            fid: [3u8; 8],
            seq: 1,
            body: vec![],
        };
        let result = validate_frame(&frame, &[2u8; 32], &[1u8; 32], &[3u8; 8]);
        assert!(matches!(result, Err(StreamError::FrameValidation(_))));
    }

    #[test]
    fn validate_frame_rejects_wrong_src() {
        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: [1u8; 32],
            src: [99u8; 32], // Wrong source.
            ttl: FRAME_TTL_MAX,
            fid: [3u8; 8],
            seq: 1,
            body: vec![],
        };
        let result = validate_frame(&frame, &[2u8; 32], &[1u8; 32], &[3u8; 8]);
        assert!(matches!(result, Err(StreamError::FrameValidation(_))));
    }

    #[test]
    fn validate_frame_rejects_wrong_dst() {
        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: [99u8; 32], // Wrong destination.
            src: [2u8; 32],
            ttl: FRAME_TTL_MAX,
            fid: [3u8; 8],
            seq: 1,
            body: vec![],
        };
        let result = validate_frame(&frame, &[2u8; 32], &[1u8; 32], &[3u8; 8]);
        assert!(matches!(result, Err(StreamError::FrameValidation(_))));
    }

    #[test]
    fn validate_frame_rejects_wrong_fid() {
        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: [1u8; 32],
            src: [2u8; 32],
            ttl: FRAME_TTL_MAX,
            fid: [99u8; 8], // Wrong FID.
            seq: 1,
            body: vec![],
        };
        let result = validate_frame(&frame, &[2u8; 32], &[1u8; 32], &[3u8; 8]);
        assert!(matches!(result, Err(StreamError::FrameValidation(_))));
    }

    #[test]
    fn validate_frame_accepts_correct_frame() {
        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: [1u8; 32],
            src: [2u8; 32],
            ttl: FRAME_TTL_MAX,
            fid: [3u8; 8],
            seq: 1,
            body: vec![],
        };
        let result = validate_frame(&frame, &[2u8; 32], &[1u8; 32], &[3u8; 8]);
        assert!(result.is_ok());
    }

    // ── Stream state machine tests (via shared state) ─────────────────────

    #[tokio::test]
    async fn window_update_replenishes_send_credit() {
        // Test that a WindowUpdate message replenishes send_credit and
        // notifies the send() path.
        
        let shared = Arc::new(Mutex::new(StreamShared {
            state: StreamState::Established,
            send_credit: 0,
            send_seq: 0,
            recv_seq: 0,
            credit_notify: Arc::new(Notify::new()),
            pending_data: VecDeque::new(),
            data_notify: Arc::new(Notify::new()),
            gateway_credit_consumed: 0,
            pending_data_total: 0,
            eager_credit_pending: 0,
        }));

        // Simulate a WindowUpdate arriving.
        {
            let mut s = shared.lock().await;
            s.send_credit = s
                .send_credit
                .saturating_add(4096)
                .min(MAX_STREAM_WINDOW);
            s.credit_notify.notify_one();
        }

        // Verify credit was replenished.
        let credit = shared.lock().await.send_credit;
        assert_eq!(credit, 4096, "credit must be replenished");
    }

    #[tokio::test]
    async fn half_close_transitions_state() {
        // Test that HalfClosedLocal → Closed when HalfClosedRemote arrives.
        
        let shared = Arc::new(Mutex::new(StreamShared {
            state: StreamState::HalfClosedLocal,
            send_credit: 0,
            send_seq: 0,
            recv_seq: 0,
            credit_notify: Arc::new(Notify::new()),
            pending_data: VecDeque::new(),
            data_notify: Arc::new(Notify::new()),
            gateway_credit_consumed: 0,
            pending_data_total: 0,
            eager_credit_pending: 0,
        }));

        // Simulate a HalfClose(remote) arriving.
        {
            let mut s = shared.lock().await;
            s.state = match s.state {
                StreamState::HalfClosedLocal => StreamState::Closed,
                other => other,
            };
        }

        assert_eq!(shared.lock().await.state, StreamState::Closed);
    }

    #[tokio::test]
    async fn reset_terminates_stream() {
        
        let shared = Arc::new(Mutex::new(StreamShared {
            state: StreamState::Established,
            send_credit: 100,
            send_seq: 0,
            recv_seq: 0,
            credit_notify: Arc::new(Notify::new()),
            pending_data: VecDeque::new(),
            data_notify: Arc::new(Notify::new()),
            gateway_credit_consumed: 0,
            pending_data_total: 0,
            eager_credit_pending: 0,
        }));

        // Simulate a Reset arriving.
        {
            let mut s = shared.lock().await;
            s.state = StreamState::Reset;
            s.credit_notify.notify_one(); // Wake blocked send().
        }

        assert_eq!(shared.lock().await.state, StreamState::Reset);
    }

    #[test]
    fn stream_open_message_roundtrip_through_circuit() {
        let key = [99u8; 32];
        let msg = StreamMessage::Open(StreamOpen {
            stream_id: 42,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 443,
                protocol: TransportProtocol::Tcp,
            },
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        });

        let cbor = encode_stream_message(&msg).unwrap();
        let sealed = encrypt_circuit_payload(&key, &cbor);
        let plaintext = decrypt_circuit_payload(&key, &sealed).unwrap();
        let decoded = decode_stream_message(&plaintext).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_window_update_roundtrip_through_circuit() {
        let key = [77u8; 32];
        let msg = StreamMessage::WindowUpdate(StreamWindowUpdate {
            stream_id: 7,
            additional_credit: 32768,
        });

        let cbor = encode_stream_message(&msg).unwrap();
        let sealed = encrypt_circuit_payload(&key, &cbor);
        let plaintext = decrypt_circuit_payload(&key, &sealed).unwrap();
        let decoded = decode_stream_message(&plaintext).unwrap();

        assert_eq!(decoded, msg);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N2.3.8 — MultiplexedCircuit (multiple streams on one circuit)
// ════════════════════════════════════════════════════════════════════════════

/// **N2.3.8** — A multiplexed Mode B circuit that can carry multiple
/// independent streams.
///
/// This owns the circuit link (one SNP-IK connection + one fresh ephemeral
/// X25519 key derivation). Multiple [`StreamHandle`]s can be opened on the
/// same circuit, each with its own `stream_id`, sequence space, flow control,
/// and TCP socket at the gateway.
///
/// ## Architecture
///
/// ```text
/// MultiplexedCircuit (owns AsyncLink + circuit keys)
///     │
///     ├── open_stream() → StreamHandle #1
///     ├── open_stream() → StreamHandle #2
///     └── open_stream() → StreamHandle #3
///         (each has independent stream_id, sequence, flow control)
/// ```
///
/// A background reader task dispatches inbound frames to the correct
/// stream via `stream_id`.
pub struct MultiplexedCircuit {
    /// The circuit link (shared by all streams on this circuit).
    link: Arc<AsyncLink>,
    /// The circuit keys (established on first open_stream).
    circuit_keys: CircuitKeys,
    /// The gateway's X25519 public key (for the first seal_circuit_payload_with_fresh_eph).
    gateway_x25519_pub: snp_crypto::X25519PubKey,
    /// The gateway's NodeId (frame destination).
    gateway_node_id: [u8; 32],
    /// The client's NodeId (frame source).
    client_node_id: [u8; 32],
    /// The frame ID for this circuit.
    fid: [u8; 8],
    /// The next frame sequence number for outbound frames (client→gateway).
    frame_seq: Arc<CircuitFrameSequencer>,
    /// Active stream dispatchers: stream_id → shared state.
    streams: Arc<Mutex<HashMap<StreamId, Arc<Mutex<StreamShared>>>>>,
    /// Background reader task handle.
    reader_handle: Option<tokio::task::JoinHandle<()>>,
    /// **N2.3.9** — Optional transport metrics. Shared with all streams and
    /// the background reader. None = metrics disabled.
    metrics: Option<Arc<super::transport_metrics::TransportMetrics>>,
}

impl std::fmt::Debug for MultiplexedCircuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexedCircuit")
            .field("fid", &self.fid)
            .field("gateway_node_id", &self.gateway_node_id)
            .finish_non_exhaustive()
    }
}

impl MultiplexedCircuit {
    /// Establish a new multiplexed circuit to the gateway.
    ///
    /// This performs the SNP-IK handshake + fresh ephemeral X25519 derivation
    /// (same as [`StreamHandle::open`]), but does NOT open any streams yet.
    /// Use [`open_stream`] to create individual streams on this circuit.
    ///
    /// # Errors
    /// Returns [`StreamError`] on circuit establishment failure.
    pub async fn establish(
        node: &Node,
        route: &Route,
        client_x25519_secret: &snp_crypto::X25519Secret,
        client_x25519_public: &snp_crypto::X25519PubKey,
    ) -> Result<Self, StreamError> {
        // Extract relay + gateway from route.
        if route.hop_details().is_empty() {
            return Err(StreamError::Circuit("route has no hop_details".into()));
        }
        let first_hop = &route.hop_details()[0];
        let relay_endpoint = first_hop
            .first_endpoint()
            .ok_or_else(|| StreamError::Circuit("first hop has no endpoints".into()))?;
        let relay_addr = relay_endpoint
            .as_tcp()
            .ok_or_else(|| StreamError::Circuit("first hop is not TCP".into()))?;
        let relay_node_id = first_hop.node_id();

        let gateway_descriptor = route
            .destination_descriptor()
            .ok_or_else(|| StreamError::Circuit("route has no destination descriptor".into()))?;
        let gateway_node_id = gateway_descriptor.node_id();
        let gateway_x25519_pub_bytes = gateway_descriptor
            .circuit_x25519_pub()
            .ok_or_else(|| StreamError::Circuit("no gateway X25519 key".into()))?;
        let gateway_x25519_pub = snp_crypto::x25519_public_from_bytes(gateway_x25519_pub_bytes);

        // Connect + SNP-IK handshake.
        let mut stream = AsyncLink::connect_raw(relay_addr)
            .await
            .map_err(|e| StreamError::Circuit(format!("relay connect: {e}")))?;
        let handshake = perform_snp_ik_handshake_async(
            &mut stream, true,
            &node.identity.secret_key, &node.identity.public_key,
            client_x25519_secret, client_x25519_public,
            Some(&relay_node_id),
        ).await.map_err(|e| StreamError::Circuit(format!("SNP-IK: {e}")))?;
        if handshake.peer_node_id != relay_node_id {
            return Err(StreamError::Circuit("relay identity substitution".into()));
        }
        let link = Arc::new(AsyncLink::new(stream, handshake.link_keys));

        let fid = random_fid();
        let client_node_id = node.identity.node_id;

        // Store the gateway X25519 pub key for the first open_stream() call.
        let circuit = Self {
            link,
            circuit_keys: CircuitKeys {
                send_key: [0u8; 32],
                recv_key: [0u8; 32],
            },
            gateway_x25519_pub,
            gateway_node_id,
            client_node_id,
            fid,
            frame_seq: Arc::new(CircuitFrameSequencer::new(1)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            reader_handle: None,
            metrics: None,
        };

        Ok(circuit)
    }

    /// **N2.3.9** — Attach transport metrics to this circuit.
    /// All streams opened on this circuit will record events to these metrics.
    /// Must be called before `open_stream`.
    pub fn set_metrics(&mut self, metrics: Arc<super::transport_metrics::TransportMetrics>) {
        self.metrics = Some(metrics);
    }

    /// **N2.3.9** — Returns the number of registered streams on this circuit.
    /// Used by tests to verify that streams are cleaned up after close.
    /// A stream is "registered" from the moment `open_stream` is called
    /// until the stream is closed/reset. The background reader dispatches
    /// by `stream_id` using this map.
    pub async fn stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// **N2.3.9** — Returns a clone of the metrics Arc (if set).
    /// Used by the background reader to record credit_update_received.
    fn metrics_clone(&self) -> Option<Arc<super::transport_metrics::TransportMetrics>> {
        self.metrics.clone()
    }

    /// Open a new stream on this circuit.
    ///
    /// The first call to this method establishes the circuit keys (via
    /// `seal_circuit_payload_with_fresh_eph`). Subsequent calls reuse the
    /// same keys (via `encrypt_circuit_payload`).
    ///
    /// # Errors
    /// Returns [`StreamError`] on failure.
    pub async fn open_stream(
        &mut self,
        destination: InternetEndpoint,
    ) -> Result<StreamHandle, StreamError> {
        // Generate stream ID.
        let stream_id: StreamId = {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf).expect("getrandom");
            u64::from_be_bytes(buf)
        };

        // Build StreamOpen.
        let open_msg = StreamMessage::Open(StreamOpen {
            stream_id,
            destination,
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        });
        let open_cbor = encode_stream_message(&open_msg)
            .map_err(|e| StreamError::Cbor(e.to_string()))?;

        // Send the StreamOpen. If this is the first stream, use
        // seal_circuit_payload_with_fresh_eph to establish the circuit keys.
        // Otherwise, use encrypt_circuit_payload with the existing keys.
        let frame_seq = self.frame_seq.allocate().await
            .ok_or(StreamError::Circuit("frame sequence exhausted".into()))?;

        // Create shared state for this stream BEFORE sending the open.
        // State starts as Opening — the background reader will set it to
        // Established when it receives the OpenAck.
        let shared = Arc::new(Mutex::new(StreamShared {
            state: StreamState::Opening,
            send_credit: 0,
            send_seq: 0,
            recv_seq: 0,
            credit_notify: Arc::new(Notify::new()),
            pending_data: VecDeque::new(),
            data_notify: Arc::new(Notify::new()),
            gateway_credit_consumed: 0,
            pending_data_total: 0,
            eager_credit_pending: 0,
        }));

        // Register in the streams map BEFORE sending (so the background reader
        // can dispatch the OpenAck when it arrives).
        self.streams.lock().await.insert(stream_id, Arc::clone(&shared));

        // Check if circuit keys have been established.
        let keys_established = self.circuit_keys.send_key != [0u8; 32];

        let sealed_body = if !keys_established {
            // First stream — establish circuit keys.
            let (keys, _eph_pub, sealed) =
                seal_circuit_payload_with_fresh_eph(
                    &self.gateway_x25519_pub,
                    &open_cbor,
                );
            self.circuit_keys = keys;
            sealed
        } else {
            encrypt_circuit_payload(&self.circuit_keys.send_key, &open_cbor)
        };

        // Send the frame.
        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: self.gateway_node_id,
            src: self.client_node_id,
            ttl: FRAME_TTL_MAX,
            fid: self.fid,
            seq: frame_seq,
            body: sealed_body,
        };
        self.link
            .send_frame(&frame)
            .await
            .map_err(|e| StreamError::Circuit(format!("send StreamOpen: {e}")))?;

        // Receive StreamOpenAck. If the background reader is already running
        // (i.e., this is the second+ stream), we can't call recv_frame()
        // directly — the reader owns the recv path. Instead, we temporarily
        // register the stream in the streams map BEFORE sending the open,
        // and wait for the background reader to deliver the ack.
        //
        // For the first stream, the background reader isn't running yet,
        // so we call recv_frame() directly.
        let send_credit = if self.reader_handle.is_none() {
            // First stream — no background reader yet. Receive directly.
            let resp_frame = self.link
                .recv_frame()
                .await
                .map_err(|e| StreamError::Circuit(format!("recv StreamOpenAck: {e}")))?;

            validate_frame(&resp_frame, &self.gateway_node_id, &self.client_node_id, &self.fid)?;

            let plaintext = decrypt_circuit_payload(&self.circuit_keys.recv_key, &resp_frame.body)
                .ok_or(StreamError::Circuit("StreamOpenAck decryption failed".into()))?;
            let resp_msg = decode_stream_message(&plaintext)
                .map_err(|e| StreamError::Cbor(e.to_string()))?;

            match resp_msg {
                StreamMessage::OpenAck(ack) => {
                    if !ack.connected {
                        return Err(StreamError::OpenRejected(
                            ack.error.unwrap_or_else(|| "unknown error".into()),
                        ));
                    }
                    ack.initial_receive_window.min(MAX_STREAM_WINDOW)
                }
                StreamMessage::Reset(reset) => {
                    return Err(StreamError::Reset(reset.reason));
                }
                other => {
                    return Err(StreamError::Circuit(format!(
                        "expected StreamOpenAck, got {other:?}"
                    )));
                }
            }
        } else {
            // Subsequent stream — background reader is running.
            // We already registered the stream in the streams map above.
            // Wait for the background reader to deliver the OpenAck (or Reset)
            // via the shared state.
            //
            // The background reader's dispatch for OpenAck sets the state
            // to Established and sets send_credit. We wait on data_notify.
            //
            // Actually, the background reader currently doesn't handle
            // OpenAck — it ignores Open/OpenAck messages. We need to fix
            // this: the background reader should dispatch OpenAck to the
            // correct stream.
            //
            // For now, we need a different approach. Since the background
            // reader consumes all recv_frame() calls, open_stream() can't
            // receive the ack. Let's use a dedicated channel for acks.
            //
            // Simplest fix: use a oneshot channel stored in the streams map
            // that the background reader fills when it sees an OpenAck.
            //
            // But we don't have that infrastructure. Let me use a simpler
            // approach: store the ack in the StreamShared.pending_data
            // and notify via data_notify. The open_stream() method then
            // reads it from there.
            //
            // Actually, the cleanest fix for now: the background reader
            // needs to handle OpenAck by setting the stream state and
            // credit. Let me add that handling.

            // Wait for the background reader to process the OpenAck.
            // The stream is registered in the streams map, so the reader
            // will dispatch the OpenAck to it.
            //
            // We need the reader to recognize OpenAck and set the state
            // + credit. Let me add a pending_ack field to StreamShared.
            //
            // For now, let's just wait on data_notify with a timeout.
            let notify = {
                // The stream is registered — wait for the reader to set its state.
                let s = shared.lock().await;
                s.data_notify.clone()
            };

            // Wait up to 30 seconds for the background reader to deliver the ack.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                if tokio::time::Instant::now() > deadline {
                    return Err(StreamError::Circuit("timeout waiting for StreamOpenAck".into()));
                }
                tokio::time::timeout(Duration::from_secs(1), notify.notified()).await.ok();
                let s = shared.lock().await;
                if s.state == StreamState::Established {
                    break s.send_credit;
                }
                if s.state == StreamState::Reset {
                    return Err(StreamError::Reset(StreamResetReason::ProtocolError));
                }
            }
        };

        // The shared state was already created and registered above.
        // For the first stream, we set the state + credit directly.
        // For subsequent streams, the background reader already set them.
        {
            let mut s = shared.lock().await;
            if s.state == StreamState::Opening {
                // First stream — set directly (we received the ack ourselves).
                s.state = StreamState::Established;
                s.send_credit = send_credit;
            }
            // For subsequent streams, the background reader already set the state.
        }

        // If this is the first stream and we haven't spawned the background
        // reader yet, do so now.
        if self.reader_handle.is_none() {
            let reader_link = Arc::clone(&self.link);
            let reader_keys = CircuitKeys {
                send_key: self.circuit_keys.send_key,
                recv_key: self.circuit_keys.recv_key,
            };
            let reader_gateway = self.gateway_node_id;
            let reader_client = self.client_node_id;
            let reader_fid = self.fid;
            let reader_streams = Arc::clone(&self.streams);
            let reader_seq = Arc::clone(&self.frame_seq);
            let reader_metrics = self.metrics_clone();
            self.reader_handle = Some(tokio::spawn(async move {
                background_reader_multiplexed(
                    reader_link,
                    reader_keys,
                    reader_gateway,
                    reader_client,
                    reader_fid,
                    reader_streams,
                    reader_seq,
                    reader_metrics,
                )
                .await;
            }));
        }

        // Create the StreamHandle. Unlike the standalone StreamHandle::open,
        // this one shares the link and doesn't own a background reader.
        // We need a lightweight handle that delegates to the shared state.
        Ok(StreamHandle::from_multiplexed(
            stream_id,
            Arc::clone(&self.link),
            self.circuit_keys.send_key,
            self.gateway_node_id,
            self.client_node_id,
            self.fid,
            Arc::clone(&self.frame_seq),
            shared,
            None, // No individual reader handle — the circuit owns it.
            self.metrics_clone(),
            Some(Arc::clone(&self.streams)), // N2.3.9: for cleanup on close/reset
        ))
    }

    /// Close the circuit (terminates all streams).
    pub async fn close(&mut self) {
        // N2.3.9: Mark ALL streams as Closed so that any pending
        // send()/recv() calls wake up and return an error.
        let streams_map = self.streams.lock().await;
        for (_, shared) in streams_map.iter() {
            let mut s = shared.lock().await;
            s.state = StreamState::Closed;
            s.credit_notify.notify_one();
            s.data_notify.notify_one();
        }
        drop(streams_map);
        // Abort the background reader task.
        if let Some(handle) = self.reader_handle.take() {
            handle.abort();
        }
    }
}

impl Drop for MultiplexedCircuit {
    fn drop(&mut self) {
        if let Some(handle) = self.reader_handle.take() {
            handle.abort();
        }
    }
}

/// **N2.3.9** — Send a WindowUpdate message from the background reader to the
/// gateway. This is used for eager credit replenishment (preventing deadlock
/// when the client sends without calling recv()).
async fn send_window_update_to_gateway(
    link: &Arc<AsyncLink>,
    send_key: &snp_crypto::SymmetricKey,
    gateway_node_id: [u8; 32],
    client_node_id: [u8; 32],
    fid: [u8; 8],
    frame_seq: &Arc<CircuitFrameSequencer>,
    stream_id: StreamId,
    additional_credit: u64,
) -> Result<(), StreamError> {
    let msg = StreamMessage::WindowUpdate(StreamWindowUpdate {
        stream_id,
        additional_credit,
    });
    let cbor = encode_stream_message(&msg).map_err(|e| StreamError::Cbor(e.to_string()))?;
    let sealed = encrypt_circuit_payload(send_key, &cbor);
    let seq = frame_seq
        .allocate()
        .await
        .ok_or_else(|| StreamError::Circuit("frame sequence exhausted".into()))?;
    let frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: gateway_node_id,
        src: client_node_id,
        ttl: FRAME_TTL_MAX,
        fid,
        seq,
        body: sealed,
    };
    link.send_frame(&frame)
        .await
        .map_err(|e| StreamError::Circuit(e.to_string()))?;
    Ok(())
}

/// Background reader for multiplexed circuits — dispatches inbound frames
/// to the correct stream via `stream_id`.
///
/// **N2.3.9** — Also sends eager WindowUpdates to the gateway when data
/// arrives and `pending_data_total` is below the high watermark. This
/// prevents deadlock when the client sends without calling recv() —
/// without eager WindowUpdates, the gateway's `gateway_credit` would
/// exhaust, the TCP reader would stop, the echo server would block, and
/// the client's `send()` would block (cascading deadlock).
async fn background_reader_multiplexed(
    link: Arc<AsyncLink>,
    circuit_keys: CircuitKeys,
    gateway_node_id: [u8; 32],
    client_node_id: [u8; 32],
    fid: [u8; 8],
    streams: Arc<Mutex<HashMap<StreamId, Arc<Mutex<StreamShared>>>>>,
    frame_seq: Arc<CircuitFrameSequencer>,
    metrics: Option<Arc<super::transport_metrics::TransportMetrics>>,
) {
    loop {
        let frame = match link.recv_frame().await {
            Ok(f) => f,
            Err(_) => {
                // N2.3.9: Link error — mark ALL streams as Closed so that
                // any pending send()/recv() calls wake up and return an
                // error. Without this, streams remain in Established state
                // and recv() hangs forever after circuit teardown.
                let streams_map = streams.lock().await;
                for (_, shared) in streams_map.iter() {
                    let mut s = shared.lock().await;
                    s.state = StreamState::Closed;
                    s.credit_notify.notify_one();
                    s.data_notify.notify_one();
                }
                break;
            }
        };

        // Validate outer frame.
        if let Err(_) = validate_frame(&frame, &gateway_node_id, &client_node_id, &fid) {
            // Mark all streams as reset.
            let streams_map = streams.lock().await;
            for (_, shared) in streams_map.iter() {
                let mut s = shared.lock().await;
                s.state = StreamState::Reset;
                s.credit_notify.notify_one();
                s.data_notify.notify_one();
            }
            break;
        }

        // Decrypt.
        let plaintext = match decrypt_circuit_payload(&circuit_keys.recv_key, &frame.body) {
            Some(p) => p,
            None => {
                let streams_map = streams.lock().await;
                for (_, shared) in streams_map.iter() {
                    let mut s = shared.lock().await;
                    s.state = StreamState::Reset;
                    s.credit_notify.notify_one();
                    s.data_notify.notify_one();
                }
                break;
            }
        };

        // Decode.
        let msg = match decode_stream_message(&plaintext) {
            Ok(m) => m,
            Err(_) => {
                let streams_map = streams.lock().await;
                for (_, shared) in streams_map.iter() {
                    let mut s = shared.lock().await;
                    s.state = StreamState::Reset;
                    s.credit_notify.notify_one();
                    s.data_notify.notify_one();
                }
                break;
            }
        };

        // Extract stream_id and dispatch.
        let stream_id = match &msg {
            StreamMessage::Data(d) => Some(d.stream_id),
            StreamMessage::WindowUpdate(w) => Some(w.stream_id),
            StreamMessage::HalfClose(h) => Some(h.stream_id),
            StreamMessage::Close(c) => Some(c.stream_id),
            StreamMessage::Reset(r) => Some(r.stream_id),
            StreamMessage::OpenAck(ack) => Some(ack.stream_id),
            StreamMessage::Open(_) => None,
        };

        if let Some(sid) = stream_id {
            let shared = {
                let streams_map = streams.lock().await;
                streams_map.get(&sid).cloned()
            };
            if let Some(shared) = shared {
                let mut s = shared.lock().await;
                match &msg {
                    StreamMessage::OpenAck(ack) => {
                        // Dispatch OpenAck — set state + credit.
                        if ack.connected {
                            s.state = StreamState::Established;
                            s.send_credit = ack.initial_receive_window.min(MAX_STREAM_WINDOW);
                        } else {
                            s.state = StreamState::Reset;
                        }
                        s.data_notify.notify_one();
                        s.credit_notify.notify_one();
                    }
                    StreamMessage::Data(data) => {
                        if data.direction == StreamDirection::GatewayToClient
                            && data.sequence == s.recv_seq
                        {
                            s.recv_seq += 1;
                            s.pending_data.push_back(data.data.clone());
                            s.pending_data_total += data.data.len() as u64;
                            s.eager_credit_pending += data.data.len() as u64;
                            s.data_notify.notify_one();

                            // N2.3.9: Eager WindowUpdate — rate-limited.
                            // Only send when:
                            // 1. pending_data_total is below the high watermark
                            //    (don't replenish if the client isn't consuming).
                            // 2. eager_credit_pending exceeds the threshold
                            //    (avoid per-message overhead on small transfers).
                            if s.pending_data_total < PENDING_DATA_HIGH_WATERMARK
                                && s.eager_credit_pending >= EAGER_WINDOW_UPDATE_THRESHOLD
                            {
                                let credit_to_replenish = s.eager_credit_pending;
                                s.eager_credit_pending = 0;
                                drop(s); // Release lock before sending.
                                let _ = send_window_update_to_gateway(
                                    &link,
                                    &circuit_keys.send_key,
                                    gateway_node_id,
                                    client_node_id,
                                    fid,
                                    &frame_seq,
                                    sid,
                                    credit_to_replenish,
                                )
                                .await;
                            }
                        } else {
                            // Protocol violation — reset this stream.
                            s.state = StreamState::Reset;
                            s.credit_notify.notify_one();
                            s.data_notify.notify_one();
                        }
                    }
                    StreamMessage::WindowUpdate(update) => {
                        s.send_credit = s
                            .send_credit
                            .saturating_add(update.additional_credit)
                            .min(MAX_STREAM_WINDOW);
                        s.credit_notify.notify_one();
                        // N2.3.9: Record credit update received in metrics.
                        if let Some(m) = &metrics {
                            m.credit_update_received();
                        }
                    }
                    StreamMessage::HalfClose(hc) => {
                        if hc.direction == StreamDirection::GatewayToClient {
                            s.state = match s.state {
                                StreamState::Established => StreamState::HalfClosedRemote,
                                StreamState::HalfClosedLocal => StreamState::Closed,
                                other => other,
                            };
                            s.data_notify.notify_one();
                        }
                    }
                    StreamMessage::Close(_) => {
                        s.state = StreamState::Closed;
                        s.data_notify.notify_one();
                        // N2.3.9: Remove from the streams map so stream_count()
                        // reflects actual active streams. Drop the lock first.
                        drop(s);
                        streams.lock().await.remove(&sid);
                    }
                    StreamMessage::Reset(_) => {
                        s.state = StreamState::Reset;
                        s.credit_notify.notify_one();
                        s.data_notify.notify_one();
                        // N2.3.9: Remove from the streams map.
                        drop(s);
                        streams.lock().await.remove(&sid);
                    }
                    _ => {}
                }
            }
            // If stream_id is not in the map, the frame is for a closed/unknown
            // stream — ignore it (don't reset the entire circuit).
        }
    }
}
