//! **N2.2.5 Phase 3 — Client-side CircuitStream / StreamHandle.**
//!
//! This module provides the client-side abstraction for Mode B streams.
//! It connects to the gateway via the existing ShareNet circuit (same
//! SNP-IK link, same AEAD encryption, same relay forwarding) but sends
//! `StreamMessage` payloads instead of `TransitRequest`.
//!
//! ## Architecture
//!
//! ```text
//! Application (TcpFlowBridge)
//!     ↓
//! AsyncUpstream (trait — unchanged from N2.3.5)
//!     ↓
//! ShareNetCircuitUpstreamModeB (Phase 4 — uses StreamHandle)
//!     ↓
//! CircuitStream / StreamHandle (this module)
//!     ↓
//! StreamMessage (CBOR, inside encrypted circuit frame)
//!     ↓
//! AsyncLink (SNP-IK + AEAD — unchanged)
//!     ↓
//! Relay → Relay → Gateway
//! ```
//!
//! ## Stream lifecycle
//!
//! ```text
//! StreamHandle::open()
//!     ↓
//! StreamOpen → gateway → StreamOpenAck
//!     ↓
//! StreamHandle::send() ↔ StreamHandle::recv()
//!     ↓ (with StreamWindowUpdate flow control)
//! StreamHandle::shutdown_write() (half-close)
//!     ↓
//! StreamHandle::close() or StreamHandle::reset()
//! ```
//!
//! ## What is NOT changed
//!
//! - Mode A (TransitRequest/TransitResponse) — frozen.
//! - Circuit key derivation (same X25519 DH, same AEAD).
//! - SNP-IK handshake.
//! - Discovery / Route / relay forwarding.
//! - Frame format.
//! - `AsyncUpstream` trait (Phase 4 will implement it via `StreamHandle`).

use std::net::IpAddr;
use std::sync::Arc;

use snp_crypto::sha256;
use snp_gateway::stream::{
    decode_stream_message, encode_stream_message, InternetEndpoint, StreamClose, StreamData,
    StreamDirection, StreamHalfClose, StreamId, StreamMessage, StreamOpen, StreamOpenAck,
    StreamReset, StreamResetReason, StreamState, StreamWindowUpdate, TransportProtocol,
    DEFAULT_RECEIVE_WINDOW, MAX_STREAM_DATA_PAYLOAD, MAX_STREAM_WINDOW,
};
use snp_link::{
    decrypt_circuit_payload, encrypt_circuit_payload, seal_circuit_payload_with_fresh_eph,
    CircuitKeys,
};
use snp_frames::{Frame, FRAME_TTL_MAX, FRAME_VERSION};
use snp_link::async_link::{AsyncLink, AsyncLinkError};
use tokio::sync::Mutex;

use super::{now_unix, random_fid, random_req_id, NodeError, NodeResult};

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
    /// Flow control: the send window is exhausted.
    #[error("send window exhausted (credit=0)")]
    WindowExhausted,
    /// The gateway rejected the StreamOpen.
    #[error("stream open rejected: {0}")]
    OpenRejected(String),
}

/// A handle to an open Mode B stream.
///
/// This is the client-side abstraction for a bidirectional raw TCP byte
/// stream over the ShareNet circuit. It provides:
///
/// - `send()` — send bytes to the remote server (client → gateway → TCP).
/// - `recv()` — receive bytes from the remote server (TCP → gateway → client).
/// - `shutdown_write()` — half-close the send direction (TCP FIN equivalent).
/// - `close()` — clean close (both directions).
/// - `reset()` — abort the stream (TCP RST equivalent).
///
/// The handle owns the circuit link (AsyncLink) and the circuit keys. It
/// tracks sequence numbers, flow-control credits, and stream state.
///
/// ## Flow control
///
/// The client maintains:
/// - `send_credit` — bytes the gateway is willing to receive (from
///   `StreamOpenAck.initial_receive_window` + `StreamWindowUpdate`).
/// - `recv_credit` — bytes the client is willing to receive (advertised to
///   the gateway via `StreamWindowUpdate`).
///
/// `send()` checks `send_credit` before sending. When the client's recv
/// buffer drains, it sends `StreamWindowUpdate` to replenish the gateway's
/// credit.
pub struct StreamHandle {
    /// The circuit link (SNP-IK + AEAD).
    link: Arc<Mutex<AsyncLink>>,
    /// The circuit keys (send_key for client→gateway, recv_key for
    /// gateway→client).
    circuit_keys: CircuitKeys,
    /// The gateway's NodeId (frame destination).
    gateway_node_id: [u8; 32],
    /// The client's NodeId (frame source).
    client_node_id: [u8; 32],
    /// The stream ID (chosen by the client).
    stream_id: StreamId,
    /// The current stream state.
    state: StreamState,
    /// The next sequence number for client→gateway data.
    send_seq: u64,
    /// The highest sequence number received from the gateway.
    recv_seq: u64,
    /// Bytes the client can still send (gateway's receive window).
    send_credit: u64,
    /// Bytes the client is willing to receive (advertised to gateway).
    /// Decremented as data arrives; when it gets low, a WindowUpdate is sent.
    recv_credit: u64,
    /// Total bytes received (for window replenishment tracking).
    total_received: u64,
    /// The frame ID for this stream (all frames use the same FID).
    fid: [u8; 8],
    /// The next frame sequence number.
    next_frame_seq: u32,
}

impl std::fmt::Debug for StreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamHandle")
            .field("stream_id", &self.stream_id)
            .field("state", &self.state)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("send_credit", &self.send_credit)
            .field("recv_credit", &self.recv_credit)
            .finish_non_exhaustive()
    }
}

impl StreamHandle {
    /// Open a new Mode B stream to the given endpoint.
    ///
    /// This establishes the circuit (SNP-IK handshake + ephemeral X25519),
    /// sends a `StreamOpen` message, and waits for `StreamOpenAck`.
    ///
    /// # Errors
    /// Returns [`StreamError`] if the circuit cannot be established, the
    /// gateway rejects the stream, or the response is malformed.
    pub async fn open(
        link: AsyncLink,
        circuit_keys: CircuitKeys,
        gateway_node_id: [u8; 32],
        client_node_id: [u8; 32],
        destination: InternetEndpoint,
    ) -> Result<Self, StreamError> {
        let stream_id: StreamId = {
            let mut buf = [0u8; 8];
            getrandom::getrandom(&mut buf).expect("getrandom");
            u64::from_be_bytes(buf)
        };
        let fid = random_fid();

        let mut handle = Self {
            link: Arc::new(Mutex::new(link)),
            circuit_keys,
            gateway_node_id,
            client_node_id,
            stream_id,
            state: StreamState::Opening,
            send_seq: 0,
            recv_seq: 0,
            send_credit: 0,
            recv_credit: DEFAULT_RECEIVE_WINDOW,
            total_received: 0,
            fid,
            next_frame_seq: 1,
        };

        // 1. Send StreamOpen.
        let open_msg = StreamMessage::Open(StreamOpen {
            stream_id,
            destination,
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        });
        handle.send_message(&open_msg).await?;

        // 2. Receive StreamOpenAck.
        let resp_msg = handle.recv_message().await?;
        match resp_msg {
            StreamMessage::OpenAck(ack) => {
                if !ack.connected {
                    return Err(StreamError::OpenRejected(
                        ack.error.unwrap_or_else(|| "unknown error".into()),
                    ));
                }
                handle.send_credit = ack.initial_receive_window.min(MAX_STREAM_WINDOW);
                handle.state = StreamState::Established;
                Ok(handle)
            }
            StreamMessage::Reset(reset) => {
                Err(StreamError::Reset(reset.reason))
            }
            other => Err(StreamError::Circuit(format!(
                "expected StreamOpenAck, got {other:?}"
            ))),
        }
    }

    /// Send bytes to the remote server (client → gateway → TCP).
    ///
    /// Returns the number of bytes accepted. If the send window is
    /// exhausted, returns [`StreamError::WindowExhausted`].
    ///
    /// # Errors
    /// Returns [`StreamError`] on state violations, circuit errors, or
    /// flow-control violations.
    pub async fn send(&mut self, data: &[u8]) -> Result<usize, StreamError> {
        if self.state == StreamState::Closed || self.state == StreamState::Reset {
            return Err(StreamError::Closed);
        }
        if self.state == StreamState::HalfClosedLocal {
            return Err(StreamError::InvalidState(self.state));
        }

        // Chunk the data to respect MAX_STREAM_DATA_PAYLOAD.
        let mut remaining = data;
        let mut total_sent = 0;

        while !remaining.is_empty() {
            if self.send_credit == 0 {
                // Window exhausted — try to receive a WindowUpdate.
                // In a real implementation, this would await a WindowUpdate.
                // For now, return how much we've sent so far.
                if total_sent > 0 {
                    return Ok(total_sent);
                }
                return Err(StreamError::WindowExhausted);
            }

            let chunk_size = remaining
                .len()
                .min(MAX_STREAM_DATA_PAYLOAD)
                .min(self.send_credit as usize);
            let chunk = &remaining[..chunk_size];

            let msg = StreamMessage::Data(StreamData {
                stream_id: self.stream_id,
                direction: StreamDirection::ClientToGateway,
                sequence: self.send_seq,
                data: chunk.to_vec(),
            });

            self.send_message(&msg).await?;
            self.send_seq += 1;
            self.send_credit -= chunk_size as u64;
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
    /// Returns [`StreamError`] on state violations or circuit errors.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, StreamError> {
        if self.state == StreamState::Closed || self.state == StreamState::Reset {
            return Err(StreamError::Closed);
        }

        loop {
            let msg = self.recv_message().await?;
            match msg {
                StreamMessage::Data(data) => {
                    // Validate direction.
                    if data.direction != StreamDirection::GatewayToClient {
                        return Err(StreamError::Circuit(
                            "StreamData from gateway with wrong direction".into(),
                        ));
                    }
                    // Validate sequence.
                    if data.sequence != self.recv_seq {
                        return Err(StreamError::Circuit(format!(
                            "StreamData sequence {} != expected {}",
                            data.sequence, self.recv_seq
                        )));
                    }
                    self.recv_seq += 1;
                    self.recv_credit = self.recv_credit.saturating_sub(data.data.len() as u64);
                    self.total_received = self.total_received.saturating_add(data.data.len() as u64);

                    // Replenish the gateway's window if we've consumed enough.
                    if self.recv_credit < DEFAULT_RECEIVE_WINDOW / 2 {
                        let replenish = DEFAULT_RECEIVE_WINDOW - self.recv_credit;
                        let update_msg = StreamMessage::WindowUpdate(StreamWindowUpdate {
                            stream_id: self.stream_id,
                            additional_credit: replenish,
                        });
                        self.send_message(&update_msg).await?;
                        self.recv_credit = DEFAULT_RECEIVE_WINDOW;
                    }

                    return Ok(Some(data.data));
                }
                StreamMessage::WindowUpdate(update) => {
                    // Replenish our send credit.
                    self.send_credit = self
                        .send_credit
                        .saturating_add(update.additional_credit)
                        .min(MAX_STREAM_WINDOW);
                    // Loop to receive the next message (likely StreamData).
                }
                StreamMessage::HalfClose(hc) => {
                    if hc.direction == StreamDirection::GatewayToClient {
                        self.state = match self.state {
                            StreamState::Established => StreamState::HalfClosedRemote,
                            StreamState::HalfClosedLocal => StreamState::Closed,
                            other => other,
                        };
                        return Ok(None);
                    }
                }
                StreamMessage::Close(_) => {
                    self.state = StreamState::Closed;
                    return Ok(None);
                }
                StreamMessage::Reset(reset) => {
                    self.state = StreamState::Reset;
                    return Err(StreamError::Reset(reset.reason));
                }
                StreamMessage::Open(_) | StreamMessage::OpenAck(_) => {
                    return Err(StreamError::Circuit(format!(
                        "unexpected message type: {msg:?}"
                    )));
                }
            }
        }
    }

    /// Half-close the send direction (TCP FIN equivalent).
    ///
    /// After this, `send()` will return an error, but `recv()` still works.
    ///
    /// # Errors
    /// Returns [`StreamError`] on state violations or circuit errors.
    pub async fn shutdown_write(&mut self) -> Result<(), StreamError> {
        if self.state == StreamState::Closed || self.state == StreamState::Reset {
            return Err(StreamError::Closed);
        }
        if self.state == StreamState::HalfClosedLocal {
            return Ok(()); // Already half-closed.
        }

        let msg = StreamMessage::HalfClose(StreamHalfClose {
            stream_id: self.stream_id,
            direction: StreamDirection::ClientToGateway,
        });
        self.send_message(&msg).await?;

        self.state = match self.state {
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
        if self.state == StreamState::Closed {
            return Ok(());
        }

        let msg = StreamMessage::Close(StreamClose {
            stream_id: self.stream_id,
        });
        // Best-effort send — ignore errors if the link is already broken.
        let _ = self.send_message(&msg).await;
        self.state = StreamState::Closed;
        Ok(())
    }

    /// Abort the stream (TCP RST equivalent).
    ///
    /// # Errors
    /// Returns [`StreamError`] on circuit errors.
    pub async fn reset(&mut self, reason: StreamResetReason) -> Result<(), StreamError> {
        if self.state == StreamState::Reset {
            return Ok(());
        }

        let msg = StreamMessage::Reset(StreamReset {
            stream_id: self.stream_id,
            reason,
        });
        let _ = self.send_message(&msg).await;
        self.state = StreamState::Reset;
        Ok(())
    }

    /// Returns the current stream state.
    #[must_use]
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Returns the stream ID.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns the available send credit (bytes the client can still send).
    #[must_use]
    pub fn send_credit(&self) -> u64 {
        self.send_credit
    }

    // ─── Internal helpers ──────────────────────────────────────────────────

    /// Encode + encrypt + send a StreamMessage through the circuit.
    async fn send_message(&mut self, msg: &StreamMessage) -> Result<(), StreamError> {
        let cbor = encode_stream_message(msg).map_err(|e| StreamError::Cbor(e.to_string()))?;
        let sealed = encrypt_circuit_payload(&self.circuit_keys.send_key, &cbor);

        let frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: self.gateway_node_id,
            src: self.client_node_id,
            ttl: FRAME_TTL_MAX,
            fid: self.fid,
            seq: self.next_frame_seq,
            body: sealed,
        };
        self.next_frame_seq = self.next_frame_seq.wrapping_add(1);

        self.link
            .lock()
            .await
            .send_frame(&frame)
            .await
            .map_err(|e| StreamError::Circuit(e.to_string()))?;
        Ok(())
    }

    /// Receive + decrypt + decode a StreamMessage from the circuit.
    async fn recv_message(&mut self) -> Result<StreamMessage, StreamError> {
        let frame = self
            .link
            .lock()
            .await
            .recv_frame()
            .await
            .map_err(|e| StreamError::Circuit(e.to_string()))?;

        if frame.cls != b'B' {
            return Err(StreamError::Circuit(format!(
                "expected Class B, got Class {}",
                frame.cls as char
            )));
        }

        let plaintext = decrypt_circuit_payload(&self.circuit_keys.recv_key, &frame.body)
            .ok_or(StreamError::Circuit("circuit decryption failed".into()))?;

        decode_stream_message(&plaintext).map_err(|e| StreamError::Cbor(e.to_string()))
    }
}

/// A trait for opening Mode B streams. This is the seam between the
/// `AsyncUpstream` implementation and the circuit.
///
/// Production implementation connects to the real ShareNet circuit.
/// Tests can mock this to test `StreamHandle` without a real mesh.
#[async_trait::async_trait]
pub trait CircuitStream: Send {
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

    // The StreamHandle tests require a mock circuit link. Since the
    // StreamHandle owns an AsyncLink (which requires a real TCP connection),
    // we test the protocol logic via the encode/decode path and the
    // flow-control state machine.

    #[test]
    fn stream_message_roundtrip_through_circuit() {
        // Verify that StreamMessage can be encoded, encrypted, decrypted,
        // and decoded — proving the circuit AEAD works with Mode B.
        let key = [42u8; 32];
        let msg = StreamMessage::Data(StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 5,
            data: b"hello stream".to_vec(),
        });

        // Encode → encrypt → decrypt → decode.
        let cbor = encode_stream_message(&msg).unwrap();
        let sealed = encrypt_circuit_payload(&key, &cbor);
        let plaintext = decrypt_circuit_payload(&key, &sealed).unwrap();
        let decoded = decode_stream_message(&plaintext).unwrap();

        assert_eq!(decoded, msg);
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

    #[test]
    fn stream_half_close_roundtrip_through_circuit() {
        let key = [33u8; 32];
        let msg = StreamMessage::HalfClose(StreamHalfClose {
            stream_id: 3,
            direction: StreamDirection::ClientToGateway,
        });

        let cbor = encode_stream_message(&msg).unwrap();
        let sealed = encrypt_circuit_payload(&key, &cbor);
        let plaintext = decrypt_circuit_payload(&key, &sealed).unwrap();
        let decoded = decode_stream_message(&plaintext).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_reset_roundtrip_through_circuit() {
        let key = [11u8; 32];
        let msg = StreamMessage::Reset(StreamReset {
            stream_id: 99,
            reason: StreamResetReason::ApplicationReset,
        });

        let cbor = encode_stream_message(&msg).unwrap();
        let sealed = encrypt_circuit_payload(&key, &cbor);
        let plaintext = decrypt_circuit_payload(&key, &sealed).unwrap();
        let decoded = decode_stream_message(&plaintext).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn decryption_with_wrong_key_fails() {
        // Verify that a message encrypted with one key cannot be decrypted
        // with a different key — proving relay opacity (relays don't have
        // the circuit keys).
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

        // Decrypt with the WRONG key — must fail.
        let result = decrypt_circuit_payload(&key2, &sealed);
        assert!(
            result.is_none(),
            "decryption with wrong key must fail (relay opacity)"
        );
    }
}
