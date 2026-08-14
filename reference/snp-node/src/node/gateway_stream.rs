//! **N2.2.5 — Gateway-side Mode B stream handler.**
//!
//! This module implements the gateway side of the Mode B streaming circuit
//! data plane. When the gateway receives a `StreamOpen` message inside the
//! encrypted circuit payload, it:
//!
//! 1. Validates the destination through the existing N2.2.4 SSRF/egress
//!    policy (`is_private_destination`, `validate_port`).
//! 2. Opens a real TCP socket to the validated destination.
//! 3. Relays bytes bidirectionally between the circuit and the TCP socket.
//! 4. Handles half-close, flow control, and reset.
//!
//! ## Security
//!
//! The gateway reuses the N2.2.4 SSRF defence **verbatim**:
//! - `is_private_destination(host)` — checks the literal host string.
//! - `is_private_ip_str(ip)` — checks the resolved IP.
//! - `validate_port(scheme, port)` — only allows port 80 (HTTP) and 443 (HTTPS)
//!   by default.
//!
//! The destination IP/port are inside the encrypted circuit payload — relays
//! B/C cannot see them.
//!
//! ## What this does NOT do
//!
//! - HTTP parsing — this is a raw TCP byte stream.
//! - DNS resolution — the `StreamOpen` contains an IP address, not a hostname.
//!   DNS is handled by the TUN DNS interception layer (N2.3.4).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use snp_gateway::stream::{
    InternetEndpoint, StreamClose, StreamData, StreamDirection, StreamHalfClose, StreamId,
    StreamMessage, StreamOpen, StreamOpenAck, StreamReset, StreamResetReason, StreamState,
    StreamWindowUpdate, DEFAULT_RECEIVE_WINDOW, MAX_STREAM_DATA_PAYLOAD,
};
use snp_gateway::{is_private_destination, is_private_ip_str, validate_port, GatewayError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;

/// A gateway-side stream entry — holds the TCP socket and stream state.
pub struct GatewayStream {
    /// The stream ID (from the client's StreamOpen).
    pub stream_id: StreamId,
    /// The real TCP socket to the destination.
    pub tcp_socket: Option<TokioTcpStream>,
    /// The current stream state.
    pub state: StreamState,
    /// The next sequence number to use when sending data TO the client
    /// (gateway → client direction).
    pub send_seq: u64,
    /// The highest sequence number seen FROM the client (client → gateway
    /// direction). Used for duplicate rejection.
    pub recv_seq: u64,
    /// Bytes the client can still send before needing a WindowUpdate.
    pub client_credit: u64,
    /// Bytes the gateway can still send before needing a WindowUpdate from
    /// the client.
    pub gateway_credit: u64,
    /// The destination endpoint (for logging/diagnostics).
    pub destination: InternetEndpoint,
}

impl std::fmt::Debug for GatewayStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayStream")
            .field("stream_id", &self.stream_id)
            .field("state", &self.state)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("client_credit", &self.client_credit)
            .field("gateway_credit", &self.gateway_credit)
            .finish_non_exhaustive()
    }
}

/// The gateway stream table — maps stream IDs to active streams.
#[derive(Debug)]
pub struct GatewayStreamTable {
    streams: Arc<Mutex<HashMap<StreamId, GatewayStream>>>,
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
    /// This is the entry point for Mode B. The gateway validates the
    /// destination through the existing N2.2.4 SSRF policy BEFORE opening
    /// the TCP socket.
    pub async fn handle_stream_open(
        &self,
        open: StreamOpen,
    ) -> Result<StreamOpenAck, GatewayError> {
        // 1. Validate the destination through the existing SSRF policy.
        let endpoint = &open.destination;
        let ip_str = endpoint.address.to_string();

        // Check the literal IP (not hostname — StreamOpen carries an IP, not
        // a DNS name, to keep DNS resolution at the TUN layer).
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

        // 2. Validate the port — only 80 and 443 are allowed by default.
        //    For Mode B, we use "http" for port 80 and "https" for port 443.
        let scheme = if endpoint.port == 443 { "https" } else { "http" };
        if let Err(e) = validate_port(scheme, endpoint.port) {
            return Ok(StreamOpenAck {
                stream_id: open.stream_id,
                initial_receive_window: 0,
                connected: false,
                error: Some(format!("port policy: {e}")),
            });
        }

        // 3. Open a real TCP socket to the validated destination.
        let sock_addr = SocketAddr::new(endpoint.address, endpoint.port);
        let tcp_socket = match TokioTcpStream::connect(&sock_addr).await {
            Ok(socket) => socket,
            Err(e) => {
                return Ok(StreamOpenAck {
                    stream_id: open.stream_id,
                    initial_receive_window: 0,
                    connected: false,
                    error: Some(format!("TCP connect to {sock_addr}: {e}")),
                });
            }
        };

        // 4. Insert the stream into the table.
        let mut streams = self.streams.lock().await;
        let stream = GatewayStream {
            stream_id: open.stream_id,
            tcp_socket: Some(tcp_socket),
            state: StreamState::Established,
            send_seq: 0,
            recv_seq: 0,
            client_credit: open.initial_receive_window,
            gateway_credit: DEFAULT_RECEIVE_WINDOW,
            destination: open.destination.clone(),
        };
        streams.insert(open.stream_id, stream);

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
    /// Returns an error if the stream doesn't exist, the sequence is stale/
    /// duplicate, or the data exceeds the credit window.
    pub async fn handle_stream_data(
        &self,
        data: StreamData,
    ) -> Result<(), GatewayError> {
        let mut streams = self.streams.lock().await;
        let stream = streams
            .get_mut(&data.stream_id)
            .ok_or_else(|| {
                GatewayError::MalformedRequest(format!(
                    "StreamData for unknown stream_id {}",
                    data.stream_id
                ))
            })?;

        // Validate direction — client → gateway data must have direction
        // ClientToGateway.
        if data.direction != StreamDirection::ClientToGateway {
            return Err(GatewayError::MalformedRequest(format!(
                "StreamData from client with wrong direction {:?}",
                data.direction
            )));
        }

        // Validate sequence — must be exactly recv_seq (next expected).
        // Duplicate or stale sequences are rejected.
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

        // Validate flow control — don't exceed the credit.
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

        Ok(())
    }

    /// Read data from the TCP socket and produce a `StreamData` message to
    /// send back to the client.
    ///
    /// Returns `Ok(None)` if no data is available or the stream is closed.
    pub async fn read_from_tcp(
        &self,
        stream_id: StreamId,
    ) -> Result<Option<StreamData>, GatewayError> {
        let mut streams = self.streams.lock().await;
        let stream = streams
            .get_mut(&stream_id)
            .ok_or_else(|| {
                GatewayError::MalformedRequest(format!(
                    "read_from_tcp: unknown stream_id {stream_id}"
                ))
            })?;

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
                // EOF — the remote end closed the connection.
                stream.state = StreamState::HalfClosedRemote;
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
        let mut streams = self.streams.lock().await;
        if let Some(stream) = streams.get_mut(&hc.stream_id) {
            if hc.direction == StreamDirection::ClientToGateway {
                // Client half-closed — shut down the write side of the TCP socket.
                if let Some(socket) = stream.tcp_socket.as_mut() {
                    let _ = socket.shutdown().await;
                }
                stream.state = match stream.state {
                    StreamState::Established => StreamState::HalfClosedLocal,
                    StreamState::HalfClosedRemote => StreamState::Closed,
                    other => other,
                };
            }
        }
        Ok(())
    }

    /// Process a `StreamClose` — clean close.
    pub async fn handle_close(&self, close: StreamClose) -> Result<(), GatewayError> {
        let mut streams = self.streams.lock().await;
        if let Some(mut stream) = streams.remove(&close.stream_id) {
            if let Some(socket) = stream.tcp_socket.as_mut() {
                let _ = socket.shutdown().await;
            }
            stream.state = StreamState::Closed;
        }
        Ok(())
    }

    /// Process a `StreamReset` — abort the stream.
    pub async fn handle_reset(&self, reset: StreamReset) -> Result<(), GatewayError> {
        let mut streams = self.streams.lock().await;
        if let Some(mut stream) = streams.remove(&reset.stream_id) {
            if let Some(socket) = stream.tcp_socket.as_mut() {
                let _ = socket.shutdown().await;
            }
            stream.state = StreamState::Reset;
        }
        Ok(())
    }

    /// Returns the number of active streams.
    pub async fn stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// Returns the state of a stream, if it exists.
    pub async fn stream_state(&self, stream_id: StreamId) -> Option<StreamState> {
        self.streams.lock().await.get(&stream_id).map(|s| s.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn stream_open_to_private_ip_rejected() {
        let table = GatewayStreamTable::new();
        let open = StreamOpen {
            stream_id: 1,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 80,
                protocol: snp_gateway::stream::TransportProtocol::Tcp,
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
                protocol: snp_gateway::stream::TransportProtocol::Tcp,
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
                port: 22, // SSH port — not allowed
                protocol: snp_gateway::stream::TransportProtocol::Tcp,
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
        // Insert a mock stream (without a real TCP socket — we're testing
        // sequence validation, not TCP).
        {
            let mut streams = table.streams.lock().await;
            streams.insert(
                1,
                GatewayStream {
                    stream_id: 1,
                    tcp_socket: None,
                    state: StreamState::Established,
                    send_seq: 0,
                    recv_seq: 5, // Expecting seq=5 next.
                    client_credit: 65536,
                    gateway_credit: 65536,
                    destination: InternetEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        port: 80,
                        protocol: snp_gateway::stream::TransportProtocol::Tcp,
                    },
                },
            );
        }

        // Send data with seq=3 (stale — expected 5).
        let data = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 3,
            data: b"hello".to_vec(),
        };

        let result = table.handle_stream_data(data).await;
        assert!(
            result.is_err(),
            "stale sequence must be rejected"
        );
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
}
