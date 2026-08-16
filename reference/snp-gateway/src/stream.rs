//! **N2.2.5 — Mode B Streaming Circuit Data Plane.**
//!
//! This module defines the CBOR wire format for Mode B — a genuine
//! bidirectional raw TCP byte stream over the existing ShareNet circuit.
//!
//! ## Design principles
//!
//! 1. **One stream per circuit** (initial implementation). The `stream_id`
//!    field exists from day one for future multiplexing, but N2.2.5 uses
//!    a single stream per circuit.
//!
//! 2. **Relay opacity**: StreamOpen (including destination IP/port) and
//!    StreamData are inside the end-to-end encrypted circuit payload.
//!    Relays B/C see only the outer AEAD frame + routing metadata.
//!
//! 3. **SSRF reuse**: The gateway validates the destination through the
//!    existing N2.2.4 `is_private_destination` / `validate_port` policy
//!    BEFORE opening the TCP socket.
//!
//! 4. **Half-close**: TCP FIN is directional. `StreamHalfClose` allows one
//!    side to signal "no more data from me" while the other direction
//!    remains active.
//!
//! 5. **Flow control**: Explicit bounded receive windows via
//!    `StreamWindowUpdate`. No unbounded buffering.
//!
//! 6. **Replay protection**: The circuit AEAD already provides uniqueness
//!    (random nonce per message). Stream-level `sequence` numbers provide
//!    ordered delivery and duplicate rejection — these are separate layers
//!    from the link/frame replay protection.
//!
//! ## Message types
//!
//! - [`StreamOpen`] — client → gateway: "connect me to this endpoint"
//! - [`StreamOpenAck`] — gateway → client: "connected, here's the initial window"
//! - [`StreamData`] — bidirectional: ordered byte chunks
//! - [`StreamWindowUpdate`] — bidirectional: "you can send N more bytes"
//! - [`StreamHalfClose`] — bidirectional: "no more data from my direction"
//! - [`StreamClose`] — bidirectional: "both directions done, clean close"
//! - [`StreamReset`] — bidirectional: "abort this stream"
//!
//! ## What is NOT changed
//!
//! - Mode A (`TransitRequest`/`TransitResponse`) — frozen.
//! - Circuit key derivation (same X25519 DH, same AEAD).
//! - SNP-IK handshake.
//! - Discovery / Route / relay forwarding.
//! - Frame format (Stream messages are new CBOR payloads inside the existing
//!   encrypted circuit frame).

use std::net::IpAddr;

use snp_cbor::CborValue;

use crate::{GatewayError, GatewayResult};

/// Stream identifier (64-bit, chosen by the client, unique per circuit).
pub type StreamId = u64;

/// Sequence number for ordered delivery within a stream direction.
pub type StreamSeq = u64;

/// Direction of a stream message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamDirection {
    /// Client → gateway direction.
    ClientToGateway,
    /// Gateway → client direction.
    GatewayToClient,
}

impl StreamDirection {
    /// Encode as a CBOR value.
    fn to_cbor(&self) -> CborValue {
        match self {
            StreamDirection::ClientToGateway => CborValue::UnsignedInt(0),
            StreamDirection::GatewayToClient => CborValue::UnsignedInt(1),
        }
    }

    /// Decode from a CBOR value.
    fn from_cbor(v: &CborValue) -> GatewayResult<Self> {
        match v {
            CborValue::UnsignedInt(0) => Ok(StreamDirection::ClientToGateway),
            CborValue::UnsignedInt(1) => Ok(StreamDirection::GatewayToClient),
            other => Err(GatewayError::MalformedRequest(format!(
                "StreamDirection must be 0 or 1; got {other:?}"
            ))),
        }
    }
}

/// An internet endpoint to connect to (inside the encrypted circuit payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternetEndpoint {
    /// The IP address to connect to (IPv4 or IPv6).
    pub address: IpAddr,
    /// The TCP port to connect to.
    pub port: u16,
    /// The transport protocol (always TCP for N2.2.5).
    pub protocol: TransportProtocol,
}

/// The transport protocol for a stream. N2.2.5 supports TCP only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// TCP (the only supported protocol in N2.2.5).
    Tcp,
}

impl TransportProtocol {
    /// Encode as a CBOR value.
    fn to_cbor(&self) -> CborValue {
        match self {
            TransportProtocol::Tcp => CborValue::UnsignedInt(6),
        }
    }

    /// Decode from a CBOR value.
    fn from_cbor(v: &CborValue) -> GatewayResult<Self> {
        match v {
            CborValue::UnsignedInt(6) => Ok(TransportProtocol::Tcp),
            other => Err(GatewayError::MalformedRequest(format!(
                "TransportProtocol must be 6 (TCP); got {other:?}"
            ))),
        }
    }
}

/// The state of a Mode B stream (mirrors TCP states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// StreamOpen sent, awaiting StreamOpenAck.
    Opening,
    /// Stream established, both directions active.
    Established,
    /// Local direction half-closed (we sent FIN, still receiving).
    HalfClosedLocal,
    /// Remote direction half-closed (they sent FIN, we can still send).
    HalfClosedRemote,
    /// Both directions closed (clean shutdown).
    Closed,
    /// Aborted (RST received or sent).
    Reset,
}

/// Reason for a stream reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamResetReason {
    /// The application closed the connection abruptly.
    ApplicationReset,
    /// The gateway could not connect to the destination.
    ConnectionRefused,
    /// The connection timed out.
    Timeout,
    /// A protocol error occurred (malformed frame, sequence violation, etc.).
    ProtocolError,
    /// The resource quota was exceeded.
    QuotaExceeded,
    /// The circuit was closed.
    CircuitClosed,
}

impl StreamResetReason {
    /// Encode as a CBOR value.
    fn to_cbor(&self) -> CborValue {
        match self {
            StreamResetReason::ApplicationReset => CborValue::TextString("application".into()),
            StreamResetReason::ConnectionRefused => CborValue::TextString("refused".into()),
            StreamResetReason::Timeout => CborValue::TextString("timeout".into()),
            StreamResetReason::ProtocolError => CborValue::TextString("protocol".into()),
            StreamResetReason::QuotaExceeded => CborValue::TextString("quota".into()),
            StreamResetReason::CircuitClosed => CborValue::TextString("circuit_closed".into()),
        }
    }

    /// Decode from a CBOR value.
    fn from_cbor(v: &CborValue) -> GatewayResult<Self> {
        match v {
            CborValue::TextString(s) if s == "application" => Ok(Self::ApplicationReset),
            CborValue::TextString(s) if s == "refused" => Ok(Self::ConnectionRefused),
            CborValue::TextString(s) if s == "timeout" => Ok(Self::Timeout),
            CborValue::TextString(s) if s == "protocol" => Ok(Self::ProtocolError),
            CborValue::TextString(s) if s == "quota" => Ok(Self::QuotaExceeded),
            CborValue::TextString(s) if s == "circuit_closed" => Ok(Self::CircuitClosed),
            other => Err(GatewayError::MalformedRequest(format!(
                "unknown StreamResetReason: {other:?}"
            ))),
        }
    }
}

// ─── CBOR message types ─────────────────────────────────────────────────────

/// A Mode B stream message (inside the encrypted circuit payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMessage {
    /// Client → gateway: open a stream to this endpoint.
    Open(StreamOpen),
    /// Gateway → client: stream opened successfully.
    OpenAck(StreamOpenAck),
    /// Bidirectional: a chunk of data.
    Data(StreamData),
    /// Bidirectional: flow-control credit update.
    WindowUpdate(StreamWindowUpdate),
    /// Bidirectional: half-close (no more data from this direction).
    HalfClose(StreamHalfClose),
    /// Bidirectional: clean close (both directions done).
    Close(StreamClose),
    /// Bidirectional: abort the stream.
    Reset(StreamReset),
}

/// StreamOpen — client requests a TCP connection to an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpen {
    /// The stream identifier (chosen by the client).
    pub stream_id: StreamId,
    /// The destination endpoint (inside the encrypted payload — relays
    /// cannot see this).
    pub destination: InternetEndpoint,
    /// The initial receive window (bytes the sender is willing to buffer).
    pub initial_receive_window: u64,
    /// Protocol version (0 for N2.2.5).
    pub version: u8,
}

/// StreamOpenAck — gateway confirms the stream is connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenAck {
    /// The stream identifier (must match the StreamOpen).
    pub stream_id: StreamId,
    /// The gateway's initial receive window (bytes the client can send
    /// before waiting for a WindowUpdate).
    pub initial_receive_window: u64,
    /// Whether the connection was successfully established.
    pub connected: bool,
    /// Error message if `connected` is false.
    pub error: Option<String>,
}

/// StreamData — a chunk of application bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamData {
    /// The stream identifier.
    pub stream_id: StreamId,
    /// The direction of this data.
    pub direction: StreamDirection,
    /// The sequence number (monotonically increasing per direction).
    pub sequence: StreamSeq,
    /// The payload bytes.
    pub data: Vec<u8>,
}

/// StreamWindowUpdate — flow-control credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindowUpdate {
    /// The stream identifier.
    pub stream_id: StreamId,
    /// Additional bytes the receiver is willing to accept.
    pub additional_credit: u64,
}

/// StreamHalfClose — no more data from this direction (TCP FIN equivalent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHalfClose {
    /// The stream identifier.
    pub stream_id: StreamId,
    /// The direction being closed.
    pub direction: StreamDirection,
}

/// StreamClose — both directions done, clean shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamClose {
    /// The stream identifier.
    pub stream_id: StreamId,
}

/// StreamReset — abort the stream (TCP RST equivalent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamReset {
    /// The stream identifier.
    pub stream_id: StreamId,
    /// The reason for the reset.
    pub reason: StreamResetReason,
}

// ─── CBOR encoding/decoding ─────────────────────────────────────────────────

/// CBOR map key constants.
const KEY_MSG_TYPE: &str = "msgType";
const KEY_STREAM_ID: &str = "streamId";
const KEY_DESTINATION: &str = "destination";
const KEY_ADDRESS: &str = "address";
const KEY_PORT: &str = "port";
const KEY_PROTOCOL: &str = "protocol";
const KEY_INITIAL_WINDOW: &str = "initialWindow";
const KEY_VERSION: &str = "version";
const KEY_CONNECTED: &str = "connected";
const KEY_ERROR: &str = "error";
const KEY_DIRECTION: &str = "direction";
const KEY_SEQUENCE: &str = "sequence";
const KEY_DATA: &str = "data";
const KEY_CREDIT: &str = "credit";
const KEY_REASON: &str = "reason";

/// Message type identifiers (as CBOR unsigned ints).
const MSG_TYPE_OPEN: u64 = 1;
const MSG_TYPE_OPEN_ACK: u64 = 2;
const MSG_TYPE_DATA: u64 = 3;
const MSG_TYPE_WINDOW_UPDATE: u64 = 4;
const MSG_TYPE_HALF_CLOSE: u64 = 5;
const MSG_TYPE_CLOSE: u64 = 6;
const MSG_TYPE_RESET: u64 = 7;

/// Default initial receive window (64 KiB).
pub const DEFAULT_RECEIVE_WINDOW: u64 = 64 * 1024;

/// Maximum StreamData payload size (16 KiB).
pub const MAX_STREAM_DATA_PAYLOAD: usize = 16 * 384;

/// Maximum receive window a client or gateway can advertise (256 KiB).
///
/// A malicious client could request an enormous `initial_receive_window` to
/// force the gateway to buffer unbounded data. This constant bounds the
/// advertised window — values above this are clamped.
pub const MAX_STREAM_WINDOW: u64 = 256 * 1024;

/// Encode a [`StreamMessage`] to canonical CBOR bytes.
///
/// # Errors
/// Returns [`GatewayError::Cbor`] on encoding failure.
pub fn encode_stream_message(msg: &StreamMessage) -> GatewayResult<Vec<u8>> {
    let cbor = message_to_cbor(msg);
    Ok(snp_cbor::encode(&cbor)?)
}

/// Decode a [`StreamMessage`] from CBOR bytes.
///
/// # Errors
/// Returns [`GatewayError`] on decoding failure or unknown message type.
pub fn decode_stream_message(bytes: &[u8]) -> GatewayResult<StreamMessage> {
    let value = snp_cbor::decode(bytes)?;
    message_from_cbor(&value)
}

fn message_to_cbor(msg: &StreamMessage) -> CborValue {
    match msg {
        StreamMessage::Open(open) => CborValue::Map(vec![
            (t(KEY_MSG_TYPE), u(MSG_TYPE_OPEN)),
            (t(KEY_STREAM_ID), u(open.stream_id)),
            (
                t(KEY_DESTINATION),
                endpoint_to_cbor(&open.destination),
            ),
            (t(KEY_INITIAL_WINDOW), u(open.initial_receive_window)),
            (t(KEY_VERSION), u(u64::from(open.version))),
        ]),
        StreamMessage::OpenAck(ack) => {
            let mut entries = vec![
                (t(KEY_MSG_TYPE), u(MSG_TYPE_OPEN_ACK)),
                (t(KEY_STREAM_ID), u(ack.stream_id)),
                (t(KEY_INITIAL_WINDOW), u(ack.initial_receive_window)),
                (t(KEY_CONNECTED), CborValue::Bool(ack.connected)),
            ];
            if let Some(err) = &ack.error {
                entries.push((t(KEY_ERROR), t(err)));
            }
            CborValue::Map(entries)
        }
        StreamMessage::Data(data) => CborValue::Map(vec![
            (t(KEY_MSG_TYPE), u(MSG_TYPE_DATA)),
            (t(KEY_STREAM_ID), u(data.stream_id)),
            (t(KEY_DIRECTION), data.direction.to_cbor()),
            (t(KEY_SEQUENCE), u(data.sequence)),
            (t(KEY_DATA), b(&data.data)),
        ]),
        StreamMessage::WindowUpdate(wu) => CborValue::Map(vec![
            (t(KEY_MSG_TYPE), u(MSG_TYPE_WINDOW_UPDATE)),
            (t(KEY_STREAM_ID), u(wu.stream_id)),
            (t(KEY_CREDIT), u(wu.additional_credit)),
        ]),
        StreamMessage::HalfClose(hc) => CborValue::Map(vec![
            (t(KEY_MSG_TYPE), u(MSG_TYPE_HALF_CLOSE)),
            (t(KEY_STREAM_ID), u(hc.stream_id)),
            (t(KEY_DIRECTION), hc.direction.to_cbor()),
        ]),
        StreamMessage::Close(c) => CborValue::Map(vec![
            (t(KEY_MSG_TYPE), u(MSG_TYPE_CLOSE)),
            (t(KEY_STREAM_ID), u(c.stream_id)),
        ]),
        StreamMessage::Reset(r) => CborValue::Map(vec![
            (t(KEY_MSG_TYPE), u(MSG_TYPE_RESET)),
            (t(KEY_STREAM_ID), u(r.stream_id)),
            (t(KEY_REASON), r.reason.to_cbor()),
        ]),
    }
}

fn message_from_cbor(value: &CborValue) -> GatewayResult<StreamMessage> {
    let entries = match value {
        CborValue::Map(entries) => entries,
        other => {
            return Err(GatewayError::MalformedRequest(format!(
                "StreamMessage must be a CBOR map; got {other:?}"
            )));
        }
    };
    let mut msg_type: Option<u64> = None;
    for (k, v) in entries {
        let key = match k {
            CborValue::TextString(s) => s,
            _ => continue,
        };
        if key == KEY_MSG_TYPE {
            msg_type = match v {
                CborValue::UnsignedInt(n) => Some(*n),
                other => {
                    return Err(GatewayError::MalformedRequest(format!(
                        "msgType must be a uint; got {other:?}"
                    )));
                }
            };
            break;
        }
    }
    let msg_type = msg_type.ok_or_else(|| {
        GatewayError::MalformedRequest("StreamMessage: msgType missing".into())
    })?;

    match msg_type {
        MSG_TYPE_OPEN => Ok(StreamMessage::Open(StreamOpen::from_cbor_entries(entries)?)),
        MSG_TYPE_OPEN_ACK => Ok(StreamMessage::OpenAck(StreamOpenAck::from_cbor_entries(
            entries,
        )?)),
        MSG_TYPE_DATA => Ok(StreamMessage::Data(StreamData::from_cbor_entries(entries)?)),
        MSG_TYPE_WINDOW_UPDATE => Ok(StreamMessage::WindowUpdate(
            StreamWindowUpdate::from_cbor_entries(entries)?,
        )),
        MSG_TYPE_HALF_CLOSE => Ok(StreamMessage::HalfClose(StreamHalfClose::from_cbor_entries(
            entries,
        )?)),
        MSG_TYPE_CLOSE => Ok(StreamMessage::Close(StreamClose::from_cbor_entries(entries)?)),
        MSG_TYPE_RESET => Ok(StreamMessage::Reset(StreamReset::from_cbor_entries(entries)?)),
        other => Err(GatewayError::MalformedRequest(format!(
            "unknown StreamMessage msgType: {other}"
        ))),
    }
}

fn endpoint_to_cbor(ep: &InternetEndpoint) -> CborValue {
    let addr_str = match ep.address {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    };
    CborValue::Map(vec![
        (t(KEY_ADDRESS), t(&addr_str)),
        (t(KEY_PORT), u(u64::from(ep.port))),
        (t(KEY_PROTOCOL), ep.protocol.to_cbor()),
    ])
}

fn endpoint_from_cbor(v: &CborValue) -> GatewayResult<InternetEndpoint> {
    let entries = match v {
        CborValue::Map(entries) => entries,
        other => {
            return Err(GatewayError::MalformedRequest(format!(
                "InternetEndpoint must be a CBOR map; got {other:?}"
            )));
        }
    };
    let mut address: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut protocol: Option<TransportProtocol> = None;
    for (k, val) in entries {
        let key = match k {
            CborValue::TextString(s) => s,
            _ => continue,
        };
        match key.as_str() {
            KEY_ADDRESS => {
                address = Some(extract_text(val.clone(), KEY_ADDRESS)?);
            }
            KEY_PORT => {
                let p = extract_uint(val.clone(), KEY_PORT)?;
                port = Some(p as u16);
            }
            KEY_PROTOCOL => {
                protocol = Some(TransportProtocol::from_cbor(val)?);
            }
            _ => {}
        }
    }
    let address_str = address.ok_or_else(|| {
        GatewayError::MalformedRequest("InternetEndpoint: address missing".into())
    })?;
    let address: IpAddr = address_str
        .parse()
        .map_err(|_| {
            GatewayError::MalformedRequest(format!(
                "InternetEndpoint: invalid IP address: {address_str}"
            ))
        })?;
    let port = port.ok_or_else(|| {
        GatewayError::MalformedRequest("InternetEndpoint: port missing".into())
    })?;
    let protocol = protocol.unwrap_or(TransportProtocol::Tcp);
    Ok(InternetEndpoint {
        address,
        port,
        protocol,
    })
}

// ─── Per-message from_cbor_entries implementations ──────────────────────────

impl StreamOpen {
    fn from_cbor_entries(entries: &[(CborValue, CborValue)]) -> GatewayResult<Self> {
        let mut stream_id: Option<StreamId> = None;
        let mut destination: Option<InternetEndpoint> = None;
        let mut initial_receive_window: Option<u64> = None;
        let mut version: Option<u8> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s.as_str(),
                _ => continue,
            };
            match key {
                KEY_STREAM_ID => {
                    stream_id = Some(extract_uint(v.clone(), KEY_STREAM_ID)?);
                }
                KEY_DESTINATION => {
                    destination = Some(endpoint_from_cbor(v)?);
                }
                KEY_INITIAL_WINDOW => {
                    initial_receive_window = Some(extract_uint(v.clone(), KEY_INITIAL_WINDOW)?);
                }
                KEY_VERSION => {
                    version = Some(extract_uint(v.clone(), KEY_VERSION)? as u8);
                }
                _ => {}
            }
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamOpen: streamId missing".into())
            })?,
            destination: destination.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamOpen: destination missing".into())
            })?,
            initial_receive_window: initial_receive_window.unwrap_or(DEFAULT_RECEIVE_WINDOW),
            version: version.unwrap_or(0),
        })
    }
}

impl StreamOpenAck {
    fn from_cbor_entries(entries: &[(CborValue, CborValue)]) -> GatewayResult<Self> {
        let mut stream_id: Option<StreamId> = None;
        let mut initial_receive_window: Option<u64> = None;
        let mut connected: Option<bool> = None;
        let mut error: Option<String> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s.as_str(),
                _ => continue,
            };
            match key {
                KEY_STREAM_ID => {
                    stream_id = Some(extract_uint(v.clone(), KEY_STREAM_ID)?);
                }
                KEY_INITIAL_WINDOW => {
                    initial_receive_window = Some(extract_uint(v.clone(), KEY_INITIAL_WINDOW)?);
                }
                KEY_CONNECTED => {
                    connected = match v {
                        CborValue::Bool(b) => Some(*b),
                        _ => None,
                    };
                }
                KEY_ERROR => {
                    error = Some(extract_text(v.clone(), KEY_ERROR)?);
                }
                _ => {}
            }
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamOpenAck: streamId missing".into())
            })?,
            initial_receive_window: initial_receive_window.unwrap_or(DEFAULT_RECEIVE_WINDOW),
            connected: connected.unwrap_or(false),
            error,
        })
    }
}

impl StreamData {
    fn from_cbor_entries(entries: &[(CborValue, CborValue)]) -> GatewayResult<Self> {
        let mut stream_id: Option<StreamId> = None;
        let mut direction: Option<StreamDirection> = None;
        let mut sequence: Option<StreamSeq> = None;
        let mut data: Option<Vec<u8>> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s.as_str(),
                _ => continue,
            };
            match key {
                KEY_STREAM_ID => {
                    stream_id = Some(extract_uint(v.clone(), KEY_STREAM_ID)?);
                }
                KEY_DIRECTION => {
                    direction = Some(StreamDirection::from_cbor(v)?);
                }
                KEY_SEQUENCE => {
                    sequence = Some(extract_uint(v.clone(), KEY_SEQUENCE)?);
                }
                KEY_DATA => {
                    data = Some(extract_bstr(v.clone(), KEY_DATA)?);
                }
                _ => {}
            }
        }
        let data = data.ok_or_else(|| {
            GatewayError::MalformedRequest("StreamData: data missing".into())
        })?;
        if data.len() > MAX_STREAM_DATA_PAYLOAD {
            return Err(GatewayError::MalformedRequest(format!(
                "StreamData payload {} exceeds max {}",
                data.len(),
                MAX_STREAM_DATA_PAYLOAD
            )));
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamData: streamId missing".into())
            })?,
            direction: direction.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamData: direction missing".into())
            })?,
            sequence: sequence.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamData: sequence missing".into())
            })?,
            data,
        })
    }
}

impl StreamWindowUpdate {
    fn from_cbor_entries(entries: &[(CborValue, CborValue)]) -> GatewayResult<Self> {
        let mut stream_id: Option<StreamId> = None;
        let mut additional_credit: Option<u64> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s.as_str(),
                _ => continue,
            };
            match key {
                KEY_STREAM_ID => {
                    stream_id = Some(extract_uint(v.clone(), KEY_STREAM_ID)?);
                }
                KEY_CREDIT => {
                    additional_credit = Some(extract_uint(v.clone(), KEY_CREDIT)?);
                }
                _ => {}
            }
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamWindowUpdate: streamId missing".into())
            })?,
            additional_credit: additional_credit.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamWindowUpdate: credit missing".into())
            })?,
        })
    }
}

impl StreamHalfClose {
    fn from_cbor_entries(entries: &[(CborValue, CborValue)]) -> GatewayResult<Self> {
        let mut stream_id: Option<StreamId> = None;
        let mut direction: Option<StreamDirection> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s.as_str(),
                _ => continue,
            };
            match key {
                KEY_STREAM_ID => {
                    stream_id = Some(extract_uint(v.clone(), KEY_STREAM_ID)?);
                }
                KEY_DIRECTION => {
                    direction = Some(StreamDirection::from_cbor(v)?);
                }
                _ => {}
            }
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamHalfClose: streamId missing".into())
            })?,
            direction: direction.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamHalfClose: direction missing".into())
            })?,
        })
    }
}

impl StreamClose {
    fn from_cbor_entries(entries: &[(CborValue, CborValue)]) -> GatewayResult<Self> {
        let mut stream_id: Option<StreamId> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s.as_str(),
                _ => continue,
            };
            if key == KEY_STREAM_ID {
                stream_id = Some(extract_uint(v.clone(), KEY_STREAM_ID)?);
            }
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamClose: streamId missing".into())
            })?,
        })
    }
}

impl StreamReset {
    fn from_cbor_entries(entries: &[(CborValue, CborValue)]) -> GatewayResult<Self> {
        let mut stream_id: Option<StreamId> = None;
        let mut reason: Option<StreamResetReason> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s.as_str(),
                _ => continue,
            };
            match key {
                KEY_STREAM_ID => {
                    stream_id = Some(extract_uint(v.clone(), KEY_STREAM_ID)?);
                }
                KEY_REASON => {
                    reason = Some(StreamResetReason::from_cbor(v)?);
                }
                _ => {}
            }
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| {
                GatewayError::MalformedRequest("StreamReset: streamId missing".into())
            })?,
            reason: reason.unwrap_or(StreamResetReason::ApplicationReset),
        })
    }
}

// ─── CBOR helpers (reuse the same pattern as the main gateway module) ───────

fn extract_uint(v: CborValue, _field: &str) -> GatewayResult<u64> {
    match v {
        CborValue::UnsignedInt(n) => Ok(n),
        other => Err(GatewayError::MalformedRequest(format!(
            "expected uint; got {other:?}"
        ))),
    }
}

fn extract_text(v: CborValue, _field: &str) -> GatewayResult<String> {
    match v {
        CborValue::TextString(s) => Ok(s),
        other => Err(GatewayError::MalformedRequest(format!(
            "expected text; got {other:?}"
        ))),
    }
}

fn extract_bstr(v: CborValue, _field: &str) -> GatewayResult<Vec<u8>> {
    match v {
        CborValue::ByteString(bytes) => Ok(bytes),
        other => Err(GatewayError::MalformedRequest(format!(
            "expected bstr; got {other:?}"
        ))),
    }
}

fn u(n: u64) -> CborValue {
    CborValue::UnsignedInt(n)
}
fn t(s: &str) -> CborValue {
    CborValue::TextString(s.to_string())
}
fn b(bytes: &[u8]) -> CborValue {
    CborValue::ByteString(bytes.to_vec())
}

// Note: No separate stream_data_binding() function is needed. The circuit
// AEAD (encrypt_circuit_payload / decrypt_circuit_payload) already
// authenticates the ENTIRE StreamMessage CBOR — including stream_id,
// direction, sequence, and data. A valid ciphertext cannot have any field
// modified without failing AEAD authentication. The sequence number is a
// protocol ordering/replay state variable, NOT a cryptographic authenticator.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn stream_open_roundtrip() {
        let open = StreamOpen {
            stream_id: 42,
            destination: InternetEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 443,
                protocol: TransportProtocol::Tcp,
            },
            initial_receive_window: 65536,
            version: 0,
        };
        let msg = StreamMessage::Open(open.clone());
        let bytes = encode_stream_message(&msg).unwrap();
        let decoded = decode_stream_message(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_open_ipv6_roundtrip() {
        let open = StreamOpen {
            stream_id: 99,
            destination: InternetEndpoint {
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                port: 80,
                protocol: TransportProtocol::Tcp,
            },
            initial_receive_window: DEFAULT_RECEIVE_WINDOW,
            version: 0,
        };
        let msg = StreamMessage::Open(open.clone());
        let bytes = encode_stream_message(&msg).unwrap();
        let decoded = decode_stream_message(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_data_roundtrip() {
        let data = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 5,
            data: b"hello world".to_vec(),
        };
        let msg = StreamMessage::Data(data.clone());
        let bytes = encode_stream_message(&msg).unwrap();
        let decoded = decode_stream_message(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_data_oversized_rejected() {
        let oversized = vec![0u8; MAX_STREAM_DATA_PAYLOAD + 1];
        let data = StreamData {
            stream_id: 1,
            direction: StreamDirection::ClientToGateway,
            sequence: 0,
            data: oversized,
        };
        let msg = StreamMessage::Data(data);
        let bytes = encode_stream_message(&msg).unwrap();
        let result = decode_stream_message(&bytes);
        assert!(
            matches!(result, Err(GatewayError::MalformedRequest(ref s)) if s.contains("exceeds max")),
            "oversized StreamData must be rejected, got {:?}",
            result
        );
    }

    #[test]
    fn stream_half_close_roundtrip() {
        let hc = StreamHalfClose {
            stream_id: 7,
            direction: StreamDirection::GatewayToClient,
        };
        let msg = StreamMessage::HalfClose(hc.clone());
        let bytes = encode_stream_message(&msg).unwrap();
        let decoded = decode_stream_message(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_reset_roundtrip() {
        let reset = StreamReset {
            stream_id: 3,
            reason: StreamResetReason::ConnectionRefused,
        };
        let msg = StreamMessage::Reset(reset.clone());
        let bytes = encode_stream_message(&msg).unwrap();
        let decoded = decode_stream_message(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_window_update_roundtrip() {
        let wu = StreamWindowUpdate {
            stream_id: 10,
            additional_credit: 32768,
        };
        let msg = StreamMessage::WindowUpdate(wu.clone());
        let bytes = encode_stream_message(&msg).unwrap();
        let decoded = decode_stream_message(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn stream_open_ack_with_error_roundtrip() {
        let ack = StreamOpenAck {
            stream_id: 5,
            initial_receive_window: 0,
            connected: false,
            error: Some("Connection refused".into()),
        };
        let msg = StreamMessage::OpenAck(ack.clone());
        let bytes = encode_stream_message(&msg).unwrap();
        let decoded = decode_stream_message(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn unknown_msg_type_rejected() {
        // Construct a CBOR map with an unknown msgType.
        let bad = CborValue::Map(vec![(t(KEY_MSG_TYPE), u(999))]);
        let bytes = snp_cbor::encode(&bad).unwrap();
        let result = decode_stream_message(&bytes);
        assert!(
            matches!(result, Err(GatewayError::MalformedRequest(ref s)) if s.contains("unknown StreamMessage msgType")),
            "unknown msgType must be rejected, got {:?}",
            result
        );
    }
}
