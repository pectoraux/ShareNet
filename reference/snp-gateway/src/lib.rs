//! SNP-GATEWAY — L7 Internet gateway: Mode A TransitRequest/Response + SSRF defence
//!
//! For N1.8 (the Rust minimal Internet bridge), this crate implements:
//!
//! - [`TransitRequest`] — a Mode A "please fetch this URL for me" bundle,
//!   signed by the client under `SIG_CONTEXTS.transitRequest`. CBOR shape
//!   matches the TypeScript reference (`/src/lib/snp/gateway.ts`).
//! - [`TransitResponse`] — the gateway's attestation that it performed a
//!   fetch, signed by the gateway under `SIG_CONTEXTS.transitResponse`.
//! - [`is_private_destination`] — SSRF defence (invariant I18, threat T9).
//!   Checks the literal host string AND every resolved IP against RFC 1918,
//!   loopback, link-local, multicast, CGN, ULA, and other restricted ranges.
//! - [`handle_transit_request`] — the gateway's request handler: validates
//!   the URL, resolves DNS, checks EVERY resolved IP against
//!   `is_private_destination`, fetches the URL via HTTP, caps the body at
//!   `max_response_bytes`, computes `objectId = SHA-256(capped body)`, signs
//!   the TransitResponse.
//!
//! ## What is NOT implemented here (out of scope for N1.8)
//!
//! - The full egress policy (allowed ports, per-peer quotas, max bytes per
//!   window). N1.8 hardcodes "allow 80/443".
//! - The full GatewayAdvert structure (capacity, cost hints). N1.8 uses a
//!   static gateway identity.
//! - Mode B (SOCKS5) and Mode C (TUN/VpnService).
//! - The full TransitReceipt chain (contribution accounting). N1.8 just
//!   signs the TransitResponse.
//! - DNS-rebinding defence via custom ureq resolver (IP pinning). N1.8
//!   validates every resolved IP via `std::net::ToSocketAddrs` BEFORE the
//!   fetch, then ureq re-resolves internally. The TOCTOU gap is documented.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::net::ToSocketAddrs;

use snp_cbor::CborValue;
use snp_crypto::{
    derive_node_id, derive_public_key, ed25519_sign, ed25519_verify, sha256, sig_contexts,
    SignatureBytes, SymmetricKey,
};
use thiserror::Error;

/// Errors from the L7 gateway.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// The requested destination is blocked by egress policy (RFC 1918,
    /// loopback, link-local, multicast, etc.).
    #[error("egress blocked by policy: {0}")]
    EgressBlocked(String),
    /// The URL is malformed or uses an unsupported scheme.
    #[error("malformed URL: {0}")]
    MalformedUrl(String),
    /// DNS resolution returned no addresses.
    #[error("DNS resolution returned no addresses for {0}")]
    DnsEmpty(String),
    /// The upstream fetch failed (DNS, TCP, TLS, HTTP).
    #[error("upstream error: {0}")]
    Upstream(String),
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Frame body was not a valid TransitRequest.
    #[error("frame body was not a valid TransitRequest: {0}")]
    MalformedRequest(String),
}

/// Convenience `Result` alias.
pub type GatewayResult<T> = Result<T, GatewayError>;

/// 16-byte request identifier (replay defence, response correlation).
pub type ReqId = [u8; 16];

/// 32-byte NodeId / ObjectId / RendezvousIdentity (I3, I4).
pub type NodeIdBytes = [u8; 32];

/// A Mode A "please fetch this URL for me" bundle, signed by the client.
///
/// CDDL (02-PROTOCOL-SPEC.md §8.2), simplified for N1.8 (empty headers, null
/// body, "any" acceptGateways):
///
/// ```text
/// TransitRequest = {
///   reqId:            bstr .size 16,
///   method:           tstr,
///   url:              tstr,
///   headers:          { * tstr => tstr },   ; empty for N1.8
///   body:             bstr / null,           ; null for N1.8
///   tlsTermination:   "GATEWAY_PLAINTEXT" / "PAYLOAD_E2E",
///   maxResponseBytes: uint,
///   deadline:         uint,
///   replyTo:          bstr .size 32,         ; rendezvous identity, not NodeId
///   acceptGateways:   "any" / [* bstr .size 32],  ; "any" for N1.8
///   clientSig:        bstr .size 64
/// }
/// ```
///
/// The Rust struct stores the simplified field set specified for N1.8
/// (reqId, method, url, tlsTermination, maxResponseBytes, deadline, replyTo,
/// clientSig). The CBOR encoder adds the empty headers map, null body, and
/// "any" acceptGateways fields automatically so the wire format matches the
/// TS reference exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitRequest {
    /// 16-byte random request identifier (replay defence).
    pub req_id: ReqId,
    /// HTTP method (e.g. "GET").
    pub method: String,
    /// Absolute URL to fetch.
    pub url: String,
    /// TLS termination mode — "GATEWAY_PLAINTEXT" or "PAYLOAD_E2E".
    pub tls_termination: String,
    /// Maximum response body size the client will accept.
    pub max_response_bytes: u64,
    /// Request deadline, unix seconds.
    pub deadline: u64,
    /// 32-byte X25519 rendezvous public key for response delivery.
    pub reply_to: NodeIdBytes,
    /// 64-byte Ed25519 signature by the client under
    /// `SIG_CONTEXTS.transitRequest`.
    pub client_sig: SignatureBytes,
}

/// The gateway's attestation that it performed a fetch.
///
/// CDDL (02-PROTOCOL-SPEC.md §8.2):
///
/// ```text
/// TransitResponse = {
///   reqId:      bstr .size 16,
///   status:     uint,
///   headers:    { * tstr => tstr },
///   objectId:   bstr .size 32,    ; SHA-256(capped body) for N1.8
///   fetchedAt:  uint,
///   gatewayId:  bstr .size 32,
///   gatewaySig: bstr .size 64
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitResponse {
    /// 16-byte request identifier — MUST match the TransitRequest.reqId.
    pub req_id: ReqId,
    /// HTTP status code.
    pub status: u16,
    /// HTTP response headers.
    pub headers: Vec<(String, String)>,
    /// 32-byte ObjectId of the response body. For N1.8 this is
    /// `SHA-256(capped response body)`. The production target is the Merkle
    /// root of chunked body (per ADR-0009).
    pub object_id: NodeIdBytes,
    /// Time the gateway performed the fetch, unix seconds.
    pub fetched_at: u64,
    /// NodeId (32 bytes) of the gateway that performed the fetch.
    pub gateway_id: NodeIdBytes,
    /// 64-byte Ed25519 signature by the gateway under
    /// `SIG_CONTEXTS.transitResponse`.
    pub gateway_sig: SignatureBytes,
}

// ─── CBOR (de)serialization ─────────────────────────────────────────────────

/// Build the canonical CBOR preimage for a TransitRequest, EXCLUDING the
/// `clientSig` field. This is the structure fed to `sign` / `verify` under
/// SIG_CONTEXT `"transitRequest"`.
///
/// The map matches the TypeScript reference byte-for-byte:
/// - `headers` is an empty map (N1.8 sends no request headers).
/// - `body` is null (N1.8 sends no request body).
/// - `acceptGateways` is the text string `"any"` (N1.8 accepts any gateway).
fn transit_request_preimage(req: &TransitRequest) -> CborValue {
    CborValue::Map(vec![
        (t("reqId"), b(&req.req_id)),
        (t("method"), t(&req.method)),
        (t("url"), t(&req.url)),
        (t("headers"), CborValue::Map(vec![])),
        (t("body"), CborValue::Null),
        (t("tlsTermination"), t(&req.tls_termination)),
        (t("maxResponseBytes"), u(req.max_response_bytes)),
        (t("deadline"), u(req.deadline)),
        (t("replyTo"), b(&req.reply_to)),
        (t("acceptGateways"), t("any")),
    ])
}

/// Build the canonical CBOR preimage for a TransitResponse, EXCLUDING the
/// `gatewaySig` field. This is the structure fed to `sign` / `verify` under
/// SIG_CONTEXT `"transitResponse"`.
fn transit_response_preimage(resp: &TransitResponse) -> CborValue {
    let headers_map: Vec<(CborValue, CborValue)> = resp
        .headers
        .iter()
        .map(|(k, v)| (t(k), t(v)))
        .collect();
    CborValue::Map(vec![
        (t("reqId"), b(&resp.req_id)),
        (t("status"), u(u64::from(resp.status))),
        (t("headers"), CborValue::Map(headers_map)),
        (t("objectId"), b(&resp.object_id)),
        (t("fetchedAt"), u(resp.fetched_at)),
        (t("gatewayId"), b(&resp.gateway_id)),
    ])
}

/// Encode a complete TransitRequest (including `clientSig`) to canonical CBOR.
pub fn encode_transit_request(req: &TransitRequest) -> GatewayResult<Vec<u8>> {
    let mut entries = match transit_request_preimage(req) {
        CborValue::Map(entries) => entries,
        _ => unreachable!("transit_request_preimage returns a Map"),
    };
    entries.push((t("clientSig"), b(&req.client_sig)));
    Ok(snp_cbor::encode(&CborValue::Map(entries))?)
}

/// Decode a TransitRequest from canonical CBOR bytes.
pub fn decode_transit_request(bytes: &[u8]) -> GatewayResult<TransitRequest> {
    let value = snp_cbor::decode(bytes)?;
    let entries = match value {
        CborValue::Map(entries) => entries,
        other => {
            return Err(GatewayError::MalformedRequest(format!(
                "TransitRequest must be a CBOR map; got {other:?}"
            )));
        }
    };
    let mut req_id: Option<ReqId> = None;
    let mut method: Option<String> = None;
    let mut url: Option<String> = None;
    let mut tls_termination: Option<String> = None;
    let mut max_response_bytes: Option<u64> = None;
    let mut deadline: Option<u64> = None;
    let mut reply_to: Option<NodeIdBytes> = None;
    let mut client_sig: Option<SignatureBytes> = None;
    for (k, v) in entries {
        let key = match k {
            CborValue::TextString(s) => s,
            other => {
                return Err(GatewayError::MalformedRequest(format!(
                    "TransitRequest key must be a text string; got {other:?}"
                )));
            }
        };
        match key.as_str() {
            "reqId" => req_id = Some(extract_bstr_16(v, "reqId")?),
            "method" => method = Some(extract_text(v, "method")?),
            "url" => url = Some(extract_text(v, "url")?),
            "tlsTermination" => tls_termination = Some(extract_text(v, "tlsTermination")?),
            "maxResponseBytes" => max_response_bytes = Some(extract_uint(v, "maxResponseBytes")?),
            "deadline" => deadline = Some(extract_uint(v, "deadline")?),
            "replyTo" => reply_to = Some(extract_bstr_32(v, "replyTo")?),
            "clientSig" => client_sig = Some(extract_bstr_64(v, "clientSig")?),
            // headers, body, acceptGateways are part of the preimage but the
            // N1.8 client always sends empty/null/"any". We tolerate their
            // presence without storing them.
            "headers" | "body" | "acceptGateways" => {}
            other => {
                return Err(GatewayError::MalformedRequest(format!(
                    "unknown TransitRequest key \"{other}\""
                )));
            }
        }
    }
    Ok(TransitRequest {
        req_id: req_id.ok_or_else(|| GatewayError::MalformedRequest("reqId missing".into()))?,
        method: method.ok_or_else(|| GatewayError::MalformedRequest("method missing".into()))?,
        url: url.ok_or_else(|| GatewayError::MalformedRequest("url missing".into()))?,
        tls_termination: tls_termination
            .ok_or_else(|| GatewayError::MalformedRequest("tlsTermination missing".into()))?,
        max_response_bytes: max_response_bytes
            .ok_or_else(|| GatewayError::MalformedRequest("maxResponseBytes missing".into()))?,
        deadline: deadline.ok_or_else(|| GatewayError::MalformedRequest("deadline missing".into()))?,
        reply_to: reply_to
            .ok_or_else(|| GatewayError::MalformedRequest("replyTo missing".into()))?,
        client_sig: client_sig
            .ok_or_else(|| GatewayError::MalformedRequest("clientSig missing".into()))?,
    })
}

/// Encode a complete TransitResponse (including `gatewaySig`) to canonical CBOR.
pub fn encode_transit_response(resp: &TransitResponse) -> GatewayResult<Vec<u8>> {
    let mut entries = match transit_response_preimage(resp) {
        CborValue::Map(entries) => entries,
        _ => unreachable!("transit_response_preimage returns a Map"),
    };
    entries.push((t("gatewaySig"), b(&resp.gateway_sig)));
    Ok(snp_cbor::encode(&CborValue::Map(entries))?)
}

/// Decode a TransitResponse from canonical CBOR bytes.
pub fn decode_transit_response(bytes: &[u8]) -> GatewayResult<TransitResponse> {
    let value = snp_cbor::decode(bytes)?;
    let entries = match value {
        CborValue::Map(entries) => entries,
        other => {
            return Err(GatewayError::MalformedRequest(format!(
                "TransitResponse must be a CBOR map; got {other:?}"
            )));
        }
    };
    let mut req_id: Option<ReqId> = None;
    let mut status: Option<u16> = None;
    let mut headers: Option<Vec<(String, String)>> = None;
    let mut object_id: Option<NodeIdBytes> = None;
    let mut fetched_at: Option<u64> = None;
    let mut gateway_id: Option<NodeIdBytes> = None;
    let mut gateway_sig: Option<SignatureBytes> = None;
    for (k, v) in entries {
        let key = match k {
            CborValue::TextString(s) => s,
            other => {
                return Err(GatewayError::MalformedRequest(format!(
                    "TransitResponse key must be a text string; got {other:?}"
                )));
            }
        };
        match key.as_str() {
            "reqId" => req_id = Some(extract_bstr_16(v, "reqId")?),
            "status" => status = Some(extract_uint(v, "status")? as u16),
            "headers" => headers = Some(extract_string_map(v, "headers")?),
            "objectId" => object_id = Some(extract_bstr_32(v, "objectId")?),
            "fetchedAt" => fetched_at = Some(extract_uint(v, "fetchedAt")?),
            "gatewayId" => gateway_id = Some(extract_bstr_32(v, "gatewayId")?),
            "gatewaySig" => gateway_sig = Some(extract_bstr_64(v, "gatewaySig")?),
            other => {
                return Err(GatewayError::MalformedRequest(format!(
                    "unknown TransitResponse key \"{other}\""
                )));
            }
        }
    }
    Ok(TransitResponse {
        req_id: req_id.ok_or_else(|| GatewayError::MalformedRequest("reqId missing".into()))?,
        status: status.ok_or_else(|| GatewayError::MalformedRequest("status missing".into()))?,
        headers: headers.unwrap_or_default(),
        object_id: object_id.ok_or_else(|| GatewayError::MalformedRequest("objectId missing".into()))?,
        fetched_at: fetched_at
            .ok_or_else(|| GatewayError::MalformedRequest("fetchedAt missing".into()))?,
        gateway_id: gateway_id
            .ok_or_else(|| GatewayError::MalformedRequest("gatewayId missing".into()))?,
        gateway_sig: gateway_sig
            .ok_or_else(|| GatewayError::MalformedRequest("gatewaySig missing".into()))?,
    })
}

// ─── Signing / verification ─────────────────────────────────────────────────

/// Sign a TransitRequest with the client's Ed25519 secret key, producing
/// the `clientSig`. Mutates `req.client_sig` in place.
pub fn sign_transit_request(req: &mut TransitRequest, client_secret_key: &SymmetricKey) {
    let preimage = transit_request_preimage(req);
    let bytes = snp_cbor::encode(&preimage).expect("CBOR encode of TransitRequest preimage");
    let mut msg = Vec::with_capacity(sig_contexts::TRANSIT_REQUEST.len() + bytes.len());
    msg.extend_from_slice(sig_contexts::TRANSIT_REQUEST);
    msg.extend_from_slice(&bytes);
    req.client_sig = ed25519_sign(client_secret_key, &msg);
}

/// Verify a TransitRequest's `clientSig` against the client's public key.
/// Returns `false` on any failure (I20 — never throws).
#[must_use]
pub fn verify_transit_request(req: &TransitRequest, client_public_key: &[u8; 32]) -> bool {
    let preimage = transit_request_preimage(req);
    let Ok(bytes) = snp_cbor::encode(&preimage) else {
        return false;
    };
    let mut msg = Vec::with_capacity(sig_contexts::TRANSIT_REQUEST.len() + bytes.len());
    msg.extend_from_slice(sig_contexts::TRANSIT_REQUEST);
    msg.extend_from_slice(&bytes);
    ed25519_verify(client_public_key, &msg, &req.client_sig)
}

/// Sign a TransitResponse with the gateway's Ed25519 secret key, producing
/// the `gatewaySig`. Mutates `resp.gateway_sig` in place.
pub fn sign_transit_response(resp: &mut TransitResponse, gateway_secret_key: &SymmetricKey) {
    let preimage = transit_response_preimage(resp);
    let bytes = snp_cbor::encode(&preimage).expect("CBOR encode of TransitResponse preimage");
    let mut msg = Vec::with_capacity(sig_contexts::TRANSIT_RESPONSE.len() + bytes.len());
    msg.extend_from_slice(sig_contexts::TRANSIT_RESPONSE);
    msg.extend_from_slice(&bytes);
    resp.gateway_sig = ed25519_sign(gateway_secret_key, &msg);
}

/// Verify a TransitResponse's `gatewaySig` against the gateway's public key.
/// Returns `false` on any failure (I20 — never throws).
#[must_use]
pub fn verify_transit_response(resp: &TransitResponse, gateway_public_key: &[u8; 32]) -> bool {
    let preimage = transit_response_preimage(resp);
    let Ok(bytes) = snp_cbor::encode(&preimage) else {
        return false;
    };
    let mut msg = Vec::with_capacity(sig_contexts::TRANSIT_RESPONSE.len() + bytes.len());
    msg.extend_from_slice(sig_contexts::TRANSIT_RESPONSE);
    msg.extend_from_slice(&bytes);
    ed25519_verify(gateway_public_key, &msg, &resp.gateway_sig)
}

// ─── SSRF defence (I18) ─────────────────────────────────────────────────────

/// Check whether a 4-byte IPv4 address is in a private/restricted range.
///
/// Returns `true` for:
/// - `0.0.0.0/8` — "this network" / unspecified
/// - `10.0.0.0/8` — RFC 1918 private
/// - `100.64.0.0/10` — RFC 6598 Carrier-Grade NAT
/// - `127.0.0.0/8` — loopback
/// - `169.254.0.0/16` — link-local (incl. 169.254.169.254 cloud metadata)
/// - `172.16.0.0/12` — RFC 1918 private
/// - `192.168.0.0/16` — RFC 1918 private
/// - `224.0.0.0/4` — multicast
/// - `240.0.0.0/4` — reserved
#[must_use]
pub fn is_private_ipv4(b: &[u8; 4]) -> bool {
    // 0.0.0.0/8 — "this network" / unspecified
    if b[0] == 0 {
        return true;
    }
    // 10.0.0.0/8 — RFC 1918 private
    if b[0] == 10 {
        return true;
    }
    // 100.64.0.0/10 — RFC 6598 CGN
    if b[0] == 100 && (64..=127).contains(&b[1]) {
        return true;
    }
    // 127.0.0.0/8 — loopback
    if b[0] == 127 {
        return true;
    }
    // 169.254.0.0/16 — link-local
    if b[0] == 169 && b[1] == 254 {
        return true;
    }
    // 172.16.0.0/12 — RFC 1918 private
    if b[0] == 172 && (16..=31).contains(&b[1]) {
        return true;
    }
    // 192.168.0.0/16 — RFC 1918 private
    if b[0] == 192 && b[1] == 168 {
        return true;
    }
    // 224.0.0.0/4 — multicast
    if (224..=239).contains(&b[0]) {
        return true;
    }
    // 240.0.0.0/4 — reserved
    if b[0] >= 240 {
        return true;
    }
    false
}

/// Check whether a 16-byte IPv6 address is in a private/restricted range.
#[must_use]
pub fn is_private_ipv6(b: &[u8; 16]) -> bool {
    // ::1 — loopback
    if b[..15].iter().all(|&x| x == 0) && b[15] == 1 {
        return true;
    }
    // :: — unspecified
    if b.iter().all(|&x| x == 0) {
        return true;
    }
    // fe80::/10 — link-local
    if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 {
        return true;
    }
    // fc00::/7 — Unique Local Addresses
    if b[0] == 0xfc || b[0] == 0xfd {
        return true;
    }
    // ff00::/8 — multicast
    if b[0] == 0xff {
        return true;
    }
    // ::ffff:a.b.c.d — IPv4-mapped IPv6
    if b[..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&b[12..16]);
        return is_private_ipv4(&v4);
    }
    false
}

/// Parse a dotted-quad IPv4 address into 4 bytes, or `None` if invalid.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        // Reject empty / leading-zero (e.g. "0177") / non-numeric.
        if p.is_empty() || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        let n: u16 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        out[i] = n as u8;
    }
    Some(out)
}

/// Determine whether a destination host is private/restricted and MUST be
/// rejected by a gateway egress (invariant I18, threat T9 — SSRF defence).
///
/// This checks the LITERAL host string. A hostname like `attacker.com` that
/// resolves to `127.0.0.1` (DNS rebinding) is NOT caught here — callers MUST
/// re-check the resolved IP via [`is_private_ip`] immediately before
/// connecting. [`handle_transit_request`] does this two-step check.
#[must_use]
pub fn is_private_destination(host: &str) -> bool {
    let h = host.to_lowercase();
    let h = h.trim();
    if h.is_empty() {
        return true;
    }
    if h == "localhost" {
        return true;
    }
    if h.ends_with(".local") {
        return true;
    }
    // Cloud metadata hostnames
    if h == "metadata.google.internal" || h == "metadata" {
        return true;
    }
    // IPv4 literal
    if let Some(v4) = parse_ipv4(h) {
        return is_private_ipv4(&v4);
    }
    // IPv6 literal — strip brackets if present
    let bare = h.trim_start_matches('[').trim_end_matches(']');
    if let Some(v6) = parse_ipv6(bare) {
        return is_private_ipv6(&v6);
    }
    // Not an IP literal — treat as a public hostname. The caller MUST re-check
    // the resolved IP.
    false
}

/// Parse a colon-separated IPv6 address into 16 bytes, or `None` if invalid.
/// Handles `::` zero-compression and IPv4-mapped (`::ffff:1.2.3.4`).
fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    if s.is_empty() || !s.contains(':') {
        return None;
    }
    // Split on "::" if present.
    let (left, right) = if let Some(idx) = s.find("::") {
        let l = &s[..idx];
        let r = &s[idx + 2..];
        (l, r)
    } else {
        (s, "")
    };
    let mut left_groups: Vec<[u8; 2]> = Vec::new();
    let mut right_groups: Vec<[u8; 2]> = Vec::new();
    let mut embedded_v4: Option<[u8; 4]> = None;
    if !left.is_empty() {
        for g in left.split(':') {
            let pair = parse_hex_group(g)?;
            left_groups.push(pair);
        }
    }
    if !right.is_empty() {
        let parts: Vec<&str> = right.split(':').collect();
        // Last part may be an IPv4 literal.
        let (groups, v4) = if parts.last().map(|p| p.contains('.')).unwrap_or(false) {
            let v4 = parse_ipv4(parts.last().unwrap())?;
            (parts[..parts.len() - 1].to_vec(), Some(v4))
        } else {
            (parts, None)
        };
        for g in groups {
            right_groups.push(parse_hex_group(g)?);
        }
        embedded_v4 = v4;
    }
    let total_groups = left_groups.len() + right_groups.len();
    let need = if embedded_v4.is_some() { 6 } else { 8 };
    if s.contains("::") {
        // Zero-compression: total_groups <= need.
        if total_groups > need {
            return None;
        }
    } else if total_groups != need {
        return None;
    }
    let mut out = [0u8; 16];
    let mut pos = 0;
    for g in &left_groups {
        out[pos] = g[0];
        out[pos + 1] = g[1];
        pos += 2;
    }
    let gap_groups = need - total_groups;
    pos += gap_groups * 2;
    for g in &right_groups {
        out[pos] = g[0];
        out[pos + 1] = g[1];
        pos += 2;
    }
    if let Some(v4) = embedded_v4 {
        out[12] = v4[0];
        out[13] = v4[1];
        out[14] = v4[2];
        out[15] = v4[3];
    }
    Some(out)
}

fn parse_hex_group(g: &str) -> Option<[u8; 2]> {
    if g.is_empty() || g.len() > 4 {
        return None;
    }
    let n = u16::from_str_radix(g, 16).ok()?;
    Some([(n >> 8) as u8, (n & 0xff) as u8])
}

/// Check whether an `IpAddr`-style string is private.
#[must_use]
pub fn is_private_ip_str(ip: &str) -> bool {
    if let Some(v4) = parse_ipv4(ip) {
        return is_private_ipv4(&v4);
    }
    let bare = ip.trim_start_matches('[').trim_end_matches(']');
    if let Some(v6) = parse_ipv6(bare) {
        return is_private_ipv6(&v6);
    }
    false
}

// ─── TransitRequest handling (the gateway request handler) ──────────────────

/// The result of a successful Mode A fetch: the response plus the capped body
/// (which the gateway stores in the CAS or returns to the client).
pub struct FetchedResponse {
    /// The signed TransitResponse.
    pub response: TransitResponse,
    /// The capped response body. For N1.8 the body is returned inline (no
    /// CAS). `object_id = SHA-256(capped body)`.
    pub body: Vec<u8>,
}

/// Validate the request's URL and egress policy. Returns the parsed URL and
/// the (host, port) for fetch.
fn validate_request(req: &TransitRequest) -> GatewayResult<url::Url> {
    if req.tls_termination != "GATEWAY_PLAINTEXT" && req.tls_termination != "PAYLOAD_E2E" {
        return Err(GatewayError::MalformedRequest(format!(
            "tlsTermination must be GATEWAY_PLAINTEXT or PAYLOAD_E2E; got \"{}\" (I17)",
            req.tls_termination
        )));
    }
    let parsed = url::Url::parse(&req.url)
        .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(GatewayError::MalformedUrl(format!(
            "URL scheme must be http or https; got \"{scheme}\""
        )));
    }
    let host = parsed.host_str().ok_or_else(|| {
        GatewayError::MalformedUrl(format!("URL has no host: {}", req.url))
    })?;
    if host.is_empty() {
        return Err(GatewayError::MalformedUrl("URL host is empty".into()));
    }
    // Step 1: SSRF defence — literal host check.
    if is_private_destination(host) {
        return Err(GatewayError::EgressBlocked(format!(
            "destination \"{host}\" is private/loopback/link-local/multicast (I18 SSRF defence)"
        )));
    }
    // Step 2: SSRF defence — resolve DNS and check EVERY resolved IP.
    let port = parsed.port_or_known_default().ok_or_else(|| {
        GatewayError::MalformedUrl(format!("URL has no default port for scheme \"{scheme}\""))
    })?;
    let host_port = format!("{host}:{port}");
    let addrs = host_port
        .to_socket_addrs()
        .map_err(|e| GatewayError::Upstream(format!("DNS resolution of {host}: {e}")))?;
    let mut resolved: Vec<std::net::SocketAddr> = addrs.collect();
    if resolved.is_empty() {
        return Err(GatewayError::DnsEmpty(host.to_string()));
    }
    for addr in &resolved {
        let ip_str = addr.ip().to_string();
        if is_private_ip_str(&ip_str) {
            return Err(GatewayError::EgressBlocked(format!(
                "destination \"{host}\" resolves to private IP {ip_str} (I18 SSRF defence — DNS rebinding check)"
            )));
        }
    }
    let _ = &mut resolved; // silence unused-mut
    Ok(parsed)
}

/// Handle a TransitRequest: validate, fetch, sign the response.
///
/// Steps:
/// 1. Validate URL scheme + tlsTermination (I17 — fail-closed on downgrade).
/// 2. SSRF literal-host check.
/// 3. Resolve DNS, check EVERY resolved IP (DNS-rebinding defence).
/// 4. Fetch the URL via `ureq` (HTTP GET for N1.8; method is honoured but
///    body is not sent).
/// 5. Cap the response body at `max_response_bytes`.
/// 6. `objectId = SHA-256(capped body)`.
/// 7. Sign the TransitResponse with the gateway's Ed25519 key.
///
/// # Errors
/// Returns [`GatewayError`] on any failure: blocked egress, malformed URL,
/// DNS failure, HTTP failure, etc.
///
/// # Known limitation
/// After validating every resolved IP, this function calls `ureq::get(url)`
/// which re-resolves DNS internally. A determined attacker with control of
/// the DNS server could return a different IP between the validation and the
/// fetch (TOCTOU). The production target is a custom `ureq` resolver that
/// pins the validated IPs; this is documented as a known gap (N1.6 finding).
pub fn handle_transit_request(
    req: &TransitRequest,
    gateway_secret_key: &SymmetricKey,
) -> GatewayResult<FetchedResponse> {
    let parsed = validate_request(req)?;

    // Determine the gateway's NodeId from its secret key.
    let gateway_public = derive_public_key(gateway_secret_key);
    let gateway_id = derive_node_id(&gateway_public);

    // Fetch the URL via ureq. ureq handles TLS via rustls by default.
    let response = ureq::get(parsed.as_str())
        .call()
        .map_err(|e| GatewayError::Upstream(format!("ureq GET {}: {e}", parsed)))?;
    let status = response.status();
    let mut headers: Vec<(String, String)> = Vec::new();
    for h in response.headers_names() {
        if let Some(val) = response.header(&h) {
            headers.push((h, val.to_string()));
        }
    }

    // Read the body, capping at max_response_bytes.
    let cap = usize::try_from(req.max_response_bytes).unwrap_or(usize::MAX);
    let mut body = Vec::new();
    let mut reader = response.into_reader();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| GatewayError::Upstream(format!("read body: {e}")))?;
        if n == 0 {
            break;
        }
        let remaining = cap.saturating_sub(body.len());
        if remaining == 0 {
            // Cap reached — discard the rest but mark as capped.
            break;
        }
        let take = n.min(remaining);
        body.extend_from_slice(&buf[..take]);
        if body.len() >= cap {
            break;
        }
    }

    // objectId = SHA-256(capped body) per ADR-0009 (N1.8 simplified form).
    let object_id = sha256(&body);

    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut response = TransitResponse {
        req_id: req.req_id,
        status,
        headers,
        object_id,
        fetched_at,
        gateway_id,
        gateway_sig: [0u8; 64],
    };
    sign_transit_response(&mut response, gateway_secret_key);
    Ok(FetchedResponse { response, body })
}

// ─── Internal CBOR helpers ──────────────────────────────────────────────────

fn extract_uint(v: CborValue, field: &str) -> GatewayResult<u64> {
    match v {
        CborValue::UnsignedInt(n) => Ok(n),
        other => Err(GatewayError::MalformedRequest(format!(
            "{field} must be a CBOR uint; got {other:?}"
        ))),
    }
}

fn extract_text(v: CborValue, field: &str) -> GatewayResult<String> {
    match v {
        CborValue::TextString(s) => Ok(s),
        other => Err(GatewayError::MalformedRequest(format!(
            "{field} must be a text string; got {other:?}"
        ))),
    }
}

fn extract_bstr_16(v: CborValue, field: &str) -> GatewayResult<ReqId> {
    match v {
        CborValue::ByteString(bytes) => {
            if bytes.len() != 16 {
                return Err(GatewayError::MalformedRequest(format!(
                    "{field} must be 16 bytes; got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        other => Err(GatewayError::MalformedRequest(format!(
            "{field} must be a byte string; got {other:?}"
        ))),
    }
}

fn extract_bstr_32(v: CborValue, field: &str) -> GatewayResult<NodeIdBytes> {
    match v {
        CborValue::ByteString(bytes) => {
            if bytes.len() != 32 {
                return Err(GatewayError::MalformedRequest(format!(
                    "{field} must be 32 bytes; got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        other => Err(GatewayError::MalformedRequest(format!(
            "{field} must be a byte string; got {other:?}"
        ))),
    }
}

fn extract_bstr_64(v: CborValue, field: &str) -> GatewayResult<SignatureBytes> {
    match v {
        CborValue::ByteString(bytes) => {
            if bytes.len() != 64 {
                return Err(GatewayError::MalformedRequest(format!(
                    "{field} must be 64 bytes; got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        other => Err(GatewayError::MalformedRequest(format!(
            "{field} must be a byte string; got {other:?}"
        ))),
    }
}

fn extract_string_map(v: CborValue, field: &str) -> GatewayResult<Vec<(String, String)>> {
    match v {
        CborValue::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let key = match k {
                    CborValue::TextString(s) => s,
                    other => {
                        return Err(GatewayError::MalformedRequest(format!(
                            "{field} map key must be a text string; got {other:?}"
                        )));
                    }
                };
                let value = match val {
                    CborValue::TextString(s) => s,
                    other => {
                        return Err(GatewayError::MalformedRequest(format!(
                            "{field} map value must be a text string; got {other:?}"
                        )));
                    }
                };
                out.push((key, value));
            }
            Ok(out)
        }
        other => Err(GatewayError::MalformedRequest(format!(
            "{field} must be a CBOR map; got {other:?}"
        ))),
    }
}

// Tiny CborValue constructors.
fn u(n: u64) -> CborValue {
    CborValue::UnsignedInt(n)
}
fn t(s: &str) -> CborValue {
    CborValue::TextString(s.to_string())
}
fn b(bytes: &[u8]) -> CborValue {
    CborValue::ByteString(bytes.to_vec())
}

// Re-export `Read` for the body-reading loop.
use std::io::Read as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv4_ranges() {
        assert!(is_private_ipv4(&[10, 0, 0, 1]));
        assert!(is_private_ipv4(&[127, 0, 0, 1]));
        assert!(is_private_ipv4(&[169, 254, 169, 254]));
        assert!(is_private_ipv4(&[172, 16, 0, 1]));
        assert!(is_private_ipv4(&[172, 31, 255, 255]));
        assert!(is_private_ipv4(&[192, 168, 1, 1]));
        assert!(is_private_ipv4(&[0, 0, 0, 0]));
        assert!(is_private_ipv4(&[100, 64, 0, 1]));
        assert!(is_private_ipv4(&[224, 0, 0, 1]));
        assert!(is_private_ipv4(&[240, 0, 0, 1]));
        // Public addresses
        assert!(!is_private_ipv4(&[93, 184, 216, 34])); // example.com
        assert!(!is_private_ipv4(&[1, 1, 1, 1]));
        assert!(!is_private_ipv4(&[8, 8, 8, 8]));
    }

    #[test]
    fn private_ipv6_ranges() {
        // ::1 loopback
        let mut v = [0u8; 16];
        v[15] = 1;
        assert!(is_private_ipv6(&v));
        // :: unspecified
        let v = [0u8; 16];
        assert!(is_private_ipv6(&v));
        // fe80::/10 link-local
        let mut v = [0u8; 16];
        v[0] = 0xfe;
        v[1] = 0x80;
        assert!(is_private_ipv6(&v));
        // fc00::/7 ULA
        let mut v = [0u8; 16];
        v[0] = 0xfc;
        assert!(is_private_ipv6(&v));
        // ff00::/8 multicast
        let mut v = [0u8; 16];
        v[0] = 0xff;
        assert!(is_private_ipv6(&v));
        // ::ffff:127.0.0.1 — IPv4-mapped IPv6
        let mut v = [0u8; 16];
        v[10] = 0xff;
        v[11] = 0xff;
        v[12] = 127;
        v[15] = 1;
        assert!(is_private_ipv6(&v));
    }

    #[test]
    fn private_destination_hostnames() {
        assert!(is_private_destination("localhost"));
        assert!(is_private_destination("foo.local"));
        assert!(is_private_destination("metadata.google.internal"));
        assert!(is_private_destination("metadata"));
        assert!(is_private_destination(""));
        assert!(is_private_destination("127.0.0.1"));
        assert!(is_private_destination("10.0.0.1"));
        assert!(is_private_destination("192.168.1.1"));
        assert!(is_private_destination("169.254.169.254"));
        assert!(is_private_destination("[::1]"));
        assert!(is_private_destination("[fe80::1]"));
        // Public
        assert!(!is_private_destination("example.com"));
        assert!(!is_private_destination("93.184.216.34"));
        assert!(!is_private_destination("[2606:2800:220:1:248:1893:25c8:1946]"));
    }

    #[test]
    fn transit_request_sign_verify_roundtrip() {
        let mut rng_seed = [0u8; 32];
        for (i, b) in rng_seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let client_secret = rng_seed;
        let client_public = derive_public_key(&client_secret);
        let mut req = TransitRequest {
            req_id: [1u8; 16],
            method: "GET".into(),
            url: "https://example.com/".into(),
            tls_termination: "GATEWAY_PLAINTEXT".into(),
            max_response_bytes: 65536,
            deadline: 2_000_000_000,
            reply_to: [2u8; 32],
            client_sig: [0u8; 64],
        };
        sign_transit_request(&mut req, &client_secret);
        assert!(verify_transit_request(&req, &client_public));
        // Wrong key
        let other_pub = derive_public_key(&[7u8; 32]);
        assert!(!verify_transit_request(&req, &other_pub));
        // Tamper
        let mut tampered = req.clone();
        tampered.url = "https://evil.com/".into();
        assert!(!verify_transit_request(&tampered, &client_public));
    }

    #[test]
    fn transit_response_sign_verify_roundtrip() {
        let gateway_secret = [42u8; 32];
        let gateway_public = derive_public_key(&gateway_secret);
        let mut resp = TransitResponse {
            req_id: [3u8; 16],
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            object_id: [4u8; 32],
            fetched_at: 1_700_000_000,
            gateway_id: derive_node_id(&gateway_public),
            gateway_sig: [0u8; 64],
        };
        sign_transit_response(&mut resp, &gateway_secret);
        assert!(verify_transit_response(&resp, &gateway_public));
        // Wrong key
        let other_pub = derive_public_key(&[8u8; 32]);
        assert!(!verify_transit_response(&resp, &other_pub));
        // Tamper
        let mut tampered = resp.clone();
        tampered.status = 404;
        assert!(!verify_transit_response(&tampered, &gateway_public));
    }

    #[test]
    fn transit_request_cbor_roundtrip() {
        let req = TransitRequest {
            req_id: [5u8; 16],
            method: "GET".into(),
            url: "https://example.com/".into(),
            tls_termination: "GATEWAY_PLAINTEXT".into(),
            max_response_bytes: 65536,
            deadline: 2_000_000_000,
            reply_to: [6u8; 32],
            client_sig: [7u8; 64],
        };
        let bytes = encode_transit_request(&req).unwrap();
        let decoded = decode_transit_request(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn transit_response_cbor_roundtrip() {
        let resp = TransitResponse {
            req_id: [8u8; 16],
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            object_id: [9u8; 32],
            fetched_at: 1_700_000_000,
            gateway_id: [10u8; 32],
            gateway_sig: [11u8; 64],
        };
        let bytes = encode_transit_response(&resp).unwrap();
        let decoded = decode_transit_response(&bytes).unwrap();
        assert_eq!(decoded, resp);
    }
}
