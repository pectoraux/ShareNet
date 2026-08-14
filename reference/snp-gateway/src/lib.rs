//! SNP-GATEWAY — L7 Internet gateway: Mode A TransitRequest/Response + SSRF defence + IP pinning
//!
//! For N1.9 (Secure Rust Link + Gateway Boundary) this crate implements:
//!
//! - [`TransitRequest`] — a Mode A "please fetch this URL for me" bundle,
//!   signed by the client under `SIG_CONTEXTS.transitRequest`. CBOR shape
//!   matches the TypeScript reference (`/src/lib/snp/gateway.ts`).
//! - [`TransitResponse`] — the gateway's attestation that it performed a
//!   fetch, signed by the gateway under `SIG_CONTEXTS.transitResponse`.
//! - [`is_private_destination`] — SSRF defence (invariant I18, threat T9).
//!   Checks the literal host string AND every resolved IP against RFC 1918,
//!   loopback, link-local, multicast, CGN, ULA, and other restricted ranges.
//! - [`PinnedConnector`] — the N1.9 IP-pinning HTTP fetcher. Parses the URL,
//!   resolves DNS, validates EVERY resolved IP via `is_private_destination`,
//!   pins the first public IP, opens a `TcpStream::connect((ip, port))` to
//!   that exact IP, and (for HTTPS) drives a rustls TLS handshake over the
//!   pinned TCP stream with `server_name = original_hostname` for SNI and
//!   certificate validation. The HTTP client never re-resolves DNS — the
//!   TOCTOU gap present in N1.8 (`ureq::get(url)` re-resolved after
//!   validation) is closed.
//! - [`handle_transit_request`] — the gateway's request handler: validates
//!   `tlsTermination`, builds a [`PinnedConnector`] (which validates the URL
//!   + SSRF + DNS + IP pin), issues a single fetch via the connector, caps
//!   the body at `max_response_bytes`, computes
//!   `objectId = SHA-256(capped body)`, signs the TransitResponse.
//!   Redirects are NOT followed (the connector returns the 3xx response
//!   verbatim; the client decides what to do).
//!
//! ## What is NOT implemented here (out of scope for N1.9)
//!
//! - The full egress policy (allowed ports, per-peer quotas, max bytes per
//!   window). N1.9 hardcodes "allow 80/443".
//! - The full GatewayAdvert structure (capacity, cost hints). N1.9 uses a
//!   static gateway identity.
//! - Mode B (SOCKS5) and Mode C (TUN/VpnService).
//! - The full TransitReceipt chain (contribution accounting). N1.9 just
//!   signs the TransitResponse.
//! - HTTP redirect-following. N1.9 returns the 3xx response to the client
//!   (Test 5 verifies a redirect to a private IP is NOT followed).
//!
//! ## Production readiness
//!
//! **What IS production-ready in this crate (N1.9):**
//!
//! - The SSRF defence `is_private_destination` / `is_private_ipv4` /
//!   `is_private_ipv6` — covers RFC 1918, loopback, link-local (incl. cloud
//!   metadata 169.254.169.254), CGN 100.64/10, multicast, reserved, ULA
//!   fc00::/7, IPv4-mapped IPv6, .local, localhost, metadata.google.internal.
//! - The DNS-pinning fetcher [`PinnedConnector`]: resolves DNS ONCE,
//!   validates EVERY resolved IP, opens `TcpStream::connect((ip, port))` to
//!   the validated IP directly, and drives a rustls TLS handshake over the
//!   pinned TCP stream. The HTTP client never re-resolves DNS — the N1.8
//!   TOCTOU gap is closed.
//! - The TransitRequest/TransitResponse CBOR wire format — byte-for-byte
//!   match with the TypeScript reference (`/src/lib/snp/gateway.ts`).
//! - The Ed25519 sign/verify under SIG_CONTEXT (invariant I2).
//!
//! **What is NOT production-ready (future tasks):**
//!
//! - The HTTP/1.1 response parser `parse_http_response` handles
//!   `Content-Length` and read-to-EOF bodies but does NOT decode
//!   `Transfer-Encoding: chunked`. Production should use a real HTTP client
//!   (ureq, reqwest) configured with a custom resolver that pins the
//!   validated IPs — or extend the N1.9 parser to handle chunked encoding.
//! - The TLS stack uses `webpki-roots` (Mozilla CA bundle). Production
//!   should consider a more frequent root-update mechanism + certificate
//!   revocation (CRL/OCSP).
//! - Redirect-following is DISABLED. Production MAY choose to follow
//!   same-host redirects (re-running the SSRF check on the new URL), but
//!   cross-host redirects MUST be returned to the client verbatim.
//! - No egress-port policy: N1.9 allows 80/443 implicitly (the URL scheme
//!   determines the port). Production should enforce an explicit allow-list.
//! - No per-peer quotas or rate-limiting.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

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
    /// The HTTP response from the upstream was malformed (could not parse
    /// status line, headers, or chunked body).
    #[error("malformed HTTP response: {0}")]
    MalformedHttp(String),
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
///   reqId:                    bstr .size 16,
///   method:                   tstr,
///   url:                      tstr,
///   headers:                  { * tstr => tstr },   ; empty for N1.8
///   body:                     bstr / null,           ; null for N1.8
///   tlsTermination:           "GATEWAY_PLAINTEXT" / "PAYLOAD_E2E",
///   maxResponseBytes:         uint,
///   deadline:                 uint,
///   replyTo:                  bstr .size 32,         ; rendezvous identity, not NodeId
///   acceptGateways:           "any" / [* bstr .size 32],  ; "any" for N1.8
///   clientEd25519PublicKey:   bstr .size 32,   ; N2.2.2-hardening
///   clientSig:                bstr .size 64
/// }
/// ```
///
/// The Rust struct stores the simplified field set specified for N1.8
/// (reqId, method, url, tlsTermination, maxResponseBytes, deadline, replyTo,
/// clientEd25519PublicKey, clientSig). The CBOR encoder adds the empty headers
/// map, null body, and "any" acceptGateways fields automatically so the wire
/// format matches the TS reference exactly.
///
/// **N2.2.2-hardening:** The `client_ed25519_public_key` field is included
/// INSIDE the circuit-encrypted payload (it's part of the `TransitRequest`
/// struct that the client seals with `seal_circuit_payload_with_fresh_eph`).
/// The gateway extracts this from the decrypted `TransitRequest` instead of
/// receiving it out-of-band. Because it's part of the `clientSig` preimage,
/// it's cryptographically bound to the client's signature — an attacker can't
/// substitute a different key after the client signs.
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
    /// N2.2.2-hardening: The client's Ed25519 public key, included INSIDE
    /// the circuit-encrypted payload. The gateway extracts this from the
    /// decrypted TransitRequest instead of receiving it out-of-band.
    /// This field is part of the `client_sig` preimage, so it's
    /// cryptographically bound to the client's signature.
    pub client_ed25519_public_key: NodeIdBytes,
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
        // N2.2.2-hardening: client_ed25519_public_key is part of the signed
        // preimage so it's cryptographically bound to client_sig.
        (t("clientEd25519PublicKey"), b(&req.client_ed25519_public_key)),
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
    let mut client_ed25519_public_key: Option<NodeIdBytes> = None;
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
            // N2.2.2-hardening: client Ed25519 public key (32 bytes).
            "clientEd25519PublicKey" => {
                client_ed25519_public_key = Some(extract_bstr_32(v, "clientEd25519PublicKey")?);
            }
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
        client_ed25519_public_key: client_ed25519_public_key.ok_or_else(|| {
            GatewayError::MalformedRequest("clientEd25519PublicKey missing".into())
        })?,
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

/// Verify a TransitRequest's `clientSig`.
///
/// **N2.2.2-hardening:** The client's Ed25519 public key is now embedded
/// inside the `TransitRequest` itself (`client_ed25519_public_key` field).
/// This field is part of the signed preimage, so it's cryptographically
/// bound to `client_sig` — an attacker can't substitute a different key
/// after the client signs. The gateway extracts the key from the request
/// (no out-of-band parameter needed).
///
/// Returns `false` on any failure (I20 — never throws).
#[must_use]
pub fn verify_transit_request(req: &TransitRequest) -> bool {
    let preimage = transit_request_preimage(req);
    let Ok(bytes) = snp_cbor::encode(&preimage) else {
        return false;
    };
    let mut msg = Vec::with_capacity(sig_contexts::TRANSIT_REQUEST.len() + bytes.len());
    msg.extend_from_slice(sig_contexts::TRANSIT_REQUEST);
    msg.extend_from_slice(&bytes);
    ed25519_verify(&req.client_ed25519_public_key, &msg, &req.client_sig)
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

// ─── PinnedConnector (N1.9: DNS pinning — close the N1.8 TOCTOU gap) ─────────

/// An HTTP response returned by [`PinnedConnector::fetch`].
///
/// N1.9 returns the full body inline (no chunked-decoding beyond what
/// HTTP/1.1 requires; the body is what was read from the socket). The
/// gateway caps it at `max_response_bytes` after the fetch returns.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 301, 404).
    pub status: u16,
    /// Response headers, as `(name, value)` pairs in the order received.
    pub headers: Vec<(String, String)>,
    /// Response body bytes (already capped by the caller if needed).
    pub body: Vec<u8>,
}

/// A connection pinning HTTP/1.1 client that resolves DNS ONCE, validates
/// every resolved IP, and connects to the validated IP — never letting the
/// HTTP client re-resolve DNS.
///
/// This closes the N1.8 TOCTOU (time-of-check-to-time-of-use) gap: N1.8
/// validated every resolved IP via `std::net::ToSocketAddrs`, then called
/// `ureq::get(url)` which re-resolved DNS internally — a determined attacker
/// with control of the DNS server could return a different IP between the
/// validation and the fetch. [`PinnedConnector`] pins the validated IP at
/// construction time; [`PinnedConnector::fetch`] opens a `TcpStream` directly
/// to that IP, so no re-resolution can occur.
///
/// For HTTPS the connector still validates the server certificate against the
/// original hostname (rustls `server_name = hostname` for SNI + cert chain
/// validation). The TCP connection goes to the pinned IP; the TLS handshake
/// verifies the server holds a certificate for the original hostname.
///
/// ## Redirects
///
/// The connector does NOT follow HTTP 3xx redirects. A 301/302/307/308
/// response is returned verbatim to the caller. This is a deliberate SSRF
/// defence: a redirect from a public URL to a private IP cannot trick the
/// gateway into connecting to the private IP. (See Test 5 in
/// `snp-node/tests/n19_security.rs`.)
#[derive(Debug, Clone)]
pub struct PinnedConnector {
    /// The validated public IP the TCP connection will go to.
    pub resolved_ip: IpAddr,
    /// The original hostname from the URL (used for the Host header and for
    /// TLS SNI/cert validation).
    pub hostname: String,
    /// The destination port (80 for http, 443 for https by default).
    pub port: u16,
    /// URL scheme: `"http"` or `"https"`.
    pub scheme: String,
    /// The URL path + query (e.g. `"/"` or `"/foo?bar=baz"`).
    pub path: String,
}

impl PinnedConnector {
    /// Parse the URL, resolve DNS, validate EVERY resolved IP, and pin the
    /// first public IP.
    ///
    /// # Errors
    /// - [`GatewayError::MalformedUrl`] if the URL is malformed or uses an
    ///   unsupported scheme.
    /// - [`GatewayError::EgressBlocked`] if the literal host or ANY resolved
    ///   IP is private/restricted (I18 SSRF defence).
    /// - [`GatewayError::DnsEmpty`] if DNS resolution returns no addresses.
    /// - [`GatewayError::Upstream`] if DNS resolution itself fails.
    pub fn new(url: &str) -> GatewayResult<Self> {
        let parsed = url::Url::parse(url)
            .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(GatewayError::MalformedUrl(format!(
                "URL scheme must be http or https; got \"{scheme}\""
            )));
        }
        let host = parsed.host_str().ok_or_else(|| {
            GatewayError::MalformedUrl(format!("URL has no host: {url}"))
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
        let port = parsed.port_or_known_default().ok_or_else(|| {
            GatewayError::MalformedUrl(format!("URL has no default port for scheme \"{scheme}\""))
        })?;
        // Step 2: SSRF defence — resolve DNS ONCE, check EVERY resolved IP.
        // We collect all addresses and reject if ANY are private — this is
        // the DNS-rebinding defence. The first PUBLIC IP becomes the pin.
        let host_port = format!("{host}:{port}");
        let addrs = host_port
            .to_socket_addrs()
            .map_err(|e| GatewayError::Upstream(format!("DNS resolution of {host}: {e}")))?;
        let mut pinned_ip: Option<IpAddr> = None;
        for addr in addrs {
            let ip = addr.ip();
            let ip_str = ip.to_string();
            if is_private_ip_str(&ip_str) {
                return Err(GatewayError::EgressBlocked(format!(
                    "destination \"{host}\" resolves to private IP {ip_str} (I18 SSRF defence — DNS rebinding check)"
                )));
            }
            if pinned_ip.is_none() {
                pinned_ip = Some(ip);
            }
        }
        let resolved_ip = pinned_ip.ok_or_else(|| GatewayError::DnsEmpty(host.to_string()))?;
        // Build the path + query for the HTTP request line.
        let path = match (parsed.path(), parsed.query()) {
            ("", Some(q)) => format!("/?{q}"),
            ("", None) => "/".to_string(),
            (p, Some(q)) => format!("{p}?{q}"),
            (p, None) => p.to_string(),
        };
        Ok(Self {
            resolved_ip,
            hostname: host.to_string(),
            port,
            scheme: scheme.to_string(),
            path,
        })
    }

    /// Construct a `PinnedConnector` from pre-validated parts.
    ///
    /// **Test-only escape hatch.** This bypasses the SSRF / DNS validation in
    /// [`PinnedConnector::new`] so tests can pin the connector to a local
    /// mock HTTP server (which lives on 127.0.0.1, an IP that `new()` would
    /// reject). Production code MUST use [`PinnedConnector::new`].
    #[doc(hidden)]
    #[must_use]
    pub fn from_parts(
        resolved_ip: IpAddr,
        hostname: String,
        port: u16,
        scheme: String,
        path: String,
    ) -> Self {
        Self {
            resolved_ip,
            hostname,
            port,
            scheme,
            path,
        }
    }

    /// Issue a single HTTP/1.1 request to the pinned IP. The `Host` header is
    /// always the original `hostname` (NOT the IP). For HTTPS, a rustls TLS
    /// handshake is driven over the pinned `TcpStream` with
    /// `server_name = hostname` for SNI and certificate validation.
    ///
    /// Redirects are NOT followed — a 3xx response is returned verbatim.
    ///
    /// # Errors
    /// Returns [`GatewayError::Upstream`] on TCP or TLS failure, or
    /// [`GatewayError::MalformedHttp`] if the response cannot be parsed.
    pub fn fetch(&self, method: &str, headers: &[(String, String)]) -> GatewayResult<HttpResponse> {
        // Connect TCP to the EXACT validated IP. This is the core of the N1.9
        // DNS pinning: the TCP connection goes to the IP we validated, NOT
        // to a re-resolved hostname.
        let sock_addr = SocketAddr::new(self.resolved_ip, self.port);
        let mut tcp = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(15))
            .map_err(|e| GatewayError::Upstream(format!("TCP connect to {sock_addr}: {e}")))?;
        tcp.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| GatewayError::Upstream(format!("set_read_timeout: {e}")))?;
        tcp.set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| GatewayError::Upstream(format!("set_write_timeout: {e}")))?;
        tcp.set_nodelay(true).ok();

        // Build the HTTP/1.1 request. The Host header is the original
        // hostname (NOT the pinned IP) — this preserves virtual-host routing
        // and is what the TLS certificate was issued for.
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {hostname}\r\n",
            method = method,
            path = self.path,
            hostname = self.hostname,
        );
        let mut has_connection = false;
        let mut has_user_agent = false;
        let mut has_accept = false;
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
            let kl = k.to_ascii_lowercase();
            if kl == "connection" {
                has_connection = true;
            } else if kl == "user-agent" {
                has_user_agent = true;
            } else if kl == "accept" {
                has_accept = true;
            }
        }
        if !has_connection {
            // Connection: close — we read until EOF, no need for Content-Length.
            req.push_str("Connection: close\r\n");
        }
        if !has_user_agent {
            req.push_str("User-Agent: snp-gateway/0.1 (N1.9 pinned)\r\n");
        }
        if !has_accept {
            req.push_str("Accept: */*\r\n");
        }
        req.push_str("\r\n");
        let req_bytes = req.as_bytes();

        // Send the request and read the response, over plain TCP (http) or
        // over a TLS stream (https). For https the TLS handshake is driven
        // over the pinned TcpStream; the certificate is validated against
        // the original hostname (NOT the pinned IP).
        let resp_bytes: Vec<u8> = if self.scheme == "https" {
            self.fetch_https(tcp, req_bytes)?
        } else {
            tcp.write_all(req_bytes)
                .map_err(|e| GatewayError::Upstream(format!("HTTP write: {e}")))?;
            tcp.flush()
                .map_err(|e| GatewayError::Upstream(format!("HTTP flush: {e}")))?;
            let mut buf = Vec::new();
            tcp.read_to_end(&mut buf)
                .map_err(|e| GatewayError::Upstream(format!("HTTP read: {e}")))?;
            buf
        };

        parse_http_response(&resp_bytes)
    }

    /// Drive a rustls TLS handshake over the pinned `TcpStream` and issue the
    /// HTTP/1.1 request over the resulting TLS stream. Reads until EOF
    /// (server-initiated close).
    fn fetch_https(&self, tcp: TcpStream, req_bytes: &[u8]) -> GatewayResult<Vec<u8>> {
        // Build a rustls ClientConfig with the Mozilla/webpki root CA bundle.
        // This is the same CA set browsers use; it lets us verify the server
        // certificate chain for any public CA-signed cert.
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let config = Arc::new(config);

        // SNI / cert-validation name = original hostname (NOT the pinned IP).
        // This means the server MUST present a certificate valid for the
        // original hostname — pinning the IP does NOT weaken cert validation.
        let server_name = rustls::pki_types::ServerName::try_from(self.hostname.clone())
            .map_err(|e| GatewayError::Upstream(format!("invalid SNI hostname \"{0}\": {e}", self.hostname)))?;
        let conn = rustls::ClientConnection::new(config, server_name)
            .map_err(|e| GatewayError::Upstream(format!("rustls ClientConnection: {e}")))?;

        // StreamOwned takes ownership of both the connection and the
        // underlying TcpStream. We drive the TLS handshake implicitly on the
        // first write.
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        tls.write_all(req_bytes)
            .map_err(|e| GatewayError::Upstream(format!("HTTPS write: {e}")))?;
        tls.flush()
            .map_err(|e| GatewayError::Upstream(format!("HTTPS flush: {e}")))?;
        // Read until EOF (server-initiated close after Connection: close).
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf)
            .map_err(|e| GatewayError::Upstream(format!("HTTPS read: {e}")))?;
        Ok(buf)
    }
}

/// Parse a raw HTTP/1.1 response into an [`HttpResponse`].
///
/// Handles:
/// - Status line: `HTTP/1.1 <code> <reason>\r\n`
/// - Headers (case-insensitive header names; values trimmed of trailing
///   whitespace)
/// - Body:
///   - If `Content-Length: N` is present, takes the first N bytes after the
///     header terminator.
///   - Otherwise, takes everything after the header terminator (read-to-EOF
///     semantics — the server is expected to close the connection).
///   - `Transfer-Encoding: chunked` is NOT decoded in N1.9; if the response
///     is chunked, the raw chunked body is returned and the caller will see
///     chunk framing bytes. (The pinned mock servers in tests use plain
///     Content-Length or Connection: close; the real example.com returns a
///     Content-Length body.)
fn parse_http_response(raw: &[u8]) -> GatewayResult<HttpResponse> {
    // Find the header/body boundary (\r\n\r\n).
    let boundary = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| GatewayError::MalformedHttp("no \\r\\n\\r\\n header terminator".into()))?;
    let header_bytes = &raw[..boundary];
    let body_start = boundary + 4;
    let body_bytes = &raw[body_start..];

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| GatewayError::MalformedHttp(format!("header not UTF-8: {e}")))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| GatewayError::MalformedHttp("empty response".into()))?;
    // Parse `HTTP/1.1 200 OK`.
    let status_parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if status_parts.len() < 2 {
        return Err(GatewayError::MalformedHttp(format!(
            "bad status line: \"{status_line}\""
        )));
    }
    let status: u16 = status_parts[1]
        .parse()
        .map_err(|e| GatewayError::MalformedHttp(format!("bad status code: {e}")))?;

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| GatewayError::MalformedHttp(format!("bad header line: \"{line}\"")))?;
        let name = name.trim().to_string();
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        }
        headers.push((name, value));
    }

    // Determine the body slice.
    let body: Vec<u8> = match content_length {
        Some(n) if n <= body_bytes.len() => body_bytes[..n].to_vec(),
        Some(_) => {
            // Server sent fewer bytes than Content-Length declared. N1.9
            // takes what was received and continues — the caller caps at
            // max_response_bytes anyway.
            body_bytes.to_vec()
        }
        None => body_bytes.to_vec(),
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ─── TransitRequest handling (the gateway request handler) ──────────────────

/// The result of a successful Mode A fetch: the response plus the capped body
/// (which the gateway stores in the CAS or returns to the client).
pub struct FetchedResponse {
    /// The signed TransitResponse.
    pub response: TransitResponse,
    /// The capped response body. For N1.9 the body is returned inline (no
    /// CAS). `object_id = SHA-256(capped body)`.
    pub body: Vec<u8>,
}

/// Handle a TransitRequest: validate, fetch via the pinned connector, sign
/// the response.
///
/// Steps:
/// 1. Validate `tlsTermination` (I17 — fail-closed on downgrade).
/// 2. Build a [`PinnedConnector`] from the request URL — this performs the
///    URL parse, literal-host SSRF check, DNS resolution, per-IP SSRF check,
///    and IP pinning in ONE step (closing the N1.8 TOCTOU gap).
/// 3. Issue a single HTTP fetch via the connector. Redirects are NOT
///    followed (3xx is returned to the client as-is).
/// 4. Cap the response body at `max_response_bytes`.
/// 5. `objectId = SHA-256(capped body)` per ADR-0009 (N1.9 simplified form).
/// 6. Sign the TransitResponse with the gateway's Ed25519 key.
///
/// # Errors
/// Returns [`GatewayError`] on any failure: blocked egress, malformed URL,
/// DNS failure, HTTP failure, etc.
pub fn handle_transit_request(
    req: &TransitRequest,
    gateway_secret_key: &SymmetricKey,
) -> GatewayResult<FetchedResponse> {
    // N1.9.2 FIX: Verify the client's signature BEFORE doing anything else.
    // Without this, anyone who can send a circuit-encrypted frame can make
    // the gateway fetch arbitrary URLs — no attribution, no accountability.
    //
    // N2.2.2-hardening: The client's Ed25519 public key is now embedded
    // INSIDE the TransitRequest (the `client_ed25519_public_key` field),
    // not passed out-of-band. The key is part of the signed preimage so it
    // is cryptographically bound to `client_sig`.
    if !verify_transit_request(req) {
        return Err(GatewayError::MalformedRequest(
            "TransitRequest client_sig verification FAILED — request is not \
             authenticated (N1.9.2: unsigned requests must not reach egress; \
             N2.2.2: client identity is read from the request, not out-of-band)"
                .to_string(),
        ));
    }

    if req.tls_termination != "GATEWAY_PLAINTEXT" && req.tls_termination != "PAYLOAD_E2E" {
        return Err(GatewayError::MalformedRequest(format!(
            "tlsTermination must be GATEWAY_PLAINTEXT or PAYLOAD_E2E; got \"{}\" (I17)",
            req.tls_termination
        )));
    }
    // Build the pinned connector — this validates the URL + SSRF + DNS + IP
    // pin in ONE step. After this returns Ok, the connector holds a validated
    // public IP; the fetch below connects to that exact IP, NOT a re-resolved
    // hostname. The N1.8 TOCTOU gap is closed.
    let connector = PinnedConnector::new(&req.url)?;

    // Delegate the fetch + sign step to the connector-parameterised variant.
    fetch_and_sign_with_connector(req, gateway_secret_key, &connector)
}

/// Like [`handle_transit_request`] but uses a pre-built [`PinnedConnector`]
/// instead of calling [`PinnedConnector::new`] internally.
///
/// **TEST-ONLY escape hatch.** This bypasses the SSRF / DNS validation in
/// [`PinnedConnector::new`] — the caller is responsible for ensuring the
/// connector points at a safe destination. The N2.0.3 local-HTTP
/// integration test (`snp-node/tests/n203_local_http.rs`) uses this with a
/// [`PinnedConnector::from_parts`] that pins to the test's own mock HTTP
/// server on 127.0.0.1 (an address that [`PinnedConnector::new`] would
/// reject — see [`is_private_destination`]).
///
/// **Production gateways MUST NOT use this function** — production MUST
/// call [`handle_transit_request`], which builds the connector via
/// [`PinnedConnector::new`] and enforces the SSRF defence (invariant I18).
///
/// The client-signature verification and `tlsTermination` validation are
/// still performed (these are NOT bypassed — only the SSRF check is).
///
/// # Errors
/// Returns [`GatewayError`] on signature-verification failure, TLS
/// termination validation failure, HTTP fetch failure, etc.
pub fn handle_transit_request_with_connector(
    req: &TransitRequest,
    gateway_secret_key: &SymmetricKey,
    connector: &PinnedConnector,
) -> GatewayResult<FetchedResponse> {
    // Same client-signature verification as handle_transit_request — this
    // is NOT bypassed by the test-only escape hatch.
    //
    // N2.2.2-hardening: The client's Ed25519 public key is embedded INSIDE
    // the TransitRequest (the `client_ed25519_public_key` field), not passed
    // out-of-band.
    if !verify_transit_request(req) {
        return Err(GatewayError::MalformedRequest(
            "TransitRequest client_sig verification FAILED — request is not \
             authenticated (N1.9.2: unsigned requests must not reach egress; \
             N2.2.2: client identity is read from the request, not out-of-band)"
                .to_string(),
        ));
    }

    if req.tls_termination != "GATEWAY_PLAINTEXT" && req.tls_termination != "PAYLOAD_E2E" {
        return Err(GatewayError::MalformedRequest(format!(
            "tlsTermination must be GATEWAY_PLAINTEXT or PAYLOAD_E2E; got \"{}\" (I17)",
            req.tls_termination
        )));
    }

    fetch_and_sign_with_connector(req, gateway_secret_key, connector)
}

/// Shared fetch + cap + sign step used by both [`handle_transit_request`]
/// and [`handle_transit_request_with_connector`].
fn fetch_and_sign_with_connector(
    req: &TransitRequest,
    gateway_secret_key: &SymmetricKey,
    connector: &PinnedConnector,
) -> GatewayResult<FetchedResponse> {
    // Determine the gateway's NodeId from its secret key.
    let gateway_public = derive_public_key(gateway_secret_key);
    let gateway_id = derive_node_id(&gateway_public);

    // Single fetch via the pinned connector. No redirect-following.
    let http_response = connector.fetch(req.method.as_str(), &[])?;
    let status = http_response.status;
    let headers = http_response.headers;

    // Cap the response body at max_response_bytes.
    let cap = usize::try_from(req.max_response_bytes).unwrap_or(usize::MAX);
    let body: Vec<u8> = if http_response.body.len() <= cap {
        http_response.body
    } else {
        http_response.body[..cap].to_vec()
    };

    // objectId = SHA-256(capped body) per ADR-0009 (N1.9 simplified form).
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

// (Read+Write are imported at the top of the file — they're used by both the
// PinnedConnector HTTP path and the circuit-payload helpers.)

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
            client_ed25519_public_key: client_public,
            client_sig: [0u8; 64],
        };
        sign_transit_request(&mut req, &client_secret);
        assert!(verify_transit_request(&req));
        // Tamper: substitute the embedded public key with a DIFFERENT key.
        // The signature was computed over the ORIGINAL key, so verification
        // must fail (the embedded key is no longer the one that signed).
        let mut tampered_key = req.clone();
        tampered_key.client_ed25519_public_key = derive_public_key(&[7u8; 32]);
        assert!(
            !verify_transit_request(&tampered_key),
            "substituting the embedded client_ed25519_public_key MUST break \
             verification (it's part of the signed preimage)"
        );
        // Tamper: change a signed field (url).
        let mut tampered = req.clone();
        tampered.url = "https://evil.com/".into();
        assert!(!verify_transit_request(&tampered));
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
            client_ed25519_public_key: [12u8; 32],
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
