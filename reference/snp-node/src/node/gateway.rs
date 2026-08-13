//! Extracted from node/mod.rs for N2.0.4 Gate E (node decomposition).
use super::*;

// ─── GatewayAdvertisement ────────────────────────────────────────────────────

/// A signed gateway advertisement. A gateway publishes this to announce
/// itself; clients verify the signature before trusting the advertisement.
///
/// **N2.0.7:** The advertisement now carries `circuitX25519Pub` — the
/// gateway's STATIC X25519 circuit public key. This field is INSIDE the
/// signed preimage, so the X25519 key is cryptographically bound to the
/// gateway's Ed25519 identity. A client that verifies the advertisement
/// signature KNOWS the X25519 key authentically belongs to the gateway —
/// an attacker cannot substitute a different X25519 key without
/// invalidating the signature. This closes the binding gap identified
/// in the N2.0.6 audit.
///
/// CDDL (sketch):
///
/// ```text
/// GatewayAdvertisement = {
///   nodeId:             bstr .size 32,
///   publicKey:          bstr .size 32,   ; Ed25519 identity public key
///   circuitX25519Pub:   bstr .size 32,   ; N2.0.7: static X25519 circuit key
///   listenAddr:         tstr,            ; transit listener (relay → gateway)
///   discoveryAddr:      tstr,            ; discovery listener (client → gateway)
///   capabilities:       [* tstr],        ; ["gateway"] for N2.0.1
///   egressPolicy:       tstr,            ; "allow-80-443" for N2.0.1
///   timestamp:          uint,            ; unix seconds
///   expiry:             uint,            ; unix seconds
///   signature:          bstr .size 64    ; Ed25519 under SIG_CONTEXT "gatewayAdvert"
/// }
/// ```
///
/// The signature is over the CBOR preimage of the map EXCLUDING the
/// `signature` field, prefixed by `SIG_CONTEXTS::GATEWAY_ADVERT`. This
/// matches invariant I2 (every signature is over `SIG_CONTEXT ‖ CBOR(payload)`).
#[derive(Debug, Clone)]
pub struct GatewayAdvertisement {
    /// The gateway's NodeId (`SHA-256("SNP/0.1 node\0" || public_key)`).
    pub node_id: [u8; 32],
    /// The gateway's Ed25519 public key.
    pub public_key: [u8; 32],
    /// **N2.0.7.** The gateway's STATIC X25519 circuit public key. The client
    /// uses this to derive fresh per-circuit keys via
    /// `seal_circuit_payload_with_fresh_eph`. This field is INSIDE the signed
    /// preimage, so it is cryptographically bound to the Ed25519 identity.
    pub circuit_x25519_pub: [u8; 32],
    /// The TCP address the gateway listens on for transit (relay → gateway).
    pub listen_addr: String,
    /// The TCP address the gateway listens on for discovery (client → gateway).
    pub discovery_addr: String,
    /// The gateway's capabilities (always includes `Gateway` for N2.0.1).
    pub capabilities: Vec<Capability>,
    /// Egress policy description (e.g. `"allow-80-443"`).
    pub egress_policy: String,
    /// When this advertisement was signed, unix seconds.
    pub timestamp: u64,
    /// When this advertisement expires, unix seconds.
    pub expiry: u64,
    /// Ed25519 signature by the gateway over the advertisement's preimage
    /// (excluding the signature itself), under `SIG_CONTEXT "gatewayAdvert"`.
    pub signature: [u8; 64],
    /// **N2.0.3 (Gate D).** Gateway-advertised observed RTT, in microseconds.
    /// This is a NON-SIGNED, OPTIONAL, GATEWAY-SELF-REPORTED metric. A
    /// [`MetricSelector`] MUST NOT trust this value blindly — it MUST prefer
    /// the locally-observed latency ([`GatewayDirectoryEntry::observed_latency`])
    /// when available, falling back to this advertised value only as a
    /// last resort.
    ///
    /// This field is NOT included in the signed preimage (see [`Self::preimage`])
    /// — it is metadata, not an authenticated claim. A malicious gateway can
    /// set it to any value, but the [`MetricSelector`] defends against this
    /// by preferring the locally-observed latency.
    ///
    /// `None` means the gateway did not advertise an RTT (the field is
    /// optional in the CBOR encoding for backward compat with N2.0/N2.0.1
    /// advertisements, which do not include it).
    pub observed_rtt: Option<u64>,
}

impl GatewayAdvertisement {
    /// Build the canonical CBOR preimage (the map EXCLUDING the `signature`
    /// field). This is the structure fed to `sign` / `verify` under
    /// `SIG_CONTEXTS::GATEWAY_ADVERT`.
    fn preimage(&self) -> CborValue {
        let caps: Vec<CborValue> = self
            .capabilities
            .iter()
            .map(|c| CborValue::TextString(c.as_str().to_string()))
            .collect();
        CborValue::Map(vec![
            (t("nodeId"), b(&self.node_id)),
            (t("publicKey"), b(&self.public_key)),
            // N2.0.7: circuitX25519Pub is INSIDE the signed preimage.
            (t("circuitX25519Pub"), b(&self.circuit_x25519_pub)),
            (t("listenAddr"), t(&self.listen_addr)),
            (t("discoveryAddr"), t(&self.discovery_addr)),
            (t("capabilities"), CborValue::Array(caps)),
            (t("egressPolicy"), t(&self.egress_policy)),
            (t("timestamp"), u(self.timestamp)),
            (t("expiry"), u(self.expiry)),
        ])
    }

    /// Sign this advertisement with the gateway's Ed25519 secret key.
    /// Mutates `self.signature` in place.
    ///
    /// # Panics
    /// Panics if CBOR encoding of the preimage fails (it never fails for
    /// well-formed advertisements).
    pub fn sign(&mut self, gateway_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage)
            .expect("CBOR encode of GatewayAdvertisement preimage never fails");
        let mut msg = Vec::with_capacity(sig_contexts::GATEWAY_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::GATEWAY_ADVERT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(gateway_secret_key, &msg);
    }

    /// Verify the signature against the `public_key` in this advertisement.
    ///
    /// Returns `false` on any failure (I20 — never throws). A client MUST
    /// call this before trusting an advertisement.
    #[must_use]
    pub fn verify(&self) -> bool {
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(sig_contexts::GATEWAY_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::GATEWAY_ADVERT);
        msg.extend_from_slice(&bytes);
        ed25519_verify(&self.public_key, &msg, &self.signature)
    }

    /// Check whether this advertisement has expired (relative to `now`).
    ///
    /// Returns `true` if `expiry <= now` (the advertisement is no longer
    /// valid). A client MUST call this before trusting an advertisement.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expiry <= now
    }

    /// Encode this advertisement to canonical CBOR (including the `signature`
    /// field). Used to send the advertisement over the discovery link.
    ///
    /// # Errors
    /// Returns [`NodeError::Other`] if CBOR encoding fails.
    pub fn encode_cbor(&self) -> NodeResult<Vec<u8>> {
        let mut entries = match self.preimage() {
            CborValue::Map(entries) => entries,
            _ => unreachable!("preimage always returns a Map"),
        };
        entries.push((t("signature"), b(&self.signature)));
        Ok(snp_cbor::encode(&CborValue::Map(entries))
            .map_err(|e| NodeError::Other(format!("CBOR encode GatewayAdvertisement: {e}")))?)
    }

    /// Decode an advertisement from canonical CBOR bytes (including the
    /// `signature` field). Used to receive an advertisement over the
    /// discovery link.
    ///
    /// # Errors
    /// Returns [`NodeError::Other`] if the bytes are not a valid
    /// GatewayAdvertisement.
    pub fn decode_cbor(bytes: &[u8]) -> NodeResult<Self> {
        let value = snp_cbor::decode(bytes)
            .map_err(|e| NodeError::Other(format!("CBOR decode GatewayAdvertisement: {e}")))?;
        let entries = match value {
            CborValue::Map(entries) => entries,
            other => {
                return Err(NodeError::Other(format!(
                    "GatewayAdvertisement must be a CBOR map; got {other:?}"
                )));
            }
        };
        let mut node_id: Option<[u8; 32]> = None;
        let mut public_key: Option<[u8; 32]> = None;
        let mut circuit_x25519_pub: Option<[u8; 32]> = None;
        let mut listen_addr: Option<String> = None;
        let mut discovery_addr: Option<String> = None;
        let mut capabilities: Option<Vec<Capability>> = None;
        let mut egress_policy: Option<String> = None;
        let mut timestamp: Option<u64> = None;
        let mut expiry: Option<u64> = None;
        let mut signature: Option<[u8; 64]> = None;
        let mut observed_rtt: Option<u64> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s,
                other => {
                    return Err(NodeError::Other(format!(
                        "GatewayAdvertisement key must be a text string; got {other:?}"
                    )));
                }
            };
            match key.as_str() {
                "nodeId" => node_id = Some(extract_bstr_32(v, "nodeId")?),
                "publicKey" => public_key = Some(extract_bstr_32(v, "publicKey")?),
                // N2.0.7: circuitX25519Pub is mandatory for production
                // advertisements. For backward compat with old N2.0.6
                // advertisements that don't carry it, we default to all-zeros
                // (which will cause circuit establishment to fail — the client
                // cannot seal a circuit payload without the gateway's X25519
                // pub). This is the correct behavior: an advertisement without
                // circuitX25519Pub cannot be used for protocol-driven circuit
                // establishment.
                "circuitX25519Pub" => circuit_x25519_pub = Some(extract_bstr_32(v, "circuitX25519Pub")?),
                "listenAddr" => listen_addr = Some(extract_text(v, "listenAddr")?),
                "discoveryAddr" => discovery_addr = Some(extract_text(v, "discoveryAddr")?),
                "capabilities" => capabilities = Some(extract_caps(v, "capabilities")?),
                "egressPolicy" => egress_policy = Some(extract_text(v, "egressPolicy")?),
                "timestamp" => timestamp = Some(extract_uint(v, "timestamp")?),
                "expiry" => expiry = Some(extract_uint(v, "expiry")?),
                "signature" => signature = Some(extract_bstr_64(v, "signature")?),
                // N2.0.3 (Gate D): optional non-signed metadata field. Older
                // advertisements (N2.0/N2.0.1) do not include this key —
                // observed_rtt stays None for backward compat.
                "observedRtt" => observed_rtt = Some(extract_uint(v, "observedRtt")?),
                other => {
                    return Err(NodeError::Other(format!(
                        "unknown GatewayAdvertisement key \"{other}\""
                    )));
                }
            }
        }
        Ok(Self {
            node_id: node_id.ok_or_else(|| NodeError::Other("nodeId missing".into()))?,
            public_key: public_key.ok_or_else(|| NodeError::Other("publicKey missing".into()))?,
            circuit_x25519_pub: circuit_x25519_pub.unwrap_or([0u8; 32]),
            listen_addr: listen_addr.ok_or_else(|| NodeError::Other("listenAddr missing".into()))?,
            discovery_addr: discovery_addr
                .ok_or_else(|| NodeError::Other("discoveryAddr missing".into()))?,
            capabilities: capabilities.unwrap_or_default(),
            egress_policy: egress_policy.unwrap_or_default(),
            timestamp: timestamp.ok_or_else(|| NodeError::Other("timestamp missing".into()))?,
            expiry: expiry.ok_or_else(|| NodeError::Other("expiry missing".into()))?,
            signature: signature.ok_or_else(|| NodeError::Other("signature missing".into()))?,
            observed_rtt,
        })
    }

    /// Construct a signed advertisement for the given gateway choice. The
    /// gateway's identity keys are the deterministic N2.0 test keys
    /// (`GATEWAY_A_SECRET` / `GATEWAY_B_SECRET`); production would use a
    /// persistent on-disk keypair.
    ///
    /// **N2.0.2 production constructor.** Build a signed advertisement for
    /// an ARBITRARY gateway identity (no `GatewayChoice` lookup).
    ///
    /// The advertisement is signed by `identity.secret_key` under
    /// `SIG_CONTEXTS::GATEWAY_ADVERT` (invariant I2). The advertised
    /// `nodeId` is `identity.node_id` (i.e. `SHA-256("SNP/0.1 node\0" ||
    /// identity.public_key)`, invariant I4). The advertised `publicKey` is
    /// `identity.public_key` (raw 32 bytes, invariant I3).
    ///
    /// **N2.0.7:** The advertisement now REQUIRES the gateway's static X25519
    /// circuit public key (`circuit_x25519_pub`). This key is INSIDE the
    /// signed preimage, so it is cryptographically bound to the Ed25519
    /// identity. Use [`GatewayAdvertisement::for_identity_with_circuit_key`]
    /// to construct an advertisement with the X25519 key.
    ///
    /// The caller is responsible for:
    /// - Generating (or loading) the gateway's Ed25519 identity keypair.
    /// - Generating (or loading) the gateway's STATIC X25519 circuit keypair.
    /// - Binding the correct `listen_addr` (transit) and `discovery_addr`
    ///   to the gateway's actual TCP listeners.
    /// - Refreshing the advertisement before its `expiry` (default 1 hour).
    #[must_use]
    pub fn for_identity(identity: &NodeIdentity, listen_addr: &str, discovery_addr: &str) -> Self {
        // N2.0.7: for_identity without an X25519 key creates an advertisement
        // with circuit_x25519_pub = [0u8; 32]. This is NOT usable for
        // protocol-driven circuit establishment — callers MUST use
        // for_identity_with_circuit_key for production. Retained for backward
        // compat with tests that don't exercise the circuit protocol.
        Self::for_identity_with_circuit_key(
            identity,
            [0u8; 32],
            listen_addr,
            discovery_addr,
        )
    }

    /// **N2.0.7 production constructor.** Build a signed advertisement that
    /// carries the gateway's STATIC X25519 circuit public key, bound to the
    /// Ed25519 identity via the signed preimage.
    ///
    /// The `circuit_x25519_pub` is the gateway's persistent X25519 public key
    /// used for fresh-ephemeral circuit key establishment (see
    /// `seal_circuit_payload_with_fresh_eph`). The corresponding secret key
    /// NEVER leaves the gateway. A client that verifies this advertisement
    /// KNOWS the X25519 key authentically belongs to the gateway identified
    /// by `identity.node_id`.
    ///
    /// # Errors
    /// Never returns an error (CBOR encoding of the preimage is infallible
    /// for well-formed inputs). Returns `Self` directly.
    #[must_use]
    pub fn for_identity_with_circuit_key(
        identity: &NodeIdentity,
        circuit_x25519_pub: [u8; 32],
        listen_addr: &str,
        discovery_addr: &str,
    ) -> Self {
        let now = now_unix();
        let mut advert = Self {
            node_id: identity.node_id,
            public_key: identity.public_key,
            circuit_x25519_pub,
            listen_addr: listen_addr.to_string(),
            discovery_addr: discovery_addr.to_string(),
            capabilities: vec![Capability::Gateway],
            egress_policy: "allow-80-443".to_string(),
            timestamp: now,
            expiry: now + ADVERTISEMENT_TTL_SECS,
            signature: [0u8; 64],
            observed_rtt: None,
        };
        advert.sign(&identity.secret_key);
        advert
    }
}

