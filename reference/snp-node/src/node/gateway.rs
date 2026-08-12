//! Extracted from node/mod.rs for N2.0.4 Gate E (node decomposition).
use super::*;
use thiserror::Error;

// ─── GatewayAdvertisement ────────────────────────────────────────────────────

/// A signed gateway advertisement. A gateway publishes this to announce
/// itself; clients verify the signature before trusting the advertisement.
///
/// CDDL (sketch):
///
/// ```text
/// GatewayAdvertisement = {
///   nodeId:        bstr .size 32,
///   publicKey:     bstr .size 32,
///   listenAddr:    tstr,           ; transit listener (relay → gateway)
///   discoveryAddr: tstr,           ; discovery listener (client → gateway)
///   capabilities:  [* tstr],       ; ["gateway"] for N2.0.1
///   egressPolicy:  tstr,           ; "allow-80-443" for N2.0.1
///   timestamp:     uint,           ; unix seconds
///   expiry:        uint,           ; unix seconds
///   signature:     bstr .size 64   ; Ed25519 under SIG_CONTEXT "gatewayAdvert"
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
    /// **N2.0.3: DEPRECATED.** This constructor uses
    /// [`crate::legacy::GatewayChoice`], which is now confined to legacy/demo code.
    /// New production code MUST use [`GatewayAdvertisement::for_identity`]
    /// with an arbitrary [`NodeIdentity`] — gateways are NOT required to be
    /// one of the two pre-N2.0.2 `GatewayChoice::A`/`GatewayChoice::B`
    /// identities. See [`NodeIdentity::gateway`] for why this is NOT also
    /// `#[cfg(test)]`.
    #[deprecated(
        since = "N2.0.2",
        note = "Use GatewayAdvertisement::for_identity(identity, listen, discovery) instead. \
                The GatewayChoice-based constructor is retained for N2.0/N2.0.1 backward compat."
    )]
    #[must_use]
    pub fn for_gateway(
        gw: crate::legacy::GatewayChoice,
        listen_addr: &str,
        discovery_addr: &str,
    ) -> Self {
        #[allow(deprecated)]
        let identity = NodeIdentity::gateway(gw);
        Self::for_identity(&identity, listen_addr, discovery_addr)
    }

    /// **N2.0.2 production constructor.** Build a signed advertisement for
    /// an ARBITRARY gateway identity (no `GatewayChoice` lookup).
    ///
    /// The advertisement is signed by `identity.secret_key` under
    /// `SIG_CONTEXTS::GATEWAY_ADVERT` (invariant I2). The advertised
    /// `nodeId` is `identity.node_id` (i.e. `SHA-256("SNP/0.1 node\0" ||
    /// identity.public_key)`, invariant I4). The advertised `publicKey` is
    /// `identity.public_key` (raw 32 bytes, invariant I3).
    ///
    /// The caller is responsible for:
    /// - Generating (or loading) the gateway's Ed25519 identity keypair.
    /// - Binding the correct `listen_addr` (transit) and `discovery_addr`
    ///   to the gateway's actual TCP listeners.
    /// - Refreshing the advertisement before its `expiry` (default 1 hour).
    #[must_use]
    pub fn for_identity(identity: &NodeIdentity, listen_addr: &str, discovery_addr: &str) -> Self {
        let now = now_unix();
        let mut advert = Self {
            node_id: identity.node_id,
            public_key: identity.public_key,
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

