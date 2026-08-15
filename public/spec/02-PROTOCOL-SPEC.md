# ShareNet Protocol Specification v0.1 (SNP/0.1)

**Normative.** RFC 2119 keywords. This document defines the wire protocol independently of any platform. Android is one implementation; it has no privileged status. An implementation that passes the Conformance Suite is conformant regardless of language or OS.

**Canonical encoding for all structures: deterministic CBOR per RFC 8949 §4.2.1.**

---

## 1. Encoding rules (SNP-CBOR)

Corrects the divergence found in the audit. Both existing implementations must change to match this.

1. Map keys MUST be sorted by the **bytewise lexicographic order of their fully encoded key**, including the major-type/length head. For text-string keys this is length-first, then UTF-8 bytes.
   - Normative example, `Contribution` keys: `id, capturedAt, sourceLang, sourceText, targetLang, modelVersion, contributorId, correctedText, originalModelOutput`
   - `android/core-crypto/Cbor.kt` currently uses `map.keys.sorted()` (lexicographic, no length prefix). **This is non-conformant and MUST be fixed.**
   - `backend/common/cbor.py::_encode_map` is already conformant.
2. Integers MUST use shortest-form encoding. Definite lengths only. No indefinite-length items.
3. No floats, no tags, no `undefined`. Simple values limited to `false` (0xF4), `true` (0xF5), `null` (0xF6).
4. Duplicate map keys MUST be rejected on decode. Decoders MUST reject non-canonical input (wrong key order, non-shortest ints) — canonical-only decoding, no leniency.
5. Byte strings are major type 2; text strings major type 3. `NodeId`, hashes, and signatures are **byte strings, never hex text**, on the wire.
6. Trailing bytes after a complete item MUST be rejected.

### 1.1 Domain separation

Every signature is over `SIG_CONTEXT ‖ CBOR(payload)` where `SIG_CONTEXT` is an ASCII byte string terminated by `0x00`:

| Structure | Context |
|---|---|
| Manifest | `"SNP/0.1 manifest\0"` |
| DeliveryReceipt | `"SNP/0.1 delivery-receipt\0"` |
| TransitReceipt | `"SNP/0.1 transit-receipt\0"` |
| NodeDescriptor | `"SNP/0.1 node-descriptor\0"` |
| GatewayAdvert | `"SNP/0.1 gateway-advert\0"` |
| RouteAdvert | `"SNP/0.1 route-advert\0"` |
| Revocation | `"SNP/0.1 revocation\0"` |
| DeviceCert | `"SNP/0.1 device-cert\0"` |

**The current repository has no domain separation.** A `DeliveryReceipt` and a future `TransitReceipt` with coincidentally identical field sets would be cross-verifiable. This MUST be fixed before any second receipt type is introduced.

### 1.2 Cryptographic primitives (locked)

| Purpose | Algorithm | Notes |
|---|---|---|
| Signatures | **Ed25519** (RFC 8032) | Raw 32-byte public keys, 64-byte signatures. **Not Tink KeysetHandles.** |
| Key agreement | **X25519** (RFC 7748) | |
| AEAD | **ChaCha20-Poly1305** (RFC 8439) | 12-byte nonce |
| Hash | **SHA-256** | |
| KDF | **HKDF-SHA256** (RFC 5869) | |
| Merkle | **RFC 6962** leaf/node domain separation | See §3.2 |
| Handshake | **Noise_IK_25519_ChaCha20Poly1305_SHA256** | §7.2 |

**Rationale for dropping Tink:** the audit found `TinkCryptoProvider` derives "public keys" as `sha256(handle.toString())` because Tink's raw key import is not public API. Every implementation must interoperate on **raw 32-byte Ed25519 keys**. Use libsodium, BoringSSL, `ed25519-dalek`, or JCA `Ed25519` (Android API 33+) / BouncyCastle below that. Tink MAY be used internally only if raw keys round-trip byte-exactly.

---

## 2. Identity (L1)

### 2.1 Four separated identities

The audit found one Ed25519 key serving as node, user, publisher, and economic identity simultaneously, with `NodeId` documented as "the global primary key everywhere." This is both a privacy failure (a permanent global correlator) and a security failure (one compromise loses everything).

```
                    UserIdentity (UID)
                    Ed25519, offline, backed up, human-recoverable
                    ├── signs ──► DeviceCert
                    │
                ┌───┴────────────────────┬─────────────────────┐
                ▼                        ▼                     ▼
         DeviceIdentity            EconomicIdentity      PublisherIdentity
         Ed25519, per device       Ed25519, settlement   Ed25519, per channel
         hardware-backed           may equal UID         optional
                │
        ┌───────┴────────┐
        ▼                ▼
   NodeIdentity     NodeIdentity        multiple nodes per device
   Ed25519, rotatable, may be ephemeral
        │
        ▼
   RendezvousIdentity (X25519)   ← how responses find you
```

| Identity | Lifetime | Scope | Rotates | On wire |
|---|---|---|---|---|
| **User** | Years | Account, recovery | Rarely (ceremony) | **Never** |
| **Device** | Device lifetime | Attestation, revocation | On re-provision | Rarely, to trusted peers |
| **Node** | Hours–months | Routing, link peer | **Frequently** | Constantly |
| **Economic** | Years | Points, settlement | Ceremony | Settlement only |
| **Publisher** | Per channel | Content signing | Per policy | In manifests |
| **Rendezvous** | Per epoch | Mode A response delivery | Per epoch | Blinded |

### 2.2 NodeId

```
NodeId := SHA-256("SNP/0.1 node\0" ‖ ed25519_public_key)[0..32]
```

**`NodeId` is a hash of the key, not the key itself.** The key is disclosed only during handshake. This is a deliberate change from the current `data class NodeId(val bytes: ByteArray)` where `bytes` *is* the public key and `publicKey` is an alias.

Rationale: a bare public key in every advertisement is a permanent, unrevocable, network-wide correlator. Hashing costs nothing, and combined with rotation it bounds long-term linkability.

### 2.3 NodeIdentity rotation and unlinkability

Nodes SHOULD rotate `NodeIdentity` per **epoch** (default 24 h) or on network change. Rotation MUST be atomic across advertisement, routing, and link layers — a node that rotates its ID but keeps a stable link-layer address (BLE MAC, Wi-Fi Direct name) has gained nothing.

**Honest limitation.** Rotation does not defeat a global passive adversary, and it does not defeat traffic-analysis correlation by a well-placed relay. It raises the cost of casual, local, long-term tracking. It is a mitigation, not a solution. See the Threat Model.

A node MAY hold a **stable** `NodeIdentity` if it is a `COMMUNITY_RELAY` or `INTERNET_GATEWAY` — these are public infrastructure roles where reputation continuity is worth more than unlinkability, and the operator has consented.

### 2.4 DeviceCert

```cddl
DeviceCert = {
  deviceId:      bstr .size 32,
  userId:        bstr .size 32,
  capabilities:  [* capability],
  platform:      tstr,          ; "android" / "ios" / "linux" / "windows" / "macos" / "embedded"
  notBefore:     uint,
  notAfter:      uint,
  attestation:   attestation / null,
  signature:     bstr .size 64  ; by userId
}
```

`attestation` carries platform hardware attestation (Android Key Attestation, iOS DeviceCheck, TPM quote) where available. It MUST be treated as **advisory reputation input, never as an authorisation gate** — requiring it would exclude AOSP, GrapheneOS, and Linux nodes, which are exactly the community-relay operators the network needs. This corrects the current design, where `PlayIntegrityVerifier` sits in the receipt path.

---

## 3. Object layer (L2)

### 3.1 Object addressing

```
ObjectId := merkle_root(chunks)          32 bytes
```

Preserves `core-content` semantics. **Change:** `ObjectId` MUST NOT be reused as the identifier for a single chunk. In the current `MerkleTree.merkleRoot`, a single-leaf blob's root *equals* its chunk hash, so a chunk and a blob are indistinguishable. Fixed by §3.2's domain separation.

### 3.2 Merkle construction (RFC 6962)

**Replaces `core-content/MerkleTree.kt`'s construction.** The existing code is otherwise good and its proof logic can be kept.

```
leaf_hash(chunk)       = SHA-256(0x00 ‖ chunk)
node_hash(left, right) = SHA-256(0x01 ‖ left ‖ right)
empty_root             = SHA-256("SNP/0.1 empty\0")
```

Odd-node handling MUST follow RFC 6962: split at the largest power of two less than `n`, **never duplicate a node**. The current `right = if (i+1 < size) level[i+1] else left` is the CVE-2012-2459 pattern and permits distinct leaf sets to yield identical roots.

Additionally, `Manifest` MUST bind `chunkCount`, and verifiers MUST check it against the received leaf count.

### 3.3 Chunking

Preserve `core-content/Chunking.kt` exactly — Gear rolling hash, splitmix64 table, 20-bit mask, MIN 256 KB / TARGET 1 MB / MAX 4 MB. These constants are **normative and frozen**; changing them forks the network's deduplication.

**Required addition:** a streaming API. `chunk(bytes: ByteArray)` cannot process the multi-GB models the system targets.

```
chunkStream(input: ByteStream, sink: (index, ChunkId, bytes) -> Unit)
```

### 3.4 Manifest

```cddl
Manifest = {
  objectId:     bstr .size 32,
  chunks:       [+ bstr .size 32],
  chunkCount:   uint,                ; NEW — binds leaf count
  totalBytes:   uint,
  mimeType:     tstr,
  class:        tstr,                ; "content" | "app" | "model" | "dataset" | "transit-response"
  publisherId:  bstr .size 32,
  publishedAt:  uint,
  expiresAt:    uint / null,
  signature:    bstr .size 64
}
```

Signed over `"SNP/0.1 manifest\0" ‖ CBOR(manifest without signature)`.

---

## 4. Node model (L1/L4) — Part 5

### 4.1 The four-level distinction

```
USER  ──1:N──►  DEVICE  ──1:N──►  NODE  ──1:1──►  NodeIdentity
```

- **User** — a person or organisation. Holds `UserIdentity`. Never appears on the wire.
- **Device** — a physical machine. Holds `DeviceIdentity` and a `DeviceCert`. Determines *platform* capabilities.
- **Node** — a protocol participant. Holds `NodeIdentity`, advertises capabilities, appears in routes. A device MAY run several (e.g. a stable `INTERNET_GATEWAY` node and a rotating personal `MESH_CLIENT` node — the correct way to run a public gateway without linking it to your browsing).
- **Identity** — the key material, per §2.

### 4.2 Capabilities

```cddl
capability = "MESH_CLIENT" / "MESH_RELAY" / "INTERNET_GATEWAY" / "CONTENT_SEED"
           / "STORAGE" / "DISCOVERY" / "SYNC" / "COMPUTE" / "COMMUNITY_RELAY"
           / "CUSTODY"
```

| Capability | Meaning | Requires |
|---|---|---|
| `MESH_CLIENT` | Originates traffic | Nothing. Baseline. |
| `MESH_RELAY` | **Forwards frames it did not originate** | Background execution |
| `INTERNET_GATEWAY` | Egresses to real Internet | Internet + background sockets |
| `CONTENT_SEED` | Serves Class A objects | Storage |
| `STORAGE` | Offers durable capacity | Disk + persistence |
| `DISCOVERY` | Aggregates/relays peer info | Multiple links |
| `SYNC` | Anti-entropy participant | Storage |
| `COMPUTE` | Local inference/transcode | Hardware |
| `COMMUNITY_RELAY` | Fixed infrastructure, stable ID | Mains power, uptime |
| `CUSTODY` | Holds Mode A bundles for others | Storage + `MESH_RELAY` |

`MESH_RELAY` is the load-bearing capability. **A network of clients and gateways with no relays is a set of hotspots, not a mesh.**

### 4.3 Capability profiles by platform

Normative; justified in the Platform Capability Matrix.

```
Android (Play or AOSP)  MESH_CLIENT, MESH_RELAY, INTERNET_GATEWAY,
                        CONTENT_SEED, STORAGE, DISCOVERY, SYNC, CUSTODY
                        [MESH_RELAY/GATEWAY require foreground service]

Linux / Raspberry Pi    all, including COMMUNITY_RELAY

Windows                 MESH_CLIENT, MESH_RELAY, INTERNET_GATEWAY,
                        CONTENT_SEED, STORAGE, DISCOVERY, SYNC, CUSTODY

macOS                   as Windows

iOS / iPadOS            MESH_CLIENT, CONTENT_SEED (foreground),
                        DISCOVERY (opportunistic)
                        ✗ INTERNET_GATEWAY  ✗ reliable MESH_RELAY  ✗ CUSTODY
```

**A node MUST NOT advertise a capability its platform cannot sustain.** Advertising `MESH_RELAY` from iOS and then failing to forward is indistinguishable from a route-poisoning attack and MUST be penalised identically by the reputation system.

### 4.4 NodeDescriptor

```cddl
NodeDescriptor = {
  nodeId:        bstr .size 32,
  nodePubKey:    bstr .size 32,
  rendezvousPub: bstr .size 32,      ; X25519
  capabilities:  [+ capability],
  platform:      tstr,
  protoVersion:  tstr,               ; "SNP/0.1"
  epoch:         uint,
  expiresAt:     uint,
  links:         [* link_hint],
  deviceCert:    DeviceCert / null,  ; omitted for privacy by default
  signature:     bstr .size 64
}
```

`expiresAt` is mandatory and SHOULD be short (≤ 1 h for mobile). **Descriptors expire rather than being withdrawn** — this is what makes the network survive nodes vanishing without explicit teardown.

---

## 5. Discovery (L4)

Three tiers, used together:

1. **Link-local** — BLE advertisement, mDNS, Wi-Fi Direct service discovery, Bluetooth SDP. Carries a truncated `NodeId` and a capability bitmask only. MUST NOT carry the full descriptor (too large, and it leaks).
2. **Gossiped descriptors** — full `NodeDescriptor`s propagate as Class A objects via anti-entropy, subject to expiry.
3. **Rendezvous** — for `COMMUNITY_RELAY` and `INTERNET_GATEWAY` nodes with stable identities, descriptors MAY be published to a well-known store reachable when any Internet is available.

**Freshness rule:** a descriptor older than `expiresAt` MUST NOT be used for routing and MUST NOT be forwarded. Relays MUST NOT extend expiry.

### 5.1 GatewayAdvert

Separate from `NodeDescriptor` because it changes far more often (capacity and policy fluctuate minute to minute; identity does not).

```cddl
GatewayAdvert = {
  nodeId:         bstr .size 32,
  modes:          [+ "A" / "B" / "C"],
  egressPolicy:   {
    allowedPorts:   [* uint] / "any",
    blockedPorts:   [* uint],
    dnsAvailable:   bool,
    tlsTermination: [* "GATEWAY_PLAINTEXT" / "PAYLOAD_E2E"],
    maxBytesPerReq: uint,
    contentPolicy:  tstr          ; operator-declared, e.g. "open" / "http-only"
  },
  capacity:       {
    maxCircuits:      uint,
    availableBps:     uint,
    queueDepth:       uint,
    remainingQuota:   uint / null    ; bytes this epoch
  },
  costHint:       uint,             ; Civic Points per MiB, operator-set
  observedRtt:    uint / null,      ; ms to a reference host
  validFrom:      uint,
  expiresAt:      uint,             ; SHOULD be ≤ 300 s
  signature:      bstr .size 64
}
```

`remainingQuota` is essential: a gateway on a metered SIM must be able to say "I have 200 MB left this month" so the network stops routing to it rather than bankrupting a volunteer. **The current codebase has no concept of gateway cost or quota. It is a prerequisite for anyone volunteering their connection.**

---

## 6. Routing (L6) — Part 6

### 6.1 Why not gossip

Gossip answers "does anyone have object X?" — a **content** question, appropriate for Class A. Routing must answer **"what is the current best path to an Internet gateway, and what do I do when it disappears?"** These are different problems and gossip cannot answer the second.

### 6.2 Model: progressive next-hop discovery (IMPLEMENTED)

> **⚠️ Architecture correction:** The original spec described a
> gateway-anchored distance-vector routing model with `RouteAdvert`
> propagation. That model has been **superseded** by progressive
> next-hop discovery, which is what the Rust reference implements.
>
> Authenticated topology is **NOT** an executable global graph.
> `ExecutableNetworkSnapshot` is locally observed authenticated
> executable state. Multi-hop discovery is **progressive**: A asks B
> for next-hop candidates, resolves C, authenticates B→C, continues
> toward G.

ShareNet uses **progressive next-hop route discovery** — each hop is
independently authenticated through actual advertisement verification
rather than being promoted from a topology claim:

```
Destination Discovery (RemoteNodeHint → CandidateDestination)
        ↓
Target Authentication (fetch + verify target advertisement)
        ↓
Next-Hop Discovery (ask authenticated neighbor for next-hop candidates)
        ↓
Per-hop Authentication (fetch + verify each candidate's advertisement)
        ↓
Path Assembly (ordered authenticated hops + link evidence)
        ↓
Path Validation (every hop authenticated + every edge backed by evidence)
        ↓
Service Agreement (signed terms — typed, NOT full capability negotiation yet)
        ↓
Route Proposal (source's belief — NOT participant consent)
        ↓
Route Acceptance (per-participant signed consent, typed role + capability)
        ↓
Committed Route (finalized — ALL required participants accepted,
                 retains full hop evidence for circuit establishment)
```

**Key invariants (implemented and tested):**

- `RemoteNodeHint` ≠ `AuthenticatedNodeRecord` — remote claims are
  discovery hints, not identity authority.
- `direct_gateways()` (authenticated, directly reachable) ≠
  `gateway_hints()` (remote claims) — no `all_known_gateways()` conflation.
- `RouteProposal` ≠ `CommittedRoute` — commitment requires participant
  acceptances.
- Every hop in a `CommittedRoute` retains its `AuthenticatedHop` evidence
  (verified node record + link evidence + endpoint + role).
- `PropagationSequence` prevents replay/stale summary lists.

### 6.3 CommittedRoute (IMPLEMENTED)

The implemented route representation is `CommittedRoute`, not the
legacy `RouteAdvert`. A `CommittedRoute` contains:

- The source's `RouteProposal` (signed by the source).
- Per-participant `RouteAcceptance` records (signed by each relay/gateway).
- The ordered `AuthenticatedHop` list with full evidence.
- The `ServiceAgreement` (typed terms).

Commitment logic verifies: proposal signature, proposal freshness,
participant membership, role, capability/role consistency, duplicate
acceptances, and complete acceptance set.

### 6.4 Route metric

A single scalar, computed locally, so different implementations can weight differently without breaking interop — but the **inputs are normative** so the Conformance Suite can test the calculation.

```
cost(route) = Σ_hops [ w_lat·latency + w_loss·loss + w_hop·1 + w_cong·congestion ]
            + gateway_term
            − w_rep·reputation
```

Normative inputs:

| Input | Source | Notes |
|---|---|---|
| `latency` | Measured RTT | EWMA, α = 0.2 |
| `loss` | Measured delivery ratio | |
| `hopCount` | Path vector length | |
| `congestion` | Advertised `queueDepth` | Untrusted |
| `reliability` | Historical route uptime | Local observation only |
| `bandwidth` | Advertised + measured | Prefer measured |
| `batteryState` | Relay's advertised power | See §6.5 |
| `gatewayCapacity` | `GatewayAdvert.capacity` | Untrusted |
| `reputation` | Local + attested | **Locally computed, never accepted from peers** |
| `costHint` | `GatewayAdvert.costHint` | Policy input |
| `scarcity` | Count of distinct known gateways | Raises willingness to use poor routes |
| `stability` | Route age, flap count | Damps oscillation |

**Reputation MUST be locally computed.** Accepting a peer's reputation claim creates a trivially gameable channel. Attested reputation (signed receipts) is *evidence* the local node evaluates.

### 6.5 Battery and mobility as first-class routing inputs

A relay MUST advertise a coarse power state: `MAINS`, `BATTERY_HIGH` (>50%), `BATTERY_LOW` (20–50%), `BATTERY_CRITICAL` (<20%).

- `BATTERY_CRITICAL` nodes MUST be excluded from new routes and SHOULD gracefully shed existing circuits.
- `MAINS` nodes receive a strong metric bonus. This makes Raspberry Pi and community relays naturally preferred, which is the desired topology.
- **This generalises the existing `Governor`.** `core-transport/Governor.kt`'s battery thresholds (5/15/20% by priority) are sound and should become the local policy input feeding this advertisement, rather than only gating local sends.

Mobility: nodes SHOULD track route flap rate and penalise unstable paths. A phone in a moving vehicle should not be selected as a relay for a long-lived circuit.

### 6.6 Route selection

Maintain **at least 2 disjoint routes per active destination where available.** Primary carries traffic; secondary is kept warm with probes. This is what makes §6.7 fast.

Selection is per-traffic-class:

| Class | Optimise for |
|---|---|
| Class B interactive (Mode C) | Latency, stability |
| Class B bulk (Mode B download) | Bandwidth, cost |
| Class A content | Availability, cost — latency irrelevant |
| Control/routing | Reliability |

### 6.7 Route migration and failure recovery

**The requirement: Gateway A disappears, traffic continues via Gateway B, applications do not notice.**

The critical design decision that makes this possible: **`CircuitId` is independent of both route and gateway.**

```
Detection      Circuit keepalive timeout (3 missed, ~2 s) OR
               link-layer down OR relay-signalled NO_ROUTE
   ↓
Local repair   Relay adjacent to the break substitutes an alternate next hop
               for the same destination, without informing the client.
               Handles most transient churn invisibly.
   ↓
Route switch   Client switches to the warm secondary route to the SAME gateway.
               Circuit state preserved. Application sees a latency blip.
   ↓
Gateway        No route to Gateway A. Client re-establishes to Gateway B.
migration      ⚠ TCP flows to origin CANNOT survive — the socket lived on A.
   ↓
Mode A         No gateway reachable. Interactive flows fail fast; tolerant
fallback       flows convert to Mode A bundles and wait.
```

**Honesty about the limit.** Gateway migration cannot preserve a live TCP connection: the origin-side socket is held by Gateway A's kernel. When A dies, that connection dies. Applications see a connection reset — the same as a Wi-Fi/cellular handoff, and handled by the same application-level retry logic that already exists in every real app.

What ShareNet *can* guarantee, and MUST:
- The **virtual interface stays up** — no interface-down event, so apps do not tear down their network state.
- The client's **virtual IP is stable** across gateway migration.
- **New** connections succeed immediately via Gateway B.
- **Mode A bundles survive gateway loss entirely** — they are addressed to a set of acceptable gateways, so any gateway completes them. *This is a genuine advantage of Mode A and should be stated as one.*

Claiming that arbitrary long-lived TCP sessions survive gateway migration would be false. Do not build UI or documentation that implies it.

---

## 7. Frame format and circuits

### 7.1 SNP frame

Every frame on every link:

```cddl
Frame = {
  v:     uint,              ; protocol version = 1
  cls:   "A" / "B" / "C",   ; A=content, B=transit, C=control
  dst:   bstr .size 32,     ; destination NodeId
  src:   bstr .size 32,     ; source NodeId (or blinded — §7.4)
  ttl:   uint,              ; decrement per hop, drop at 0. Max 16.
  fid:   bstr .size 8,      ; flow/circuit id — opaque to relays
  seq:   uint,
  body:  bstr               ; Class A: object protocol. Class B: ciphertext.
}
```

**Relays process `dst`, `ttl`, `fid`, `seq` and nothing else for Class B.** A relay that decrypts or inspects a Class B `body` is non-conformant.

### 7.2 Link handshake

Every link MUST run **Noise_IK** before carrying frames. This is the missing peer authentication identified in the audit — `NearbyTransport` currently auto-accepts every connection with no identity check whatsoever.

```
Initiator                                Responder
  → e, es, s, ss   {NodeDescriptor}
  ←        e, ee, se   {NodeDescriptor}
  ── transport keys established; link is authenticated and encrypted ──
```

Provides: peer authentication, forward secrecy, identity hiding for the initiator, and 0-RTT-ish setup. Link encryption is **in addition to** end-to-end circuit encryption, never a substitute — the audit's finding that Nearby's link encryption terminates at each hop is exactly why.

### 7.3 Circuit encryption (Class B)

```
Client ═══════════ E2E ChaCha20-Poly1305 ═══════════ Gateway
        R1 sees ciphertext   R2 sees ciphertext
```

- Keys from Noise_IK between client `NodeIdentity` and gateway `NodeIdentity`.
- Rekey every 2^20 frames or 15 minutes.
- Nonce = `fid ‖ seq`; strictly monotonic. Receivers keep a sliding replay window (default 1024).
- **Relays cannot decrypt.** A relay knows: previous hop, next hop, `fid`, frame sizes, and timing. It does not know the origin server, the protocol, or the content.

### 7.4 Metadata minimisation

Relays inevitably learn *something*. Required mitigations, with honest limits:

| Leak | Mitigation | Residual risk |
|---|---|---|
| `src` visible to every hop | Blind `src` to per-circuit ephemeral ID | First-hop relay still knows who you are |
| Frame sizes | Pad Class B frames to 256/512/1024/1500 buckets | Coarse fingerprinting survives |
| Timing | Optional jitter (costs latency) | Correlation by global observer survives |
| Circuit longevity | Rotate `fid` per epoch | Rotation itself is observable |
| Gateway learns destinations | Nothing — inherent to the role | **Choose gateways you trust; use multiple** |

**Stated plainly: ShareNet is not an anonymity network.** It does not provide Tor-equivalent guarantees. The first-hop relay knows a client is using the network; the gateway knows what the client is connecting to. The design goal is that **no single node knows both**, and that is achievable — but it must not be oversold.

---

## 8. Gateway protocol (L7)

### 8.1 Mode B / C circuit operations

```cddl
CircuitOpen = { op: "open", proto: "tcp"/"udp", host: tstr, port: uint,
                mode: "B"/"C", deadline: uint }
CircuitData = { op: "data", data: bstr }
CircuitClose = { op: "close", reason: tstr }
DnsQuery    = { op: "dns", name: tstr, type: uint }
```

Gateway MUST enforce its advertised `egressPolicy` and MUST reject `CircuitOpen` to RFC 1918, loopback, link-local, and multicast destinations unless explicitly configured. **Without this an open gateway is an SSRF pivot into its owner's LAN.** This is a hard requirement, not a hardening nicety.

### 8.2 Mode A bundles

```cddl
TransitRequest = {
  reqId:           bstr .size 16,
  method:          tstr,
  url:             tstr,
  headers:         { * tstr => tstr },
  body:            bstr / null,
  tlsTermination:  "GATEWAY_PLAINTEXT" / "PAYLOAD_E2E",   ; MANDATORY
  maxResponseBytes: uint,                                  ; MANDATORY
  deadline:        uint,                                   ; MANDATORY
  replyTo:         bstr .size 32,   ; rendezvous identity, not NodeId
  acceptGateways:  [* bstr .size 32] / "any",
  clientSig:       bstr .size 64
}

TransitResponse = {
  reqId:      bstr .size 16,
  status:     uint,
  headers:    { * tstr => tstr },
  objectId:   bstr .size 32,     ; body is a Class A object — reuses CAS
  fetchedAt:  uint,
  gatewayId:  bstr .size 32,
  gatewaySig: bstr .size 64      ; gateway attests it performed this fetch
}
```

The response body being a **content-addressed object** is the key reuse: it gets chunking, Merkle verification, resumable transfer, and multi-source fetch from `core-content` for free. A large Mode A download can be reassembled from several relays that each carry part of it.

`gatewaySig` is what makes `GATEWAY_PLAINTEXT` accountable — the client knows exactly which gateway saw the plaintext.

---

## 9. Version negotiation and forward compatibility

- `protoVersion` in `NodeDescriptor`; `v` in every frame.
- Nodes MUST reject frames with unknown major versions.
- **Unknown CBOR map keys MUST be rejected in signed structures** (they would break signature determinism) and **MAY be ignored in unsigned control structures.**
- New capabilities and new frame classes are additive; unknown values MUST be ignored rather than causing disconnect.

---

## 10. Frozen constants

Changing any of these forks the network. They require an ADR and a protocol version bump.

| Constant | Value |
|---|---|
| Chunking MIN / TARGET / MAX | 256 KiB / 1 MiB / 4 MiB |
| Chunking mask bits | 20 |
| Gear table derivation | splitmix64 over `i` |
| Merkle | RFC 6962, SHA-256, `0x00`/`0x01` prefixes |
| `NodeId` derivation | `SHA-256("SNP/0.1 node\0" ‖ pk)` |
| Signature scheme | Ed25519, raw 32-byte keys |
| AEAD | ChaCha20-Poly1305, 12-byte nonce |
| CBOR | RFC 8949 §4.2.1 canonical, encoded-key ordering |
| Max TTL | 16 |
| Frame padding buckets | 256 / 512 / 1024 / 1500 |
