# ShareNet — Security Threat Model & Human-Review Boundary

---

## 1. Adversaries

| ID | Adversary | Capability | In scope |
|---|---|---|---|
| A1 | Curious relay | Sees frames it forwards | ✅ |
| A2 | Malicious relay | Drops, delays, reorders, forges metrics | ✅ |
| A3 | Malicious gateway | Sees all transit destinations; can tamper with plaintext | ✅ |
| A4 | Sybil operator | Thousands of cheap identities | ✅ |
| A5 | Local passive observer | RF monitoring in one area | ✅ |
| A6 | Compromised device | Full key access on one node | ✅ |
| A7 | Economic attacker | Farms Civic Points | ✅ |
| A8 | Content publisher attacker | Forged/malicious objects | ✅ |
| A9 | Network-wide passive observer | Sees all links everywhere | ❌ **Out of scope — stated, not solved** |
| A10 | State actor with device seizure | Legal compulsion, forensics | ❌ Partially mitigated only |

**A9 and A10 are explicitly out of scope.** ShareNet is not Tor. Documenting this is a requirement, not an admission — a user in a repressive environment must not mistake ShareNet for an anonymity system.

---

## 2. Threat catalogue

### T1 — Traffic analysis
**Threat:** A1/A5 correlate frame timing and size to infer activity even without decryption.
**Mitigations:** padding to 256/512/1024/1500 buckets; optional timing jitter; `fid` rotation per epoch; cover traffic on `COMMUNITY_RELAY` nodes only (mobile cannot afford it).
**Residual:** ⚠️ **Substantial.** Coarse patterns survive. A relay learns *that* you use the network and roughly how much.

### T2 — Endpoint correlation
**Threat:** first-hop relay knows the client; gateway knows the destination. Collusion links them.
**Mitigations:** ≥2 hops required for Class B where topology permits; prefer routes where first hop and gateway are not co-operated (heuristic: different `UserIdentity` where disclosed, different platform, different subnet); client may use multiple gateways concurrently.
**Residual:** ⚠️ **High in sparse networks.** In a village with one gateway and one relay, there is no anonymity. **This must be stated in the UI when the topology is that thin.** Do not pretend otherwise.

### T3 — Replay
**Threat:** relay replays captured frames or receipts.
**Mitigations:** per-circuit monotonic `seq` with 1024-frame sliding window; AEAD nonce = `fid‖seq`, reuse is fatal and detectable; receipts carry a 16-byte nonce and are deduplicated at settlement; Mode A `reqId` deduplicated at gateway.
**Residual:** ✅ Low, **if** nonce state survives restart. The current in-memory `_nonces` set in `backend/attest/router.py` does not. Must be durable and unique-indexed.

### T4 — Sybil
**Threat:** A4 generates identities to dominate routing, farm points, or eclipse a victim.
**Mitigations, layered — none sufficient alone:**
1. **Cost of identity:** proof-of-work on `NodeId` generation (a leading-zero prefix). Cheap for honest nodes, linearly costly at scale.
2. **`DeviceCert` binding:** many nodes may share a device, but points accrue to `DeviceIdentity`, capping per-device yield.
3. **Physical-encounter weighting:** reputation is earned only through *observed* link-layer contact. A Sybil swarm on one device cannot manufacture distinct physical encounters.
4. **Web-of-trust for `COMMUNITY_RELAY`:** human-vouched, out-of-band.
5. **Diversity requirements at settlement:** points require counterparty diversity (§Civic Points).
**Residual:** ⚠️ **Medium.** Sybil resistance without a central authority or stake is an unsolved problem. ShareNet raises cost; it does not eliminate the attack. **This is the single largest open security risk in the design and is flagged for human review.**

### T5 — Malicious relay: drop / delay / reorder
**Threat:** A2 blackholes traffic or degrades it selectively.
**Mitigations:** end-to-end circuit keepalives detect loss regardless of relay claims; local reputation decrements on observed loss; ≥2 warm routes enable fast migration; relays that consistently underperform their advertised metric are demoted.
**Residual:** ✅ Low for availability (routes migrate). ⚠️ Medium for targeted censorship in a sparse topology.

### T6 — Route poisoning / metric forgery
**Threat:** A2 advertises fraudulent metrics to attract traffic (then drops it, or observes it).
**Mitigations:** path-vector loop detection; monotonic `seq` per destination with origin signature over the origin-owned fields; **metrics are treated as untrusted hints and validated against local measurement** — advertised RTT that disagrees with measured RTT decrements reputation; route selection weights measured over advertised.
**Residual:** ⚠️ Medium. Per-hop metrics are structurally unsignable — no node can attest to another's link quality. Mitigation is empirical, not cryptographic. **Design rule: never make a routing decision on advertised data alone when measured data is available.**

### T7 — Fake availability
**Threat:** a node advertises `INTERNET_GATEWAY` or `MESH_RELAY` it cannot deliver, to attract traffic or farm points.
**Mitigations:** gateway capability is provable — clients verify with a signed reachability probe to a known reference; capability advertisement without delivery decrements reputation sharply; **no points are ever awarded for advertisement, only for verified delivery.**
**Residual:** ✅ Low. This is well-defended because the service is directly verifiable by the beneficiary.

### T8 — Malicious gateway
**Threat:** A3 reads, tampers with, or logs traffic.
**Mitigations:**
- Modes B/C: TLS is end-to-end with the origin. Gateway sees SNI/IP only — equivalent to an ISP.
- Mode A `PAYLOAD_E2E`: opaque body.
- Mode A `GATEWAY_PLAINTEXT`: **gateway sees everything. There is no mitigation.** The `tlsTermination` field is mandatory precisely so this is a conscious, per-request choice, and `gatewaySig` names the gateway that saw it.
- Clients MUST refuse credentials over `GATEWAY_PLAINTEXT`.
- Gateway reputation; clients may pin trusted gateways.
**Residual:** ✅ Low for B/C. 🔴 **Inherent and unmitigable for Mode A `GATEWAY_PLAINTEXT`.** This must be prominent in the UI, not a footnote.

### T9 — Gateway abuse (the operator's risk)
**Threat:** a client routes illegal or abusive traffic through a volunteer's home connection, attributable to that volunteer's IP.
**This is the risk most likely to end the project socially, and the current codebase has no defence whatsoever.**
**Mitigations:**
- Mandatory operator-configured `egressPolicy`; conservative defaults (HTTP/HTTPS/DNS only).
- **Mandatory RFC 1918 / loopback / link-local / multicast blocking** — without it a gateway is an SSRF pivot into its owner's LAN.
- Per-client rate and volume quotas; `remainingQuota` advertisement.
- Operator-visible logging of *destinations only* (never content), retained locally and briefly, so an operator can respond to a complaint.
- Optional operator allow/deny lists.
- Clear operator consent flow explaining the risk **before** `INTERNET_GATEWAY` can be enabled.
**Residual:** 🔴 **High, and partly legal rather than technical.** Flagged for human legal review. Deployment jurisdiction matters enormously.

### T10 — Receipt fraud
**Threat:** A7 fabricates proofs of contribution.
**Mitigations:** the beneficiary signs, never the claimant (preserved from `core-attest` — the best idea in the existing codebase); counterparty diversity requirements; durable rate caps; holdback with clawback; settlement-side verification with a durable nonce index.
**Residual:** ⚠️ Medium — bounded by Sybil resistance (T4). Two colluding real devices can generate mutual receipts for service genuinely rendered between themselves. **Diversity requirements are the only defence and they are heuristic.**

### T11 — Denial of service
**Threat:** flooding, circuit exhaustion, storage exhaustion via Mode A bundles.
**Mitigations:** per-peer rate limits at the link layer; `maxCircuits` enforced by gateways; **`deadline` and `maxResponseBytes` mandatory on every Mode A bundle** so custody storage is bounded; TTL ≤ 16; proof-of-work on identity raises flood cost; relays shed load by capability, dropping Class A before Class B control.
**Residual:** ⚠️ Medium. A mesh with battery-constrained nodes is inherently DoS-sensitive; a node can always be drained.

### T12 — Identity theft / key compromise (A6)
**Mitigations:** hardware-backed keys where available (Keystore/StrongBox, Secure Enclave, TPM); **`UserIdentity` is offline and never on the wire**; compromise of a `NodeIdentity` loses only that node; `DeviceCert` revocation propagates as CRITICAL-priority Class A; economic identity is separate, so a stolen phone does not drain a wallet.
**Residual:** ✅ Low — **this is the primary payoff of the four-way identity split.** Under the current single-key design, one compromised phone loses the user's node, publisher, and economic identity simultaneously.

### T13 — Malicious content (A8)
**Mitigations:** all objects Merkle-verified against a signed manifest; publisher registry with pinned root and signed delegation (`core-catalog` design is sound); revocation propagates at CRITICAL priority; RFC 6962 domain separation closes the leaf/node second-preimage gap.
**Residual:** ✅ Low, **once the pinned root is a real key and not `000102030405…`**.

### T14 — Eclipse
**Threat:** A4 surrounds a victim with attacker-controlled nodes, controlling its entire view.
**Mitigations:** require route diversity across distinct link types (BLE + Wi-Fi + Internet) where available; persist known-good peers across restarts; long-lived `COMMUNITY_RELAY` anchors; alert the user when *all* peers are new and unattested.
**Residual:** ⚠️ **High in sparse networks.** A user whose only peer is the attacker cannot be helped by protocol design.

### T15 — Downgrade attack
**Threat:** an adversary forces Mode C → Mode A `GATEWAY_PLAINTEXT` to read traffic.
**Mitigation:** mode and `tlsTermination` are **client policy, not negotiated capability**. A client configured to require `PAYLOAD_E2E` MUST fail closed rather than downgrade. UI must display the active mode.
**Residual:** ✅ Low if implemented as fail-closed. 🔴 High if any implementation makes downgrade automatic. **Listed as a forbidden architectural change.**

---

## 3. Privacy analysis: what each party learns

| Party | Learns | Does not learn |
|---|---|---|
| First-hop relay | Client node exists, is active, approximate volume | Destination, content, client's user identity |
| Middle relay | Two adjacent node IDs, frame sizes/timing | Origin, destination, content |
| Gateway | Destination host/IP, volume, timing; **plaintext iff `GATEWAY_PLAINTEXT`** | Client's user identity (unless linked by other means) |
| Local RF observer | Devices present, that ShareNet is in use | Content, destinations |
| Settlement backend | Economic identities, aggregate contribution volumes | Content, destinations, node identities |

**The design goal is that no single party learns both "who" and "what."** In a healthy topology this holds. In a sparse topology (one relay, one gateway, both possibly the same operator) **it does not**, and the implementation must detect and disclose that condition rather than imply protection it cannot provide.

---

## 4. Part 14 — Security-critical subsystem classification

### 4.1 🟢 SAFE FOR AI IMPLEMENTATION

Well-specified, testable against golden vectors, failure modes are functional rather than catastrophic:

- Deterministic CBOR encode/decode
- Chunking (Gear/CDC)
- Merkle tree construction and proofs (against RFC 6962 vectors)
- Object store, blob index, LRU eviction
- Manifest parsing and validation logic
- Frame serialisation and parsing
- Routing table data structures, metric arithmetic, path-vector loop detection
- Discovery bookkeeping, descriptor expiry
- Anti-entropy / HAVE-vector exchange
- Transport link adapters (BLE, TCP, Wi-Fi Direct plumbing)
- TUN/VpnService packet plumbing and flow demultiplexing
- Userspace NAT / flow table
- UI, storage, local database schemas
- Conformance test harnesses

### 4.2 🟡 AI-IMPLEMENTABLE, MANDATORY HUMAN SECURITY REVIEW BEFORE MERGE

Correct-looking implementations can be silently wrong:

- Noise_IK handshake integration (**use a vetted library; do not hand-roll**)
- AEAD nonce construction and rekey scheduling
- Replay-window logic
- Key derivation and `NodeId` derivation
- Signature verification call sites (**the audit found a `verify()` that returns `signature.size == 64`**)
- Gateway egress policy enforcement, especially RFC 1918 blocking
- Rate limiting and quota enforcement
- Revocation propagation and enforcement
- Reputation calculation
- Route metric validation against measurement

### 4.3 🔴 REQUIRES HUMAN SECURITY DESIGN AND REVIEW — AI MAY NOT DECIDE

Not because AI cannot write the code, but because the **design decisions are consequential, contested, and not verifiable by tests**:

| Subsystem | Why |
|---|---|
| **Anti-Sybil mechanism design** | Unsolved research problem (T4). Parameter choices determine whether the economy survives. |
| **Civic Point issuance and settlement** | Real economic value. Errors are theft. |
| **Payment and wallet** | Regulated. Licensing implications. |
| **Secure element / card applet** | Hardware ceremony, key injection, procurement. |
| **Cryptographic key ceremonies** | Root key generation, custody, rotation, pinned-root provisioning. |
| **Identity recovery** | The recovery path *is* the attack path. Trade-off between lockout and takeover. |
| **Gateway abuse prevention & operator liability** | Legal, jurisdictional (T9). |
| **Privacy guarantee statements** | What is *claimed* to users is an ethical decision. |
| **Mode A `GATEWAY_PLAINTEXT` policy** | Deliberate plaintext exposure (T8). |
| **Threat model scope (A9/A10)** | Deciding what *not* to defend is a human decision. |

### 4.4 Labelling discipline — non-negotiable

The audit found `PlayIntegrityVerifierImpl` (named as production) returning `Unavailable`, `KeystoreCryptoProvider` self-described as "a **stub** for M0" wired into the production factory, and a README claiming byte-identical cross-language vectors that were `sha256(label)` placeholders with all-zero signatures.

**Mandatory rules going forward:**

1. Any non-functional implementation MUST be named `NotImplemented*` or `Stub*` — never `*Impl`, never `Default*`, never `Production*`.
2. Any type named `Fake*` MUST NOT be referenced from a `main` source set. (Currently `ReceiptManager` and `ShareNetSdk` sign using `FakeCborCodec`.)
3. A stub in a security-critical path MUST throw `NotImplementedError` at construction, not return a permissive default. **`verify()` returning `true`, or `signature.size == 64`, is the worst possible failure mode** — it is silent and it inverts the security property.
4. No milestone may be marked complete in any document without a **passing, executable test**. The `README` "M0-M5 implemented" claim, against one test file in the entire codebase, is how this repository reached its current state.
5. Every `// Real:` or `// In production this would…` comment is a merge blocker in a 🟡 or 🔴 subsystem.
