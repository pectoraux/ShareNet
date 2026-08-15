# ShareNet — Migration Plan, Repository Structure & Roadmap

> **Status:** Live roadmap. The network stack described below is now
> **implemented** in the Rust reference at `reference/snp-node/src/node/`.
> This document is updated to reflect the current implementation state
> at commit `f7bd6ec` (N2.4-I1 rev5).

---

## 1. Migration strategy

**Do not rewrite. Do not refactor in place. Extract, verify, rebuild beneath.**

The original audit found a clean seam: the **content stack was sound and
the network stack did not exist.** That has now changed — the network
stack (identity, discovery, topology, progressive route discovery,
distributed circuits, per-hop encrypted traffic, capability authority)
is **implemented and tested** in the Rust reference.

The current migration state is:

```
DONE      identity, discovery, topology, routing, circuits, traffic, capability authority
KEEP      content addressing, chunking, CAS, catalog trust model, receipt concept
FIX       (ongoing) spec synchronization, capability model unification, gateway service model
BUILD     real Internet gateway service (Mode A), multi-process network harness, Android adapter
DEFER     iOS, decentralised settlement, transferable points, card hardware
DELETE    stale documentation claims, legacy-circuit-keys (after migration)
```

### 1.1 Phase 0 — Stop the bleeding (Week 1)

Before any new work, correct the documents that are actively misleading. The repository currently asserts security properties it does not have; a second agent reading `README.md` and `system_architecture_review.md` would build on false premises.

- [ ] Delete `docs/system_architecture_review.md`; replace with `01-ARCHITECTURE.md`.
- [ ] Rewrite `README.md` — remove "M0-M5 implemented", remove the byte-identical golden-vector claim, state actual status.
- [ ] Rename `PlayIntegrityVerifierImpl` → `NotImplementedPlayIntegrityVerifier`.
- [ ] Rename `KeystoreCryptoProvider` → `StubKeystoreCryptoProvider` and make it **throw at construction**.
- [ ] File issues for every finding in `00-AUDIT.md` §3.
- [ ] Add a `SECURITY.md` stating plainly that no code in the repository is production-ready.

**This phase produces no functionality. It is still the highest-value week in the plan** — it prevents three agents building on documented falsehoods.

### 1.2 Migration sequence

```
Phase 0  Documentation truth                          Week 1
Phase 1  Spec + conformance vectors (Tier 0/1)        Weeks 2-4      ← BLOCKS ALL
Phase 2  Crypto correction + content extraction       Weeks 5-8
Phase 3  Reference implementation (Rust/Linux)        Weeks 7-14
Phase 4  Routing + discovery + sync                   Weeks 11-18
Phase 5  Gateway + Mode A                             Weeks 15-22
Phase 6  Android port                                 Weeks 13-24   (parallel from Ph.2)
Phase 7  Mode B/C virtual networking                  Weeks 21-30
Phase 8  Civic Points + settlement                    Weeks 25-34   🔴 human-gated
Phase 9  Content capability re-integration            Weeks 29-36
```

---

## 2. Module disposition

### 2.1 Remain unchanged (Deliverable 17)

| Module / file | Note |
|---|---|
| `core-content/Chunking.kt` | Gear CDC. **Constants frozen.** Add streaming API alongside — do not modify existing logic. |
| `core-content/BlobStore.kt`, `db/` | CAS, pinning, LRU. Sound. |
| `core-content/Models.kt` | Chunk model. |
| `core-catalog/PublisherRegistry.kt` | Pinned-root + delegation + rotation **design**. Only the hardcoded root value changes. |
| `core-catalog/RevocationList.kt` | Ordered sync batching. |
| `core-catalog/db/` | Schema. |
| `sharenet-feed/*` | Only tested module in the repo. Becomes an L10 capability consumer. |
| `app-demo`, `app-feed` UI | Compose shells; retarget, don't rewrite. |
| `backend` `Decimal(prec=28)` discipline | Correct instinct. Keep. |

### 2.2 Refactor (Deliverable 18)

| Module | Change | Risk |
|---|---|---|
| `core-crypto/Cbor.kt` | Key ordering → RFC 8949 encoded-byte (length-first). Reject non-canonical on decode. | **Breaking** — all existing signatures invalidate. Acceptable: none are valid today. |
| `core-crypto/Models.kt` | `NodeId` becomes a hash, not the key. Split four identity types. | Breaking |
| `core-content/MerkleTree.kt` | RFC 6962 prefixes; remove odd-node duplication; bind `chunkCount`. Keep proof logic. | Breaking — all `ObjectId`s change |
| `core-content/Chunking.kt` | **Add** streaming API. Do not touch boundary logic. | Low |
| `core-transport/Governor.kt` | Generalise to a policy engine feeding route metrics and power-state advertisement. | Low |
| `core-attest/ReceiptManager.kt` | Generalise `DeliveryReceipt` → `ContributionProof`. Replace `FakeCborCodec` with `Cbor`. Add domain separation. | Medium |
| `core-attest/PointsLedger.kt` | Keep integer arithmetic + holdback. Reframe explicitly as a **view**, not a ledger. Delete `pointsForBridging`. | Medium |
| `core-catalog/*Store.kt` | Retarget onto corrected crypto. | Low |
| `sharenet-sdk/ShareNetSdk.kt` | New surface exposing modes and capabilities. | Medium |

### 2.3 Replace outright

| Module | Reason |
|---|---|
| `core-crypto/Crypto.kt` providers | `TinkCryptoProvider` derives keys as `sha256(handle.toString())`; `createRawVerifyHandle` throws unconditionally; `KeystoreCryptoProvider` is a self-declared stub. Rewrite on raw Ed25519. |
| `core-crypto/FakeCrypto.kt` | `verify()` returns `signature.size == 64`. Replace with a fake that actually verifies against a test keypair. |
| `core-transport/Transport.kt` | `EndpointId` is "as issued by Nearby Connections" — a platform API defining protocol semantics. → `Link` interface. |
| `core-transport/NearbyTransport.kt` | Auto-accepts every connection with no peer authentication; BYTES-only (~32 KB cap). → `LinkNearby` with Noise_IK, plus a Play-free link. |
| `core-transport/SyncWorker.kt` | Sends the literal string `"HAVE:"`; `getHaveVector()` returns empty; nothing consumes `incoming`. → `core-sync`. |
| `core-attest/FraudControls.kt` | In-memory counters reset on restart. |
| `sharenet-sdk/SdkModule.kt` | "Production" factory wires `InMemoryUploader`, stub availability, and a test-vector trust root. |
| `backend/common/golden_vectors.py` | Placeholders: `sha256(label)` and all-zero signatures. |
| `backend/attest/router.py` | Throws `AttributeError` on every call. |
| `backend/settlement/router.py` | In-memory state, unverified signatures, unauthenticated revocation. |
| `docs/system_architecture_review.md` | Describes a system that does not exist. |

### 2.4 New modules (Deliverable 19)

| Module | Layer | Owner | Priority |
|---|---|---|---|
| `spec/` | Tier 0/1 | Human + Claude | **P0** |
| `conformance/` | Tier 0 | Human + Claude | **P0** |
| `core-identity` | L1 | Z.ai | P0 |
| `core-link` | L8 | Z.ai | P0 |
| `core-discovery` | L4 | Z.ai | P1 |
| `core-sync` | L5 | Z.ai | P1 |
| `core-routing` | L6 | Z.ai | **P1 — the heart of the new thesis** |
| `core-circuit` | L6/L7 | Z.ai | P1 |
| `core-gateway` | L7 | Z.ai | P1 |
| `core-civic` | L11 | Z.ai | P2 🔴 |
| `platform-linux` | L9 | Z.ai | P1 |
| `platform-android` | L9 | Gemini | P1 |
| `platform-windows` | L9 | Z.ai | P2 |
| `platform-macos` | L9 | Z.ai | P3 |
| `platform-ios` | L9 | deferred | P4 |
| `reference/` | all | Z.ai | **P0** |

### 2.5 Explicitly NOT to be built yet (Deliverable 20)

Building these now would be premature, unsafe, or would foreclose better options.

| Item | Why not | Revisit when |
|---|---|---|
| **iOS implementation** | Entitlements, review risk, and the platform cannot relay or gateway. Effort is high, network contribution is zero. | Android + Linux mesh is live in a real deployment |
| **Decentralised/quorum settlement** | Needs validator selection + BFT + governance. Half-built consensus is worse than an honest centralised authority. | v2, after human design |
| **Transferable Civic Points** | Non-transferable points are a reputation score; transferable points are a currency, with regulatory and attack surface to match. | 🔴 Human legal + security review |
| **Card applet / SE integration** | Hardware procurement, key ceremony, HSM. Correctly listed as human-blocked in roadmap §7. | Hardware secured |
| **Cover traffic / mixnet features** | Costs battery, invites over-claiming anonymity ShareNet cannot provide (T2, A9). | Never for mobile; maybe for `COMMUNITY_RELAY` |
| **Onion routing** | Multi-layer encryption over a 2–3 hop sparse mesh yields little and costs much. | If topology density justifies it |
| **HTML5 app clones (`snr://`)** | Contradicts the thesis. Demote to offline fallback. | Offline fallback only |
| **Ad network / revenue split** | Monetisation before a working network. | Network operates in one real community |
| **AI assistant expansion** | It is an L10 consumer, not the product. | Bearer is stable |
| **Play Integrity gating** | Would exclude AOSP/GrapheneOS — exactly the relay operators needed. | Advisory input only, never a gate |
| **LoRa / exotic links** | Interesting, distracting. `Link` abstraction keeps the door open. | After Wi-Fi/BLE/TCP are solid |
| **Multi-gateway load balancing across a single TCP flow** | Impossible — the socket lives on one gateway. | Never. Document it. |

---

## 3. Recommended repository structure (Deliverable 22)

```
ShareNet/
├── spec/                       ← TIER 1. Normative. Human+Claude owned.
│   ├── SNP-0.1-core.md
│   ├── SNP-0.1-routing.md
│   ├── SNP-0.1-gateway.md
│   ├── SNP-0.1-identity.md
│   ├── SNP-0.1-civic.md
│   ├── platform-matrix.md
│   ├── threat-model.md
│   └── adr/
├── conformance/                ← TIER 0. Golden vectors. THE constraint.
│   ├── vectors/  generator/  runners/  SPEC-COVERAGE.md
├── reference/                  ← Rust, Linux. Defines truth. Z.ai.
│   ├── snp-cbor/  snp-crypto/  snp-object/  snp-identity/
│   ├── snp-link/  snp-discovery/  snp-sync/  snp-routing/
│   ├── snp-circuit/  snp-gateway/  snp-civic/
│   └── snp-node/               (daemon)
├── platform/
│   ├── linux/   (TUN)          ├── windows/ (WinTun)
│   ├── macos/   (utun/NE)      └── ios/     (deferred)
├── android/                    ← Gemini owned. Kotlin port.
│   ├── core-crypto/  core-content/  core-catalog/     (preserved/refactored)
│   ├── core-identity/  core-link/  core-discovery/
│   ├── core-sync/  core-routing/  core-circuit/  core-gateway/
│   ├── platform-android/       (VpnService, FGS, links)
│   ├── sharenet-sdk/
│   └── apps/    (demo, feed, assistant, wallet)
├── backend/                    ← settlement. 🔴 human-gated.
├── card-applet/                ← 🔴 human only. Unchanged.
├── docs/
│   ├── architecture.md  audit-2026-08.md  migration.md  roadmap.md
└── tools/                      interop-harness, network simulator
```

**Key structural decisions:**
- `spec/` and `conformance/` sit **above** all implementations. No implementation directory may contain a normative statement.
- `reference/` is Rust on Linux — no platform obstacles, so protocol bugs surface as protocol bugs.
- `android/` keeps its existing Gradle layout so preserved modules migrate without churn.
- `platform/` isolates every OS-specific line. **If platform code appears outside `platform*/`, the layering is broken.**

---

## 4. Revised roadmap (Deliverable 21)

Milestones renamed `N0…N9` to break association with the old `M0–M13`, whose completion claims cannot be trusted.

### N0 — Truth and specification (Weeks 1–4) — BLOCKS EVERYTHING
Phase 0 doc corrections; `spec/` v0.1 complete; conformance vector *formats* defined; ADR process live; module ownership assigned.
**DoD:** every normative MUST has an ID; `SPEC-COVERAGE.md` exists; a second agent can read `spec/` and implement without inventing decisions.

### N1 — Conformance foundation (Weeks 3–6)
Reference generator; suites 01–07 and 14; Kotlin + Python runners; CI gates including grep gates.
**DoD:** vectors generated by one generator; the existing Kotlin CBOR **fails** ordering vectors (proving the suite works); Suite 14 rejects `verify() == signature.size == 64`.

### N2 — Crypto correction (Weeks 5–8)
Raw Ed25519/X25519 (libsodium or `ed25519-dalek`); CBOR ordering fix; RFC 6962 Merkle; four-way identity split; streaming chunking.
**DoD:** suites 01–06 pass in Kotlin, Python, Rust; **a signature made on one platform verifies on another** — which is not true today.

### N3 — Reference node (Weeks 7–14)
Rust daemon: `snp-link` (TCP + mDNS), Noise_IK handshake, `snp-discovery`, `snp-sync` anti-entropy, Class A transfer.
**DoD:** two Linux nodes discover each other, authenticate, and transfer a 1 GB object with resumption.

### N4 — Routing (Weeks 11–18)
`snp-routing`: gateway-anchored proactive adverts, path-vector loop detection, metric computation, dual-route maintenance, migration. Network simulator with churn.
**DoD:** 20-node simulated mesh; killing the primary gateway migrates traffic within 5 s; no loops under 30% churn.

### N5 — Gateway + Mode A (Weeks 15–22)
`snp-gateway`: egress policy, **RFC 1918 blocking**, quotas, DNS. Mode A bundles with mandatory `tlsTermination`/`deadline`/`maxResponseBytes`. `TransitReceipt` and `GatewayReceipt`.
**DoD:** a Linux node with no route to the Internet fetches a real URL through a peer. **This is the first demonstration of the thesis.**

### N6 — Android port (Weeks 13–24, parallel)
Kotlin core modules against vectors; `platform-android` links (Nearby **and** Play-free Wi-Fi Direct/BLE/TCP); foreground service; Mode A client.
**DoD:** Android ↔ Linux interop passes; an Android phone with mobile data off loads a real web page through a Linux gateway.

### N7 — Modes B and C (Weeks 21–30)
Local SOCKS5 (Mode B); `platform-linux` TUN and `platform-android` `VpnService` (Mode C); userspace NAT at the gateway; gateway-side DNS; flow demux; fail-closed downgrade policy.
**DoD:** unmodified Chrome on an offline Android phone browses the real web through a peer's connection. **This is the thesis, demonstrated.**

### N8 — Civic Points (Weeks 25–34) 🔴 HUMAN-GATED
`core-civic` proof pipeline; durable fraud controls; value function with sub-linear volume and diversity; settlement replacement with durable, authenticated, signature-verifying storage.
**Gate:** human security + economic review before merge. Points remain non-transferable.

### N9 — Content capability re-integration (Weeks 29–36)
Catalog, app distribution, model distribution as L10 over the bearer. Retarget `sharenet-feed`, `app-feed`, `app-assistant`.
**DoD:** content distribution works over routed multi-hop paths, not just single-hop.

### Critical path
```
N0 → N1 → N2 → N3 → N4 → N5 → N7
                      ↘ N6 ↗
```
`N8` and `N9` are parallel from N5. **N0 and N1 block everything and cannot be compressed** — they are the fix for the failure mode that produced the current repository.

---

## 5. Work division (Deliverable 23)

### Human + Claude — specification and review
Owns `spec/`, `conformance/vectors/`, ADR approval, all 🔴 subsystems, threat model, privacy claims, Civic Point parameters, key ceremonies, capability audits.
**Never delegated:** anti-Sybil parameters, settlement authority, point transferability, what is claimed to users about privacy.

### Z.ai — protocol, reference implementation, desktop, backend
**Owns:** `reference/` (all Rust crates), `platform/linux|windows|macos`, `backend/`, `tools/`, `conformance/generator`.
**Why:** the reference implementation must be built by one agent in one language to avoid the divergence the audit found. Linux/Rust has no platform obstacles, so protocol bugs surface cleanly.
**Sequence:** N1 generator → N2 crypto → N3 node → N4 routing → N5 gateway → N7 desktop Mode C → N8 backend.
**Constraints:** may not modify `spec/` or `android/`; every crate ships passing vectors; 🔴 work stops at the design boundary and files an ADR.

### Gemini + Android Studio — Android
**Owns:** `android/` entirely, including preserved `core-content` and `core-catalog`.
**Why:** Android is the network's backbone — the only mobile platform that can relay *and* gateway. It needs sustained, platform-specific attention (FGS lifecycle, permission matrices, Doze, `VpnService`).
**Sequence:** N2 Kotlin crypto → N6 Android core + links → N6 Mode A client → N7 `VpnService` Mode C → N9 content apps.
**Constraints:** must pass identical vectors; may not define protocol semantics; **must implement a Play-free link path**; may not advertise a capability the Platform Matrix denies.

### Deferred / future agents
- **iOS** — after N7, requires human entitlement work.
- **Embedded/RPi** — reuses the Linux reference; packaging only.
- **Security audit** — independent human, before N8 ships.

### Coordination protocol
- Weekly: interop matrix run; failures are P0 for both owners.
- Cross-module need → ADR, never a direct edit.
- **Vector disagreement:** the reference is presumed correct; the other implementation fixes. If the reference is wrong, an ADR regenerates the vector — and every implementation re-verifies.
- A milestone is complete only when its vectors and interop pass. **No document may claim otherwise.**

---

## 6. Success criteria

**Technical.** An Android phone with no SIM and no Wi-Fi Internet, running unmodified Chrome, loads a real website through a peer's connection over ≥2 hops — with the route migrating automatically when the first gateway is switched off.

**Architectural.** A third implementation agent, given only `spec/` and `conformance/`, produces a node that interoperates with both existing implementations without inventing a single architectural decision.

**Honesty.** Every claim in `README.md` is backed by a passing test. That is the one criterion the current repository fails most completely, and the one that everything else depends on.
