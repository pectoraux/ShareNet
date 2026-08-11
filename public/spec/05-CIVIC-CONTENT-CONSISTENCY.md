# ShareNet — Civic Points, Content Distribution, and Consistency Model

---

# PART A — Civic Points (Part 8)

## A1. What is wrong today

From `core-attest/PointsLedger.kt`:

```kotlin
fun pointsForReceipt(bytesDelivered: Long, category: Category?): Long {
    val mb = bytesDelivered / (1024 * 1024)
    return if (category == Category.AD) mb * 1000L * 2 else mb * 1000L
}

fun pointsForBridging(bytesBridged: Long): Long = (bytesBridged / (1024*1024)) * 5000L
```

Three defects:

1. **Payment is per byte.** Exactly what the brief forbids. It rewards volume, not value — sending 1 GB of garbage to a colluding peer pays five times more than relaying a life-critical 200 MB medical dataset.
2. **`pointsForBridging` has no proof object at all.** Delivery has a recipient-signed receipt; bridging is a **bare self-claim**. A node calls the function and mints points. This is precisely the anti-pattern the brief names: *"Do not design a system where users can generate points simply by claiming that they provided service."* It already exists.
3. **Fraud controls are in-memory** (`DefaultFraudControls` uses `mutableMapOf`), so every rate cap resets when the app restarts.

**What to preserve:** the recipient-signed receipt. *The party who benefits signs the proof, so the claimant cannot forge it.* That is the correct primitive and it generalises cleanly.

## A2. The pipeline

```
CONTRIBUTION → PROOF → VERIFICATION → SETTLEMENT → CIVIC POINTS
   (act)      (signed   (independent   (authoritative,  (spendable
              by the     re-check)      durable)         balance)
              beneficiary)
```

**Invariant CP-1: points are never minted by the claimant.** Every proof is signed by a party that did *not* benefit from issuing it.
**Invariant CP-2: points are never final on a client device.** The client keeps a *view*; settlement is authoritative.
**Invariant CP-3: no proof, no points.** A contribution type without a defined proof object cannot be rewarded. This deletes `pointsForBridging` in its current form.

## A3. Contribution types and their proofs

| Contribution | Proof object | Signed by | Verifiable? |
|---|---|---|---|
| **Content delivery** | `DeliveryReceipt` | Recipient | ✅ Strong — beneficiary attests |
| **Internet transit (relay)** | `TransitReceipt` | **Client (circuit originator)** | ✅ Strong |
| **Internet gateway** | `GatewayReceipt` | Client + gateway counter-signature | ✅ Strong |
| **Content seeding** | Aggregated `DeliveryReceipt`s | Multiple distinct recipients | ✅ Diversity-dependent |
| **Storage** | `StorageChallenge` response | Challenger | ⚠️ Requires proof-of-retrievability |
| **Relay availability** | `AvailabilityAttestation` | Peers who probed | ⚠️ Weak — collusion-prone |
| **Custody (Mode A)** | `CustodyReceipt` | Next custodian or final recipient | ✅ Chain-verifiable |
| **Discovery** | — | — | ❌ **Not rewarded.** No sound proof exists. |
| **Infrastructure operation** | Human-vouched `COMMUNITY_RELAY` registration | Governance | ⚠️ Out-of-band |

**Discovery is deliberately unrewarded.** There is no way to prove you introduced two peers without the introduction being trivially fabricable. Rewarding it would be a farming vector. It is listed in the brief as a candidate; the honest answer is no.

## A4. TransitReceipt — the new core object

This is what makes Internet bridging accountable. It replaces `pointsForBridging`.

```cddl
TransitReceipt = {
  circuitId:     bstr .size 8,
  relayId:       bstr .size 32,     ; who is being credited
  clientId:      bstr .size 32,     ; economic identity of beneficiary
  bytesForward:  uint,
  bytesReturn:   uint,
  epochStart:    uint,
  epochEnd:      uint,
  qualityClass:  "interactive" / "bulk" / "tolerant",
  gatewayId:     bstr .size 32 / null,
  nonce:         bstr .size 16,
  clientSig:     bstr .size 64      ; SIGNED BY THE CLIENT — the beneficiary
}
```

Key properties:
- **The client signs.** The relay cannot forge it. Symmetric with `DeliveryReceipt`, and for the same reason.
- Issued **per epoch** (default 60 s), not per frame — bounded overhead.
- A relay that stops forwarding stops receiving receipts. Payment tracks service continuously, with an epoch's granularity of loss.
- `qualityClass` allows value-weighting: sustaining an interactive circuit is worth more per byte than carrying tolerant bulk.
- Gateways receive a `GatewayReceipt` (same shape, counter-signed by the gateway so the amount of *egress* is attested by both parties, since the gateway bears the real cost).

## A5. Value function — beyond bytes

```
points = Σ_contributions  base(type) × volume_factor × quality × scarcity × diversity × reputation
```

| Factor | Range | Purpose |
|---|---|---|
| `base(type)` | fixed per type | Transit > delivery > seeding > storage |
| `volume_factor` | **sub-linear**, e.g. `log₂(1 + MiB)` | **Breaks the "more bytes = more money" incentive.** Doubling volume does not double pay. |
| `quality` | 0–1.5 | Interactive circuits, low loss, high uptime |
| `scarcity` | 1.0–3.0 | Being the *only* gateway in a region is worth far more than being the tenth |
| `diversity` | 0–1 | Distinct counterparties in the epoch — collapses toward 0 for repeated pairs |
| `reputation` | 0–1 | Verified history |

**`volume_factor` being sub-linear is the single most important change from the current design.** It removes the incentive to manufacture traffic while still rewarding real work. **`scarcity` is the second** — it directs reward to where connectivity is genuinely absent, which is the project's actual purpose.

## A6. Anti-farming

| Attack | Defence |
|---|---|
| Self-dealing (own devices) | Points accrue to `DeviceIdentity`; `diversity` collapses for repeated pairs; per-device daily ceiling |
| Two-node collusion ring | `diversity` requires N distinct counterparties for full weight; sub-linear volume caps yield |
| Sybil swarm | See Threat Model T4 — PoW identity cost, physical-encounter weighting, device binding |
| Fake traffic through a real gateway | Gateway counter-signs; gateway bears real bandwidth cost, so it will not sign fictitious volume |
| Replay of receipts | 16-byte nonce, durable unique index at settlement |
| Volume inflation | Both parties sign the byte count; disagreement voids the receipt |
| Restart to reset caps | **Rate state MUST be durable** — fixes the current in-memory `DefaultFraudControls` |

**Holdback and clawback** (already in `PointsLedger`, 30 days) are correct and preserved: points are pending until the holdback elapses, and fraud detected within the window clears them. Keep this.

## A7. Migration from existing code

| Existing | Action |
|---|---|
| `ReceiptManager.generateReceipt/verify` | **Preserve** — generalise to `ContributionProof`; fix `FakeCborCodec` → `Cbor`; add domain separation |
| `DeliveryReceipt` | **Preserve** wire shape; add `SIG_CONTEXT` |
| `pointsForReceipt` | **Replace** with the value function |
| `pointsForBridging` | **Delete.** No proof object. Replaced by `GatewayReceipt`. |
| `PointsLedger` | **Refactor** — keep integer-only arithmetic and holdback; make it explicitly a *view*, not a ledger |
| `DefaultFraudControls` | **Replace** — durable, Room-backed |
| `PlayIntegrityVerifier` in receipt path | **Move** to advisory reputation input; MUST NOT gate |
| `backend/attest/router.py` | **Replace** — currently throws on every call (dict passed to attribute-accessing function) |

---

# PART B — Content Distribution as a Capability (Part 9)

## B1. Position

Content distribution is **L10, a capability over the bearer** — not the network's definition. Preserved in full, but it no longer sets the architecture's terms.

## B2. Preserved without change

- `core-content/Chunking.kt` — Gear CDC. Constants frozen.
- `core-content/BlobStore.kt` — CAS with pinning and LRU.
- `core-catalog/PublisherRegistry.kt` — pinned root, signed delegation, rotation.
- `core-catalog/RevocationList.kt` — ordered sync batching.
- Resumable transfer semantics.

## B3. Changed

- **Merkle → RFC 6962** (leaf/node domain separation, no odd-node duplication). See Protocol Spec §3.2.
- **Streaming chunking API** — current in-memory `ByteArray` API cannot handle the multi-GB models it targets.
- **Anti-entropy replaces the stub.** `SyncWorker`'s `"HAVE:"` string is replaced by a real CBOR HAVE-vector exchange (Bloom filter or IBLT) at L5.
- **Manifest gains `chunkCount` and `class`.**
- **Trust root replaced** — the hardcoded `000102030405…` is a test vector.

## B4. Class A vs Class B semantics, restated

| | Class A content | Class B transit |
|---|---|---|
| Caching | Required | **Forbidden** |
| Duplication | Encouraged | **Forbidden** |
| Addressing | `ObjectId` | `CircuitId` |
| Verification | Merkle + publisher signature | E2E AEAD |
| Ordering | Irrelevant | Strict |
| Latency budget | Unbounded | Mode-dependent |
| Relay reads payload | Yes | **No** |

**The bridge between them:** a Mode A `TransitResponse` body is stored as a Class A object. A gateway fetching content from the origin Internet on the mesh's behalf performs a Class B transit that *yields* a Class A object. This is the correct, explicit form of what `pointsForBridging` was gesturing at.

---

# PART C — Consistency Model (Part 10)

## C1. Why this matters here specifically

`docs/system_architecture_review.md` closes with:

> *"The 'Illusion of Online' is maintained by optimistic local writes that eventually converge via the mesh."*

Applied to Civic Points and wallet balances, **this is an invitation to double-spend.** Eventual consistency is correct for a catalog and catastrophic for money. The current implementation makes it worse: `backend/settlement/router.py` holds double-spend state in module-level Python collections that are lost on restart, and never verifies the `signature` field it accepts.

## C2. Classification

| Data type | Class | Authority | Rationale |
|---|---|---|---|
| Content chunks | `IMMUTABLE` | Content hash | Self-verifying |
| Manifests | `IMMUTABLE` | Publisher signature | Signed; new version = new object |
| `ObjectId` → chunks | `IMMUTABLE` | Merkle | — |
| Catalog membership | `EVENTUAL` | None | Partial views are fine and expected |
| Node descriptors | `EVENTUAL` + expiry | Self-signed | Staleness bounded by `expiresAt` |
| Gateway adverts | `EVENTUAL` + short expiry | Self-signed | ≤300 s |
| Routing tables | `EVENTUAL`, per-node | Local | Convergence not required; **liveness is** |
| Route sequence numbers | `MONOTONIC` | Destination | Non-monotonic ⇒ loops |
| Link/session keys | `AUTHORITATIVE` (local) | Both endpoints | — |
| Circuit sequence numbers | `MONOTONIC` | Circuit | Nonce reuse breaks AEAD |
| **Revocations** | **`APPEND_ONLY` + `MONOTONIC`** | Publisher root | **Never un-revoke.** Must propagate at CRITICAL priority. |
| Contribution proofs | `APPEND_ONLY` | Signer | Immutable once signed |
| Local receipt queue | `APPEND_ONLY` | Local | Client-side buffer |
| **Reputation** | **`EVENTUAL`, locally computed** | **Local only** | Accepting peers' reputation claims is trivially gameable |
| **Civic Point balance** | 🔴 **`AUTHORITATIVE`** | Settlement service | **Local value is a cached view, never truth** |
| Pending points | `MONOTONIC` (local view) | Local | Advisory display only |
| **Wallet balance** | 🔴 **`SECURE_ELEMENT_AUTHORITY`** | Card SE counter | Hardware-enforced |
| **Card tx counter** | 🔴 **`MONOTONIC` + `SECURE_ELEMENT_AUTHORITY`** | Card | **Double-spend detection depends entirely on this** |
| Settlement ledger | 🔴 **`QUORUM_REQUIRED`** (long-term) / `AUTHORITATIVE` (v1) | Settlement | See C4 |
| Publisher registry root | `AUTHORITATIVE` + pinned | Build-time pin | Defence in depth |
| Publisher delegations | `APPEND_ONLY` + revocable | Root signature | — |
| `DeviceCert` | `APPEND_ONLY` + revocable | `UserIdentity` | — |

## C3. Hard rules

**CR-1.** Economic state is never eventually consistent. Civic Points and wallet balances are `AUTHORITATIVE` or `SECURE_ELEMENT_AUTHORITY`. A client MUST render locally-known points as **"pending"** and MUST NOT permit spending against unsettled balance.

**CR-2.** Revocation is monotone. Once revoked, always revoked. A node MUST NOT accept a message that reverses a revocation. Revocation is the one data type that must reach everyone, so it rides at CRITICAL priority — the existing `Governor` tier is correct for this.

**CR-3.** Monotonic counters must be durable across restart. This is a real bug today: `_nonces` and `_tx_records` in `backend/settlement/router.py` are in-memory and reset on restart, which nullifies double-spend detection.

**CR-4.** Local reputation is never transmitted as authoritative. Peers exchange *evidence* (signed proofs); each node computes its own scores.

**CR-5.** Partition tolerance is asymmetric by design:

| During partition | Behaviour |
|---|---|
| Content distribution | **Fully available.** Serve, verify, cache. |
| Routing | **Fully available.** Local view is sufficient. |
| Internet transit | Available iff a gateway is reachable. |
| Proof generation | **Available.** Sign and queue. |
| Point settlement | ❌ **Suspended.** Balance is stale, marked so. |
| Point spending | ❌ **Blocked** — except against SE-held value. |
| Wallet (SE) | ✅ **Available** — this is exactly what the secure element is for. |

**The secure element is the only mechanism that permits offline value transfer, because it is the only component that can enforce a monotonic counter without network consensus.** That is why `card-applet` matters architecturally, notwithstanding that it is currently one Java file and hardware-blocked.

## C4. Settlement authority — an honest open question

v1 uses a single `AUTHORITATIVE` settlement service. This is centralised, and it contradicts the project's decentralisation ethos.

The alternative — `QUORUM_REQUIRED` settlement across community-operated validators — is materially harder: it needs validator selection, Byzantine agreement, and a governance model. **It is out of scope for v1 and should be explicitly deferred rather than half-built.**

What v1 MUST do to keep that door open:
- Settlement inputs are **signed proofs**, so the ledger is independently auditable and reconstructible.
- The settlement API is versioned and the client treats it as a replaceable authority, not a hardcoded endpoint.
- Points are **not transferable between users in v1.** Non-transferable points are a reputation score; transferable points are a currency, with the regulatory and attack surface that implies. Do not cross that line before the settlement authority is decentralised and human-reviewed.
