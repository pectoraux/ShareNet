# ShareNet — Repository Audit & Gap Analysis

**Audited commit:** `c4266d5` (repo has exactly 2 commits; all code landed in `0874207` "Initial production-hardened release")
**Method:** full source read of `android/` (100 Kotlin files), `backend/` (17 Python files), `card-applet/`, `docs/`. Claims in `README.md` and `docs/system_architecture_review.md` were treated as unverified assertions and tested against source. Two findings were verified by executing the repository's own code.

---

## 0. Headline

The repository is a **well-organised, plausibly-shaped scaffold whose cryptographic and networking foundations do not function.** The module boundaries, data model, and content-addressing layer are genuinely good and worth preserving. Almost everything below them that the system's security depends on is either a stub, a placeholder, or actively incorrect.

Critically for the new thesis: **there is no Internet gateway, routing, tunnelling, relay, or multi-hop code anywhere in the repository.** A grep across all Kotlin and Python for `gateway|route|tunnel|relay|nextHop|VpnService|TUN` returns only `SmsGateway.kt` (an SMS `BroadcastReceiver` for keypad-phone commands) and Compose navigation `toRoute` calls. ShareNet today is a **single-hop, store-and-forward content exchange** — not a mesh network in the routing sense. The new thesis is therefore not a refactor of the existing network layer; it is a **new network layer** beneath a preserved content layer.

Two of the modules I was asked to inspect — **`core-gossip` and `core-incentive` — do not exist.** Gossip lives (vestigially) in `core-transport/SyncWorker.kt`; incentives live in `core-attest`.

---

## 1. What actually exists

`android/settings.gradle.kts` declares 12 modules. Actual line counts:

| Module | Kotlin LOC | Verdict |
|---|---|---|
| `core-crypto` | 1463 | **Broken** — production provider non-functional |
| `core-catalog` | 1010 | Sound design, unverifiable at runtime (depends on crypto) |
| `core-content` | 862 | **Genuinely implemented** — best code in repo |
| `testing` | 648 | Fakes + fixtures; golden vectors are placeholders |
| `core-transport` | 635 | Single-hop only; gossip is a stub |
| `core-attest` | 600 | Design sound, enforcement fake |
| `sharenet-sdk` | 475 | Production factory wires stubs |
| `sharenet-feed` | 685 | Only tested module in the repo |
| `app-assistant` / `app-wallet` / `app-demo` / `app-feed` | 3445 | UI shells |

**Test coverage across the entire Android codebase is one file:** `sharenet-feed/src/test/java/net/sharenet/feed/FeedRepositoryTest.kt`. There are no tests in `core-crypto`, `core-content`, `core-catalog`, `core-transport`, `core-attest`, or `sharenet-sdk`.

---

## 2. Genuinely implemented

### 2.1 `core-content` — preserve
- **`Chunking.kt`** — real content-defined chunking. Gear rolling hash over a splitmix64-derived 256-entry table, 20-bit boundary mask, MIN 256 KB / TARGET 1 MB / MAX 4 MB. Correct and deterministic.
- **`MerkleTree.kt`** — real binary Merkle tree, real `buildProof`/`verifyProof`, parallel leaf verification via `Dispatchers.Default`.
- **`BlobStore.kt` / `db/`** — Room-backed blob index with pinning and LRU eviction.

This is the only subsystem where the code matches its documentation.

### 2.2 `core-crypto/Cbor.kt` — preserve with one normative fix
A real hand-rolled deterministic CBOR encoder/decoder covering majors 0,1,2,3,4,5,7. Shortest-form integers, definite lengths, no floats. Correct except for map key ordering (§3.2).

### 2.3 `core-catalog` — architecturally sound
`PublisherRegistry.kt` implements a pinned-root trust model with signed delegation and old-root-signs-transition rotation, and treats the pinned root as trusted even if the DB disagrees (defence in depth). `RevocationList.kt` has ordered sync batching. The **design** is right; it is untestable today because every signature check routes into broken crypto, and because the pinned root is a test vector (§3.4).

---

## 3. What is fake, and what is broken

I distinguish **fake** (honestly labelled placeholder) from **broken** (labelled production, does not work). The repository's central problem is the second category.

### 3.1 BROKEN — `TinkCryptoProvider` is non-functional (`core-crypto/Crypto.kt:120-300`)

Documented as "Production `CryptoProvider` using Google Tink's Ed25519". It is not.

- `extractRawPublicKey()` → `derivePublicBytesFromHandle()` → **`sha256(handle.toString())`**. `KeysetHandle.toString()` returns a redacted debug summary. The "Ed25519 public key" is a hash of a debug string. **`NodeId` is therefore not a public key and nothing signed by one device can be verified by another.**
- `extractRawPrivateKey()` → `sha256(handle.toString() + "-priv")`. Likewise not a private key.
- `ephemeralHandleFromPrivate()` generates a **fresh random keypair** and admits it in comment: *"the signature will be valid but not correspond to the supplied privateKey bytes."* So `sign(privateKey, bytes)` signs with an unrelated key.
- `createRawVerifyHandle()` **throws unconditionally**. `verify()` catches `GeneralSecurityException` and returns `false`. Therefore **verification of any public key not in the local in-memory `handleCache` — i.e. every remote peer — always returns `false`.**
- `seededKeypair()` calls `KeysetHandle.generateNew()`, discards it, then derives from `sr.nextLong()` into another random handle. Not deterministic in key material.

**`KeystoreCryptoProvider` (`Crypto.kt:504`) — the provider actually wired in `SdkModule.create()` — is self-documented as "a **stub** for M0" and delegates `verify()` straight to the above.** Its `sign()` also ignores the caller's `privateKey` whenever a Keystore handle exists, signing with the device default alias regardless of requested identity.

**Consequence: no signature produced on one device can be verified on another, anywhere in ShareNet, today.** Every trust claim in `system_architecture_review.md` §4.1 rests on this.

### 3.2 BROKEN — the two CBOR implementations disagree

`core-crypto/Cbor.kt` sorts map keys with `map.keys.sorted()` (Kotlin `String` natural order). `backend/common/cbor.py::_encode_map` sorts by the **encoded** key bytes, which includes the major-type/length head — i.e. length-first. RFC 8949 §4.2.1 requires the latter. Kotlin is wrong.

Executed against the real `Contribution` field set:

```
Python (RFC 8949, correct): id, capturedAt, sourceLang, sourceText, targetLang,
                            modelVersion, contributorId, correctedText, originalModelOutput
Kotlin (lexicographic)    : capturedAt, contributorId, correctedText, id, modelVersion,
                            originalModelOutput, sourceLang, sourceText, targetLang
IDENTICAL: False
```

Different byte strings → different signatures → cross-platform verification fails even once §3.1 is fixed.

### 3.3 BROKEN — the golden vectors are placeholders, and the README claim is false

`README.md`: *"Kotlin and Python produce byte-identical CBOR + Ed25519 signatures for 20 fixtures. See `android/core-crypto/src/test/resources/golden-vectors.json`."*

- **That file does not exist.** Golden vectors exist only on the Python side.
- `backend/common/golden_vectors.py` generates `"cbor_hex": hashlib.sha256(f"cbor-manifest-{i}").hexdigest()[:64]` — a hash of a label, not an encoding — and `"signature_hex": "00" * 64`.
- Its own docstring admits: *"hand-computed placeholders that satisfy shape. Real values are filled by running `common/golden_vectors_test.py --regenerate`."* **That script does not exist.**

Verified by running the repo's own encoder on fixture `manifest-00`:

```
stored  cbor_hex length:  32 bytes
ACTUAL  encoding length: 241 bytes
MATCH: False
all 20 signatures all-zero: True
```

**M0 — declared in the roadmap as "blocks everything" — was never completed.** Nothing has ever cross-validated. This is precisely why §3.1 and §3.2 went unnoticed, and it is the single most important finding for a multi-agent build.

### 3.4 BROKEN — the trust root is a test vector

`sharenet-sdk/SdkModule.kt:38`:
```kotlin
private const val PINNED_ROOT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e00"
```
Counting bytes. This is the anchor of the entire publisher trust chain, hardcoded in the production factory.

### 3.5 BROKEN — the "production" SDK factory wires stubs

In `SdkModule.create()` (the documented production path):
- `uploader = InMemoryUploader()` — receipts are "uploaded" to an in-memory `ArrayList`, then marked `UPLOADED` and effectively discarded. **The production SDK never contacts the backend. Settlement does not happen.**
- `localAvailability` is an inline object returning `null` / `emptyList()` unconditionally.
- `DefaultFraudControls()` — in-memory `mutableMapOf` counters, wiped on process death.

### 3.6 BROKEN — backend receipt ingest throws on every call

`backend/attest/router.py`:
```python
payload = encode_receipt_signing(r.model_dump() if hasattr(r, 'model_dump') else dict(r))
```
`encode_receipt_signing` performs attribute access (`receipt.blob_id.merkle_root`, `receipt.bytes_delivered`, …) on what is now a `dict` → `AttributeError` → HTTP 500. `POST /attest/receipts` cannot succeed.

### 3.7 FAKE (honestly labelled) — the gossip protocol

`docs/system_architecture_review.md` §2.3 claims *"Nodes exchange 'HAVE' vectors (compact summaries of local catalogs)."* In `core-transport/SyncWorker.kt`:

- `ChunkProtocol` declares `TYPE_REQUEST`/`TYPE_RESPONSE`/`TYPE_HAVE` and three data classes. Its KDoc says *"All payloads are length-prefixed CBOR maps with a `type` discriminator."* **No encoder or decoder exists.** Nothing serialises these types.
- The worker sends `"HAVE:${vector.joinToString(",")}"` as an ASCII string — contradicting its own spec.
- `RealSyncDependencies.getHaveVector()` returns `emptyList()`. The literal bytes sent to every peer are `HAVE:`.
- `onSyncTick()` is empty with a `// Real:` comment.
- **Nothing anywhere subscribes to `transport.incoming`.** Inbound payloads are never processed.

There is no gossip protocol. There is no content propagation.

### 3.8 FAKE — fraud controls and integrity
- `DefaultFraudControls` counters are in-memory → defeated by restarting the app.
- Geographic plausibility: *"stub always passes locally."*
- `StubPlayIntegrityVerifier` **and** `PlayIntegrityVerifierImpl` both return `Unavailable`. The second is named as production but is a stub — a labelling failure of exactly the kind Part 14 asks to prevent.
- Backend `_verify_play_integrity` returns `True` when the token is `None`, and otherwise accepts any token beginning with `valid-`.

### 3.9 FAKE — `FakeCryptoProvider.verify()` accepts anything
```kotlin
override fun verify(...): Boolean = signature.size == 64
```
Any 64 bytes is a valid signature. Fine for a fake — **except** it is `createFake()`'s default and `testing/Fixtures.kt` mirrors its derivation, so the only test infrastructure in the repo cannot detect signature errors.

### 3.10 Naming hazard — production code depends on `Fake` classes
`core-attest/ReceiptManager.kt:84,95` and `sharenet-sdk/ShareNetSdk.kt:155` sign and verify using **`FakeCborCodec`**. It happens to delegate to real `Cbor`, so behaviour is currently correct — but the production signing path is one "remove the fakes" cleanup away from breaking silently.

### 3.11 Backend settlement is in-memory and unauthenticated
`backend/settlement/router.py` holds `_tx_records`, `_revoked_cards`, `_nonces_settled` in module-level Python collections. `CardTxRecord.signature` is accepted and **never verified**. `POST /settlement/revoke/{card_id}` has no authentication. Double-spend state is lost on restart, and detection is an O(n) scan per record.

---

## 4. Architecturally sound (preserve the design, not always the code)

1. **Module boundaries.** `crypto → content → catalog → transport → attest → sdk` is a clean, correct dependency order. Keep it; insert new layers rather than reshuffling.
2. **Recipient-signed delivery receipts.** The core insight — *the party who benefits signs the proof, so the claimant cannot forge it* — is correct and is the right seed for the Civic Points redesign.
3. **Content addressing and Merkle verification.** Sound.
4. **Pinned-root publisher trust with signed rotation.** Sound.
5. **Priority-tiered governor.** `CRITICAL > HIGH > LOW` with battery thresholds and metered-network awareness is the right shape for a mesh with mobile nodes; it needs generalising, not replacing.
6. **Backend uses `Decimal` with `getcontext().prec = 28` for money.** Correct instinct — never float in a ledger.

---

## 5. Must be redesigned

| # | Subsystem | Why |
|---|---|---|
| R1 | `core-crypto` provider | Non-functional; replace Tink-wrapper approach with direct Ed25519 over raw 32-byte keys |
| R2 | `Cbor.kt` key ordering | Violates RFC 8949; breaks cross-platform signing |
| R3 | Golden vectors | Placeholders; must be regenerated as real, executable, cross-language |
| R4 | `Transport` interface | Single-hop and Nearby-shaped; must become a link abstraction under a routing layer |
| R5 | Gossip/sync | Does not exist; must be specified and built |
| R6 | Identity model | One Ed25519 key is simultaneously node, user, publisher, and economic identity |
| R7 | Civic Points | Paid per byte with no proof for bridging (§6) |
| R8 | Fraud controls | In-memory, restart-resettable |
| R9 | Backend settlement | In-memory, unauthenticated, unverified signatures |
| R10 | `system_architecture_review.md` | Describes a system that does not exist; must be replaced, not amended |

### 5.1 The Merkle construction needs two security fixes before it is reused

`core-content/MerkleTree.kt` is good code with two classical flaws that matter more once content is fetched across an untrusted mesh:

- **No leaf/internal domain separation.** Leaf = `SHA-256(chunk)`, internal = `SHA-256(l‖r)`. A 64-byte chunk consisting of two concatenated hashes is indistinguishable from an internal node → second-preimage attack. RFC 6962 solves this with `0x00`/`0x01` prefixes. **Adopt RFC 6962 hashing.**
- **Odd-node duplication (CVE-2012-2459 shape).** `right = if (i+1 < level.size) level[i+1] else left`. Distinct leaf sets can produce identical roots. Bind the leaf count into the root, or use the RFC 6962 split rule.

Additionally: `chunk(bytes: ByteArray)` and `reassemble()` operate on **whole in-memory arrays**. The stated use case is multi-gigabyte AI models. This will OOM. A streaming API is required.

### 5.2 `Transport` leaks Android into the protocol

```kotlin
/** Opaque endpoint identifier as issued by Nearby Connections. */
@JvmInline value class EndpointId(val id: String)
```

The protocol's peer identifier is defined by a Google Play Services API — the exact failure Part 4 forbids. Additional consequences:
- `NearbyTransport` **auto-accepts every connection** (`onConnectionInitiated` → `acceptConnection` unconditionally) with no Ed25519 peer handshake. Comment claims auth is "handled at the application layer (core-catalog manifest verification)" — but that authenticates *content*, not *peers*. **There is no peer authentication at all.** Sybil and impersonation are unmitigated at the link layer.
- Only `Payload.Type.BYTES` is handled; non-BYTES payloads are logged and dropped. Nearby caps BYTES at ~32 KB. **Large blob transfer does not work over this transport**, despite the multi-GB model claim. The code says so: *"Optimize: Use FILE payload for large chunks… For now, continue with BYTES."*
- `ConnectionsClient.incomingFlow()` is dead code — it builds a callback, never registers it, and `awaitClose {}`.
- `Nearby` requires Play Services, excluding AOSP/Huawei/GrapheneOS devices and all non-Android platforms.

---

## 6. Obsolete assumptions in `docs/system_architecture_review.md`

| Claim | Status |
|---|---|
| §1 "decentralized *App Store* and *Data Mesh*" | **Obsolete by thesis.** ShareNet is a network; the store is one capability on top. |
| §1 "cryptographically enforced incentive model" | **False.** Enforcement is a stub; bridging has no proof at all. |
| §2.2 "Ed25519 public keys are the global primary keys (`NodeId`)" | **Obsolete.** Conflates four identities and makes a permanent global correlator. |
| §2.2 "Private keys are held in Android Keystore (StrongBox/TEE)" | **False.** `KeystoreCryptoProvider` is a self-declared stub. |
| §2.3 "Gossip Protocol… HAVE vectors" | **False.** Sends the literal string `HAVE:`. |
| §2.4 "Civic Points… Internet Bridging" | **Redefined.** Currently means *fetching a manifest from the ShareNet backend* — content ingestion, not Internet transit. |
| §3.1 "App Clones… HTML5 zip-bundles in Sandboxed WebView" | **Contradicts the new thesis.** Cloned apps are explicitly not the goal. Demote to an offline-fallback capability. |
| §4.1 Threat matrix | **Unsupported.** Every row depends on §3.1's broken crypto. |
| §4.2 "no access to external URLs" | **Inverted by thesis.** Real Internet access is now the product. |
| §5 "Merkle proofs enable selective chunk fetching" | Proof code exists; **no fetch protocol uses it.** |
| Note: "Illusion of Online… optimistic local writes that eventually converge" | **Dangerous.** Applied to Civic Points and wallet balances, this is an invitation to double-spend. See Consistency Model. |

---

## 7. Missing primitives required for transparent Internet access

None of the following exist in any form:

1. **Node capability advertisement** — no node can say "I am an `INTERNET_GATEWAY`."
2. **Multi-hop addressing** — `EndpointId` is link-local; there is no routable node address.
3. **A routing table, metric, or path selection** of any kind.
4. **Frame forwarding** — no node ever relays a payload it did not originate.
5. **Circuit / session abstraction** — no notion of a flow with lifetime and state.
6. **End-to-end encryption between client and gateway** — Nearby's link encryption terminates at each hop; a relay would see plaintext.
7. **Traffic-class separation** — nothing distinguishes content sync from Internet transit.
8. **Gateway request/response semantics** — no CONNECT, no HTTP-fetch, no DNS.
9. **Congestion, flow control, and fragmentation** across hops.
10. **Route repair / gateway failover.**
11. **Transit accounting** — receipts cover blob delivery only; bytes forwarded on someone's behalf have no proof object.
12. **Platform virtual-network adapters** — no `VpnService`, no TUN, no SOCKS, no proxy.
13. **Replay/nonce windows for transit frames.**
14. **Gateway admission and abuse policy** — a gateway would be running an open proxy attributable to its owner's IP, with no controls.

---

## 8. Platform limitations to account for

- **Play Services dependency** — `NearbyTransport` is unavailable on AOSP, Huawei, GrapheneOS, and every non-Android platform. `docs` §5 mentions a "secondary Pure Offline WifiDirect stack"; **no such code exists.**
- **`minSdk = 26`, `compileSdk/targetSdk = 34`.** Android 12+ requires `BLUETOOTH_SCAN`/`BLUETOOTH_CONNECT`; Android 13+ requires `NEARBY_WIFI_DEVICES`. Background execution limits (Doze, App Standby, FGS restrictions on Android 14) make a long-lived relay hard without a foreground service and a user-visible notification.
- **`ShareNetSyncWorker` uses `PeriodicWorkRequest` at 15 minutes** — WorkManager's floor. This is compatible with Mode A (delay-tolerant) and **fundamentally incompatible** with Modes B and C, which need a persistent foreground service.
- **`setRequiredNetworkType(NetworkType.CONNECTED)`** on the sync worker means sync only runs when the device already has a network — the exact opposite of the offline-first premise, and wrong for a node whose entire purpose is reaching a gateway.
- **iOS is entirely absent** from the repository. No target, no adapter, no assessment.
- **Card applet** is 1 Java file + 1 test, JavaCard 3.x on NXP JCOP, unprocurable without hardware — correctly listed under roadmap §7 human-blocked.

---

## 9. Preserve / Refactor / Replace

**Preserve as-is:** `core-content/Chunking.kt` (add streaming), `core-content/BlobStore.kt`, `core-catalog/PublisherRegistry.kt` design, `core-attest` receipt *concept*, module dependency order, backend `Decimal` discipline.

**Refactor:** `core-content/MerkleTree.kt` (RFC 6962 + leaf-count binding), `core-crypto/Cbor.kt` (RFC 8949 ordering), `core-transport/Governor.kt` (generalise to a policy engine), `core-catalog` (retarget onto real crypto), `core-attest` (generalise receipts to contribution proofs).

**Replace:** `core-crypto/Crypto.kt` provider implementations, `core-transport/Transport.kt` + `NearbyTransport.kt`, `core-transport/SyncWorker.kt`, `backend/common/golden_vectors.py`, `backend/settlement/router.py`, `backend/attest/router.py`, `SdkModule.create()`, `docs/system_architecture_review.md`.

**Delete:** `ConnectionsClient.incomingFlow()` (dead), `FakeCborCodec` indirection (call `Cbor` directly), `PlayIntegrityVerifierImpl` (rename to `NotImplementedPlayIntegrityVerifier` until real).

---

## 10. Root cause

Two commits, one bulk generation, no executable cross-validation. The repository has the *shape* of a reviewed system — KDoc on every class, threat matrices, milestone tables, `// Real:` markers — without the *substance*. Comments frequently describe intended behaviour while the adjacent code does something else, and in several places (`ephemeralHandleFromPrivate`, `extractRawPublicKey`, `KeystoreCryptoProvider`) the code **honestly documents its own incorrectness** in a comment that no test ever escalated into a failure.

This is the central lesson for the multi-agent phase: **prose did not constrain the implementation. Only executable golden vectors will.** Part 11's conformance suite is not a late-stage deliverable — it is the precondition for letting a second agent touch the codebase.
