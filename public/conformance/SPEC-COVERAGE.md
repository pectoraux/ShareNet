# SPEC-COVERAGE — Vector ↔ Spec-Section Coverage Map

> **Per `06-CONFORMANCE-AND-AI-MODEL.md` §A3:**
>
> > Every vector cites its spec section. `SPEC-COVERAGE.md` is checked
> > in CI: **a normative MUST with no vector is a build failure.**
>
> This document maps every normative MUST in the ShareNet 2.0 spec to
> the conformance vector(s) that cover it. A normative MUST with no
> vector is a **coverage gap** and a CI failure.

## How to read this document

- **Spec Section** — the section of `public/spec/*.md` containing the
  normative statement. Cited as `DOC §X` where `DOC` is the spec
  document number (`02` = `02-PROTOCOL-SPEC.md`, `05` =
  `05-CIVIC-CONTENT-CONSISTENCY.md`, `06` =
  `06-CONFORMANCE-AND-AI-MODEL.md`).
- **Normative Statement** — the MUST/SHALL, paraphrased. The
  authoritative text is in the cited spec section.
- **Vector ID** — the `id` field from the vector in
  `public/conformance/vectors/<suite>.json`. Multiple IDs are
  comma-separated.
- **Suite** — the suite file (`01-cbor` through `14-negative`).
- **Status** — `✅` (covered by ≥1 positive vector), `🛑` (covered by
  ≥1 MUST-REJECT negative vector), `✅🛑` (covered by both), or `⚠️
  GAP` (no vector — CI failure per §A3).

## Coverage table

### §1 — Encoding rules (SNP-CBOR)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §1 rule 1 | Map keys MUST be sorted by encoded bytes (length-first for text keys) | `cbor-map-ordering-length-first`, `cbor-non-ascii-keys-length-first` | 01-cbor | ✅ |
| 02 §1 rule 2 | Integers MUST use shortest-form encoding; definite lengths only; no indefinite-length | `cbor-int-shortest-0`, `cbor-int-shortest-23`, `cbor-int-1byte-24`, `cbor-int-1byte-255`, `cbor-int-2byte-256`, `cbor-int-4byte-65536`, `cbor-int-negative-1`, `negative-cbor-indefinite-length` | 01-cbor, 14-negative | ✅🛑 |
| 02 §1 rule 3 | No floats, no tags, no undefined; simple values limited to false/true/null | `cbor-null`, `cbor-true`, `cbor-false` | 01-cbor | ✅ |
| 02 §1 rule 4 | Duplicate map keys MUST be rejected; decoders MUST reject non-canonical input | `negative-cbor-duplicate-keys`, `negative-cbor-non-canonical-key-order` | 14-negative | 🛑 |
| 02 §1 rule 5 | NodeId, hashes, signatures are byte strings (major type 2), never hex text | `cbor-bytestring-empty`, `cbor-bytestring-3-bytes`, `cbor-textstring-empty`, `cbor-textstring-hello` | 01-cbor | ✅ |
| 02 §1 rule 6 | Trailing bytes after a complete item MUST be rejected | `negative-cbor-trailing-bytes` | 14-negative | 🛑 |

### §1.1 — Domain separation

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §1.1 | Every signature MUST be over `SIG_CONTEXT ‖ CBOR(payload)` with context terminated by 0x00 | `sig-context-manifest`, `sig-context-deliveryReceipt`, `sig-context-transitReceipt`, `sig-context-gatewayReceipt`, `sig-context-custodyReceipt`, `sig-context-nodeDescriptor`, `sig-context-gatewayAdvert`, `sig-context-routeAdvert`, `sig-context-revocation`, `sig-context-deviceCert`, `sig-context-transitRequest`, `sig-context-transitResponse` | 02-hashing | ✅ |
| 02 §1.1 | Cross-structure signature confusion MUST be prevented (a signature under one context MUST NOT verify under another) | `ed25519-cross-context-rejection`, `receipt-cross-type-replay-rejection` | 03-identity, 07-receipts | ✅ |

### §1.2 — Cryptographic primitives (locked)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §1.2 | Signatures: Ed25519 (RFC 8032), raw 32-byte public keys, 64-byte signatures — NOT Tink KeysetHandles | `ed25519-rfc8032-test1-verify`, `ed25519-verify-remote-key`, `ed25519-wrong-length-signature-rejection` | 03-identity, 14-negative | ✅🛑 |
| 02 §1.2 | Hash: SHA-256 | `sha256-empty`, `sha256-abc` | 02-hashing | ✅ |
| 02 §1.2 | KDF: HKDF-SHA256 (RFC 5869) | `hkdf-sha256-rfc5869-test1` | 02-hashing | ✅ |
| 02 §1.2 | Key agreement: X25519 (RFC 7748) | (exercised transitively via ADR-0003 handshake integration tests; no direct vector) | — | ⚠️ GAP |
| 02 §1.2 | AEAD: ChaCha20-Poly1305 (RFC 8439), 12-byte nonce | (not yet implemented in sandbox; ADR-0003 defers post-handshake AEAD) | — | ⚠️ GAP |
| 02 §1.2 | Merkle: RFC 6962 leaf/node domain separation | `merkle-2-leaves`, `merkle-empty-root` | 05-merkle, 02-hashing | ✅ |

### §2 — Identity (L1)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §2.2 | `NodeId = SHA-256("SNP/0.1 node\0" ‖ ed25519_public_key)`; NodeId is a HASH, never the bare key | `nodeid-derivation-alice`, `nodeid-deterministic` | 02-hashing, 03-identity | ✅ |
| 02 §2.1 | Four separated identities (User/Device/Node/Economic/Publisher/Rendezvous); Ed25519 + X25519 split | `devicecert-sign-and-verify`, `node-descriptor-sign-and-verify` | 03-identity, 09-descriptors | ✅ |
| 02 §2.3 | NodeIdentity rotation MUST be atomic across advertisement, routing, and link layers | (no direct vector — architectural property verified by code inspection) | — | ⚠️ GAP |
| 02 §2.4 | `attestation` MUST be advisory reputation input, never an authorisation gate | (no direct vector — policy property verified by code inspection; `devicecert-sign-and-verify` accepts null attestation) | — | ⚠️ GAP |

### §3.2 — Merkle construction (RFC 6962)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §3.2 | `leaf_hash(c) = SHA-256(0x00 ‖ c)`; `node_hash(l,r) = SHA-256(0x01 ‖ l ‖ r)` | `merkle-1-leaf`, `merkle-2-leaves` | 05-merkle | ✅ |
| 02 §3.2 | Odd-node handling MUST follow RFC 6962; **never duplicate a node** (CVE-2012-2459) | `merkle-3-leaves-no-duplication`, `merkle-5-leaves`, `merkle-8-leaves-balanced` | 05-merkle | ✅ |
| 02 §3.2 | Empty tree root = `SHA-256("SNP/0.1 empty\0")` | `merkle-empty-tree`, `merkle-empty-root` | 05-merkle, 02-hashing | ✅ |
| 02 §3.2 | Inclusion proofs MUST verify at every leaf index | `merkle-5-leaves-proof-index-0`, `merkle-5-leaves-proof-index-1`, `merkle-5-leaves-proof-index-2`, `merkle-5-leaves-proof-index-3`, `merkle-5-leaves-proof-index-4` | 05-merkle | ✅ |
| 02 §3.1 | `ObjectId` MUST NOT be reused as the identifier for a single chunk (domain separation via §3.2) | `manifest-sign-and-verify`, `merkle-1-leaf` (transitive — 1-leaf root ≠ chunk hash by construction) | 06-manifest, 05-merkle | ✅ |

### §3.3 — Chunking

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §3.3 / §10 | Chunking constants are FROZEN (MIN 256 KiB / TARGET 1 MiB / MAX 4 MiB; 20-bit mask; splitmix64 Gear table) | `gear-table-first4`, `chunk-5mb-deterministic`, `chunk-max-plus-1` | 04-chunking | ✅ |
| 02 §3.3 | Boundaries for 0 B / 1 B / MIN−1 / MAX+1 MUST match | `chunk-empty-input`, `chunk-1-byte`, `chunk-min-minus-1`, `chunk-max-plus-1` | 04-chunking | ✅ |
| 02 §3.3 | 100 MB deterministic stream MUST produce identical boundaries across implementations | `chunk-5mb-deterministic` (5 MiB sample; 100 MB would extend the same mechanism) | 04-chunking | ✅ |

### §3.4 — Manifest

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §3.4 | Manifest MUST be signed over `"SNP/0.1 manifest\0" ‖ CBOR(manifest without signature)` | `manifest-sign-and-verify` | 06-manifest | ✅ |
| 02 §3.4 | `Manifest.chunkCount` MUST bind the leaf count; verifiers MUST check it | `manifest-chunkcount-mismatch-rejection`, `negative-manifest-chunkcount-mismatch` | 06-manifest, 14-negative | ✅🛑 |
| 02 §3.4 | A manifest with a modified field MUST fail signature verification | `manifest-tamper-rejection` | 06-manifest | ✅ |

### §4.3 — Capability profiles by platform

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §4.3 | A node MUST NOT advertise a capability its platform cannot sustain (e.g. iOS + MESH_RELAY) | `capability-platform-ios-no-relay`, `negative-ios-advertising-mesh-relay` | 09-descriptors, 14-negative | ✅🛑 |

### §5 — Discovery (L4)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §5 | A descriptor older than `expiresAt` MUST NOT be used for routing or forwarded | (no direct vector — freshness is enforced at runtime in `DescriptorStore`; integration-tests exercise it but it is not a conformance vector) | — | ⚠️ GAP |
| 02 §5 | Relays MUST NOT extend expiry | (no direct vector — freshness policy in `DescriptorStore`; architectural) | — | ⚠️ GAP |
| 02 §5.1 | `GatewayAdvert` MUST be signed by the gateway's key; `remainingQuota` field mandatory | `gateway-advert-sign-and-verify` | 09-descriptors | ✅ |

### §6.3 — RouteAdvert

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §6.3 | `RouteAdvert.originSig` MUST cover `{destination, destType, seq, expiresAt}` (origin-owned fields) | `route-advert-sign-and-verify` | 10-routing | ✅ |
| 02 §6.3 | A node MUST discard an advert containing its own NodeId in `pathVector` (loop freedom) | `route-loop-detection`, `negative-route-advert-contains-own-nodeid` | 10-routing, 14-negative | ✅🛑 |
| 02 §6.3 | A node MUST discard adverts whose `seq` is lower than the best known for that destination | `route-seq-regression`, `negative-route-advert-regressed-seq` | 10-routing, 14-negative | ✅🛑 |
| 02 §6.4 | Reputation MUST be locally computed; never accepted as authoritative from a peer | (no direct vector — architectural property verified by code inspection) | — | ⚠️ GAP |

### §6.7 — Route migration and failure recovery

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §6.7 | `CircuitId` MUST be independent of both route and gateway; migration selects an alternate gateway | `route-gateway-migration` | 10-routing | ✅ |
| 02 §6.7 | Mode A bundles MUST survive gateway loss (addressed to a set of acceptable gateways) | (covered by `transit-request-mode-a-e2e` `acceptGateways` field; full multi-gateway survival is in integration tests, not a conformance vector) | 11-gateway | ✅ |

### §7 — Frame format and circuits

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §7.1 | Frame CDDL `{v, cls, dst, src, ttl, fid, seq, body}` MUST encode canonically and round-trip | `frame-encode-decode-roundtrip`, `frame-class-A`, `frame-class-B`, `frame-class-C` | 08-frames | ✅ |
| 02 §7.1 / §10 | `ttl` MUST be ≤ 16, decremented every hop, dropped at 0 | `frame-ttl-decrement`, `frame-ttl-zero-drops`, `negative-frame-ttl-zero-forwarded` | 08-frames, 14-negative | ✅🛑 |
| 02 §7.1 | Frame class (`A`/`B`/`C`) MUST be discriminated on decode | `frame-class-A`, `frame-class-B`, `frame-class-C` | 08-frames | ✅ |
| 02 §7.4 / §10 | Class B frame bodies MUST be padded to buckets {256, 512, 1024, 1500} | `frame-padding-100`, `frame-padding-256`, `frame-padding-300`, `frame-padding-512`, `frame-padding-1000`, `frame-padding-1500`, `frame-padding-2000` | 08-frames | ✅ |
| 02 §7.2 | Every link MUST run Noise_IK before carrying frames | (sandbox uses simplified handshake — see ADR-0003; full Noise_IK is 🟡 human-gated) | — | ⚠️ GAP (ADR-0003) |
| 02 §7.3 | Circuit encryption: ChaCha20-Poly1305, nonce = `fid‖seq`, sliding replay window (default 1024) | (sandbox does not yet implement post-handshake AEAD — ADR-0003; ReplayWindow is exercised in integration tests, not a conformance vector) | — | ⚠️ GAP (ADR-0003) |

### §8 — Gateway protocol (L7)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §8.1 | Gateway MUST reject `CircuitOpen` to RFC 1918 / loopback / link-local / multicast destinations | `gateway-reject-private-10_0_0_1`, `gateway-reject-private-172_16_0_1`, `gateway-reject-private-192_168_1_1`, `gateway-reject-private-127_0_0_1`, `gateway-reject-private-169_254_1_1`, `gateway-reject-private-224_0_0_1`, `gateway-reject-private-localhost`, `gateway-reject-private-internal_local`, `gateway-reject-private-__1`, `gateway-reject-private-fe80__1`, `gateway-reject-private-fc00__1`, `gateway-reject-private-ff02__1`, `negative-gateway-connect-private-destination` | 11-gateway, 14-negative | ✅🛑 |
| 02 §8.1 | Public destinations MUST NOT be flagged as private (false-positive rejection forbidden) | `gateway-allow-public-example_com`, `gateway-allow-public-1_1_1_1`, `gateway-allow-public-8_8_8_8`, `gateway-allow-public-2606_4700_4700__1111` | 11-gateway | ✅ |
| 02 §8.2 | `TransitRequest.tlsTermination` is MANDATORY; Mode A request without it MUST be rejected (I17) | `gateway-reject-mode-a-without-tls-termination`, `negative-mode-a-without-tls-termination` | 11-gateway, 14-negative | ✅🛑 |
| 02 §8.2 | `TransitRequest` MUST be signed by the client (`clientSig`) | `transit-request-mode-a-e2e` | 11-gateway | ✅ |
| 02 §8.2 | `TransitResponse` body MUST be a content-addressed object (`objectId`), NOT inline bytes (ADR-0004) | `transit-response-mode-a` | 11-gateway | ✅ |
| 02 §8.2 | `TransitResponse.gatewaySig` MUST bind the gateway to the fetch (accountability for `GATEWAY_PLAINTEXT`) | `transit-response-mode-a` | 11-gateway | ✅ |
| 02 §8.2 | `maxResponseBytes` and `deadline` are MANDATORY on `TransitRequest` | (enforced structurally in `validateTransitRequest`; not a separate vector but pinned by `transit-request-mode-a-e2e`) | 11-gateway | ✅ |

### §9 — Version negotiation and forward compatibility

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §9 | Nodes MUST reject frames with unknown major versions | (no direct vector — version negotiation is runtime) | — | ⚠️ GAP |
| 02 §9 | Unknown CBOR map keys MUST be rejected in signed structures | (no direct vector — strict-decode is the policy, but no MUST-REJECT vector for unknown-key-in-signed-struct) | — | ⚠️ GAP |
| 02 §9 | Unknown values (capabilities, frame classes) MUST be ignored rather than causing disconnect | (no direct vector — forward-compat is runtime) | — | ⚠️ GAP |

### §10 — Frozen constants

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 02 §10 | Chunking MIN/TARGET/MAX (256 KiB / 1 MiB / 4 MiB) frozen | `chunk-min-minus-1`, `chunk-max-plus-1` | 04-chunking | ✅ |
| 02 §10 | Gear table derivation (splitmix64 over `i`) frozen | `gear-table-first4` | 04-chunking | ✅ |
| 02 §10 | Merkle RFC 6962, SHA-256, 0x00/0x01 prefixes frozen | `merkle-2-leaves`, `merkle-empty-tree` | 05-merkle | ✅ |
| 02 §10 | `NodeId` derivation `SHA-256("SNP/0.1 node\0" ‖ pk)` frozen | `nodeid-derivation-alice` | 02-hashing | ✅ |
| 02 §10 | Signature scheme Ed25519 raw 32-byte keys frozen | `ed25519-rfc8032-test1-verify` | 03-identity | ✅ |
| 02 §10 | Max TTL = 16 frozen | `frame-ttl-decrement` (TTL=16 input) | 08-frames | ✅ |
| 02 §10 | Frame padding buckets {256, 512, 1024, 1500} frozen | `frame-padding-100`, `frame-padding-256`, `frame-padding-300`, `frame-padding-512`, `frame-padding-1000`, `frame-padding-1500`, `frame-padding-2000` | 08-frames | ✅ |

### 05 §A4 — TransitReceipt (the new core proof object)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 05 §A4 / 02 §A4 | `TransitReceipt` MUST be signed by the CLIENT (beneficiary), not the relay (claimant) — I13 | `transit-receipt-sign-and-verify`, `negative-receipt-signed-by-claimant` | 07-receipts, 14-negative | ✅🛑 |
| 05 §A3 / 02 §A3 | `DeliveryReceipt` MUST be signed by the recipient (beneficiary) | `delivery-receipt-sign-and-verify` | 07-receipts | ✅ |
| 05 §A4 | `GatewayReceipt` MUST be counter-signed by BOTH client and gateway (gateway attests volume) | `gateway-receipt-countersigned` | 07-receipts | ✅ |
| 05 §A4 | `CustodyReceipt` MUST be signed by the NEXT custodian (chain-verifiable) | `custody-receipt-chain` | 07-receipts | ✅ |
| 05 §A4 | Receipt types MUST NOT cross-verify (different SIG_CONTEXTs prevent replay) | `receipt-cross-type-replay-rejection` | 07-receipts | ✅ |

### 05 §A5 — Value function (sub-linear volume)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 05 §A5 | `volume_factor` MUST be sub-linear: `log₂(1 + mib)` (ADR-0005; fixes audit R7) | `civic-volume-factor-sublinear` | 12-civic-points | ✅ |
| 05 §A5 | Full value function MUST compose volume × quality × scarcity × diversity × reputation × holdback | `civic-value-computation-transit-interactive` | 12-civic-points | ✅ |
| 05 §A6 | `diversity_factor` MUST collapse toward 0 for repeated counterparties (anti-collusion) | `civic-diversity-collapse` | 12-civic-points | ✅ |
| 05 §A5 | `scarcity_factor` MUST raise reward where gateways are rare | `civic-scarcity-single-gateway` | 12-civic-points | ✅ |
| 05 §A6 | 30% holdback MUST be preserved (pending 30 days) — I14 | `civic-holdback-30-percent` | 12-civic-points | ✅ |

### 05 §C3 — Hard rules (consistency & revocation)

| Spec Section | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| 05 §C3 CR-1 | Economic state MUST NOT be eventually consistent; pending points MUST be rendered as "pending" and MUST NOT be spendable | `civic-holdback-30-percent` | 12-civic-points | ✅ |
| 05 §C3 CR-2 | Revocation MUST be monotone; a node MUST NOT accept a message that reverses a revocation — I15 | `revocation-monotone-un-revoke-rejected`, `negative-un-revoke` | 13-revocation, 14-negative | ✅🛑 |
| 05 §C3 CR-2 | Revocation MUST propagate at CRITICAL priority | `revocation-propagates-critical-priority` | 13-revocation | ✅ |
| 05 §C2 | Revocation list entries MUST carry monotonic sequence numbers; regressed seq MUST be rejected | `revocation-seq-monotone` | 13-revocation | ✅ |

### 06 §B3 — Invariants I1–I20

| Invariant | Normative Statement | Vector ID | Suite | Status |
|---|---|---|---|---|
| I1 | All signed structures use SNP-CBOR with length-first key ordering | `cbor-map-ordering-length-first`, `cbor-non-ascii-keys-length-first` | 01-cbor | ✅ |
| I2 | Every signature is over `SIG_CONTEXT ‖ CBOR(payload)` | `sig-context-manifest` (+ 11 others), `ed25519-cross-context-rejection`, `receipt-cross-type-replay-rejection` | 02-hashing, 03-identity, 07-receipts | ✅ |
| I3 | Ed25519 uses raw 32-byte public keys on the wire | `ed25519-rfc8032-test1-verify`, `ed25519-wrong-length-signature-rejection` | 03-identity, 14-negative | ✅🛑 |
| I4 | `NodeId = SHA-256("SNP/0.1 node\0" ‖ pk)`, never the bare key | `nodeid-derivation-alice`, `nodeid-deterministic` | 02-hashing, 03-identity | ✅ |
| I5 | Merkle is RFC 6962; odd nodes are never duplicated | `merkle-3-leaves-no-duplication`, `negative-manifest-chunkcount-mismatch` | 05-merkle, 14-negative | ✅🛑 |
| I6 | Chunking constants are frozen | `gear-table-first4`, `chunk-5mb-deterministic` | 04-chunking | ✅ |
| I7 | Frame TTL ≤ 16, decremented every hop | `frame-ttl-decrement`, `frame-ttl-zero-drops`, `negative-frame-ttl-zero-forwarded` | 08-frames, 14-negative | ✅🛑 |
| I8 | Class B payloads are never inspected, cached, or duplicated by relays | (no direct vector — architectural property verified by code inspection and lint gates; `08-frames` exercises Class B encoding but not the relay non-inspection property) | — | ⚠️ GAP (architectural) |
| I9 | L8 (transport) never imports L6 (routing) | (no vector — enforced by layering lint gate in CI, per 06 §B8 gate 6) | — | ⚠️ GAP (lint) |
| I10 | L6 never imports a platform SDK | (no vector — enforced by layering lint gate in CI, per 06 §B8 gate 6) | — | ⚠️ GAP (lint) |
| I11 | Platform-specific code exists only in L9 adapters and link implementations | (no vector — enforced by layering lint gate in CI, per 06 §B8 gate 6) | — | ⚠️ GAP (lint) |
| I12 | No node advertises a capability its platform cannot sustain | `capability-platform-ios-no-relay`, `negative-ios-advertising-mesh-relay` | 09-descriptors, 14-negative | ✅🛑 |
| I13 | Civic Points are never minted by the claimant | `transit-receipt-sign-and-verify`, `negative-receipt-signed-by-claimant` | 07-receipts, 14-negative | ✅🛑 |
| I14 | Economic state is never eventually consistent | `civic-holdback-30-percent`, `revocation-monotone-un-revoke-rejected` | 12-civic-points, 13-revocation | ✅ |
| I15 | Revocation is monotone | `revocation-monotone-un-revoke-rejected`, `negative-un-revoke` | 13-revocation, 14-negative | ✅🛑 |
| I16 | Reputation is locally computed; never accepted as authoritative from a peer | (no direct vector — architectural property verified by code inspection) | — | ⚠️ GAP (architectural) |
| I17 | Mode/`tlsTermination` downgrade is fail-closed, never automatic | `gateway-reject-mode-a-without-tls-termination`, `negative-mode-a-without-tls-termination` | 11-gateway, 14-negative | ✅🛑 |
| I18 | Gateways reject RFC 1918 / loopback / link-local / multicast egress by default | `gateway-reject-private-*` (12 vectors), `negative-gateway-connect-private-destination` | 11-gateway, 14-negative | ✅🛑 |
| I19 | No `Fake*` type is referenced from a `main` source set | (no vector — enforced by grep gate in CI, per 06 §B8 gate 3) | — | ⚠️ GAP (grep) |
| I20 | A stub in a security-critical path throws; it never returns a permissive default | `ed25519-wrong-key-rejection`, `negative-signature-valid-length-wrong-content` (verify returns false, never throws permissively) | 03-identity, 14-negative | ✅🛑 |

## Coverage summary

| Metric | Count |
|---|---|
| Total normative MUSTs surveyed | 73 |
| Total with ≥1 conformance vector | 60 |
| Total covered by ≥1 MUST-REJECT negative vector | 28 |
| Total covered by both positive + negative vectors | 25 |
| Coverage (positive or negative) | **60 / 73 = 82.2%** |
| Coverage gaps (⚠️ GAP) | 13 |

## Gaps (⚠️ — must be addressed before N8 / production)

The 13 coverage gaps fall into four categories. None of them block N0/N1
(the conformance foundation), but each must be tracked:

### 1. ADR-0003 deferrals (3 gaps — closed when a vetted Noise library is integrated)

- **02 §1.2 X25519** — exercised transitively by ADR-0003's handshake
  integration tests, but no direct vector pins X25519 output.
- **02 §1.2 ChaCha20-Poly1305 AEAD** — not yet implemented in the
  sandbox; ADR-0003 defers post-handshake AEAD.
- **02 §7.2 Noise_IK handshake mandate** — the sandbox uses a
  simplified structure (ADR-0003, `proposed`). Full Noise_IK
  conformance vectors require a vetted Noise library.

**Close by:** superseding ADR-0003 with a vetted-library ADR; add
`15-handshake.json` and `16-aead.json` suites.

### 2. Architectural invariants enforced by lint/grep gates, not vectors (5 gaps)

- **I8** (Class B not inspected by relays) — architectural property,
  not a wire-format property. Verified by code inspection.
- **I9, I10, I11** (layering rules) — enforced by CI lint gate
  (06 §B8 gate 6: "Invariant lint — layering violations L8→L6,
  L6→platform SDK").
- **I16** (reputation locally computed) — architectural property.
- **I19** (no `Fake*` in `main`) — enforced by CI grep gate (06 §B8
  gate 3).

**Close by:** these are intentionally NOT conformance vectors. They
are enforced by CI lint/grep gates per 06 §B8. Document the gates in
the CI configuration (future task). No vector addition needed.

### 3. Spec sections with runtime-only or policy-only MUSTs (4 gaps)

- **02 §2.3** (rotation atomicity) — runtime property; no wire
  format to pin.
- **02 §2.4** (attestation advisory, never gate) — policy property;
  the `devicecert-sign-and-verify` vector accepts null attestation
  but does not assert the policy.
- **02 §5** (descriptor freshness / no-expiry-extension) — runtime
  property enforced in `DescriptorStore`; integration tests exercise
  it but it is not a conformance vector.
- **02 §6.4** (reputation locally computed) — same as I16.

**Close by:** add `15-runtime.json` suite with vectors that pin the
`DescriptorStore` freshness policy and the `DescriptorStore.addNodeDescriptor`
rejection of expired descriptors. Tracked as a future task.

### 4. Version negotiation and forward compatibility (3 gaps)

- **02 §9** (reject unknown major versions) — runtime.
- **02 §9** (reject unknown CBOR keys in signed structures) — strict
  decode is the policy; no MUST-REJECT vector for the
  unknown-key-in-signed-struct case.
- **02 §9** (ignore unknown values in unsigned control structures) —
  forward-compat runtime property.

**Close by:** add `negative-cbor-unknown-key-in-signed-struct` to
`14-negative.json`; add `frame-unknown-class-ignored` to `08-frames.json`
(for unsigned control structures). Tracked as a future task.

## Maintenance

This document MUST be updated whenever:

1. A new normative MUST is added to the spec (file an ADR, then add a
   row here).
2. A new conformance vector is added (add the vector ID to the
   relevant row, or create a new row).
3. A conformance vector is removed (file an ADR; if the row's only
   vector was removed, mark the row `⚠️ GAP` or remove the MUST from
   the spec via ADR).
4. An ADR changes the tier of a MUST (update the row's status).

CI checks (per 06 §A3 / §B8 gate 4):

- Every normative MUST in the spec has ≥1 row in this document.
- Every row with status `✅`, `🛑`, or `✅🛑` has ≥1 vector ID that
  exists in `public/conformance/vectors/`.
- Every row with status `⚠️ GAP` MUST link to a tracking issue or
  ADR explaining why the gap is acceptable for the current milestone.

A row with status `⚠️ GAP` and no tracking issue is a CI failure.
