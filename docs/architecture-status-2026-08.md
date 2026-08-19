# ShareNet — Architecture Implementation Status

**Date:** 2026-08-19 (updated R4.4 correction)
**HEAD:** see `git rev-parse HEAD`
**Status:** implementation progress, NOT production-ready

---

## N3-B Runtime

**NOT VERIFIED** until privileged external runtime test passes.

The TUN/transparent networking implementation exists but has not been
executed in a privileged Linux environment. The sandbox lacks:
- `/dev/net/tun`
- `CAP_NET_ADMIN`
- `CAP_SYS_ADMIN`
- `unshare` permission

---

## Layer Status Matrix

| Layer | Frozen Architecture | Current Implementation | Status | Evidence | Known Gaps |
|---|---|---|---|---|---|
| **L1 Identity** | 4 identity classes, Ed25519+X25519, rotation, revocation | snp-identity: NodeIdentity + Capability + NodeId + derive_node_id + verify_signed + GatewayAdvertisement + VerifiedNodeDescriptor + TransportEndpoint. **R4.2 interop**: `NodeDescriptor` + `DeviceCert` now have frozen wire codecs (`encode_cbor()`/`decode_cbor()`) matching TS `nodeDescriptorToWireMap`/`deviceCertToCborMap` field-for-field. Signature preimage = `SIG_CONTEXT ‖ CBOR(unsigned_fields)`. Decode ≠ verify (structural only). 17 tests pass. | PASS | Conformance vectors 03-identity: 7/7 pass. snp-identity tests: 17 pass. snp-node tests: 97 pass. | R2.2 + R2 + R4.2 interop complete. NodeDescriptor + DeviceCert canonical codecs implemented. |
| **L2 Object/Content** | CAS, chunking, Merkle, manifests | snp-object: Merkle tree, chunking, proofs, CAS trait (real code). InMemoryCas impl: todo!(). **R4.2 interop**: `Manifest` now has frozen wire codecs (`encode_cbor()`/`decode_cbor()`) matching TS `manifestToWireMap`/`manifestFromWireMap` field-for-field (10 fields + signature). Signature preimage = `SIG_CONTEXT("manifest") ‖ CBOR(fields 1-9)`. Decode ≠ verify. 28 tests pass. TS reference: complete. Android: complete. | PASS (Rust Merkle/chunking/Manifest codec), PARTIAL (CAS storage) | Conformance vectors 04-chunking, 05-merkle, 06-manifest: all pass. snp-object tests: 28 pass. | CAS storage not implemented in Rust; TS is authoritative for CAS. Manifest canonical codec implemented (R4.2 interop). |
| **L3 Trust** | Attestations, reputation, revocation | AuthenticatedNodeRecord (complete). VerifiedNodeAdvertisement (complete). No reputation system. | PARTIAL | Conformance vectors 13-revocation: 3/3 pass. | Reputation system not yet implemented |
| **L4 Discovery** | Peer+capability advertisement, freshness | snp-discovery: DiscoveredNode + DiscoveryProvider + StaticDiscovery (extracted R2). Beacon/DescriptorStore: skeleton (todo!()). snp-node: BootstrapDiscovery (runtime TCP I/O). GatewayAdvertisement now in snp-identity. | PASS (types), PARTIAL (runtime) | snp-node integration tests: n210 pass. | Beacon/DescriptorStore still skeleton. BootstrapDiscovery runtime in snp-node. |
| **L5 Mesh Sync** | Anti-entropy, store-carry-forward, bundle custody | snp-sync: generic `Bundle` + `BundleId` + `BundlePayload` (opaque) + `CustodyHop` (frozen CustodyReceipt semantics, §A4) + `BundleStore` — implemented R4.1. Anti-entropy (`HaveVector` + `SyncRequest` + `SyncResponse` + `SyncDiff` + `SyncSession` + `ObjectStore`/`DescriptorStore` traits + `bundle_ids_for_have_vector`) — implemented R4.2 per frozen TS `sync.ts` semantics. **R4.2 interop**: `SyncResponse` carries `DescriptorPayload(Vec<u8>)` + `ManifestPayload(Vec<u8>)` (opaque canonical bytes). Owner codecs now exist: `snp_identity::NodeDescriptor::encode_cbor()`/`decode_cbor()` + `snp_object::Manifest::encode_cbor()`/`decode_cbor()`. Composition-layer integration tests verify: descriptor → encode → opaque payload → SyncResponse → decode → opaque payload → owner decode → same descriptor (zero byte loss). TS reference: complete (sync.ts, 2316 lines). | PARTIAL (Rust — Bundle layer + anti-entropy domain protocol + canonical descriptor/manifest interop complete; runtime forwarding pending) | snp-sync tests: 92 pass (51 R4.1 + 32 R4.2 + 6 R4.2-correction + 3 composition-interop). snp-identity: 17 pass. snp-object: 28 pass. | Runtime store-carry-forward forwarding loop (R4.3), Mode-A adapter wiring (R4.3+) remain. snp-sync has NO L7/L6/L8 dependency. R4.2 interop: descriptor + manifest canonical codecs exist in their owning layers; L5 carries opaque bytes; decode ≠ verify. |
| **L6 Routing** | Route discovery, metrics, selection, migration | snp-node: route.rs + route_engine.rs + route_discovery_protocol.rs (complete). Route, RouteHop, RouteState, signed descriptors. | PASS | Conformance vectors 10-routing: 4/4 pass. snp-node tests: n212, n2132 pass. | No drift |
| **L7 Gateway** | Egress, DNS, NAT, policy, quotas | snp-gateway: TransitRequest/Response (Mode A protocol, complete). GatewayStreamTable (Mode B, complete, production SSRF). DNS interception (complete). | PASS | Conformance vectors 11-gateway: 19/19 pass. | No drift |
| **L8 Transport** | One-hop framing, platform-neutral | snp-link: AsyncLink+AuthenticatedLink (complete). snp-frames: Frame+TTL (complete). No imports from L6. | PASS | Conformance vectors 08-frames: 13/13 pass. | No drift — L8 remains platform-neutral |
| **L9 Virtual Network** | TUN, SOCKS5, store-forward, OS integration | TunClient (smoltcp+any_ip, SYN extraction, split-tunnel). N3AClient (SOCKS5). TCP-only, Linux-only. | PARTIAL | any_ip_verification: 5/5. transparent_tcp: 7/7. | NOT RUNTIME-VERIFIED. TCP-only, Linux-only, no UDP, no DNS-over-TUN |
| **L10 App Capability** | Catalog, apps, models, datasets | Android: complete. Not connected to new network architecture. | DEFERRED | Android app-feed tests pass. | Not yet integrated with the bearer |
| **L11 Civic** | Contribution proof, value function, verification | TS reference: complete (civic.ts 503 lines, receipts.ts 934 lines). Rust (snp-civic): types defined (ContributionProof, ContributionStore) but all methods todo!(). Conformance vectors: 5/5 pass. | MISSING (Rust), PASS (TS) | Conformance vectors 12-civic-points: 5/5 pass. | Rust civic types defined but methods unimplemented. TS is authoritative. |
| **L12 Settlement** | Authoritative points/wallet state | No implementation (Rust, TS, or Android). | MISSING | — | No authoritative settlement exists |

---

## Mode Ladder

| Mode | Status | Evidence |
|---|---|---|
| **Mode A** (delay-tolerant) | CONFIGURED SIGNED-ROUTE MULTI-HOP (limited) — NOT live discovery | R4.4 (corrected): multi-hop store-carry-forward Client → Relay A → Relay B → Gateway. The route is constructed from **configured, signed** `NodeAdvertisement` + `GatewayAdvertisement` descriptors (`verify_into_verified()` → `VerifiedNodeDescriptor` → `RouteHop`); the `BundleForwarder` does NOT call a live peer discovery service. Direction is routing-derived: forward = `destination == next_hop \|\| destination == gateway`; reverse = `destination == client (route.source)`. Response bundles can NEVER enter the forward path. Authenticated L8 (SNP-IK + AEAD) at every hop. Provenance binding (#21) at every hop. Deliberate interruption test passes. 8 multi-hop tests (incl. 4 R4.4-correction regression tests) + 9 R4.3 tests pass. **Live peer discovery (runtime relay selection from a peer graph) is NOT implemented — it is R4.5.** |
| **Mode B** (proxied) | PASS (Rust) | MultiplexedCircuit, StreamHandle, serve_gateway_mode_b_multiplexed, N3AClient. |
| **Mode C** (transparent) | PARTIAL | TunClient with any_ip + destination extraction + split-tunnel. NOT RUNTIME-VERIFIED. TCP-only, Linux-only. |

### Mode A — R4.3 runtime status

**Mode A is now RUNTIME VERIFIED (limited).** The first real store-carry-forward
proof exists:

```text
Client → Relay → Gateway → HTTP endpoint
```

with a **deliberate interruption**: the relay holds the bundle in its
`BundleStore` while the gateway is unavailable, then forwards when it
becomes available. This is the defining R4.3 property.

**Limitations (honestly stated):**
- **Authenticated transport: VERIFIED** — SNP-IK handshake + AEAD (ChaCha20-Poly1305) + peer identity pinning
- **In-memory store**: `BundleStore` is in-memory. Bundles are NOT persisted
  across process restarts. This is honestly classified as:
  `runtime store-carry-forward: process-lifetime only`.
- **Single-hop relay**: The first proof uses one relay (Client → Relay → Gateway).
  Multi-hop relay forwarding is R4.4+.
- **Host-local egress**: The gateway fetches from a mock HTTP server on
  127.0.0.1. This is honestly classified as `host-local egress test` — NOT
  genuine external Internet egress. The sandbox may not have external access.
- **No persistent database**: Bundles are stored in-memory only.
- **No peer discovery**: The first slice uses explicitly configured carrier
  endpoints (acceptable for the first vertical proof).

**The previous status ("Mode A: PASS") was imprecise.** The precise statement is:

> `TransitRequest`/`TransitResponse` protocol semantics exist (in snp-gateway)
> and are currently transported through the **live circuit path**
> (`send_request_via_gateway_full_with_relay_async` in async_node.rs).
>
> **Frozen Mode A remains unimplemented** because store-carry-forward
> execution does not yet exist. Frozen Mode A requires a `Bundle` to be
> stored, carried, and forwarded through the mesh — which is the R4.2+
> work.

R4.1 status:
- ✅ Generic `Bundle` + `BundleId` + `BundlePayload` (opaque) + `CustodyHop` (frozen CustodyReceipt §A4) + `BundleStore` — **implemented in snp-sync** (28 tests pass).
- ❌ Anti-entropy exchange (R4.2) — `SyncRequest`/`SyncResponse`/`SyncObject` types declared, exchange NOT implemented.
- ❌ Runtime forwarding (R4.2+) — no node currently calls `BundleStore::pending` to forward bundles.
- ❌ Mode-A adapter (R4.3+) — no composition layer currently serializes a `TransitRequest` into `BundlePayload`, wraps it in a `Bundle`, and stores it in a `BundleStore` for store-carry-forward. The L7 gateway does not yet `from_cbor` a `Bundle`, decode the payload as a `TransitRequest`, and respond via a response `Bundle`.

Until R4.2+R4.3 land, the live circuit path is Mode B semantics (proxied, not delay-tolerant), even though it carries `TransitRequest`/`TransitResponse` payloads that were originally specified for Mode A.

### Mode A — R4.4 multi-hop (corrected)

R4.4 extends R4.3's single-hop path to a multi-hop route
`Client → Relay A → Relay B → Gateway → endpoint`, with a deliberate
interruption at the `Relay A → Relay B` hop proving store-carry-forward.

**Verified capability (precise wording):** multi-hop route construction from
**configured, signed descriptors** + L6 `Route`/`RouteHop` + L8 authenticated
transport (`AuthenticatedBundleCarrier`, SNP-IK + AEAD) + L5 store-carry-forward.
The `BundleForwarder` operates at a route position and forwards to
`route.hop(position + 1)`. It does NOT choose routes and does NOT call a live
peer discovery service.

**NOT live discovery-backed.** The route is supplied to the forwarder by
composition, built from `NodeAdvertisement::create_and_sign` →
`verify_into_verified()` → `VerifiedNodeDescriptor` → `RouteHop` →
`Route::new_with_hop_details`. There is no `DiscoveryProvider`,
`DiscoveredNode`, beacon, or runtime relay selection in the Mode-A path. This
is acceptable for the R4.4 proof. **Live peer discovery remains R4.5.**

**Direction semantics (R4.4 correction).** Bundles are partitioned by
direction, derived from ROUTING (the route's source/destination NodeIds) —
never from a catch-all identity negation:

- **Forward** (`forward_pending_bundles`): `destination == next_hop
  || destination == route.destination()` (gateway). These travel
  Client → A → B → Gateway.
- **Reverse** (`try_send_response_back`): `destination == route.source()`
  (client). These travel Gateway → B → A → Client.

A response bundle (destination == client) can therefore NEVER enter the forward
path, and a request bundle (destination == gateway) can never enter the reverse
path. The previous filter `destination != self.identity.node_id` was a
catch-all that incorrectly captured response bundles and could push them
Gateway-ward; it is removed.

**Previous-hop carrier is identity-pinned.** The carrier retained for reverse
delivery is set ONLY when the authenticated peer equals the route-derived
previous hop (`route.hop(position - 1)`, or `route.source()` at position 0).
An unrelated peer cannot overwrite the reverse-path connection.

**RouteHop identity binding (verified by test).**
`route.hop(position + 1).node_id() == AuthenticatedBundleCarrier.peer_id`
(the initiator pins `expected_peer`, and SNP-IK verifies it). Each
`RouteHop.endpoint` is the `listen_addr` from a SIGNED advertisement.

**Custody chain.** Every hop appends a `CustodyHop` (signed by the next
custodian). Provenance binding (#21) at every hop rejects any bundle whose
authenticated peer != expected previous custodian, so a successful round-trip
implies the chain `Client → A → B → Gateway`. An explicit test constructs this
chain and verifies continuity + signatures.

**Honest limitations (unchanged):**
- In-memory `BundleStore` (process-lifetime only; no durable persistence).
- Configured bootstrap (signed adverts), NOT live peer discovery.
- Host-local egress (mock HTTP server on 127.0.0.1).
- No Civic / settlement.

**R4.4 tests:** 8 in `r4_multihop_store_forward.rs` — including 4 R4.4-correction
regression tests:
- `r4_response_bundle_never_forwarded_to_next_hop` (negative — proven to fail
  against the buggy filter)
- `r4_response_follows_reverse_path` (response `destination == client`)
- `r4_multihop_route_next_hop_identity_matches_transport_peer`
  (`RouteHop.node_id` == authenticated peer; endpoint == signed listen_addr)
- `r4_configured_descriptor_route_is_not_called_discovery` (static: no
  `snp_discovery` / `DiscoveryProvider` in the Mode-A path)
- `r4_multihop_custody_chain_explicit` (chain == `[Client, A, B, Gateway]`)

**STOP after R4.4.** No durable persistence, no Civic. Next: R4.5 live peer
discovery.

---

## Traffic Class Split

| Aspect | Status | Evidence |
|---|---|---|
| Class A (Content) | PASS (TS+Android) | Chunking, Merkle, manifests, CAS in TS/Android |
| Class B (Transit) | PASS (Rust) | TransitRequest, StreamMessage, encrypted circuit frames — relays cannot read payloads |
| Structural separation | PASS | `FrameClass` enum (Content/Transit/Control) replaces raw u8. `Ciphertext` newtype (opaque, no as_bytes). `ContentBytes` newtype (readable). No implicit conversion between them. 10 regression tests in snp-frames/tests/traffic_class_separation.rs. R4.1 added a parallel separation at L5: `BundlePayload` (opaque, no L7 import) is distinct from `ContentBytes` (L2, readable). R4.2 preserved this — anti-entropy operates on `ObjectId` (32-byte content hash), never on `ContentBytes` directly. |

---

## R4.2 Anti-Entropy Domain Protocol (snp-sync)

R4.2 implements the frozen L5 anti-entropy primitives per the TS `sync.ts`
reference, while preserving the R4.1 dependency boundary (no L7/L6/L8 deps).

### Implemented primitives

| Primitive | Frozen source (sync.ts) | Rust implementation |
|---|---|---|
| `HaveVector` | lines 904-1013 | `HaveVector` struct + `new`/`empty`/`contains_*`/`validate`/`to_cbor`/`from_cbor` |
| `SyncRequest` | lines 1263-1382 | `SyncRequest` struct + `new`/`validate`/`to_cbor`/`from_cbor` |
| `SyncResponse` | lines 1398-1561 | `SyncResponse` struct + `SyncObjectEntry` + `new`/`empty_complete`/`validate`/`to_cbor`/`from_cbor` |
| `SyncDiff` | lines 1619-1675 | `SyncDiff` struct + `compute_sync_diff(local, remote)` |
| `SyncSession` | lines 2072-2316 | `SyncSession` struct + `build_local_have_vector`/`build_sync_request`/`handle_sync_request`/`apply_sync_response`/`pending_object_ids`/`get_pending_manifest`/`commit_pending_object` |
| `ObjectStore` trait | lines 1054-1095 | L5 contract for CAS access (`has`/`get_manifest`/`put`/`list`) |
| `DescriptorStore` trait | (implicit in TS) | L5 contract for descriptor access (`add_node_descriptor`/`get_node_descriptor`/`active_node_descriptors`/`known_gateways`) |
| `bundle_ids_for_have_vector` | (new — R4.2) | Builds the `known_objects` portion of a HAVE vector from a `BundleStore`, excluding expired bundles |

### Frozen semantics verified

- **HaveVector 4-field shape**: `known_nodes` + `known_gateways` + `known_objects` + `generated_at` — matches TS field names exactly.
- **SyncRequest 5-field shape**: `want` + `offer` + `want_descriptors` + `requester_node_id` + `generated_at` — matches TS CDDL.
- **SyncResponse**: `objects` (ObjectId + Manifest + chunkCount) + `descriptors` + `complete` — matches TS.
- **SyncDiff asymmetry invariant**: `compute_sync_diff(A, B).local_wants == compute_sync_diff(B, A).local_offers` — verified by test.
- **Expiry**: `now >= deadline` (frozen TS `isBundleExpired`). Expired bundles excluded from `bundle_ids_for_have_vector`.
- **Idempotence**: `apply_sync_response` twice with same response → no duplicate pending manifests (BTreeMap key collision).
- **Determinism**: BTreeSet ordering for diff computation; CBOR encoder sorts map keys; encode→decode→re-encode produces identical bytes.

### Transport-neutral

`SyncSession` does NOT open TCP connections, does NOT import `AsyncLink`/`Route`/`MultiplexedCircuit`/`TcpStream`. The composition layer (R4.3+) wires the session to a transport.

### Known gaps (documented, NOT normative)

- **Descriptor canonical encoding**: The skeleton `snp_identity::NodeDescriptor` has no `to_cbor`/`from_cbor` method. R4.2 correction: `SyncResponse` carries descriptors as opaque `DescriptorPayload(Vec<u8>)` bytes — L5 does NOT interpret them. The composition layer (R4.3+) is responsible for encoding descriptors to canonical bytes before passing to L5, and decoding + verifying after receiving. `GatewayAdvertisement::encode_cbor()`/`decode_cbor()` already exist for gateway adverts; `NodeDescriptor` needs the same API (R4.x+). This is NOT a fake encoder — L5 honestly carries opaque bytes.
- **Manifest canonical encoding**: The skeleton `snp_object::Manifest` has no `to_cbor`/`from_cbor` method. R4.2 correction: `SyncResponse` carries manifests as opaque `ManifestPayload(Vec<u8>)` bytes — L5 does NOT interpret them. The composition layer (R4.3+) is responsible for encoding manifests to canonical bytes. `snp_object::Manifest` needs `encode_cbor()`/`decode_cbor()` matching the TS `manifestToWireMap`/`manifestFromWireMap` (R4.x+).
- **No frozen conformance vectors for sync**: The TS reference has no `15-sync.json` conformance vector file. R4.2 does NOT create Rust-only golden vectors (per Step 16 instruction). The gap is documented here.
- **Manifest signature verification**: The `snp_object::Manifest` skeleton has no signature field. R4.2 correction: L5 carries the manifest as opaque bytes and does NOT verify the signature — that is the receiver's responsibility (L2/L3 concern). The composition layer decodes the manifest and verifies the signature.

---

## R4.1 Layer Boundary (snp-sync dependency graph)

Target per architecture correction (Step 10):

```text
snp-sync (L5)
    ↓
snp-object (L2)
snp-identity (L1)
snp-cbor
snp-crypto
```

**Verified** via `cargo tree -p snp-sync --depth 2`:

```text
snp-sync
├── snp-cbor
├── snp-crypto
├── snp-identity (→ snp-cbor, snp-crypto)
├── snp-object  (→ snp-cbor, snp-crypto)
└── thiserror
```

No L7/L6/L8 dependency exists. The previous skeleton's `snp-discovery` +
`snp-link` deps (used by the `exchange()` anti-entropy stub) have been
removed — they will be re-added only if/when R4.2 anti-entropy requires
them.

**L5 does NOT understand:** HTTP, URL, TransitRequest, TransitResponse,
Gateway, DNS, Internet policy. Those remain L7/application semantics. A
higher-level Mode-A adapter (R4.3+, in `snp-node` or a composition crate)
will serialize L7 types into `BundlePayload` bytes; L5 carries the bytes
without inspecting them.

---

## Production Composition (R1)

| Role | Production Command | Status |
|---|---|---|
| Gateway | `snp-node gateway-prod` | PASS — uses `serve_gateway_mode_b_multiplexed` + `GatewayStreamTable::new()` |
| Relay | `snp-node relay-prod --config <path>` | PASS — uses `serve_relay_via_route` + signed advert config |
| Client | `snp-node client-prod --config <path> --dest-ip <IP> --dest-port <PORT>` | PASS — uses `MultiplexedCircuit::establish` + `open_stream` |
| TUN (Mode C) | `n3b_tun_demo mesh/tun` (snp-stack) | PARTIAL — separate composition, not runtime-verified |

All production commands generate fresh identity locally. No private keys
cross process boundaries. Route endpoints are authenticated via signed
advertisements.

---

## Invariants

1. ShareNet is a bearer, not an application.
2. Class A and Class B are structurally distinct (enforcement: PARTIAL).
3. Mode A/B/C are capability levels, not competing architectures.
4. L8 remains platform-neutral (verified: no L6 imports).
5. L9 is the only platform-specific networking layer.
6. Relays do not read Class B payloads (verified: I8 invariant enforced).
7. Gateway owns Internet egress policy (verified: GatewayStreamTable::new).
8. Civic points require verified contribution proofs (TS: complete; Rust: MISSING).
9. Client balances are never economic authority (not yet implemented).
10. Settlement is authoritative for Civic balances (not yet implemented).
11. Civic Points remain non-transferable until human review.
12. UI never claims a protocol capability that runtime evidence has not established (IS_MOCK=true).
13. **(R4.1) L5 does not depend upward on L7.** snp-sync has no `snp-gateway`/`snp-node`/`snp-routing`/`snp-frames`/`snp-discovery`/`snp-link` dependency. The `Bundle` payload is opaque `BundlePayload(Vec<u8>)` — L5 carries bytes, never imports L7 types. The higher-level Mode-A adapter (R4.3+) will live in a composition crate, not in snp-sync.
14. **(R4.1) Custody is cryptographically bound.** `CustodyHop` implements the frozen `CustodyReceipt` §A4 CDDL — signed by the NEXT custodian under SIG_CONTEXT `"custodyReceipt"`. The signature binds carrier + signer + timestamps + nonce + bundle identity. Chain continuity (`hop[i].next_custodian_id == hop[i+1].custodian_id`) binds to prior custody state. A credited custodian cannot forge a receipt for its own custody (I13).
15. **(R4.1) Bundle custody is append-only (I15).** `take_custody` APPENDS a hop; existing hops are never modified or removed. `BundleStore::add` keeps the more-advanced bundle (longer chain or delivered), preventing regression.
16. **(R4.2) Anti-entropy is transport-neutral.** `SyncSession` does NOT import `TcpStream`/`AsyncLink`/`Route`/`MultiplexedCircuit`. It computes diffs + builds requests + applies responses — the composition layer (R4.3+) wires the session to a transport.
17. **(R4.2) Anti-entropy is idempotent.** `apply_sync_response` twice with the same response → no duplicate pending manifests, no duplicate objects, no duplicate descriptors. The ObjectStore's `has` check + the DescriptorStore's `add_node_descriptor` seq check handle deduplication.
18. **(R4.2) Anti-entropy is deterministic.** `compute_sync_diff` uses `BTreeSet` for set membership — no `HashMap` iteration order leaks into the diff output. CBOR encoding is canonical (RFC 8949 §4.2.1). Encode→decode→re-encode produces identical bytes.
19. **(R4.2) Anti-entropy respects expiry.** `bundle_ids_for_have_vector` excludes bundles where `now >= deadline` (R4.1 expiry semantics). Expired bundles MUST NOT be offered as active work.
20. **(R4.2) Anti-entropy preserves the L5 dependency boundary.** snp-sync still depends only on `snp-cbor` + `snp-crypto` + `snp-identity` + `snp-object` + `thiserror`. No L7/L6/L8/L4 dependency was added (verified via `cargo tree`). The `ObjectStore`/`DescriptorStore` traits are L5 contracts — the composition layer adapts L2 `Cas` → `ObjectStore` and L4 discovery → `DescriptorStore`.
21. **(R4.3) Authenticated transport identity MUST equal bundle provenance.** For every received Mode-A bundle, the authenticated SNP-IK peer NodeId MUST equal the bundle's expected previous custodian (source on first hop, last custody hop's `next_custodian_id` thereafter). This check occurs BEFORE `take_custody()`. Mismatch → no custody, no `BundleStore` insertion, no forwarding. This is a permanent architecture invariant — the transport identity and bundle provenance must agree.
22. **(R4.4) Bundle direction is routing-derived, never identity-negated.** `BundleForwarder` partitions bundles by direction using the route's source/destination NodeIds — NOT a catch-all `destination != self.identity.node_id`. Forward direction: `destination == next_hop || destination == route.destination()` (gateway). Reverse direction: `destination == route.source()` (client). A response bundle (destination == client) can therefore NEVER enter the forward path (`forward_pending_bundles`), and a request bundle (destination == gateway) can never enter the reverse path (`try_send_response_back`). The previous-hop carrier retained for reverse delivery is set ONLY when the authenticated peer equals the route-derived previous hop (`route.hop(position - 1)` / `route.source()`), so an unrelated peer cannot overwrite the reverse-path connection.
