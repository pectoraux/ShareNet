# ShareNet — Architecture Implementation Status

**Date:** 2026-08-18 (updated R4.1)
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
| **L1 Identity** | 4 identity classes, Ed25519+X25519, rotation, revocation | snp-identity: NodeIdentity + Capability (extracted R2.2) + NodeId + derive_node_id + verify_signed. snp-crypto: Ed25519+X25519 primitives. | PASS | Conformance vectors 03-identity: 7/7 pass. snp-node tests: 97 pass. | R2.2 + R2 descriptor extraction complete. GatewayAdvertisement + VerifiedNodeDescriptor + TransportEndpoint now in snp-identity. |
| **L2 Object/Content** | CAS, chunking, Merkle, manifests | snp-object: Merkle tree, chunking, proofs, CAS trait (real code). InMemoryCas impl: todo!(). TS reference: complete. Android: complete. | PASS (Rust Merkle/chunking), PARTIAL (CAS storage) | Conformance vectors 04-chunking, 05-merkle, 06-manifest: all pass. | CAS storage not implemented in Rust; TS is authoritative for CAS. |
| **L3 Trust** | Attestations, reputation, revocation | AuthenticatedNodeRecord (complete). VerifiedNodeAdvertisement (complete). No reputation system. | PARTIAL | Conformance vectors 13-revocation: 3/3 pass. | Reputation system not yet implemented |
| **L4 Discovery** | Peer+capability advertisement, freshness | snp-discovery: DiscoveredNode + DiscoveryProvider + StaticDiscovery (extracted R2). Beacon/DescriptorStore: skeleton (todo!()). snp-node: BootstrapDiscovery (runtime TCP I/O). GatewayAdvertisement now in snp-identity. | PASS (types), PARTIAL (runtime) | snp-node integration tests: n210 pass. | Beacon/DescriptorStore still skeleton. BootstrapDiscovery runtime in snp-node. |
| **L5 Mesh Sync** | Anti-entropy, store-carry-forward, bundle custody | snp-sync: generic `Bundle` + `BundleId` + `BundlePayload` (opaque) + `CustodyHop` (frozen CustodyReceipt semantics, §A4) + `BundleStore` (add/get/remove/pending/more_advanced/prune_expired) — implemented R4.1. Anti-entropy (`SyncRequest`/`SyncResponse`/`SyncObject` types declared; exchange NOT implemented — R4.2+). TS reference: complete (sync.ts, 2316 lines). | PARTIAL (Rust — Bundle layer complete, anti-entropy pending) | snp-sync tests: 51 pass (R4.1 audit-expanded). TS sync.ts exports 30+ functions. | Anti-entropy exchange (R4.2), runtime forwarding (R4.2+), Mode-A adapter wiring (R4.3+) remain. snp-sync has NO L7 dependency (verified: dep graph is snp-cbor+snp-crypto+snp-identity+snp-object only). R4.1 audit: BundleId pinned to `SHA-256(cbor({source,destination,createdAt,deadline,payload}))` — custody chain + delivered flag excluded; CustodyHop field names match frozen §A4 CDDL exactly; expiry uses `now >= deadline`; more_advanced matches TS rule 1+3+4 (rule 2 N/A — generic L5 Bundle has no response field). |
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
| **Mode A** (delay-tolerant) | PARTIAL (R4.1) | See corrected terminology below. |
| **Mode B** (proxied) | PASS (Rust) | MultiplexedCircuit, StreamHandle, serve_gateway_mode_b_multiplexed, N3AClient. |
| **Mode C** (transparent) | PARTIAL | TunClient with any_ip + destination extraction + split-tunnel. NOT RUNTIME-VERIFIED. TCP-only, Linux-only. |

### Mode A — corrected terminology (R4.1 Step 8)

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

---

## Traffic Class Split

| Aspect | Status | Evidence |
|---|---|---|
| Class A (Content) | PASS (TS+Android) | Chunking, Merkle, manifests, CAS in TS/Android |
| Class B (Transit) | PASS (Rust) | TransitRequest, StreamMessage, encrypted circuit frames — relays cannot read payloads |
| Structural separation | PASS | `FrameClass` enum (Content/Transit/Control) replaces raw u8. `Ciphertext` newtype (opaque, no as_bytes). `ContentBytes` newtype (readable). No implicit conversion between them. 10 regression tests in snp-frames/tests/traffic_class_separation.rs. R4.1 added a parallel separation at L5: `BundlePayload` (opaque, no L7 import) is distinct from `ContentBytes` (L2, readable). |

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
