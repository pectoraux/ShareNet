# ShareNet — Architecture Implementation Status

**Date:** 2026-08-19 (updated R4.9.3 peer lifecycle)
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
| **Mode A** (delay-tolerant) | DISCOVERY-DERIVED MULTI-HOP + DURABLE CUSTODY + REAL INTERNET EGRESS (limited) | R4.7: Mode-A `BundleForwarder` path proven with real Internet egress via the production `PinnedConnector::new()` (SSRF defence + DNS pinning + rustls TLS + IP validation). Deadline-aware timeout: Bundle `deadline` maps to connect/read timeouts. Chunked `Transfer-Encoding` explicitly rejected (R4.7 limitation: HTTP/1.1, non-chunked, GET-oriented, ports 80/443, redirects disabled). 10 R4.7 tests (local integration, chunked rejection, expired deadline, 7 SSRF rejections) + 1 opt-in `#[ignore]` real-Internet HTTPS test. R4.6 durable custody preserved. R4.5b autonomous routing preserved. R4.4 direction (#22) + R4.3 provenance (#21) preserved. **R4.7 limitations honestly stated:** no POST body, no HTTP/2, no streaming, no chunked transfer, no arbitrary egress ports. |
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

### Mode A — R4.5 live discovery

R4.5 replaces the R4.4 **configured signed-descriptor bootstrap** with a
**live discovery** path. The `Route` is now constructed from candidates
obtained at runtime over TCP discovery, verified, and accepted into the
candidate store — NOT manually assembled from per-hop advertisements.

```text
bootstrap discovery addresses  (configured seed — NOT manual per-hop config)
    ↓
LiveNodeAdvertDiscovery::discover_candidates  (TCP → decode → verify)
    ↓
Vec<VerifiedNodeAdvertisement>  (signature + NodeId↔pubkey + expiry + role/key)
    ↓
accept_discovered  →  AdvertisementAcceptanceStore  (verified candidate set)
    ↓
build_mode_a_route  (L6 route builder: capability-gated, expiry-enforced)
    ↓
Route / RouteHop  (endpoint == signed advert listen_addr)
    ↓
BundleForwarder  (UNCHANGED — receives the immutable Route)
```

**Bootstrap ≠ manual per-hop config (Step 21).** R4.5 permits a configured
bootstrap *discovery seed* (the TCP address of an initial discovery peer).
This is NOT the same as R4.4's manual per-hop advertisement configuration.
The bootstrap supplies a discovery entry point; discovery then learns Relay
A, Relay B, and Gateway; the route is built from the discovered/verified
candidates. Decentralized bootstrap is NOT required by R4.5.

**Discovery ≠ Routing ≠ Sync (Steps 15–16).**
- **Discovery** (`mode_a_discovery::LiveNodeAdvertDiscovery` +
  `serve_node_advertisement_async`) finds/advertises candidates and verifies
  them. It does NOT choose a route, order hops, or pick a gateway. It only
  populates the candidate store.
- **Routing** (`build_mode_a_route`) reads the candidate store, filters by
  capability + expiry + endpoint, selects the gateway by
  `Capability::Gateway` + circuit key, validates each relay by
  `Capability::Relay`, and builds the immutable `Route`.
- **L5** (`snp-sync`) is untouched — no discovery/routing/transport import
  (verified: `cargo tree -p snp-sync` is clean of snp-discovery/snp-node).
- **L4** (`snp-discovery`) is untouched — no routing import (verified:
  `cargo tree -p snp-discovery` is clean of snp-routing/snp-node). The
  R4.5 discovery seam (`mode_a_discovery`) lives in the composition layer
  (snp-node), reusing the existing `NodeAdvertisement` verification + the
  existing discovery wire framing, NOT the gateway-only
  `snp_discovery::DiscoveryProvider` (which wraps
  `VerifiedGatewayAdvertisement` and is unsuitable for relay discovery).
- **L8** (`AuthenticatedBundleCarrier`) remains the authority for transport
  identity; a discovered candidate is only a candidate until the L8
  handshake authenticates it. `RouteHop.node_id ==
  AuthenticatedBundleCarrier.peer_id` (verified by test).

**Freshness (Step 6).** `NodeAdvertisement::verify_into_verified()` enforces
`expiry > now` at discovery time; `build_mode_a_route` re-checks
`is_expired(now)` at route-construction time (a descriptor can expire
between discovery and route construction). Stale descriptors are NEVER
silently used — an expired candidate is excluded; an empty store yields
`NoEligibleRoute`; a missing gateway yields `NoGateway`.

**Failure behavior (Step 14).** `build_mode_a_route` returns explicit errors:
`NoEligibleRoute` (empty store), `NoGateway`, `RelayNotDiscovered`,
`RelayIneligible` (wrong capability/expired/no endpoint), `ExpiredCandidate`,
`NoTcpEndpoint`, `RouteValidationFailed`. No silent stale use.

**R4.5 tests** (`r4_5_live_discovery.rs`, 13 tests):
- `r4_5_live_discovery_multihop` — full Client → A → B → Gateway with the
  route built from live discovery (NOT manual). Response returns.
- `r4_5_discovery_matters_route_cannot_build_without_discovery` — proves
  the route CANNOT be constructed until discovered candidates exist
  (Phase 1: no services → `NoEligibleRoute`; Phase 2: start → route OK).
- Tampering: tampered signature / expired advert / wrong NodeId / wrong
  capability / freshness boundary (`expiry == now` → expired) / route uses
  signed `listen_addr` (not discovery address).
- Route selection: 3 discovered relays → route from a subset; gateway
  missing → `NoGateway`; undiscovered relay → `RelayNotDiscovered`.
- `r4_5_no_l5_or_l4_dependency_from_mode_a_discovery` — static assertion
  the composition layer imports neither snp-sync nor snp-discovery.

**Honest limitations (unchanged):**
- In-memory `BundleStore` (process-lifetime only; no durable persistence —
  R4.6).
- Configured bootstrap discovery seed (NOT decentralized bootstrap).
- Host-local egress (mock HTTP server on 127.0.0.1).
- No live route migration/repair (a route may remain fixed after
  construction — Step 13).
- No Civic / settlement.

**STOP after R4.5.** Next: R4.6 durable `BundleStore` / restart recovery.

### Mode A — R4.5b discovery-derived autonomous route selection

R4.5b corrects the R4.5a architectural defect: `build_mode_a_route(source,
store, relay_order)` took a **caller-supplied** `relay_order`, which made path
selection an application decision rather than a routing-layer decision.

R4.5b introduces `discover_mode_a_route(client, bootstrap, intent)`:

```text
BootstrapSeed { advert_discovery_addr, route_discovery_addr, ed25519_public_key }
    ↓
discover_all_candidates (TCP → CBOR array → verify each)
    ↓
TopologyGraph (verified candidate set)
    ↓
routing layer: select gateway (Capability::Gateway + circuit key
    + not expired + TCP endpoint, lowest NodeId — deterministic)
    ↓
RemoteNodeHint { target: gateway_node_id, learned_from: bootstrap_node_id }
    ↓
TcpRecursiveTransport (bootstrap peer at route_discovery_addr)
    ↓
NextHopResolver::resolve_route(gateway_node_id, hint)
    ↓
ForwardedQuery → Relay A → Relay B → Gateway (ForwardingNode chain)
    ↓
DistributedRouteResolution::verify() + into_route()
    ↓
immutable Route (endpoint == signed advert listen_addr)
    ↓
BundleForwarder (UNCHANGED — receives the Route)
```

**The caller does NOT supply:**
- `relay_order` — the relay path is discovered by the recursive protocol.
- `gateway_node_id` — the routing layer selects the gateway from verified
  candidates.
- A manually constructed `Route`.

**R4.5a vs R4.5b distinction:**
- R4.5a — live signed-advertisement candidate discovery (caller supplies
  `relay_order`).
- R4.5b — discovery-derived route selection (caller supplies `ModeARoutingIntent`).

**Discovery ≠ Routing ≠ Sync (#23 preserved):**
- Discovery (`discover_all_candidates` + `serve_node_adverts_with_neighbors_async`)
  finds candidates and verifies them.
- Routing (`discover_mode_a_route` + `resolve_route` + `into_route`) selects
  the gateway and the relay path.
- L5 (`snp-sync`) is untouched.
- `BundleForwarder` is discovery-blind (unchanged).

**Remote-hint security:** `RemoteNodeHint` is non-authoritative — it triggers
resolution but never becomes a `RouteHop`. Every `RouteHop` comes from a VERIFIED
`AuthenticatedNodeRecord` obtained during recursive discovery.

**R4.5b tests** (`r4_5b_discovery_derived_routing.rs`, 12 tests):
- `r4_5b_autonomous_route_selection_multihop` — full Client → A → B → Gateway
  round-trip with route built by routing layer (NOT caller-supplied).
- `r4_5b_discovery_bypass_route_fails_without_discovery` — Phase 1: no
  discovery → `NoEligibleRoute`; Phase 2: start → route succeeds (no
  relay_order or gateway_node_id).
- `r4_5b_gateway_selection_deterministic` — multiple gateways → routing
  selects lowest NodeId.
- `r4_5b_non_gateway_cannot_be_destination` — no gateway → `NoGateway`.
- Advertisement security: tampered signature / wrong NodeId / expired /
  valid accepted.
- `r4_5b_remote_hint_cannot_become_route_hop_directly` — structural proof.
- `r4_5b_route_endpoint_is_signed_listen_addr_not_discovery_addr`.
- `r4_5b_api_does_not_accept_relay_order_or_gateway_nodeid`.
- `r4_5b_discover_all_candidates_from_one_bootstrap`.

**STOP after R4.5b.** Next: R4.6 durable `BundleStore` / restart recovery.

### Mode A — R4.5b correction: bootstrap discovery trust

The R4.5b correction tightens two trust boundaries:

1. **Bootstrap identity binding (Issue A):** `discover_all_candidates` now
   takes a `&BootstrapSeed` (not a bare address). The FIRST advert in the
   discovery response MUST be the bootstrap peer's own advert, and its NodeId
   MUST equal `bootstrap.node_id()` (derived from `ed25519_public_key`). If
   not, the entire response is REJECTED — an imposter server X cannot serve
   stolen-but-valid adverts as if they were the configured bootstrap's output.

2. **Verified peer state (Issue B):** `serve_bootstrap_discovery_async`
   derives the served neighbor adverts from the `TopologyGraph`'s
   `AdvertisementAcceptanceStore::all_records()` (verified
   `AuthenticatedNodeRecord`s only) — NOT from a preassembled
   `Vec<NodeAdvertisement>`. `RemoteNodeHint`s are non-authoritative and
   NEVER appear in discovery output (type-enforced: `all_records()` returns
   `&AuthenticatedNodeRecord`, which a `RemoteNodeHint` cannot become).

The model remains: configured bootstrap seed → authenticated bootstrap →
bootstrap's verified peer knowledge → routing. NOT global live mesh
discovery. The caller supplies only `BootstrapSeed` + `ModeARoutingIntent`.

**Tests added:**
- `r4_5b_bootstrap_identity_mismatch_rejected` — negative (server identity ≠
  seed identity → rejected) + positive (match → succeeds).
- `r4_5b_bootstrap_serves_only_verified_no_remote_hints` —
  `serve_bootstrap_discovery_async` serves only verified records; a
  `RemoteNodeHint` for a fake gateway does NOT appear in discovery output.

**STOP after R4.5b correction.** Next: R4.6 durable `BundleStore` / restart recovery.

### Mode A — R4.6 durable bundle custody

R4.6 adds file-backed durability to the Mode-A bundle store. The L5
`snp_sync::BundleStore` remains the **authoritative** in-memory custody
model — `PersistentBundleStore` (in `snp-node`, the composition layer) OWNS a
`BundleStore` and mirrors its mutations to the filesystem. It does NOT create
a second custody authority.

```text
L5 BundleStore (authoritative in-memory custody state)
    ↑
    | owns + delegates
    |
PersistentBundleStore (snp-node composition adapter)
    |
    | mirrors mutations (atomic write + fsync + rename + dir-fsync)
    ↓
filesystem (durable representation: <bundle_id_hex>.cbor per bundle)
```

**Critical transaction (R4.6 invariant #24):**

```text
take_custody()
    ↓
PersistentBundleStore::add() — persist bundle (fsync)
    ↓
if Err: do NOT ack → previous hop re-sends
    ↓
carrier.send_bundle() — custody ACK
    ↓
forward_pending_bundles()
    ↓
[next hop acks] → PersistentBundleStore::remove() — release custody
```

**Corruption model (fail-closed):** `PersistentBundleStore::open(dir)` reads
every `.cbor` file, decodes + validates. If ANY record is corrupt (truncated,
invalid CBOR, `bundle_id` mismatch, broken custody chain), `open()` returns
`Err(Corrupt)`. The node does NOT start with a partial custody state. This
prevents a node from silently forgetting custody it previously acknowledged.

**Restart recovery:** `open()` loads durable bundles → the existing
`forward_pending_bundles()` periodic retry (every 500ms in `run()`) resumes
forwarding. Recovery is automatic — no separate `recover()` method needed.

**Custody dedup ≠ application exactly-once:** `BundleStore::more_advanced()`
prevents custody-state regression (a re-forwarded bundle with the same or
shorter chain is deduped). This is custody deduplication, NOT application-
level exactly-once execution. The L7 gateway may receive the same
`TransitRequest` twice — application-level idempotence (e.g., reqId dedup)
is an L7 concern, outside `BundleStore`.

**R4.6 tests** (`r4_6_durable_bundle_store.rs`, 10 tests):
- Basic durability (persist → drop → reopen → present)
- Custody durability (chain survives restart)
- Crash before ACK (bundle present → forwarder retries)
- Crash after ACK (bundle present → forwarder resumes)
- Expiry recovery (expired bundles pruned, not resurrected)
- Duplicate insertion (`more_advanced` keeps longer chain)
- Corruption (truncated → fail-closed)
- Corruption (invalid CBOR → fail-closed)
- Full Mode-A restart (Relay B crashes → restarts → forwards → gateway receives)
- In-memory backward compat (`new()` = in-memory)

**Preserved (untouched):**
- `snp-sync` (L5) — no `tokio`/`std::fs`/`std::io` (invariant #13)
- `Bundle`/`BundleStore`/`CustodyHop` types (frozen)
- `Route`/`RouteHop` (L6)
- `AuthenticatedBundleCarrier` (L8)
- `BundleForwarder` direction/provenance logic (#21/#22)
- `ModeARelay` (frozen R4.3 — uses in-memory `BundleStore`, unchanged)
- Discovery, routing, Civic

**STOP after R4.6.** No Civic. No route migration. No hard storage quota.

### Mode A — R4.7 real Internet egress

R4.7 proves that the Mode-A `BundleForwarder` path can reach a real public
HTTPS endpoint via the gateway's production `PinnedConnector::new()` egress.

```text
Client (ModeAClient)
  ↓ send_request(https://example.com/, relay, gateway)
BundleForwarder (Relay A)
  ↓
BundleForwarder (Relay B)
  ↓
ModeAGateway
  ↓ PinnedConnector::new(url) — production path
  → URL validation (scheme, port, length)
  → SSRF literal-host check
  → DNS resolution → validate EVERY IP (DNS rebinding defence)
  → IP pinning
  → TCP connect to pinned IP (deadline-aware timeout)
  → TLS handshake (rustls + webpki-roots, SNI=hostname)
  → HTTP/1.1 request (GET, Connection: close)
  → Response parsing (status, headers, Content-Length body)
  → Chunked Transfer-Encoding: REJECTED explicitly
  → Response body capped at max_response_bytes (read-time)
  → TransitResponse (signed by gateway)
  ↓ response Bundle
BundleForwarder (Relay B → Relay A)
  ↓
ModeAClient
  ↓ verify_transit_response (gateway signature + reqId match)
```

**R4.7 changes:**
- `fetch_with_limit` now takes a `deadline` parameter → maps to
  `connect_timeout = min(remaining, CONNECT_TIMEOUT_SECS)` and
  `read_timeout = min(remaining, READ_TIMEOUT_SECS)`. Expired deadline →
  rejected before TCP connect.
- Chunked `Transfer-Encoding` is explicitly rejected with a clear error
  (the HTTP/1.1 parser does NOT implement chunked decoding — silently
  treating chunked bytes as a normal body would corrupt data).

**R4.7 limitations (honestly stated):**
- HTTP/1.1 only (no HTTP/2)
- GET-oriented (no request body support — `TransitRequest` has no `body` field)
- Non-chunked responses only (chunked is explicitly rejected)
- Ports 80/443 only (fail-closed on non-standard)
- Redirects disabled (3xx returned verbatim)
- No POST/PUT/PATCH/DELETE body support

**R4.7 tests** (`r4_7_real_internet_egress.rs`, 10 + 1 ignored):
- `r4_7_mode_a_local_egress_integration` — Client → A → B → Gateway →
  local mock HTTP → response → B → A → Client (uses `from_parts` test bypass)
- `r4_7_chunked_transfer_encoding_rejected` — chunked explicitly rejected
- `r4_7_expired_deadline_prevents_egress` — expired Bundle deadline →
  egress rejected before TCP
- 7 SSRF rejection tests (loopback, private IP, metadata endpoint,
  unsupported scheme, non-standard port, IPv6 loopback, link-local)
- `r4_7_production_real_internet_egress` (#[ignore]) — opt-in real HTTPS
  via `PinnedConnector::new()` through the full Mode-A mesh

**Preserved:** all SSRF defences, DNS rebinding protection, IP pinning,
rustls TLS SNI/cert validation, response/header size limits, redirect
disabling, gateway signature integrity, reqId binding, provenance #21,
direction #22, durable custody #24.

**STOP after R4.7.**

### Mode A — R4.8 operational hardening

R4.8 hardens the R4.3–R4.7 substrate for operational use. No new features —
only correctness, availability, and observability improvements.

**Changes:**
1. **Runtime expired-bundle pruning** — `BundleForwarder::run()` periodically
   calls `PersistentBundleStore::prune_expired(now)` every ~30s. Expired
   bundles are durably removed from memory + disk during runtime (not just
   on restart).
2. **Route execution-expiry enforcement** — before `forward_pending_bundles`,
   the forwarder checks `route.is_expired(now)`. If expired, forwarding is
   suspended (bundles remain safely stored). No automatic rerouting (R4.9).
3. **Gateway concurrency limiting** — `ModeAGateway::run_with_shutdown()`
   uses a `Semaphore` (`MAX_CONCURRENT_EGRESS = 8`) to bound concurrent
   upstream egress. Permit acquisition is deadline-aware.
4. **Persistent-store .tmp cleanup** — `PersistentBundleStore::open()`
   removes orphaned `.tmp` files from interrupted writes.
5. **Graceful shutdown** — `run_with_shutdown(token: &CancellationToken)`
   on both `BundleForwarder` and `ModeAGateway`. Shutdown cancels the
   `tokio::select!` loop → clean exit. Durable custody is preserved.
6. **Structured tracing** — all `eprintln!` calls in `BundleForwarder`,
   `ModeAGateway`, and `PersistentBundleStore` replaced with `tracing::info!`
   / `warn!` / `error!` with structured fields (`node_id`, `bundle_id`,
   `peer_id`, `req_id`, `error`).

**Explicitly deferred to R4.9+:**
- Key rotation / revocation
- Periodic peer rediscovery
- Automatic route rebuild
- Retry backoff
- Per-client economic quotas
- Civic / Settlement
- Mode C expansion

**R4.8 tests** (`r4_8_operational_hardening.rs`, 9 tests):
- `r4_8_runtime_prune_expired_bundle` — memory + disk cleaned
- `r4_8_expired_route_does_not_forward` — forwarding suspended
- `r4_8_expired_route_retains_durable_bundle` — no data loss
- `r4_8_gateway_requests_are_concurrent` — gateway starts + shuts down cleanly
- `r4_8_orphan_tmp_files_are_cleaned` — .tmp removed during recovery
- `r4_8_bundle_forwarder_graceful_shutdown` — run() returns on cancel
- `r4_8_gateway_graceful_shutdown` — run() returns on cancel
- `r4_8_tracing_is_available` — tracing in dependency graph
- `r4_8_shutdown_token_reexported` — `ShutdownToken` re-exported

**STOP after R4.8.**

### R4.9.1 — Identity Lifecycle Foundation

R4.9.1 introduces an additive identity lifecycle layer around the existing
`NodeIdentity` primitive. No protocol wire formats changed. `NodeIdentity`
is unmodified.

**New types in `snp-identity`:**
- `IdentityState` enum: `Active`, `Rotating`, `Revoked`, `Retired`
- `IdentityLifecycle` struct: wraps `NodeIdentity` + `IdentityState` +
  durable persistence (atomic write + fsync + rename)
- `IdentityLifecycleError` enum

**Semantics:**
- **`Active`** — identity is authoritative for new authenticated operations.
- **`Rotating`** — rotation begun; old identity remains authoritative until
  new is durably persisted.
- **`Revoked`** — no longer valid for new operations (persisted).
- **`Retired`** — permanently superseded (persisted).

**Rotation atomicity:**
```text
old identity Active → begin_rotation → Rotating
→ persist new identity (fsync) → success → Active (new identity)
→ failure → Active (old identity restored)
```

**Durable state FIRST, memory mutation SECOND** — mandatory.

**Startup:**
- `load_or_create(path)` — loads existing identity or creates + persists new.
- Corrupt identity file → **fail-closed** (NOT silently generate new).
- Missing identity file → first initialization (create + persist).

**File format:** magic "SNPI" + version 1 + 32-byte secret key + null-terminated
state string. Public key and NodeId are recomputed from the secret key — never
independently trusted from the file.

**R4.9.1 tests** (`r4_9_1_identity_lifecycle.rs`, 9 tests):
- `r4_9_1_identity_rotation_preserves_service` — rotation succeeds, new identity persisted
- `r4_9_1_failed_rotation_keeps_previous_identity` — persistence failure → old identity restored
- `r4_9_1_revoked_identity_rejected` — revoked identity cannot rotate
- `r4_9_1_retired_identity_not_selected_for_new_sessions` — retired identity not active
- `r4_9_1_load_or_create_initializes_and_persists` — startup load/create
- `r4_9_1_corrupt_identity_file_fails_closed` — corrupt file rejected
- `r4_9_1_truncated_identity_file_fails_closed`
- `r4_9_1_wrong_magic_fails_closed`
- `r4_9_1_unsupported_version_fails_closed`

**STOP after R4.9.1.**

### R4.9.2 — Identity Revocation and Trust Update

R4.9.2 makes revocation operationally meaningful by establishing a durable
and fail-closed mechanism by which a revoked identity is no longer accepted
for new authenticated sessions or new trust decisions.

**New types in `snp-identity`:**
- `RevocationStore` — a durable set of revoked NodeIds with atomic write +
  fsync + rename persistence. Fail-closed on corruption.
- `IdentityLifecycle::is_revoked()` — checks if the local identity is revoked.
- `IdentityLifecycle::is_authorized_for_new_sessions()` — the authorization
  boundary: returns `true` only for `Active` state.

**Semantics:**
- A revoked identity's historical signatures remain **cryptographically
  valid** for verification (revocation ≠ cryptographic invalidation).
- A revoked identity is **NOT authorized** for new authenticated sessions,
  new trust decisions, or new advertisement authority.
- The `RevocationStore` is the trust enforcement boundary for both local
  and remote peer revocation.
- Revocation is durable (survives restart).
- Persistence failure leaves the identity `Active` (durable-state-first).

**No distributed revocation protocol introduced** — R4.9.2 provides only
the local trust enforcement boundary. Distributed revocation (gossip,
consensus) is a later milestone.

**R4.9.2 tests** (`r4_9_2_identity_revocation.rs`, 7 tests):
- `r4_9_2_revocation_survives_restart` — reload after revoke → still revoked
- `r4_9_2_revoked_identity_rejected` — lifecycle rejects rotation from Revoked
- `r4_9_2_revoked_peer_not_trusted_for_new_session` — RevocationStore
  rejects revoked peer, authorizes non-revoked peer
- `r4_9_2_historical_signature_remains_verifiable` — signature created
  while Active is still valid after revocation
- `r4_9_2_revocation_persistence_failure_preserves_active_state` —
  persistence failure → identity remains Active
- `r4_9_2_revocation_store_corruption_fails_closed` — corrupt file → Err
- `r4_9_2_idempotent_revocation` — revoking twice is a no-op

**STOP after R4.9.2.**

### R4.9.3 — Peer Lifecycle Automation

R4.9.3 makes peer state self-maintaining by introducing the
`PeerLifecycleManager` — an additive operational layer around the existing
`AdvertisementAcceptanceStore`.

**New types in `snp-node`:**
- `PeerLifecycleManager` — wraps `AdvertisementAcceptanceStore` +
  `RevocationStore` + in-memory quarantine set
- `PeerOperationalState` — `Active`, `Stale`, `Quarantined`, `Revoked`,
  `Unknown`

**Behavior:**
- **Periodic expiry:** `maintain(now)` calls
  `AdvertisementAcceptanceStore::purge_expired_records(now)` — transitions
  ACTIVE → STALE without deleting identity history or sequence floors.
- **Advertisement refresh:** `accept_advertisement(verified)` checks the
  RevocationStore first (revoked peers cannot recover), then delegates to
  the acceptance store, then clears quarantine (successful revalidation).
- **Stale exclusion:** `is_eligible_for_forwarding(node_id)` returns `true`
  only for `Active` peers.
- **Quarantine:** `quarantine(node_id, reason)` adds the peer to an
  in-memory set. Quarantine is NOT persisted — it clears on restart,
  requiring fresh revalidation. Quarantine does NOT revoke the identity
  or reset the sequence floor.
- **Recovery:** A quarantined peer returns to `Active` after receiving a
  fresh valid advertisement (revalidation) that passes all existing
  verification + revocation check.
- **Revocation integration:** `revoke_peer(node_id)` delegates to
  `RevocationStore::revoke()` — durable, survives restart. Revoked peers
  cannot recover through advertisement refresh.

**Preserved:**
- `AdvertisementAcceptanceStore` — authoritative peer state, sequence
  floors, atomic writes
- `PeerVisibility` — unchanged
- `NodeAdvertisement` — unchanged
- All protocol wire formats, `Route`/`RouteHop`, `Bundle`/`CustodyHop`

**R4.9.3 tests** (`r4_9_3_peer_lifecycle.rs`, 8 tests):
- `r4_9_3_peer_refresh_updates_liveness` — STALE → ACTIVE after refresh
- `r4_9_3_expired_peer_becomes_stale` — expiry + maintain → STALE
- `r4_9_3_stale_peer_not_selected` — stale NOT eligible
- `r4_9_3_quarantined_peer_not_selected` — quarantined NOT eligible
- `r4_9_3_peer_recovery_after_revalidation` — quarantine → ACTIVE
- `r4_9_3_revoked_peer_cannot_recover_through_refresh` — revocation blocks
- `r4_9_3_sequence_floor_survives_stale` — sequence persists
- `r4_9_3_sequence_floor_survives_quarantine` — sequence persists

**STOP after R4.9.3.**

### R4.9.4 — Retry Intelligence

R4.9.4 replaces the pre-R4.9.4 fixed 500ms retry cadence with bounded,
jittered, failure-aware exponential backoff. Retry intelligence is an
**operational scheduling policy** — it decides *when* the next forwarding
attempt for a peer occurs, never *which* route a bundle uses (R5 territory).

**New module** (`snp-node/src/node/retry_policy.rs`):
- `RetryPolicy` — pure, testable exponential backoff with bounded jitter.
- `RetryRng` trait + `SystemRetryRng` (OS `getrandom`) + `DeterministicRetryRng`
  (tests). The RNG is abstracted so unit tests are fully reproducible.
- `FailureClass` (`Retryable` / `Terminal`) + `classify_forwarding_error` —
  classifies `ModeAError` against the existing error taxonomy.
- `PeerRetryState` — `failure_count` + `next_eligible_at` (monotonic `Instant`).
- `RetryScheduler` — per-peer ephemeral state + terminal-bundle set.

**Constants** (derived from existing behaviour):
- `BASE_DELAY = 500ms` — matches the pre-R4.9.4 cadence so the first retry is
  no slower than before.
- `MAX_DELAY = 30s` — bounds exponential growth.

**Backoff formula:**
```text
backoff = min(MAX_DELAY, BASE_DELAY * 2^(failure_count - 1))
jitter  = rng.jitter_millis(backoff / 2)     // [0, backoff/2]
delay   = min(MAX_DELAY, backoff + jitter)    // <= MAX_DELAY, >= 0
```

**Behaviour:**
- **Exponential backoff** — `attempt 1 → 500ms`, `2 → 1s`, `3 → 2s`, … capped
  at `MAX_DELAY`.
- **Bounded jitter** — `delay = backoff + [0, backoff/2]`, capped at
  `MAX_DELAY`. Jitter is never negative and never overflows the cap.
- **Local failure scoring** — each retryable peer-attributable failure
  increments the peer's `failure_count`; a genuine success (custody ACK)
  resets it to `0`. This is NOT reputation and NOT route selection.
- **Terminal vs retryable classification** — only
  `ModeAError::Link(AsyncLinkError::Io(_))` and `ModeAError::Transport(_)`
  (connection refused / reset / EOF / timeout / unreachable / peer I/O) are
  retryable. Cryptographic (handshake, AEAD), malformed (CBOR), expiry,
  identity-substitution, downstream-gateway, and local errors are terminal.
- **Expiry-aware retries** — `BundleStore::pending` already excludes expired
  bundles; additionally `RetryScheduler::retry_fits_before_deadline` reports
  whether a scheduled retry would occur before the bundle deadline (a retry
  past the deadline is never relied upon). Bundle TTL is never extended.
- **Cancellation-aware waiting** — the forwarder sleeps for
  `min(poll_interval, time_until_next_eligible)` inside a `select!` with
  `shutdown.cancelled()` as the first branch, so shutdown never waits for a
  full backoff.
- **Ephemeral retry state** — per-peer state is in-memory only and resets on
  restart. Durable bundle custody (R4.6) remains authoritative; on restart a
  fresh operational schedule is applied to the durable bundles.
- **Successful reset** — a custody ACK from the next hop resets the peer's
  failure score to `0` and clears any pending backoff. Reset is not triggered
  by merely scheduling a retry, attempting a connection, or an unrelated bundle
  succeeding.
- **Terminal-bundle set** — a bundle that hits a terminal failure is marked
  terminal and skipped on future forwarding ticks (it stays in durable custody
  until expiry pruning). A terminal bundle does NOT poison the peer's score.

**Failure attribution** — only peer-attributable transient failures increment
the score: connection refused, connection reset, transport handshake I/O,
peer unreachable, I/O failure during peer forwarding. Local disk failure, CPU
exhaustion, malformed local state, downstream gateway failure, bundle expiry,
intentional shutdown, cancellation, and caller-side validation failure do NOT
increment the score.

**Integration into `BundleForwarder`** (`mode_a_bundle.rs`):
- `run_with_shutdown` — the fixed `sleep(500ms)` is replaced by an adaptive
  `sleep(retry.next_sleep_duration(now, FORWARD_POLL_INTERVAL))`.
- `forward_pending_bundles` — adds an eligibility gate (skip peers in backoff),
  a terminal-bundle filter, failure classification + recording on
  connect/send/custody-ack failure, and a success reset on custody ACK. Route
  expiry (`route.is_expired`) and bundle expiry (`pending`/`prune_expired`)
  remain authoritative.
- `ModeARelay` (R4.3 legacy in-memory relay) is intentionally untouched — it
  is used only by R4.3 conformance tests and has no shutdown/durable-store.

**Preserved (frozen — NOT modified):**
- `Bundle`, `BundleId`, `CustodyHop`, `Route`, `RouteHop`, `RoutePolicy`,
  `TransitRequest`, `TransitResponse`, `AuthenticatedBundleCarrier`,
  `NodeIdentity`, all wire formats, custody semantics, SNP-IK, advertisement
  signature format, NodeId derivation.
- `PeerLifecycleManager` (R4.9.3) — NOT redesigned; retry intelligence is
  self-contained. The failure score is a documented hook for future peer
  lifecycle / resource-governance integration (R4.9.5). No quarantine
  thresholds are introduced here.

**R4.9.4 tests** (`r4_9_4_retry_intelligence.rs`, 9 tests):
- `r4_9_4_backoff_increases` — attempt 1 <= 2 <= 3 (exact doubling w/o jitter)
- `r4_9_4_backoff_is_capped` — large attempts saturate at MAX_DELAY
- `r4_9_4_jitter_is_bounded` — BASE_DELAY <= delay <= MAX_DELAY for all attempts
- `r4_9_4_deterministic_rng_produces_testable_jitter` — reproducible jitter
- `r4_9_4_success_resets_failure_state` — success resets score + backoff
- `r4_9_4_expired_bundle_not_retried` — deadline-aware + store expiry filter
- `r4_9_4_retryable_failure_increments_failure_score` — 0 → 1 → 2 → 3 → 0
- `r4_9_4_terminal_failure_not_retried` — terminal marks bundle, no peer poison
- `r4_9_4_retry_wait_respects_shutdown` — cancellation wins over backoff

**Verification:** R4.9.4: 9/9 · R4.9.3: 8/8 · R4.9.2: 7/7 · R4.9.1: 9/9 ·
R4.8: 11/11 · R4.7: 10/10+1i · R4.6: 30/30 · R4.5b: 14/14 · R4.4: 8/8 ·
R4.3: 9/9 · conformance: 138/138 · `cargo fmt -p snp-node --check`: clean.

**STOP after R4.9.4.**

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
23. **(R4.5) Discovery ≠ Routing ≠ Sync.** Live candidate discovery, route construction, and bundle sync are structurally separate. Discovery (`mode_a_discovery::LiveNodeAdvertDiscovery`) finds/advertises candidates and verifies them — it does NOT choose a route, order hops, or pick a gateway. Routing (`build_mode_a_route`) reads the candidate store and builds the `Route` — it does NOT query discovery. `snp-sync` (L5) imports neither (`cargo tree -p snp-sync` is clean). A discovered candidate is only a candidate until the L8 `AuthenticatedBundleCarrier` handshake authenticates it — discovery never replaces cryptographic transport identity. The route endpoint is the signed `listen_addr` from the verified advertisement (`RouteHop.endpoint == advert.endpoints`, NOT the discovery address). Stale descriptors (`expiry <= now`) are never silently used — `verify_into_verified()` rejects at discovery time; `build_mode_a_route` re-checks `is_expired(now)` at route-construction time.
24. **(R4.6) Custody acknowledgement implies durable recoverable custody.** `PersistentBundleStore::add()` (which persists the bundle to the filesystem via atomic write + `fsync` + `rename` + directory `fsync`) MUST complete successfully BEFORE `BundleForwarder::run()` sends the custody ACK to the previous hop. If `add()` returns `Err`, the forwarder does NOT ack — the previous hop re-sends. The L5 `snp_sync::BundleStore` remains the authoritative custody model; `PersistentBundleStore` (snp-node composition adapter) owns + mirrors it — it does NOT create a second custody authority. Corruption of a persisted custody record causes `PersistentBundleStore::open()` to return `Err` (fail-closed) — the node does NOT silently skip or fabricate partial custody state. Custody deduplication (`more_advanced`) is distinct from application-level exactly-once execution (L7 reqId dedup is separate).
