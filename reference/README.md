# ShareNet 2.0 — Rust Reference Implementation

This directory is the **Rust reference implementation** of ShareNet 2.0, per
`/public/spec/07-MIGRATION-AND-ROADMAP.md` §3 (Deliverable 22) and §2.4.

> *"reference/ is Rust on Linux — no platform obstacles, so protocol bugs
> surface as protocol bugs."* — 07-MIGRATION-AND-ROADMAP §3

## Authority

This implementation is the **authoritative** reference for ShareNet 2.0.
Conformance vectors generated here are the golden vectors; every other
implementation (Kotlin, Python, Swift) must match byte-for-byte.

## Status: PARTIAL — Network core implemented

The following crates contain **real protocol logic** (not stubs):

| Crate | Status | What's implemented |
|---|---|---|
| `snp-cbor` | ✅ Complete | Canonical CBOR per RFC 8949 §4.2.1 (sorted keys, shortest-form, no floats/tags, dup keys rejected) |
| `snp-crypto` | ✅ Complete | Ed25519, X25519, SHA-256, HKDF-SHA256, ChaCha20-Poly1305 (ed25519-dalek / sha2 / hkdf / chacha20poly1305) |
| `snp-node` | ✅ Substantial | The reference daemon — 20+ submodules: identity, capability, gateway, node_advert, descriptor, route, route_discovery, topology, peer_directory, topology_protocol, propagation_state, link, circuit, circuit_handshake, distributed_circuit, traffic, session, discovery, transport, async_node |
| `snp-link` | ✅ Complete | L8 link abstraction with directional AEAD-encrypted frame transport (N1.9 fixes bidirectional nonce-reuse risk) |
| `snp-gateway` | ✅ Substantial | Mode A TransitRequest/Response, SSRF defence (`is_private_destination`), N1.9 IP-pinning HTTPS fetcher (`PinnedConnector`) |
| `snp-object` | ✅ Complete | Gear CDC chunking, RFC 6962 Merkle trees, CAS, manifests |
| `snp-frames` | ✅ Complete | SNP/0.1 §7 Frame format — Class A/B/C |
| `snp-conformance` | ✅ Complete | Independent conformance harness — loads JSON vectors, classifies INDEPENDENT/NEGATIVE/UNSUPPORTED/FAILED |

The following crates remain **skeleton stubs** — their functionality is
implemented inside `snp-node/src/node/` (the reference daemon holds the
production code):

| Crate | Status | Where functionality lives |
|---|---|---|
| `snp-identity` | 🔲 Skeleton | `snp-node/src/node/identity.rs` |
| `snp-discovery` | 🔲 Skeleton | `snp-node/src/node/discovery.rs` |
| `snp-sync` | 🔲 Skeleton | (future) |
| `snp-routing` | 🔲 Skeleton | `snp-node/src/node/route_discovery.rs` + `route.rs` |
| `snp-circuit` | 🔲 Skeleton | `snp-node/src/node/distributed_circuit.rs` + `circuit_handshake.rs` + `circuit.rs` |
| `snp-civic` | 🔲 Skeleton | (future — contribution proofs deferred) |

## Implemented architecture (at commit `f7bd6ec`)

The network core is implemented and tested:

```
NodeIdentity (Ed25519 + NodeId = SHA-256("SNP/0.1 node\0" ‖ pk))
    ↓
NodeAdvertisement (signed, sequence, expiry, capabilities, endpoints)
    ↓
Discovery (link-local beacons, mDNS, authenticated descriptor exchange)
    ↓
Links (TCP + SNP-IK/0.1 handshake, directional AEAD LinkKeys)
    ↓
Topology (RemoteNodeHint ≠ AuthenticatedNodeRecord; direct_gateways() ≠ gateway_hints())
    ↓
Propagation (propagation_sequence, replay/stale rejection)
    ↓
Route Discovery (progressive next-hop: destination discovery → target auth →
                 next-hop discovery → per-hop auth → path assembly → path
                 validation → service agreement → route proposal →
                 participant acceptance → committed route)
    ↓
Distributed Circuits (CircuitSetup → relay handshake → X25519 possession proof →
                      forwarding state → ActiveCircuit)
    ↓
Traffic Forwarding (A → B → C → G, per-hop AEAD unwrap, circuit-owned sequence)
    ↓
Capability Authority (governance → issuer → authorization → capability →
                      revocation; durable persistence; semantic validation;
                      conformance vectors)
```

## Crate layout

| Crate | Layer | Responsibility |
|---|---|---|
| `snp-cbor` | — | Canonical CBOR per RFC 8949 §4.2.1 |
| `snp-crypto` | L1 | Ed25519, X25519, SHA-256, HKDF, ChaCha20-Poly1305 |
| `snp-object` | L2 | Chunking, Merkle (RFC 6962), CAS, Manifest |
| `snp-identity` | L1 | Four-way identity split, NodeId, DeviceCert, NodeDescriptor |
| `snp-link` | L8 | Link abstraction, SNP-IK/0.1 handshake, directional AEAD |
| `snp-discovery` | L4 | Link-local beacons, descriptor store, HAVE vectors |
| `snp-sync` | L5 | Anti-entropy, store-carry-forward, Mode A bundle custody |
| `snp-routing` | L6 | Progressive next-hop route discovery, path validation |
| `snp-circuit` | L6/L7 | Circuit abstraction, E2E AEAD, replay windows |
| `snp-gateway` | L7 | Internet gateway, egress policy, Mode A/B/C |
| `snp-civic` | L11 | Contribution proofs, value function (NOT settlement) |
| `snp-node` | — | The reference daemon binary that ties it all together |
| `snp-conformance` | — | Independent conformance harness |

## Build

```sh
cargo build --workspace
```

## Test

```sh
cargo test --workspace
```

The test suite includes:
- Unit tests per crate
- Adversarial security tests (`n19_adversarial.rs`, `n19_security.rs`)
- Topology tests (`n211_topology.rs`) — RemoteNodeHint vs AuthenticatedNodeRecord
- Routing tests (`n212_routing.rs`) — progressive route discovery
- Circuit tests (`n213_circuits.rs`, `n214_distributed_circuits.rs`)
- Traffic forwarding tests (`n215_traffic_forwarding.rs`)
- Capability authority tests (`n24_capability_authority.rs` — 54 tests)
- Conformance vectors (`n24_conformance_vectors.rs` — 12 frozen vectors)

## Run conformance suite

```sh
cargo run -p snp-node -- conformance
```

## Tooling

- `cargo fmt` — formatting (config in `.rustfmt.toml`)
- `cargo clippy` — lints (config in `clippy.toml`)
- `cargo test --workspace` — unit tests + integration tests
- `cargo run -p snp-node -- conformance` — conformance vectors

## Invariants enforced (per 06-CONFORMANCE-AND-AI-MODEL §B3)

Every crate MUST enforce the protocol invariants:

- **I1** — All signed structures use SNP-CBOR with length-first key ordering
- **I2** — Every signature is over `SIG_CONTEXT ‖ CBOR(payload)`
- **I3** — Ed25519 uses raw 32-byte public keys on the wire
- **I4** — `NodeId = SHA-256("SNP/0.1 node\0" ‖ pk)`, never the bare key
- **I5** — All wire structures use canonical CBOR; non-canonical input rejected
- **I6** — Every cross-layer message carries its layer's wire format

The conformance suite at `/public/conformance/vectors/` is the source of truth
for these invariants.

## License

Dual-licensed under MIT OR Apache-2.0, matching the Rust ecosystem convention.
