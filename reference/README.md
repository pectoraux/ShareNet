# ShareNet 2.0 — Rust Reference Implementation

This directory is the **Rust reference implementation** of ShareNet 2.0, per
`/public/spec/07-MIGRATION-AND-ROADMAP.md` §3 (Deliverable 22) and §2.4.

> *"reference/ is Rust on Linux — no platform obstacles, so protocol bugs
> surface as protocol bugs."* — 07-MIGRATION-AND-ROADMAP §3

## Authority

This implementation is the **authoritative** reference for ShareNet 2.0. When
complete, conformance vectors generated here are the golden vectors; every
other implementation (TypeScript, Kotlin, Python) must match byte-for-byte.

## Status: SKELETON

The crates in this workspace are **stubs**. The directory structure,
`Cargo.toml` workspace, public API skeletons, and build configuration are in
place; the actual protocol logic is not yet implemented. Each `lib.rs` declares
its major public types and functions with `todo!()` bodies.

The **TypeScript implementation in `/src/lib/snp/`** is the sandbox reference
per ADR-0001 (`/public/docs/adr/0001-typescript-reference-language.md`). It
remains authoritative for vector generation until this Rust workspace reaches
parity. At that point Rust regenerates the vectors and the TypeScript
implementation must match byte-for-byte.

The skeleton exists to prove the repository structure required by 07 §3 is in
place; a future Rust implementation agent will fill in the `todo!()` bodies.

## Crate layout

The 12-crate layout mirrors the layer model in `01-ARCHITECTURE.md`:

| Crate | Layer | Responsibility | TypeScript equivalent |
|---|---|---|---|
| `snp-cbor` | — | Canonical CBOR per RFC 8949 §4.2.1 | `cbor.ts` |
| `snp-crypto` | L1 | Ed25519, X25519, SHA-256, HKDF, ChaCha20-Poly1305 | `crypto.ts` + `hashing.ts` |
| `snp-object` | L2 | Chunking, Merkle (RFC 6962), CAS, Manifest | `chunking.ts` + `merkle.ts` + `manifest.ts` |
| `snp-identity` | L1 | Four-way identity split, NodeId, DeviceCert, NodeDescriptor | `identity.ts` |
| `snp-link` | L8 | Link abstraction, Noise_IK handshake structure | `link.ts` + `frames.ts` |
| `snp-discovery` | L4 | Link-local beacons, descriptor store, HAVE vectors | `discovery.ts` |
| `snp-sync` | L5 | Anti-entropy, store-carry-forward, Mode A bundle custody | `sync.ts` |
| `snp-routing` | L6 | Gateway-anchored routing, path-vector, metrics, migration | `routing.ts` |
| `snp-circuit` | L6/L7 | Circuit abstraction, E2E AEAD, replay windows | (new) |
| `snp-gateway` | L7 | Internet gateway, egress policy, Mode A/B/C | `gateway.ts` |
| `snp-civic` | L11 | Contribution proofs, value function (NOT settlement) | `civic.ts` + `receipts.ts` |
| `snp-node` | — | The daemon binary that ties it all together | (new) |

## Build

```sh
cargo build --workspace
```

## Test

```sh
cargo test --workspace
```

## Run conformance suite

```sh
cargo run -p snp-node -- conformance
```

Other daemon subcommands (also skeletons):

```sh
cargo run -p snp-node -- run        # start the node daemon
cargo run -p snp-node -- keygen     # generate a new node identity
cargo run -p snp-node -- discover   # scan for peers
```

## Tooling

- `cargo fmt` — formatting (config in `.rustfmt.toml`)
- `cargo clippy` — lints (config in `clippy.toml`)
- `cargo test --workspace` — unit tests
- `cargo run -p snp-node -- conformance` — conformance vectors

## Invariants enforced (per 06-CONFORMANCE-AND-AI-MODEL §B3)

When complete, every crate MUST enforce the protocol invariants:

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
