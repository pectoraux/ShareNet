# ShareNet — Offline-First Mesh Platform

> **Status:** N2.4-I1 complete. Rust reference implementation is the
> authoritative protocol implementation. Android/Kotlin is a future
> platform consumer, not the protocol authority.

ShareNet is a cross-platform, delay-tolerant distributed network for
offline-first content distribution and value transfer. The protocol is
defined by the frozen architecture in `public/spec/` and implemented in
the Rust reference at `reference/`.

## Reference implementation

The **authoritative** implementation is Rust on Linux:

```sh
cd reference
cargo build --workspace
cargo test --workspace
```

See `reference/README.md` for the current implementation status (network
core implemented: identity, discovery, topology, progressive route
discovery, distributed circuits, per-hop encrypted traffic, capability
authority with durable persistence).

## Monorepo layout

```
ShareNet/
├── reference/              Rust reference implementation (14 crates)
├── public/
│   ├── spec/              Frozen normative specification (10 files)
│   ├── docs/adr/          Architecture Decision Records (25 ADRs)
│   └── conformance/       Golden conformance vectors + coverage
├── android/               Android platform consumers (future — NOT the protocol authority)
├── backend/               Python backend (catalog, attest, corpus)
├── docs/                  General documentation
└── sharenetimplementationroadmap.md  (HISTORICAL — superseded by public/spec/)
```

## Architecture authority hierarchy

```
Frozen specification (public/spec/)
    ↓
Golden conformance vectors (public/conformance/)
    ↓
Rust reference implementation (reference/)
    ↓
Platform implementations (Kotlin, Python, Swift — future)
```

The frozen architecture is normative. The Rust reference is the executable
authority. Platform implementations must match byte-for-byte.

## Key architecture documents

| Document | Location | Status |
|----------|----------|--------|
| Protocol specification | `public/spec/02-PROTOCOL-SPEC.md` | Live |
| Architecture | `public/spec/01-ARCHITECTURE.md` | Live |
| Migration & roadmap | `public/spec/07-MIGRATION-AND-ROADMAP.md` | Live |
| Threat model | `public/spec/04-THREAT-MODEL.md` | Live |
| Conformance model | `public/spec/06-CONFORMANCE-AND-AI-MODEL.md` | Live |
| Circuit spec | `public/spec/08-circuits.md` | Live |
| ADR index | `public/docs/adr/README.md` | Live |

## Build the reference

```sh
cd reference
cargo build --workspace
cargo test --workspace
```

## License

Dual-licensed under MIT OR Apache-2.0 (matching the Rust ecosystem
convention). See `reference/README.md`.
