# ShareNet — Architecture Specification Package

**Status:** Live specification. Implementation authority: `reference/snp-node/src/node/`.

This package is the **frozen normative specification** for ShareNet 2.0.
The Rust reference implementation at `reference/` is the executable authority;
conformance vectors at `public/conformance/` are the golden vectors.

---

## Read in this order

| # | Document | Covers |
|---|---|---|
| 0 | `00-AUDIT.md` | Historical gap analysis of the pre-redesign repository (commit `c4266d5`). Findings describe the OLD repo state; preserved as context for the architecture decisions. |
| 1 | `01-ARCHITECTURE.md` | Revised thesis, 12-layer model, traffic classes, Internet Modes A/B/C |
| 2 | `02-PROTOCOL-SPEC.md` | SNP/0.1 wire spec, node model, routing, circuits |
| 3 | `03-PLATFORM-MATRIX.md` | What each platform actually permits |
| 4 | `04-THREAT-MODEL.md` | 15 threats, privacy analysis, AI/human review boundary |
| 5 | `05-CIVIC-CONTENT-CONSISTENCY.md` | Civic Points, content as capability, consistency classes |
| 6 | `06-CONFORMANCE-AND-AI-MODEL.md` | Golden vectors, invariants, module ownership |
| 7 | `07-MIGRATION-AND-ROADMAP.md` | Migration, module disposition, repo layout, roadmap |
| 8 | `08-circuits.md` | Circuit establishment, traffic forwarding, packet format |

---

## Architecture authority hierarchy

```
Frozen specification (this package)
    ↓
Golden conformance vectors (public/conformance/)
    ↓
Rust reference implementation (reference/)
    ↓
Platform implementations (Kotlin, Python, Swift — future)
```

The frozen architecture is normative. The Rust reference is the executable
authority. Platform implementations must match byte-for-byte.

---

## Current implementation status (at commit `f7bd6ec`)

The network core is **implemented and tested** in the Rust reference:

- ✅ Node identity (Ed25519 + NodeId derivation)
- ✅ Signed node advertisements with sequence + expiry
- ✅ Link-layer transport (TCP + SNP-IK/0.1 handshake, directional AEAD)
- ✅ Topology (RemoteNodeHint ≠ AuthenticatedNodeRecord; `direct_gateways()` ≠ `gateway_hints()`)
- ✅ Propagation freshness (propagation_sequence, replay/stale rejection)
- ✅ Progressive multi-hop route discovery (destination → target auth → next-hop → path validation → proposal → acceptance → committed route)
- ✅ Distributed circuit establishment (CircuitSetup → relay handshake → X25519 proof → ActiveCircuit)
- ✅ Per-hop encrypted traffic forwarding (A → B → C → G, circuit-owned sequence)
- ✅ Capability authority subsystem (governance → issuer → authorization → revocation; durable persistence; semantic validation; 12 frozen conformance vectors)

### What is NOT yet done

- 🔴 Real Internet gateway service (Mode A end-to-end through real external Internet)
- 🔴 Route recovery (link failure → new route)
- 🔴 Live circuit key rotation
- 🔴 Multi-process Linux network harness (separate node processes, not shared memory)
- 🔴 Android VPN/TUN adapter
- 🔴 Contribution proofs + Civic Points closed-loop settlement

See `07-MIGRATION-AND-ROADMAP.md` for the closure roadmap.

---

## Historical context

The "five findings" in `00-AUDIT.md` described the repository at commit
`c4266d5` (pre-redesign). They are preserved as historical context for
the architecture decisions, but the negative findings (broken crypto,
fake golden vectors, no mesh) **no longer describe the current repository**.
The Rust reference at `reference/` has real crypto, real conformance
vectors, and a real network stack.

The core architectural judgement remains valid: the content stack is sound,
the network stack needed to be built. That has now been done.
