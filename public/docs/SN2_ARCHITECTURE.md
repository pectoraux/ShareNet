# ShareNet 2.0 — Architecture

**Status:** normative for the 2.0 codebase  
**Supersedes:** `docs/system_architecture_review.md` (the 1.0 document, now archived)  
**Date:** 2026-08-12  

---

## Overview

ShareNet is a delay-tolerant mesh network that redistributes Internet
reachability. A device without direct Internet access reaches the real
Internet by routing through peers that have connectivity. The user runs
ordinary applications — Chrome, WhatsApp, any API — and ShareNet supplies
the network path beneath them.

```
                         INTERNET
                            │
                            ▼
                    ┌──────────────┐
                    │   GATEWAY    │
                    └──────┬───────┘
                           │
                     ShareNet link
                           │
                           ▼
                    ┌──────────────┐
                    │   RELAY      │
                    └──────┬───────┘
                           │
                    ShareNet mesh
                           │
                           ▼
                    ┌──────────────┐
                    │   OFFLINE    │
                    │    CLIENT    │
                    └──────────────┘
```

---

## Repository Structure

```
ShareNet 2.0
│
├── Protocol / Specification          ← public/spec/ (normative, human+Claude owned)
│   ├── 00-AUDIT.md
│   ├── 01-ARCHITECTURE.md
│   ├── 02-PROTOCOL-SPEC.md
│   ├── 03-PLATFORM-MATRIX.md
│   ├── 04-THREAT-MODEL.md
│   ├── 05-CIVIC-CONTENT-CONSISTENCY.md
│   ├── 06-CONFORMANCE-AND-AI-MODEL.md
│   └── 07-MIGRATION-AND-ROADMAP.md
│
├── Conformance Vectors              ← public/conformance/vectors/ (frozen, Tier 0)
│   ├── 01-cbor.json through 15-aead.json
│   └── SPEC-COVERAGE.md
│
├── Reference Implementation         ← src/lib/snp/ (TypeScript, Z.ai owned)
│   ├── cbor.ts, crypto.ts, hashing.ts
│   ├── merkle.ts, chunking.ts, identity.ts
│   ├── manifest.ts, receipts.ts, frames.ts
│   ├── routing.ts, gateway.ts, civic.ts
│   ├── link.ts, discovery.ts, sync.ts
│   └── conformance.ts, integration-tests.ts
│
├── Conformance Verifiers            ← scripts/ (independent consumers)
│   ├── generate-vectors.ts          (TypeScript generator — ONE generator)
│   ├── verify-vectors.ts            (TypeScript independent verifier)
│   └── verify-vectors-python.py     (Python cross-language verifier)
│
├── Rust Conformance Core            ← reference/ (Rust, Z.ai owned)
│   ├── snp-cbor/                    (CBOR — 19/19 vectors verified)
│   ├── snp-crypto/                  (SHA-256, HKDF, Ed25519, AEAD — 25/25)
│   ├── snp-identity/                (NodeId — 6/7)
│   ├── snp-object/                  (Merkle, Gear chunking — 18/18)
│   ├── snp-conformance/             (test harness binary)
│   └── snp-link/, snp-discovery/, snp-sync/, snp-routing/,
│       snp-circuit/, snp-gateway/, snp-civic/, snp-node/  (skeletons)
│
├── Network Runtime                  ← mini-services/mesh-simulator/
│   ├── index.ts                     (orchestrator)
│   └── node.ts                      (Client / Relay / Gateway processes)
│
├── Dashboard                        ← src/app/ (Next.js)
│   ├── page.tsx                     (conformance + integration + mesh dashboard)
│   └── api/                         (conformance, integration-tests, mesh-simulator,
│                                      cross-verify, rust-verify)
│
├── Platform Adapters                ← (future)
│   ├── android/                     (Gemini owned — not yet started)
│   ├── platform/linux/              (Z.ai owned — future)
│   ├── platform/windows/            (Z.ai owned — future)
│   ├── platform/macos/              (Z.ai owned — future)
│   └── platform/ios/                (deferred — requires human entitlement work)
│
├── Economic Layer                   ← (future, human-gated)
│   ├── core-civic/                  (Civic Points value function — implemented in TS)
│   └── backend/                     (settlement — human-gated, not yet started)
│
└── Legacy                           ← android/ (1.0 codebase, preserved per migration plan)
    └── (the original ShareNet Android app — NOT the 2.0 architecture)
```

---

## Ownership

| Component | Owner | Status |
|-----------|-------|--------|
| `public/spec/` | Human + Claude | Complete (8 documents) |
| `public/conformance/vectors/` | Human + Claude | Frozen (138 vectors, 15 suites) |
| `src/lib/snp/` (TypeScript reference) | Z.ai | Complete (16 modules) |
| `scripts/verify-vectors-python.py` | Z.ai | Complete (106/138 independent) |
| `reference/` (Rust conformance core) | Z.ai | 72/138 independent, 0 disagreements |
| `mini-services/mesh-simulator/` | Z.ai | Complete (3-process TCP mesh, real Internet egress) |
| `src/app/` (Dashboard) | Z.ai | Complete |
| `android/` (2.0) | Gemini | NOT YET STARTED |
| `platform/linux/` | Z.ai | NOT YET STARTED |
| `platform/ios/` | Deferred | Needs human entitlement work |
| `backend/` (settlement) | Human-gated | NOT YET STARTED |
| `card-applet/` | Human-only | Unchanged from 1.0 |

---

## Three-Way Conformance

The protocol primitives are independently verified across three languages
with zero disagreements:

| Suite | TypeScript | Python | Rust |
|-------|-----------|--------|------|
| CBOR | 19/19 | 19/19 | 19/19 |
| SHA-256 / Hashing | 17/17 | 17/17 | 17/17 |
| Ed25519 / Identity | 7/7 | 6/7 | 6/7 |
| HKDF | 1/1 | 1/1 | 1/1 |
| AEAD (ChaCha20-Poly1305) | 7/7 | 7/7 | 7/7 |
| Merkle (RFC 6962) | 12/12 | 12/12 | 12/12 |
| Gear Chunking | 6/6 | 1/6 | 6/6 |

**Zero disagreements.** The original ShareNet CBOR bug (Kotlin vs Python
disagreeing on key ordering) is now definitively impossible.

---

## ADRs

| # | Title | Status |
|---|-------|--------|
| 0001 | TypeScript as reference language (sandbox) | accepted |
| 0002 | @noble/ed25519 + @noble/curves | accepted |
| 0003 | Simplified Noise_IK | superseded by ADR-0006 |
| 0004 | Mode A response as CAS object | accepted |
| 0005 | Sub-linear volume factor for Civic Points | accepted |
| 0006 | SNP-IK/0.1 custom handshake (NOT Noise_IK) | accepted |
| 0007 | Civic reputation factor spec-drift fix | accepted |
| 0008 | Gateway DNS rebinding defence | proposed |
| 0009 | Response object hashing semantics | accepted |
| 0010 | SplitMix64 deterministic stream spec | accepted |

---

## Milestone Status

| Milestone | Status | Evidence |
|-----------|--------|----------|
| N0 — Truth & specification | ✅ Complete | 8 spec documents |
| N1 — Conformance foundation | ✅ Complete | 138 vectors, 15 suites |
| N1.5 — Foundation hardening | ✅ Complete | AEAD, SNP-IK/0.1, durable seq floor |
| N1.6 — Adversarial conformance | ✅ Complete | Honest classification, SSRF defence |
| N1.7 — Rust conformance core | ✅ Complete | 72/138 Rust, 0 disagreements |
| N1.7.1 — Spec findings | ✅ Complete | Merkle streaming fix, ADR-0010 |
| N1.8 — Rust minimal Internet bridge | 🟡 In progress | Client → Relay → Gateway → Internet |
| N2 — Crypto correction | ✅ Complete | (folded into N1.5) |
| N3 — Reference node | 🟡 In progress | (Rust conformance core done; networking next) |
| N4 — Routing | 🟡 Partial | (TS implementation + integration tests) |
| N5 — Gateway + Mode A | 🟡 Partial | (TS mesh simulator with real Internet egress) |
| N6 — Android port | ⛔ Not started | (Gemini — blocked until N1.8 complete) |
| N7 — Modes B and C | ⛔ Not started | |
| N8 — Civic Points | ⛔ Not started | (human-gated) |

---

## North-Star Acceptance Test

> An Android phone with no Internet access, running unmodified Chrome, reaches
> the real Internet through a ShareNet gateway.

This is Mode C (transparent Internet). The path to it:

```
N1.8 (Rust Internet bridge) → N3 (Rust node) → N4 (routing) → N5 (gateway)
    → N6 (Android) → N7 (VpnService / TUN) → unmodified Chrome
```

---

## Key Invariants

1. **Protocol primitives are language-independent** — proven by TS/Python/Rust three-way agreement
2. **Vectors are frozen** — committed JSON, not regenerated per implementation
3. **No implementation invents protocol semantics** — the spec is the authority
4. **Conformance is executable** — not prose, not comments, not aspirations
5. **Security stubs throw, never return permissive defaults** — invariant I20
6. **Class B transit payloads are never inspected by relays** — invariant I8
7. **Revocation is monotone** — invariant I15
8. **Civic Points are never minted by the claimant** — invariant I13

---

## References

- Architecture package: `public/spec/00-AUDIT.md` through `07-MIGRATION-AND-ROADMAP.md`
- Conformance coverage: `public/conformance/SPEC-COVERAGE.md`
- ADRs: `public/docs/adr/`
- Security policy: `public/docs/SECURITY.md`
- Worklog: `worklog.md`
