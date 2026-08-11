# ShareNet — Architecture Redesign Package

**Prepared by:** Principal System Architect (Claude)
**Audited commit:** `pectoraux/ShareNet` @ `c4266d5`
**Date:** 2026-08-11
**Status:** architecture phase — no implementation

---

## Read in this order

| # | Document | Covers |
|---|---|---|
| 0 | `00-AUDIT.md` | **Part 1** — gap analysis of the real repository, with file references and two executed proofs |
| 1 | `01-ARCHITECTURE.md` | **Parts 2, 3** — revised thesis, 12-layer model, traffic classes, Internet Modes A/B/C |
| 2 | `02-PROTOCOL-SPEC.md` | **Parts 4, 5, 6, 7** — SNP/0.1 wire spec, node model, routing, circuits |
| 3 | `03-PLATFORM-MATRIX.md` | **Part 13** — what each platform actually permits |
| 4 | `04-THREAT-MODEL.md` | **Parts 7, 14** — 15 threats, privacy analysis, AI/human review boundary |
| 5 | `05-CIVIC-CONTENT-CONSISTENCY.md` | **Parts 8, 9, 10** — Civic Points, content as capability, consistency classes |
| 6 | `06-CONFORMANCE-AND-AI-MODEL.md` | **Parts 11, 12** — golden vectors, invariants, module ownership |
| 7 | `07-MIGRATION-AND-ROADMAP.md` | **Part 15 (16–23)** — migration, module disposition, repo layout, roadmap, work division |

---

## The five findings that drive everything

1. **The production crypto provider does not work.** `TinkCryptoProvider` derives "Ed25519 public keys" as `sha256(handle.toString())`, its `ephemeralHandleFromPrivate` signs with an unrelated random key (its own comment admits this), and `createRawVerifyHandle` throws unconditionally — so **verification of any remote peer's key always returns `false`**. `KeystoreCryptoProvider`, the provider actually wired into the production factory, is self-documented as "a **stub** for M0" and delegates to it.

2. **The golden vectors are placeholders and the README claim is false.** `cbor_hex` is `sha256("cbor-manifest-0")`; all 20 signatures are zero bytes; the referenced Kotlin test resource does not exist; the regeneration script does not exist. Verified by running the repo's own encoder: stored 32 bytes vs actual 241 bytes. **M0 — "blocks everything" — was never completed**, which is why findings 1 and 3 survived.

3. **The two CBOR implementations produce different bytes.** Kotlin sorts map keys lexicographically; Python sorts by encoded key (RFC 8949, length-first). Executed on the real `Contribution` field set, the orderings are completely different. Cross-platform signatures cannot verify.

4. **There is no mesh.** No routing, no gateway, no relay, no multi-hop, no tunnel anywhere in the repository. The claimed gossip protocol sends the literal ASCII string `"HAVE:"` and nothing ever reads `transport.incoming`. `Transport`'s peer identifier is documented as "issued by Nearby Connections" — a platform API defining protocol semantics.

5. **Civic Points can be minted by claiming.** `pointsForBridging(bytes)` has **no proof object at all** — a node calls the function and mints points. Fraud controls are in-memory and reset on restart. This is the exact anti-pattern the brief forbids, already in the code.

---

## The core architectural judgement

The repository has a **clean seam**: the content stack (chunking, Merkle, CAS, catalog trust model) is genuinely good and worth preserving; the network stack does not exist and must be built. The redesign therefore **preserves the entire content layer and replaces the entire network layer** — an evolution, not a rewrite.

The new thesis is delivered by inserting a real bearer beneath the preserved content services:

```
apps → virtual network (L9) → gateway (L7) → routing (L6) → sync (L5)
     → discovery (L4) → trust (L3) → object (L2) → identity (L1) → links (L8)
```

with a **hard split between Class A content traffic** (mesh-understood, cached, content-addressed) **and Class B transit traffic** (opaque ciphertext, never cached, circuit-addressed).

---

## Three things this package refuses to claim

1. **iOS cannot be an Internet gateway or a reliable relay.** `NEPacketTunnelProvider` sends *the device's own* traffic to a remote server; it is not a mechanism for egressing others' traffic, and background execution cannot sustain relaying. An all-iOS neighbourhood is a non-functional ShareNet. iOS is a consumer of the mesh.

2. **Live TCP connections cannot survive gateway migration.** The origin-side socket lives on the gateway. When it dies, that connection dies. What survives: the virtual interface stays up, the client's virtual IP is stable, new connections succeed immediately via another gateway, and Mode A bundles complete regardless.

3. **ShareNet is not an anonymity network.** The first-hop relay knows who you are; the gateway knows where you are going. The design goal is that no single node knows both — achievable in a healthy topology, **false in a sparse one**, which the implementation must detect and disclose. And in Mode A with `GATEWAY_PLAINTEXT`, the gateway operator reads everything — which is why that field is mandatory and per-request.

---

## What must happen first

**No implementation work begins until `spec/` and `conformance/` exist.**

The current repository is what happens when 100 Kotlin files are written against prose instead of executable vectors: plausible structure, KDoc on every class, threat matrices, milestone tables — and a crypto layer that cannot verify a signature. Comments repeatedly describe intended behaviour while the adjacent code does something else, and in several places the code **honestly documents its own incorrectness** in a comment that no test ever escalated into a failure.

With three AI agents about to work in parallel, golden vectors are not a testing artefact. They are the only thing that will hold the protocol together.
