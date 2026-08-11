# Architecture Decision Records (ADR)

This directory holds every Tier 0, Tier 1, and Tier 2 architectural
decision in ShareNet 2.0. It is the audit trail that lets a third
agent — human or AI — reconstruct *why* the codebase looks the way it
does, without having to read the git log.

## Process

ADRs follow the process defined in
[`public/spec/06-CONFORMANCE-AND-AI-MODEL.md` §B6](../../spec/06-CONFORMANCE-AND-AI-MODEL.md):

```
docs/adr/NNNN-title.md
  Status: proposed | accepted | rejected | superseded
  Tier affected: 0 | 1 | 2
  Change · Rationale · Alternatives · Conformance impact
  · Migration path · Human reviewer (required for Tier 0/1)
```

### Tier definitions (06 §B2)

| Tier | Layer | Change requires |
|---|---|---|
| 0 | Golden vectors (`conformance/vectors/`) | ADR + **named human approval** + vector regeneration |
| 1 | Normative spec (`spec/`) | ADR + **named human approval** + protocol version bump |
| 2 | API contracts (`reference/`, `android/` interfaces) | ADR + owning agent + one reviewer |
| 3 | Implementation (language, structure, style) | No ADR — free choice |

**Conflict resolution is mechanical: Tier 0 beats Tier 1 beats Tier 2
beats Tier 3.** If an agent believes a vector is wrong, it files an ADR;
it does not change the vector.

### Status values

- **proposed** — drafted, awaiting review. NOT enforceable; CI does not
  treat the proposed change as the truth.
- **accepted** — reviewed and approved. For Tier 0/1, the Human reviewer
  field MUST be filled. An accepted Tier 0/1 ADR with a blank reviewer
  field is a CI failure.
- **rejected** — reviewed and turned down. Kept in the directory so the
  same proposal does not get re-litigated next month.
- **superseded** — replaced by a later ADR. The superseding ADR is
  named in the front matter.

### File naming

`NNNN-kebab-case-title.md`, zero-padded four digits, starting at `0001`.
The template lives at [`0000-template.md`](./0000-template.md).

## Index

| ADR | Title | Tier | Status | One-line summary |
|---|---|---|---|---|
| [0001](./0001-typescript-reference-language.md) | TypeScript as reference implementation language | 2 | accepted (sandbox-only caveat) | The architecture specifies Rust; this sandbox uses TypeScript because the conformance vectors (language-independent JSON) are the constraint, not the language. A Rust reference must be built for production and must produce byte-identical vectors. |
| [0002](./0002-noble-crypto-libraries.md) | Use @noble/ed25519 + @noble/curves for Ed25519/X25519 | 2 | accepted | The audit (§3.1) found `TinkCryptoProvider` derives public keys as `sha256(handle.toString())`. We use the @noble family — raw 32-byte Ed25519 keys, no KeysetHandle indirection — so signatures made here verify against RFC 8032 test vectors and against any conformant implementation. |
| [0003](./0003-simplified-noise-ik.md) | Simplified Noise_IK handshake structure | 1 | superseded by ADR-0006 | The spec mandates Noise_IK (§7.2) and the threat model (§4.2) says "use a vetted library; do not hand-roll." This ADR documented the sandbox's *structural* simplification (signed-descriptor exchange + DH-derived keys) and called it "simplified Noise_IK." **Superseded by ADR-0006** — the hardening audit found this framing misleading; the handshake is now explicitly named SNP-IK/0.1, not Noise_IK. |
| [0004](./0004-mode-a-response-as-cas-object.md) | Mode A response body is a content-addressed object | 1 | accepted | Per 02-PROTOCOL-SPEC.md §8.2, the Mode A `TransitResponse.body` is delivered as an `ObjectId` (Merkle root) referencing a Class A object in the L2 CAS — not as inline bytes. This reuses chunking, Merkle verification, resumable transfer, and multi-source fetch from `core-content` for free. |
| [0005](./0005-sublinear-volume-factor.md) | Sub-linear volume factor for Civic Points | 1 | accepted | Audit finding R7: Civic Points were paid per byte, incentivising manufactured traffic. We adopt `volume_factor = log₂(1 + MiB)` (05-CIVIC-CONTENT-CONSISTENCY.md §A5) so doubling volume does not double pay, breaking the "more bytes = more money" farming incentive. |
| [0006](./0006-snp-ik-custom-handshake.md) | Rename sandbox handshake to SNP-IK/0.1 (a custom authenticated-DH construction, NOT Noise_IK) | 1 | accepted (rename decision); 🟡 PENDING human review for production use of SNP-IK/0.1 | Hardening audit Blocker B: the sandbox handshake was described as "simplified Noise_IK" but performs three DH ops + HKDF without Noise's chaining key, transcript hash, or prologue. Renamed to SNP-IK/0.1 — a custom construction defined honestly. The spec's Noise_IK mandate remains the production target; SNP-IK/0.1 is the sandbox's honest name for what it actually does today. Supersedes ADR-0003. Note: ADR-0006's migration section anticipated "ADR-0007" as the future vetted-Noise_IK-library ADR; that number was reassigned to ADR-0007 (civic reputation). The Noise_IK library ADR will be filed at the next free number (ADR-0009+). |
| [0007](./0007-civic-reputation-spec-drift.md) | Fix civic reputationFactor to match spec range [0,1] (was [0.5,1.0]) | 1 | accepted (provisional — human review PENDING before N8 Civic Points milestone) | Hardening audit Blocker E: `reputationFactor` returned [0.5, 1.0] but spec 05 §A5 says reputation ∈ [0,1]. This was a protocol semantic change made in implementation without an ADR — exactly the drift the foundation is supposed to prevent. Fixed the implementation to match the spec: `reputationFactor(score) = score/1000` clamped to [0,1]. Vector `civic-value-computation-transit-interactive` regenerated (expected points 5679 → 5048). The bootstrapping concern (new nodes getting zeroed) is real but must be solved at the spec level (a future bootstrap-bonus ADR), not by silently changing the formula in code. |
| [0008](./0008-gateway-dns-rebinding-defence.md) | Gateway egress DNS-rebinding defence (resolve → validate → pin → connect) | 1 | proposed (🟡 PENDING human review — mandatory before N5 gateway implementation) | Hardening audit Blocker F: `isPrivateDestination` checks the hostname but does NOT resolve DNS. A URL like `http://evil.com` (which resolves to 192.168.1.1) would pass the hostname check but still be an SSRF pivot. This ADR specifies the gateway egress flow as: URL → canonicalize → resolve DNS → validate EVERY resolved address against isPrivateDestination → PIN the validated address → connect specifically to that address (not re-resolve) → validate redirects (re-run the full flow for each redirect) → revalidate as necessary. The key invariant: the gateway connects to the IP it validated, not to a fresh DNS resolution. Closes the TOCTOU window that DNS rebinding exploits. |

## How to file a new ADR

1. Copy `0000-template.md` to `NNNN-<kebab-title>.md` (next free number).
2. Fill every section. Do not leave "Context" or "Conformance impact"
   empty — those are the sections that justify the ADR's existence.
3. Set status to `proposed`.
4. For Tier 0/1: request human review. The ADR stays `proposed` until a
   named human signs the Human reviewer field.
5. For Tier 2: the owning agent and one other reviewer approve in PR.
6. Update this README's index table with a one-line summary.
7. If the ADR adds, removes, or regenerates any conformance vector,
   update `conformance/SPEC-COVERAGE.md` in the same PR. CI checks
   that every normative MUST still has ≥1 vector after the change.

## What does NOT need an ADR

- Tier 3 changes (language choice within an implementation, internal
  refactors, test fixtures, naming).
- Bug fixes that do not change a wire format, an interface signature,
  or a frozen constant.
- Documentation updates that do not introduce a normative claim.

When in doubt, file the ADR. A redundant ADR costs a paragraph; a silent
Tier 1 change costs the next interop failure.
