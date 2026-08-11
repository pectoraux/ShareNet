# Security Policy

> **Per `07-MIGRATION-AND-ROADMAP.md` §1.1 Phase 0:**
>
> > Add a `SECURITY.md` stating plainly that no code in the repository
> > is production-ready.

## Status: PRE-PRODUCTION REFERENCE IMPLEMENTATION

**No code in this repository is production-ready.**

This repository is a pre-production reference implementation of the
ShareNet 2.0 protocol. It exists to specify the protocol
(`public/spec/`) and to provide executable conformance vectors
(`public/conformance/vectors/`) that any implementation — regardless
of language or platform — can be checked against. The TypeScript
source under `src/lib/snp/` is the *sandbox reference* that generates
those vectors; it is not the production reference (which per
`07-MIGRATION-AND-ROADMAP.md` §3 is Rust on Linux — see
[ADR-0001](./adr/0001-typescript-reference-language.md)).

**Do not deploy this code. Do not put real keys into it. Do not route
real traffic through it. Do not depend on it for any security
property.**

## What has NOT been audited

- **The crypto has not been audited by a third party.** The @noble
  libraries (`@noble/ed25519`, `@noble/curves`, `@noble/hashes`) were
  audited by Trail of Bits in 2022 at the *library* level; this
  repository's *use of* those libraries has not been audited. See
  [ADR-0002](./adr/0002-noble-crypto-libraries.md) for the library
  selection rationale.
- **The simplified Noise_IK handshake is NOT production-safe.** Per
  [ADR-0003](./adr/0003-simplified-noise-ik.md) (status: `proposed`,
  🟡 mandatory human security review per `04-THREAT-MODEL.md` §4.2),
  the sandbox L8 link layer implements a *simplified* handshake
  structure, not full Noise_IK. Specifically:
  - The initiator's static key (`rendezvousPub`) is sent in the clear
    inside the signed descriptor. In real Noise_IK, it is encrypted
    under the responder's static key.
  - There is **no post-handshake AEAD**. Frames are sent as raw CBOR
    on the underlying `HandshakeChannel`. The derived `linkKeys` are
    returned to the caller, who MUST apply ChaCha20-Poly1305 at a
    higher layer — but the sandbox does not yet do this.
  - There is no transcript hash binding.
- **The Civic Points value function is economic policy, not protocol
  semantics.** Per `06-CONFORMANCE-AND-AI-MODEL.md` §B5, Civic Point
  parameters are **Human-only** (🔴). The sandbox's choice of
  `log₂(1 + MiB)` for the volume factor (see
  [ADR-0005](./adr/0005-sublinear-volume-factor.md)) is spec-endorsed
  but not production-authoritative until a human reviewer signs off.
- **No timing-attack or side-channel analysis has been performed.**
  The TypeScript sandbox runs on the V8 JIT, which does not provide
  the timing guarantees of Rust or C. @noble's constant-time field
  arithmetic helps, but the sandbox is not suitable for production
  key storage or high-throughput signing.

## What the conformance suite catches (and what it does NOT)

The conformance suite (`public/conformance/vectors/`, 14 suites, ~130
vectors) is the precondition for letting any second agent touch the
protocol. It catches:

- ✅ **Encoding bugs.** CBOR canonical ordering, shortest-form ints,
  byte vs text strings, duplicate key rejection, trailing byte
  rejection. (Suites 01, 14.)
- ✅ **Hash / KDF bugs.** SHA-256, HKDF-SHA256, NodeId derivation, all
  12 SIG_CONTEXT domain separators. (Suite 02.)
- ✅ **Signature interop bugs.** Ed25519 sign/verify with raw 32-byte
  keys; remote-key verification; cross-context rejection; wrong-key
  rejection; wrong-length-signature rejection. (Suites 03, 14.)
- ✅ **Merkle construction bugs.** RFC 6962 leaf/node prefixes,
  odd-node non-duplication (CVE-2012-2459 pattern), inclusion proofs,
  empty tree. (Suite 05.)
- ✅ **Chunking drift.** Frozen Gear table, boundary cases, 5 MiB
  deterministic stream. (Suite 04.)
- ✅ **Manifest binding bugs.** `chunkCount` mismatch rejection,
  tamper rejection. (Suites 06, 14.)
- ✅ **Receipt forgery.** Cross-type replay rejection, claimant-
  signed-receipt rejection. (Suites 07, 14.)
- ✅ **Frame TTL / class / padding bugs.** TTL decrement, TTL=0 drop,
  class discrimination, padding buckets. (Suites 08, 14.)
- ✅ **Capability matrix violations.** iOS + MESH_RELAY rejection.
  (Suites 09, 14.)
- ✅ **Routing loop / seq regression bugs.** Path-vector loop
  detection, seq-regression rejection. (Suites 10, 14.)
- ✅ **Gateway SSRF.** RFC 1918 / loopback / link-local / multicast
  egress rejection (12 negative vectors + 4 public allow-list).
  (Suites 11, 14.)
- ✅ **Civic Points farming.** Sub-linear volume factor, diversity
  collapse, holdback. (Suite 12.)
- ✅ **Revocation reversal.** Monotone un-revoke rejection, CRITICAL
  priority, seq monotonicity. (Suites 13, 14.)

The conformance suite does **NOT** catch:

- ❌ **Timing attacks.** JS engine timing is not deterministic enough
  to test for constant-time behavior. A production implementation in
  Rust or C must be independently audited for timing leaks.
- ❌ **Side-channel attacks.** Power analysis, EM emanation, cache
  timing, branch prediction — all out of scope for a software
  conformance suite.
- ❌ **Implementation-level vulnerabilities.** Memory safety bugs
  (not applicable to TypeScript, but applicable to any C/C++/unsafe-
  Rust port), integer overflow in non-vector code paths, TOCTOU
  races, unsafe deserialization of untrusted input outside the
  conformance vector inputs.
- ❌ **Key storage security.** The sandbox stores keys in process
  memory. Production key storage (Android Keystore, iOS Secure
  Enclave, TPM, HSM) is out of scope.
- ❌ **Network-level attacks.** TCP reset injection, traffic analysis,
  global passive adversary correlation, denial of service — these are
  addressed (partially, honestly) in `04-THREAT-MODEL.md`, not in the
  conformance suite.
- ❌ **Human-review-gated items.** Per `04-THREAT-MODEL.md` §4.2, the
  following are 🟡 AI-implementable but require mandatory human
  security review before merge to production:
  - Noise_IK handshake integration (see ADR-0003).
  - AEAD nonce construction and rekey scheduling.
  - Replay-window logic.
  - Key derivation and NodeId derivation.
  - Signature verification call sites.
  - Gateway egress policy enforcement (especially RFC 1918 blocking).
  - Rate limiting and quota enforcement.
  - Revocation propagation and enforcement.
  - Reputation calculation.
  - Route metric validation against measurement.

## Reporting a vulnerability

**Do not report vulnerabilities against this repository as if it were
production software.** It is not. If you find a bug, file a GitHub
issue or open a PR — the repository is open.

If, despite this warning, you have deployed this code in production
and found a vulnerability, contact:

- **Email:** `security@sharenet.example` (placeholder — replace
  before any real deployment)
- **PGP key:** (placeholder — generate and publish before any real
  deployment)

Do not expect a rapid response. Do not expect a fix in this
repository. The fix is "do not deploy this code in production."

## What you SHOULD do with this repository

- ✅ **Read the spec.** `public/spec/00-AUDIT.md` through
  `07-MIGRATION-AND-ROADMAP.md` define the protocol.
- ✅ **Run the conformance suite against your implementation.**
  Consume the vectors in `public/conformance/vectors/*.json` and
  verify your implementation produces the same `expected` outputs.
  File an ADR if your implementation disagrees with a vector.
- ✅ **Use the TypeScript source as a reference for behavior.** If
  you are unsure how a structure should be encoded, read
  `src/lib/snp/cbor.ts` and the corresponding conformance vector.
- ✅ **Use the integration-tests API route (`/api/integration-tests`)
  as a live demo.** It exercises the full stack end-to-end (CBOR →
  crypto → identity → handshake → routing → gateway → civic points →
  revocation) and reports pass/fail per scenario.

## What you should NOT do with this repository

- ❌ **Do not deploy it.**
- ❌ **Do not put real Ed25519 keys into it.** The sandbox's key
  management is `Uint8Array` in process memory. There is no HSM, no
  Keystore, no Secure Enclave.
- ❌ **Do not route real traffic through it.** The L8 link layer
  (ADR-0003) does not provide post-handshake AEAD. The L7 gateway
  layer is conformance-tested for egress policy but is not hardened
  against real Internet traffic.
- ❌ **Do not depend on the simplified Noise_IK for any security
  property.** It provides peer authentication and NodeId binding but
  not confidentiality (no AEAD) or full Noise_IK downgrade
  resistance.
- ❌ **Do not trust the Civic Points value function for real economic
  decisions.** It is spec-endorsed but not human-approved for
  production (ADR-0005).
- ❌ **Do not assume the conformance suite catches all bugs.** It
  catches encoding, verification, and MUST-REJECT bugs. It does not
  catch timing, side-channel, or implementation-level vulnerabilities
  (see above).

## Roadmap to production-ready

Per `07-MIGRATION-AND-ROADMAP.md` §1.2, the path to production is:

1. **Phase 0 (this repository):** Spec + conformance vectors + ADR
   process + SECURITY.md (this file). ✅ Done.
2. **Phase 3:** Rust reference implementation on Linux. Uses
   `ed25519-dalek`, `sha2`, `hkdf`, `snow` (Noise_IK), `rand_core`.
   Regenerates vectors; must match the TypeScript vectors
   byte-for-byte (ADR-0001).
3. **Independent security audit** (per `07-MIGRATION-AND-ROADMAP.md`
   §5: "Security audit — independent human, before N8 ships").
4. **N8 (Civic Points)** is 🔴 HUMAN-GATED (per §4 of the roadmap).
   No Civic Points code ships without human security + economic
   review.

Until steps 2–4 are complete, this repository remains a
pre-production reference. This SECURITY.md file will be updated when
the status changes.

## ADRs referenced by this policy

- [ADR-0001](./adr/0001-typescript-reference-language.md) — TypeScript
  as sandbox reference language (production stays Rust).
- [ADR-0002](./adr/0002-noble-crypto-libraries.md) — @noble libraries
  for Ed25519/X25519/SHA-256/HKDF (library-level audit only; no
  repository-level audit).
- [ADR-0003](./adr/0003-simplified-noise-ik.md) — Simplified Noise_IK
  handshake (🟡 proposed, NOT production-safe).
- [ADR-0004](./adr/0004-mode-a-response-as-cas-object.md) — Mode A
  response body as content-addressed object (spec-mandated).
- [ADR-0005](./adr/0005-sublinear-volume-factor.md) — Sub-linear
  volume factor for Civic Points (spec-endorsed; human-gated for
  production parameters).
