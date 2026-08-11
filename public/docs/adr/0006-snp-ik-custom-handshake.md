---
ADR: 0006
Title: Rename sandbox handshake to SNP-IK/0.1 (a custom authenticated-DH construction, NOT Noise_IK)
Status: accepted (replaces ADR-0003)
Tier affected: 1
Date: 2026-08-12
Deciders:
  - Owning agent: Z.ai (reference/ + L8 link layer)
  - Human reviewer (REQUIRED for production use of SNP-IK/0.1, per
    04-THREAT-MODEL.md §4.2): PENDING
---

# ADR-0006 — Rename sandbox handshake to SNP-IK/0.1

> **Scope of `accepted`.** The *decision* documented here — to stop
> calling the sandbox handshake "Noise_IK" and to name it honestly as
> a custom construction (SNP-IK/0.1) — is `accepted` and effective
> immediately. This is a documentation/naming fix that closes Blocker B
> of the hardening audit.
>
> The *protocol* SNP-IK/0.1 itself is still 🟡 **human-review-gated**
> per `04-THREAT-MODEL.md §4.2` and is **NOT production-safe**. The
> Human reviewer field below is therefore `PENDING`: a named human
> must approve SNP-IK/0.1 (or, more likely, approve its replacement by
> a vetted Noise_IK library per ADR-0007) before any production merge.
> ADR-0003, which this ADR supersedes, made the same gating demand; it
> is restated here so the rename does not get confused with relaxation.

## Context

`02-PROTOCOL-SPEC.md §7.2` mandates, as the production target:

> Every link MUST run **Noise_IK** before carrying frames.

`04-THREAT-MODEL.md §4.2` lists, under "🟡 AI-IMPLEMENTABLE, MANDATORY
HUMAN SECURITY REVIEW BEFORE MERGE":

> Noise_IK handshake integration (**use a vetted library; do not
> hand-roll**)

ADR-0003 (now superseded) described the sandbox's link handshake as a
"*simplified* Noise_IK handshake structure." The sandbox L8 link layer
(`src/lib/snp/link.ts`) implemented:

- Ephemeral X25519 keypair generation on each side
- A two-message exchange: each side sends its ephemeral X25519 public
  key + its signed `NodeDescriptor`
- Three DH operations: `DH(eph, peer_static)`, `DH(static, peer_eph)`,
  `DH(eph, peer_eph)`
- HKDF-SHA256 to derive two AEAD keys (`sendKey`, `recvKey`)
- `NodeDescriptor` signature verification before accepting the link

The hardening audit (Blocker B) reviewed this implementation and found
that it is **not Noise_IK**:

> "performs three DH operations and HKDF" ≠ "implements Noise_IK."
> A real Noise implementation has precise: handshake state, chaining-key
> evolution, handshake hash, prologue, cipher state, transcript binding,
> nonce handling, static-key authentication semantics, message pattern.

The audit further found that ADR-0003's framing ("simplified Noise_IK")
was itself misleading: by claiming partial Noise_IK conformance, it
created the impression that the implementation had been measured
against the Noise specification and found to satisfy a subset of its
properties. In fact, no such conformance measurement was possible,
because the implementation does not follow the Noise state machine at
all — it is a separate, custom authenticated-DH construction.

The audit offered two paths forward:

- **(A) Use a vetted Noise implementation.** Not feasible in this
  sandbox — there is no verified TypeScript Noise library that has
  been independently audited for use as the link-layer handshake.
- **(B) Rename it to a custom protocol and explicitly define it.**
  Honest, low-cost, and unblocks the conformance foundation without
  overclaiming.

**This ADR chooses (B).** The sandbox handshake is renamed from
"Noise_IK" / "simplified Noise_IK" to **SNP-IK/0.1** — the ShareNet
custom authenticated key agreement — and is explicitly defined here as
a fixed construction. It is not called Noise_IK anywhere in the
sandbox source, ADRs, or docs (other than where the *spec's target* is
being cited, or where the contrast against real Noise_IK is being
drawn).

## Decision

1. **The sandbox L8 link-layer handshake is named SNP-IK/0.1.** It is
   defined as a custom authenticated-DH construction below. It is
   NOT Noise_IK. It is NOT a "simplified Noise_IK." It is NOT a
   "structural model of Noise_IK." It is its own construction.

2. **`src/lib/snp/link.ts` is updated:**
   - `performNoiseIKHandshake` is renamed to `performSnpIkHandshake`.
   - A deprecated alias `performNoiseIKHandshake` is kept for
     backward compatibility with existing callers (notably
     `src/lib/snp/integration-tests.ts`). The alias calls
     `performSnpIkHandshake` unchanged. New code MUST call
     `performSnpIkHandshake`.
   - All JSDoc references to "Noise_IK" that describe what this
     sandbox *does* are changed to "SNP-IK/0.1." References that
     *cite the spec's Noise_IK target* or that *contrast against real
     Noise_IK* are kept (renaming those would erase the very
     distinction we are drawing).
   - The "STRUCTURAL MODEL of Noise_IK" disclaimer is replaced with
     an explicit construction definition for SNP-IK/0.1.
   - All thrown-error prefixes change from `"Noise_IK: …"` to
     `"SNP-IK/0.1: …"`. Existing callers that match on error
     substrings must be updated; this is a known consequence of the
     rename.
   - The HKDF `info` literal string `"SNP/0.1 noise-ik link keys v1"`
     is **NOT changed**. Changing it would change the derived keys,
     which is a wire-breaking change outside this ADR's scope. The
     literal is an internal implementation detail; the protocol name
     callers and reviewers see is SNP-IK/0.1.

3. **ADR-0003 is superseded by this ADR.** Its status changes from
   `proposed` to `superseded by ADR-0006`. A `SUPERSEDED` banner is
   added at the top of `0003-simplified-noise-ik.md`. The text of
   ADR-0003 is otherwise preserved as an audit trail.

4. **The spec (`02-PROTOCOL-SPEC.md`) is NOT modified.** The spec
   names `Noise_IK_25519_ChaCha20Poly1305_SHA256` as the production
   target. That target stands. SNP-IK/0.1 is the sandbox reference's
   honest name for what it *actually does today*. The relationship is:
   **spec (production target) > implementation (sandbox reference)**.
   The sandbox admits it has not reached the spec's target. Naming
   the gap honestly is the entire point of this ADR.

## Rationale

- **Honesty is the cheapest security property.** Claiming Noise_IK
  conformance we do not have is worse than admitting a custom
  construction, because the claim gives downstream readers
  (integrators, auditors, future agents) a false confidence that the
  handshake has been measured against the Noise specification. The
  custom construction has NOT been so measured. Naming it SNP-IK/0.1
  forces every reader to engage with the construction definition
  below on its own terms, not on Noise's terms.

- **The audit's recommendation is rename, not rewrite.** The audit
  (Blocker B) explicitly offered path (B) as a legitimate response:
  rename and explicitly define. A vetted Noise_IK library is the
  production answer; SNP-IK/0.1 is the sandbox's honest answer until
  that library is integrated. There is no third option that involves
  claiming Noise_IK conformance.

- **The construction itself is unchanged.** This ADR changes naming
  and documentation only. The DH operations, the HKDF info string,
  the descriptor verification order, the AEAD framing — all identical
  to what ADR-0003 described. Existing vectors, integration tests,
  and call sites that depend on the derived keys continue to work.
  The only behavior change is the error-message prefix on thrown
  errors (`"Noise_IK: …"` → `"SNP-IK/0.1: …"`), which does not affect
  any conformance vector.

- **The threat model still lists this as 🟡, not 🔴.**
  `04-THREAT-MODEL.md §4.2` places Noise_IK integration in the
  "AI-implementable, mandatory human review" tier. SNP-IK/0.1 is in
  the same tier: an AI wrote it, a human must review it before
  production. The §4.3 🔴 tier (human-design-only) does not include
  the link-layer handshake. So a documented, custom, deferral-to-
  production implementation is process-compliant *if* it never
  reaches production without human sign-off.

- **The conformance suite does not cover the handshake itself.** The
  handshake is 🟡 human-review; it is not (and per the threat model
  should not be) machine-checked by golden vectors. The AEAD that
  runs AFTER the handshake IS covered by conformance suite 15-aead
  (the post-handshake frame encryption).

## Alternatives considered

### (a) Use a vetted Noise_IK library — rejected (for this sandbox)

There is no verified, independently-audited TypeScript Noise_IK
library readily available in this sandbox. The candidates
(`noise-protocol`, `@chainsafe/noise`) exist but have not been
audited for this use case and would themselves require human review
before merge per `04-THREAT-MODEL.md §4.2`. Integrating one is the
*production* answer and is documented in the Migration section
below; it is not the answer for this sandbox's reference
implementation today.

### (b) Hand-roll a full Noise_IK state machine — rejected

The threat model says "use a vetted library; do not hand-roll." A
hand-rolled full Noise_IK state machine — with the running
chaining-key, the encrypted initiator static key, the AEAD framing
of handshake messages, the PSK option, the rekey logic — is exactly
the kind of subtle, attack-surface-heavy code that the 🟡 tier
exists to flag. Hand-rolling *SNP-IK/0.1* (a much simpler custom
construction) is defensible; hand-rolling *full Noise_IK* is not.

### (c) Keep calling it "simplified Noise_IK" and hope no one notices — rejected (Blocker B)

This is what the audit found. It is the status quo ante. It is
rejected by this ADR.

### (d) Adopt SNP-IK/0.1 as the production target, dropping the spec's Noise_IK mandate — rejected

The spec's Noise_IK mandate (`02-PROTOCOL-SPEC.md §7.2`) reflects
the consensus design decision that production ShareNet should use a
vetted Noise pattern. Replacing that mandate with "use SNP-IK/0.1"
would be a Tier 1 spec change requiring its own ADR, and would
abandon the property of being able to point at a public, scrutinized
handshake construction (Noise_IK) as the design intent. SNP-IK/0.1
is the sandbox reference's honest name for what it actually does;
Noise_IK remains the production target. The gap between the two is
real and tracked.

## Construction

### SNP-IK/0.1 — ShareNet custom authenticated key agreement

SNP-IK/0.1 is a custom authenticated-DH handshake, NOT a Noise
protocol. It is defined here as a fixed construction; do not call it
Noise_IK.

```
Construction:
  1. Initiator generates ephemeral X25519 keypair (e, E)
  2. Initiator sends E + their signed NodeDescriptor to responder
  3. Responder generates ephemeral X25519 keypair (e', E')
  4. Responder sends E' + their signed NodeDescriptor to initiator
  5. Both compute three DH operations:
       dh1 = initiator_ephemeral × responder_static (rendezvousPub)
       dh2 = initiator_static × responder_ephemeral
       dh3 = initiator_ephemeral × responder_ephemeral
  6. Both derive link keys via HKDF-SHA256(dh1 || dh2 || dh3,
       salt=empty, info="SNP-IK/0.1 link keys")
  7. Both verify the peer's NodeDescriptor signature BEFORE accepting
     the link
```

### Implementation note (HKDF `info` literal)

The HKDF `info` string the sandbox uses is the legacy literal
`"SNP/0.1 noise-ik link keys v1"` (frozen before the SNP-IK/0.1
rename). It is NOT changed by this ADR because changing it would
change the derived keys (a wire-breaking change outside this ADR's
scope). The literal is an internal implementation detail; the
protocol name callers and reviewers see is SNP-IK/0.1. A future ADR
that adopts a vetted Noise_IK library will replace the entire key
derivation (new HKDF info, new DH mix, new cipher state) and the
legacy literal will be deleted at that time.

### On-wire message format

The two-message exchange uses the CBOR map `{ephPub, descriptor}`
defined in `src/lib/snp/link.ts` (`encodeHandshakeMessage` /
`decodeHandshakeMessage`). This format is internal to SNP-IK/0.1; a
vetted Noise_IK implementation will have a different on-wire format
per the Noise specification. The two are not wire-compatible.

### `expectedPeerNodeId` (the "I"-style property)

If the initiator supplies `expectedPeerNodeId`, the handshake fails
if the responder's verified `descriptor.nodeId` does not match. This
is the "I"-style property (initiator knows responder's identity in
advance), analogous to the "I" in Noise_IK's pattern naming. It is
not the same mechanism — Noise_IK's "I" is implemented via
DH-protected static-key encryption in the initiator's first message;
SNP-IK/0.1 implements it via NodeId pinning at the descriptor
verification step.

## Security properties (vs real Noise_IK)

| Property | SNP-IK/0.1 | Real Noise_IK |
|---|---|---|
| Mutual authentication (both NodeDescriptors signature-verified) | ✓ | ✓ (via transcript + DH-bound static) |
| Forward secrecy (ephemeral keys; long-term key compromise doesn't reveal past sessions) | ✓ | ✓ |
| Key agreement (X25519 ECDH) | ✓ | ✓ |
| Transcript binding (every handshake message hashed into a chaining key) | ✗ | ✓ |
| Handshake hash (single hash binding the entire transcript) | ✗ | ✓ |
| Prologue support (negotiated/known data bound into the transcript) | ✗ | ✓ |
| Vetted, publicly scrutinized pattern | ✗ | ✓ |
| DH-protected initiator static key (encrypted under responder's static) | ✗ | ✓ |
| AEAD-protected handshake messages | ✗ | ✓ (after the first DH) |
| Post-handshake AEAD on data frames | ✓ (EstablishedLink, suite 15-aead) | ✓ |

The bottom four rows are the gaps. They are real security properties
that SNP-IK/0.1 does not provide. They are why SNP-IK/0.1 is
🟡 human-review-gated and NOT production-safe.

### What SNP-IK/0.1 DOES guarantee

- ✅ **Peer authentication.** Each side verifies the other's
  `NodeDescriptor` signature (`verifyNodeDescriptor` from
  `identity.ts`, which returns false on bad sig — I20). A forged
  descriptor is rejected; the handshake throws and the channel is
  closed.
- ✅ **NodeId binding (I4).** Each side re-derives the peer's NodeId
  via `deriveNodeId(peerDescriptor.nodePubKey)` and verifies it
  matches `peerDescriptor.nodeId`. A descriptor with a mismatched
  NodeId (name-squatting) is rejected.
- ✅ **"I"-style pinning.** If `expectedPeerNodeId` is set, the
  initiator verifies the responder's NodeId before completing the
  handshake.
- ✅ **Forward secrecy for the ephemeral DH.** `dh3 = DH(eph, eph)`
  means compromising both static keys after the handshake does not
  recover `linkKeys`.
- ✅ **Key separation.** `sendKey` and `recvKey` are distinct;
  initiator and responder use them in opposite directions (no
  reflection).
- ✅ **No auto-accept.** `LinkListener.onLink` fires only AFTER a
  successful handshake. There is no `onAccept` returning raw
  channels. This structurally prevents the audit's NearbyTransport
  auto-accept bug (`00-AUDIT.md §5.2`).
- ✅ **Post-handshake AEAD on frames.** `EstablishedLink`
  AEAD-encrypts every frame with ChaCha20-Poly1305 using the derived
  `LinkKeys` and a per-frame nonce derived from `fid ‖ seq`
  (suite 15-aead). A bad AEAD tag kills the link.

### What SNP-IK/0.1 does NOT guarantee (vs real Noise_IK)

- ❌ **No transcript binding.** The handshake messages are not
  hashed into a chaining key. A man-in-the-middle cannot forge the
  descriptor signature, but the transcript is not bound the way
  Noise_IK's running hash binds it.
- ❌ **No handshake hash.** There is no single hash binding the
  entire transcript; downstream key derivation cannot detect
  transcript tampering.
- ❌ **No prologue support.** There is no mechanism to bind
  out-of-band negotiated data (e.g. protocol version, capability
  hints) into the handshake.
- ❌ **No DH-protected initiator static key.** The initiator's
  `rendezvousPub` (their X25519 static key) is sent in the clear
  inside the signed `NodeDescriptor`. A passive observer learns it.
  Real Noise_IK encrypts the initiator's `s` under the responder's
  static key.
- ❌ **Not a vetted Noise pattern.** SNP-IK/0.1 has not had the
  public scrutiny that Noise_IK has had. It is a custom construction
  written by an AI agent and reviewed by no human cryptographer yet.

## Conformance impact

**None on the handshake itself.** The handshake is 🟡 human-review
per `04-THREAT-MODEL.md §4.2`; it is intentionally NOT covered by
conformance vectors (machine-checking a custom handshake would
provide little assurance compared to a vetted library). No vector
exercises `performSnpIkHandshake` directly. The
`expectedPeerNodeId`-related test cases described in ADR-0003's
"Recommended future vectors" section are still recommended as
*integration tests* (not conformance vectors) and are exercised by
the existing `/api/integration-tests` route.

**None on the AEAD.** Suite 15-aead covers the post-handshake
ChaCha20-Poly1305 frame encryption that `EstablishedLink` performs.
This ADR does not touch that AEAD — only the naming of the handshake
that *derives* the AEAD keys. The derived `linkKeys` are byte-
identical before and after this rename (HKDF info literal unchanged),
so suite 15-aead's vectors remain valid.

**No vector regeneration required.** The error-message prefix change
(`"Noise_IK: …"` → `"SNP-IK/0.1: …"`) does not affect any conformance
vector. Integration tests that match on error substrings may need
updating; that is an integration-test concern, not a conformance-
vector concern, and is not blocking.

## Migration path

### To a vetted Noise_IK library (future, ADR-0007)

When a vetted Noise_IK library is integrated (whether in TypeScript
or in the future Rust reference per ADR-0001):

1. **File ADR-0007** to supersede this ADR. ADR-0007 documents the
   chosen library, the audit status, and the migration plan.
2. **Update `02-PROTOCOL-SPEC.md` §7.2** to reflect that the
   production target is now met (the spec's `Noise_IK_25519_
   ChaCha20Poly1305_SHA256` becomes the implemented reality, not
   just the target).
3. **Replace `performSnpIkHandshake` in `src/lib/snp/link.ts`** with
   the vetted implementation. Keep the `Link` interface and
   `HandshakeChannel` interface unchanged — only the handshake
   function's internals change.
4. **Update or remove the deprecated `performNoiseIKHandshake` alias.**
   With a real Noise_IK in place, the alias should be removed
   (callers migrate to `performSnpIkHandshake` or directly to the
   vetted library entry point).
5. **Regenerate any affected vectors.** Suite 15-aead's vectors may
   need regeneration if the vetted Noise_IK library uses a different
   HKDF info string or cipher state derivation (it will). File this
   as a Tier 0 ADR with named human approval per `06-CONFORMANCE-
   AND-AI-MODEL.md §B6`.
6. **Human reviewer signs ADR-0007.** This is the mandatory gate per
   `04-THREAT-MODEL.md §4.2`. Until then, SNP-IK/0.1 remains the
   sandbox's honest handshake and ADR-0006 remains `accepted`.

### Rollback

This ADR can be rolled back by reverting the naming changes in
`src/lib/snp/link.ts` and changing ADR-0003's status back to
`proposed`. There is no cryptographic or wire-format consequence —
the construction is unchanged. Rollback is not recommended; the
audit's Blocker B finding would re-open.

## Consequences

### Positive

- The sandbox handshake is named honestly. A reader of `link.ts`
  cannot leave with the impression that they are looking at a
  Noise_IK implementation. The construction definition is in the
  module-level JSDoc and in this ADR; the gap against real Noise_IK
  is explicit (the ✗ rows in the security-properties table).
- Blocker B of the hardening audit is closed: the misleading
  "simplified Noise_IK" framing is removed.
- The spec's Noise_IK mandate remains intact as the production
  target. The gap between spec and implementation is now visible
  by name (SNP-IK/0.1 vs Noise_IK), not hidden behind a "simplified"
  qualifier.
- Existing call sites (e.g. `integration-tests.ts`) continue to work
  via the deprecated `performNoiseIKHandshake` alias. No migration
  is required for this ADR; migration is required only when ADR-0007
  lands.

### Negative

- ❌ **SNP-IK/0.1 is NOT production-safe.** The four ✗ rows in the
  security-properties table are real gaps. A passive observer learns
  the initiator's static X25519 key. There is no transcript hash.
  There is no prologue support. The construction has not had public
  scrutiny. Production deployment requires either human sign-off on
  SNP-IK/0.1 (unlikely, given the gaps) or migration to a vetted
  Noise_IK library via ADR-0007.
- ❌ **Process risk remains.** A future agent reading only the
  deprecated `performNoiseIKHandshake` alias could still assume the
  underlying handshake is Noise_IK. Mitigated by the prominent
  `@deprecated` JSDoc on the alias pointing at `performSnpIkHandshake`
  and at this ADR, plus the construction definition in the
  module-level JSDoc. The alias should be removed in ADR-0007.
- ❌ **Error-message prefix change.** Any caller matching on the
  literal `"Noise_IK: …"` prefix in thrown errors must be updated
  to match `"SNP-IK/0.1: …"` instead. This is a known, scoped
  consequence.

### Neutral

- The `HandshakeMessage` CBOR format (`{ephPub, descriptor}`) is
  internal to SNP-IK/0.1. A Rust reference using real Noise_IK will
  have a different on-wire handshake format. This was already true
  under ADR-0003; the rename makes it more obvious.
- The HKDF `info` literal string remains `"SNP/0.1 noise-ik link
  keys v1"` (a historical artifact). This is now documented in
  `link.ts` and in this ADR; it is no longer a hidden inconsistency.

## Human reviewer

> Required for production use of SNP-IK/0.1 per `04-THREAT-MODEL.md
> §4.2`. The *rename decision* (this ADR) is `accepted` and effective
> immediately; the *protocol* SNP-IK/0.1 remains 🟡 human-review-gated
> and NOT production-safe.

- **Reviewer name:** <PENDING — required before any production
  deployment that uses SNP-IK/0.1 as the link-layer handshake>
- **Review date:** <PENDING>
- **Review outcome:** <PENDING — approved | approved-with-conditions |
  rejected>
- **Conditions / notes:**
  - **This ADR's `accepted` status applies only to the renaming
    decision (Blocker B of the hardening audit).** It does NOT
    constitute approval to use SNP-IK/0.1 in production.
  - **The most likely path forward is that this ADR is superseded
    by ADR-0007** (vetted Noise_IK library integration) rather than
    that SNP-IK/0.1 is approved as-is for production. The human
    reviewer's role is to decide which path: (a) approve SNP-IK/0.1
    for a narrowly-scoped production deployment (unlikely, given
    the four ✗ rows in the security-properties table), or (b)
    require a vetted Noise_IK library before any production merge
    (likely, matches the spec's `02-PROTOCOL-SPEC.md §7.2` mandate).
  - **In the meantime, the sandbox uses SNP-IK/0.1 honestly.** It
    is not called Noise_IK. The gap against the spec's Noise_IK
    target is explicit.

## References

- Spec sections:
  - `02-PROTOCOL-SPEC.md §7.2` (the Noise_IK production target —
    unchanged by this ADR; SNP-IK/0.1 is the sandbox's honest name
    for what it does today, not a replacement for the target).
  - `04-THREAT-MODEL.md §4.2` (🟡 mandatory human review for
    handshake integration — applies to SNP-IK/0.1 just as it
    applied to ADR-0003).
  - `06-CONFORMANCE-AND-AI-MODEL.md §B3` (invariants I4, I9, I11,
    I20 — all still enforced by `link.ts` after the rename), `§B6`
    (ADR process — Tier 1 requires human approval for production
    use).
- Audit findings:
  - `00-AUDIT.md §5.2` (NearbyTransport auto-accept bug —
    structurally closed by `link.ts` regardless of handshake naming).
  - Hardening audit Blocker B (the finding this ADR closes): the
    handshake was described as "Noise_IK" / "simplified Noise_IK"
    but is not Noise.
- Invariants:
  - I4 — `NodeId = SHA-256("SNP/0.1 node\0" ‖ pk)` — enforced in
    `performSnpIkHandshake` step 5.
  - I9 — L8 never imports L6 — unchanged by this ADR.
  - I11 — Link interface is platform-independent — unchanged.
  - I20 — `verify*` returns false, never throws; handshake throws
    on verification failure (never accepts an unauthenticated peer)
    — unchanged. Error message prefixes changed; behavior unchanged.
- Conformance vectors:
  - No direct vectors exercise `performSnpIkHandshake` (the
    handshake is 🟡 human-review, not machine-checked).
  - Suite 15-aead covers the post-handshake AEAD that runs on the
    keys this handshake derives. The keys are byte-identical before
    and after this rename (HKDF info literal unchanged), so 15-aead
    vectors remain valid.
- Related ADRs:
  - **ADR-0003** (superseded by this ADR). The sandbox's prior
    framing of the handshake as a "simplified Noise_IK structure."
    Status changed from `proposed` to `superseded by ADR-0006`.
  - **ADR-0001** (TypeScript as sandbox reference — the reason a
    vetted Noise_IK library is not yet integrated).
  - **ADR-0002** (@noble libraries — provides the X25519, HKDF, and
    ChaCha20-Poly1305 primitives SNP-IK/0.1 and the post-handshake
    AEAD use).
  - **ADR-0007** (future — will supersede this ADR when a vetted
    Noise_IK library is integrated; not yet filed).
