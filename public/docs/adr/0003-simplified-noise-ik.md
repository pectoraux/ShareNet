---
ADR: 0003
Title: Simplified Noise_IK handshake structure (sandbox only — NOT production-safe)
Status: 🟡 proposed (mandatory human security review before any merge to production)
Tier affected: 1
Date: 2026-08-11
Deciders:
  - Owning agent: Z.ai (reference/ + L8 link layer)
  - Human reviewer (REQUIRED, Tier 1): PENDING
---

# ADR-0003 — Simplified Noise_IK handshake structure

> 🟡 **This ADR is `proposed`, not `accepted`.** Per
> `04-THREAT-MODEL.md §4.2`, Noise_IK handshake integration is
> 🟡 AI-implementable with **mandatory human security review before
> merge**. The simplified structure described here is suitable for the
> sandbox conformance foundation and for the integration-tests API
> route, and is **NOT production-safe**. The Human reviewer field
> below is intentionally blank; this ADR becomes `accepted` only when
> a named human reviewer signs it (or, more likely, when it is
> superseded by an ADR adopting a vetted Noise library).

## Context

`02-PROTOCOL-SPEC.md §7.2` mandates:

> Every link MUST run **Noise_IK** before carrying frames. This is the
> missing peer authentication identified in the audit —
> `NearbyTransport` currently auto-accepts every connection with no
> identity check whatsoever.

`04-THREAT-MODEL.md §4.2` lists, under "🟡 AI-IMPLEMENTABLE, MANDATORY
HUMAN SECURITY REVIEW BEFORE MERGE":

> Noise_IK handshake integration (**use a vetted library; do not
> hand-roll**)

The audit (`00-AUDIT.md §5.2`, "Transport / NearbyTransport") found
that the existing transport:

- Auto-accepts every connection with no peer authentication.
- Uses `EndpointId` (a Nearby Connections platform API) as a protocol
  identifier — defining protocol semantics in terms of a platform API.
- Has a 32 KB (BYTES-only) cap.
- Has link encryption that "terminates at each hop."

The L8 link layer (`src/lib/snp/link.ts`, Task 12) replaces this with a
`Link` interface and a `performNoiseIKHandshake` function. **The
problem this ADR addresses:** the TypeScript sandbox does not have a
vetted Noise library readily available, and the spec mandates Noise_IK.
The choice is between (a) blocking the L8 link layer until a vetted
Noise library is integrated, (b) hand-rolling a *full* Noise_IK state
machine, or (c) implementing a *simplified* handshake structure that
preserves the security properties the audit requires (peer
authentication, descriptor binding, key derivation) while explicitly
deferring full Noise_IK compliance to a production reference.

## Decision

**The sandbox L8 link layer implements a *simplified* handshake
structure, not full Noise_IK.** The structure is:

1. **Initiator and responder each generate an ephemeral X25519
   keypair.**
2. **Each side sends a `HandshakeMessage`** containing:
   - `ephPub` — the ephemeral X25519 public key (32 bytes).
   - `descriptor` — the sender's signed `NodeDescriptor` (which
     carries `nodePubKey` (Ed25519) and `rendezvousPub` (X25519 static)).
3. **Each side verifies the peer's `NodeDescriptor` signature** using
   `verifyNodeDescriptor` (which returns false, never throws — I20).
4. **Each side enforces I4:** `deriveNodeId(peerDescriptor.nodePubKey)
   === peerDescriptor.nodeId`. This binds the NodeId to the Ed25519
   key, preventing name-squatting.
5. **If `expectedPeerNodeId` is set** (initiator knows the responder
   in advance — the "I" in Noise_IK), the initiator verifies the
   peer's `NodeId` matches.
6. **Three DH operations** are computed using the ephemeral and
   rendezvous (static) keys:
   - `dh1 = DH(localEph, peerRendezvous)` (es equivalent)
   - `dh2 = DH(localRendezvous, peerEph)` (ss equivalent — using
     rendezvous as the static key)
   - `dh3 = DH(localEph, peerEph)` (ee equivalent)
7. **HKDF-SHA256** derives 64 bytes of link key material:
   `HKDF-SHA256(salt = empty, ikm = dh1 ‖ dh2 ‖ dh3, info =
   "SNP/0.1 noise-ik link keys v1", length = 64)`.
8. **The 64 bytes are split** into `sendKey` (first 32) and `recvKey`
   (last 32). The initiator's `sendKey` is the responder's `recvKey`
   and vice versa.
9. **The handshake returns `{link, peerDescriptor, linkKeys}`.** The
   `linkKeys` are returned to the caller; the caller (or a higher
   layer) is responsible for AEAD-encrypting frames using those keys.

**What this structure does NOT do, that full Noise_IK does:**

- ❌ **No DH-protected initiator static key.** In real Noise_IK, the
  initiator's static key is encrypted under DH(es, ee) before
  transmission. In this simplified structure, the initiator's static
  key (rendezvousPub) is carried in the clear inside the (signed but
  unencrypted) `NodeDescriptor`. The descriptor is signed, so it
  cannot be forged — but it is visible to a passive observer.
- ❌ **No post-handshake AEAD.** `EstablishedLink` sends frames as
  raw CBOR bytes on the underlying `HandshakeChannel`. The derived
  `linkKeys` are returned to the caller, who MUST apply
  ChaCha20-Poly1305 (or AES-256-GCM) at a higher layer. The sandbox
  does not yet have an AEAD primitive in `crypto.ts`.
- ❌ **No handshake hash chaining.** Real Noise_IK chains a running
  hash through every message, binding the transcript. This structure
  does not; the binding comes from the signed `NodeDescriptor`
  instead.
- ❌ **No identity hiding for the initiator.** In real Noise_IK, the
  initiator's static key is encrypted under the responder's static
  key before transmission (the "I" pattern's `s` is encrypted). Here,
  the initiator's `rendezvousPub` is in the clear.

**What this structure DOES preserve:**

- ✅ **Peer authentication.** Each side verifies the other's
  `NodeDescriptor` signature. A forged descriptor is rejected.
- ✅ **NodeId binding (I4).** Each side re-derives the peer's NodeId
  from the peer's `nodePubKey` and verifies it matches the
  descriptor. A descriptor with a mismatched NodeId is rejected.
- ✅ **Known-peer pre-authentication (the "I" in IK).** If
  `expectedPeerNodeId` is set, the initiator verifies the responder's
  NodeId before completing the handshake.
- ✅ **Forward secrecy for the ephemeral DH.** Compromising the
  static keys after the handshake does not reveal the derived
  `linkKeys` (because `dh3 = DH(eph, eph)` is forward-secret).
- ✅ **Key separation.** `sendKey` and `recvKey` are distinct; the
  initiator and responder use them in opposite directions, preventing
  reflection attacks.
- ✅ **No auto-accept.** `LinkListener.onLink` fires only AFTER a
  successful handshake. There is no `onAccept` returning raw
  channels. This structurally prevents the audit's "NearbyTransport
  auto-accepts every connection" bug.

## Rationale

- **The audit's primary transport failure is auto-accept, not
  hand-rolled crypto.** §5.2: "NearbyTransport currently auto-accepts
  every connection with no identity check whatsoever." The simplified
  handshake closes the auto-accept gap structurally (no path to a
  `Link` without a handshake) even though it does not implement full
  Noise_IK.
- **The descriptor signature is the actual authentication.** In
  real Noise_IK, the static key is authenticated by its presence in
  the handshake transcript and its use in DH. Here, the
  `NodeDescriptor` signature authenticates the static key (and binds
  it to the NodeId via I4). The authentication property is preserved
  by a different mechanism.
- **The forward-secret DH is preserved.** The `dh3 = DH(eph, eph)`
  term means compromising both static keys after the handshake does
  not recover `linkKeys`. This is the forward-secrecy property that
  makes Noise_IK worth using over plain static-static DH.
- **The threat model lists this as 🟡, not 🔴.** 04-THREAT-MODEL.md
  §4.2 places Noise_IK in the "AI-implementable, mandatory human
  review" tier — AI may write the code, a human must review it before
  merge. The §4.3 🔴 tier (human-design-only) does not include
  Noise_IK. So a simplified, documented, deferral-to-production
  implementation is process-compliant *if* it never reaches production
  without human sign-off.
- **The conformance suite does not currently cover the handshake.**
  Suites 01–14 cover CBOR, hashing, identity, chunking, Merkle,
  manifest, receipts, frames, descriptors, routing, gateway, civic
  points, revocation, and negatives. None of them exercise
  `performNoiseIKHandshake` directly. The integration-tests API route
  (`/api/integration-tests`) exercises the handshake end-to-end via
  `InMemoryHandshakeChannelPair`, but those are integration tests, not
  conformance vectors. This is a coverage gap; see "Conformance
  impact" below.

## Alternatives considered

### (a) Block the L8 link layer until a vetted Noise library is
integrated — rejected

The L8 link layer is a prerequisite for L6 routing (Task 11), L5 sync
(Task 14), and the integration-tests API route (Task 15). Blocking it
on Noise library integration would block the entire conformance
foundation and the dashboard's ability to demonstrate end-to-end
behavior. The conformance foundation is the critical path; the
handshake's production-readiness is not on the critical path for N0/N1.

**Revisit when:** a TypeScript Noise library (`noise-protocol`, `@noisy`
, or similar) is evaluated and integrated, OR the Rust reference
supersedes the TypeScript reference (ADR-0001) and uses `snow` or
`noise-rust`.

### (b) Hand-roll full Noise_IK — rejected

The threat model says "use a vetted library; do not hand-roll." A
hand-rolled full Noise_IK state machine — with the running hash, the
encrypted initiator static key, the AEAD framing, the PSK option, the
rekey logic — is exactly the kind of subtle, attack-surface-heavy code
that the 🟡 tier exists to flag. Hand-rolling a *simplified* structure
that preserves the audit-critical properties and defers the rest is
defensible; hand-rolling *full* Noise_IK is not.

### (c) Implement only the parts of Noise_IK that the audit requires
— accepted (this ADR)

This is what the sandbox does. The audit requires: no auto-accept,
peer authentication, NodeId binding, key derivation. The simplified
structure provides all four. The parts it defers (DH-protected
initiator static, post-handshake AEAD, transcript hash chaining) are
real security properties, but they are not the properties the audit
found missing — they are properties the audit assumed would be there
in production.

### (d) Use a different handshake pattern (e.g. Noise_XX or Noise_NK)
— rejected

The spec mandates Noise_IK (§7.2). Switching to Noise_XX (which does
not require the initiator to know the responder in advance) or Noise_NK
(which does not authenticate the initiator to the responder) would be
a Tier 1 spec change requiring its own ADR and is out of scope for the
sandbox.

## Conformance impact

**No conformance vectors currently exercise `performNoiseIKHandshake`
directly.** This is a coverage gap that should be closed in a future
task. The integration-tests API route exercises the handshake
end-to-end (tests 01–08 in `src/lib/snp/integration-tests.ts` all run
through `performNoiseIKHandshake` via `InMemoryHandshakeChannelPair`),
but integration tests are not conformance vectors.

**Vectors that transitively assume the handshake works:**

- `03-identity.json` — `devicecert-sign-and-verify` (the
  `NodeDescriptor` signature is what the handshake verifies).
- `09-descriptors.json` — `node-descriptor-sign-and-verify`,
  `gateway-advert-sign-and-verify` (signatures verified during
  handshake).
- `10-routing.json` — `route-advert-sign-and-verify` (gateway's
  NodeDescriptor is verified during the handshake before its
  RouteAdverts are accepted).
- `14-negative.json` — `negative-ios-advertising-mesh-relay` (the
  descriptor rejection that the handshake would enforce before
  accepting a peer).

**Recommended future vectors (not blocking this ADR):**

- `handshake-initiator-knows-responder` — `expectedPeerNodeId` set;
  handshake completes when peer's NodeId matches, throws when it
  does not.
- `handshake-responder-tofu` — `expectedPeerNodeId` null; handshake
  completes for any peer with a valid signed descriptor (TOFU model).
- `handshake-rejects-forged-descriptor` — peer sends a descriptor
  signed by a different key than its `nodePubKey`; handshake throws.
- `handshake-rejects-nodeid-mismatch` — peer's `nodeId` ≠
  `deriveNodeId(nodePubKey)`; handshake throws (I4 enforcement at the
  link layer).
- `handshake-keys-are-distinct` — `sendKey ≠ recvKey` and
  initiator's `sendKey === responder's recvKey`.

These vectors would be added to a new `15-handshake.json` suite in a
future task. Until they exist, the integration-tests API route is the
only runtime check that the handshake works.

## Migration path

**To a vetted Noise library (future):**

1. Evaluate TypeScript Noise libraries: `noise-protocol` (original,
  less maintained), `@chainsafe/noise` (more recent, used in libp2p),
  or roll a thin wrapper around `@noble/ciphers` (ChaCha20-Poly1305)
  + `@noble/hashes` (SHA-256) + `@noble/curves` (X25519) implementing
  the Noise_IK state machine per the Noise spec.
2. Replace `performNoiseIKHandshake` in `src/lib/snp/link.ts` with the
  vetted implementation. Keep the `Link` interface and
  `HandshakeChannel` interface unchanged — only the handshake
  function's internals change.
3. Add the `15-handshake.json` conformance suite (see "Conformance
  impact") with vectors generated by the vetted library.
4. Have a named human reviewer (per 04-THREAT-MODEL.md §4.2) audit
  the integration. This is the mandatory gate.
5. Supersede this ADR with the production ADR. Status → `superseded`.

**To a Rust reference (future, per ADR-0001):** the Rust reference
uses `snow` (the most widely-used Rust Noise library) or `noise-rust`.
The Rust `performNoiseIKHandshake` produces different `linkKeys` than
the TypeScript simplified version (because the DH mix and HKDF info
string differ), so the link layer is NOT cross-compatible between the
TypeScript sandbox and a future Rust reference. This is acceptable
because the link layer is local to each implementation; only the
Class A / Class B *frame* format is wire-compatible (and that is
pinned by Suite 08).

**Rollback:** if the vetted library cannot be integrated (e.g.
licensing, performance, audit failure), the simplified handshake
remains in the sandbox. The sandbox is not production; the rollback
cost is that the audit's "use a vetted library" recommendation is not
yet realised. The cost of remaining on the simplified handshake *in
production* is the security gap documented in "Decision" above — which
is why this ADR is `proposed`, not `accepted`, and why the Human
reviewer field is blank.

## Consequences

### Positive

- The L8 link layer exists today, unblocking L6 routing, L5 sync, and
  the integration-tests API route.
- The audit's auto-accept bug is structurally closed: there is no path
  to a `Link` without a handshake. `LinkListener.onLink` fires only
  after `performNoiseIKHandshake` completes.
- Peer authentication, NodeId binding (I4), and forward secrecy are
  preserved — the security properties the audit explicitly identified
  as missing.
- The `LinkKeys` are returned to the caller, so a future AEAD layer
  can be added without re-running the handshake.
- The deferral is documented, named, and human-gated. It cannot
  silently become "production Noise_IK" because this ADR is
  `proposed` and the Human reviewer field is blank.

### Negative

- ❌ **The simplified handshake is NOT production-safe.** The
  initiator's static key (`rendezvousPub`) is sent in the clear
  inside the signed descriptor. A passive observer learns the
  initiator's static X25519 public key. In real Noise_IK, this is
  encrypted under the responder's static key (the "I" pattern's
  encrypted `s`).
- ❌ **No post-handshake AEAD.** Frames are sent as raw CBOR on the
  underlying `HandshakeChannel`. The derived `linkKeys` are not used
  by `EstablishedLink`. A passive observer on the link can read every
  frame's `dst`, `src`, `ttl`, `fid`, `seq`, and `body` (though
  Class B `body` is end-to-end encrypted by the circuit layer per
  §7.3, and Class A `body` is the object protocol, also encrypted at
  a higher layer). The link-layer encryption the spec mandates (§7.2:
  "link encryption is in addition to end-to-end circuit encryption")
  is NOT provided.
- ❌ **No transcript hash binding.** A man-in-the-middle cannot forge
  the descriptor signature, but the simplified structure does not
  bind the handshake transcript the way real Noise_IK's running hash
  does. This is a downgrade in downgrade-attack resistance.
- ❌ **Coverage gap.** The conformance suite has no
  `15-handshake.json`. The handshake is exercised only by integration
  tests, which are not part of the CI conformance gate.
- ❌ **Process risk.** A future agent reading `link.ts` and not
  reading this ADR might assume the simplified handshake *is*
  Noise_IK. Mitigated by the prominent ⚠️ warning in `link.ts`'s
  JSDoc and by this ADR's `proposed` status, but the risk is real.

### Neutral

- The `HandshakeMessage` CBOR format (`{ephPub, descriptor}`) is
  internal to the sandbox. A Rust reference using real Noise_IK will
  have a different on-wire handshake format. This is acceptable
  because the link layer is local; only the frame format is
  cross-implementation.

## Human reviewer

- **Reviewer name:** <PENDING — required for Tier 1, per 06 §B6>
- **Review date:** <PENDING>
- **Review outcome:** <PENDING — approved | approved-with-conditions | rejected>
- **Conditions / notes:**
  - **This ADR is `proposed`. It MUST NOT be marked `accepted`
    without a named human reviewer.**
  - The most likely path forward is that this ADR is **superseded**
    by a future ADR adopting a vetted Noise library, rather than
    being `accepted` as-is. The human reviewer's role is to decide
    which path: (a) accept the simplified structure for a
    narrowly-scoped production deployment (unlikely, given the
    missing AEAD), or (b) require a vetted library before any
    production merge (likely).
  - In the meantime, the sandbox uses the simplified handshake. The
    `SECURITY.md` file states plainly that this is not
    production-safe.

## References

- Spec sections:
  - 02-PROTOCOL-SPEC.md §7.2 (Noise_IK handshake mandate), §7.3
    (circuit encryption — separate from link encryption), §7.4
    (metadata minimisation — the link layer's contribution).
  - 04-THREAT-MODEL.md §4.2 (🟡 mandatory human review for Noise_IK
    integration).
  - 06-CONFORMANCE-AND-AI-MODEL.md §B3 (invariants I4, I9, I11, I20
    — all enforced by the link layer regardless of handshake
    structure), §B6 (ADR process — Tier 1 requires human approval).
- Audit findings: 00-AUDIT.md §5.2 (NearbyTransport auto-accept,
  EndpointId-as-protocol-id, 32 KB cap, link-encryption-terminates-
  per-hop), §3.10 (production code depending on Fake classes — the
  link layer's `InMemoryLink` is testing-only and clearly marked).
- Invariants:
  - I4 — `NodeId = SHA-256("SNP/0.1 node\0" ‖ pk)` — enforced in
    `performNoiseIKHandshake` step 4.
  - I9 — L8 (transport) never imports L6 (routing) — verified in
    Task 12 worklog.
  - I11 — L6 never imports a platform SDK; L11 (link) likewise —
    `LinkTransportKind` is a string enum, not a platform type.
  - I20 — A stub in a security-critical path throws; it never
    returns a permissive default — `verifyNodeDescriptor` returns
    false (never throws); `performNoiseIKHandshake` throws on
    verification failure (never accepts an unauthenticated peer).
- Conformance vectors:
  - No direct vectors (coverage gap; see "Conformance impact").
  - Indirect: `03-identity.json:devicecert-sign-and-verify`,
    `09-descriptors.json:node-descriptor-sign-and-verify`,
    `09-descriptors.json:gateway-advert-sign-and-verify`,
    `14-negative.json:negative-ios-advertising-mesh-relay`.
- Related ADRs:
  - ADR-0001 (TypeScript as sandbox reference — the reason a vetted
    Noise library is not yet integrated).
  - ADR-0002 (@noble libraries — provides the X25519 and HKDF
    primitives this handshake uses).
