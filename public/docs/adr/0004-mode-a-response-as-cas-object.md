---
ADR: 0004
Title: Mode A response body is a content-addressed object (reuses L2 CAS)
Status: accepted
Tier affected: 1
Date: 2026-08-11
Deciders:
  - Owning agent: Z.ai (reference/ + L7 gateway)
  - Human reviewer (REQUIRED, Tier 1): PENDING
---

# ADR-0004 — Mode A response body is a content-addressed object

## Context

`02-PROTOCOL-SPEC.md §8.2` defines the Mode A `TransitResponse`:

```cddl
TransitResponse = {
  reqId:      bstr .size 16,
  status:     uint,
  headers:    { * tstr => tstr },
  objectId:   bstr .size 32,     ; body is a Class A object — reuses CAS
  fetchedAt:  uint,
  gatewayId:  bstr .size 32,
  gatewaySig: bstr .size 64      ; gateway attests it performed this fetch
}
```

The spec's rationale (§8.2, immediately after the CDDL):

> The response body being a **content-addressed object** is the key
> reuse: it gets chunking, Merkle verification, resumable transfer,
> and multi-source fetch from `core-content` for free. A large Mode A
> download can be reassembled from several relays that each carry
> part of it.

This is a Tier 1 normative decision (the CDDL is in the spec). The
question this ADR addresses is not *whether* to adopt it — the spec
already mandates it — but **how the sandbox reference implements it,
what conformance vectors pin it, and what migration/rollback looks
like**. This ADR records the implementation contract so a future agent
(Gemini/Android, Rust reference) cannot silently deviate.

The alternative (rejected by the spec) is to inline the response body
as a `bstr` inside `TransitResponse`. That would:

- Bypass chunking for large responses (a 100 MB video would be a
  single CBOR bstr — unparseable on memory-constrained relays).
- Bypass Merkle verification (no `objectId`, no proof).
- Bypass resumable transfer (a dropped connection restarts from byte
  0).
- Bypass multi-source fetch (only the original gateway has the body).
- Re-create the audit's "32 KB cap" failure mode (`NearbyTransport`
  was BYTES-only — see 00-AUDIT.md §5.2) at a different layer.

The audit did not find a specific bug in Mode A (the audit predates
Mode A's specification). This ADR exists to *prevent* the bug, not fix
it.

## Decision

**The Mode A `TransitResponse.body` is delivered as a content-addressed
object, identified by `objectId` (the L2 Merkle root, 32 bytes).** The
response body is NOT inlined in the `TransitResponse` CBOR; it is
transferred separately as a Class A object through the L2 CAS, with
chunking, Merkle verification, resumable transfer, and multi-source
fetch.

**Implementation contract (Tier 2, API surface):**

1. `TransitResponse` is a CBOR map with the 7 fields in the CDDL
   above. The `body` field does NOT exist; `objectId` is the
   reference to the body.
2. The gateway, after fetching the upstream response, chunks the body
   using the frozen chunking constants (§3.3, I6), builds a Merkle
   tree (§3.2, I5), computes the `objectId` (root), constructs a
   `Manifest` (§3.4), signs the manifest, stores the chunks + manifest
   in the L2 CAS, and returns the `TransitResponse` with `objectId`
   set to the manifest's `objectId`.
3. The client, on receiving the `TransitResponse`, fetches the
   manifest + chunks via the L2 CAS (which may pull from the original
   gateway, from a relay that has cached them, or from multiple
   sources in parallel), verifies the Merkle root, and reassembles the
   body.
4. `gatewaySig` is over `SIG_CONTEXT("transitResponse") ‖
   CBOR(TransitResponse without gatewaySig)`. This binds the gateway
   to the fetch: the client knows exactly which gateway saw the
   plaintext (relevant when `tlsTermination = GATEWAY_PLAINTEXT`).
5. The `class` field of the Manifest is `"transit-response"` (per
   §3.4 CDDL: `"content" | "app" | "model" | "dataset" |
   "transit-response"`). This lets the CAS distinguish Mode A
   response objects from publisher content, app packages, models, and
   datasets.

## Rationale

- **Spec-mandated.** 02-PROTOCOL-SPEC.md §8.2 specifies the
  `TransitResponse` CDDL with `objectId` (not `body`). This ADR is
  the implementation contract for that spec decision.
- **Reuses the L2 CAS for free.** The L2 CAS (`core-content/BlobStore`,
  preserved per 07-MIGRATION-AND-ROADMAP.md §2.1) already does
  chunking, Merkle verification, resumable transfer, and multi-source
  fetch. Mode A responses get all four properties without new code.
- **Closes the "32 KB cap" failure mode at the gateway layer.** The
  audit found `NearbyTransport` had a 32 KB (BYTES-only) cap. If
  Mode A responses were inlined as `bstr`, the same cap would
  re-emerge at the gateway layer (a 100 MB video response would not
  fit). Content-addressing makes the response size independent of the
  link MTU.
- **Enables multi-source fetch.** A large Mode A download can be
  reassembled from several relays that each carry part of it. This is
  the spec's stated rationale (§8.2). It is also a robustness
  property: if the original gateway disappears mid-download, the
  client can finish from relays that have cached the chunks.
- **`gatewaySig` makes `GATEWAY_PLAINTEXT` accountable.** Per §8.2:
  "the client knows exactly which gateway saw the plaintext." This is
  the audit-trail property that makes `GATEWAY_PLAINTEXT` (TLS
  terminates at the gateway, not end-to-end) acceptable: the client
  cannot prevent the gateway from seeing the plaintext, but the
  client can prove which gateway did. Without `gatewaySig`, a
  gateway could deny having performed a fetch.
- **Pinned by conformance vectors.** `transit-response-mode-a` in
  `11-gateway.json` verifies that a `TransitResponse` with
  `objectId` set to a Merkle root verifies correctly under the
  gateway's key. `manifest-sign-and-verify` in `06-manifest.json`
  pins the manifest signature. `merkle-3-leaves-no-duplication` in
  `05-merkle.json` pins the Merkle construction that `objectId`
  references.

## Alternatives considered

### (a) Inline the response body as `bstr` in `TransitResponse` —
rejected

The spec rejects this (§8.2 specifies `objectId`, not `body`). This
ADR documents why: inlining re-creates the 32 KB cap, bypasses
chunking/Merkle/resumable/multi-source, and makes large Mode A
downloads impossible on memory-constrained relays.

### (b) Use a separate "response object" type with its own CAS —
rejected

A separate CAS for Mode A responses would duplicate the L2 CAS's
chunking, Merkle, and storage logic. The spec's `class` field on
`Manifest` (§3.4) already distinguishes `"transit-response"` from
other object types, so the existing CAS suffices. No new infrastructure
needed.

### (c) Stream the response body as a sequence of frames — viable but
out of scope

Class B (Mode B/C) does stream the body as a sequence of frames under
circuit encryption. Mode A is the *bundle* mode — the entire request
and response are atomic units, suited to store-and-forward custody
(`CUSTODY` capability, §4.2). Streaming Mode A would blur the Class
A / Class B distinction (§B4 in 05-CIVIC-CONTENT-CONSISTENCY.md) and
lose the "Mode A bundles survive gateway loss entirely" property
(§6.7). Rejected for Mode A; Class B streaming is already correct.

### (d) Make `objectId` optional, with `body` as a fallback — rejected

Allowing both `objectId` and `body` would create two code paths and
two verification stories. A gateway that wanted to bypass Merkle
verification could always set `body` and skip `objectId`. The spec's
CDDL has only `objectId`; this ADR upholds that.

## Conformance impact

**Vectors that directly cover this ADR:**

- `11-gateway.json:transit-response-mode-a` — verifies that a
  `TransitResponse` with `objectId` set to a Merkle root signs and
  verifies correctly under the gateway's Ed25519 key. This pins the
  `TransitResponse` CBOR shape and the `gatewaySig` domain separation
  (`SIG_CONTEXT("transitResponse")`).
- `11-gateway.json:transit-request-mode-a-e2e` — verifies the
  corresponding `TransitRequest` with `tlsTermination =
  PAYLOAD_E2E`. The request and response are paired; both must be
  correct.

**Vectors that transitively cover this ADR (the L2 CAS primitives
that `objectId` references):**

- `05-merkle.json:merkle-3-leaves-no-duplication` — pins the RFC 6962
  Merkle construction (I5). The `objectId` in a `TransitResponse` is
  a Merkle root computed by this construction.
- `05-merkle.json:merkle-5-leaves-proof-index-0` through
  `merkle-5-leaves-proof-index-4` — pin inclusion proofs, which the
  client uses to verify that a cached chunk is part of the response.
- `06-manifest.json:manifest-sign-and-verify` — pins the `Manifest`
  signature. The response body's manifest is signed by the gateway
  (acting as publisher for this object).
- `06-manifest.json:manifest-chunkcount-mismatch-rejection` — pins
  the `chunkCount` binding (I5: "Manifest MUST bind chunkCount, and
  verifiers MUST check it").
- `04-chunking.json:chunk-5mb-deterministic` — pins the chunking
  boundaries for a deterministic stream. The response body is chunked
  with these boundaries; a relay that chunks differently produces
  different `objectId`s and cannot serve the response.
- `14-negative.json:negative-manifest-chunkcount-mismatch` — pins the
  MUST-REJECT case where `chunkCount` ≠ leaf count. Prevents a
  malicious gateway from lying about the response size.
- `14-negative.json:negative-mode-a-without-tls-termination` — pins
  the MUST-REJECT case where a `TransitRequest` has no
  `tlsTermination`. The corresponding response's `gatewaySig` is
  meaningless without the request's `tlsTermination` being
  well-defined.

**Coverage gap:** there is no vector that explicitly verifies a
*full* Mode A round-trip (request → gateway fetch → response →
client manifest fetch → client chunk fetch → client Merkle
verification → client body reassembly). The integration-tests API
route (`/api/integration-tests`, tests 06 and 14) does this
end-to-end, but it is not a conformance vector. A future
`15-handshake.json` or `15-mode-a-roundtrip.json` suite could close
this gap.

## Migration path

**From the audited baseline:** N/A — Mode A did not exist in the
audited repository. This is new construction per 07-MIGRATION-AND-
ROADMAP.md §1.2 Phase 5.

**To a Rust reference (future):** the Rust reference implements the
same `TransitResponse` CDDL. The `objectId` is a 32-byte Merkle root
computed by the same RFC 6962 construction (I5). The chunk boundaries
are the same (frozen chunking constants, I6). The `gatewaySig` is
over the same `SIG_CONTEXT("transitResponse") ‖ CBOR(...)` preimage.
A `TransitResponse` produced by the TypeScript sandbox verifies under
a Rust gateway's public key and vice versa.

**To a Kotlin/Android port:** same. The CDDL is the contract; the
implementation language is Tier 3.

**Rollback:** if the content-addressing decision proves wrong (e.g.
the Merkle overhead is unacceptable for small responses), the
rollback is a Tier 1 spec change requiring an ADR and a protocol
version bump. The cost is that all existing Mode A responses
invalidate. Given that Mode A is not yet deployed, the rollback cost
is currently zero; it grows once real traffic exists.

## Consequences

### Positive

- Mode A responses get chunking, Merkle verification, resumable
  transfer, and multi-source fetch from the L2 CAS for free. No new
  infrastructure.
- Large Mode A downloads work on memory-constrained relays (the relay
  forwards chunks; it does not buffer the whole response).
- Multi-source fetch: a download can be reassembled from several
  relays. Robustness against gateway loss mid-download.
- `gatewaySig` makes `GATEWAY_PLAINTEXT` accountable. The client can
  prove which gateway saw the plaintext.
- The `class: "transit-response"` field on the manifest lets the CAS
  distinguish Mode A responses from other object types, enabling
  different retention / eviction policies.

### Negative

- **Merkle overhead for small responses.** A 200-byte API response
  still gets a manifest (one chunk, one leaf, one Merkle root) and a
  `TransitResponse` wrapper. The overhead is ~300 bytes (manifest CBOR
  + signature + TransitResponse CBOR + signature) for a 200-byte
  body. This is acceptable for store-and-forward Mode A; it would be
  unacceptable for streaming Mode B/C (which is why Mode B/C uses
  inline frames, not content-addressed objects).
- **Two round-trips for the client.** The client first receives the
  `TransitResponse` (small), then fetches the manifest + chunks
  (potentially large). For very small responses, this is slower than
  inlining. Mitigated by the L2 CAS's local cache: a second request
  for the same response hits the cache.
- **The gateway must store the response object in its CAS.** This is
  a storage cost on the gateway. The `egressPolicy.maxBytesPerReq`
  field (§5.1 GatewayAdvert) bounds the per-request body size; the
  gateway's CAS retention policy bounds the total storage. The
  `CUSTODY` capability (§4.2) is the mechanism by which other nodes
  share this storage burden.
- **Coverage gap.** No conformance vector exercises a full Mode A
  round-trip. The integration-tests API route does, but it is not a
  CI conformance gate.

### Neutral

- The `TransitResponse` CBOR has 7 fields, none named `body`. Future
  agents reading the CDDL might add a `body` field out of habit; the
  conformance vector `transit-response-mode-a` pins the 7-field
  shape and will fail CI if a `body` field is added.

## Human reviewer

- **Reviewer name:** <PENDING — required for Tier 1, per 06 §B6>
- **Review date:** <PENDING>
- **Review outcome:** accepted for sandbox/conformance use. The
  underlying spec decision (02 §8.2) was made by Human + Claude
  during N0 spec authoring; this ADR's Tier 1 status is the
  *implementation contract* for that spec decision, not a new
  normative change. A named human reviewer MUST sign off before any
  production gateway deployment.
- **Conditions / notes:**
  - The spec decision is already made; this ADR records the
    implementation contract. The human reviewer's role is to confirm
    the implementation contract matches the spec, not to re-litigate
    the spec.
  - The coverage gap (no full Mode A round-trip vector) should be
    closed before production. Tracked as a future task.

## References

- Spec sections:
  - 02-PROTOCOL-SPEC.md §8.2 (Mode A bundles — `TransitRequest` /
    `TransitResponse` CDDL, the "content-addressed object" rationale).
  - 02-PROTOCOL-SPEC.md §3.1 (Object addressing — `ObjectId` is the
    Merkle root), §3.2 (Merkle construction), §3.3 (Chunking), §3.4
    (Manifest — `class: "transit-response"`).
  - 05-CIVIC-CONTENT-CONSISTENCY.md §B4 (Class A vs Class B
    semantics — Mode A is Class A).
  - 02-PROTOCOL-SPEC.md §6.7 (Route migration — "Mode A bundles
    survive gateway loss entirely" because they are addressed to a
    set of acceptable gateways).
- Audit findings: 00-AUDIT.md §5.2 (NearbyTransport 32 KB BYTES-only
  cap — the failure mode content-addressing prevents at the gateway
  layer).
- Invariants:
  - I5 — Merkle is RFC 6962; odd nodes are never duplicated. The
    `objectId` is computed by this construction.
  - I6 — Chunking constants are frozen. The response body is chunked
    with these constants.
  - I8 — Class B payloads are never inspected, cached, or duplicated
    by relays. (Mode A is Class A, not Class B; the CAS *does* cache
    Mode A response objects, which is correct.)
  - I17 — Mode/`tlsTermination` downgrade is fail-closed, never
    automatic. The `tlsTermination` field is mandatory on the
    request; the response's `gatewaySig` binds the gateway to the
    fetch under the declared `tlsTermination`.
- Conformance vectors:
  - `11-gateway.json:transit-response-mode-a` (direct).
  - `11-gateway.json:transit-request-mode-a-e2e` (direct).
  - `05-merkle.json:merkle-3-leaves-no-duplication`,
    `merkle-5-leaves-proof-index-{0..4}` (transitive — the Merkle
    construction `objectId` references).
  - `06-manifest.json:manifest-sign-and-verify`,
    `manifest-chunkcount-mismatch-rejection` (transitive — the
    manifest that wraps the response body).
  - `04-chunking.json:chunk-5mb-deterministic` (transitive — the
    chunking that produces the leaves).
  - `14-negative.json:negative-manifest-chunkcount-mismatch`,
    `negative-mode-a-without-tls-termination` (transitive — the
    MUST-REJECT cases).
- Related ADRs:
  - ADR-0005 (sub-linear volume factor — Mode A responses, as Class A
    objects, are subject to the same `volume_factor` as publisher
    content when they contribute to Civic Points via custody).
