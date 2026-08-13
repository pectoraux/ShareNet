# ADR-0009: Mode A Response Object Hashing Semantics

**Status:** accepted  
**Tier:** 1 (normative — resolves spec ambiguity)  
**Date:** 2026-08-12  
**Deciders:** PENDING (required before N5 production gateway)  

---

## Context

The N1.6 audit found that the mesh simulator computes:

```
objectId = SHA-256(responseBody.slice(0, maxResponseBytes))
```

This truncates the response body to `maxResponseBytes` BEFORE hashing. The
audit asked: is this correct per the normative specification?

The spec (02-PROTOCOL-SPEC.md §8.2) says:

```
TransitResponse = {
  ...
  objectId:   bstr .size 32,     ; body is a Class A object — reuses CAS
  ...
}
```

And the content layer (§3.1) says:

```
ObjectId := merkle_root(chunks)
```

So there are three possible interpretations:

**A.** `objectId = SHA-256(complete remote response body)`  
   — hash the entire response, no cap. Problem: `maxResponseBytes` exists
   precisely to bound storage; an uncapped hash would require downloading
   the entire response.

**B.** `objectId = merkle_root(chunk(capped response body))`  
   — cap to `maxResponseBytes`, then chunk and Merkle-root per §3.1-3.2.
   This is the "pure" reading of the spec: the response IS a Class A object.

**C.** `objectId = SHA-256(capped response body)`  
   — cap to `maxResponseBytes`, then simple SHA-256. This is what the
   simulator currently does.

## Decision

**Option C is the correct interpretation for the simulator.**

Rationale:
1. `maxResponseBytes` is mandatory (§8.2) and bounds relay storage. The
   gateway MUST NOT download more than this. So the cap is applied FIRST.
2. The `objectId` identifies the bounded representation the protocol
   actually transfers — not the unbounded remote response.
3. In production (Option B), the capped body would be chunked and Merkle-
   rooted per §3.1-3.2, reusing the full content layer. But the simulator
   does not implement chunking for Mode A responses; it uses a simple
   SHA-256 as a simplified objectId.
4. The simulator's `objectId` is still useful: the client can verify that
   the response body matches the signed `objectId`, proving the gateway
   attests to the exact bytes it returned.

**Production target:** Option B. The production gateway MUST:
1. Download up to `maxResponseBytes`
2. Chunk the downloaded bytes per §3.3 (Gear CDC, frozen constants)
3. Compute `objectId = merkle_root(leaf_hashes)`
4. Store the chunks in the CAS
5. The client fetches chunks via the content layer and verifies the Merkle root

The simulator's Option C is a simplification that preserves the security
property (gateway attests to the exact bytes) without the full content layer.

## Conformance impact

No conformance vectors are affected. The `TransitResponse.objectId` is
generated and verified within the integration tests, not by the conformance
suite. When the production gateway implements Option B, a new conformance
suite for Mode A response chunking should be added.

## Alternatives considered

- **Option A (hash complete response):** Rejected because it defeats the
  purpose of `maxResponseBytes`. A 10 GB response would require downloading
  10 GB before the gateway could even compute the hash.

- **Option B (Merkle root of chunks):** This is the production target. It
  is not used in the simulator because the simulator does not implement
  the full content layer for Mode A responses. Implementing it would add
  complexity without proving anything new (the chunking and Merkle logic
  is already verified by suites 04-chunking and 05-merkle).

## Migration path

When the production gateway (N5) is implemented:
1. Replace `hashSha256(responseBody)` with `merkleRoot(chunk(responseBody).map(leafHash))`
2. Store the chunks in the CAS
3. The TransitResponse carries the Merkle root as `objectId`
4. The client fetches chunks via the content layer
5. Add a conformance suite for Mode A response chunking

## References

- 02-PROTOCOL-SPEC.md §8.2 (TransitResponse)
- 02-PROTOCOL-SPEC.md §3.1 (ObjectId)
- 02-PROTOCOL-SPEC.md §3.2 (Merkle construction)
- 02-PROTOCOL-SPEC.md §3.3 (Chunking)
- N1.6 audit finding: "objectId = SHA-256(responseBody) against the normative specification"
