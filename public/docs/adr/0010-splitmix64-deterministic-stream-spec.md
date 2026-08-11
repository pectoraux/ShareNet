# ADR-0010: SplitMix64 Deterministic Test Stream Generation

**Status:** accepted  
**Tier:** 1 (normative — resolves spec ambiguity)  
**Date:** 2026-08-12  
**Deciders:** PENDING (required before production)  

---

## Context

The N1.7 Rust conformance core independently discovered that the specification
(02-PROTOCOL-SPEC.md §3.3) says "splitmix64 table" for the Gear chunking
table, but does NOT specify how the deterministic test streams for chunking
vectors are generated.

The committed chunking vectors (`04-chunking.json`) include:
- `chunk-5mb-deterministic`: a 5 MiB stream generated from "seed=7"
- `chunk-max-plus-1`: a stream generated from "seed=99"

The TypeScript implementation (`src/lib/snp/chunking.ts`) uses a function
`deterministicStream(seed, length)` that generates bytes via splitmix64 in
counter mode, emitting 8 little-endian bytes per call. But this function is
an IMPLEMENTATION detail — it's not in the normative spec.

The Rust implementation had to independently derive this by brute-force
search against the committed boundary values. That's exactly the kind of
hidden assumption that caused the original ShareNet interoperability
problem (audit §3.2: Kotlin and Python CBOR disagreed because the spec
didn't pin the exact encoding).

## Decision

**Promote the SplitMix64 deterministic stream generation to normative spec.**

The conformance vector generation procedure for chunking test streams is:

```
deterministicStream(seed: bigint, length: number) -> Uint8Array:
  state = seed
  output = []
  while output.length < length:
    state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    x = state
    z = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    z = z ^ (z >> 31)
    // Emit 8 bytes, little-endian
    for j in 0..8:
      output.push(z & 0xFF)
      z = z >> 8
  return output[0..length]
```

This is splitmix64 (https://prng.di.unimi.it/splitmix64.c) in counter mode:
the state is incremented by the golden gamma before each output, and each
output produces 8 little-endian bytes.

## Rationale

1. **Reproducibility**: Any independent implementation must be able to
   generate the exact same test streams from the same seeds. Without this
   spec, implementers have to reverse-engineer the generation procedure.

2. **Not a CSPRNG**: This is for TEST VECTOR generation only, not for
   cryptographic key material. SplitMix64 is a fast, deterministic PRNG
   with good distribution properties — appropriate for testing chunk
   boundary detection.

3. **Already frozen in practice**: The committed vectors depend on this
   exact procedure. Changing it would invalidate every chunking vector.
   This ADR makes the implicit dependency explicit.

## Conformance impact

No vectors change. This ADR documents the procedure that was already
implicitly required. The Rust implementation independently derived this
procedure and produces identical streams — confirming it is reproducible.

## Alternatives considered

- **Use a standard test vector format (e.g. NIST CAVP)**: Rejected because
  chunking boundaries depend on the byte content, and we need deterministic
  multi-megabyte streams. Standard test vectors don't provide this.

- **Specify a different PRNG (e.g. xoshiro256)**: Rejected because
  splitmix64 is already what the TypeScript implementation uses, and the
  vectors are already committed. Changing the PRNG would invalidate all
  chunking vectors without any protocol benefit.

- **Remove deterministic streams from the spec**: Rejected because chunking
  boundary detection MUST be deterministic across implementations — that's
  the whole point of the frozen Gear table and the chunking conformance
  vectors.

## Migration path

None needed. This ADR documents existing behavior. Future implementations
(TS, Python, Rust, Kotlin) MUST implement `deterministicStream` per this
specification to reproduce the chunking vectors.

## References

- 02-PROTOCOL-SPEC.md §3.3 (Chunking)
- 06-CONFORMANCE-AND-AI-MODEL.md §A4 (Required suites — chunking)
- src/lib/snp/chunking.ts `deterministicStream` (TypeScript reference)
- reference/snp-object/src/lib.rs (Rust independent implementation)
- splitmix64 reference: https://prng.di.unimi.it/splitmix64.c
- N1.7 audit finding: "spec says splitmix64 table but doesn't specify the
  PRNG for deterministic test streams"
