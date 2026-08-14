# ShareNet Protocol Freeze Notice

## N2.3 — Frozen Protocol

**Frozen commit:** `425eccb`
**Frozen at:** 2026-08-14
**Status:** ACCEPTED / FROZEN

This document defines the immutable boundary for the N2.3 protocol. The
N2.3 milestone is declared frozen. No further architectural changes to the
N2.3 protocol semantics are permitted without a formal protocol evolution
process.

## Wire compatibility statement

The N2.3 freeze includes two packet profiles:

### V1 (frozen N2.3 legacy)

- 5-field CBOR map: `circuitId`, `seq`, `ttl`, `payload`, `finalDst`
- AAD: `circuit_id ‖ seq(BE) ‖ ttl ‖ final_dst` (no domain prefix)
- Nonce: `circuit_id[0..8] ‖ seq(BE)` (no direction XOR)
- Forward-only, no direction, no flow_id
- Circuit-profile selected (no wire self-description)
- Golden wire vector: `public/conformance/vectors/11-circuit-packet-v1.json`

### V2 (N2.4 groundwork, forward-only in N2.3 scope)

- 8-field CBOR map: `circuitId`, `direction`, `flowId`, `v`, `seq`, `ttl`, `payload`, `finalDst`
- AAD: `"SNP/0.1/circuit/packet/v2" ‖ circuit_id ‖ direction ‖ flow_id ‖ seq(BE) ‖ ttl ‖ final_dst`
- Nonce: `(circuit_id[0..8] ⊕ direction) ‖ seq(BE)`
- Wire self-describing (`"v": 2` field)
- Direction + flow_id bound in AAD

V1 and V2 are NOT wire-compatible.

## Allowed changes (post-freeze)

- Bug fixes that do not change wire bytes, AAD, nonce, or forwarding semantics
- Documentation improvements
- Performance optimizations (no behavioral change)
- New tests (without modifying existing frozen tests or vectors)

## Forbidden changes (post-freeze)

- Modifying `CircuitPacketV1` (struct, encode, decode, AAD, nonce, CBOR)
- Modifying the V1 golden wire vector JSON
- Modifying V1 AAD construction (`v1_packet_aad`)
- Modifying V1 nonce derivation (`v1_packet_nonce`)
- Modifying V1 forwarding behavior (`forward_packet_v1`)
- Modifying the V1 conformance ADR (`N2.3-V1-CONFORMANCE.md`)
- Changing the V2 `"v"` field value or semantics
- Changing the V2 AAD domain prefix
- Changing the V2 nonce derivation
- Removing or weakening any N2.3 security invariant

## Migration rules

Any protocol evolution (V3, N2.4 freeze, etc.) requires:

1. A new ADR documenting the change
2. A new `PacketProfile` variant
3. New golden vectors for the new profile
4. V1 and V2 golden vectors must remain unchanged
5. The `PacketProfile` enum must not remove existing variants
6. Explicit architectural approval

## Git tag

```
tag: n2.3-frozen
commit: 425eccb
```

## CI freeze guard

Future CI should reject:
- Changes to `reference/snp-node/src/node/traffic.rs` that modify V1 functions
  (prefixed `v1_` or in the `CircuitPacketV1` impl block)
- Changes to `public/conformance/vectors/11-circuit-packet-v1.json`
- Changes to `public/docs/adr/N2.3-V1-CONFORMANCE.md`

unless a "protocol-evolution" label is present on the PR.
