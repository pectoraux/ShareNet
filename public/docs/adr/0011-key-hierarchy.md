# ADR-0011: Key Hierarchy — Hop, Circuit, Identity, and Handshake Keys

**Status:** accepted  
**Tier:** 1 (normative — defines the key separation architecture)  
**Date:** 2026-08-12  
**Deciders:** PENDING (required before production)  

---

## Context

N1.9 introduced directional link keys and circuit encryption, but the key
hierarchy was not formally documented. The N1.9.1 audit requested an
explicit freeze of the distinction between:

- Hop keys (per-link)
- Circuit keys (end-to-end)
- Identity keys (Ed25519)
- Handshake-derived keys (future)

This ADR freezes the key hierarchy so that N2.0 (multi-hop sessions) and
Gemini (Android) have a clear, normative reference.

## Decision

### Key Hierarchy

```
┌────────┐  hop key S1 (directional)  ┌───────┐  hop key S2 (directional)  ┌─────────┐
│ Client │ ────────────────────────── │ Relay │ ────────────────────────── │ Gateway │
└────────┘                             └───────┘                             └─────────┘
     │                                                                        │
     └────────── circuit key S3 (directional) — relay does NOT possess ────────┘
```

### Layer 1: Hop Keys (per-link)

Each TCP link has its own directional key pair:

- `S1` = Client ↔ Relay hop key
- `S2` = Relay ↔ Gateway hop key
- (In multi-hop: `S3` = Relay ↔ Relay, `S4` = Relay ↔ Gateway, etc.)

Derivation:
```
base = HKDF-SHA256(seed, salt="SNP/0.1 link base", info="", L=32)
i2r  = HKDF-SHA256(base, salt="SNP/0.1 link dir", info="initiator-to-responder", L=32)
r2i  = HKDF-SHA256(base, salt="SNP/0.1 link dir", info="responder-to-initiator", L=32)
```

- **Initiator** (the node that opens the TCP connection): `send_key = i2r, recv_key = r2i`
- **Responder** (the node that accepts the TCP connection): `send_key = r2i, recv_key = i2r`

**Purpose:** Protects traffic on a single physical/logical hop. The relay
can decrypt hop-level frames (it needs to read `dst` and `ttl` for
forwarding), but the frame BODY is the circuit ciphertext, which the relay
cannot read.

**N1.9.1 status:** Test-only (deterministic seeds). Production target:
derived from the SNP-IK/0.1 handshake transcript (ADR-0006).

### Layer 2: Circuit Keys (end-to-end)

The client and gateway share a directional key pair that NO relay possesses:

- `C` = Client ↔ Gateway circuit key (directional)

Derivation (same HKDF pattern as hop keys):
```
base = HKDF-SHA256(circuit_seed, salt="SNP/0.1 circuit base", info="", L=32)
i2r  = HKDF-SHA256(base, salt="SNP/0.1 circuit dir", info="initiator-to-responder", L=32)
r2i  = HKDF-SHA256(base, salt="SNP/0.1 circuit dir", info="responder-to-initiator", L=32)
```

- **Client** (circuit initiator): `send_key = i2r, recv_key = r2i`
- **Gateway** (circuit responder): `send_key = r2i, recv_key = i2r`

**Purpose:** Protects the TransitRequest/TransitResponse body end-to-end.
The relay forwards the circuit ciphertext verbatim — it never has the key
to decrypt it. This is **cryptographic** non-inspection, not just policy.

**Circuit nonce:** 12 bytes from `getrandom()` (OS CSPRNG). Unique per
encryption under a given key. The 2^96 collision space makes reuse
negligibly probable (birthday bound ~2^48 messages).

**N1.9.1 status:** Test-only (deterministic circuit seed). Production
target: the circuit seed is derived from the SNP-IK/0.1 handshake between
client and gateway, so the relay (which only participates in hop
handshakes) cannot derive it. **Until SNP-IK/0.1 is implemented, the
circuit key is explicitly marked TEST-ONLY.**

### Layer 3: Identity Keys (Ed25519)

Each node has an Ed25519 keypair that serves as its identity:

- NodeIdentity: Ed25519, rotatable per epoch
- UserIdentity: Ed25519, offline, never on the wire
- DeviceIdentity: Ed25519, per-device
- EconomicIdentity: Ed25519, settlement only

**Purpose:** Signing NodeDescriptors, TransitResponses, receipts, and
other protocol structures. The client verifies the gateway's
TransitResponse signature using the gateway's identity key (obtained from
the gateway's signed NodeDescriptor).

**N1.9.1 status:** Implemented and verified. Ed25519 signatures are
independently verified across TypeScript (@noble/ed25519), Python (PyNaCl),
and Rust (ed25519-dalek) with zero disagreements.

### Layer 4: Handshake-Derived Keys (future)

The SNP-IK/0.1 handshake (ADR-0006) will derive hop keys from:
1. Ephemeral X25519 key agreement
2. Both parties' signed NodeDescriptors
3. HKDF over the DH shared secret

The circuit key will be derived from a SEPARATE handshake between client
and gateway (which the relay does not participate in).

**N1.9.1 status:** NOT IMPLEMENTED. Hop and circuit keys use deterministic
test seeds. This is the primary remaining security shortcut.

## Key Independence

The following properties are verified by N1.9.1 Test 7:

1. Hop keys S1 and S2 are cryptographically independent (different seeds,
   different HKDF info strings).
2. Circuit key C is cryptographically independent of ALL hop keys.
3. A relay that possesses S1 (send+recv) and S2 (send+recv) CANNOT derive
   or brute-force C.
4. The directional separation (i2r vs r2i) prevents nonce reuse across
   directions under the same key.

## Conformance impact

No conformance vectors are affected. The key hierarchy is an architectural
property, not a wire-format property. The AEAD vectors (suite 15) verify
the AEAD primitive; the key hierarchy verifies how keys are DERIVED and
SEPARATED.

## References

- ADR-0006: SNP-IK/0.1 custom handshake (the production handshake target)
- ADR-0008: Gateway DNS rebinding defence (the PinnedConnector)
- 02-PROTOCOL-SPEC.md §7.2 (Noise_IK → SNP-IK/0.1)
- 02-PROTOCOL-SPEC.md §7.3 (Circuit encryption)
- reference/snp-link/src/lib.rs (Rust implementation)
- reference/snp-node/tests/n19_security.rs (security regression tests)
