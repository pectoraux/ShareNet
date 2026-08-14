# ShareNet Spec — Circuits

**Normative.** RFC 2119 keywords. This document defines the circuit layer independently of any platform.

The implementation authority is the Rust reference at `reference/snp-node/src/node/`. This specification is the frozen description; the implementation MUST conform to it.

---

## N2.1.3 — Circuit Cryptographic Setup

**Status: CLOSED (per ADR-0012)**

N2.1.3 is **source-side cryptographic preparation only**. It does NOT establish a distributed circuit. No relay receives the handshake, verifies it, derives its key, or acknowledges establishment. No forwarding state is installed on any remote participant.

### Pipeline

```text
CommittedRoute (agreement + evidence)
        ↓
CircuitHandshake (signed by source, bound to commitment hash)
        ↓
Per-hop X25519 DH + HKDF-SHA256 key derivation
        ↓
CircuitSetup (source-side cryptographic preparation artifact)
```

### CircuitSetup is NOT

- A live circuit
- Forwarding state
- An established session
- Installed on any relay

### CircuitSetup IS

- Source-side cryptographic preparation
- Per-hop forwarding keys (derived locally via X25519 DH + HKDF)
- Binding to a CommittedRoute (via commitment hash)
- A unique `circuit_id` (for instance identification — NOT replay prevention by itself)
- Handshake + teardown messages (ready to be sent, but not yet sent)

### `circuit_id`

`circuit_id` uniquely identifies a circuit instance. Random uniqueness helps distinguish circuit instances. It is **NOT** replay protection by itself. Replay protection requires receiver-side acceptance state (`CircuitAcceptanceStore`, normative as of N2.2 — see below).

### X25519 Circuit Key Requirement (per ADR-0013)

```text
INTERNET_GATEWAY capability
    → X25519 circuit public key REQUIRED

RELAY capability (participating in circuits)
    → X25519 circuit public key REQUIRED

Other nodes
    → X25519 circuit public key OPTIONAL
```

A relay without an X25519 circuit key cannot participate in circuits. `prepare_circuit_setup()` rejects such hops with `HopMissingCircuitKey`.

### Fail-closed principle

- All CBOR encoding uses `map_err` (no `unwrap_or_default`).
- OS randomness (`circuit_id`, `nonce`) is checked (no `let _ =`).
- `RouteSerializationError` propagates through all creation paths.

---

## N2.2 — Distributed Circuit Establishment & Forwarding State

**Status: CLOSED**

N2.2 establishes a distributed circuit: each relay independently verifies the source-signed handshake, proves X25519 key possession, derives its forwarding key, installs forwarding state, and acknowledges. An `ActiveCircuit` (live distributed state) is produced only after ALL required relays acknowledge.

### Pipeline

```text
CircuitSetup (N2.1.3)
        ↓
SignedHopAuthorization (per relay, signed by source)
        ↓
authorization_root = SHA-256(hash(auth_1) ‖ … ‖ hash(auth_n))
        ↓
RelayHandshakeRequest → each relay
        ↓
Each relay: verify handshake + verify authorization signature +
            prove X25519 key possession (DH proof) +
            verify authorization membership in authorization_root +
            record acceptance (CircuitAcceptanceStore, BEFORE state install)
        ↓
Each relay installs RelayForwardingState
        ↓
Each relay returns RelayHandshakeResponse (signed)
        ↓
Source verifies all responses (signature + DH proof + authorization hash)
        ↓
ActiveCircuit (live distributed forwarding state)
```

### Normative requirements (N2.2)

#### `SignedHopAuthorization`

Each non-source hop's position (relay NodeId, predecessor, successor, role, hop_index, X25519 public key) is signed by the source's Ed25519 key. A relay verifies this signature (using `handshake.source_public_key`) BEFORE installing forwarding state. A malicious intermediary that tampers with any position field breaks the signature — fail-closed.

#### `authorization_root`

The handshake commits to the EXACT set of relay authorizations:

```text
authorization_root = SHA-256(
    SHA-256(auth_1.canonical_preimage) ‖
    SHA-256(auth_2.canonical_preimage) ‖
    … ‖
    SHA-256(auth_n.canonical_preimage)
)
```

This is signed inside the `CircuitHandshake`. It prevents split-view attacks where different relays receive different (individually signed) authorizations for the same circuit.

#### `authorization_count`

The handshake carries a signed `authorization_count: u8` bounding the number of relay authorizations. The relay verifies:

- `authorization_count <= ROUTE_MAX_HOPS - 1`
- `authorization_hashes.len() == authorization_count`
- no duplicate hashes
- the relay's own authorization hash is in the set
- `SHA-256(concat(all hashes)) == handshake.authorization_root`

This gives the relay an authenticated cardinality bound without needing the `CommittedRoute`.

#### Relay-side DH proof

Each relay computes `DH(relay_x25519_private, source_ephemeral_public)` and includes `SHA-256(dh_secret)` in its signed response. The source verifies this matches the DH it computed locally — proving the relay possesses the X25519 private key without revealing it.

#### `CircuitAcceptanceStore`

Each relay maintains a per-circuit acceptance store to reject duplicate handshakes (replay). Acceptance is recorded BEFORE forwarding state is installed — even if state installation is interrupted, the replay check fires on the next attempt.

#### `ActiveCircuit`

An `ActiveCircuit` is produced ONLY after every required relay has acknowledged. It is **NOT `Clone`** — the circuit owns the packet-sequence namespace (see N2.3). It carries:

- `circuit_id`, `commitment_hash`, `source`, `destination`
- `relay_responses` (all acknowledgements)
- `hops` (per-hop forwarding state, confirmed by relays)
- `established_at`, `expires_at`
- `seq_state` (the circuit-owned sequence allocator — see N2.3)

#### `RelayForwardingState`

Installed on each relay after accepting a circuit:

- `circuit_id`
- `predecessor_node_id` (who sends to this relay)
- `successor_node_id` (who this relay forwards to; `None` for gateway)
- `forwarding_key` (derived from X25519 DH + HKDF)
- `role` (Relay or Gateway)
- `expires_at` (from the signed `CircuitHandshake.expiry`; enforced in N2.3)

#### Circuit expiry

The circuit's lifetime is bounded by `expires_at`, taken from the signed `CircuitHandshake.expiry`. After expiry, the circuit MUST NOT produce or forward packets (enforced in N2.3).

### NOT in N2.2

- Actual traffic forwarding (N2.3).
- TCP connection migration (N2.1.4+, spec §39).
- Route failure / recovery (N2.1.4, spec §39).
- Key rotation within a live circuit (N2.1.4+).

---

## N2.3 — Traffic Forwarding over ActiveCircuit

**Status: IMPLEMENTATION CANDIDATE (frozen for review)**

N2.3 proves that an encrypted packet genuinely traverses the installed relay forwarding state from source to destination. This is the first proof that ShareNet is a functioning mesh network — not merely a protocol/data-model project.

### Acceptance test

```text
A ──sealed packet──> B ──sealed packet──> C ──plaintext──> G
```

where B and C consult their installed `RelayForwardingState` (from N2.2's `accept_relay_handshake`), unwrap one AEAD layer, and forward. A never talks directly to G. A three-hop (A→B→C→G) traversal MUST be proven.

### CircuitPacket wire format

```text
CircuitPacket = {
  circuitId : bstr .size 32,   ; the circuit this packet belongs to
  seq       : uint,            ; per-circuit sequence number (starts at 1)
  ttl       : uint,            ; hop budget, decremented per relay, drop at 0
  payload   : bstr,            ; sealed (AEAD) bytes, one layer per non-source hop
  finalDst  : bstr .size 32,   ; terminal destination NodeId (gateway)
}
```

The payload is bounded by `MAX_WIRE_PAYLOAD_BYTES` (see Payload limits below). The decoder MUST reject oversized payloads at the CBOR head, before allocation.

### Per-hop onion AEAD

The source wraps the payload in nested ChaCha20-Poly1305 layers, **one per non-source hop, including the terminal gateway**, in reverse traversal order. Each relay peels exactly one layer with its `forwarding_key`. The terminal gateway peels the final layer to recover the plaintext.

**General invariant:** ONE AEAD LAYER PER NON-SOURCE HOP, INCLUDING THE TERMINAL GATEWAY. For a route A → B → C → G, there are three non-source hops (B, C, G), so the source creates three nested AEAD layers.

#### Concrete example: A → B → C → G

```text
source constructs:
  inner   = plaintext (for G)

  layer_G = AEAD_seal(key_G, nonce, inner,
                      aad = circuit_id ‖ seq ‖ ttl_G ‖ final_dst)

  layer_C = AEAD_seal(key_C, nonce, layer_G,
                      aad = circuit_id ‖ seq ‖ ttl_C ‖ final_dst)

  layer_B = AEAD_seal(key_B, nonce, layer_C,
                      aad = circuit_id ‖ seq ‖ ttl_B ‖ final_dst)

  packet  = { circuit_id, seq, ttl, payload = layer_B, final_dst }
```

where `ttl_B` is the TTL the first relay sees (`PACKET_TTL_MAX`), `ttl_C = ttl_B - 1`, `ttl_G = ttl_B - 2`. Each layer authenticates the hop-local TTL that relay is expected to see.

#### Forwarding sequence

```text
A → B:  B unwraps layer_B → reveals layer_C  → forwards to C
B → C:  C unwraps layer_C → reveals layer_G  → forwards to G
C → G:  G unwraps layer_G → reveals plaintext → delivers locally
```

A non-terminal relay always treats the decrypted inner bytes as the **next AEAD layer** (for its successor). Only the terminal gateway (successor = `None`) treats the inner bytes as the plaintext to deliver. A relay cannot skip a hop — each layer reveals only the next successor's sealed payload.

### AEAD AAD (normative)

The AAD for each hop's AEAD layer is:

```text
AAD = circuit_id ‖ seq(BE) ‖ ttl ‖ final_dst
```

where `ttl` is the hop-local TTL for the relay opening that layer. An attacker who modifies `ttl`, `circuit_id`, `seq`, or `final_dst` in transit breaks the AEAD authentication. The AAD is NOT a single end-to-end immutable value — each nested layer authenticates the TTL that specific hop will see.

### Sequence namespace (circuit-owned allocator)

The packet sequence allocator is owned by the `ActiveCircuit`, not by an independently-constructible sender object.

#### `CircuitSeqState` (pub(crate))

- `next_seq: u32` — the next sequence to assign.
- `exhausted: bool` — whether `u32::MAX` has been assigned.
- `pub(crate)` — external crates cannot construct a second allocator for an existing circuit.
- NOT `Clone`.

#### `CircuitSender<'_>` (borrowed handle)

- Borrows `&mut` the circuit's `CircuitSeqState` + `&` the circuit's hops/id/dst/expires_at.
- The `&mut` borrow prevents two concurrent sender handles — the borrow checker enforces uniqueness.
- NOT `Clone`.

#### `ActiveCircuit` ownership

- `ActiveCircuit` owns the `CircuitSeqState`.
- `ActiveCircuit` is NOT `Clone` (cloning would duplicate the sequence namespace → AEAD nonce reuse).
- The only production packet-creation APIs are `ActiveCircuit::send_packet(plaintext, now)` and `ActiveCircuit::sender()`.
- `wrap_packet(seq: u32)` is `pub(crate)` — not accessible to external production callers. Test-only aliases (`wrap_packet_for_testing`, `new_standalone_for_testing`, `new_at_seq_for_testing`) are feature-gated behind `test-utils` and absent from production builds.

#### Sequence lifecycle (no wrap, no reuse)

- First sequence = `FIRST_PACKET_SEQ` (= 1).
- Strictly monotonically increasing per circuit.
- `seq == 0` is INVALID — the relay rejects it with `SequenceZero` before AEAD.
- `seq == u32::MAX` (`MAX_PACKET_SEQUENCE`) is the last valid sequence.
- After `u32::MAX`, the circuit is `SequenceExhausted` — NO wraparound to 0.
- The circuit MUST be torn down and re-established before further traffic.
- A failed packet construction (e.g. `PayloadTooLarge`) MUST NOT consume a sequence number — the sequence is committed only after successful packet construction.

### Replay window

#### Ordering: check-before-AEAD, commit-after-AEAD

```text
circuit lookup
    ↓
predecessor check
    ↓
READ-ONLY replay check (check)
    ↓
AEAD authentication
    ↓
COMMIT replay state (commit)  ← only on success
    ↓
forward/deliver
```

A packet that fails AEAD MUST NOT mutate replay state. This prevents an unauthenticated attacker from poisoning the replay window.

#### O(WINDOW) update

The replay window is a fixed-size bit window (`REPLAY_WINDOW_SIZE` = 1024 slots). The commit operation is O(WINDOW):

- If `delta = seq - max_seen >= WINDOW`: clear the entire window (O(WINDOW)).
- Else: clear only `delta` slots (O(delta) ≤ O(WINDOW)).
- NEVER iterate `max_seen..seq` (that was a CPU DoS).

### TTL semantics

- `ttl` starts at `PACKET_TTL_MAX` (= `ROUTE_MAX_HOPS`).
- Each relay decrements `ttl` by 1 before forwarding.
- `ttl == 0` → `TtlExhausted` (drop, do not forward).
- `ttl` is authenticated per-hop (see AEAD AAD above). An attacker cannot modify `ttl` in transit without breaking AEAD.

### Predecessor/successor enforcement

- The relay's `RelayForwardingState` carries the registered `predecessor_node_id`. `forward_packet` checks the packet came from this predecessor — a relay cannot receive from a different node and forward on this circuit.
- The successor comes from the installed `RelayForwardingState`, NOT from a packet field. A relay cannot substitute the successor.
- `final_dst` is authenticated as AEAD AAD — a relay cannot substitute the destination.

### Circuit expiration

Both source and relay enforce the circuit's lifetime:

- Source: `ActiveCircuit::send_packet(plaintext, now)` checks `is_expired(now)` → `CircuitExpired`.
- Relay: `RelayForwardingState.expires_at` (from the signed `CircuitHandshake.expiry`) is checked in `forward_packet(packet, predecessor, now)` → `CircuitExpired` if `now >= expires_at`.
- Boundary: `now < expires_at` → permitted; `now >= expires_at` → expired.

### Payload limits (plaintext vs wire)

The source-side plaintext limit and the decoder-side wire limit are SEPARATE:

```text
MAX_PLAINTEXT_PAYLOAD_BYTES = 65_536
AEAD_TAG_BYTES = 16            (ChaCha20-Poly1305 tag per layer)
MAX_WIRE_PAYLOAD_BYTES = MAX_PLAINTEXT_PAYLOAD_BYTES + AEAD_TAG_BYTES × (ROUTE_MAX_HOPS - 1)
                     = 65_536 + 16 × 15 = 65_776
```

Each AEAD layer appends a 16-byte tag, so a multi-hop packet's wire payload exceeds the plaintext. `wrap_packet` rejects a plaintext whose worst-case sealed size exceeds `MAX_WIRE_PAYLOAD_BYTES`. `decode_from_cbor` enforces `MAX_WIRE_PAYLOAD_BYTES` at the CBOR head (before allocation).

### Malformed/oversized packet handling

- Oversized payload → `PayloadTooLarge` (rejected at the CBOR head, before allocation).
- Malformed wire (not CBOR / wrong shape) → `WireDecodeFailed` (fail-closed).
- AEAD failure → `PacketUnauthentic` (no partial state mutation).
- Unknown circuit → `UnknownCircuit`.
- Teardown → `remove_circuit()` / `apply_teardown()` removes forwarding state immediately; subsequent packets for that circuit → `UnknownCircuit`.

### Teardown

`CircuitTeardown` (source-signed) removes the circuit's forwarding state from the relay table. After teardown, packets for that circuit are rejected. Teardown is the deterministic cleanup path.

### The 15 N2.3 invariants (summary)

1. Packet bound to exactly one circuit.
2. Relay cannot substitute circuit/destination.
3. Relay cannot decrypt beyond its layer.
4. Packet replay rejected (check-before-AEAD, commit-after-AEAD).
5. Sequence/order bounded (u32, monotonic, stale rejected).
6. Cannot inject into another circuit (AAD binds circuit_id).
7. Cannot skip a designated hop (each layer reveals only the next successor).
8. Relay cannot change predecessor/successor (state check + AAD).
9. TTL prevents forwarding loops (decremented per hop, drop at 0, authenticated).
10. Unknown circuit IDs rejected.
11. Teardown immediately blocks new traffic.
12. Oversized packets rejected before allocation (plaintext + wire limits).
13. Malformed forwarding messages fail closed.
14. Forwarding state cleaned up deterministically.
15. Path operates without inspecting application payload.

### NOT in N2.3 (deferred)

- Internet gateway egress (N2.3+ — this slice proves mesh traversal only).
- Backward (gateway→source) traffic (symmetric; deferred).
- TCP connection migration / route recovery (N2.1.4+, spec §39).
- Flow control / congestion (transport layer).
- Android VPN, TUN, Civic Points, crypto services.
