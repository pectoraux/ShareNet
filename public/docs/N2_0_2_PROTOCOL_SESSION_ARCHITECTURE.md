# N2.0.2 Protocol Session Architecture

**Status:** normative for the N2.0.2 runtime  
**Date:** 2026-08-12  

---

## Architecture

```
                         ┌──────────────────────┐
                         │      ShareNet Node   │
                         │                      │
                         │ Identity             │
                         │ Capabilities         │
                         │ PeerDirectory        │
                         │ GatewayDirectory     │
                         │ PeerSessions         │
                         │ Routes               │
                         │ Circuits             │
                         └──────────┬───────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
             Discovery          Sessions          Routing
                  │                 │                 │
                  ▼                 ▼                 ▼
             Peer/Gateway       SNP-IK/0.1       Route Manager
             Advertisements     authenticated       │
                                  links              ▼
                                                  Circuit
                                                     │
                                                     ▼
                                               Internet Gateway
```

## Layer Separation

| Layer | What it IS | What it is NOT |
|-------|-----------|----------------|
| Node | Protocol participant with identity and capabilities | A specific role (Client/Relay/Gateway) |
| PeerSession | Authenticated cryptographic session between two nodes | A TCP connection |
| TransportConnection | A TCP stream carrying encrypted frames | A protocol session |
| Route | An explicit path through the mesh with lifecycle | A function call chain |
| Circuit | End-to-end encrypted channel between client and gateway | A hop key |
| Gateway | A node with the INTERNET_GATEWAY capability | A hardcoded GatewayChoice::A/B |

## Identity

Every node has:
- Ed25519 identity keypair (signs NodeDescriptors, advertisements, transit responses)
- X25519 rendezvous keypair (used for DH in SNP-IK/0.1 handshake)
- NodeId = SHA-256("SNP/0.1 node\0" || ed25519_public_key)

**Production-ready:** YES. NodeIdentity::from_secret() accepts arbitrary 32-byte secret keys. NodeIdentity::new_with_x25519() generates fresh X25519 keypairs. No compile-time identity assumptions.

## SNP-IK/0.1 Handshake

Per ADR-0006, the handshake:
1. Both sides generate fresh ephemeral X25519 keypairs
2. Exchange ephemeral public keys + signed NodeDescriptors
3. Compute three DH operations (eph×static, static×eph, eph×eph)
4. Derive directional link keys via HKDF
5. Verify peer's NodeDescriptor signature
6. Verify peer's NodeId matches public key (I4)
7. Verify expected peer NodeId if provided ("I"-style pinning)

**Production-ready:** YES. `perform_snp_ik_handshake()` produces fresh keys per session. Two sessions between the same pair produce different keys (Test 3). Wrong-identity is rejected (Test 1b). Transcript tampering is rejected (Test 1c).

## Circuit Key Establishment

Circuit keys are derived from a fresh client↔gateway X25519 DH:
1. Client generates ephemeral X25519 keypair
2. Client includes ephemeral public key in circuit payload (before encrypted TransitRequest)
3. Gateway generates its own ephemeral X25519 keypair
4. Gateway includes its ephemeral public key in circuit response (before encrypted TransitResponse)
5. Both derive circuit keys via HKDF from DH(client_eph, gateway_eph)

**Production-ready:** YES. `seal_circuit_payload_with_fresh_eph()` and `open_circuit_payload_with_fresh_eph()` implement this. The relay never sees the X25519 public keys (they're inside the circuit ciphertext). Test 5 proves fresh keys. Test 6 proves relay cannot derive circuit key.

## Gateway Discovery

GatewayAdvertisement is signed by the gateway's Ed25519 key. The client:
1. Connects to known bootstrap addresses
2. Requests advertisement
3. Verifies Ed25519 signature
4. Checks expiry
5. Cross-checks NodeId == SHA-256("SNP/0.1 node\0" || publicKey)
6. Adds to GatewayDirectory

**Production-ready:** YES. Gateway C (arbitrary identity) test proves a previously unknown gateway can be discovered, authenticated, and used without modifying protocol code (Test 2).

## What is Production-Ready

- SNP-IK/0.1 handshake (fresh keys, identity verification, tamper rejection)
- Circuit key establishment (fresh DH, relay cannot derive)
- GatewayAdvertisement (signed, verified, expired-checked)
- Gateway C (arbitrary identity, no compile-time knowledge)
- Persistent TCP sessions (multiple requests per connection)
- Genuine failover (NACK detection, circuit switch, no restart)
- All N1.9.2 security fixes (replay, signature, reqId dedup)

## What is Test-Only

- Old N1.9/N2.0 demo functions in lib.rs (use GatewayChoice and deterministic seeds)
- Discovery link keys (pre-shared seed for the discovery connection)
- Synchronous I/O (production needs tokio for concurrent connections)
- select_gateway (first non-expired — needs metric-based scoring)

## What is NOT Implemented

- DiscoveryProvider trait (generic discovery abstraction)
- Async I/O (tokio)
- Route object with explicit hops list (state machine exists but route doesn't carry hop list)
- Relay failover (gateway failover works, relay failover does not)
- Session replacement (old session replaced by new with fresh handshake)
