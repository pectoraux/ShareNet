# N2.0.2 Baseline Audit

**Date:** 2026-08-12  
**Auditor:** Z.ai  
**Baseline commit:** `356a22e`

---

## Method

Full source inspection of `reference/snp-node/src/node.rs`, `reference/snp-node/src/lib.rs`, `reference/snp-link/src/lib.rs`, `reference/snp-crypto/src/lib.rs`, all ADRs, and test suites. No reports trusted without source verification.

---

## Current State

### Node abstraction (node.rs, 2122 lines)

| Component | Specification | Implementation | Test | Status |
|-----------|--------------|----------------|------|--------|
| Node struct | Generic node with identity, capabilities, peers, circuits | EXISTS but depends on GatewayChoice for gateway identity | n201_sessions.rs | PARTIALLY IMPLEMENTED |
| NodeIdentity | Arbitrary Ed25519 keypair | `from_secret()` works, but `gateway(gw)` hardcodes A/B | Test-only identities | TEST ONLY |
| Capability | Client/Relay/Gateway as roles | Enum exists, but gateway methods take `GatewayChoice` | Tests use A/B | PARTIALLY IMPLEMENTED |
| GatewayAdvertisement | Signed by gateway Ed25519 | IMPLEMENTED with sign/verify/expiry/nodeId check | 7 security tests pass | IMPLEMENTED |
| Circuit | Fresh keys per circuit | `Circuit::for_gateway(gw)` uses `CIRCUIT_SEED_A/B` | Tests use deterministic seeds | TEST ONLY |
| PeerConnection | Persistent TCP + hop keys | EXISTS, uses `derive_link_keys(seed)` not handshake | Tests use deterministic seeds | TEST ONLY |

### Key establishment

| Component | Specification | Implementation | Test | Status |
|-----------|--------------|----------------|------|--------|
| SNP-IK/0.1 handshake | ADR-0006: X25519 DH + NodeDescriptor sig + HKDF | IMPLEMENTED in snp-link (perform_snp_ik_handshake) | snp-link unit tests pass | IMPLEMENTED (not wired to runtime) |
| derive_link_keys_from_dh | HKDF from DH outputs | IMPLEMENTED in snp-link | Unit tests pass | IMPLEMENTED |
| derive_link_keys (seed) | HKDF from deterministic seed | IMPLEMENTED, used by runtime | Tests use this | TEST ONLY |
| derive_circuit_keys (seed) | HKDF from deterministic seed | IMPLEMENTED, used by runtime | Tests use this | TEST ONLY |
| Circuit key from DH | Client↔gateway X25519 DH | NOT IMPLEMENTED | No test | NOT IMPLEMENTED |

### GatewayChoice in production code

| File | GatewayChoice references | Status |
|------|------------------------|--------|
| node.rs | 59 | PRODUCTION CODE — must be removed |
| lib.rs | 30+ | Demo/test code — acceptable |
| tests/n20_multihop.rs | 10+ | Test code — acceptable |
| tests/n201_sessions.rs | 5+ | Test code — acceptable |

### Discovery

| Component | Specification | Implementation | Test | Status |
|-----------|--------------|----------------|------|--------|
| GatewayAdvertisement | Signed, with expiry, capabilities | IMPLEMENTED | Tests pass | IMPLEMENTED |
| discover_gateways | Connect to known addrs, request advert | IMPLEMENTED | Tests pass | IMPLEMENTED |
| select_gateway | Select from known_gateways | "First non-expired" — no scoring | Tests use this | PARTIALLY IMPLEMENTED |
| DiscoveryProvider trait | Generic discovery abstraction | NOT IMPLEMENTED | No test | NOT IMPLEMENTED |

### Sessions

| Component | Specification | Implementation | Test | Status |
|-----------|--------------|----------------|------|--------|
| Persistent TCP sessions | Multiple requests per connection | IMPLEMENTED (serve_relay_persistent, serve_gateway_persistent) | Test 1: 3 requests, 1 connection | IMPLEMENTED |
| PeerSession struct | Protocol-level session with state machine | NOT IMPLEMENTED (PeerConnection is just TCP+keys) | No test | NOT IMPLEMENTED |
| Session state machine | NEW→HANDSHAKING→ESTABLISHED→... | NOT IMPLEMENTED | No test | NOT IMPLEMENTED |
| Session replacement | Old session replaced by new | NOT IMPLEMENTED | No test | NOT IMPLEMENTED |

### Routing

| Component | Specification | Implementation | Test | Status |
|-----------|--------------|----------------|------|--------|
| Route object | Explicit route with hops, state, epoch | NOT IMPLEMENTED | No test | NOT IMPLEMENTED |
| Route state machine | PROPOSED→ESTABLISHING→ACTIVE→... | NOT IMPLEMENTED | No test | NOT IMPLEMENTED |
| Route migration | State transition, not process restart | Failover works (NACK-based), but no route object | Test 3: A→B failover | PARTIALLY IMPLEMENTED |

### Failover

| Component | Specification | Implementation | Test | Status |
|-----------|--------------|----------------|------|--------|
| Gateway failover | Detect failure, select new gateway, new circuit | IMPLEMENTED (NACK detection, circuit switch) | Test 3: A→B, no restart | IMPLEMENTED |
| Relay failover | Relay drops, traffic reroutes | NOT IMPLEMENTED | No test | NOT IMPLEMENTED |
| Failure detection | Transport vs session vs peer vs route | TCP EOF/NACK only | No separation | PARTIALLY IMPLEMENTED |

### Concurrency

| Component | Specification | Implementation | Test | Status |
|-----------|--------------|----------------|------|--------|
| Synchronous I/O | std::net::TcpStream | Current implementation | All tests synchronous | IMPLEMENTED (test-only) |
| Concurrent sessions | Multiple peers/sessions/circuits | Mutex-based, single-threaded per role | No concurrent test | PARTIALLY IMPLEMENTED |

### Security

| Property | Status |
|----------|--------|
| Directional AEAD keys | IMPLEMENTED |
| Replay protection (link layer) | IMPLEMENTED (SeenNonceSet) |
| Replay protection (circuit layer) | IMPLEMENTED (reqId dedup) |
| Client signature verification | IMPLEMENTED (handle_transit_request) |
| Relay cannot decrypt circuit | IMPLEMENTED + tested |
| Tampering detection | IMPLEMENTED + tested |
| DNS pinning | IMPLEMENTED (PinnedConnector) |
| Redirect SSRF rejection | IMPLEMENTED + tested |
| GatewayAdvertisement signature | IMPLEMENTED + tested |
| SNP-IK/0.1 handshake | IMPLEMENTED in snp-link, NOT WIRED to runtime |

---

## Summary

| Category | IMPLEMENTED | PARTIALLY | TEST ONLY | NOT IMPLEMENTED |
|----------|------------|-----------|-----------|-----------------|
| Node | 0 | 3 | 3 | 0 |
| Keys | 2 | 0 | 2 | 1 |
| Discovery | 2 | 1 | 0 | 1 |
| Sessions | 1 | 0 | 0 | 3 |
| Routing | 0 | 1 | 0 | 2 |
| Failover | 1 | 1 | 0 | 1 |
| Concurrency | 0 | 1 | 1 | 0 |
| Security | 9 | 0 | 0 | 0 |

**Primary blockers for N2.1:**
1. SNP-IK/0.1 handshake exists but is NOT wired to the runtime (deterministic seeds still used)
2. GatewayChoice in production code (59 references in node.rs)
3. No PeerSession state machine
4. No Route/Circuit objects with lifecycle
5. No DiscoveryProvider abstraction

**What IS ready:**
- GatewayAdvertisement (signed, verified, expired-checked)
- Persistent TCP sessions (multi-request)
- Genuine failover (NACK-based, no restart)
- All N1.9.2 security fixes (replay, signature, reqId dedup)
- SNP-IK/0.1 handshake implementation (just not wired)
