# ShareNet 2.0 — Android Platform Contract

**Status:** normative contract for Gemini Android implementation  
**Date:** 2026-08-12  
**Prerequisite:** N2.0.3 Gate A-M complete

---

## Purpose

This document defines the platform-independent interfaces that Gemini must
implement for the Android ShareNet node. Gemini must NOT infer protocol
semantics from Rust implementation details. This contract IS the authority.

---

## Architecture

```
Android ShareNet Node
│
├── Identity (Ed25519 + X25519)
├── Capabilities (Client, Relay, Gateway)
├── PeerDirectory
├── GatewayDirectory
├── PeerSessions (SNP-IK/0.1 handshake)
├── Routes (explicit hop list, state machine)
├── Circuits (fresh DH keys, lifecycle)
│
├── DiscoveryProvider (Android: Nearby, BLE, Wi-Fi Direct, mDNS)
├── TransportProvider (Android: TCP, BLE GATT, Wi-Fi Direct)
│
└── VpnService / TUN
       │
       ▼
   Android apps (Chrome, WhatsApp, etc.)
```

---

## Interfaces

### 1. DiscoveryProvider

```rust
trait DiscoveryProvider: Send + Sync {
    fn discover(&self) -> Vec<DiscoveredNode>;
    fn advertise(&self, advertisement: &GatewayAdvertisement, endpoint: &str);
}
```

Android implementations:
- `NearbyDiscovery` — uses Google Nearby Connections (requires Play Services)
- `BleDiscovery` — uses BLE GATT advertising/scaning (Play-free)
- `WiFiDirectDiscovery` — uses WifiP2pManager (Play-free)
- `MdnsDiscovery` — uses NSD on local Wi-Fi

### 2. TransportProvider

Not yet defined as a trait in the Rust reference. Android MUST define:

```kotlin
interface TransportProvider {
    fun connect(endpoint: String): TransportConnection
    fun listen(endpoint: String): TransportListener
}

interface TransportConnection {
    fun send(data: ByteArray): Boolean
    fun onReceived(handler: (ByteArray) -> Unit)
    fun close()
    fun isAlive(): Boolean
}
```

### 3. PeerSession

A PeerSession is established via the SNP-IK/0.1 handshake. The Android
implementation MUST:

1. Generate a fresh ephemeral X25519 keypair per session
2. Exchange ephemeral public keys + signed NodeDescriptors
3. Compute three DH operations
4. Derive directional AEAD keys via HKDF
5. Verify the peer's Ed25519 signature on its NodeDescriptor
6. Verify NodeId == SHA-256("SNP/0.1 node\0" || publicKey)

The session state machine: NEW → HANDSHAKING → ESTABLISHED → DEGRADED → CLOSING → CLOSED

### 4. Route

A Route is an explicit object with:
- `source: NodeId` (client)
- `destination: NodeId` (gateway)
- `hops: Vec<NodeId>` (ordered, including destination)
- `state: RouteState` (Proposed → Establishing → Active → Degraded → Migrating → Failed → Closed)
- `epoch: u64`
- `expires_at: u64`

Route validation rules:
- Not empty
- Source set
- Destination matches last hop
- No duplicate hops (loop)
- Hop count ≤ 16
- Not expired

### 5. Circuit

A Circuit is the end-to-end encrypted channel between client and gateway:
- `circuit_id: [u8; 32]`
- `client_node_id: NodeId`
- `gateway_node_id: NodeId`
- `send_key: SymmetricKey` (directional)
- `recv_key: SymmetricKey` (directional)
- `state: CircuitState` (Discovering → Establishing → Active → Degraded → Migrating → Failed → Closed)

Circuit keys are derived from a fresh client↔gateway X25519 DH. The relay
MUST NEVER possess the circuit key.

### 6. Gateway

A gateway is a node with the `INTERNET_GATEWAY` capability. It MUST:
- Sign and serve GatewayAdvertisements
- Verify client signatures on TransitRequests
- Enforce SSRF policy (isPrivateDestination + DNS pinning)
- NOT follow redirects
- Sign TransitResponses with its Ed25519 key

### 7. Transit Frame Format

SNP frames are CBOR-encoded with canonical key ordering (RFC 8949 §4.2.1):
```
Frame = { v, cls, dst, src, ttl, fid, seq, body }
```

- `cls`: "A" (content), "B" (transit), "C" (control)
- `ttl`: max 16, decremented per hop
- `body`: Class B = opaque circuit ciphertext (relay MUST NOT inspect)

---

## Conformance Vectors

The Android implementation MUST consume the committed golden vectors at:
`/public/conformance/vectors/*.json` (138 vectors across 15 suites).

Android MUST pass all 138 vectors.

---

## What Gemini MUST Implement

1. `DiscoveryProvider` implementations (Nearby, BLE, Wi-Fi Direct)
2. `TransportProvider` implementations (TCP, BLE GATT, Wi-Fi Direct)
3. `VpnService` for Mode C (transparent Internet)
4. Foreground service for relay/gateway background operation
5. Android Keystore integration for hardware-backed Ed25519 keys
6. The SNP-IK/0.1 handshake (using the same X25519/Ed25519/HKDF/AEAD)

## What Gemini MUST NOT Implement

1. Protocol semantics not in the specification
2. Custom CBOR encoding (use the canonical RFC 8949 §4.2.1)
3. Custom key derivation (use the HKDF info strings from the spec)
4. Alternative handshake constructions
5. Civic Points economics
6. Settlement
7. A new routing protocol

## What Gemini MUST NOT Modify

1. `spec/` — the normative specification
2. `conformance/vectors/` — the golden vectors
3. `reference/` — the Rust reference implementation
4. Any ADR

---

## North-Star Acceptance Test

```
Phone A (no Internet)
  │
  │ ShareNet mesh (BLE / Wi-Fi Direct / TCP)
  ▼
Phone B or Laptop (Internet ON)
  │
  │ Gateway
  ▼
Real Internet

Chrome on Phone A → real website.
No modified Chrome. No ShareNet browser. No cached content.
```
