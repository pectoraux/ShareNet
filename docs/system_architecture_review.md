# ShareNet: System Architecture & Design Review

**Author:** ShareNet Core Team
**Version:** 1.1 (Production Hardened)
**Target:** LLM-based Architectural Reviewers

---

## 1. Executive Summary
ShareNet is an **offline-first mesh platform** designed for resilient content distribution and value transfer in environments with zero or intermittent internet connectivity. It transforms a network of Android devices into a decentralized "App Store" and "Data Mesh" using Nearby P2P communication, content-addressed storage (CAS), and a cryptographically enforced incentive model (Civic Points).

## 2. Core Pillars

### 2.1 Content Addressing & Integrity (`core-content`)
- **Deduplication**: Content-defined chunking (Gear/Buzhash) splits files into 1MB (avg) chunks.
- **Merkle Trees**: Every blob is identified by its Merkle root (SHA-256).
- **Verification**: Parallel hashing across cores ensures high-performance integrity checks for multi-gigabyte blobs (AI models, App bundles).
- **Persistence**: `DiskBlobStore` uses an encrypted file system + SQLCipher-backed Room index.

### 2.2 Identity & Trust (`core-crypto` & `core-catalog`)
- **Identity**: Ed25519 public keys are the global primary keys (`NodeId`).
- **Hardware Security**: Private keys are held in the **Android Keystore** (StrongBox/TEE).
- **Manifests**: Signed metadata describing blobs. Manifests propagate via Gossip protocol.
- **Publisher Registry**: Pinned root-key model with signed delegation and rotation.

### 2.3 Mesh Transport (`core-transport`)
- **Nearby Connections**: Uses `P2P_CLUSTER` to multiplex BLE, Bluetooth Classic, and Wi-Fi Direct.
- **Adaptive Governor**: Battery-aware and network-aware transfer logic.
    - **Prioritization**: `CRITICAL` (Revocations) > `HIGH` (Manifests/Ads) > `LOW` (Large Blobs).
- **Gossip Protocol**: Nodes exchange "HAVE" vectors (compact summaries of local catalogs) to identify missing data.
- **SmsGateway**: Structured SMS bridge for keypad phone accessibility.

### 2.4 Mesh Economics (`core-attest`)
- **Proof-of-Delivery**: Recipient-signed receipts earned on successful transfer.
- **Civic Points**: Rewards for **Internet Bridging** (fetching content from the "real" internet) and **Delivery**.
- **Ad Network**: Decentralized ad revenue split: 70% to Bridger, 20% to Deliverer, 10% to Platform.

## 3. Application Ecosystem

### 3.1 App Hub & Sandbox (`app-feed`)
- **App Store**: Mimics App Store/Play Store UX for offline discovery.
- **App Clones**: HTML5 zip-bundles executed in a **Sandboxed WebView** with `snr://` protocol.
- **Multitasking**: Launcher managing concurrent "Active App" lifecycles.

### 3.2 Offline AI Assistant (`app-assistant`)
- **Pipeline**: On-device ASR (Whisper) -> Translation (NLLB) -> LLM (MediaPipe Gemma).
- **Optimization**: `ModelOptimizer` picks tiers (Tiny/Small/Medium) based on device RAM/NPU.

### 3.3 Offline Wallet (`app-wallet`)
- **NFC Terminal**: Phone acts as an untrusted terminal for JavaCard SE cards.
- **Secure Element**: Value held in hardware; phone only mediates the DEBIT/CREDIT APDU exchange.

## 4. Security Model

### 4.1 Threat Matrix & Mitigations
| Threat | Mitigation |
| --- | --- |
| **Node Spoofing** | Ed25519 signatures on all manifests and receipts. |
| **Content Tampering** | Merkle root verification on every chunk read. |
| **Double-Spending** | Card-enforced tx counters + backend settlement reconciliation. |
| **Ad Fraud** | Recipient diversity weighting + temporal plausibility checks. |
| **Privacy Leaks** | SQLCipher at rest + PII-free mesh protocol. |

### 4.2 Sandboxing
Apps run in WebViews with no access to external URLs. They communicate with the ShareNet SDK via a restricted JavaScript Bridge that enforces data quotas and permission prompts.

## 5. Deployment Considerations
- **Play Services**: Currently depends on Nearby Connections. `core-transport` allows for a secondary "Pure Offline" WifiDirect stack.
- **Scaling**: Merkle proofs enable selective chunk fetching, allowing nodes to participate in model propagation without storing the full multi-GB weight set.

---

> [!NOTE]
> This system is designed to be **autonomous**. The "Illusion of Online" is maintained by optimistic local writes that eventually converge via the mesh.
