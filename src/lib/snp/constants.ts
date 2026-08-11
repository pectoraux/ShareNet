/**
 * SNP/0.1 — Frozen Protocol Constants
 *
 * Source: 02-PROTOCOL-SPEC.md §10 "Frozen constants"
 * Source: 06-CONFORMANCE-AND-AI-MODEL.md §B3 (Invariants I1–I7)
 *
 * Changing any of these forks the network. They require an ADR and a
 * protocol version bump. See 06-CONFORMANCE-AND-AI-MODEL.md §B4 item 1.
 *
 * @ invariant FROZEN — do not mutate at runtime
 */

/** Protocol version string carried in NodeDescriptor.protoVersion and Frame.v */
export const PROTO_VERSION = "SNP/0.1" as const;

/** Major wire version carried in Frame.v (integer form). */
export const FRAME_VERSION = 1 as const;

// ─── Chunking (frozen — I6) ────────────────────────────────────────────────
export const CHUNK_MIN = 256 * 1024; // 256 KiB
export const CHUNK_TARGET = 1024 * 1024; // 1 MiB
export const CHUNK_MAX = 4 * 1024 * 1024; // 4 MiB
export const CHUNK_MASK_BITS = 20; // 20-bit boundary mask
export const CHUNK_MASK = (1 << CHUNK_MASK_BITS) - 1; // 0xFFFFF
export const GEAR_TABLE_SIZE = 256;

// ─── Merkle (RFC 6962 — I5) ────────────────────────────────────────────────
export const MERKLE_LEAF_PREFIX = 0x00;
export const MERKLE_NODE_PREFIX = 0x01;
export const MERKLE_EMPTY_CONTEXT = "SNP/0.1 empty\0";

// ─── Identity (I3, I4) ─────────────────────────────────────────────────────
export const NODE_ID_CONTEXT = "SNP/0.1 node\0";
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
export const X25519_PUBLIC_KEY_BYTES = 32;

// ─── Hash / AEAD ───────────────────────────────────────────────────────────
export const SHA256_BYTES = 32;
export const AEAD_NONCE_BYTES = 12;
export const AEAD_KEY_BYTES = 32;

// ─── Frame (I7) ────────────────────────────────────────────────────────────
export const FRAME_TTL_MAX = 16;
export const FRAME_FLOW_ID_BYTES = 8;
export const FRAME_PADDING_BUCKETS = [256, 512, 1024, 1500] as const;

// ─── Domain separators for signatures (I2) ─────────────────────────────────
// Every signature is over SIG_CONTEXT ‖ CBOR(payload). SIG_CONTEXT is an
// ASCII byte string terminated by 0x00. See 02-PROTOCOL-SPEC.md §1.1.
export const SIG_CONTEXTS = {
  manifest: "SNP/0.1 manifest\0",
  deliveryReceipt: "SNP/0.1 delivery-receipt\0",
  transitReceipt: "SNP/0.1 transit-receipt\0",
  gatewayReceipt: "SNP/0.1 gateway-receipt\0",
  custodyReceipt: "SNP/0.1 custody-receipt\0",
  nodeDescriptor: "SNP/0.1 node-descriptor\0",
  gatewayAdvert: "SNP/0.1 gateway-advert\0",
  routeAdvert: "SNP/0.1 route-advert\0",
  revocation: "SNP/0.1 revocation\0",
  deviceCert: "SNP/0.1 device-cert\0",
  transitRequest: "SNP/0.1 transit-request\0",
  transitResponse: "SNP/0.1 transit-response\0",
} as const;

export type SigContextName = keyof typeof SIG_CONTEXTS;

// ─── Capabilities (02-PROTOCOL-SPEC.md §4.2) ───────────────────────────────
export const CAPABILITIES = [
  "MESH_CLIENT",
  "MESH_RELAY",
  "INTERNET_GATEWAY",
  "CONTENT_SEED",
  "STORAGE",
  "DISCOVERY",
  "SYNC",
  "COMPUTE",
  "COMMUNITY_RELAY",
  "CUSTODY",
] as const;
export type Capability = (typeof CAPABILITIES)[number];

// ─── Traffic classes ───────────────────────────────────────────────────────
export const TRAFFIC_CLASSES = ["A", "B", "C"] as const;
export type TrafficClass = (typeof TRAFFIC_CLASSES)[number];

// ─── Internet modes (01-ARCHITECTURE.md §4) ────────────────────────────────
export const INTERNET_MODES = ["A", "B", "C"] as const;
export type InternetMode = (typeof INTERNET_MODES)[number];

// ─── TLS termination policy (02-PROTOCOL-SPEC.md §4.4) ─────────────────────
export const TLS_TERMINATIONS = ["GATEWAY_PLAINTEXT", "PAYLOAD_E2E"] as const;
export type TlsTermination = (typeof TLS_TERMINATIONS)[number];

// ─── Power states (02-PROTOCOL-SPEC.md §6.5) ───────────────────────────────
export const POWER_STATES = [
  "MAINS",
  "BATTERY_HIGH",
  "BATTERY_LOW",
  "BATTERY_CRITICAL",
] as const;
export type PowerState = (typeof POWER_STATES)[number];

// ─── Receipt quality classes (05-CIVIC-CONTENT-CONSISTENCY.md §A4) ─────────
export const QUALITY_CLASSES = ["interactive", "bulk", "tolerant"] as const;
export type QualityClass = (typeof QUALITY_CLASSES)[number];

// ─── Platforms (03-PLATFORM-MATRIX.md) ─────────────────────────────────────
export const PLATFORMS = [
  "android",
  "ios",
  "linux",
  "windows",
  "macos",
  "embedded",
] as const;
export type Platform = (typeof PLATFORMS)[number];

// ─── Route destination types ───────────────────────────────────────────────
export const DEST_TYPES = ["gateway", "node"] as const;
export type DestType = (typeof DEST_TYPES)[number];

/** Conformance suite IDs — must match conformance/vectors/*.json */
export const CONFORMANCE_SUITES = [
  { id: "01-cbor", name: "CBOR canonical encoding", specSection: "SNP/0.1 §1" },
  { id: "02-hashing", name: "Hashing & domain separators", specSection: "SNP/0.1 §1.1" },
  { id: "03-identity", name: "Identity & Ed25519", specSection: "SNP/0.1 §2" },
  { id: "04-chunking", name: "Gear content-defined chunking", specSection: "SNP/0.1 §3.3" },
  { id: "05-merkle", name: "RFC 6962 Merkle trees", specSection: "SNP/0.1 §3.2" },
  { id: "06-manifest", name: "Manifest signing & verification", specSection: "SNP/0.1 §3.4" },
  { id: "07-receipts", name: "Contribution receipts", specSection: "SNP/0.1 §A4, 05 §A3" },
  { id: "08-frames", name: "Frame format & TTL", specSection: "SNP/0.1 §7" },
  { id: "09-descriptors", name: "Node & gateway descriptors", specSection: "SNP/0.1 §4.4, §5.1" },
  { id: "10-routing", name: "Routing metrics & loops", specSection: "SNP/0.1 §6" },
  { id: "11-gateway", name: "Gateway egress policy", specSection: "SNP/0.1 §8" },
  { id: "12-civic-points", name: "Civic Points value function", specSection: "05 §A5" },
  { id: "13-revocation", name: "Revocation monotonicity", specSection: "05 §C2, §C3" },
  { id: "14-negative", name: "Negative / MUST-REJECT vectors", specSection: "06 §A5" },
] as const;
