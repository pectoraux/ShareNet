/**
 * SNP Merkle Tree — RFC 6962 construction
 *
 * Source: 02-PROTOCOL-SPEC.md §3.2
 * Source: 00-AUDIT.md §5.1 (the flaws this replaces)
 *
 * The existing `core-content/MerkleTree.kt` has two classical flaws:
 *
 *   1. NO leaf/internal domain separation.
 *      leaf_hash   = SHA-256(chunk)
 *      node_hash   = SHA-256(left ‖ right)
 *      A 64-byte chunk that is itself two concatenated hashes is
 *      indistinguishable from an internal node → second-preimage attack.
 *      RFC 6962 fixes this with 0x00 / 0x01 prefixes.
 *
 *   2. Odd-node duplication (CVE-2012-2459 shape).
 *      right = if (i+1 < size) level[i+1] else left
 *      Distinct leaf sets can produce identical roots.
 *      RFC 6962 fixes this by splitting at the largest power of two
 *      less than n, never duplicating.
 *
 * Additionally, the existing code operates on whole in-memory arrays.
 * The architecture requires a streaming API for multi-GB objects. That
 * streaming concern is addressed in chunking.ts; here we provide both
 * the batch and incremental interfaces.
 *
 * @ invariant I5 — Merkle is RFC 6962; odd nodes are never duplicated
 */

import { sha256 } from "@noble/hashes/sha2.js";
import {
  MERKLE_LEAF_PREFIX,
  MERKLE_NODE_PREFIX,
} from "./constants";
import { merkleEmptyRoot } from "./hashing";

// ─── Core hash functions ───────────────────────────────────────────────────

/** leaf_hash(chunk) = SHA-256(0x00 ‖ chunk) */
export function leafHash(chunk: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + chunk.length);
  buf[0] = MERKLE_LEAF_PREFIX;
  buf.set(chunk, 1);
  return sha256(buf);
}

/** node_hash(left, right) = SHA-256(0x01 ‖ left ‖ right) */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = MERKLE_NODE_PREFIX;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

// ─── Tree construction (RFC 6962, no odd-node duplication) ─────────────────

/**
 * Compute the Merkle root for an ordered list of leaf hashes.
 *
 * RFC 6962 §2.1 construction:
 *   - 0 leaves  → empty_root = SHA-256("SNP/0.1 empty\0")
 *   - 1 leaf    → leaf_hash (the leaf IS the root)
 *   - n leaves  → split at the largest power of two < n
 *                  root = node_hash(MT(left[k]), MT(right[n-k]))
 *                  where k = largest power of two < n
 *
 * This split rule NEVER duplicates a node, unlike the existing code's
 * `right = level[i+1] ?? left` shortcut. This closes CVE-2012-2459-style
 * second-preimage attacks where distinct leaf sets collide.
 *
 * @param leafHashes 32-byte leaf hashes (already computed via leafHash)
 */
export function merkleRoot(leafHashes: Uint8Array[]): Uint8Array {
  if (leafHashes.length === 0) return merkleEmptyRoot();
  return merkleRootRec(leafHashes, 0, leafHashes.length);
}

function merkleRootRec(leaves: Uint8Array[], start: number, end: number): Uint8Array {
  const n = end - start;
  if (n === 1) return leaves[start];
  // Largest power of two < n. For n=3 → 2. For n=5 → 4. For n=8 → 4.
  // (For n a power of two, this is n/2, giving a balanced tree.)
  const k = largestPowerOfTwoLessThan(n);
  return nodeHash(
    merkleRootRec(leaves, start, start + k),
    merkleRootRec(leaves, start + k, end),
  );
}

function largestPowerOfTwoLessThan(n: number): number {
  // For n=1 this is never called. For n>=2:
  //   n=2 → 1, n=3 → 2, n=4 → 2, n=5 → 4, n=8 → 4, n=9 → 8
  // i.e. 2^floor(log2(n-1))
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// ─── Inclusion proofs ──────────────────────────────────────────────────────

export interface MerkleProof {
  /** The leaf hash this proof is for. */
  leafHash: Uint8Array;
  /** The leaf's index in the original array. */
  leafIndex: number;
  /** Audit path: each entry is { hash, side } where side ∈ {left, right}. */
  path: Array<{ hash: Uint8Array; side: "left" | "right" }>;
  /** The expected root. */
  root: Uint8Array;
}

/**
 * Build an inclusion proof for the leaf at `index`.
 * The proof follows RFC 6962 §2.1.1 audit paths.
 */
export function buildProof(
  leafHashes: Uint8Array[],
  index: number,
): MerkleProof {
  if (leafHashes.length === 0) {
    throw new Error("Cannot build a proof for an empty tree");
  }
  if (index < 0 || index >= leafHashes.length) {
    throw new Error(`Leaf index ${index} out of range [0, ${leafHashes.length})`);
  }
  const path: MerkleProof["path"] = [];
  const root = buildProofRec(leafHashes, 0, leafHashes.length, index, path);
  return { leafHash: leafHashes[index], leafIndex: index, path, root };
}

function buildProofRec(
  leaves: Uint8Array[],
  start: number,
  end: number,
  index: number,
  path: MerkleProof["path"],
): Uint8Array {
  const n = end - start;
  if (n === 1) return leaves[start];
  const k = largestPowerOfTwoLessThan(n);
  if (index - start < k) {
    // index is in the left subtree; the right subtree's root is the sibling.
    const leftRoot = buildProofRec(leaves, start, start + k, index, path);
    const rightRoot = merkleRootRec(leaves, start + k, end);
    path.push({ hash: rightRoot, side: "right" });
    return nodeHash(leftRoot, rightRoot);
  } else {
    // index is in the right subtree; the left subtree's root is the sibling.
    const leftRoot = merkleRootRec(leaves, start, start + k);
    const rightRoot = buildProofRec(leaves, start + k, end, index, path);
    path.push({ hash: leftRoot, side: "left" });
    return nodeHash(leftRoot, rightRoot);
  }
}

/**
 * Verify an inclusion proof. Returns true iff the proof is valid.
 *
 * Verification recomputes the root from the leaf and the audit path:
 *   acc = leafHash
 *   for each { hash, side } in path:
 *     acc = side === 'left' ? nodeHash(hash, acc) : nodeHash(acc, hash)
 *   return acc === root
 *
 * Note the side semantics: 'left' means the sibling is to the LEFT of acc,
 * so it goes in the first argument of nodeHash.
 */
export function verifyProof(proof: MerkleProof): boolean {
  let acc = proof.leafHash;
  for (const step of proof.path) {
    if (step.side === "left") {
      acc = nodeHash(step.hash, acc);
    } else {
      acc = nodeHash(acc, step.hash);
    }
  }
  return bytesEqual(acc, proof.root);
}

// ─── Batch helpers ─────────────────────────────────────────────────────────

/**
 * Compute leaf hashes for a list of raw chunks, then return the root.
 * Convenience wrapper for the common case.
 */
export function rootFromChunks(chunks: Uint8Array[]): Uint8Array {
  return merkleRoot(chunks.map(leafHash));
}

/** Build proofs for every leaf in the tree. */
export function buildAllProofs(leafHashes: Uint8Array[]): MerkleProof[] {
  return leafHashes.map((_, i) => buildProof(leafHashes, i));
}

// ─── Streaming tree builder (for chunked ingestion of large objects) ───────

/**
 * Incremental Merkle tree builder. Append leaf hashes one at a time and
 * compute the root at the end. This supports the streaming chunking API
 * required by 02-PROTOCOL-SPEC.md §3.3 for multi-GB objects.
 *
 * Implementation: keep a list of "peak" hashes at each level (binary
 * representation of the leaf count). This is O(log n) memory and O(n log n)
 * total work, identical to the batch construction.
 */
export class StreamingMerkle {
  /**
   * Streaming Merkle builder that produces the SAME root as the batch
   * `merkleRoot` function for the same leaf sequence.
   *
   * N1.7.1 FIX: The previous implementation used a "Merkle mountain range"
   * (MMR) approach that folded peaks right-to-left. This produces a DIFFERENT
   * tree structure than RFC 6962's split-at-largest-power-of-two rule for
   * non-power-of-two leaf counts. The batch and streaming implementations
   * MUST produce identical roots — that's the whole point of the
   * `merkle-streaming-matches-batch` conformance vector.
   *
   * The fix: store all leaf hashes as they arrive, then compute the root
   * using the same `merkleRootRec` function as the batch builder. This is
   * O(n) memory (not O(log n) like a true MMR), but it's correct. A future
   * optimization can implement an incremental RFC 6962 builder that matches
   * the batch root without storing all leaves — but correctness first.
   */
  private leafHashes: Uint8Array[] = [];

  append(leaf: Uint8Array): void {
    this.leafHashes.push(leafHash(leaf));
  }

  /** Compute the root using the same algorithm as the batch builder. */
  root(): Uint8Array {
    if (this.leafHashes.length === 0) return merkleEmptyRoot();
    return merkleRoot(this.leafHashes);
  }

  get size(): number {
    return this.leafHashes.length;
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
