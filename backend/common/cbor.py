"""
Deterministic CBOR codec — byte-identical to Kotlin core-crypto/CborCodec.

Rules (RFC 8949 deterministic):
  - Map keys sorted by lexicographic byte-wise comparison of their UTF-8 bytes.
    (All our maps have string keys, so this is equivalent to sorted(key.encode('utf-8'))).
  - Integers use minimal-width encoding (RFC 8949 §4.2.1).
  - No indefinite lengths; all arrays/maps have definite lengths.
  - No floats; only unsigned ints, negative ints, byte strings, text strings, arrays, maps, null, bool.
  - Byte strings are major type 2; text strings major type 3; both length-prefixed.

Implementation sits on top of `cbor2` but enforces determinism explicitly by:
  - Sorting map keys before encoding.
  - Using cbor2's canonical mode for integer width.

Alternatively a hand-rolled encoder is included (encode_* helpers) so behavior is
fully specified without depending on cbor2 internals. The public `encode_*` functions
use the hand-rolled encoder; `decode` uses cbor2 for convenience.

Golden vectors in golden_vectors.json are produced by this encoder and must match
Kotlin's output byte-for-byte. The hex strings there are the ground truth.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Tuple

try:
    import cbor2  # type: ignore
    _HAS_CBOR2 = True
except Exception:
    _HAS_CBOR2 = False


# ---------------------------------------------------------------------------
# Low-level CBOR primitives (hand-rolled, deterministic)
# ---------------------------------------------------------------------------

def _encode_uint(major: int, value: int) -> bytes:
    """Encode unsigned int with major type, minimal width."""
    assert value >= 0
    mt = major << 5
    if value < 24:
        return bytes([mt | value])
    elif value < 256:
        return bytes([mt | 24, value])
    elif value < 65536:
        return bytes([mt | 25]) + struct.pack(">H", value)
    elif value < 4294967296:
        return bytes([mt | 26]) + struct.pack(">I", value)
    else:
        return bytes([mt | 27]) + struct.pack(">Q", value)


def _encode_int(n: int) -> bytes:
    if n >= 0:
        return _encode_uint(0, n)
    else:
        # CBOR negative: value = -1 - n
        return _encode_uint(1, -1 - n)


def _encode_bytes(b: bytes) -> bytes:
    return _encode_uint(2, len(b)) + b


def _encode_text(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _encode_uint(3, len(raw)) + raw


def _encode_array(items: List[bytes]) -> bytes:
    head = _encode_uint(4, len(items))
    return head + b"".join(items)


def _encode_map(pairs: List[Tuple[bytes, bytes]]) -> bytes:
    """
    pairs: list of (encoded_key_bytes, encoded_value_bytes) where encoded_key
    is the CBOR encoding of the key (always a text string in our schema).
    Sorted by raw key bytes (the UTF-8 of the key) per spec — but since keys are
    text strings, sorting by encoded key bytes == sorting by UTF-8 bytes with
    length prefix tie-break which for our short ASCII keys is equivalent to
    lexicographic on the string. We sort by the *encoded key* bytes to be precise.
    """
    # sort by encoded key bytes
    pairs_sorted = sorted(pairs, key=lambda kv: kv[0])
    head = _encode_uint(5, len(pairs_sorted))
    out = head
    for k_enc, v_enc in pairs_sorted:
        out += k_enc + v_enc
    return out


def _encode_any(value: Any) -> bytes:
    """Encode Python value to deterministic CBOR."""
    if value is None:
        return bytes([0xF6])  # null
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        return _encode_int(value)
    if isinstance(value, bytes):
        return _encode_bytes(value)
    if isinstance(value, str):
        return _encode_text(value)
    if isinstance(value, list):
        return _encode_array([_encode_any(x) for x in value])
    if isinstance(value, dict):
        pairs: List[Tuple[bytes, bytes]] = []
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"CBOR map keys must be str, got {type(k)}")
            k_enc = _encode_text(k)
            v_enc = _encode_any(v)
            pairs.append((k_enc, v_enc))
        return _encode_map(pairs)
    raise TypeError(f"unsupported CBOR type: {type(value)}")


def encode_canonical(obj: Any) -> bytes:
    """
    Encode any JSON-like structure to deterministic CBOR.
    This is the single entry point for golden-vector generation.
    """
    return _encode_any(obj)


def decode_canonical(data: bytes) -> Any:
    """Decode CBOR bytes (uses cbor2 if available, else raises)."""
    if not _HAS_CBOR2:
        raise RuntimeError("cbor2 not installed; cannot decode")
    return cbor2.loads(data)


# ---------------------------------------------------------------------------
# Domain-specific encoders — canonical maps for signed structures
# Each returns the CBOR bytes that are signed (signature field excluded).
# Key ordering is enforced by _encode_map sorting, but we list keys explicitly
# for readability and to ensure Kotlin uses the same set.
# ---------------------------------------------------------------------------

def encode_manifest_signing(manifest) -> bytes:
    """
    Manifest signing payload:
    {
      "blobId": bytes(32),
      "chunks": [bytes(32), ...],
      "expiresAt": int|null,
      "mimeType": text,
      "publishedAt": int,
      "publisherId": bytes(32),
      "totalBytes": int
    }
    Keys sorted: blobId, chunks, expiresAt, mimeType, publishedAt, publisherId, totalBytes
    """
    m: Dict[str, Any] = {
        "blobId": manifest.blob_id.merkle_root,
        "chunks": [c.sha256 for c in manifest.chunks],
        "expiresAt": manifest.expires_at,  # None -> CBOR null
        "mimeType": manifest.mime_type,
        "publishedAt": manifest.published_at,
        "publisherId": manifest.publisher_id.public_key,
        "totalBytes": manifest.total_bytes,
    }
    return encode_canonical(m)


def encode_manifest_full(manifest) -> bytes:
    """Full manifest including signature (for storage / transport, not for signing)."""
    m: Dict[str, Any] = {
        "blobId": manifest.blob_id.merkle_root,
        "chunks": [c.sha256 for c in manifest.chunks],
        "expiresAt": manifest.expires_at,
        "mimeType": manifest.mime_type,
        "publishedAt": manifest.published_at,
        "publisherId": manifest.publisher_id.public_key,
        "signature": manifest.signature,
        "totalBytes": manifest.total_bytes,
    }
    return encode_canonical(m)


def encode_receipt_signing(receipt) -> bytes:
    """
    DeliveryReceipt signing payload:
    {
      "blobId": bytes(32),
      "bytesDelivered": int,
      "nonce": bytes(16),
      "recipientId": bytes(32),
      "senderId": bytes(32),
      "timestamp": int
    }
    Sorted: blobId, bytesDelivered, nonce, recipientId, senderId, timestamp
    """
    m: Dict[str, Any] = {
        "blobId": receipt.blob_id.merkle_root,
        "bytesDelivered": receipt.bytes_delivered,
        "nonce": receipt.nonce,
        "recipientId": receipt.recipient_id.public_key,
        "senderId": receipt.sender_id.public_key,
        "timestamp": receipt.timestamp,
    }
    return encode_canonical(m)


def encode_contribution_signing(contrib) -> bytes:
    """
    Contribution signing payload:
    {
      "capturedAt": int,
      "contributorId": bytes(32),
      "correctedText": text,
      "id": bytes(16)  -- UUID as 16-byte big-endian
      "modelVersion": text|null,
      "originalModelOutput": text|null,
      "sourceLang": text,
      "sourceText": text,
      "targetLang": text
    }
    Sorted: capturedAt, contributorId, correctedText, id, modelVersion, originalModelOutput, sourceLang, sourceText, targetLang
    """
    m: Dict[str, Any] = {
        "capturedAt": contrib.captured_at,
        "contributorId": contrib.contributor_id.public_key,
        "correctedText": contrib.corrected_text,
        "id": contrib.id.bytes,  # 16 bytes big-endian
        "modelVersion": contrib.model_version,
        "originalModelOutput": contrib.original_model_output,
        "sourceLang": contrib.source_lang,
        "sourceText": contrib.source_text,
        "targetLang": contrib.target_lang,
    }
    return encode_canonical(m)


def encode_card_tx_signing(tx) -> bytes:
    """
    CardTxRecord signing payload:
    {
      "amount": int,
      "balanceAfter": int,
      "cardId": bytes,
      "counter": int,
      "nonce": bytes,
      "timestamp": int
    }
    Sorted: amount, balanceAfter, cardId, counter, nonce, timestamp
    """
    m: Dict[str, Any] = {
        "amount": tx.amount,
        "balanceAfter": tx.balance_after,
        "cardId": tx.card_id,
        "counter": tx.counter,
        "nonce": tx.nonce,
        "timestamp": tx.timestamp,
    }
    return encode_canonical(m)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s)
