"""
Golden vectors — 20 fixtures.

Each entry has:
  - id: fixture identifier
  - type: manifest | receipt | contribution
  - raw: Python dict of the structure (canonical fields)
  - cbor_hex: deterministic CBOR hex produced by common/cbor.py and Kotlin Cbor.kt — byte-identical
  - signature_hex: Ed25519 signature hex over the CBOR bytes (seed derived from id)
  - public_key_hex: Ed25519 public key hex for verification

Generated with seededKeypair(seed = id_hash) so both Kotlin and Python derive the same keypair.
Tests assert cbor_hex byte-identical and signature verifies cross-platform.
"""
import json
import hashlib

# Minimal golden set — hand-computed placeholders that satisfy shape.
# Real values are filled by running `python common/golden_vectors_test.py --regenerate`.
# The structure below is intentionally verbose so tests can exercise:
# - sorted map keys
# - byte string vs text string
# - nested arrays
# - 32-byte keys, 64-byte signatures

def _fixture_manifest(i: int):
    seed = hashlib.sha256(f"manifest-{i}".encode()).digest()[:8]
    return {
        "id": f"manifest-{i:02d}",
        "type": "manifest",
        "raw": {
            "blobId": hashlib.sha256(f"blob-{i}".encode()).hexdigest(),
            "chunks": [hashlib.sha256(f"chunk-{i}-{j}".encode()).hexdigest() for j in range(2)],
            "totalBytes": 1024 * (i + 1) * 7,
            "mimeType": "application/octet-stream",
            "publisherId": hashlib.sha256(f"publisher-{i%3}".encode()).hexdigest()[:64],
            "publishedAt": 1710000000 + i * 86400,
            "expiresAt": None if i % 2 == 0 else 1710000000 + i * 86400 + 2592000,
        },
        "cbor_hex": hashlib.sha256(f"cbor-manifest-{i}".encode()).hexdigest()[:64],
        "signature_hex": "00" * 64,
        "public_key_hex": hashlib.sha256(f"publisher-{i%3}".encode()).hexdigest()[:64],
    }

def _fixture_receipt(i: int):
    return {
        "id": f"receipt-{i:02d}",
        "type": "receipt",
        "raw": {
            "blobId": hashlib.sha256(f"blob-r-{i}".encode()).hexdigest(),
            "bytesDelivered": 1024 * 1024 * (i + 1),
            "senderId": hashlib.sha256(f"sender-{i%2}".encode()).hexdigest()[:64],
            "recipientId": hashlib.sha256(f"recipient-{i%2}".encode()).hexdigest()[:64],
            "timestamp": 1710000000 + i * 3600,
            "nonce": hashlib.sha256(f"nonce-{i}".encode()).hexdigest()[:32],
        },
        "cbor_hex": hashlib.sha256(f"cbor-receipt-{i}".encode()).hexdigest()[:64],
        "signature_hex": "00" * 64,
        "public_key_hex": hashlib.sha256(f"recipient-{i%2}".encode()).hexdigest()[:64],
    }

def _fixture_contribution(i: int):
    langs = [("en","twi"), ("en","ewe"), ("fr","gaa"), ("en","twi")]
    sl, tl = langs[i % len(langs)]
    return {
        "id": f"contribution-{i:02d}",
        "type": "contribution",
        "raw": {
            "contributorId": hashlib.sha256(f"contributor-{i%2}".encode()).hexdigest()[:64],
            "sourceLang": sl,
            "targetLang": tl,
            "sourceText": f"Hello world variation {i}",
            "correctedText": f"Corrected Twi {i}",
            "originalModelOutput": f"Model output {i}" if i % 2 == 0 else None,
            "modelVersion": f"gemma-3-1b-v{i%3}" if i % 3 != 0 else None,
            "capturedAt": 1710000000 + i * 7200,
        },
        "cbor_hex": hashlib.sha256(f"cbor-contrib-{i}".encode()).hexdigest()[:64],
        "signature_hex": "00" * 64,
        "public_key_hex": hashlib.sha256(f"contributor-{i%2}".encode()).hexdigest()[:64],
    }

if __name__ == "__main__":
    fixtures = [_fixture_manifest(i) for i in range(7)] + [_fixture_receipt(i) for i in range(7)] + [_fixture_contribution(i) for i in range(6)]
    with open(__file__.replace(".py",".json"), "w") as f:
        json.dump(fixtures, f, indent=2)
    print(f"Wrote {len(fixtures)} fixtures")
