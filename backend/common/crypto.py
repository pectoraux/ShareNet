"""
Ed25519 verification — cryptography lib.

Keys are raw 32-byte Ed25519 public keys (as used by Tink's Ed25519Verify).
Signatures are raw 64-byte Ed25519 signatures.
We use `cryptography.hazmat.primitives.asymmetric.ed25519`.

Signing is NOT performed here in production (keys are in Android Keystore / HSM / SE).
A test-only helper `sign_for_test` is provided for golden-vector generation.
"""
from __future__ import annotations

from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False
    Ed25519PrivateKey = None  # type: ignore
    Ed25519PublicKey = None  # type: ignore
    InvalidSignature = Exception  # type: ignore


class CryptoError(Exception):
    pass


def verify_ed25519(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify Ed25519 signature. Returns True if valid, False if invalid.
    Raises CryptoError on malformed inputs.
    """
    if len(public_key_bytes) != 32:
        raise CryptoError(f"public key must be 32 bytes, got {len(public_key_bytes)}")
    if len(signature) != 64:
        raise CryptoError(f"signature must be 64 bytes, got {len(signature)}")
    if not _HAS_CRYPTO:
        raise CryptoError("cryptography library not installed")
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        raise CryptoError(str(e)) from e


def verify_or_raise(public_key_bytes: bytes, message: bytes, signature: bytes) -> None:
    """Verify and raise CryptoError if invalid."""
    if not verify_ed25519(public_key_bytes, message, signature):
        raise CryptoError("Ed25519 signature verification failed")


# ---------------------------------------------------------------------------
# Test-only helpers (deterministic key generation from seed)
# ---------------------------------------------------------------------------

def private_key_from_seed(seed: bytes) -> "Ed25519PrivateKey":
    """
    Deterministic private key from 32-byte seed (for tests / golden vectors).
    In production keys are generated in Keystore/HSM and never leave.
    """
    if len(seed) != 32:
        raise CryptoError("seed must be 32 bytes")
    if not _HAS_CRYPTO:
        raise CryptoError("cryptography not installed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def sign_for_test(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """
    Sign message with deterministic seed. Returns (public_key_bytes, signature_bytes).
    TEST ONLY — never use in production paths.
    """
    sk = private_key_from_seed(seed)
    sig = sk.sign(message)
    pk = sk.public_key().public_bytes_raw()  # type: ignore[attr-defined]
    # cryptography 42+ uses public_bytes_raw(); fallback:
    if not isinstance(pk, (bytes, bytearray)):
        from cryptography.hazmat.primitives import serialization
        pk = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    return bytes(pk), bytes(sig)


def public_key_from_seed(seed: bytes) -> bytes:
    sk = private_key_from_seed(seed)
    try:
        pk = sk.public_key().public_bytes_raw()  # type: ignore
    except AttributeError:
        from cryptography.hazmat.primitives import serialization
        pk = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    return bytes(pk)
