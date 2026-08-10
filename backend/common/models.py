"""
ShareNet canonical data model — mirrors Kotlin data classes byte-for-byte.

All ByteArray fields are 32-byte hashes / 32-byte Ed25519 keys / 64-byte signatures.
Pydantic v2 models validate lengths and expose helpers for CBOR canonical encoding.
"""
from __future__ import annotations

import base64
import binascii
import enum
import uuid
from typing import Optional, List

from pydantic import BaseModel, Field, field_validator, ConfigDict


# ---------------------------------------------------------------------------
# Primitive wrappers
# ---------------------------------------------------------------------------

class NodeId(BaseModel):
    """Ed25519 public key — primary key everywhere. 32 bytes."""
    model_config = ConfigDict(frozen=True)
    public_key: bytes = Field(..., min_length=32, max_length=32, description="Ed25519 public key, 32 bytes")

    @field_validator("public_key", mode="before")
    @classmethod
    def _coerce_hex(cls, v):
        if isinstance(v, str):
            # accept hex (64 chars) or base64
            v = v.strip()
            if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
                return bytes.fromhex(v)
            # try base64
            try:
                return base64.b64decode(v)
            except Exception:
                raise ValueError("NodeId must be 32-byte hex or base64")
        return v

    def hex(self) -> str:
        return self.public_key.hex()

    def __hash__(self):
        return hash(self.public_key)

    def __eq__(self, other):
        if isinstance(other, NodeId):
            return self.public_key == other.public_key
        return False


class ChunkId(BaseModel):
    model_config = ConfigDict(frozen=True)
    sha256: bytes = Field(..., min_length=32, max_length=32)

    @field_validator("sha256", mode="before")
    @classmethod
    def _coerce(cls, v):
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    def hex(self) -> str:
        return self.sha256.hex()


class BlobId(BaseModel):
    model_config = ConfigDict(frozen=True)
    merkle_root: bytes = Field(..., min_length=32, max_length=32)

    @field_validator("merkle_root", mode="before")
    @classmethod
    def _coerce(cls, v):
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    def hex(self) -> str:
        return self.merkle_root.hex()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Category(str, enum.Enum):
    EDUCATION = "EDUCATION"
    HEALTH = "HEALTH"
    APP_UPDATE = "APP_UPDATE"
    MODEL_WEIGHTS = "MODEL_WEIGHTS"
    DATASET = "DATASET"
    REVOCATION = "REVOCATION"


# ---------------------------------------------------------------------------
# Manifest / Catalog
# ---------------------------------------------------------------------------

class Manifest(BaseModel):
    """
    Signed manifest. The `signature` field is Ed25519 over the deterministic CBOR
    encoding of all other fields (sorted keys, canonical ints). See common/cbor.py.
    """
    model_config = ConfigDict(frozen=True)
    blob_id: BlobId
    chunks: List[ChunkId]
    total_bytes: int = Field(..., ge=0)
    mime_type: str
    publisher_id: NodeId
    published_at: int = Field(..., description="unix millis")
    expires_at: Optional[int] = Field(default=None, description="unix millis or null")
    signature: bytes = Field(..., min_length=64, max_length=64, description="Ed25519 signature 64 bytes")

    @field_validator("signature", mode="before")
    @classmethod
    def _sig_coerce(cls, v):
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    def signing_bytes(self) -> bytes:
        """Canonical CBOR bytes that are signed (all fields except signature)."""
        from .cbor import encode_manifest_signing
        return encode_manifest_signing(self)


class CatalogEntry(BaseModel):
    manifest: Manifest
    category: Category
    priority: int = Field(..., ge=0, le=100)
    min_app_version: int = Field(..., ge=0)


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------

class DeliveryReceipt(BaseModel):
    """
    Attestation unit that earns points/money.
    recipientSignature is Ed25519 by recipientId over canonical CBOR of
    (blobId, bytesDelivered, senderId, recipientId, timestamp, nonce).
    nonce is recipient-generated anti-replay (16 bytes).
    """
    model_config = ConfigDict(frozen=True)
    blob_id: BlobId
    bytes_delivered: int = Field(..., ge=0)
    sender_id: NodeId
    recipient_id: NodeId
    timestamp: int = Field(..., description="unix millis")
    nonce: bytes = Field(..., min_length=16, max_length=16)
    recipient_signature: bytes = Field(..., min_length=64, max_length=64)

    @field_validator("nonce", "recipient_signature", mode="before")
    @classmethod
    def _hex_coerce(cls, v):
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    def signing_bytes(self) -> bytes:
        from .cbor import encode_receipt_signing
        return encode_receipt_signing(self)


# ---------------------------------------------------------------------------
# Contribution
# ---------------------------------------------------------------------------

class Contribution(BaseModel):
    """
    Corpus contribution that earns model revenue share.
    signature is Ed25519 by contributorId over canonical CBOR of all fields except signature.
    """
    model_config = ConfigDict(frozen=True)
    id: uuid.UUID
    contributor_id: NodeId
    source_lang: str = Field(..., description="BCP-47 or custom: twi, ewe, gaa")
    target_lang: str
    source_text: str
    corrected_text: str
    original_model_output: Optional[str] = None
    model_version: Optional[str] = None
    captured_at: int = Field(..., description="unix millis")
    signature: bytes = Field(..., min_length=64, max_length=64)

    @field_validator("signature", mode="before")
    @classmethod
    def _sig_coerce2(cls, v):
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    @field_validator("source_text", "corrected_text")
    @classmethod
    def _non_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("text must be non-empty")
        return v

    def signing_bytes(self) -> bytes:
        from .cbor import encode_contribution_signing
        return encode_contribution_signing(self)


# ---------------------------------------------------------------------------
# Card transaction record (offline value transfer)
# ---------------------------------------------------------------------------

class CardTxRecord(BaseModel):
    """
    Signed offline transaction produced by ShareNetApplet DEBIT.
    Fields are CBOR-encoded and Ed25519-signed inside the SE.
    """
    model_config = ConfigDict(frozen=True)
    card_id: bytes = Field(..., min_length=8, max_length=32, description="card public key or serial")
    counter: int = Field(..., ge=0, description="monotonic counter from SE")
    amount: int = Field(..., ge=1, description="minor units debited")
    nonce: bytes = Field(..., min_length=8, max_length=32)
    timestamp: int = Field(..., description="unix millis (card clock or terminal supplied)")
    balance_after: int = Field(..., ge=0)
    signature: bytes = Field(..., min_length=64, max_length=64)

    @field_validator("card_id", "nonce", "signature", mode="before")
    @classmethod
    def _hex_c(cls, v):
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    def signing_bytes(self) -> bytes:
        from .cbor import encode_card_tx_signing
        return encode_card_tx_signing(self)


# ---------------------------------------------------------------------------
# SQLAlchemy ORM stubs (async) — real tables created via Alembic in prod
# ---------------------------------------------------------------------------
# Kept here for single-source-of-truth; ORM is optional at import time.

try:
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    from sqlalchemy import String, LargeBinary, BigInteger, Integer, Text
    import sqlalchemy as sa

    class Base(DeclarativeBase):
        pass

    class ManifestRow(Base):
        __tablename__ = "manifests"
        blob_id_hex: Mapped[str] = mapped_column(String(64), primary_key=True)
        publisher_hex: Mapped[str] = mapped_column(String(64), index=True)
        cbor_hex: Mapped[str] = mapped_column(Text)  # canonical cbor hex for audit
        category: Mapped[str] = mapped_column(String(32))
        priority: Mapped[int] = mapped_column(Integer)
        min_app_version: Mapped[int] = mapped_column(Integer)
        published_at: Mapped[int] = mapped_column(BigInteger)
        expires_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
        revoked: Mapped[bool] = mapped_column(sa.Boolean, default=False)

    class ReceiptRow(Base):
        __tablename__ = "receipts"
        nonce_hex: Mapped[str] = mapped_column(String(64), primary_key=True)
        blob_id_hex: Mapped[str] = mapped_column(String(64), index=True)
        sender_hex: Mapped[str] = mapped_column(String(64), index=True)
        recipient_hex: Mapped[str] = mapped_column(String(64), index=True)
        bytes_delivered: Mapped[int] = mapped_column(BigInteger)
        timestamp: Mapped[int] = mapped_column(BigInteger)
        points_awarded: Mapped[int] = mapped_column(Integer, default=0)
        hold_until: Mapped[int] = mapped_column(BigInteger)  # payout holdback

except Exception:
    # SQLAlchemy not installed in minimal test env — ORM is optional
    Base = object  # type: ignore
    ManifestRow = object  # type: ignore
    ReceiptRow = object  # type: ignore
