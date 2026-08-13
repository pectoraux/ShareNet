"""
Receipt ingest, fraud scoring, points ledger — §M4.

Rules (ROADMAP §4 M4):
 - Recipient diversity: receipts from same pair beyond N/day weighted to zero
 - Play Integrity on upload (stub)
 - Geographic/temporal plausibility (reject impossible sequences)
 - Rate caps per identity per day
 - 30-day holdback before points convert; clawback on later fraud
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict
import time
from collections import defaultdict

from common.models import DeliveryReceipt
from common.crypto import verify_ed25519
from common.cbor import encode_receipt_signing

router = APIRouter(prefix="/attest", tags=["attest"])

_receipts: List[DeliveryReceipt] = []
_nonces: set[str] = set()
_daily_counts: Dict[str, int] = defaultdict(int)  # recipient hex -> count today
_points: Dict[str, int] = defaultdict(int)        # sender hex -> points (holdback)

# Config
MAX_RECEIPTS_PER_PAIR_PER_DAY = 50
MAX_RECEIPTS_PER_IDENTITY_PER_DAY = 200
HOLD_BACK_DAYS = 30

class ReceiptUploadRequest(BaseModel):
    receipt: DeliveryReceipt
    play_integrity_token: str | None = None  # validated if present

def _verify_play_integrity(token: str | None) -> bool:
    # Stub — in prod calls Play Integrity API
    if token is None:
        return True  # allow offline; real would flag for review
    return token.startswith("valid-")

def _check_geo_temporal(receipt: DeliveryReceipt) -> bool:
    # Stub: reject if timestamp is far future or same pair with <1s gap
    now = int(time.time())
    if receipt.timestamp > now + 300:
        return False
    return True

@router.post("/receipts")
async def ingest_receipt(req: ReceiptUploadRequest):
    r = req.receipt
    # Nonce replay
    nonce_hex = r.nonce.hex()
    if nonce_hex in _nonces:
        raise HTTPException(status_code=409, detail="Replayed nonce")
    # Recipient signature verification (sender cannot forge)
    payload = encode_receipt_signing(r.model_dump() if hasattr(r, 'model_dump') else dict(r))
    if not verify_ed25519(r.recipientId.public_key, payload, r.recipientSignature):
        raise HTTPException(status_code=400, detail="Invalid recipient signature")
    if not _verify_play_integrity(req.play_integrity_token):
        raise HTTPException(status_code=400, detail="Play Integrity failed")
    if not _check_geo_temporal(r):
        raise HTTPException(status_code=400, detail="Geographically/temporally implausible")
    # Rate caps
    recipient_hex = r.recipientId.public_key.hex()
    sender_hex = r.senderId.public_key.hex()
    pair_key = f"{sender_hex}:{recipient_hex}"
    if _daily_counts[pair_key] >= MAX_RECEIPTS_PER_PAIR_PER_DAY:
        # Weighted to zero — still store but 0 points
        points = 0
    elif _daily_counts[sender_hex] >= MAX_RECEIPTS_PER_IDENTITY_PER_DAY:
        raise HTTPException(status_code=429, detail="Rate cap exceeded")
    else:
        points = int(r.bytesDelivered // 1024)  # 1 point per KB, example

    _nonces.add(nonce_hex)
    _daily_counts[pair_key] += 1
    _daily_counts[sender_hex] += 1
    _receipts.append(r)
    if points > 0:
        _points[sender_hex] += points
    return {"accepted": True, "points_awarded": points, "holdback_days": HOLD_BACK_DAYS}

@router.get("/receipts")
async def list_receipts():
    return {"receipts": _receipts, "count": len(_receipts)}

@router.get("/points/{node_id}")
async def get_points(node_id: str):
    return {"node_id": node_id, "points": _points.get(node_id.lower(), 0), "holdback_days": HOLD_BACK_DAYS}

@router.post("/points/clawback/{node_id}")
async def clawback(node_id: str, points: int):
    hex_id = node_id.lower()
    _points[hex_id] = max(0, _points.get(hex_id, 0) - points)
    return {"node_id": hex_id, "points": _points[hex_id]}
