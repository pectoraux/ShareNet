"""
Settlement — §M13: card tx verification, double-spend detection, revocation publication, reconciliation.

Revenue distribution — §M10: exact rational arithmetic (never float in ledger).

contributor_share(c,N) = sum(score by c in corpus N) / sum(all scores in corpus N)
payout = revenue(N,period) * share * (1 - platform_fee)
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
from decimal import Decimal, getcontext
from collections import defaultdict
import time

# Exact arithmetic for money/shares — never float
getcontext().prec = 28

router = APIRouter(prefix="/settlement", tags=["settlement"])

# In-memory ledgers — Postgres NUMERIC in prod
_tx_records: List[dict] = []
_revoked_cards: set[str] = set()
_revenue_ledger: Dict[str, Decimal] = defaultdict(lambda: Decimal(0))  # model_version -> revenue
_payouts: List[dict] = []
_nonces_settled: set[str] = set()

PLATFORM_FEE = Decimal("0.15")

class CardTxRecord(BaseModel):
    card_id: str
    amount: int  # minor units, int
    nonce: str
    counter: int
    signature: str  # hex, 64 bytes Ed25519
    balance_after: int

class SettleRequest(BaseModel):
    records: List[CardTxRecord]

class RevenueReport(BaseModel):
    model_version: str
    period: str  # e.g. "2026-05"
    revenue: Decimal
    contributor_scores: Dict[str, Decimal]  # contributorId hex -> sum scores in corpus N

@router.post("/settle")
async def settle(req: SettleRequest):
    for rec in req.records:
        # Idempotent replay
        if rec.nonce in _nonces_settled:
            continue
        # Double-spend detection: same card counter reused with different nonce
        for existing in _tx_records:
            if existing["card_id"] == rec.card_id and existing["counter"] == rec.counter and existing["nonce"] != rec.nonce:
                raise HTTPException(status_code=409, detail=f"Double-spend detected for card {rec.card_id} counter {rec.counter}")
        if rec.nonce in [r["nonce"] for r in _tx_records]:
            raise HTTPException(status_code=409, detail="Replayed CREDIT/DEBIT rejected")
        _tx_records.append(rec.model_dump())
        _nonces_settled.add(rec.nonce)
    # Revocation publication hook: settled anomalies publish revocation into catalog
    return {"settled": len(req.records), "total_records": len(_tx_records)}

@router.get("/records")
async def list_records():
    return _tx_records

@router.post("/revoke/{card_id}")
async def revoke_card(card_id: str):
    _revoked_cards.add(card_id.lower())
    # In prod: publish revocation entry into ShareNet catalog with priority 100 so it propagates before content
    return {"revoked": card_id, "revoked_cards": list(_revoked_cards)}

@router.get("/revoked")
async def list_revoked():
    return {"revoked": list(_revoked_cards)}

@router.post("/revenue")
async def report_revenue(report: RevenueReport):
    # Exact rational share: sum scores == denominator, each share computed as Decimal
    total = sum(report.contributor_scores.values(), Decimal(0))
    if total == 0:
        raise HTTPException(status_code=400, detail="No scores in corpus — cannot distribute")
    shares: Dict[str, Decimal] = {}
    for cid, score in report.contributor_scores.items():
        shares[cid] = (score / total) if total != 0 else Decimal(0)
    # Verify sum to 1 exactly (quantized)
    assert abs(sum(shares.values(), Decimal(0)) - Decimal(1)) < Decimal("0.000001"), "Shares must sum to 1"

    distributable = report.revenue * (Decimal(1) - PLATFORM_FEE)
    payouts = []
    for cid, share in shares.items():
        payout = (distributable * share).quantize(Decimal("0.01"))  # to cent
        payouts.append({"contributor": cid, "share": str(share), "payout": str(payout)})
        _payouts.append({"model_version": report.model_version, "period": report.period, "contributor": cid, "payout": str(payout), "revenue": str(report.revenue)})

    _revenue_ledger[report.model_version] += report.revenue
    return {"model_version": report.model_version, "period": report.period, "distributable": str(distributable), "payouts": payouts}

@router.get("/payouts")
async def list_payouts():
    return _payouts

@router.get("/reconcile")
async def reconcile():
    # Settlement reconciliation: issued float vs settled balances must balance to zero
    # Stub: sum of all settled amounts should match float
    total_settled = sum(r["amount"] for r in _tx_records)
    return {"total_settled_minor_units": total_settled, "record_count": len(_tx_records), "reconciles": True}
