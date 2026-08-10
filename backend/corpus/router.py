"""
Contribution ingest & scoring — §M9.

Score = acceptance_gate × quality_weight × novelty_weight × recency_decay

Where:
 - acceptance_gate: 0 or 1 (dedup + quality classifier + review sample)
 - quality_weight: 0.5–1.5 (inter-annotator agreement)
 - novelty_weight: 0.5–2.0 (embedding distance to existing corpus)
 - recency_decay: exp(-age_days / 365)
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import time
import math
import hashlib
from collections import defaultdict

from common.models import Contribution

router = APIRouter(prefix="/corpus", tags=["corpus"])

_contributions: List[Contribution] = []
_corpus_by_release: dict[str, list[str]] = {}  # release_id -> contribution id hexes
_embeddings: dict[str, list[float]] = {}  # stub embeddings

def _quality_classifier(text: str) -> bool:
    # Stub adversarial garbage detection — >95% on held-out set required for M9
    if len(text.strip()) < 3:
        return False
    if text.count("http") > 2:
        return False
    # Block trivial repeats like "aaaa..."
    if len(set(text.lower())) < 3:
        return False
    return True

def _dedup_check(contribution: Contribution) -> bool:
    # Near-duplicate via embedding distance stub (exact text match for now)
    for existing in _contributions:
        if existing.correctedText.strip().lower() == contribution.correctedText.strip().lower():
            return False  # duplicate
    return True

def _novelty_weight(contribution: Contribution) -> float:
    # Stub: distance to nearest existing embedding; 0.5–2.0
    # Real uses sentence embedding cosine distance
    if not _contributions:
        return 1.0
    # Cheap heuristic: length novelty
    avg_len = sum(len(c.correctedText) for c in _contributions) / len(_contributions)
    diff = abs(len(contribution.correctedText) - avg_len) / max(avg_len, 1)
    return max(0.5, min(2.0, 0.8 + diff))

def _recency_decay(captured_at: int) -> float:
    now = int(time.time())
    age_days = max(0, (now - captured_at) / 86400)
    return math.exp(-age_days / 365.0)

class ContributionIngestRequest(BaseModel):
    contribution: Contribution
    inter_annotator_agreement: float = 1.0  # 0.5–1.5 mapped

@router.post("/contributions")
async def ingest_contribution(req: ContributionIngestRequest):
    c = req.contribution
    # Acceptance gate
    if not _quality_classifier(c.correctedText):
        return {"accepted": False, "reason": "quality_classifier_failed", "score": 0}
    if not _dedup_check(c):
        return {"accepted": False, "reason": "duplicate", "score": 0}

    quality_w = max(0.5, min(1.5, req.inter_annotator_agreement))
    novelty_w = _novelty_weight(c)
    recency = _recency_decay(c.capturedAt)

    score = 1.0 * quality_w * novelty_w * recency

    _contributions.append(c)
    return {
        "accepted": True,
        "score": round(score, 4),
        "quality_weight": quality_w,
        "novelty_weight": round(novelty_w, 3),
        "recency_decay": round(recency, 3),
    }

@router.get("/contributions")
async def list_contributions():
    return {"count": len(_contributions), "contributions": _contributions}

@router.post("/releases/{release_id}/freeze")
async def freeze_release(release_id: str):
    if release_id in _corpus_by_release:
        raise HTTPException(status_code=409, detail="Release already frozen")
    ids = [c.id.hex if hasattr(c.id, 'hex') else str(c.id) for c in _contributions]
    _corpus_by_release[release_id] = ids
    # Immutable snapshot hash
    snapshot_hash = hashlib.sha256(",".join(sorted(ids)).encode()).hexdigest()
    return {"release_id": release_id, "snapshot_hash": snapshot_hash, "size": len(ids)}

@router.get("/releases/{release_id}")
async def get_release(release_id: str):
    ids = _corpus_by_release.get(release_id)
    if ids is None:
        raise HTTPException(status_code=404, detail="Release not found")
    return {"release_id": release_id, "contribution_ids": ids, "size": len(ids)}
