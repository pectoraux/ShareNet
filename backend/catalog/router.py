from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from pydantic import BaseModel
import time

from common.models import Manifest, CatalogEntry, Category
from common.crypto import verify_ed25519
from common.cbor import encode_manifest_signing

router = APIRouter(prefix="/catalog", tags=["catalog"])

# In-memory stores — replace with Postgres + SQLAlchemy in prod
_manifests: dict[str, Manifest] = {}
_publishers: dict[str, bytes] = {}  # publisherId hex -> public key
_revoked: set[str] = set()
_root_key: Optional[bytes] = None

class PublishRequest(BaseModel):
    manifest: Manifest

class RevokeRequest(BaseModel):
    blobId: str  # hex of merkleRoot
    reason: str = ""

@router.get("/catalog", response_model=List[CatalogEntry])
async def list_catalog(category: Optional[Category] = None, min_app_version: Optional[int] = None):
    entries = []
    for m in _manifests.values():
        blob_hex = m.blobId.merkle_root.hex()
        if blob_hex in _revoked:
            continue
        #_stub category/minAppVersion from in-memory; real uses CatalogEntry table
        entries.append(CatalogEntry(manifest=m, category=category or Category.EDUCATION, priority=50, min_app_version=1))
    if category:
        entries = [e for e in entries if e.category == category]
    # REVOCATION priority would sort first — stub
    return entries

@router.post("/publish", response_model=Manifest)
async def publish(req: PublishRequest):
    m = req.manifest
    # Verify signature via canonical CBOR
    payload = encode_manifest_signing(m.model_dump() if hasattr(m, 'model_dump') else dict(m))
    pub_key = m.publisherId.public_key
    if not verify_ed25519(pub_key, payload, m.signature):
        raise HTTPException(status_code=400, detail="Invalid manifest signature")
    # Check publisher registry (pinned root key)
    if _root_key and pub_key not in _publishers.values():
        # allow only registered publishers — simplified
        pass
    blob_hex = m.blobId.merkle_root.hex()
    if blob_hex in _revoked:
        raise HTTPException(status_code=409, detail="Blob revoked")
    _manifests[blob_hex] = m
    return m

@router.post("/revoke")
async def revoke(req: RevokeRequest):
    _revoked.add(req.blobId.lower())
    # Priority propagation: revocation entries must be synced before content.
    # In prod this is a DB flag that the sync endpoint orders by (priority DESC).
    return {"revoked": req.blobId, "priority": 100}

@router.get("/manifest/{blob_id}")
async def get_manifest(blob_id: str):
    m = _manifests.get(blob_id.lower())
    if not m:
        raise HTTPException(status_code=404, detail="Not found")
    return m

@router.get("/publishers")
async def list_publishers():
    return {"publishers": list(_publishers.keys()), "root_key": _root_key.hex() if _root_key else None}
