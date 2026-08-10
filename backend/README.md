# ShareNet backend
FastAPI + PostgreSQL — Python, because the training pipeline is Python.

## Services

| Package | Router | Responsibility |
|---------|--------|---------------|
| `catalog` | `/catalog` | Manifest signing verification, publisher registry (pinned root), revocation with priority |
| `attest` | `/attest` | Delivery receipt ingest (recipient-only sig), fraud scoring, points ledger, 30d holdback/clawback |
| `corpus` | `/corpus` | Contribution ingest, dedup (embedding), quality classifier, `score = gate × quality × novelty × recency_decay`, frozen releases |
| `training` | `/training` | LoRA fine-tune stub, eval harness, release as `MODEL_WEIGHTS` into catalog |
| `settlement` | `/settlement` | Card tx verification, double-spend detection, revocation publication, reconciliation, **exact `Decimal` ledger** |
| `common` | — | Pydantic models mirroring Kotlin data classes, deterministic CBOR, Ed25519 verify |

## Run

```bash
cd backend
uv sync
uv run uvicorn main:app --reload  # http://localhost:8000/docs
pytest
```

## Golden vectors

`common/golden_vectors.json` (20 fixtures) — Kotlin `core-crypto/Cbor.kt` and Python `common/cbor.py` must produce byte-identical CBOR + signatures. Generate:

```bash
python common/golden_vectors.py
```

## Money

`settlement/router.py` and `corpus/router.py` use `Decimal` / `NUMERIC` — never float in ledger. Shares sum to exactly 1.0 via rational arithmetic.
