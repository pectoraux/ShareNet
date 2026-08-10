"""ShareNet backend — FastAPI app."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from catalog.router import router as catalog_router
from attest.router import router as attest_router
from corpus.router import router as corpus_router
from training.router import router as training_router
from settlement.router import router as settlement_router

app = FastAPI(
    title="ShareNet Backend",
    description="Catalog, Attest, Corpus, Training, Settlement — Offline-first mesh platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(catalog_router)
app.include_router(attest_router)
app.include_router(corpus_router)
app.include_router(training_router)
app.include_router(settlement_router)

@app.get("/")
async def root():
    return {"service": "sharenet-backend", "version": "0.1.0", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "ok"}
