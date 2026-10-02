"""FastAPI 진입점. Phase 1 feature 4에서 /health, /analyze(빈 결과) 구현."""
from __future__ import annotations

from fastapi import FastAPI

from app.config import settings

app = FastAPI(title="Supply Chain Watch Engine", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "engine", "model": settings.llm_model}
