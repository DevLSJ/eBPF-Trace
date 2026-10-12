"""FastAPI 진입점. 정적 분석(Phase 3) 연결. LLM은 Phase 4."""
from __future__ import annotations

from fastapi import FastAPI

from app.analyze import analyze as run_analysis
from app.config import settings
from app.models import AnalysisResult, AnalyzeRequest
from app.static.rules_loader import get_rules

app = FastAPI(title="Supply Chain Watch Engine", version="0.2.0")


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "service": "engine",
        "model": settings.llm_model,
        "provider": "anthropic",
        "rulesLoaded": len(get_rules()),
        "promptVersion": None,
    }


@app.post("/analyze", response_model=AnalysisResult, response_model_by_alias=True)
def analyze(req: AnalyzeRequest) -> AnalysisResult:
    return run_analysis(req)


@app.post("/analyze/static", response_model=AnalysisResult, response_model_by_alias=True)
def analyze_static(req: AnalyzeRequest) -> AnalysisResult:
    """LLM 없이 정적 분석만 (평가 스크립트·디버깅용)."""
    return run_analysis(req, allow_llm=False)
