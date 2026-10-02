"""FastAPI 진입점. 정적·LLM 분석은 Phase 3·4에서 구현. 지금은 빈 결과 왕복 스켈레톤."""
from __future__ import annotations

from fastapi import FastAPI

from app.config import settings
from app.models import AnalysisResult, AnalyzeRequest, PreprocessSection

app = FastAPI(title="Supply Chain Watch Engine", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "service": "engine",
        "model": settings.llm_model,
        "provider": "anthropic",
        "rulesLoaded": 0,
        "promptVersion": None,
    }


@app.post("/analyze", response_model=AnalysisResult, response_model_by_alias=True)
def analyze(req: AnalyzeRequest) -> AnalysisResult:
    # Phase 3: 정적 분석 → Phase 4: LLM. 현재는 입력을 받아 빈 결과를 돌려준다.
    return AnalysisResult(
        preprocess=PreprocessSection(analyzed_bytes=len(req.diff.encode("utf-8"))),
    )


@app.post("/analyze/static", response_model=AnalysisResult, response_model_by_alias=True)
def analyze_static(req: AnalyzeRequest) -> AnalysisResult:
    return AnalysisResult(
        preprocess=PreprocessSection(analyzed_bytes=len(req.diff.encode("utf-8"))),
    )
