"""FastAPI 진입점. 정적 분석(Phase 3) + LLM 2차 분석(Phase 4)."""
from __future__ import annotations

from fastapi import FastAPI

from app.analyze import analyze as run_analysis
from app.config import settings
from app.llm import prompts
from app.models import AnalysisResult, AnalyzeRequest
from app.static.rules_loader import get_rules

app = FastAPI(title="Supply Chain Watch Engine", version="0.3.0")


@app.get("/health")
def health() -> dict:
    try:
        version = prompts.get_template("default").version
    except Exception:  # noqa: BLE001 — DB 없이도 health는 응답
        version = None
    return {
        "ok": True,
        "service": "engine",
        "model": settings.llm_model,
        "modelCheap": settings.llm_model_cheap,
        "twoStage": settings.llm_two_stage,
        "provider": "anthropic",
        "rulesLoaded": len(get_rules()),
        "promptVersion": version,
    }


@app.post("/analyze", response_model=AnalysisResult, response_model_by_alias=True)
async def analyze(req: AnalyzeRequest) -> AnalysisResult:
    return await run_analysis(req)


@app.post("/analyze/static", response_model=AnalysisResult, response_model_by_alias=True)
async def analyze_static(req: AnalyzeRequest) -> AnalysisResult:
    """LLM 없이 정적 분석만 (평가 스크립트·디버깅용)."""
    return await run_analysis(req, allow_llm=False)


@app.post("/prompts/reload")
def prompts_reload() -> dict:
    """설정 화면에서 프롬프트를 저장하면 gateway가 호출 (docs/03 §5.6)."""
    return {"ok": True, "data": prompts.reload()}
