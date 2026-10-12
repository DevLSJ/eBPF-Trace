"""분석 오케스트레이션 (docs/03 §1): 전처리 → 정적 → 게이트 → LLM → 융합(§6)."""
from __future__ import annotations

from app.config import settings
from app.llm.analyzer import LlmRun, run_llm
from app.models import (
    AnalysisResult,
    AnalyzeRequest,
    LlmSection,
    MatchedRule,
    PreprocessSection,
    StaticSection,
)
from app.static.engine import StaticOutcome, level_of, run_rules
from app.static.gate import decide
from app.static.preprocess import parse_diff
from app.static.rules_loader import get_rules

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _static_tags(outcome: StaticOutcome, min_sev: str = "MEDIUM") -> list[str]:
    """정적 태그: 기준 심각도 이상 룰의 분류만. 약한 보조 룰(LOW)은 태그를 만들지 않는다."""
    limit = _SEV_ORDER[min_sev]
    ordered = sorted(outcome.hits, key=lambda h: _SEV_ORDER[h.rule.severity])
    return list(dict.fromkeys(h.rule.category for h in ordered if _SEV_ORDER[h.rule.severity] <= limit))


def fuse(outcome: StaticOutcome, run: LlmRun | None) -> tuple[int, str, list[str]]:
    """docs/03 §6: LLM이 결과를 냈으면 LLM 점수 기준(치명 룰이 있으면 최소 60), 아니면 정적 점수."""
    if run is not None and run.status in ("OK", "CACHED") and run.analysis is not None:
        score = run.analysis.risk_score
        if any(h.rule.severity == "CRITICAL" for h in outcome.hits):
            score = max(score, 60)
        llm_tags = [t for t in run.analysis.detected_tags if t != "NONE"]
        tags = list(dict.fromkeys(llm_tags + _static_tags(outcome, "HIGH")))
        return score, level_of(score), tags
    return outcome.score, outcome.level, _static_tags(outcome)


async def analyze(req: AnalyzeRequest, *, allow_llm: bool = True) -> AnalysisResult:
    statuses = {f.filename: f.status for f in req.files}
    files = parse_diff(req.diff, statuses)
    outcome = run_rules(get_rules(), files)
    gate = decide(outcome, files, req.options, settings.llm_threshold)

    matched = [
        MatchedRule(
            rule_id=h.rule.id, category=h.rule.category, severity=h.rule.severity, file=h.file.path,
            snippet=h.snippet, line_hint=h.snippet, count=h.count, description_ko=h.rule.description_ko,
        )
        for h in sorted(outcome.hits, key=lambda h: (_SEV_ORDER[h.rule.severity], h.file.path))
    ]
    static = StaticSection(
        score=outcome.score, level=outcome.level, matched_rules=matched,
        sensitive_files=[f.path for f in files if f.is_sensitive], latency_ms=outcome.latency_ms,
    )

    passed = gate.call_llm and allow_llm
    run: LlmRun | None = None
    if passed:
        try:
            run = await run_llm(req, outcome, files, gate)
        except Exception as e:  # noqa: BLE001 — DB·Redis 장애 등: 정적 결과로 계속
            run = LlmRun("ERROR", error=f"llm pipeline: {type(e).__name__}: {str(e)[:160]}")

    llm = LlmSection(
        status=run.status if run else "SKIPPED_GATE",
        model=run.model if run else None,
        prompt_version=run.prompt_version if run else None,
        result=run.analysis.model_dump(by_alias=True) if run and run.analysis else None,
        usage=run.usage if run else None,
        latency_ms=run.latency_ms if run else None,
        error=run.error if run else None,
        gate_passed=passed, gate_reasons=gate.reasons, prompt_name=gate.prompt_name,
        stages=run.stages if run else [],
    )
    score, level, tags = fuse(outcome, run)
    return AnalysisResult(
        risk_score=score, risk_level=level, tags=tags, static=static, llm=llm,
        preprocess=PreprocessSection(truncated="…[파일 절삭]" in req.diff, analyzed_bytes=len(req.diff.encode("utf-8"))),
    )
