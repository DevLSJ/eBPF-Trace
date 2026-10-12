"""분석 오케스트레이션 (docs/03 §1): 전처리 → 정적 → 게이트 → (Phase 4: LLM) → 융합."""
from __future__ import annotations

from app.config import settings
from app.models import (
    AnalysisResult,
    AnalyzeRequest,
    LlmSection,
    MatchedRule,
    PreprocessSection,
    StaticSection,
)
from app.static.engine import StaticOutcome, run_rules
from app.static.gate import decide
from app.static.preprocess import parse_diff
from app.static.rules_loader import get_rules

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _static_tags(outcome: StaticOutcome) -> list[str]:
    """정적만으로 낸 태그: 주의(MEDIUM) 이상 룰의 분류만. 약한 보조 룰(LOW)은 태그를 만들지 않는다."""
    ordered = sorted(outcome.hits, key=lambda h: _SEV_ORDER[h.rule.severity])
    return list(dict.fromkeys(h.rule.category for h in ordered if h.rule.severity != "LOW"))


def analyze(req: AnalyzeRequest, *, allow_llm: bool = True) -> AnalysisResult:
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
        score=outcome.score,
        level=outcome.level,
        matched_rules=matched,
        sensitive_files=[f.path for f in files if f.is_sensitive],
        latency_ms=outcome.latency_ms,
    )
    passed = gate.call_llm and allow_llm
    llm = LlmSection(
        status="SKIPPED_GATE",
        gate_passed=passed,
        gate_reasons=gate.reasons,
        prompt_name=gate.prompt_name,
        error="LLM 분석은 아직 연결되지 않았습니다(Phase 4)" if passed else None,
    )
    # LLM 미실행 → 최종 = 정적 결과 (docs/03 §6)
    return AnalysisResult(
        risk_score=outcome.score,
        risk_level=outcome.level,
        tags=_static_tags(outcome),
        static=static,
        llm=llm,
        preprocess=PreprocessSection(
            truncated="…[파일 절삭]" in req.diff,
            analyzed_bytes=len(req.diff.encode("utf-8")),
        ),
    )
