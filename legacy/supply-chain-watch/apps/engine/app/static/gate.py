"""LLM 게이트 (docs/03 §4). 정적 결과를 보고 2차 LLM 분석을 부를지, 어떤 프롬프트로 부를지 정한다.

예산(시간당 상한)·diff 캐시는 Phase 4에서 이 결정 뒤에 붙는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.models import AnalyzeOptions
from app.static.engine import StaticOutcome
from app.static.preprocess import ParsedFile

CI_LANGS = {"WORKFLOW", "DOCKER", "SHELL", "MAKE"}  # docs/03 §5.5.1 ci 프롬프트 대상
ALWAYS_LLM_LANGS = {"WORKFLOW", "DOCKER"}  # 빈도 낮고 위험도 높음 → 게이트와 무관하게 LLM


@dataclass
class GateDecision:
    call_llm: bool
    prompt_name: str
    reasons: list[str] = field(default_factory=list)


def decide(outcome: StaticOutcome, files: list[ParsedFile], opts: AnalyzeOptions, threshold: int) -> GateDecision:
    reasons: list[str] = []
    if opts.force_llm:
        reasons.append("재분석 요청(LLM 강제)")
    if opts.always_llm:
        reasons.append("레포 설정: 항상 LLM")
    if outcome.score >= threshold:
        reasons.append(f"정적 점수 {outcome.score} ≥ {threshold}")
    critical = sorted({h.rule.id for h in outcome.hits if h.rule.severity == "CRITICAL"})
    if critical:
        reasons.append(f"치명 룰: {', '.join(critical)}")
    ci_files = [f.path for f in files if f.lang in ALWAYS_LLM_LANGS]
    if ci_files:
        reasons.append(f"CI·Dockerfile 변경: {', '.join(ci_files[:3])}")
    sensitive = [f.path for f in files if f.is_sensitive and f.lang not in ALWAYS_LLM_LANGS]
    if sensitive:
        reasons.append(f"민감 파일 변경: {', '.join(sensitive[:3])}")

    prompt = opts.prompt_name or ("ci" if any(f.lang in CI_LANGS for f in files) else "default")
    call = bool(reasons) and not opts.skip_llm
    return GateDecision(call_llm=call, prompt_name=prompt, reasons=reasons)
