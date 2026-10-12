"""2차 LLM 분석 (docs/03 §5, Phase 4). 2단계: 저렴한 모델로 거르고, 위험해 보이는 것만 정밀 모델.

- 같은 diff·같은 프롬프트 버전이면 캐시 결과(CACHED)
- 시간당 상한을 넘으면 SKIPPED_BUDGET (정적 결과만)
- 정밀 모델 접근이 막혀 있으면(403) 1단계 결과를 그대로 쓰고 10분 뒤 다시 시도 (2026-10-12: 중계 토큰이 haiku만 허용)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from app.config import settings
from app.llm import budget
from app.llm.prompts import get_template, render
from app.llm.provider import LlmCallResult, get_provider
from app.llm.schema import LlmAnalysis
from app.models import AnalyzeRequest
from app.static.engine import StaticOutcome
from app.static.gate import GateDecision
from app.static.preprocess import ParsedFile

MAIN_UNAVAILABLE = "main_model_unavailable"


@dataclass
class LlmRun:
    status: str  # OK | REFUSED | ERROR | SKIPPED_BUDGET | CACHED
    model: str | None = None
    prompt_version: int | None = None
    analysis: LlmAnalysis | None = None
    usage: dict = field(default_factory=lambda: {"inputTokens": 0, "outputTokens": 0, "cacheReadTokens": 0})
    latency_ms: int = 0
    error: str | None = None
    stages: list[dict] = field(default_factory=list)


def _user_values(req: AnalyzeRequest, outcome: StaticOutcome, files: list[ParsedFile]) -> dict:
    owner, _, repo = req.commit.repo_full_name.partition("/")
    rules = "\n".join(f"- {h.rule.id} ({h.rule.severity}) in {h.file.path}: {h.snippet}" for h in outcome.hits) or "(매칭 룰 없음)"
    summary = ", ".join(f"{f.path} (+{len(f.added)} -{len(f.removed)})" for f in files[:40])
    return dict(
        owner=owner, repo=repo, stars=req.commit.stars if req.commit.stars is not None else "-",
        default_branch=req.commit.default_branch or "-", sha=req.commit.sha,
        author=req.commit.author_login or req.commit.author_name or "-", committed_at=req.commit.committed_at or "-",
        message=req.commit.message.strip()[:2000], files_summary=f"{len(files)}개: {summary}",
        static_score=outcome.score, static_level=outcome.level, matched_rules_block=rules,
        sensitive_files=", ".join(f.path for f in files if f.is_sensitive) or "없음",
        truncated_note=" (절삭됨)" if "…[파일 절삭]" in req.diff else "", diff=req.diff,
    )


def _merge_usage(total: dict, r: LlmCallResult) -> None:
    for k in total:
        total[k] += r.usage.get(k, 0)


def _stage(r: LlmCallResult) -> dict:
    return {"model": r.model, "status": r.status, "riskScore": r.analysis.risk_score if r.analysis else None,
            "latencyMs": r.latency_ms, "error": r.error}


async def run_llm(req: AnalyzeRequest, outcome: StaticOutcome, files: list[ParsedFile], gate: GateDecision) -> LlmRun:
    tpl = get_template(gate.prompt_name)
    user = render(tpl, _user_values(req, outcome, files))
    cache_key = f"{hashlib.sha256(req.diff.encode()).hexdigest()}:{tpl.name}:{tpl.version}"
    if not req.options.force_llm and (cached := await budget.cache_get(cache_key)):
        return LlmRun("CACHED", cached["model"], tpl.version, LlmAnalysis.model_validate(cached["analysis"]),
                      stages=cached.get("stages", []))

    provider = get_provider()
    run = LlmRun("ERROR", prompt_version=tpl.version)
    repo = req.commit.repo_full_name

    # 1단계: 저렴한 모델 (2단계 끔이면 바로 정밀 모델)
    first_model = settings.llm_model_cheap if settings.llm_two_stage else settings.llm_model
    if not await budget.try_acquire(repo):
        return LlmRun("SKIPPED_BUDGET", prompt_version=tpl.version, error="시간당 LLM 호출 상한 초과")
    first = await provider.analyze(tpl.system_prompt, user, first_model)
    _merge_usage(run.usage, first)
    run.latency_ms += first.latency_ms
    run.stages.append(_stage(first))
    best = first

    critical = any(h.rule.severity == "CRITICAL" for h in outcome.hits)
    escalate = settings.llm_two_stage and (
        first.status == "REFUSED"  # 저렴한 모델이 거부하면 정밀 모델로 한 번 더
        or (first.status == "OK" and (first.analysis.risk_score >= settings.llm_triage_threshold or critical or req.options.force_llm))
    )
    if escalate and not await budget.flag_get(MAIN_UNAVAILABLE):
        if await budget.try_acquire(repo):
            second = await provider.analyze(tpl.system_prompt, user, settings.llm_model)
            _merge_usage(run.usage, second)
            run.latency_ms += second.latency_ms
            run.stages.append(_stage(second))
            if second.status == "OK":
                best = second
            elif second.error and second.error.startswith("api 403"):
                await budget.flag_set(MAIN_UNAVAILABLE, 600)  # 접근 막힘: 10분 동안 정밀 단계 건너뜀
        else:
            run.stages.append({"model": settings.llm_model, "status": "SKIPPED_BUDGET"})
    elif escalate:
        run.stages.append({"model": settings.llm_model, "status": "SKIPPED", "error": "정밀 모델 접근 불가 — 1단계 결과 사용"})

    run.status, run.model, run.analysis, run.error = best.status, best.model, best.analysis, best.error
    if best.status == "OK" and best.analysis is not None:
        await budget.cache_set(cache_key, {"model": best.model, "analysis": best.analysis.model_dump(), "stages": run.stages})
    return run
