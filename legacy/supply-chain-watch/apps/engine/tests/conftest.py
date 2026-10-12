"""테스트는 실제 LLM·DB·Redis를 쓰지 않는다 (비용 0). 가짜 provider·메모리 예산·고정 프롬프트를 주입."""
from __future__ import annotations

import pytest

from app.llm import analyzer, budget, prompts
from app.llm.prompts import PromptTemplate
from app.llm.provider import LlmCallResult, set_provider
from app.llm.schema import LlmAnalysis


def make_analysis(score: int = 5, tags: list[str] | None = None) -> LlmAnalysis:
    return LlmAnalysis(
        risk_score=score, risk_level="HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW",
        detected_tags=tags or ["NONE"], attack_narrative_ko="테스트", evidence=[],
        benign_explanation_ko=None, confidence=80, recommended_action_ko="없음",
    )


class FakeProvider:
    """모델별 응답을 미리 정해 둔다. calls에 호출 기록."""

    def __init__(self, by_model: dict[str, LlmCallResult] | None = None):
        self.by_model = by_model or {}
        self.calls: list[str] = []

    async def analyze(self, system: str, user: str, model: str) -> LlmCallResult:
        self.calls.append(model)
        return self.by_model.get(model) or LlmCallResult("OK", model, analysis=make_analysis(5))


@pytest.fixture(autouse=True)
def offline_llm(monkeypatch):
    store: dict[str, object] = {}
    counts: dict[str, int] = {"n": 0}
    limit = {"max": 1000}

    async def try_acquire(repo: str) -> bool:
        counts["n"] += 1
        return counts["n"] <= limit["max"]

    async def cache_get(key: str):
        return store.get("cache:" + key)

    async def cache_set(key: str, value: dict) -> None:
        store["cache:" + key] = value

    async def flag_get(name: str) -> bool:
        return bool(store.get("flag:" + name))

    async def flag_set(name: str, ttl_s: int) -> None:
        store["flag:" + name] = True

    for name, fn in [("try_acquire", try_acquire), ("cache_get", cache_get), ("cache_set", cache_set),
                     ("flag_get", flag_get), ("flag_set", flag_set)]:
        monkeypatch.setattr(budget, name, fn)
    tpl = PromptTemplate("default", 1, "SYSTEM", "{owner}/{repo} {diff}")
    monkeypatch.setattr(prompts, "get_template", lambda name: PromptTemplate(name, 1, "SYSTEM", tpl.user_template))
    monkeypatch.setattr(analyzer, "get_template", lambda name: PromptTemplate(name, 1, "SYSTEM", tpl.user_template))
    fake = FakeProvider()
    set_provider(fake)
    yield {"provider": fake, "limit": limit, "store": store}
    set_provider(None)
