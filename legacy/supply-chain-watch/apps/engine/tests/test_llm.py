"""LLM 2차 분석 경로 테스트 (가짜 provider — 비용 0). docs/03 §4~6, llm-analyzer skill: OK/REFUSED/ERROR/SKIPPED 4경로."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.llm.provider import LlmCallResult, set_provider
from app.main import app
from app.models import AnalysisResult
from tests.conftest import FakeProvider, make_analysis

CHEAP, MAIN = settings.llm_model_cheap, settings.llm_model


def nf(path: str, body: str) -> str:
    lines = body.split("\n")
    return f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + x for x in lines) + "\n"


WORKFLOW = nf(".github/workflows/ci.yml", "on: push\njobs: {}")  # 게이트 통과(워크플로우 변경)
PLAIN = nf("src/math.js", "export const add = (a, b) => a + b;")  # 게이트 미통과


def post(diff: str, **opts) -> dict:
    body = {"commit": {"repoFullName": "o/r", "sha": "a" * 40, "message": "m"}, "diff": diff, "options": opts}
    r = TestClient(app).post("/analyze", json=body)
    assert r.status_code == 200
    AnalysisResult.model_validate(r.json())  # 모든 경로에서 스키마 유효
    return r.json()


def test_gate_closed_skips_llm(offline_llm):
    d = post(PLAIN)
    assert d["llm"]["status"] == "SKIPPED_GATE" and offline_llm["provider"].calls == []


def test_ok_low_score_stays_on_cheap_model(offline_llm):
    d = post(WORKFLOW)
    assert d["llm"]["status"] == "OK" and d["llm"]["model"] == CHEAP
    assert offline_llm["provider"].calls == [CHEAP]  # 1단계 점수가 낮으면 정밀 단계 생략
    assert d["llm"]["result"]["riskScore"] == 5 and "attackNarrativeKo" in d["llm"]["result"]  # camelCase


def test_high_triage_escalates_to_main_and_fuses(offline_llm):
    set_provider(FakeProvider({
        CHEAP: LlmCallResult("OK", CHEAP, analysis=make_analysis(55, ["C2_CONNECTION"])),
        MAIN: LlmCallResult("OK", MAIN, analysis=make_analysis(88, ["C2_CONNECTION", "ENV_EXFILTRATION"])),
    }))
    d = post(WORKFLOW)
    assert d["llm"]["model"] == MAIN and [s["model"] for s in d["llm"]["stages"]] == [CHEAP, MAIN]
    assert d["riskScore"] == 88 and d["riskLevel"] == "HIGH"
    assert {"C2_CONNECTION", "ENV_EXFILTRATION"} <= set(d["tags"])


def test_main_model_forbidden_keeps_cheap_result_and_backs_off(offline_llm):
    fake = FakeProvider({
        CHEAP: LlmCallResult("OK", CHEAP, analysis=make_analysis(60)),
        MAIN: LlmCallResult("ERROR", MAIN, error="api 403: no access"),
    })
    set_provider(fake)
    d = post(WORKFLOW)
    assert d["llm"]["status"] == "OK" and d["llm"]["model"] == CHEAP and d["riskScore"] == 60
    post(nf(".github/workflows/b.yml", "on: pull_request\njobs: {}"))  # 다른 diff: 정밀 단계는 10분간 건너뜀
    assert fake.calls.count(MAIN) == 1


def test_refusal_on_cheap_escalates_then_refused_falls_back_to_static(offline_llm):
    set_provider(FakeProvider({
        CHEAP: LlmCallResult("REFUSED", CHEAP, error="refusal:cyber"),
        MAIN: LlmCallResult("REFUSED", MAIN, error="refusal:cyber"),
    }))
    d = post(WORKFLOW)
    assert d["llm"]["status"] == "REFUSED" and d["llm"]["result"] is None
    assert d["riskScore"] == d["static"]["score"]  # 정적 결과 기준


def test_error_falls_back_to_static(offline_llm):
    set_provider(FakeProvider({CHEAP: LlmCallResult("ERROR", CHEAP, error="connection: APITimeoutError")}))
    d = post(WORKFLOW)
    assert d["llm"]["status"] == "ERROR" and d["riskLevel"] == d["static"]["level"]


def test_budget_exhausted(offline_llm):
    offline_llm["limit"]["max"] = 0
    d = post(WORKFLOW)
    assert d["llm"]["status"] == "SKIPPED_BUDGET" and offline_llm["provider"].calls == []


def test_same_diff_is_cached(offline_llm):
    post(WORKFLOW)
    d = post(WORKFLOW)
    assert d["llm"]["status"] == "CACHED" and offline_llm["provider"].calls == [CHEAP]


@pytest.mark.parametrize("force", [True])
def test_force_llm_bypasses_cache_and_escalates(offline_llm, force):
    post(WORKFLOW)
    d = post(WORKFLOW, forceLlm=force)
    assert d["llm"]["status"] == "OK" and MAIN in offline_llm["provider"].calls


def test_critical_rule_floor_in_fusion(offline_llm):
    # 치명 룰(INSTALL_HOOK_SHELL)이 있으면 LLM이 낮게 봐도 최소 60 (docs/03 §6)
    pkg = nf("package.json", '{\n  "scripts": {\n    "postinstall": "node -e \\"require(\'./build\')\\""\n  }\n}')
    d = post(pkg)
    assert any(m["severity"] == "CRITICAL" for m in d["static"]["matchedRules"])
    assert d["llm"]["status"] == "OK" and d["riskScore"] >= 60
