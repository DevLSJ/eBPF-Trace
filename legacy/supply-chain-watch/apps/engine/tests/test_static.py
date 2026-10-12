"""정적 분석 단위 테스트 (Phase 3). 정상(무해) 입력만 사용한다.

탐지(양성) 쪽 회귀는 외부 평가 데이터(data/, git 제외)로 test_external_regression 에서 본다 — 데이터가 없으면 건너뜀.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import AnalyzeOptions
from app.static.engine import Hit, level_of, run_rules, score_hits
from app.static.gate import decide
from app.static.preprocess import ParsedFile, detect_lang, parse_diff
from app.static.rules_loader import SEVERITY_WEIGHT, load_rules

RULES = load_rules()
BY_ID = {r.id: r for r in RULES}
ROOT = Path(__file__).resolve().parents[3]


def new_file_diff(path: str, body: str) -> str:
    lines = body.strip("\n").split("\n")
    return (f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines) + "\n")


def fired(path: str, body: str) -> set[str]:
    return {h.rule.id for h in run_rules(RULES, parse_diff(new_file_diff(path, body))).hits}


# ---------- 룰 파일 ----------

def test_rules_load_and_are_valid():
    assert len(RULES) >= 49
    assert len(BY_ID) == len(RULES), "룰 id 중복"
    for r in RULES:
        assert r.description_ko
        assert r.exclude_pattern is not None or r.false_positive_hint, r.id


def test_combo_rules_evaluated_last():
    modes = [r.mode for r in RULES]
    first_combo = modes.index("combo")
    assert all(m == "combo" for m in modes[first_combo:])


# ---------- 전처리 ----------

@pytest.mark.parametrize(("path", "first", "lang"), [
    (".github/workflows/ci.yml", "", "WORKFLOW"),
    ("docker/Dockerfile.prod", "", "DOCKER"),
    ("Makefile", "", "MAKE"),
    ("src/a.ts", "", "JS"),
    ("pkg/mod.py", "", "PY"),
    ("scripts/run", "#!/usr/bin/env bash", "SHELL"),
    ("bin/tool", "#!/usr/bin/env node", "JS"),
    ("requirements-dev.txt", "", "CONFIG"),
    ("README.md", "", "OTHER"),
])
def test_detect_lang(path, first, lang):
    assert detect_lang(path, first) == lang


def test_parse_gateway_and_git_formats():
    gw = "diff --- src/a.js (modified, +2 -1)\n@@ -1,2 +1,3 @@\n keep\n-old\n+new1\n+new2\n…[파일 절삭]\n"
    git = new_file_diff("lib/b.py", "x = 1\ny = 2")
    files = parse_diff(gw + git)
    assert [f.path for f in files] == ["src/a.js", "lib/b.py"]
    assert files[0].added == ["new1", "new2"] and files[0].removed == ["old"]
    assert files[1].status == "added" and files[1].lang == "PY"


def test_file_multiplier():
    assert ParsedFile("docs/guide.md").multiplier == 0.2
    assert ParsedFile("src/__tests__/a.test.js").multiplier == 0.5
    assert ParsedFile("package.json").multiplier == 1.5
    assert ParsedFile(".github/workflows/x.yml").multiplier == 1.5
    assert ParsedFile("src/app.js").multiplier == 1.0


# ---------- 점수 ----------

def test_score_formula_and_levels():
    f = ParsedFile("src/app.js")
    high = Hit(BY_ID["NET_RAW_IP_URL"], f, "x", count=4)  # 30 × 1.0 × (1+log2 4)=90
    assert score_hits([high]) == 90
    med_in_doc = Hit(BY_ID["NET_SUSPICIOUS_TLD"], ParsedFile("README.md"), "x")  # 15 × 0.2
    assert score_hits([med_in_doc]) == 3
    assert score_hits([high, high]) == 100  # 상한
    assert SEVERITY_WEIGHT == {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}
    assert (level_of(70), level_of(69), level_of(40), level_of(39)) == ("HIGH", "MEDIUM", "MEDIUM", "LOW")
    assert math.isclose(30 * (1 + math.log2(4)), 90)


# ---------- 정상 관용구는 걸리면 안 됨 (오탐 회귀) ----------

BENIGN = [
    ("src/util.js", "const m = /a(b)/.exec(input);\nconst re = new RegExp('x');"),
    ("pkg/setup.py", "exec(open('pkg/version.py').read())\nexec(Path('pkg/_version.py').read_text())"),
    ("pkg/run.py", "env = dict(os.environ)\nchild_env = os.environ.copy()\nsubprocess.run(cmd, env=env)"),
    ("lib/parser.js", "if (token !== 'space' && token !== 'comment') break"),
    ("src/config.js", "devApi: 'http://127.0.0.1:8080/api',\nstaging: 'http://192.168.0.20:8080'"),
    ("package.json", '"postinstall": "husky install",\n"homepage": "https://example.com/pkg",\n"twitter": "https://twitter.com/x"'),
    (".github/workflows/ci.yml", "    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4"),
    ("pkg/ns.py", "return eval(typ, *ns)\nexec(func_code, globals_, locals_)\ntree = compile(src, path, 'exec', ast.PyCF_ONLY_AST)"),
    ("pkg/lexers.py", "filenames = ['.bashrc', 'bashrc', '.zshrc']"),
    ("pkg/sdk.py", "api_key = os.environ.get('ANTHROPIC_API_KEY')\nresp = httpx.post(url, headers=h)"),
    ("pkg/regex.py", "PATTERN = re.compile(r'[a-z]+')\nfrom re import compile\nRX = compile(r'x')"),
    (".github/workflows/release.yml", "permissions:\n  contents: write\n  id-token: write\non: push"),
]


@pytest.mark.parametrize(("path", "body"), BENIGN)
def test_benign_idioms_not_flagged(path, body):
    strong = {rid for rid in fired(path, body) if BY_ID[rid].severity != "LOW"}
    assert strong == set(), f"{path}: {strong}"


def test_typosquat_names():
    hit = fired("package.json", '  "lodahs": "^4.17.21",\n  "expres": "^4.0.0"')
    assert "TYPO_DEP_ADDED" in hit
    ok = fired("package.json", '  "eclint": "^2.8.1",\n  "vitest": "^1.0.0",\n  "@types/node": "^22.0.0",\n  "lodash": "^4.17.21"')
    assert "TYPO_DEP_ADDED" not in ok
    assert "TYPO_DEP_ADDED" in fired("requirements.txt", "reqeusts==2.31.0")
    assert "TYPO_DEP_ADDED" not in fired("requirements.txt", "requests==2.31.0\nhttpx>=0.27")


# ---------- 게이트 ----------

def _gate(diff: str, **opts):
    files = parse_diff(diff)
    return decide(run_rules(RULES, files), files, AnalyzeOptions(**opts), threshold=20)


def test_gate_workflow_always_llm_with_ci_prompt():
    g = _gate(new_file_diff(".github/workflows/ci.yml", "on: push\njobs: {}"))
    assert g.call_llm and g.prompt_name == "ci"


def test_gate_plain_change_skips_llm():
    g = _gate(new_file_diff("src/math.js", "export const add = (a, b) => a + b;"))
    assert not g.call_llm and g.prompt_name == "default" and g.reasons == []


def test_gate_sensitive_force_and_skip():
    assert _gate(new_file_diff("package.json", '"name": "x"')).call_llm  # 민감 파일
    assert _gate(new_file_diff("src/a.js", "x"), force_llm=True).call_llm
    assert not _gate(new_file_diff("package.json", '"name": "x"'), skip_llm=True).call_llm


# ---------- API ----------

def test_api_reports_static_and_gate():
    client = TestClient(app)
    assert client.get("/health").json()["rulesLoaded"] == len(RULES)
    body = {"commit": {"repoFullName": "o/r", "sha": "a" * 40}, "diff": new_file_diff(".github/workflows/ci.yml", "on: push")}
    d = client.post("/analyze", json=body).json()
    assert d["llm"]["gatePassed"] is True and d["llm"]["promptName"] == "ci"
    assert d["static"]["latencyMs"] >= 0 and "matchedRules" in d["static"]
    d2 = client.post("/analyze/static", json=body).json()
    assert d2["llm"]["gatePassed"] is False  # 정적 전용 경로는 LLM으로 넘기지 않음


# ---------- 외부 데이터 회귀 (있을 때만) ----------

@pytest.mark.skipif(not (ROOT / "data" / "guarddog" / "tests").exists(), reason="data/ 없음 — scripts/fetch-datasets.sh")
def test_external_regression():
    sys.path.insert(0, str(ROOT / "scripts"))
    import eval_pipeline as ev  # noqa: PLC0415

    results = [ev.evaluate(s, RULES) for s in ev.load_guarddog() + ev.load_zizmor()]
    pos = [r for r in results if r.sample.label == "positive"]
    neg = [r for r in results if r.sample.label == "negative"]
    recall = sum(r.ok for r in pos) / len(pos)
    fp = sum(not r.ok for r in neg) / len(neg)
    # 2026-10-12 기준선(guarddog+zizmor 탐지 72.5%·오탐 4.4%)에서 떨어지면 실패
    assert recall >= 0.70, recall
    assert fp <= 0.06, fp
    assert max(r.ms for r in results) < 200
