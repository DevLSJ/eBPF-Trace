"""정적 분석 평가 (docs/03 §7, Phase 3-6). 외부 데이터·정상 패키지로 탐지율·오탐률을 잰다.

    uv run --project apps/engine python -I scripts/eval_pipeline.py --static-only
    uv run --project apps/engine python -I scripts/eval_pipeline.py --static-only --write-log --csv out.csv

평가 세트 (data/README.md):
- guarddog  : GuardDog 테스트 파일의 `ruleid:`(걸려야 함)·`ok:`(걸리면 안 됨) 주석 블록 — 줄 단위 라벨
- datadog   : 실제 악성 npm·PyPI 패키지 (암호 zip을 메모리에서만 읽음, 디스크에 풀지 않음)
- zizmor    : GitHub Actions 테스트 워크플로우 중 우리 CI 룰 범위에 대응하는 것
- benign-npm/benign-py : 이 프로젝트에 설치된 실제 인기 패키지(node_modules, engine venv) — 오탐 측정
- benign-pypi : 다운로드 상위 PyPI 패키지 휠 (data/benign-pypi, 메모리에서만 읽음) — 오탐 측정
- corpus    : corpus/positives·negatives (파일 이름 앞 = 룰 ID). 있으면 함께 평가

판정 기준:
- 탐지(rule)  : 테스트·문서가 아닌 파일에서 주의(MEDIUM) 이상 룰이 1개 이상 매칭. 약한 보조 룰(LOW)만으로는 탐지 아님
- 게이트(gate): 룰 근거만으로 LLM 2차 분석으로 넘어감 (점수 ≥ 임계치 또는 치명 룰). 민감 파일 트리거는 제외
- 패키지 전체는 "새 파일만 있는 커밋"으로 보고 gateway와 같은 절삭(파일 20KB·전체 120KB)을 적용한다

안전: 악성 샘플의 코드는 출력하지 않는다. --misses 는 샘플 ID와 매칭 룰·키워드 개수만 보인다.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import random
import re
import sys
import tarfile
import time
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "engine"))

from app.config import settings  # noqa: E402
from app.models import AnalyzeOptions  # noqa: E402
from app.static.engine import run_rules  # noqa: E402
from app.static.gate import decide  # noqa: E402
from app.static.preprocess import parse_diff  # noqa: E402
from app.static.rules_loader import get_rules  # noqa: E402

DATA = ROOT / "data"
FILE_CAP, TOTAL_CAP, LONG_LINE = 20 * 1024, 120 * 1024, 2000
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".json", ".sh", ".bash", ".toml", ".cfg",
            ".yml", ".yaml", ".txt", ".ps1", ".bat", ".cmd", ".pth", ""}
EXCLUDE_RE = re.compile(r"(^|/)(node_modules|dist|build|vendor|__pycache__|\.git)/|\.(min\.js|map|d\.ts|lock)$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$", re.I)
SENSITIVE_RE = re.compile(r"(^|/)(package\.json|setup\.py|setup\.cfg|pyproject\.toml|__init__\.py|index\.js|main\.js)$|(^|/)bin/", re.I)
ZIP_PASSWORD = b"infected"  # DataDog 데이터셋 공개 암호 (README)


@dataclass
class Sample:
    source: str
    sid: str
    label: str  # positive | negative | info
    files: dict[str, str]  # path → text
    expect: set[str] = field(default_factory=set)  # 이 룰 중 하나가 걸려야 함 (비면 아무 MEDIUM+)
    nocode: bool = False  # 분석할 코드가 사실상 없음(빈 index.js·바이너리만) — 이름·버전 같은 메타데이터로만 판단 가능
    forbid: set[str] = field(default_factory=set)  # 이 룰이 걸리면 오탐 (비면 아무 MEDIUM+)


# ---------- diff 생성 (gateway preprocess 와 같은 규칙) ----------

def _clamp(text: str) -> str:
    return "\n".join(ln if len(ln) <= LONG_LINE else f"{ln[:500]} …[OBFUSCATION_SUSPECT {len(ln)}자]" for ln in text.split("\n"))


def build_diff(files: dict[str, str], total_cap: int | None = TOTAL_CAP) -> str:
    kept = [(p, t) for p, t in files.items() if not EXCLUDE_RE.search(p)]
    kept.sort(key=lambda pt: (not SENSITIVE_RE.search(pt[0]), pt[0]))
    parts, total = [], 0
    for path, text in kept:
        body = _clamp(text)
        if len(body) > FILE_CAP:
            body = body[:FILE_CAP]
        lines = body.split("\n")
        block = f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines) + "\n"
        if total_cap is not None and total + len(block) > total_cap:
            break
        parts.append(block)
        total += len(block)
    return "".join(parts)


def _decode(raw: bytes) -> str | None:
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _wanted(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    return suffix in TEXT_EXT or name in ("Makefile", "Dockerfile")


# ---------- 소스별 로더 ----------

GUARDDOG_MAP: dict[str, set[str]] = {
    # GuardDog 룰 → 우리 룰 중 하나라도 걸리면 탐지로 본다 (같은 위협 범주)
    "exec-base64": {"AST_DECODE_TO_EXEC", "OBF_BASE64_DECODE_EXEC", "OBF_EVAL_DYNAMIC", "OBF_LONG_B64_LITERAL", "OBF_DYNAMIC_LOOKUP_CALL"},
    "npm-exec-base64": {"AST_DECODE_TO_EXEC", "OBF_BASE64_DECODE_EXEC", "OBF_EVAL_DYNAMIC", "OBF_LONG_B64_LITERAL"},
    "exfiltrate-sensitive-data": {"AST_SENSITIVE_TO_NET", "ENV_PLUS_NET", "ENV_ACCESS_BULK", "ENV_ACCESS_SECRET_KEY", "FS_SENSITIVE_PATH", "SYSINFO_TO_NET", "NET_DNS_EXFIL"},
    "npm-exfiltrate-sensitive-data": {"ENV_PLUS_NET", "ENV_ACCESS_BULK", "ENV_ACCESS_SECRET_KEY", "FS_SENSITIVE_PATH", "SYSINFO_TO_NET", "NET_DNS_EXFIL"},
    "npm-serialize-environment": {"ENV_ACCESS_BULK", "ENV_PLUS_NET"},
    "download-executable": {"AST_DOWNLOAD_TO_EXEC", "DL_WRITE_THEN_EXEC", "DL_EXEC_PIPE"},
    "shady-links": {"NET_SUSPICIOUS_TLD", "NET_RAW_IP_URL", "NET_WEBHOOK_ENDPOINT"},
    "obfuscation": {"OBF_HEX_ESCAPE_STRING", "OBF_STRING_SPLIT_JOIN", "OBF_CHARCODE_ARITH", "OBF_LONG_B64_LITERAL", "OBF_EVAL_DYNAMIC", "OBF_DYNAMIC_LOOKUP_CALL", "OBF_HEX_ENCODED_WORD"},
    "npm-obfuscation": {"OBF_HEX_ESCAPE_STRING", "OBF_STRING_SPLIT_JOIN", "OBF_CHARCODE_ARITH", "OBF_LONG_B64_LITERAL", "OBF_EVAL_DYNAMIC", "OBF_JS_OBFUSCATOR_IDENT", "OBF_DYNAMIC_LOOKUP_CALL", "OBF_HEX_ENCODED_WORD", "OBF_LONG_LINE"},
    "npm-install-script": {"INSTALL_HOOK_ADDED", "INSTALL_HOOK_SHELL"},
    "code-execution": {"AST_DECODE_TO_EXEC", "AST_DOWNLOAD_TO_EXEC", "OBF_EVAL_DYNAMIC", "NET_OUTBOUND_IN_INSTALL", "DL_EXEC_PIPE", "INSTALL_SETUP_EXEC", "OBF_DYNAMIC_LOOKUP_CALL"},
}
_ANNOT = re.compile(r"^\s*(?:#|//)\s*(ruleid|ok)\s*:\s*([a-z0-9_-]+)")


def load_guarddog() -> list[Sample]:
    base = DATA / "guarddog" / "tests" / "analyzer" / "sourcecode"
    out: list[Sample] = []
    if not base.exists():
        return out
    for path in sorted(base.glob("*")):
        if not path.is_file() or path.suffix not in (".py", ".js", ".json") or path.name.startswith("test_"):
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        marks = [(i, m.group(1), m.group(2)) for i, ln in enumerate(lines) if (m := _ANNOT.match(ln))]
        for k, (i, kind, rule) in enumerate(marks):
            end = marks[k + 1][0] if k + 1 < len(marks) else len(lines)
            block = "\n".join(lines[i + 1 : min(end, i + 31)])
            mapped = GUARDDOG_MAP.get(rule)
            label = "info" if mapped is None else ("positive" if kind == "ruleid" else "negative")
            # GuardDog의 code-execution·cmd-overwrite 룰은 setup.py 문맥 전용
            setup_ctx = path.suffix == ".py" and path.stem in ("code-execution", "cmd-overwrite")
            fname = "setup.py" if setup_ctx else f"src/sample{path.suffix}"
            if path.suffix == ".json":
                fname = "package.json"
            out.append(Sample("guarddog", f"{path.name}#{i + 1}:{rule}", label, {fname: block},
                              expect=mapped or set(), forbid=mapped or set()))
    benign = base / "benign"
    for path in sorted(benign.glob("*")) if benign.exists() else []:
        name = "package.json" if path.suffix == ".json" else f"src/{path.name}"
        out.append(Sample("guarddog-benign", path.name, "negative", {name: path.read_text(encoding="utf-8", errors="replace")}))
    return out


def _read_archive_members(data: bytes, name: str) -> dict[str, str]:
    """중첩 아카이브(.tgz/.tar.gz/.whl/.zip)를 메모리에서만 연다."""
    files: dict[str, str] = {}
    try:
        if name.endswith((".tgz", ".tar.gz")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and m.size < 1_000_000 and _wanted(m.name):
                        f = tf.extractfile(m)
                        if f and (txt := _decode(f.read())) is not None:
                            files[m.name] = txt
        elif name.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for n in zf.namelist():
                    if not n.endswith("/") and _wanted(n) and zf.getinfo(n).file_size < 1_000_000:
                        if (txt := _decode(zf.read(n))) is not None:
                            files[n] = txt
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError):
        pass
    return files


def _strip_root(files: dict[str, str]) -> dict[str, str]:
    """패키지 최상위 폴더(…/package/, name-1.0/)를 걷어 내 경로를 레포 기준처럼 만든다."""
    out = {}
    for p, t in files.items():
        parts = p.split("/")
        idx = next((i for i, s in enumerate(parts) if s in ("package",) or re.fullmatch(r"[\w.-]+-\d[\w.]*", s)), None)
        out["/".join(parts[idx + 1 :]) if idx is not None and idx + 1 < len(parts) else parts[-1]] = t
    return out


def load_datadog(limit: int | None) -> list[Sample]:
    base = DATA / "datadog" / "samples"
    out: list[Sample] = []
    for eco in ("npm", "pypi"):
        zips = sorted((base / eco).glob("**/*.zip"))[: limit or None]
        for zp in zips:
            files: dict[str, str] = {}
            try:
                with zipfile.ZipFile(zp) as zf:
                    for n in zf.namelist():
                        # package_info-*.json 은 DataDog이 붙인 레지스트리 메타데이터(패키지 내용 아님)
                        if n.endswith("/") or zf.getinfo(n).file_size > 5_000_000 or n.rsplit("/", 1)[-1].startswith("package_info-"):
                            continue
                        raw = zf.read(n, pwd=ZIP_PASSWORD)
                        if n.endswith((".tgz", ".tar.gz", ".whl", ".zip")):
                            files.update(_read_archive_members(raw, n))
                        elif _wanted(n) and (txt := _decode(raw)) is not None:
                            files[n] = txt
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
                continue
            if files:
                stripped = _strip_root(files)
                code = sum(len(t) for p, t in stripped.items() if re.search(r"\.(?:[cm]?js|ts|py|sh|pth|ps1|bat)$|(?:^|/)(?:setup\.py|Makefile)$", p))
                hooks = any(re.search(r'"(?:pre|post)?install"\s*:', t) for p, t in stripped.items() if p.endswith("package.json"))
                out.append(Sample(f"datadog-{eco}", zp.stem, "positive", stripped, nocode=code < 200 and not hooks))
    return out


def _zizmor_expect(key: str, text: str) -> set[str] | None:
    """zizmor 감사 항목 중 우리 룰과 의미가 같은 경우만 양성으로 쓴다.
    - excessive-permissions: 쓰기 권한 확대(write-all)가 있는 픽스처만 (기본 권한·read-all은 설정 점검이라 범위 밖)
    - unpinned-uses: 해시 미고정 외부 액션
    - dangerous-triggers: pull_request_target + 외부 PR 코드 체크아웃이 있는 픽스처만
    - self-hosted 등 나머지는 "설정 상태 점검"이라 악성 변경 탐지 범위 밖(info)
    """
    if key == "excessive-permissions" and re.search(r"write-all", text):
        return {"CI_PERMISSIONS_ESCALATE"}
    # zizmor는 공식 액션의 태그 고정도 지적하지만, 우리 룰은 "외부 액션을 브랜치·ref 없이" 쓰는 경우만 본다
    if key == "unpinned-uses" and re.search(r"uses:\s*['\"]?(?!actions/|github/|docker/|\./|docker://|\$)[\w.-]+/[\w./-]+(?:@(?:main|master|latest|dev|HEAD)\b|['\"]?\s*$)", text, re.M):
        return {"CI_UNPINNED_ACTION"}
    if key == "dangerous-triggers" and "pull_request_target" in text and re.search(r"head\.(?:sha|ref)|head_ref|refs/pull/", text):
        return {"CI_PR_TARGET_CHECKOUT"}
    return None


def load_zizmor() -> list[Sample]:
    base = DATA / "zizmor" / "crates" / "zizmor" / "tests" / "integration" / "test-data"
    out: list[Sample] = []
    if not base.exists():
        return out
    for path in sorted(base.rglob("*.y*ml")):
        rel = path.relative_to(base).as_posix()
        if "/configs/" in f"/{rel}" or not re.search(r"^\s*(on|jobs|runs):", path.read_text(encoding="utf-8", errors="replace"), re.M):
            continue  # zizmor 자체 설정 파일 등 워크플로우가 아닌 것
        key = rel.split("/")[0].removesuffix(".yml").removesuffix(".yaml")
        text = path.read_text(encoding="utf-8", errors="replace")
        mapped = _zizmor_expect(key, text)
        out.append(Sample("zizmor", rel, "positive" if mapped else "info",
                          {f".github/workflows/{path.name}": text}, expect=mapped or set()))
    return out


def _pkg_files(root: Path, max_files: int = 400) -> dict[str, str]:
    files: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if len(files) >= max_files:
            break
        rel = p.relative_to(root).as_posix()
        if p.is_file() and _wanted(rel) and not EXCLUDE_RE.search(rel) and p.stat().st_size < 1_000_000:
            if (txt := _decode(p.read_bytes())) is not None:
                files[rel] = txt
    return files


def load_benign_npm(n: int, seed: int) -> list[Sample]:
    store = ROOT / "node_modules" / ".pnpm"
    pkgs = []
    for d in sorted(store.glob("*")):
        inner = d / "node_modules"
        if not inner.is_dir():
            continue
        name = d.name.split("@")[0] if not d.name.startswith("@") else "@" + d.name[1:].split("@")[0].replace("+", "/")
        cand = inner / name
        if cand.is_dir():
            pkgs.append((d.name, cand))
    random.Random(seed).shuffle(pkgs)
    return [Sample("benign-npm", sid, "negative", files) for sid, path in pkgs[: n or None] if (files := _pkg_files(path))]


def load_benign_py(n: int, seed: int) -> list[Sample]:
    site = next((ROOT / "apps" / "engine" / ".venv" / "lib").glob("python3*/site-packages"), None)
    if site is None:
        return []
    pkgs = sorted(p for p in site.iterdir() if p.is_dir() and not p.name.endswith((".dist-info", ".data")) and not p.name.startswith(("_", ".")))
    random.Random(seed).shuffle(pkgs)
    return [Sample("benign-py", p.name, "negative", {f"{p.name}/{k}": v for k, v in files.items()}) for p in pkgs[: n or None] if (files := _pkg_files(p))]


def load_benign_pypi_wheels(n: int | None) -> list[Sample]:
    """다운로드 상위 PyPI 패키지의 휠(zip) — 메모리에서만 읽는다 (scripts/fetch_benign_pypi.py)."""
    out: list[Sample] = []
    for whl in sorted((DATA / "benign-pypi").glob("*.whl"))[: n or None]:
        files: dict[str, str] = {}
        try:
            with zipfile.ZipFile(whl) as zf:
                for name in zf.namelist():
                    if ".dist-info/" in name or name.endswith("/") or not _wanted(name) or zf.getinfo(name).file_size > 1_000_000:
                        continue
                    if (txt := _decode(zf.read(name))) is not None:
                        files[name] = txt
                    if len(files) >= 400:
                        break
        except zipfile.BadZipFile:
            continue
        if files:
            out.append(Sample("benign-pypi", whl.name.split("-py")[0], "negative", files))
    return out


def load_corpus() -> list[Sample]:
    out: list[Sample] = []
    for label, sub in (("positive", "positives"), ("negative", "negatives")):
        for path in sorted((ROOT / "corpus" / sub).glob("*.diff")) if (ROOT / "corpus" / sub).exists() else []:
            rid = path.name.split("__")[0]
            rules = {rid} if re.fullmatch(r"[A-Z][A-Z0-9_]+", rid) else set()
            s = Sample("corpus", path.name, label, {}, expect=rules if label == "positive" else set(), forbid=rules if label == "negative" else set())
            s.files = {"__diff__": path.read_text(encoding="utf-8", errors="replace")}
            out.append(s)
    return out


# ---------- 실행 ----------

@dataclass
class Result:
    sample: Sample
    rules: list[str]
    strong: list[str]
    score: int
    gate: bool
    ok: bool
    ms: float
    whole_pkg: bool = False
    reach: bool = False  # 룰 탐지 또는 실제 게이트(민감 파일 포함)로 LLM 검토에 도달


def evaluate(s: Sample, rules) -> Result:
    whole_pkg = s.source.startswith(("datadog", "benign-"))  # benign-npm·benign-py·benign-pypi
    diff = s.files["__diff__"] if "__diff__" in s.files else build_diff(s.files, None if whole_pkg else TOTAL_CAP)
    t0 = time.perf_counter()
    files = parse_diff(diff)
    outcome = run_rules(rules, files)
    ms = (time.perf_counter() - t0) * 1000
    matched = [h.rule.id for h in outcome.hits]
    strong = [h.rule.id for h in outcome.hits if h.rule.severity != "LOW" and not (h.file.is_test or h.file.is_doc)]
    gate = outcome.score >= settings.llm_threshold or any(h.rule.severity == "CRITICAL" for h in outcome.hits)
    reach = bool(strong) or decide(outcome, files, AnalyzeOptions(), settings.llm_threshold).call_llm
    if s.label == "positive":
        ok = bool(set(strong) & s.expect) if s.expect else bool(strong)
    elif s.label == "negative":
        ok = not (set(strong) & s.forbid) if s.forbid else not strong
    else:
        ok = True
    return Result(s, matched, strong, outcome.score, gate, ok, ms, whole_pkg, reach)


def pct(a: int, b: int) -> str:
    return f"{a / b * 100:.1f}%" if b else "—"


# ---------- LLM 포함 평가 (--with-llm, 비용 발생 → 사전 승인 · 호출 상한 강제) ----------

HAIKU_PRICE = (1.0, 5.0)  # $/MTok 입력·출력 — Anthropic 정가 기준 추정(중계 과금과 다를 수 있음)


def run_with_llm(n: int, max_calls: int, seed: int, note: str, write_log: bool) -> int:
    import asyncio

    from app.analyze import analyze
    from app.llm import provider as prov
    from app.models import AnalyzeRequest, CommitMeta

    real = prov.AnthropicProvider()
    calls = {"n": 0}

    class CappedProvider:
        async def analyze(self, system, user, model):  # noqa: ANN001
            if calls["n"] >= max_calls:
                return prov.LlmCallResult("ERROR", model, error=f"평가 호출 상한 {max_calls}회 도달")
            calls["n"] += 1
            return await real.analyze(system, user, model)

    prov.set_provider(CappedProvider())
    rng = random.Random(seed)
    pos = [s for s in load_datadog(None) if not s.nocode]
    neg = load_benign_npm(0, seed) + load_benign_pypi_wheels(None)
    rng.shuffle(pos)
    rng.shuffle(neg)
    n_pos = round(n * 0.6)
    picked = pos[:n_pos] + neg[: n - n_pos]

    async def one(s: Sample):
        diff = build_diff(s.files, TOTAL_CAP)  # 실제 커밋과 같은 120KB 상한
        req = AnalyzeRequest(commit=CommitMeta(repo_full_name=f"eval/{s.source}", sha=hashlib.sha1(s.sid.encode()).hexdigest(), message="update"), diff=diff)
        return s, await analyze(req)

    async def run_all():
        return [await one(s) for s in picked]  # 순차 실행(중계 서버 부하·상한 계산 단순화)

    import hashlib  # noqa: E401
    rows = asyncio.run(run_all())
    prov.set_provider(None)

    stat = {lab: Counter() for lab in ("positive", "negative")}
    tok = Counter()
    lat: list[int] = []
    for s, r in rows:
        st = stat[s.label]
        st["n"] += 1
        strong = [m for m in r.static.matched_rules if m.severity != "LOW"]
        st["static"] += bool(strong)
        st["gate"] += r.llm.gate_passed
        st[r.llm.status] += 1
        if r.llm.result:
            st["llm_flag"] += r.llm.result["riskScore"] >= 40
        st["fused_flag"] += r.risk_level != "LOW"
        for k, v in (r.llm.usage or {}).items():
            tok[k] += v
        if r.llm.latency_ms:
            lat.append(r.llm.latency_ms)
    cost = tok["inputTokens"] / 1e6 * HAIKU_PRICE[0] + tok["outputTokens"] / 1e6 * HAIKU_PRICE[1]
    models = f"{settings.llm_model_cheap}→{settings.llm_model}" if settings.llm_two_stage else settings.llm_model
    lines = [f"### LLM 포함 평가 — {date.today().isoformat()} (모델 {models}, 실제 호출 {calls['n']}회 / 상한 {max_calls})", "",
             "| 종류 | 샘플 | 정적 탐지 | LLM 분석 완료 | LLM 위험(≥40) | 최종 주의 이상 | 거부 | 오류 | 예산 건너뜀 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for lab, name in (("positive", "실제 악성"), ("negative", "정상")):
        st = stat[lab]
        done = st["OK"] + st["CACHED"]
        lines.append(f"| {name} | {st['n']} | {st['static']} | {done} | {st['llm_flag']} | {st['fused_flag']} | {st['REFUSED']} | {st['ERROR']} | {st['SKIPPED_BUDGET']} |")
    p, ng = stat["positive"], stat["negative"]
    lines += ["",
              f"- 실제 악성: 정적 {pct(p['static'], p['n'])} → **최종(LLM 융합) {pct(p['fused_flag'], p['n'])}** · LLM 단독 {pct(p['llm_flag'], p['OK'] + p['CACHED'])}",
              f"- 정상: 정적 오탐 {pct(ng['static'], ng['n'])} → **최종 오탐 {pct(ng['fused_flag'], ng['n'])}** · LLM 단독 오탐 {pct(ng['llm_flag'], ng['OK'] + ng['CACHED'])}",
              f"- 토큰: 입력 {tok['inputTokens']:,} · 출력 {tok['outputTokens']:,} · 캐시 읽기 {tok['cacheReadTokens']:,} → 추정 비용 ${cost:.3f} (haiku 정가 기준)",
              f"- LLM 지연: 평균 {sum(lat) / max(1, len(lat)) / 1000:.1f}s · 최대 {max(lat, default=0) / 1000:.1f}s"]
    if note:
        lines.append(f"- 메모: {note}")
    report = "\n".join(lines)
    print(report)
    if write_log:
        with (ROOT / "docs" / "eval-log.md").open("a", encoding="utf-8") as fh:
            fh.write(report + "\n\n")
    return 0


# ---------- LLM 호출 비율 (--gate-rate, 비용 없음) ----------
# 실제 공개 레포 최근 커밋(scripts/fetch_real_commits.py)에 gateway 전처리 → 정적 검사 → 게이트를 그대로 적용해
# "AI 분석까지 가는 커밋 비율"을 잰다 (Phase 4 완료 기준 ≤ 30%). 레포 설정 '항상 LLM'은 끈 상태 기준.

_GW_EXCLUDE_EXACT = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Cargo.lock", "composer.lock"}
_GW_EXCLUDE_RE = re.compile(r"(^|/)(node_modules|dist|build|vendor)/|\.(min\.js|map|png|jpe?g|gif|webp|ico|woff2?|ttf|eot|pdf|zip|gz|lock)$", re.I)
_GW_SENSITIVE_RE = re.compile(
    r"(^|/)(package\.json|setup\.py|setup\.cfg|pyproject\.toml|\.npmrc|\.pypirc|Dockerfile[^/]*|Makefile|index\.js|main\.js|__init__\.py)$"
    r"|^\.github/workflows/|(^|/)bin/|\.env|\.pem$|\.key$|credentials", re.I)


def gateway_diff(files: list[dict]) -> str:
    """apps/gateway/src/collector/preprocess.ts preprocessDiff 의 파이썬 이식 (제외·민감 우선·긴 줄·20KB/120KB 절삭)."""
    kept = [f for f in files if f["filename"].rsplit("/", 1)[-1] not in _GW_EXCLUDE_EXACT and not _GW_EXCLUDE_RE.search(f["filename"])]
    kept.sort(key=lambda f: not _GW_SENSITIVE_RE.search(f["filename"]))
    parts, total = [], 0
    for f in kept:
        if not f.get("patch"):
            continue
        patch = "\n".join(f"{ln[:500]} …[OBFUSCATION_SUSPECT {len(ln)}자]" if len(ln) > LONG_LINE else ln for ln in f["patch"].split("\n"))
        if len(patch) > FILE_CAP:
            patch = f"{patch[:FILE_CAP]}\n…[파일 절삭]"
        block = f"diff --- {f['filename']} ({f['status']}, +{f['additions']} -{f['deletions']})\n{patch}\n"
        if total + len(block) > TOTAL_CAP:
            break
        parts.append(block)
        total += len(block)
    return "".join(parts)


def _reason_kind(reason: str) -> str:
    for prefix, kind in (("정적 점수", "정적 점수 ≥ 임계치"), ("치명 룰", "치명 룰"), ("CI·Dockerfile", "CI·Dockerfile 변경"), ("민감 파일", "민감 파일 변경")):
        if reason.startswith(prefix):
            return kind
    return reason


def run_gate_rate(note: str, write_log: bool) -> int:
    root = ROOT / "data" / "real-commits"
    commits = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(root.glob("*/*.json"))]
    if not commits:
        print("data/real-commits 가 비어 있음 → python3 -I scripts/fetch_real_commits.py data/real-commits 20")
        return 1
    rules = get_rules()
    by_repo: dict[str, Counter] = defaultdict(Counter)
    kinds, only_kind, sens_files = Counter(), Counter(), Counter()
    for c in commits:
        files = parse_diff(gateway_diff(c["files"]))
        outcome = run_rules(rules, files)
        g = decide(outcome, files, AnalyzeOptions(), settings.llm_threshold)
        st = by_repo[c["repo"]]
        st["n"] += 1
        st["llm"] += g.call_llm
        ks = sorted({_reason_kind(r) for r in g.reasons})
        for k in ks:
            kinds[k] += 1
        if len(ks) == 1:
            only_kind[ks[0]] += 1
        if "민감 파일 변경" in ks:
            for f in files:
                if f.is_sensitive:
                    sens_files[f.path.rsplit("/", 1)[-1]] += 1
    n = sum(st["n"] for st in by_repo.values())
    llm = sum(st["llm"] for st in by_repo.values())
    lines = [f"### LLM 호출 비율 — {date.today().isoformat()} (룰 {len(rules)}개, 게이트 임계치 {settings.llm_threshold}, 실제 커밋 {n}개)", "",
             "| 레포 | 커밋 | AI 분석 대상 | 비율 |", "|---|---:|---:|---:|"]
    for repo, st in sorted(by_repo.items()):
        lines.append(f"| {repo} | {st['n']} | {st['llm']} | {pct(st['llm'], st['n'])} |")
    lines += ["", f"- 전체: **{llm}/{n} = {pct(llm, n)}** (목표 ≤ 30%)",
              "- 이유별(중복 포함): " + " · ".join(f"{k} {v}" for k, v in kinds.most_common()),
              "- 그 이유 하나만으로 넘어간 커밋: " + " · ".join(f"{k} {v}" for k, v in only_kind.most_common()),
              "- 민감 파일 이름 상위: " + " · ".join(f"{k} {v}" for k, v in sens_files.most_common(8)),
              "- 측정: 각 레포 기본 브랜치 최근 커밋, gateway 전처리 이식(scripts/eval_pipeline.py gateway_diff), 레포 '항상 LLM' 꺼짐 기준"]
    if note:
        lines.append(f"- 메모: {note}")
    report = "\n".join(lines)
    print(report)
    if write_log:
        with (ROOT / "docs" / "eval-log.md").open("a", encoding="utf-8") as fh:
            fh.write(report + "\n\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--static-only", action="store_true", help="정적 분석만 (현재 유일한 모드)")
    ap.add_argument("--datadog-limit", type=int, default=None)
    ap.add_argument("--benign-npm", type=int, default=0, help="0 = 설치된 전체")
    ap.add_argument("--benign-py", type=int, default=0, help="0 = engine venv 전체")
    ap.add_argument("--benign-pypi", type=int, default=0, help="0 = data/benign-pypi 전체")
    ap.add_argument("--seed", type=int, default=20261012)
    ap.add_argument("--csv", type=Path)
    ap.add_argument("--write-log", action="store_true", help="docs/eval-log.md에 결과 표 추가")
    ap.add_argument("--note", default="", help="eval-log 메모")
    ap.add_argument("--misses", action="store_true", help="놓친 양성·오탐 음성 ID와 룰만 출력 (코드 미출력)")
    ap.add_argument("--with-llm", type=int, default=0, metavar="N", help="LLM 포함 평가 표본 수 (비용 발생, 실제 악성 60%·정상 40%)")
    ap.add_argument("--max-calls", type=int, default=50, help="LLM 실제 호출 상한 (2026-10-12 사용자 결정: 50)")
    ap.add_argument("--gate-rate", action="store_true", help="실제 공개 레포 커밋의 LLM 호출 비율(게이트 통과율) — 비용 없음")
    args = ap.parse_args()
    if args.gate_rate:
        return run_gate_rate(args.note, args.write_log)
    if args.with_llm:
        return run_with_llm(args.with_llm, args.max_calls, args.seed, args.note, args.write_log)

    rules = get_rules()
    samples = (load_corpus() + load_guarddog() + load_datadog(args.datadog_limit) + load_zizmor()
               + load_benign_npm(args.benign_npm, args.seed) + load_benign_py(args.benign_py, args.seed)
               + load_benign_pypi_wheels(args.benign_pypi))
    results = [evaluate(s, rules) for s in samples]

    by_src: dict[str, list[Result]] = defaultdict(list)
    for r in results:
        by_src[r.sample.source].append(r)

    lines = [f"### 정적 분석 평가 — {date.today().isoformat()} (룰 {len(rules)}개, 게이트 임계치 {settings.llm_threshold})", ""]
    lines.append("| 세트 | 종류 | 샘플 | 탐지(룰) | 룰 근거 게이트 | 검토 도달 | 지표 | 평균 ms | 최대 ms |")
    lines.append("|---|---|---:|---:|---:|---:|---|---:|---:|")
    tot = Counter()
    for src, rs in by_src.items():
        for label in ("positive", "negative"):
            sel = [r for r in rs if r.sample.label == label]
            if not sel:
                continue
            n = len(sel)
            okc = sum(r.ok for r in sel)
            gate = sum(r.gate for r in sel)
            reach = sum(r.reach for r in sel)
            ms = [r.ms for r in sel]
            if label == "positive":
                metric = f"탐지율 {pct(okc, n)}"
                tot["pos"] += n
                tot["tp"] += okc
                tot["reach"] += reach
            else:
                metric = f"오탐률 {pct(n - okc, n)}"
                tot["neg"] += n
                tot["fp"] += n - okc
            lines.append(f"| {src} | {'양성' if label == 'positive' else '음성'} | {n} | {okc if label == 'positive' else n - okc} | {gate} | {reach} | {metric} | {sum(ms) / n:.1f} | {max(ms):.1f} |")
    precision = tot["tp"] / (tot["tp"] + tot["fp"]) if tot["tp"] + tot["fp"] else 0.0
    recall = tot["tp"] / tot["pos"] if tot["pos"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    all_ms = sorted(r.ms for r in results if not r.whole_pkg)  # 패키지 전체는 커밋 크기가 아니므로 지연 지표에서 제외
    p95 = all_ms[int(len(all_ms) * 0.95)] if all_ms else 0
    lines += ["", f"- 검토 도달 = 룰 탐지 또는 실제 게이트(민감 파일 변경 포함)로 LLM 2차 분석에 넘어감 → 양성 {pct(tot['reach'], tot['pos'])}",
              f"- 전체: 양성 {tot['pos']} · 음성 {tot['neg']} → **탐지율 {pct(tot['tp'], tot['pos'])} · 오탐률 {pct(tot['fp'], tot['neg'])}** · Precision {precision:.3f} · Recall {recall:.3f} · F1 {f1:.3f}",
              f"- 지연(커밋 크기 샘플, 120KB 이하): p95 {p95:.1f}ms · 최대 {all_ms[-1] if all_ms else 0:.1f}ms (목표 ≤ 200ms)",
              "- 패키지 세트(datadog·benign)는 패키지 전체를 새 파일 커밋으로 보고 전체 상한 없이 평가(파일당 20KB 상한만)"]
    real = [r for r in results if r.sample.source.startswith("datadog")]
    if real:
        withcode = [r for r in real if not r.sample.nocode]
        lines.append(f"- **실제 악성 패키지(DataDog) 탐지율 {pct(sum(r.ok for r in real), len(real))}** ({sum(r.ok for r in real)}/{len(real)}) · "
                     f"분석할 코드가 있는 패키지만 {pct(sum(r.ok for r in withcode), len(withcode))} ({sum(r.ok for r in withcode)}/{len(withcode)}) · "
                     f"코드가 사실상 없는 패키지 {len(real) - len(withcode)}개(빈 파일·바이너리만, 이름·버전으로만 판단 가능)")
    info = [r for r in results if r.sample.label == "info"]
    if info:
        lines.append(f"- 범위 밖 참고 세트 {len(info)}개(라벨이 우리 룰과 대응하지 않음) 중 주의 이상 룰 발화 {sum(bool(r.strong) for r in info)}개")
    fired = Counter(rid for r in results for rid in r.strong)
    lines.append("- 많이 발화한 룰: " + ", ".join(f"{k} {v}" for k, v in fired.most_common(8)))
    if args.note:
        lines.append(f"- 메모: {args.note}")
    report = "\n".join(lines)
    print(report)

    if args.misses:
        print("\n# 놓친 양성 (ID · 매칭 룰)")
        for r in results:
            if r.sample.label == "positive" and not r.ok:
                print(f"  {r.sample.source} {r.sample.sid} · {r.rules or '-'}")
        print("\n# 오탐 음성 (ID · 발화 룰)")
        for r in results:
            if r.sample.label == "negative" and not r.ok:
                print(f"  {r.sample.source} {r.sample.sid} · {r.strong}")

    if args.csv:
        with args.csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["source", "id", "label", "ok", "score", "gate", "strong_rules", "all_rules", "ms"])
            for r in results:
                w.writerow([r.sample.source, r.sample.sid, r.sample.label, r.ok, r.score, r.gate, " ".join(r.strong), " ".join(r.rules), f"{r.ms:.2f}"])
    if args.write_log:
        log = ROOT / "docs" / "eval-log.md"
        head = "" if log.exists() else "# 평가 기록 (docs/03 §7)\n\n룰·프롬프트를 바꿀 때마다 `scripts/eval_pipeline.py` 결과를 여기에 남긴다.\n\n"
        with log.open("a", encoding="utf-8") as fh:
            fh.write(head + report + "\n\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
