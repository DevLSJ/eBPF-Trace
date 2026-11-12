#!/usr/bin/env python3
"""평가 규칙 v2 — 정적 규칙 층: 이전 프로젝트(Supply Chain Watch)의 규칙 엔진(규칙 71개 + 파이썬 AST 흐름 분석)을 표본에 돌린다.

엔진은 복사하지 않는다. legacy/supply-chain-watch/apps/engine 을 그 자리에서 불러 쓰고, 규칙 YAML 도 그 자리의 것을 읽는다.
엔진 입력은 이전 평가(legacy/supply-chain-watch/scripts/eval_pipeline.py)가 DataDog 표본을 다룬 방식 그대로다 — 패키지 전체를
「새 파일만 있는 커밋」 diff 로 만든다(파일당 20KB 절삭 · 전체 상한 없음). 악성 · 정상을 같은 절차로 읽는다.
그 스크립트는 불러오는 순간 엔진 설정을 읽으므로(pydantic-settings 가 더 필요하고 환경 변수의 API 키 · DB 주소를 읽는다) 불러오지 않고,
필요한 함수 다섯 개만 아래 「이전 평가에서 옮긴 것」에 옮겼다. 원본과 같은 동작인지는 시험이 원본 소스와 맞대어 지킨다.

표본은 디스크에 풀지 않고 메모리에서 글로만 읽는다. 어떤 파일도 실행하지 않는다. 결과에는 코드 조각을 남기지 않는다(규칙 id · 경로 · 개수만).
읽지 못하거나 엔진이 오류를 낸 표본은 status error 로 남기고 「못 잡음」으로 센다(protocol.json layers.missing).

  python3 -m venv bench/.venv && bench/.venv/bin/pip install -r bench/v2/requirements-rules.txt
  bench/.venv/bin/python bench/v2/rules_layer.py run                      # 학습 구간 → $SG_BENCH_DATA/results/rules-train.jsonl
  bench/.venv/bin/python bench/v2/rules_layer.py run --part calibration   # 다시 돌리면 이어서 한다. 봉인 구간은 거부
  bench/.venv/bin/python bench/v2/rules_layer.py report [--part train] [--json]
  표본은 차례로 하나씩 검사한다(학습 구간 앞 200개에 40초쯤 — 파일이 1,500개쯤인 패키지 하나가 13초쯤). 표본 하나의 제한은 --timeout.

결과 한 줄(키 = id): {"id", "status": "ok"|"error", "why", "score"(0~100, 오류면 null), "level",
  "hits": [{"rule", "severity", "category", "file", "count", "test", "doc"}], "strong": [규칙 id], "truncatedFiles", "files", "ms"}
  strong = 이전 평가의 strong 과 같은 뜻: LOW 가 아닌 규칙이 시험 · 문서가 아닌 파일에 걸린 것. files = 엔진에 넣은 파일 수,
  truncatedFiles = 그 가운데 20KB 에서 잘린 파일 수, ms = 표본 하나를 읽고 검사하는 데 걸린 시간.
"""
import argparse
import contextlib
import glob
import hashlib
import importlib.util
import json
import os
import platform
import re
import signal
import statistics
import sys
import threading
import time
import unicodedata

sys.dont_write_bytecode = True  # bench/ · legacy/ 에 __pycache__ 를 남기지 않는다(추적 안 된 파일이 있으면 split.py unseal 이 거부한다)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import metrics  # noqa: E402
import sample  # noqa: E402
import split  # noqa: E402

LEGACY = os.path.join(split.ROOT, "legacy", "supply-chain-watch")
ENGINE_DIR = os.path.join(LEGACY, "apps", "engine")
EVAL_SCRIPT = os.path.join(LEGACY, "scripts", "eval_pipeline.py")
ENGINE_PARTS = ("app/models.py", "app/static/*.py", "rules/*.yaml")  # 엔진 지문에 넣는 파일(엔진 코드 + 규칙)
NEEDS = ("yaml", "pydantic")  # 엔진을 불러오는 데 필요한 것(requirements-rules.txt)
MAX_FILE_BYTES = 5_000_000    # 이전 평가의 DataDog 읽기와 같다(이보다 큰 파일은 넣지 않는다)
TIMEOUT = 600.0               # 표본 하나의 시간 제한(초). 넘으면 status error
TOP_RULES = 15


# ── 이전 평가에서 옮긴 것(eval_pipeline.py 의 같은 이름 — 고치지 않는다. test_rules_layer.Port 가 원본과 맞대어 본다) ──

FILE_CAP, LONG_LINE = 20 * 1024, 2000
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".json", ".sh", ".bash", ".toml", ".cfg",
            ".yml", ".yaml", ".txt", ".ps1", ".bat", ".cmd", ".pth", ""}
EXCLUDE_RE = re.compile(r"(^|/)(node_modules|dist|build|vendor|__pycache__|\.git)/|\.(min\.js|map|d\.ts|lock)$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$", re.I)
SENSITIVE_RE = re.compile(r"(^|/)(package\.json|setup\.py|setup\.cfg|pyproject\.toml|__init__\.py|index\.js|main\.js)$|(^|/)bin/", re.I)


def _clamp(text):
    return "\n".join(ln if len(ln) <= LONG_LINE else f"{ln[:500]} …[OBFUSCATION_SUSPECT {len(ln)}자]" for ln in text.split("\n"))


def _blocks(files):
    """build_diff 의 몸통 — 파일마다 (20KB 에서 잘렸는가, diff 조각). 제외 경로를 빼고, 민감 파일 먼저 · 경로 순서."""
    kept = [(p, t) for p, t in files.items() if not EXCLUDE_RE.search(p)]
    kept.sort(key=lambda pt: (not SENSITIVE_RE.search(pt[0]), pt[0]))
    for path, text in kept:
        body = _clamp(text)
        cut = len(body) > FILE_CAP
        if cut:
            body = body[:FILE_CAP]
        lines = body.split("\n")
        yield cut, (f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n"
                    + "\n".join("+" + ln for ln in lines) + "\n")


def build_diff(files):
    """{경로: 글} → 「새 파일만 있는 커밋」 diff. 이전 평가가 패키지에 쓴 build_diff(files, None) 과 같다(전체 상한 없음)."""
    return "".join(block for _, block in _blocks(files))


def _decode(raw):
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _wanted(path):
    name = path.rsplit("/", 1)[-1]
    suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    return suffix in TEXT_EXT or name in ("Makefile", "Dockerfile")


def _strip_root(files):
    """패키지 최상위 폴더(…/package/, name-1.0/)를 걷어 내 경로를 저장소 기준처럼 만든다. 그런 폴더가 없으면 파일 이름만 남는다."""
    out = {}
    for p, t in files.items():
        parts = p.split("/")
        idx = next((i for i, s in enumerate(parts) if s in ("package",) or re.fullmatch(r"[\w.-]+-\d[\w.]*", s)), None)
        out["/".join(parts[idx + 1:]) if idx is not None and idx + 1 < len(parts) else parts[-1]] = t
    return out


# ── 표본 → 엔진 입력 ──

def wanted(path):
    """내용을 읽는 파일: 이전 평가의 _wanted. DataDog 가 표본에 붙인 메타 파일은 패키지 내용이 아니라 뺀다."""
    return _wanted(path) and not path.rsplit("/", 1)[-1].startswith(sample.META_PREFIX)


def engine_files(data):
    """표본 바이트 → ({경로: 글}, None) 또는 (None, 사유). 이전 평가의 DataDog 읽기(load_datadog)와 같은 절차를 모든 표본에 쓴다:
    wanted 인 5,000,000바이트 이하 파일 · 앞 4KB 에 NUL 이 있으면 이진 파일로 보고 뺌 · UTF-8(깨진 글자는 대체) · 최상위 폴더를 걷어 냄.
    압축은 한 단계만 읽는다(v2 unit.depth — 이전 평가는 안쪽 압축도 열었다). 경로가 겹치면 경로 순서로 뒤의 것이 남는다."""
    members, why = sample.members(data, wanted=wanted)
    if members is None:
        return None, why
    files = {}
    for path, raw in members:
        if raw is None or len(raw) > MAX_FILE_BYTES:
            continue
        text = _decode(raw)
        if text is not None:
            files[path] = text
    return _strip_root(files), None


def strong_rules(hits):
    """이전 평가의 strong: LOW 가 아닌 규칙이 시험 · 문서가 아닌 파일에 걸린 것(규칙 id, 중복 없이 정렬)."""
    return sorted({h["rule"] for h in hits if h["severity"] != "LOW" and not (h["test"] or h["doc"])})


# ── 엔진 ──

def engine_missing():
    """엔진을 불러올 수 없는 사유(불러올 수 있으면 빈 글). 시험은 이 사유로 건너뛴다."""
    lacking = [m for m in NEEDS if importlib.util.find_spec(m) is None]
    if lacking:
        return f"엔진 의존성 없음({' · '.join(lacking)}) — bench/.venv/bin/pip install -r bench/v2/requirements-rules.txt"
    if not os.path.isdir(os.path.join(ENGINE_DIR, "app", "static")):
        return "legacy/supply-chain-watch/apps/engine 이 없다"
    return ""


def engine_sha256():
    """엔진 코드 · 규칙 파일의 지문 — 결과 파일이 어떤 엔진으로 만든 것인지 적어 두고, 이어받을 때 견준다."""
    h = hashlib.sha256()
    for pattern in ENGINE_PARTS:
        for path in sorted(glob.glob(os.path.join(ENGINE_DIR, pattern))):
            with open(path, "rb") as f:
                h.update(os.path.relpath(path, ENGINE_DIR).replace(os.sep, "/").encode() + b"\0" + f.read() + b"\0")
    return h.hexdigest()


class Engine:
    """이전 프로젝트 엔진을 그 자리에서 불러온 것. 엔진 · 규칙 파일은 고치지 않는다."""

    def __init__(self):
        if ENGINE_DIR not in sys.path:
            sys.path.insert(0, ENGINE_DIR)
        from app.static.engine import run_rules  # noqa: PLC0415
        from app.static.preprocess import parse_diff  # noqa: PLC0415
        from app.static.rules_loader import load_rules  # noqa: PLC0415
        self._run, self._parse, self.rules = run_rules, parse_diff, load_rules()

    def scan(self, diff):
        """diff → {"score", "level", "hits"}. 엔진이 근거로 남기는 코드 조각(snippet)은 버린다."""
        outcome = self._run(self.rules, self._parse(diff))
        hits = [{"rule": h.rule.id, "severity": h.rule.severity, "category": h.rule.category, "file": h.file.path,
                 "count": h.count, "test": h.file.is_test, "doc": h.file.is_doc} for h in outcome.hits]
        return {"score": outcome.score, "level": outcome.level, "hits": sorted(hits, key=lambda h: (h["file"], h["rule"]))}


class TimedOut(Exception):
    pass


@contextlib.contextmanager
def time_limit(seconds):
    """표본 하나의 시간 제한(SIGALRM — 정규식이 오래 걸려도 끊긴다). 신호를 못 쓰는 곳(윈도우 · 보조 스레드)에서는 제한 없이 돈다."""
    if not seconds or not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        yield
        return

    def late(_signum, _frame):
        raise TimedOut()

    before = signal.signal(signal.SIGALRM, late)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, before)


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000)


def failed(why, t0):
    return {"status": "error", "why": why, "score": None, "level": None, "hits": [], "strong": [], "truncatedFiles": 0,
            "files": 0, "ms": _ms(t0)}


def analyze(engine, data, timeout=TIMEOUT):
    """표본 바이트 → 결과 한 줄(id 빼고). 읽지 못하거나 엔진이 오류를 내면 status error."""
    t0 = time.perf_counter()
    try:
        with time_limit(timeout):
            files, why = engine_files(data)
            if files is None:
                return failed(why, t0)
            blocks = list(_blocks(files))
            out = engine.scan("".join(block for _, block in blocks))
    except TimedOut:
        return failed(f"시간 초과({timeout:g}초)", t0)
    except Exception as e:  # noqa: BLE001 — 오류 글에는 표본 내용이 섞일 수 있어 종류 이름만 남긴다
        return failed("엔진 오류: " + type(e).__name__, t0)
    return {"status": "ok", "why": "", "score": out["score"], "level": out["level"], "hits": out["hits"],
            "strong": strong_rules(out["hits"]), "truncatedFiles": sum(1 for cut, _ in blocks if cut), "files": len(blocks),
            "ms": _ms(t0)}


# ── 표본 고르기 · 결과 파일 ──

def data_dir():
    return os.environ.get("SG_BENCH_DATA") or collect.DATA


def results_path(data, part):
    return os.path.join(data, "results", f"rules-{part}.jsonl")


def select_rows(data, sp, ledger, part, limit=None):
    """구간의 색인 줄(split.select_ids 순서 — 봉인 구간이면 SealedError)과 표본 폴더. limit 는 앞에서 N개만."""
    ids = split.select_ids(sp, [part], ledger)
    if limit:
        ids = ids[:limit]
    want = set(ids)
    index = {r["id"]: r for r in split.read_jsonl(os.path.join(data, "index.jsonl")) if r["id"] in want}
    lost = [i for i in ids if i not in index]
    if lost:
        raise ValueError(f"색인에 없는 표본 {len(lost)}개(예: {lost[0]}) — index.jsonl 과 split.json 이 맞지 않는다")
    folder = os.path.join(data, "sealed", part) if part in sp["sealed"] else os.path.join(data, "store")
    return [index[i] for i in ids], folder


def read_results(path):
    """{id: 결과 줄}. 같은 id 가 여러 번이면 뒤의 것. 쓰다 끊긴 마지막 줄은 버린다."""
    rows = {}
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    for n, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            if n == len(lines) - 1:
                break
            raise
        rows[r["id"]] = r
    return rows


def _drop_broken_tail(path):
    """끝이 줄바꿈이 아니면(쓰다 끊김) 마지막 줄바꿈 뒤를 잘라 낸다 — 이어 쓰는 줄이 깨진 줄에 붙지 않게."""
    if not os.path.exists(path):
        return
    with open(path, "rb+") as f:
        data = f.read()
        keep = data.rfind(b"\n") + 1
        if keep != len(data):
            f.truncate(keep)


def read_engine_mark(path):
    """결과 파일 옆의 엔진 표식(<결과 파일 이름>.meta.json) — 없으면 None."""
    mark = os.path.splitext(path)[0] + ".meta.json"
    if not os.path.exists(mark):
        return None
    with open(mark, encoding="utf-8") as f:
        return json.load(f)


def check_engine_mark(path, sha, rules):
    """결과 파일 옆에 엔진 지문을 적어 둔다. 이미 있는데 지금 엔진과 다르면 멈춘다(다른 엔진의 결과가 한 파일에 섞이지 않게)."""
    mark = os.path.splitext(path)[0] + ".meta.json"
    old = read_engine_mark(path)
    if old is not None:
        if old["engineSha256"] != sha:
            raise ValueError(f"엔진 · 규칙이 결과 파일을 만들 때와 다르다({old['engineSha256'][:12]} → {sha[:12]}) — "
                             f"{os.path.basename(path)} 과 {os.path.basename(mark)} 을 치우고 처음부터 다시 돌려라")
        return
    with open(mark, "w", encoding="utf-8") as f:
        json.dump({"engineSha256": sha, "rules": rules, "python": platform.python_version(), "fileCap": FILE_CAP,
                   "maxFileBytes": MAX_FILE_BYTES}, f, ensure_ascii=False, indent=1)
        f.write("\n")


def run(engine, rows, folder, out_path, *, timeout=TIMEOUT, retry_errors=False, progress=None):
    """rows 를 차례로 검사해 out_path 에 한 줄씩 덧붙인다. 이미 결과가 있는 id 는 건너뛴다(이어받기). 새로 검사한 수를 돌려준다."""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    _drop_broken_tail(out_path)
    done = read_results(out_path)
    todo = [r for r in rows if r["id"] not in done or (retry_errors and done[r["id"]]["status"] == "error")]
    with open(out_path, "a", encoding="utf-8") as out:
        for n, r in enumerate(todo, 1):
            t0 = time.perf_counter()
            try:
                with open(os.path.join(folder, f"{r['id']}.{collect.EXT[r['form']]}"), "rb") as f:
                    data = f.read()
            except OSError:
                res = failed("표본 파일 없음", t0)
            else:
                res = analyze(engine, data, timeout) if sample.sample_id(data) == r["id"] else failed("표본 파일이 색인과 다름", t0)
            out.write(json.dumps({"id": r["id"], **res}, ensure_ascii=False, separators=(",", ":")) + "\n")
            out.flush()
            if progress:
                progress(n, len(todo), res)
    return len(todo)


# ── 보고 ──

def _summaries(main, y, flags):
    """후보 하나의 판정 → 전체 · 생태계별 metrics.summary."""
    out = {"all": metrics.summary(y, flags)}
    for eco in split.ECOSYSTEMS:
        pick = [i for i, r in enumerate(main) if r["ecosystem"] == eco]
        out[eco] = metrics.summary([y[i] for i in pick], [flags[i] for i in pick])
    return out


def report(rows, results, top=TOP_RULES):
    """구간의 색인 줄 + 결과 → 후보별 지표(dict). 분모는 metrics.main_rows(정상 전부 + 코드 있는 악성), 코드 없는 악성은 따로.
    결과가 없거나 status error 인 표본은 분모에 그대로 두고 어느 후보에서도 「못 잡음」이다.
    점수형 후보의 임계값은 이 구간 자체의 값으로 만든 참고값이다 — 운영점은 보정 구간에서 따로 고른다."""
    def done(r):
        res = results.get(r["id"])
        return res if res and res["status"] == "ok" else None

    def score(r):
        return done(r)["score"] if done(r) else None

    main = metrics.main_rows(rows)
    y = metrics.labels(main)
    no_code = [r for r in rows if r["label"] == "malicious" and not metrics.analyzable(r)]
    judges = [("R-strong", None, None, lambda r: bool(done(r) and done(r)["strong"]))]
    for budget, threshold in metrics.budget_points([score(r) for r in main], y):
        judges.append((f"R-score>={threshold:g}", budget, threshold, lambda r, t=threshold: metrics.score_flags([score(r)], t)[0]))
    candidates = [{"name": name, "budget": budget, "threshold": threshold, **_summaries(main, y, [flag(r) for r in main]),
                   "noCode": {"rows": len(no_code), "detected": sum(1 for r in no_code if flag(r))}}
                  for name, budget, threshold, flag in judges]

    seen = {}  # 규칙 → [심각도, 악성 표본 수, 정상 표본 수, strong 에 든 악성 표본 수, strong 에 든 정상 표본 수]
    for r in main:
        res = done(r)
        if not res:
            continue
        col = 1 if r["label"] == "malicious" else 2
        for rule, severity in sorted({(h["rule"], h["severity"]) for h in res["hits"]}):
            counts = seen.setdefault(rule, [severity, 0, 0, 0, 0])
            counts[col] += 1
            counts[col + 2] += rule in res["strong"]
    ranked = sorted(seen.items(), key=lambda kv: (-(kv[1][1] + kv[1][2]), kv[0]))[:top]

    errors = {}
    for r in rows:
        res = results.get(r["id"])
        if res and res["status"] == "error":
            errors[res["why"]] = errors.get(res["why"], 0) + 1
    checked = [done(r) for r in rows if done(r)]
    ms = [c["ms"] for c in checked]
    return {
        "rows": len(rows),
        "main": {"malicious": sum(y), "benign": len(y) - sum(y)},
        "noCodeMalicious": len(no_code),
        "results": {"ok": len(checked), "error": sum(errors.values()), "missing": sum(1 for r in rows if r["id"] not in results),
                    "errors": dict(sorted(errors.items()))},
        "candidates": candidates,
        "topRules": [{"rule": k, "severity": v[0], "malicious": v[1], "benign": v[2], "strongMalicious": v[3], "strongBenign": v[4]}
                     for k, v in ranked],
        "truncatedSamples": sum(1 for c in checked if c["truncatedFiles"]),
        "ms": {"total": sum(ms), "median": round(statistics.median(ms)) if ms else 0, "max": max(ms, default=0)},
    }


def _table(rows, left=(0,)):
    """글 칸의 목록 → 줄 목록. 한글은 두 칸으로 쳐서 맞춘다. left 에 든 칸만 왼쪽 맞춤."""
    def width(text):
        return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)

    widths = [max(width(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = []
    for r in rows:
        cells = [c + " " * (widths[i] - width(c)) if i in left else " " * (widths[i] - width(c)) + c for i, c in enumerate(r)]
        out.append("  ".join(cells).rstrip())
    return out


def format_report(rep, part):
    """사람이 읽는 표. rep = report() 결과(+ 명령이 붙이는 engine 표식)."""
    def pct(x):
        return f"{x * 100:.2f}%"

    def ci(pair):
        return f"{pair[0] * 100:.1f}~{pair[1] * 100:.1f}"

    res = rep["results"]
    first = f" 가운데 앞에서 {rep['limit']:,}개만" if rep.get("limit") else ""
    lines = [f"정적 규칙 층 · {part} 구간{first} · 표본 {rep['rows']:,}(주 지표: 코드 있는 악성 {rep['main']['malicious']:,} + 정상 "
             f"{rep['main']['benign']:,} · 코드 없는 악성 {rep['noCodeMalicious']:,}은 따로)",
             f"결과: 검사함 {res['ok']:,} · 오류 {res['error']:,} · 결과 없음 {res['missing']:,}(오류 · 결과 없음은 분모에 두고 「못 잡음」으로 센다)"]
    if rep.get("engine"):
        e = rep["engine"]
        lines.insert(1, f"엔진 {e['engineSha256'][:12]} · 규칙 {e['rules']}개 · 파이썬 {e['python']} · 파일당 {e['fileCap']:,}자 절삭")
    lines += [f"  오류 {n:,}: {why}" for why, n in res["errors"].items()]
    table = [["후보", "범위", "악성", "잡음", "탐지율", "95% 구간", "정상", "오탐", "오탐률", "95% 구간", "정밀도", "F1", "코드 없는 악성"]]
    for c in rep["candidates"]:
        for scope, label in (("all", "전체"), *((e, e) for e in split.ECOSYSTEMS)):
            s = c[scope]
            table.append([c["name"] if scope == "all" else "", label, f"{s['tp'] + s['fn']:,}", f"{s['tp']:,}", pct(s["detection"]),
                          ci(s["detectionCi95"]), f"{s['fp'] + s['tn']:,}", f"{s['fp']:,}", pct(s["fpr"]), ci(s["fprCi95"]),
                          pct(s["precision"]), pct(s["f1"]),
                          f"{c['noCode']['detected']:,}/{c['noCode']['rows']:,}" if scope == "all" else ""])
    lines += ["", *_table(table, left=(0, 1))]
    points = [c for c in rep["candidates"] if c["budget"]]
    lines += ["", "점수형 후보(R-score)의 임계값은 이 구간 자체의 값으로 만든 참고값이다. 운영점은 보정 구간에서 따로 고른다."]
    lines += [f"  {c['name']}: 이 구간 정상 오탐률이 {c['budget'][5:]} 이하가 되는 가장 낮은 점수" for c in points]
    if not points:
        lines.append("  점수형 후보 없음: 가장 높은 점수를 임계값으로 잡아도 이 구간 정상 오탐률이 가장 큰 예산(0.02)을 넘는다")
    rules = [["규칙", "심각도", "악성", "(strong)", "정상", "(strong)"]]
    rules += [[t["rule"], t["severity"], f"{t['malicious']:,}", f"({t['strongMalicious']:,})", f"{t['benign']:,}", f"({t['strongBenign']:,})"]
              for t in rep["topRules"]]
    lines += ["", f"가장 많이 걸린 규칙 {len(rep['topRules'])}개(걸린 표본 수, 괄호는 그 가운데 strong 에 든 표본 수)", *_table(rules, left=(0, 1))]
    lines += ["", f"20KB 에서 잘린 파일이 있는 표본 {rep['truncatedSamples']:,} · 걸린 시간 합계 {rep['ms']['total'] / 1000:,.1f}초 · "
                  f"중앙값 {rep['ms']['median']:,}ms · 최대 {rep['ms']['max']:,}ms"]
    return "\n".join(lines)


# ── 명령 ──

def _select(args):
    with open(split.SPLIT, encoding="utf-8") as f:
        sp = json.load(f)
    data = data_dir()
    rows, folder = select_rows(data, sp, split.read_ledger(), args.part, args.limit)
    return rows, folder, os.path.abspath(args.results or results_path(data, args.part))


def cmd_run(args):
    why = engine_missing()
    if why:
        sys.exit(why)
    rows, folder, out = _select(args)
    engine = Engine()
    sha = engine_sha256()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    check_engine_mark(out, sha, len(engine.rules))
    print(f"엔진 {sha[:12]} · 규칙 {len(engine.rules)}개 · 파이썬 {platform.python_version()} · {args.part} 구간 {len(rows):,}개 → {out}", flush=True)
    t0, count = time.perf_counter(), {"error": 0}

    def progress(n, total, res):
        count["error"] += res["status"] == "error"
        if n % 100 == 0 or n == total:
            print(f"  {n:,}/{total:,} · 오류 {count['error']:,} · {time.perf_counter() - t0:,.0f}초", flush=True)

    fresh = run(engine, rows, folder, out, timeout=args.timeout, retry_errors=args.retry_errors, progress=progress)
    print(f"끝: 새로 검사 {fresh:,} · 건너뜀(이미 있음) {len(rows) - fresh:,} · 새로 검사한 것 가운데 오류 {count['error']:,} · "
          f"{time.perf_counter() - t0:,.0f}초")


def cmd_report(args):
    rows, _, path = _select(args)
    rep = {"part": args.part, "limit": args.limit, "engine": read_engine_mark(path), **report(rows, read_results(path), args.top)}
    print(json.dumps(rep, ensure_ascii=False, indent=1) if args.json else format_report(rep, args.part))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("report", cmd_report)):
        p = sub.add_parser(name)
        p.add_argument("--part", default="train", choices=split.PARTS, help="구간(기본 train). 봉인 구간은 연 기록이 있을 때만")
        p.add_argument("--limit", type=int, help="select_ids 순서로 앞에서 N개만(동작 확인용)")
        p.add_argument("--results", help="결과 파일(기본 $SG_BENCH_DATA/results/rules-<구간>.jsonl)")
        p.set_defaults(fn=fn)
        if name == "run":
            p.add_argument("--timeout", type=float, default=TIMEOUT, help="표본 하나의 시간 제한(초)")
            p.add_argument("--retry-errors", action="store_true", help="status error 로 남은 표본을 다시 검사한다")
        else:
            p.add_argument("--json", action="store_true")
            p.add_argument("--top", type=int, default=TOP_RULES, help="보일 규칙 수")
    args = ap.parse_args()
    try:
        args.fn(args)
    except split.SealedError as e:
        sys.exit(f"거부: {e}")
    except (ValueError, OSError) as e:
        sys.exit(f"멈춤: {e}")


if __name__ == "__main__":
    main()
