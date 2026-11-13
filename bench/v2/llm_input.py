#!/usr/bin/env python3
"""평가 규칙 v2 — LLM 층 입력 만들기: 표본 → llm_layer.py 가 읽는 JSONL(한 줄 = {"id", "text", "static": {…}}).

표본은 디스크에 풀지 않고 메모리에서 글로만 읽는다. 어떤 파일도 실행하지 않는다.
  text   = 규칙 엔진(rules_layer.py)이 읽는 파일과 같은 파일 · 같은 글(rules_layer 의 wanted · 제외 경로 · 긴 줄 표시 · 파일당 20KB 절삭을
           그 함수 그대로 쓴다). 파일마다 머리 줄 「===== <경로> (<원래 바이트> 바이트[, 앞 20,480자만 실음]) =====」 + 본문.
           설치 스크립트 · 매니페스트(setup.py · pyproject.toml · setup.cfg · package.json · *.pth)를 먼저, 그다음 나머지를 경로 순서로 —
           LLM 층이 앞 200,000자만 보내므로 설치 시점 파일이 앞에 남게. 글로 못 읽는 파일(앞 4KB 에 NUL)은 머리 줄에 「글 아님」만.
           전체는 TEXT_LIMIT(210,000자)에서 자른다(LLM 층이 다시 200,000자로 자른다 — 여기서는 디스크만 아낀다).
  static = 두 정적 엔진 결과의 요약(results/static-<구간>.jsonl · rules-<구간>.jsonl). 처리 못 한 엔진은 그 사실만.
           정적 ML 확률 · 라벨 · 출처 · 이름 · 판 · 날짜 · 표본 id 는 넣지 않는다(id 는 줄의 키로만).
           LLM 층이 JSON 키를 정렬해 4,000자에서 자르므로, 키 이름 순서가 중요도 순서가 되게 짓고 4,000자 안에 들도록 hit 목록을 줄인다.

  bench/.venv/bin/python -B bench/v2/llm_input.py build --part train --out /tmp/…/llm-in-train.jsonl [--limit 5]
  bench/.venv/bin/python -B bench/v2/llm_input.py build --part calibration --out … --ml …/ml-calibration.jsonl --band-low 0.02 --band-high 0.9994

봉인 구간(test · reserve)은 split.select_ids 로 거부한다(연 기록이 있을 때만). 출력에는 악성 코드 글이 들어가므로 git 이 추적하지 않는 곳에만
쓴다 — 저장소 안이면 bench/datasets/ · bench/raw/ 아래만, 다른 git 작업 폴더 안이면 그 저장소가 무시하는 경로만 받는다. 파일 권한은 600.
출력 옆 <출력 이름>.meta.json: 도구 sha256 · 행 수 · 잘린 파일 수 · 글 아닌 파일 수 · 관문 인자 · 두 결과 파일 sha256(같은 입력이면 같은 바이트).
표준 라이브러리만 쓴다.
"""
import argparse
import collections
import hashlib
import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True  # bench/ 에 __pycache__ 를 남기지 않는다(추적 안 된 파일이 있으면 split.py unseal 이 거부한다)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import llm_layer  # noqa: E402
import rules_layer  # noqa: E402
import run_static  # noqa: E402
import sample  # noqa: E402
import split  # noqa: E402

TEXT_LIMIT = 210_000                      # llm_layer.MAX_TEXT_CHARS(200,000)보다 조금 크게
FIRST = ("setup.py", "pyproject.toml", "setup.cfg", "package.json")  # 이 순서로 맨 앞, 그다음 *.pth
MAX_HIT_FILES = 3                         # hit 규칙 하나에 보이는 파일 경로 수(개수 상위)
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
NOT_DONE = "처리 못 함"
NO_TEXT = "(글로 읽을 파일 없음)"
SAFE_OUT = (("bench", "datasets"), ("bench", "raw"))


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def file_sha(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return sha256_bytes(f.read())


# ── 표본 → 파일 목록(규칙 엔진과 같은 기준) ──

def order_key(path):
    """설치 스크립트 · 매니페스트 먼저(FIRST 순서 → *.pth), 같은 종류는 얕은 것 먼저 · 경로 순서. 나머지는 경로 순서."""
    name = path.rsplit("/", 1)[-1]
    rank = FIRST.index(name) if name in FIRST else len(FIRST) if name.lower().endswith(".pth") else len(FIRST) + 1
    return (rank, path.count("/") if rank <= len(FIRST) else 0, path)


def package_files(data):
    """표본 바이트 → ([{"path", "bytes", "kind": "text"|"binary"|"large", "body", "cut"}], None) 또는 (None, 사유).
    글 파일은 rules_layer.engine_files 와 같은 절차(wanted · 5,000,000바이트 이하 · 앞 4KB 에 NUL 이면 이진 · UTF-8 대체 · 최상위 폴더 걷기 ·
    경로가 겹치면 뒤의 것)로 고르고, _blocks 처럼 제외 경로를 빼고 긴 줄 표시 · 20KB 절삭을 한다. 이진 · 너무 큰 파일은 본문 없이 남긴다
    (걷어 낸 경로가 글 파일과 겹치면 뺀다 — 규칙 엔진은 글 파일만 본다)."""
    members, why = sample.members(data, wanted=rules_layer.wanted)
    if members is None:
        return None, why
    texts, other = {}, {}
    for path, raw in members:
        if not rules_layer.wanted(path):  # members 는 읽지 않은 파일도 이름만(바이트 None) 돌려준다
            continue
        if raw is None or len(raw) > rules_layer.MAX_FILE_BYTES:  # wanted 인데 None = sample.MAX_CODE_BYTES 를 넘어 읽지 않은 것
            other[path] = ("large", None if raw is None else len(raw))
            continue
        text = rules_layer._decode(raw)
        if text is None:
            other[path] = ("binary", len(raw))
        else:
            texts[path] = (text, len(raw))
    stripped = rules_layer._strip_root(texts)
    entries = []
    for path, (text, size) in stripped.items():
        if rules_layer.EXCLUDE_RE.search(path):
            continue
        body = rules_layer._clamp(text)
        cut = len(body) > rules_layer.FILE_CAP
        entries.append({"path": path, "bytes": size, "kind": "text", "body": body[:rules_layer.FILE_CAP] if cut else body, "cut": cut})
    for path, (kind, size) in rules_layer._strip_root(other).items():
        if path in stripped or rules_layer.EXCLUDE_RE.search(path):
            continue
        entries.append({"path": path, "bytes": size, "kind": kind, "body": "", "cut": False})
    entries.sort(key=lambda e: order_key(e["path"]))
    return entries, None


def header(e):
    if e["kind"] == "binary":
        note = f"{e['bytes']:,} 바이트, 글 아님"
    elif e["kind"] == "large":
        note = f"{rules_layer.MAX_FILE_BYTES:,} 바이트 넘음, 싣지 않음"
    elif e["cut"]:
        note = f"{e['bytes']:,} 바이트, 앞 {rules_layer.FILE_CAP:,}자만 실음"
    else:
        note = f"{e['bytes']:,} 바이트"
    return f"===== {e['path']} ({note}) ====="


def render(entries, limit=TEXT_LIMIT):
    """파일 목록 → (글, limit 에서 잘렸는가). 파일마다 머리 줄 + 본문(이진 · 큰 파일은 머리 줄만)."""
    if not entries:
        return NO_TEXT, False
    blocks = []
    for e in entries:
        body = e["body"]
        blocks.append(header(e) + "\n" + (body if not body or body.endswith("\n") else body + "\n"))
    text = "\n".join(blocks)
    return (text[:limit], True) if len(text) > limit else (text, False)


# ── 정적 결과 요약 ──

def _ok(res):
    return res if isinstance(res, dict) and res.get("status") == "ok" else None


def _hit_list(hits):
    """규칙 엔진 hits(파일 × 규칙) → 규칙마다 {"rule", "severity", "count", "fileCount", "files"}. 심각도 → 개수 많은 것 먼저."""
    by = collections.OrderedDict()
    for h in hits:
        g = by.setdefault(h["rule"], {"severity": h["severity"], "files": {}})
        mark = " (시험)" if h.get("test") else " (문서)" if h.get("doc") else ""
        g["files"][h["file"]] = (g["files"].get(h["file"], (0, ""))[0] + h["count"], mark)
    out = []
    for rule, g in by.items():
        files = sorted(g["files"].items(), key=lambda kv: (-kv[1][0], kv[0]))
        out.append({"rule": rule, "severity": g["severity"], "count": sum(c for _, (c, _) in files), "fileCount": len(files),
                    "files": [f"{path} ×{c}{mark}" for path, (c, mark) in files[:MAX_HIT_FILES]]})
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out.sort(key=lambda h: (rank.get(h["severity"], len(rank)), -h["count"], h["rule"]))
    return out


def static_summary(gd, ru):
    """두 엔진 결과 줄 → 요약. 키는 llm_layer.static_block 이 정렬하므로 guarddog → rules, rules 안은 level · score · status · strong →
    topHits(가장 긴 목록이 맨 끝)가 되게 지었다. static_block 글이 MAX_STATIC_CHARS 를 넘으면 topHits 뒤에서부터 덜고 덜어 낸 수를 적는다."""
    g = _ok(gd)
    guard = ({"status": "ok", "verdict": g.get("verdict"), "score": g.get("score"), "installThreats": g.get("installThreats"),
              "rules": sorted(g.get("rules") or [])} if g else {"status": NOT_DONE})
    r = _ok(ru)
    if not r:
        return {"guarddog": guard, "rules": {"status": NOT_DONE}}
    hits = _hit_list(r.get("hits") or [])
    rules = {"status": "ok", "score": r.get("score"), "level": r.get("level"), "strong": sorted(r.get("strong") or []), "topHits": hits}
    out = {"guarddog": guard, "rules": rules}
    omitted = 0
    while hits and len(llm_layer.static_block(out)) > llm_layer.MAX_STATIC_CHARS:
        hits.pop()
        omitted += 1
        rules["topHitsOmitted"] = omitted
    return out


# ── 출력 경로 ──

def _inside(path, folder):
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def _existing(path):
    while not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return path


def _git_top(path):
    """path 를 품은 git 작업 폴더(.git 이 있는 가장 가까운 위 폴더) 또는 None."""
    cur = _existing(path)
    if os.path.isfile(cur):
        cur = os.path.dirname(cur)
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def check_out_path(path, root=None):
    """출력이 git 에 들어갈 수 있는 곳이면 ValueError. 저장소(root) 안이면 bench/datasets/ · bench/raw/ 아래만,
    git 작업 폴더 안이면 그 저장소가 무시(git check-ignore)하는 경로만."""
    real = os.path.realpath(os.path.abspath(path))
    root = os.path.realpath(root or split.ROOT)
    if _inside(real, root) and not any(_inside(real, os.path.join(root, *safe)) for safe in SAFE_OUT):
        raise ValueError("출력에는 표본 코드 글이 들어간다 — 저장소 안이면 bench/datasets/ · bench/raw/ 아래에만 쓴다(또는 저장소 밖)")
    top = _git_top(os.path.dirname(real))
    if top is None:
        return
    top = os.path.realpath(top)
    try:
        ignored = subprocess.run(["git", "-C", top, "check-ignore", "-q", "--", real], capture_output=True).returncode == 0
    except OSError:
        ignored = False
    if not ignored:
        raise ValueError("출력 경로가 git 작업 폴더 안인데 무시 목록에 없다 — 표본 코드 글이 커밋될 수 있어 쓰지 않는다")


def _write_private(path, text):
    """권한 600 으로 임시 파일에 쓴 뒤 바꿔 넣는다."""
    tmp = path + ".part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ── 만들기 ──

def build(data, *, part, out, ml=None, band_low=None, band_high=None, limit=None, split_path=None, ledger_path=None, root=None,
          progress=None):
    """구간의 표본(관문을 주면 ML 확률 [band_low, band_high) 인 것만, limit 는 그 가운데 앞 N개)을 입력 JSONL 로. → 메타(dict).
    출력 경로 · 봉인 · 관문 인자를 표본을 읽기 전에 본다. 읽지 못하거나 색인과 다른 표본은 쓰지 않고 사유별로 센다."""
    check_out_path(out, root)
    with open(split_path or split.SPLIT, encoding="utf-8") as f:
        sp = json.load(f)
    ledger = split.read_ledger(ledger_path or split.LEDGER)
    rows, folder = rules_layer.select_rows(data, sp, ledger, part)  # 봉인이면 SealedError
    if ml is None:
        if band_low is not None or band_high is not None:
            raise ValueError("--band-low · --band-high 는 --ml 과 함께 준다")
        gate = llm_layer.Gate("all")
    else:
        probs, ml_sha = llm_layer.read_ml(ml)
        gate = llm_layer.Gate("ml", band_low, band_high, probs, ml_sha)
        rows = [r for r in rows if gate.check(r["id"])[0]]
    if limit:
        rows = rows[:limit]
    gd_path, ru_path = run_static.results_path(data, part), rules_layer.results_path(data, part)
    gd, ru = run_static.read_results(gd_path), rules_layer.read_results(ru_path)

    lines, skipped = [], collections.Counter()
    count = collections.Counter()
    for n, r in enumerate(rows, 1):
        try:
            with open(os.path.join(folder, f"{r['id']}.{collect.EXT[r['form']]}"), "rb") as f:
                raw = f.read()
        except OSError:
            skipped["표본 파일 없음"] += 1
            continue
        if sample.sample_id(raw) != r["id"]:
            skipped["표본 파일이 색인과 다름"] += 1
            continue
        entries, why = package_files(raw)
        if entries is None:
            skipped[why or "압축을 읽지 못함"] += 1
            continue
        text, over = render(entries)
        count["files"] += len(entries)
        count["textFiles"] += sum(1 for e in entries if e["kind"] == "text")
        count["truncatedFiles"] += sum(1 for e in entries if e["cut"])
        count["binaryFiles"] += sum(1 for e in entries if e["kind"] == "binary")
        count["largeFiles"] += sum(1 for e in entries if e["kind"] == "large")
        count["rowsOverLimit"] += over
        count["chars"] += len(text)
        line = {"id": r["id"], "text": text, "static": static_summary(gd.get(r["id"]), ru.get(r["id"]))}
        lines.append(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        if progress:
            progress(n, len(rows))

    with open(os.path.abspath(__file__), "rb") as f:
        tool_sha = sha256_bytes(f.read())
    meta = {"tool": "bench/v2/llm_input.py", "toolSha256": tool_sha, "part": part, "selected": len(rows), "rows": len(lines),
            "files": count["files"], "textFiles": count["textFiles"], "truncatedFiles": count["truncatedFiles"],
            "binaryFiles": count["binaryFiles"], "largeFiles": count["largeFiles"], "rowsOverLimit": count["rowsOverLimit"],
            "chars": count["chars"], "skipped": dict(sorted(skipped.items())), "gate": gate.config(), "limit": limit,
            "fileCap": rules_layer.FILE_CAP, "textLimit": TEXT_LIMIT, "staticResultsSha256": file_sha(gd_path),
            "rulesResultsSha256": file_sha(ru_path)}
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    _write_private(out, "".join(lines))
    _write_private(os.path.splitext(out)[0] + ".meta.json", json.dumps(meta, ensure_ascii=False, indent=1) + "\n")
    return meta


def cmd_build(args):
    def progress(n, total):
        if n % 200 == 0 or n == total:
            print(f"  {n:,}/{total:,}", file=sys.stderr, flush=True)

    meta = build(args.data, part=args.part, out=args.out, ml=args.ml, band_low=args.band_low, band_high=args.band_high,
                 limit=args.limit, progress=progress)
    print(f"{args.part} 구간 · 고른 표본 {meta['selected']:,} → 행 {meta['rows']:,} · 파일 {meta['files']:,}"
          f"(20KB 잘림 {meta['truncatedFiles']:,} · 글 아님 {meta['binaryFiles']:,} · 큰 파일 {meta['largeFiles']:,}) · "
          f"{TEXT_LIMIT:,}자에서 잘린 행 {meta['rowsOverLimit']:,} · 건너뜀 {sum(meta['skipped'].values()):,}")
    print("출력에는 표본 코드 글이 들어 있다 — 커밋 · 공유하지 말고, 쓴 뒤에는 지운다.", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="구간의 표본 → LLM 층 입력 JSONL")
    b.add_argument("--part", default="train", choices=split.PARTS, help="구간(기본 train). 봉인 구간은 연 기록이 있을 때만")
    b.add_argument("--data", default=rules_layer.data_dir(), help="데이터 폴더(기본 $SG_BENCH_DATA 또는 bench/datasets/v2)")
    b.add_argument("--out", required=True, help="출력 JSONL — git 이 추적하지 않는 곳")
    b.add_argument("--ml", help='정적 ML 결과 ml-<구간>.jsonl(줄마다 {"id", "p"}) — 주면 관문 구간 안 표본만')
    b.add_argument("--band-low", type=float, help="관문 아래 경계(포함)")
    b.add_argument("--band-high", type=float, help="관문 위 경계(제외)")
    b.add_argument("--limit", type=int, help="관문 뒤 select_ids 순서로 앞에서 N개만")
    b.set_defaults(fn=cmd_build)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except split.SealedError as e:
        print(f"거부: {e}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as e:
        print(f"멈춤: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
