#!/usr/bin/env python3
"""평가 규칙 v2 — 정적 층 기준선 측정. 열린 구간의 표본을 떠 있는 백엔드의 공급망 검사(GuardDog + OSV)에 올리고 결과를 남긴다.

규칙은 bench/v2/protocol.json 의 layers(static · missing). 표본은 split.select_ids 로만 고른다 — 봉인 구간(test · reserve)은 거부된다.
악성(DataDog 암호 zip)은 디스크에 풀지 않고 메모리에서 tar.gz 로 다시 묶어 올리고, 정상은 저장한 파일을 그대로 올린다. 어떤 파일도 실행하지 않는다.
올리는 파일 이름 · 결과에는 패키지 이름을 넣지 않는다(sgb-<id>). 토큰은 출력하지 않는다. 표준 라이브러리만 쓴다.
다시 묶기 · 백엔드 호출 · 결과 요약은 v1 도구(tools/sg-bench-dataset)의 pack_datadog · API · wait_scan · summarize 를 그대로 쓴다.

  python3 bench/v2/run_static.py run --dry-run                 # 백엔드에 닿지 않고 구간별 표본 수 · 올림 형식만
  ADMIN_TOKEN=… python3 bench/v2/run_static.py run [--parts train] [--limit N] [--api http://127.0.0.1:8000/api]
  python3 bench/v2/run_static.py report [--parts train] [--json 결과.json]

데이터 폴더는 SG_BENCH_DATA(없으면 bench/datasets/v2): index.jsonl · store/<id>.<확장자> → results/static-<구간>.jsonl
결과 한 줄(표본마다 하나 — 다시 돌리면 기록한 id 는 건너뛴다. 검사는 한 번에 하나씩):
  {"id", "status": "ok"|"skip"|"error", "why"(ok 가 아니면), "verdict", "score", "rules", "installThreats", "threats",
   "capabilities", "vulns", "seconds", "engines"}
  skip = 올리지 못했거나 백엔드가 받지 않은 표본(묶기 실패 · 50MB 초과 · 압축 해제 실패), error = 검사 오류 · 시간 초과.
둘 다 버리지 않고 남기며, report 는 결과가 없는 표본과 함께 「정적이 못 잡음」으로 센다(분모에서 빼지 않는다).
표본 탓이 아닌 실패(백엔드에 닿지 않음 · 토큰 거부 · 없는 주소 · 서버 오류)는 기록하지 않고 멈춘다 — 고친 뒤 다시 돌리면 그 표본부터 이어진다.
error 로 남은 표본만 다시 하려면 run --retry-errors(같은 id 는 마지막 줄이 이긴다).
"""
import argparse
import bz2
import collections
import datetime as dt
import gzip
import importlib.machinery
import importlib.util
import io
import json
import lzma
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import metrics  # noqa: E402
import sample  # noqa: E402
import split  # noqa: E402

API_DEFAULT = "http://127.0.0.1:8000/api"
# 정적 층 후보 판정(protocol.json layers.static). 백엔드 판정 caution 은 v1 도구의 VERDICT 표가 suspicious 로 옮긴다
CANDIDATES = (("S-malicious", ("malicious",)), ("S-suspicious", ("malicious", "suspicious")))
VERDICTS = ("malicious", "suspicious", "vulnerable", "clean")
STATUSES = ("ok", "skip", "error")
FIELDS = ("verdict", "score", "rules", "installThreats", "threats", "capabilities", "testFindings", "vulns", "seconds", "engines")
RETRY_CODES = (0, 429, 502, 503, 504)  # 백엔드가 다시 뜨는 중 · 자리가 없음 — 기다렸다 다시 한다(v1 도구와 같은 식)
TRIES = 6
FORM_NOTE = {"zip": "암호 zip → 메모리에서 tar.gz 로 다시 묶음", "sdist": "sdist(.tar.gz) 그대로", "wheel": "wheel(.whl) 그대로",
             "tarball": "npm tarball(.tgz) 그대로"}
LABEL_KO = {"malicious": "악성", "benign": "정상"}
SOURCE_KO = {"popular": "인기", "longTail": "롱테일"}


class Stop(Exception):
    """측정을 멈춰야 하는 상황(백엔드에 닿지 않음 · 토큰 거부 · 없는 주소 · 표본 파일 없음). 표본 탓이 아니므로 그 표본은 기록하지 않는다."""


_V1 = None


def v1():
    """v1 측정 도구(tools/sg-bench-dataset)를 모듈로 불러온다 — 같은 코드를 베끼지 않고 그대로 쓴다."""
    global _V1
    if _V1 is None:
        loader = importlib.machinery.SourceFileLoader("sg_bench_dataset", os.path.join(split.ROOT, "tools", "sg-bench-dataset"))
        mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("sg_bench_dataset", loader))
        keep, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # tools/ 에 __pycache__ 를 남기지 않는다
        try:
            loader.exec_module(mod)
        finally:
            sys.dont_write_bytecode = keep
        _V1 = mod
    return _V1


def make_api(base, token):
    return v1().API(base, token)


def data_dir():
    return os.environ.get("SG_BENCH_DATA") or collect.DATA


def results_path(data, part):
    return os.path.join(data, "results", f"static-{part}.jsonl")


def read_results(path):
    """결과 파일 → {id: 줄}. 같은 id 는 마지막 줄이 이긴다. 쓰다 끊긴 줄은 버린다(그 표본은 다시 한다)."""
    out = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("status") in STATUSES and "id" in rec:
                    out[rec["id"]] = rec
    return out


def append_result(path, rec):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "ab+") as f:
        if f.seek(0, os.SEEK_END) > 0:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":  # 앞 실행이 줄을 쓰다 끊겼다 — 새 줄이 거기에 붙지 않게
                f.write(b"\n")
        f.write((json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode())


def select(parts, data):
    """구간의 표본을 색인과 맞춘다 → [(구간, 색인 줄)], 요청한 구간 순서 · 구간 안에서는 id 순.
    봉인 구간은 split.select_ids 가 거부한다(SealedError) — 색인을 읽기도 전에."""
    parts = list(dict.fromkeys(parts))
    with open(split.SPLIT, encoding="utf-8") as f:
        sp = json.load(f)
    try:
        ids = split.select_ids(sp, parts, split.read_ledger(split.LEDGER))
    except ValueError as e:
        raise Stop(str(e))
    index = {r["id"]: r for r in split.read_jsonl(os.path.join(data, "index.jsonl"))}
    lost = [i for i in ids if i not in index]
    if lost:
        raise Stop(f"분할에 든 표본 {len(lost)}개가 색인에 없다 — 데이터 폴더({data})가 이 분할의 것인지 확인하라")
    return [(p, index[i]) for p in parts for i in ids if sp["assignments"][i] == p]


def sample_path(data, row):
    """표본 파일 자리: store/, 없으면 sealed/<구간>/(봉인을 연 뒤의 최종 측정 — 여기까지 오는 id 는 select 가 이미 걸렀다)."""
    name = f"{row['id']}.{collect.EXT[row['form']]}"
    for folder in ("store",) + tuple(os.path.join("sealed", p) for p in split.SEALED):
        path = os.path.join(data, folder, name)
        if os.path.exists(path):
            return path
    return os.path.join(data, "store", name)


def regzip(raw):
    """bz2 · xz 로 압축한 tar → gzip 으로 다시 압축한 바이트(안의 tar 는 그대로). 그 형식이 아니면 None.
    백엔드는 gzip tar 와 zip 만 푼다 — 그대로 올리면 정상 표본이 「검사 못 함 → 못 잡음」으로 세어져 오탐률이 낮아진다.
    풀어서 상한(sample.MAX_EXTRACT)을 넘거나 끝까지 읽히지 않으면 ValueError(사유)."""
    if raw[:3] == b"BZh":
        dec = bz2.BZ2Decompressor()
    elif raw[:6] == b"\xfd7zXZ\x00":
        dec = lzma.LZMADecompressor()
    else:
        return None
    try:
        tar = dec.decompress(raw, max_length=sample.MAX_EXTRACT + 1)
    except (OSError, lzma.LZMAError, EOFError):
        raise ValueError("압축을 읽지 못함")
    if len(tar) > sample.MAX_EXTRACT:
        raise ValueError("풀면 크기 상한 초과")
    if not dec.eof:
        raise ValueError("압축을 읽지 못함")
    return gzip.compress(tar, compresslevel=6, mtime=0)


def upload_ext(form, raw):
    """올릴 파일 이름의 확장자. 백엔드는 확장자로 푸는 방식을 고른다(.tar.gz · .tgz = gzip tar, .whl · .zip = zip).
    옛 sdist 가운데는 zip 인 것이 있고 저장 이름은 늘 .tar.gz 라서, 그런 파일은 내용에 맞춰 .zip 으로 올린다."""
    ext = collect.EXT[form]
    return "zip" if raw[:2] == b"PK" and ext in ("tar.gz", "tgz") else ext


def prepare(row, data):
    """표본 → ((올릴 파일 이름, 바이트), None) 또는 (None, 건너뜀 사유). 디스크에 풀지 않는다."""
    try:
        with open(sample_path(data, row), "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise Stop(f"표본 파일이 없다: {row['id']}")
    if sample.sample_id(raw) != row["id"]:
        raise Stop(f"저장한 파일이 색인과 다르다: {row['id']}")
    if row["form"] == "zip":  # DataDog 암호 zip — v1 과 같은 묶음(패키지 루트를 pkg/ 아래로, 메타 파일 제외)
        try:
            packed, why = v1().pack_datadog(io.BytesIO(raw))
        except Exception as e:  # 손상된 표본 하나가 측정을 멈추지 않게 — 사유를 남기고 다음으로
            packed, why = None, f"묶기 실패({type(e).__name__})"
        if packed is None:
            return None, why
        return (f"sgb-{row['id']}.tar.gz", packed[0]), None
    try:
        again = regzip(raw)
    except ValueError as e:
        return None, str(e)
    body, ext = (raw, upload_ext(row["form"], raw)) if again is None else (again, "tar.gz")
    if len(body) > v1().MAX_UPLOAD:
        return None, "업로드 50MB 초과"
    return (f"sgb-{row['id']}.{ext}", body), None


def scan(api, filename, body, timeout):
    """한 표본을 올려 검사시킨다 → 결과 줄의 칸(id 빼고).
    시작 단계에서 표본 탓인 응답은 400 · 413 뿐이다(backend scan.Service.start). 그 밖의 실패(닿지 않음 · 토큰 거부 · 없는 주소 · 서버 오류)는
    표본의 결과가 아니므로 기록하지 않고 Stop — 원인을 고친 뒤 다시 돌리면 그 표본부터 이어진다."""
    for attempt in range(TRIES):
        code, resp = api.upload(filename, body)
        if code not in RETRY_CODES:
            break
        if attempt + 1 < TRIES:
            time.sleep(10 * (attempt + 1))
    if code in RETRY_CODES:
        raise Stop(f"백엔드가 받지 않는다(응답 {code} · {TRIES}번 시도) — 이 표본은 기록하지 않았다. 다시 돌리면 이어서 한다")
    if code in (401, 403):
        raise Stop(f"백엔드가 토큰을 거부했다(응답 {code}) — ADMIN_TOKEN 을 확인하라")
    if code in (400, 413):  # 백엔드가 받지 않은 표본(풀지 못함 · 너무 큼)
        return {"status": "skip", "why": v1().skip_reason(code, resp)}
    if code != 202 or not isinstance(resp, dict) or "id" not in resp:
        raise Stop(f"백엔드가 검사를 시작하지 못했다(응답 {code}) — --api 주소와 백엔드 상태를 확인하라. 이 표본은 기록하지 않았다")
    done = v1().wait_scan(api, resp["id"], timeout)
    if done is None:
        return {"status": "error", "why": "결과 대기 시간 초과"}
    s = v1().summarize(done)
    if s["verdict"] == "error":
        rec = {"status": "error", "why": s.get("error") or "검사 실패"}
        return {**rec, "seconds": s["seconds"]} if s.get("seconds") is not None else rec
    return {"status": "ok", **{k: s.get(k) for k in FIELDS}}


def reason(rec):
    """화면 · 보고에 쓰는 사유. 백엔드 오류 글은 앞머리(종류)만 — 뒤쪽에는 표본에서 나온 경로 · 글이 섞일 수 있어 결과 파일에만 둔다.
    건너뜀 사유는 이 도구 · v1 도구가 정한 고정 문구라 그대로 쓴다."""
    why = rec.get("why") or ""
    return re.split(r"[:(,]", why, maxsplit=1)[0].strip()[:40] if rec["status"] == "error" else why


def read_token(token_file):
    """ADMIN_TOKEN — 환경 변수 먼저, 없으면 파일의 ADMIN_TOKEN= 줄(v1 도구의 읽기). 값은 어디에도 출력하지 않는다."""
    path = os.path.expanduser(token_file or "")
    if not os.environ.get("ADMIN_TOKEN") and not os.path.isfile(path):
        raise Stop("ADMIN_TOKEN 이 없다(환경 변수 또는 --token-file 의 ADMIN_TOKEN= 줄)")
    return v1().read_token(argparse.Namespace(token_file=path))


def num(n):
    return f"{n:,}"


def plan_lines(parts, todo, done, pending):
    lines = []
    for part in dict.fromkeys(parts):
        rows = [r for p, r in todo if p == part]
        strata = collections.Counter((r["ecosystem"], r["label"]) for r in rows)
        forms = collections.Counter(r["form"] for r in rows)
        big = sum(1 for r in rows if r.get("bytes", 0) > v1().MAX_UPLOAD)
        lines += [
            f"구간 {part}: 표본 {num(len(rows))} · 이미 기록 {num(sum(1 for r in rows if r['id'] in done[part]))} · "
            f"이번 대상 {num(sum(1 for p, _ in pending if p == part))}",
            "  " + " · ".join(f"{e} {LABEL_KO[lab]} {num(strata[(e, lab)])}" for e in split.ECOSYSTEMS for lab in split.LABELS),
            "  올림 형식: " + " · ".join(f"{FORM_NOTE[f]} {num(forms[f])}" for f in FORM_NOTE if forms[f]),
        ]
        if big:
            lines.append(f"  파일이 50MB 를 넘는 표본 {num(big)} — 악성은 다시 묶은 크기로 가리고, 넘으면 건너뜀으로 남긴다")
    return lines


def cmd_run(args):
    data = data_dir()
    todo = select(args.parts, data)
    done = {p: read_results(results_path(data, p)) for p in dict.fromkeys(args.parts)}

    def recorded(part, sid):
        rec = done[part].get(sid)
        return rec is not None and not (args.retry_errors and rec["status"] == "error")

    pending = [(p, r) for p, r in todo if not recorded(p, r["id"])]
    if args.reverse:
        pending.reverse()
    if args.limit:
        pending = pending[:args.limit]
    print("\n".join(plan_lines(args.parts, todo, done, pending)), flush=True)
    if args.dry_run:
        print("dry-run — 백엔드에 닿지 않았고 아무것도 쓰지 않았다")
        return
    if not pending:
        return
    lost = [r["id"] for _, r in pending if not os.path.exists(sample_path(data, r))]
    if lost:
        raise Stop(f"표본 파일이 없다({num(len(lost))}개, 처음 {lost[0]}) — 아무것도 올리지 않았다. 데이터 폴더: {data}")
    api = make_api(args.api, read_token(args.token_file))
    tally = collections.Counter()
    for n, (part, row) in enumerate(pending, 1):
        t0 = time.time()
        # --reverse 는 앞에서부터 도는 다른 실행과 함께 쓰는 것 — 표본마다 결과 파일을 다시 보고, 그사이 기록된 것은 건너뛴다
        if args.reverse and row["id"] in read_results(results_path(data, part)):
            tally["other"] += 1
            continue
        upload, why = prepare(row, data)
        rec = {"status": "skip", "why": why} if upload is None else scan(api, *upload, args.timeout)
        del upload
        append_result(results_path(data, part), {"id": row["id"], **rec})
        tally[rec["status"]] += 1
        note = f"{rec['verdict']:<10} 점수 {rec['score']} · 설치 시점 {rec['installThreats']}" if rec["status"] == "ok" else reason(rec)
        print(f"[{n}/{len(pending)}] {row['id']} {rec['status']:<5} {note} · {time.time() - t0:.1f}s", flush=True)
    print(f"이번 실행 {num(len(pending))}건: 검사함 {num(tally['ok'])} · 건너뜀 {num(tally['skip'])} · 오류 {num(tally['error'])}"
          + (f" · 다른 실행이 기록함 {num(tally['other'])}" if args.reverse else ""))


# ── 보고 ──

def flags(rows, results, verdicts):
    """{id: 후보 판정}. 결과가 없거나 처리하지 못한(status 가 ok 가 아닌) 표본은 None — 지표에서 「못 잡음」."""
    out = {}
    for r in rows:
        rec = results.get(r["id"])
        out[r["id"]] = rec.get("verdict") in verdicts if rec and rec["status"] == "ok" else None
    return out


def share(k, n):
    return {"flagged": k, "rows": n, "rate": round(k / n, metrics.DIGITS) if n else 0.0,
            "ci95": [round(x, metrics.DIGITS) for x in metrics.wilson(k, n)]}


def breakdown(rows, pred):
    """주 지표(정상 전부 + 코드 있는 악성) · 코드 없는 악성(따로) · 정상 묶음(인기 · 롱테일)별 오탐률."""
    main = metrics.main_rows(rows)
    no_code = [r for r in rows if r["label"] == "malicious" and not metrics.analyzable(r)]
    benign = [r for r in rows if r["label"] == "benign"]
    hit = lambda rs: sum(1 for r in rs if pred[r["id"]])  # noqa: E731
    return {
        "main": metrics.summary(metrics.labels(main), [pred[r["id"]] for r in main]),
        "maliciousWithoutCode": share(hit(no_code), len(no_code)),
        "benignBySource": {src: share(hit([r for r in benign if r["source"] == src]), sum(1 for r in benign if r["source"] == src))
                           for src in sorted({r["source"] for r in benign})},
    }


def part_report(rows, results, results_sha=None):
    """한 구간의 보고(dict). rows = 색인 줄, results = read_results() 결과."""
    ids = {r["id"] for r in rows}
    state = lambda r: results[r["id"]]["status"] if r["id"] in results else "missing"  # noqa: E731
    count = collections.Counter(state(r) for r in rows)
    unprocessed = [r for r in rows if state(r) != "ok"]
    why = collections.Counter(f"{state(r)}: {reason(results[r['id']])}" if r["id"] in results else "결과 없음" for r in unprocessed)
    verdicts = {}
    for eco in split.ECOSYSTEMS:
        for label in split.LABELS:
            c = collections.Counter(results[r["id"]].get("verdict") if state(r) == "ok" else "unprocessed"
                                    for r in rows if (r["ecosystem"], r["label"]) == (eco, label))
            verdicts[f"{eco}:{label}"] = {k: c[k] for k in VERDICTS + ("unprocessed",)}
    engines = collections.defaultdict(set)
    for r in rows:
        for name, version in (results.get(r["id"], {}).get("engines") or {}).items():
            engines[name].add(version)
    candidates = {}
    for name, hits in CANDIDATES:
        pred = flags(rows, results, hits)
        candidates[name] = {"all": breakdown(rows, pred),
                            "byEcosystem": {eco: breakdown([r for r in rows if r["ecosystem"] == eco], pred) for eco in split.ECOSYSTEMS}}
    return {
        "samples": {"total": len(rows), **{k: count[k] for k in STATUSES + ("missing",)}, "outsidePart": sum(1 for i in results if i not in ids)},
        "rows": {"benign": sum(1 for r in rows if r["label"] == "benign"),
                 "maliciousWithCode": sum(1 for r in rows if r["label"] == "malicious" and metrics.analyzable(r)),
                 "maliciousWithoutCode": sum(1 for r in rows if r["label"] == "malicious" and not metrics.analyzable(r))},
        "unprocessed": {"total": len(unprocessed), **{lab: sum(1 for r in unprocessed if r["label"] == lab) for lab in split.LABELS},
                        "why": dict(why.most_common())},
        "engines": {name: sorted(vs) for name, vs in sorted(engines.items())},
        "verdicts": verdicts,
        "candidates": candidates,
        "resultsSha256": results_sha,
    }


def pct(x):
    return f"{x * 100:.2f}%"


def span(ci):
    return f"{ci[0] * 100:.2f}~{ci[1] * 100:.2f}%"


def cell(s):
    return f"{num(s['flagged'])}/{num(s['rows'])}" + (f" ({pct(s['rate'])})" if s["rows"] else "")


def render(part, rep):
    """사람이 읽는 표(마크다운)."""
    s, rows, un = rep["samples"], rep["rows"], rep["unprocessed"]
    out = [
        f"# 정적 층 기준선 · 구간 {part}", "",
        f"표본 {num(s['total'])} = 정상 {num(rows['benign'])} + 코드 있는 악성 {num(rows['maliciousWithCode'])} "
        f"+ 코드 없는 악성 {num(rows['maliciousWithoutCode'])}(주 지표 밖 · 따로 보고)",
        "검사기: " + (" · ".join(f"{name} {' / '.join(vs)}" for name, vs in rep["engines"].items()) or "검사한 표본 없음"),
        f"처리: 검사함 {num(s['ok'])} · 건너뜀 {num(s['skip'])} · 오류 {num(s['error'])} · 결과 없음 {num(s['missing'])} → "
        f"「못 잡음」으로 센 표본 {num(un['total'])}(악성 {num(un['malicious'])} · 정상 {num(un['benign'])}) — 분모에서 빼지 않았다",
    ]
    if un["why"]:
        out.append("사유: " + " · ".join(f"{k} {num(n)}" for k, n in un["why"].items()))
    if s["outsidePart"]:
        out.append(f"이 구간 표본이 아닌 결과 줄 {num(s['outsidePart'])}개는 세지 않았다")
    out += ["", "| 후보 | 범위 | 탐지율 | 95% 구간 | 오탐률 | 95% 구간 | 정밀도 | F1 | TP | FN | FP | TN |",
            "|---|---|---:|---|---:|---|---:|---:|---:|---:|---:|---:|"]
    scopes = lambda c: [("전체", c["all"])] + list(c["byEcosystem"].items())  # noqa: E731
    for name, c in rep["candidates"].items():
        for scope, b in scopes(c):
            m = b["main"]
            out.append(f"| {name} | {scope} | {pct(m['detection'])} | {span(m['detectionCi95'])} | {pct(m['fpr'])} | {span(m['fprCi95'])} | "
                       f"{pct(m['precision'])} | {m['f1']:.4f} | {num(m['tp'])} | {num(m['fn'])} | {num(m['fp'])} | {num(m['tn'])} |")
    sources = sorted({src for c in rep["candidates"].values() for src in c["all"]["benignBySource"]},
                     key=lambda src: (list(SOURCE_KO).index(src) if src in SOURCE_KO else len(SOURCE_KO), src))
    out += ["", "| 후보 | 범위 | " + " | ".join(f"정상 {SOURCE_KO.get(src, src)} 묶음 오탐" for src in sources) + " | 코드 없는 악성 탐지(따로) |",
            "|---|---|" + "---:|" * (len(sources) + 1)]
    for name, c in rep["candidates"].items():
        for scope, b in scopes(c):
            cells = [cell(b["benignBySource"][src]) if src in b["benignBySource"] else "" for src in sources]
            out.append(f"| {name} | {scope} | " + " | ".join(cells + [cell(b["maliciousWithoutCode"])]) + " |")
    out += ["", "| 판정 분포 | 악성 | 주의 | 취약 | 정상 | 처리 못 함(못 잡음으로 셈) |", "|---|---:|---:|---:|---:|---:|"]
    for key, v in rep["verdicts"].items():
        eco, label = key.split(":")
        out.append(f"| {eco} {LABEL_KO[label]} | " + " | ".join(num(v[k]) for k in VERDICTS + ("unprocessed",)) + " |")
    return "\n".join(out) + "\n"


def file_sha(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return sample.sha256(f.read())


def cmd_report(args):
    data = data_dir()
    todo = select(args.parts, data)
    doc = {
        "schema": 1, "layer": "static",
        "generatedAt": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocolSha256": file_sha(split.PROTOCOL), "splitSha256": file_sha(split.SPLIT),
        "candidates": {name: list(hits) for name, hits in CANDIDATES},
        "parts": {},
    }
    for part in dict.fromkeys(args.parts):
        path = results_path(data, part)
        doc["parts"][part] = part_report([r for p, r in todo if p == part], read_results(path), file_sha(path))
        print(render(part, doc["parts"][part]))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
            f.write("\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="표본을 백엔드에 올려 검사하고 결과를 남긴다")
    r.add_argument("--parts", nargs="+", default=["train"], help="구간(기본 train). 봉인 구간은 거부된다")
    r.add_argument("--api", default=API_DEFAULT, help=f"백엔드 API 주소(기본 {API_DEFAULT})")
    r.add_argument("--token-file", default=os.path.join(split.ROOT, ".env.local"), help="ADMIN_TOKEN= 줄이 있는 파일(환경 변수가 먼저)")
    r.add_argument("--limit", type=int, default=0, help="이번 실행에서 새로 검사할 표본 수 상한")
    r.add_argument("--timeout", type=int, default=900, help="검사 한 건 결과 대기 상한(초)")
    r.add_argument("--retry-errors", action="store_true", help="status 가 error 인 표본을 다시 검사한다(마지막 줄이 이긴다)")
    r.add_argument("--reverse", action="store_true",
                   help="뒤에서부터 돈다 — 앞에서부터 도는 다른 실행과 함께 쓸 때(백엔드가 검사 두 개를 함께 돌린다). 그사이 기록된 표본은 건너뛴다")
    r.add_argument("--dry-run", action="store_true", help="백엔드에 닿지 않고 구간별 표본 수 · 올림 형식만 보인다")
    r.set_defaults(fn=cmd_run)
    p = sub.add_parser("report", help="결과 → 후보 판정별 지표")
    p.add_argument("--parts", nargs="+", default=["train"])
    p.add_argument("--json", help="보고를 JSON 으로도 쓸 경로")
    p.set_defaults(fn=cmd_report)
    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except split.SealedError as e:
        sys.exit(f"거부: {e}")
    except Stop as e:
        sys.exit(f"멈춤: {e}")
    except KeyboardInterrupt:
        sys.exit("중단 — 다시 돌리면 이어서 한다")


if __name__ == "__main__":
    main()
