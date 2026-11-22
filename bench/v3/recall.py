#!/usr/bin/env python3
"""평가 규칙 v3 — LLM 재호출 변동 측정(부록 4-recall, 결과 전에 고정).

  python3 -B bench/v3/recall.py pick --input <보정 LLM 입력> --out <부분 입력>
  python3 -B bench/v3/recall.py summarize --input <부분 입력> --original <보정 LLM 결과> --runs <실행 1> <실행 2> <실행 3> \\
      --json bench/reports/v3-recall.json

같은 입력을 다시 부를 때 LLM 층의 점수와 판정이 얼마나 달라지는지를 잰다. 호출은 측정에 쓴 도구 그대로
(bench/v3/run.py llm_layer run — 같은 프롬프트 · 모델 · 요청 설정 · 2단계 규칙)이고, 이 파일은 표본을 고르고 결과를 견주기만 한다.

  pick       입력 줄을 sha256("<시드>:<id>") 오름차순으로 늘어놓고 앞 N 줄을 그대로 옮긴다. 라벨 · 점수 · 앞선 답을 보지 않는다.
             보정 구간의 표본만 받는다(다른 구간 · 봉인 구간의 표본이 섞이면 멈춘다).
  summarize  표본마다 원래 답과 새 실행들의 점수 · 판정을 견준다. 표본 id · 표본별 점수는 내지 않고 수만 낸다.

이 측정은 시험 구간의 값을 본 뒤에 더한 보조 측정이다. 임계값 · 운영점 · 대표 수치를 바꾸는 데 쓰지 않는다.
입력 · 결과 파일에는 표본 코드 글이 들어 있으므로 데이터 폴더 밖(저장소)에 두지 않는다.
"""
import argparse
import collections
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = "20261123:recall"       # 부록 4-recall
ROWS = 100
PART = "calibration"
KINDS = ("codeMalicious", "noCodeMalicious", "benign")


# ── 순수 계산 ──

def order_key(seed, sid):
    return hashlib.sha256(f"{seed}:{sid}".encode()).hexdigest()


def pick_ids(ids, seed, rows):
    """id 를 해시 순서로 늘어놓은 앞 rows 개. 입력 순서와 무관하다."""
    ids = sorted(set(ids))
    if rows > len(ids):
        raise ValueError(f"표본이 {len(ids)}개뿐이다 — {rows}개를 고를 수 없다")
    return sorted(ids, key=lambda s: order_key(seed, s))[:rows]


def nearest_rank(xs, p):
    """오름차순 목록의 p 분위(가장 가까운 순위)."""
    return xs[max(1, math.ceil(p * len(xs))) - 1]


def _score(r):
    s = r.get("riskScore")
    return s if isinstance(s, (int, float)) and not isinstance(s, bool) else None


def _flag(r, threshold):
    """점수가 임계 점수 이상이면 양성. 점수가 없는 결과(거부 · 오류 등)는 음성 — 평가 규칙과 같다."""
    s = _score(r)
    return s is not None and s >= threshold


def _escalated(r):
    return len({s.get("model") for s in r.get("stages") or []}) > 1


def _decision(original, runs, ids, threshold):
    pairs = [(a, b) for a in range(len(runs)) for b in range(a + 1, len(runs))]
    out = {"threshold": threshold, "allFlagged": 0, "noneFlagged": 0, "unstable": 0, "originalFlagged": 0, "differsFromOriginal": 0,
           "perRunDiffersFromOriginal": [0] * len(runs), "pairAgreement": [0] * len(pairs)}
    unstable = set()
    for sid in ids:
        base = _flag(original[sid], threshold)
        flags = [_flag(run[sid], threshold) for run in runs]
        out["originalFlagged"] += base
        if all(flags):
            out["allFlagged"] += 1
        elif not any(flags):
            out["noneFlagged"] += 1
        else:
            out["unstable"] += 1
            unstable.add(sid)
        out["differsFromOriginal"] += any(f != base for f in flags)
        for k, f in enumerate(flags):
            out["perRunDiffersFromOriginal"][k] += f != base
        for k, (a, b) in enumerate(pairs):
            out["pairAgreement"][k] += flags[a] == flags[b]
    return out, unstable


def summarize(original, runs, ids, thresholds, kind_of):
    """original = {id: 원래 결과 줄}, runs = [{id: 결과 줄}, …], thresholds = {이름: 임계 점수}, kind_of = {id: 표본 종류}."""
    for sid in ids:
        if sid not in original:
            raise ValueError("원래 결과에 없는 표본이 있다")
        if sid not in kind_of:
            raise ValueError("색인에 없는 표본이 있다")
        for k, run in enumerate(runs):
            if sid not in run:
                raise ValueError(f"실행 {k + 1} 의 결과에 없는 표본이 있다 — 실행을 끝낸 뒤 다시 센다")
    decision, unstable = {}, {}
    for name, threshold in thresholds.items():
        decision[name], unstable[name] = _decision(original, runs, ids, threshold)

    ranges, sds, inside = [], [], 0
    for sid in ids:
        scores = [_score(run[sid]) for run in runs]
        if any(s is None for s in scores):
            continue
        mean = sum(scores) / len(scores)
        ranges.append(max(scores) - min(scores))
        sds.append(math.sqrt(sum((s - mean) ** 2 for s in scores) / len(scores)))     # 모집단 꼴
        base = _score(original[sid])
        inside += base is not None and min(scores) <= base <= max(scores)
    ranges.sort()
    score = {"complete": len(ranges), "originalInsideRange": inside,
             "ranges": ({"zero": sum(1 for r in ranges if r == 0), "median": nearest_rank(ranges, 0.5), "p90": nearest_rank(ranges, 0.9),
                         "max": ranges[-1]} if ranges else None),
             "meanSd": (sum(sds) / len(sds) if sds else None)}

    esc = [[_escalated(run[sid]) for run in runs] for sid in ids]
    escalation = {"perRun": [sum(e[k] for e in esc) for k in range(len(runs))], "originalEscalated": sum(_escalated(original[s]) for s in ids),
                  "unstable": sum(1 for e in esc if any(e) and not all(e))}

    by_kind = {}
    for kind in KINDS:
        members = [s for s in ids if kind_of[s] == kind]
        if members:
            by_kind[kind] = {"rows": len(members), **{f"{name}Unstable": sum(1 for s in members if s in unstable[name]) for name in thresholds}}
    return {"rows": len(ids), "runs": len(runs), "decision": decision, "score": score, "escalation": escalation, "byKind": by_kind,
            "status": [dict(sorted(collections.Counter(run[s].get("status") for s in ids).items())) for run in runs],
            "spentUsd": [round(sum(float(run[s].get("costUsd") or 0) for s in ids), 8) for run in runs]}


# ── 파일 ──

def read_rows(path):
    """결과 JSONL → {id: 마지막 줄}. 찢어진 줄은 건너뛴다."""
    rows = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            rows[r["id"]] = r
    return rows


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _assignments():
    with open(os.path.join(HERE, "split.json"), encoding="utf-8") as f:
        return json.load(f)["assignments"]


def _refuse_tracked(path):
    """표본 코드 글이 든 파일을 저장소 안에 쓰지 않는다."""
    repo = os.path.dirname(os.path.dirname(HERE))
    if os.path.commonpath([os.path.realpath(path), os.path.realpath(repo)]) == os.path.realpath(repo) \
            and os.sep + os.path.join("bench", "datasets") + os.sep not in os.path.realpath(path):
        raise ValueError("입력 · 결과 파일은 데이터 폴더(bench/datasets/…)에만 쓴다")


def cmd_pick(args):
    _refuse_tracked(args.out)
    assignments = _assignments()
    lines = {}
    with open(args.input, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                sid = json.loads(line)["id"]
                if assignments.get(sid) != PART:
                    raise ValueError(f"{PART} 구간이 아닌 표본이 입력에 있다 — 멈춘다")
                lines[sid] = line if line.endswith("\n") else line + "\n"
    chosen = pick_ids(list(lines), args.seed, args.rows)
    with open(args.out, "w", encoding="utf-8") as f:
        for sid in chosen:
            f.write(lines[sid])
    print(f"{PART} 구간 LLM 입력 {len(lines):,}줄 가운데 {len(chosen):,}줄 → {args.out}(시드 {args.seed}) · 표본 코드 글이 들어 있다 — 커밋 · 공유하지 않는다")
    return 0


def cmd_summarize(args):
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), "v2"))
    import metrics  # noqa: E402
    ids = []
    with open(args.input, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ids.append(json.loads(line)["id"])
    if ids != pick_ids(ids, args.seed, len(ids)):
        raise ValueError("부분 입력의 순서가 시드의 해시 순서와 다르다 — pick 이 만든 파일이 아니다")
    kind_of = {}
    wanted = set(ids)
    with open(args.index, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                if r["id"] in wanted:
                    kind_of[r["id"]] = "benign" if r["label"] != "malicious" else ("codeMalicious" if metrics.analyzable(r) else "noCodeMalicious")
    with open(os.path.join(HERE, "selection.json"), encoding="utf-8") as f:
        sel = json.load(f)
    thresholds = {name: sel[name]["points"]["llm"]["threshold"] for name in ("primary", "secondary") if "llm" in sel[name]["points"]}
    report = summarize(read_rows(args.original), [read_rows(p) for p in args.runs], ids, thresholds, kind_of)
    report = {"schema": 1, "addendum": "4-recall", "part": PART, "seed": args.seed, **report,
              "inputs": {"subsetSha256": sha256_file(args.input), "originalSha256": sha256_file(args.original),
                         "runsSha256": [sha256_file(p) for p in args.runs], "selectionSha256": sha256_file(os.path.join(HERE, "selection.json"))}}
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    d = report["decision"]["primary"]
    print(f"표본 {report['rows']} · 실행 {report['runs']} · 주 운영점 임계 점수 {d['threshold']}: 세 판정이 갈린 표본 {d['unstable']} · "
          f"원래 판정과 다른 판정이 있는 표본 {d['differsFromOriginal']} · 비용 {sum(report['spentUsd']):.4f}달러 → {args.json}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pick = sub.add_parser("pick", help="보정 구간 LLM 입력에서 해시 순서 앞 N 줄을 옮긴다")
    pick.add_argument("--input", required=True)
    pick.add_argument("--out", required=True)
    pick.add_argument("--rows", type=int, default=ROWS)
    pick.add_argument("--seed", default=SEED)
    summ = sub.add_parser("summarize", help="원래 답과 새 실행들을 견주어 수만 낸다")
    summ.add_argument("--input", required=True, help="pick 이 만든 부분 입력")
    summ.add_argument("--original", required=True, help="보정 구간 LLM 결과(원래 답)")
    summ.add_argument("--runs", required=True, nargs="+", help="새 실행의 결과 파일들")
    summ.add_argument("--index", default=os.path.join(os.environ.get("SG_BENCH_DATA") or os.path.join(os.path.dirname(HERE), "datasets", "v3"), "index.jsonl"))
    summ.add_argument("--json", required=True)
    summ.add_argument("--seed", default=SEED)
    args = ap.parse_args(argv)
    return {"pick": cmd_pick, "summarize": cmd_summarize}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
