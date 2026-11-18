#!/usr/bin/env python3
"""평가 규칙 v3 — LLM 관문 경계 · 비용 상한 · 운영점 선택(주 · 보조) · 시험 구간 측정. 규칙은 bench/v3/protocol.json
(layers.llm · selection · metrics).

  bench/.venv/bin/python -B bench/v3/select3.py gate                       # v3 학습 구간 겹 밖 예측 → 관문 경계(JSON)
  python3 -B bench/v3/select3.py llm-budget --part calibration             # → 45
  python3 -B bench/v3/select3.py llm-budget --part test                    # → 100 − 보정에서 쓴 돈(다시 쓴 v2 답은 0)
  python3 -B bench/v3/select3.py select --llm <out-calibration.jsonl> [--write]   # 보정 구간 → bench/v3/selection.json
  python3 -B bench/v3/select3.py measure --llm <out-test.jsonl> --json <보고 파일>  # 시험 구간(개봉 뒤) — 주 · 보조 운영점 · 기준선

입력: <데이터>/index.jsonl · results/ml-<구간>.jsonl(정적 ML) · results/static-<구간>.jsonl · results/rules-<구간>.jsonl · LLM 결과 파일.
층이 처리하지 못한 표본(점수 없음 · 관문 밖 · 예산 건너뜀 · 오류)은 그 층이 못 잡은 것으로 센다 — 분모에서 빼지 않는다.
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2")
sys.path.insert(0, V2)
sys.path.insert(0, HERE)
import llm_layer  # noqa: E402
import metrics  # noqa: E402
import run_static  # noqa: E402
import split  # noqa: E402
import split3  # noqa: E402
import static_ml  # noqa: E402

PRIMARY_FPR = 0.02
SECONDARY_FPR = 0.001
INCLUSION_POINTS = 100   # LLM 을 판정에 넣는 기준: 탐지 수가 악성 분모의 1/100(= 1%p) 이상 늘어야 한다(3-llm)
CAL_BUDGET, TEST_BUDGET = 45.0, 55.0   # 합 $100(사용자 결정 2026-11-18). 보정에서 남은 돈은 시험으로 넘긴다
GATE_LOW, GATE_HIGH_BUDGET = 0.02, 0.0025   # 3-llm: 아래 0.02 · 위 = 겹 밖 예측의 오탐 0.25% 지점
STATIC_ADDENDUM = os.path.join(V2, "addenda", "1-static.json")
LAYERS = (("ml", "M-static"), ("llm", "L"))


# ── 후보 · 판정(순수) ──

def candidates(layer, prefix, main, scores):
    """점수형 층의 후보(protocol layers.budgets — v2 metrics.budget_points 그대로). main = 주 지표 줄(정상 + 코드 있는 악성)."""
    pts = metrics.budget_points([scores.get(r["id"]) for r in main], metrics.labels(main))
    out = []
    for name, threshold in pts:
        budget = float(name[len("fpr<="):])
        out.append({"layer": layer, "name": f"{prefix}@{budget}", "budget": budget, "threshold": threshold})
    return out


def flags(cand, rows, scores):
    """후보 판정 [bool]. 점수가 없으면 음성(못 잡음)."""
    return metrics.score_flags([scores.get(r["id"]) for r in rows], cand["threshold"])


def _best(y, layers, max_fpr):
    try:
        return metrics.select(y, layers, max_fpr)
    except ValueError:
        return None


def make_selection(rows, scores):
    """보정 구간 → 선택(dict). 후보: ML(M-static@예산) · LLM(L@예산). LLM 은 포함 규칙(ML 만의 주 운영점보다 탐지 +1%p 이상)을
    통과할 때만 선택 공간에 넣고, 그 공간에서 주(오탐 <= 2%) · 보조(오탐 <= 0.1%) 운영점을 v2 selection.rule 로 고른다."""
    main = metrics.main_rows(rows)
    y = metrics.labels(main)
    positives = sum(y)
    cands = {layer: candidates(layer, prefix, main, scores.get(layer) or {}) for layer, prefix in LAYERS}
    fl = {layer: [(c["name"], flags(c, main, scores.get(layer) or {})) for c in cs] for layer, cs in cands.items()}
    ml_only = _best(y, [("ml", fl["ml"])], PRIMARY_FPR) if fl["ml"] else None
    with_llm = _best(y, [("llm", fl["llm"]), ("ml", fl["ml"])], PRIMARY_FPR) if fl["llm"] else None
    tp_ml = ml_only["calibration"]["tp"] if ml_only else 0
    tp_both = with_llm["calibration"]["tp"] if with_llm else 0
    included = with_llm is not None and (tp_both - tp_ml) * INCLUSION_POINTS >= positives > 0
    space = ([("llm", fl["llm"])] if included else []) + ([("ml", fl["ml"])] if fl["ml"] else [])
    if not space:
        raise ValueError("후보가 없다 — 보정 구간 ML 예측 · LLM 결과를 확인하라")
    by_name = {c["name"]: c for cs in cands.values() for c in cs}

    def point(max_fpr):
        sel = _best(y, space, max_fpr)
        if sel is None:
            return None
        return {"maxFpr": max_fpr, "points": {layer: by_name[name] for layer, name in sel["points"].items()},
                "calibration": sel["calibration"]}

    primary = point(PRIMARY_FPR)
    if primary is None:
        raise ValueError(f"보정 구간 복합 오탐률 <= {PRIMARY_FPR} 인 조합이 없다")
    return {
        "schema": 1,
        "rows": {"total": len(rows), "main": len(main), "malicious": positives, "benign": len(y) - positives},
        "candidates": cands,
        "llmInclusion": {"included": included, "gain": (tp_both - tp_ml) / positives if positives else 0.0,
                         "rule": "보정 구간 오탐 <= 0.02 에서 ML 만의 운영점보다 탐지율 +0.01 이상(3-llm)",
                         "mlOnly": ml_only["calibration"] if ml_only else None, "withLlm": with_llm["calibration"] if with_llm else None},
        "primary": primary,
        "secondary": point(SECONDARY_FPR),
    }


def write_selection(sel, path=split3.SELECTION3, *, ledger_path=split3.LEDGER3):
    """선택 파일을 쓴다. 시험 구간을 연 뒤에는 거부한다(protocol selection.output)."""
    if "test" in split.opened(split.read_ledger(ledger_path)):
        raise split.SealedError("시험 구간을 이미 열었다 — 선택을 바꾸지 않는다")
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sel, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, path)


def _subset(main, y, pred, keep):
    pick = [k for k, r in enumerate(main) if keep(r)]
    return metrics.summary([y[k] for k in pick], [pred[k] for k in pick])


def measure(rows, scores, selection, *, v2_ids=None):
    """구간 줄 + 층 점수 + 선택 → 보고(dict). 운영점마다 주 지표(95% 윌슨 구간 · 달성 여부) · 생태계별 · 출신별(v2 · 새 표본) ·
    코드 없는 악성 · 정상 인기 / 롱테일 · 발견 연도별 · 절제. 달성 판정은 주 운영점으로만."""
    main = metrics.main_rows(rows)
    y = metrics.labels(main)
    no_code = [r for r in rows if r["label"] == "malicious" and not metrics.analyzable(r)]
    benign = [r for r in rows if r["label"] == "benign"]
    out = {"rows": {"total": len(rows), "main": len(main), "malicious": sum(y), "benign": len(y) - sum(y), "noCodeMalicious": len(no_code)}}
    for key in ("primary", "secondary"):
        pt = selection.get(key)
        if not pt:
            out[key] = None
            continue
        layer_flags = {layer: flags(spec, main, scores.get(layer) or {}) for layer, spec in pt["points"].items()}
        pred = metrics.any_layer(list(layer_flags.values()))
        hit = {r["id"]: p for r, p in zip(main, pred)}
        nc = metrics.any_layer([flags(spec, no_code, scores.get(layer) or {}) for layer, spec in pt["points"].items()]) if no_code else []
        rep = {
            "maxFpr": pt["maxFpr"],
            "points": {layer: {"name": spec["name"], "threshold": spec["threshold"]} for layer, spec in pt["points"].items()},
            "main": metrics.summary(y, pred),
            "byEcosystem": {eco: _subset(main, y, pred, lambda r, e=eco: r["ecosystem"] == e) for eco in split.ECOSYSTEMS},
            "noCode": {"rows": len(no_code), "detected": sum(1 for x in nc if x)},
            "benignBySource": {src: run_static.share(sum(1 for r in benign if r["source"] == src and hit.get(r["id"])),
                                                     sum(1 for r in benign if r["source"] == src))
                               for src in sorted({r["source"] for r in benign})},
            "byYear": metrics.by_year(main, pred),
            "ablation": metrics.ablation(y, layer_flags),
        }
        if v2_ids is not None:
            rep["byOrigin"] = {"v2": _subset(main, y, pred, lambda r: r["id"] in v2_ids),
                               "new": _subset(main, y, pred, lambda r: r["id"] not in v2_ids)}
        out[key] = rep
    out["goal"] = {"point": "primary", "met": bool(out["primary"] and out["primary"]["main"]["met"])}
    return out


def precise_lists(path=STATIC_ADDENDUM):
    """1-static 의 R-precise@k 규칙 목록 {후보 이름: 규칙들}."""
    with open(path, encoding="utf-8") as f:
        cands = json.load(f)["candidates"]["rules"]
    return {c["id"]: set(c["rules"]) for c in cands if "rules" in c}


def baselines(rows, gd, ru, precise=None):
    """1-static 기준선(선택 공간 밖 · 보고만) {후보: [bool]}. 처리하지 못한 표본은 음성."""
    precise = precise if precise is not None else precise_lists()

    def ok(res):
        return res if res and res.get("status") == "ok" else None

    verdict = [(ok(gd.get(r["id"])) or {}).get("verdict") for r in rows]
    strong = [set((ok(ru.get(r["id"])) or {}).get("strong") or []) for r in rows]
    out = {"S-malicious": [v == "malicious" for v in verdict], "S-suspicious": [v in ("malicious", "suspicious") for v in verdict],
           "R-strong": [bool(s) for s in strong]}
    for name in sorted(precise):
        out[name] = [bool(s & precise[name]) for s in strong]
    return out


# ── LLM 관문 · 비용(순수) ──

def gate_bounds(oof, y, low=GATE_LOW, high_budget=GATE_HIGH_BUDGET):
    """3-llm 의 방법: 학습 구간 겹 밖 예측의 정상 오탐률 high_budget 지점 = 위 경계, 아래 경계 = low. 보정 구간은 보지 않는다.
    참고 값: 겹 밖 2% 운영점이 놓친 악성 가운데 관문 안 수 · 관문 안 정상 수."""
    pts = metrics.budget_points(oof, y, budgets=(high_budget,))
    if not pts:
        raise ValueError("겹 밖 예측으로 위 경계를 만들 수 없다")
    high = pts[0][1]
    two = metrics.budget_points(oof, y, budgets=(0.02,))
    t2 = two[0][1] if two else None
    missed = [p for p, a in zip(oof, y) if a == 1 and not (t2 is not None and p is not None and round(p, metrics.SCORE_DIGITS) >= t2)]
    return {"low": low, "high": high, "highBudget": high_budget, "twoPercentThreshold": t2,
            "benignRows": sum(1 for a in y if a == 0), "benignInBand": sum(1 for p, a in zip(oof, y) if a == 0 and llm_layer.gated(p, low, high)),
            "maliciousRows": sum(y), "maliciousInBand": sum(1 for p, a in zip(oof, y) if a == 1 and llm_layer.gated(p, low, high)),
            "missedAtTwoPercent": {"rows": len(missed), "inBand": sum(1 for p in missed if llm_layer.gated(p, low, high))}}


def llm_budget(part, calibration_spent):
    """LLM 상한(USD): 보정 45, 시험 55 + 보정에서 남은 돈. 예비는 없다."""
    if part == "calibration":
        return CAL_BUDGET
    if part == "test":
        return TEST_BUDGET + max(0.0, CAL_BUDGET - calibration_spent)
    raise ValueError(f"{part} 구간에는 LLM 예산이 없다")


def calibration_spent(path):
    """보정 결과 파일의 v3 비용(다시 쓴 v2 답은 0 으로 적혀 있다). 파일이 없으면 0."""
    return llm_layer.Results(path).spent if os.path.exists(path) else 0.0


def llm_scores(results_rows):
    """LLM 결과 줄 {id: 줄} → {id: 위험 점수}. 점수가 있는 답(OK · CACHED)만 — 거부 · 오류 · 예산 건너뜀 · 관문 밖은 점수 없음."""
    return {i: row["riskScore"] for i, row in results_rows.items()
            if row.get("status") in ("OK", "CACHED") and row.get("riskScore") is not None}


# ── 명령 ──

def _file_sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _context():
    data = split3.data_dir()
    with open(split3.SPLIT3, encoding="utf-8") as f:
        sp = json.load(f)
    return data, sp, split.read_ledger(split3.LEDGER3)


def _part_scores(data, part, llm_path):
    ml_path = static_ml.predictions_path(os.path.join(data, "results"), part)
    if not os.path.exists(ml_path):
        raise ValueError(f"{part} 구간 ML 예측이 없다({ml_path}) — run.py static_ml predict --parts {part}")
    scores = {"ml": static_ml.read_predictions(ml_path)}
    inputs = {"ml": _file_sha(ml_path)}
    if llm_path:
        scores["llm"] = llm_scores(llm_layer.Results(llm_path).rows)
        inputs["llm"] = _file_sha(llm_path)
    return scores, inputs


def cmd_gate(_args):
    data, sp, ledger = _context()
    if static_ml.ml_missing():
        sys.exit(static_ml.ml_missing())
    rows, gd, ru = static_ml.load_part(data, sp, ledger, ["train"])
    _, y, oof = static_ml.oof_predictions(rows, gd, ru, sp["groupOf"])
    print(json.dumps({"part": "train", "rows": len(y), **gate_bounds(oof, y)}, ensure_ascii=False, indent=1))


def cmd_budget(args):
    spent = calibration_spent(args.calibration_results or os.path.join(split3.data_dir(), "llm", "out-calibration.jsonl"))
    print(f"{llm_budget(args.part, spent):.2f}")


def cmd_select(args):
    data, sp, ledger = _context()
    rows, _, _ = static_ml.load_part(data, sp, ledger, ["calibration"])
    scores, inputs = _part_scores(data, "calibration", args.llm)
    sel = make_selection(rows, scores)
    sel["inputs"] = {"splitSha256": _file_sha(split3.SPLIT3), "protocolSha256": _file_sha(split3.PROTOCOL3), **inputs}
    p, s = sel["primary"], sel["secondary"]
    print(f"LLM 포함: {sel['llmInclusion']['included']}(탐지 +{sel['llmInclusion']['gain']:.4f})")
    for name, pt in (("주(<= 2%)", p), ("보조(<= 0.1%)", s)):
        if pt is None:
            print(f"{name}: 없음")
            continue
        c = pt["calibration"]
        print(f"{name}: {', '.join(v['name'] for v in pt['points'].values())} · 보정 탐지 {c['detection']:.4f} · 오탐 {c['fpr']:.4f}")
    if args.write:
        write_selection(sel)
        print("bench/v3/selection.json 을 썼다 — 커밋한 뒤 split3.py unseal test")


def cmd_measure(args):
    data, sp, ledger = _context()
    with open(split3.SELECTION3, encoding="utf-8") as f:
        sel = json.load(f)
    rows, gd, ru = static_ml.load_part(data, sp, ledger, [args.part])  # 봉인이면 SealedError
    scores, inputs = _part_scores(data, args.part, args.llm)
    with open(split3.V2_SPLIT, encoding="utf-8") as f:
        v2_ids = set(json.load(f)["assignments"])
    main = metrics.main_rows(rows)
    base = baselines(main, gd, ru)
    rep = measure(rows, scores, sel, v2_ids=v2_ids)
    y = metrics.labels(main)
    rep["baselines"] = {name: metrics.summary(y, fl) for name, fl in base.items()}
    rep["part"] = args.part
    rep["inputs"] = {"selectionSha256": _file_sha(split3.SELECTION3), "splitSha256": _file_sha(split3.SPLIT3), **inputs}
    rep["split"] = {k: sp.get(k) for k in ("kept", "newKept", "inherited", "excludedRows", "duplicatesDropped", "groups")}
    if args.llm:
        rep["llm"] = llm_layer.summarize(llm_layer.Results(args.llm))
        rep["llm"]["reused"] = sum(1 for r in llm_layer.Results(args.llm).rows.values() if r.get("reusedFrom"))
    text = json.dumps(rep, ensure_ascii=False, indent=1)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    m = rep["primary"]["main"]
    print(f"{args.part} 주 운영점: 탐지 {m['detection']:.4f} {m['detectionCi95']} · 오탐 {m['fpr']:.4f} {m['fprCi95']} · 달성 {m['met']}")
    if rep["secondary"]:
        s = rep["secondary"]["main"]
        print(f"{args.part} 보조 운영점: 탐지 {s['detection']:.4f} · 오탐 {s['fpr']:.4f}")
    if not args.json:
        print(text)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gate", help="학습 구간 겹 밖 예측 → LLM 관문 경계").set_defaults(fn=cmd_gate)
    b = sub.add_parser("llm-budget", help="구간의 LLM 상한(USD)")
    b.add_argument("--part", required=True, choices=("calibration", "test"))
    b.add_argument("--calibration-results", help="보정 LLM 결과 파일(기본 <데이터>/llm/out-calibration.jsonl)")
    b.set_defaults(fn=cmd_budget)
    s = sub.add_parser("select", help="보정 구간 → 주 · 보조 운영점")
    s.add_argument("--llm", help="보정 LLM 결과 파일(없으면 ML 만)")
    s.add_argument("--write", action="store_true", help="bench/v3/selection.json 에 쓴다")
    s.set_defaults(fn=cmd_select)
    m = sub.add_parser("measure", help="열린 구간을 선택 그대로 잰다")
    m.add_argument("--part", default="test", choices=split.PARTS)
    m.add_argument("--llm", help="그 구간 LLM 결과 파일")
    m.add_argument("--json", help="보고를 JSON 으로 쓸 경로")
    m.set_defaults(fn=cmd_measure)
    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except split.SealedError as e:
        sys.exit(f"거부: {e}")
    except (ValueError, OSError, split3.Stop) as e:
        sys.exit(f"멈춤: {e}")


if __name__ == "__main__":
    main()
