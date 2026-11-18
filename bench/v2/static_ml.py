#!/usr/bin/env python3
"""평가 규칙 v2 — 정적 ML 층(M-static v1): 두 정적 엔진의 출력으로 학습한 모델의 악성 확률 p.

명세는 bench/v2/addenda/2-ml.json(특징 · 모델 · 학습 행 · 결측 · 제외 특징 · 후보). 이 파일은 그 부록의 기계적 구현이다.
입력은 표본이 아니라 앞 도구들의 결과 줄뿐이다 — GuardDog(bench/v2/run_static.py → results/static-<구간>.jsonl) ·
규칙 엔진(bench/v2/rules_layer.py → results/rules-<구간>.jsonl) · 색인의 ecosystem · label · codeLines. 표본 파일은 열지 않는다.
구간은 split.select_ids 로만 고른다 — 봉인 구간(test · reserve)은 연 기록이 없으면 거부된다.

  python3 -m venv bench/.venv && bench/.venv/bin/pip install -r bench/requirements-ml.txt
  bench/.venv/bin/python -B bench/v2/static_ml.py cv                                  # 학습 구간 묶음 5겹 교차 검증(개발용 · 지표 아님)
  bench/.venv/bin/python -B bench/v2/static_ml.py train [--out 모델 파일]              # → $SG_BENCH_DATA/models/static-ml.pkl + .meta.json
  bench/.venv/bin/python -B bench/v2/static_ml.py predict --parts calibration [--model …] [--out-dir …]   # → ml-<구간>.jsonl
  bench/.venv/bin/python -B bench/v2/static_ml.py report --parts calibration [--thresholds-from calibration] [--json]

특징(부록 features.order 순서로 한 줄):
  규칙 엔진 어휘 V_R 마다 시험 · 문서가 아닌 파일의 hit 의 min(count, 20) 합 → GuardDog 어휘 V_G 마다 0/1 →
  규칙 엔진 score · GuardDog score · GuardDog installThreats · npm 이면 1.
  어휘는 학습 구간 결과(처리된 것 전부)에서 만든 정렬 목록이고 모델 파일에 함께 넣는다. 다른 구간에서 처음 보는 이름은 버린다.
  엔진이 처리하지 못한 표본(skip · error · 결과 없음)은 그 엔진의 특징을 모두 0 으로 둔다.
학습 행: 학습 구간의 정상 + 코드 있는 악성(codeLines >= 1). 코드 없는 악성은 학습에서 빼고, 지표에서도 따로 센다.

예측 결과 한 줄(다른 층 — LLM 관문 — 이 읽는 계약): {"id": 표본 id, "p": 악성 확률(소수 6자리)}. 구간의 모든 표본(코드 없는 악성 포함)을
  id 순서로 쓴다. 옆의 ml-<구간>.meta.json 에 모델 sha256 을 적는다. 예측이 없는 표본은 보고에서 「못 잡음」(분모에서 빼지 않는다).
후보 M-static@<예산>: p >= 임계값. 임계값은 protocol layers.budgets 대로 보정 구간에서 metrics.budget_points 로 만든다.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pickle
import platform
import sys

sys.dont_write_bytecode = True  # bench/ 에 __pycache__ 를 남기지 않는다(추적 안 된 파일이 있으면 split.py unseal 이 거부한다)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import metrics  # noqa: E402
import rules_layer  # noqa: E402
import run_static  # noqa: E402
import split  # noqa: E402

NEEDS = ("sklearn", "numpy")
SKLEARN = "1.9.1"  # bench/requirements-ml.txt 와 같은 판
ADDENDUM = "bench/v2/addenda/2-ml.json"
RULE_CAP = 20
SCALARS = ("rules.score", "guarddog.score", "guarddog.installThreats", "npm")
PARAMS = {"max_iter": 300, "learning_rate": 0.05, "random_state": 7}
CV_FOLDS, CV_SEED = 5, 7
CV_BUDGETS = (0.01, 0.02, 0.03, 0.05)
MODEL_NAME = "static-ml.pkl"


def ml_missing():
    """모델을 맞출 수 없는 사유(맞출 수 있으면 빈 글). 시험은 이 사유로 건너뛴다."""
    lacking = [m for m in NEEDS if importlib.util.find_spec(m) is None]
    if lacking:
        return f"ML 의존성 없음({' · '.join(lacking)}) — bench/.venv/bin/pip install -r bench/requirements-ml.txt"
    return ""


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ── 입력 ──

def load_part(data, sp, ledger, parts):
    """구간의 색인 줄(split.select_ids 순서 — 봉인 구간이면 아무것도 읽기 전에 SealedError)과 두 엔진의 결과 {id: 줄}."""
    ids = split.select_ids(sp, parts, ledger)
    want = set(ids)
    index = {r["id"]: r for r in split.read_jsonl(os.path.join(data, "index.jsonl")) if r["id"] in want}
    lost = [i for i in ids if i not in index]
    if lost:
        raise ValueError(f"색인에 없는 표본 {len(lost)}개(예: {lost[0]}) — index.jsonl 과 split.json 이 맞지 않는다")
    gd, ru = {}, {}
    for part in parts:
        gd.update(run_static.read_results(run_static.results_path(data, part)))
        ru.update(rules_layer.read_results(rules_layer.results_path(data, part)))
    return ([index[i] for i in ids], {i: v for i, v in gd.items() if i in want}, {i: v for i, v in ru.items() if i in want})


def _ok(res):
    return res if res and res.get("status") == "ok" else None


def build_vocab(rows, gd, ru):
    """학습 구간 결과(처리된 것)에 나온 이름의 정렬 목록 — V_R(규칙 엔진 hits) · V_G(GuardDog rules)."""
    vr, vg = set(), set()
    for r in rows:
        if _ok(ru.get(r["id"])):
            vr.update(h["rule"] for h in ru[r["id"]]["hits"])
        if _ok(gd.get(r["id"])):
            vg.update(gd[r["id"]].get("rules") or [])
    return {"rules": sorted(vr), "guarddog": sorted(vg)}


def feature_names(vocab):
    return [f"rules:{n}" for n in vocab["rules"]] + [f"guarddog:{n}" for n in vocab["guarddog"]] + list(SCALARS)


def features(row, gd_res, rules_res, vocab):
    """한 표본의 특징 줄(feature_names 순서). 처리되지 않은 엔진의 특징은 모두 0, 어휘 밖의 이름은 버린다."""
    rules, guard = _ok(rules_res), _ok(gd_res)
    counts = dict.fromkeys(vocab["rules"], 0)
    if rules:
        for h in rules["hits"]:
            if h["rule"] in counts and not (h["test"] or h["doc"]):
                counts[h["rule"]] += min(h["count"], RULE_CAP)
    names = set(guard.get("rules") or []) if guard else set()
    return ([counts[n] for n in vocab["rules"]]
            + [1 if n in names else 0 for n in vocab["guarddog"]]
            + [(rules or {}).get("score") or 0, (guard or {}).get("score") or 0, (guard or {}).get("installThreats") or 0,
               1 if row["ecosystem"] == "npm" else 0])


def training_rows(rows):
    """학습 행: 정상 전부 + 코드 있는 악성(metrics.main_rows 와 같다)."""
    return metrics.main_rows(rows)


def coverage(rows, gd, ru):
    return {"rows": len(rows), "guarddogOk": sum(1 for r in rows if _ok(gd.get(r["id"]))),
            "rulesOk": sum(1 for r in rows if _ok(ru.get(r["id"])))}


# ── 모델 ──

def make_estimator():
    from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: PLC0415
    return HistGradientBoostingClassifier(**PARAMS)


def _matrix(rows, gd, ru, vocab):
    import numpy as np  # noqa: PLC0415
    return np.array([features(r, gd.get(r["id"]), ru.get(r["id"]), vocab) for r in rows], dtype=float)


def _p(model, X):
    proba = model.predict_proba(X)
    col = list(model.classes_).index(1)
    return [round(float(v), metrics.SCORE_DIGITS) for v in proba[:, col]]


def train(data, sp, ledger):
    """학습 구간 → 묶음(dict): 모델 · 어휘 · 특징 이름 · 학습 행 수 · 판."""
    import sklearn  # noqa: PLC0415
    rows, gd, ru = load_part(data, sp, ledger, ["train"])
    vocab = build_vocab(rows, gd, ru)
    main = training_rows(rows)
    y = metrics.labels(main)
    if len(set(y)) < 2:
        raise ValueError("학습 구간에 악성 · 정상이 함께 있어야 한다")
    model = make_estimator()
    model.fit(_matrix(main, gd, ru, vocab), y)
    names = feature_names(vocab)
    return {
        "schema": 1,
        "addendum": ADDENDUM,
        "model": model,
        "vocab": vocab,
        "features": names,
        "featureCount": len(names),
        "trainRows": {"total": len(main), "malicious": sum(y), "benign": len(y) - sum(y),
                      "noCodeMaliciousLeftOut": len(rows) - len(main)},
        "coverage": coverage(rows, gd, ru),
        "estimator": {"name": "HistGradientBoostingClassifier", "params": dict(PARAMS)},
        "sklearn": sklearn.__version__,
    }


def predict(bundle, rows, gd, ru):
    """[(id, p)] — rows 순서 그대로, 모든 표본."""
    if not rows:
        return []
    return list(zip((r["id"] for r in rows), _p(bundle["model"], _matrix(rows, gd, ru, bundle["vocab"]))))


def meta_path(model_path):
    return os.path.splitext(model_path)[0] + ".meta.json"


def save_model(bundle, path):
    """모델 파일(pickle) + 옆의 메타(json: sha256 · 어휘 · 특징 · 학습 행 수 · 판). 메타를 돌려준다."""
    import numpy  # noqa: PLC0415
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(bundle, f, protocol=5)
    meta = {"modelSha256": file_sha(path), **{k: v for k, v in bundle.items() if k != "model"},
            "numpy": numpy.__version__, "python": platform.python_version()}
    with open(meta_path(path), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
        f.write("\n")
    return meta


def load_model(path):
    """메타의 sha256 · scikit-learn 판이 맞을 때만 모델을 읽는다(우리가 만든 파일만 — pickle 이다)."""
    import sklearn  # noqa: PLC0415
    with open(meta_path(path), encoding="utf-8") as f:
        meta = json.load(f)
    if file_sha(path) != meta["modelSha256"]:
        raise ValueError(f"모델 파일이 메타의 sha256 과 다르다({os.path.basename(path)}) — 다시 train 하라")
    if meta["sklearn"] != sklearn.__version__:
        raise ValueError(f"scikit-learn 판이 모델을 만들 때와 다르다({meta['sklearn']} → {sklearn.__version__})")
    with open(path, "rb") as f:
        return pickle.load(f)  # noqa: S301 — sha256 을 맞춘 자기 모델 파일


# ── 예측 파일(계약) ──

def predictions_path(out_dir, part):
    return os.path.join(out_dir, f"ml-{part}.jsonl")


def write_predictions(path, preds):
    """[(id, p)] → 한 줄 {"id", "p"}. 구간 전체를 한 번에 다시 쓴다(임시 파일 → 이름 바꾸기)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for i, p in preds:
            f.write(json.dumps({"id": str(i), "p": round(float(p), metrics.SCORE_DIGITS)}, separators=(",", ":")) + "\n")
    os.replace(tmp, path)


def read_predictions(path):
    """{id: p}. 같은 id 는 뒤의 것."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                out[rec["id"]] = rec["p"]
    return out


# ── 교차 검증(개발용) ──

def folds(y, groups):
    """StratifiedGroupKFold(5, shuffle=True, random_state=7) — [(학습 위치, 검증 위치)]. 한 묶음은 한 겹에만."""
    from sklearn.model_selection import StratifiedGroupKFold  # noqa: PLC0415
    skf = StratifiedGroupKFold(n_splits=CV_FOLDS, shuffle=True, random_state=CV_SEED)
    return [(list(tr), list(te)) for tr, te in skf.split([[0]] * len(y), y, groups)]


def oof_predictions(rows, gd, ru, group_of):
    """학습 구간 묶음 5겹 교차 검증의 겹 밖 예측 → (학습 행, 라벨, p 목록 — 학습 행 순서). 어휘는 학습 구간 전체에서 한 번.
    v3 는 이 예측으로 LLM 관문 경계를 다시 정한다(3-llm 의 방법)."""
    vocab = build_vocab(rows, gd, ru)
    main = training_rows(rows)
    y = metrics.labels(main)
    X = _matrix(main, gd, ru, vocab)
    oof = [None] * len(main)
    for tr, te in folds(y, [group_of[r["id"]] for r in main]):
        model = make_estimator()
        model.fit(X[tr], [y[i] for i in tr])
        for i, p in zip(te, _p(model, X[te])):
            oof[i] = p
    return main, y, oof


def cross_validate(rows, gd, ru, group_of, budgets=CV_BUDGETS):
    """학습 구간 묶음 5겹 교차 검증. 어휘는 학습 구간 전체에서 한 번(부록 trainReference 와 같은 식).
    겹 밖 예측을 모아 예산마다 metrics.budget_points 의 임계값 → 탐지 · 오탐."""
    main, y, oof = oof_predictions(rows, gd, ru, group_of)
    features = len(feature_names(build_vocab(rows, gd, ru)))
    at = []
    for b in budgets:
        pts = metrics.budget_points(oof, y, budgets=(b,))
        t = pts[0][1] if pts else None
        flags = metrics.score_flags(oof, t) if t is not None else [False] * len(y)
        at.append({"budget": b, "threshold": t, **metrics.summary(y, flags)})
    return {"rows": {"total": len(main), "malicious": sum(y), "benign": len(y) - sum(y)}, "features": features,
            "folds": CV_FOLDS, "atFpr": at}


# ── 보고 ──

def thresholds(cal_rows, cal_p):
    """[(예산, 임계값)] — 보정 구간 주 지표 줄(정상 전부 + 코드 있는 악성)의 p 로 metrics.budget_points. 예측 없는 표본은 None."""
    main = metrics.main_rows(cal_rows)
    pts = metrics.budget_points([cal_p.get(r["id"]) for r in main], metrics.labels(main))
    return [(float(name[len("fpr<="):]), t) for name, t in pts]


def report(rows, p, ths):
    """구간의 색인 줄 + 예측 {id: p} + 임계값 → 후보 M-static@<예산> 별 지표. 예측 없는 표본은 「못 잡음」."""
    main = metrics.main_rows(rows)
    y = metrics.labels(main)
    no_code = [r for r in rows if r["label"] == "malicious" and not metrics.analyzable(r)]
    candidates = []
    for budget, t in ths:
        flags = metrics.score_flags([p.get(r["id"]) for r in main], t)
        nc = metrics.score_flags([p.get(r["id"]) for r in no_code], t)
        candidates.append({"name": f"M-static@{budget}", "budget": budget, "threshold": t,
                           **rules_layer._summaries(main, y, flags),
                           "noCode": {"rows": len(no_code), "detected": sum(nc)}})
    return {"rows": len(rows), "main": {"malicious": sum(y), "benign": len(y) - sum(y)}, "noCodeMalicious": len(no_code),
            "predictions": {"rows": len(rows), "missing": sum(1 for r in rows if r["id"] not in p)},
            "candidates": candidates}


def _pct(x):
    return f"{x * 100:.2f}%"


def _ci(pair):
    return f"{pair[0] * 100:.1f}~{pair[1] * 100:.1f}"


def format_report(rep):
    lines = [f"정적 ML 층(M-static v1) · {rep['part']} 구간 · 표본 {rep['rows']:,}(주 지표: 코드 있는 악성 {rep['main']['malicious']:,} + "
             f"정상 {rep['main']['benign']:,} · 코드 없는 악성 {rep['noCodeMalicious']:,}은 따로)",
             f"예측 없음 {rep['predictions']['missing']:,}(분모에 두고 「못 잡음」으로 센다) · 임계값은 {rep['thresholdsFrom']} 구간 예산으로"]
    if rep.get("model"):
        lines.insert(1, f"모델 {rep['model'][:12]}")
    if rep["part"] == "train":
        lines.append("학습 구간은 모델이 학습한 표본이라 지표가 아니다(동작 확인용)")
    table = [["후보", "임계값", "범위", "악성", "잡음", "탐지율", "95% 구간", "정상", "오탐", "오탐률", "95% 구간", "정밀도", "F1", "코드 없는 악성"]]
    for c in rep["candidates"]:
        for scope in ("all", *split.ECOSYSTEMS):
            s = c[scope]
            first = scope == "all"
            table.append([c["name"] if first else "", f"{c['threshold']:g}" if first else "", "전체" if first else scope,
                          f"{s['tp'] + s['fn']:,}", f"{s['tp']:,}", _pct(s["detection"]), _ci(s["detectionCi95"]),
                          f"{s['fp'] + s['tn']:,}", f"{s['fp']:,}", _pct(s["fpr"]), _ci(s["fprCi95"]), _pct(s["precision"]),
                          _pct(s["f1"]), f"{c['noCode']['detected']:,}/{c['noCode']['rows']:,}" if first else ""])
    lines += ["", *rules_layer._table(table, left=(0, 2))]
    if not rep["candidates"]:
        lines.append("후보 없음: 임계값을 만들 수 없다")
    return "\n".join(lines)


def format_cv(res):
    lines = [f"정적 ML 층 · 학습 구간 묶음 {res['folds']}겹 교차 검증(개발용 · 지표 아님) · 행 {res['rows']['total']:,}"
             f"(코드 있는 악성 {res['rows']['malicious']:,} · 정상 {res['rows']['benign']:,}) · 특징 {res['features']}"]
    table = [["오탐 예산", "임계값", "탐지율", "95% 구간", "오탐률", "잡음", "오탐"]]
    for b in res["atFpr"]:
        table.append([f"{b['budget']:g}", "" if b["threshold"] is None else f"{b['threshold']:g}", _pct(b["detection"]),
                      _ci(b["detectionCi95"]), _pct(b["fpr"]), f"{b['tp']:,}", f"{b['fp']:,}"])
    return "\n".join(lines + ["", *rules_layer._table(table, left=())])


# ── 명령 ──

def _split(args):
    with open(args.split_json, encoding="utf-8") as f:
        return json.load(f)


def _need_ml():
    why = ml_missing()
    if why:
        sys.exit(why)


def cmd_cv(args):
    sp = _split(args)
    rows, gd, ru = load_part(args.data, sp, split.read_ledger(), ["train"])
    _need_ml()
    res = cross_validate(rows, gd, ru, sp["groupOf"])
    print(json.dumps(res, ensure_ascii=False, indent=1) if args.json else format_cv(res))


def cmd_train(args):
    sp = _split(args)
    split.select_ids(sp, ["train"], split.read_ledger())
    _need_ml()
    bundle = train(args.data, sp, split.read_ledger())
    bundle["inputs"] = {"splitSha256": file_sha(args.split_json),
                        **{k: file_sha(p) if os.path.exists(p) else None
                           for k, p in (("staticSha256", run_static.results_path(args.data, "train")),
                                        ("rulesSha256", rules_layer.results_path(args.data, "train")))}}
    out = os.path.abspath(args.out or os.path.join(args.data, "models", MODEL_NAME))
    meta = save_model(bundle, out)
    t, cov = meta["trainRows"], meta["coverage"]
    print(f"모델 {out}\n  sha256 {meta['modelSha256']}\n  학습 행 {t['total']:,}(코드 있는 악성 {t['malicious']:,} · 정상 {t['benign']:,} · "
          f"코드 없는 악성 {t['noCodeMaliciousLeftOut']:,} 뺌) · 특징 {meta['featureCount']}(규칙 엔진 {len(meta['vocab']['rules'])} · "
          f"GuardDog {len(meta['vocab']['guarddog'])} · 값 {len(SCALARS)})\n  학습 구간 결과: GuardDog 처리 {cov['guarddogOk']:,} · "
          f"규칙 엔진 처리 {cov['rulesOk']:,} / {cov['rows']:,} · scikit-learn {meta['sklearn']}")


def cmd_predict(args):
    sp, ledger = _split(args), split.read_ledger()
    split.select_ids(sp, args.parts, ledger)  # 봉인 구간은 모델을 읽기 전에 거부
    _need_ml()
    model_path = os.path.abspath(args.model or os.path.join(args.data, "models", MODEL_NAME))
    bundle = load_model(model_path)
    sha = file_sha(model_path)
    out_dir = os.path.abspath(args.out_dir or os.path.join(args.data, "results"))
    for part in args.parts:
        rows, gd, ru = load_part(args.data, sp, ledger, [part])
        path = predictions_path(out_dir, part)
        write_predictions(path, predict(bundle, rows, gd, ru))
        cov = coverage(rows, gd, ru)
        with open(os.path.splitext(path)[0] + ".meta.json", "w", encoding="utf-8") as f:
            json.dump({"part": part, "modelSha256": sha, "featureCount": bundle["featureCount"], "sklearn": bundle["sklearn"],
                       **cov}, f, ensure_ascii=False, indent=1)
            f.write("\n")
        print(f"{part} 구간 {cov['rows']:,}개 → {path}(GuardDog 처리 {cov['guarddogOk']:,} · 규칙 엔진 처리 {cov['rulesOk']:,} — "
              f"처리 못 한 엔진의 특징은 0)")


def cmd_report(args):
    sp, ledger = _split(args), split.read_ledger()
    split.select_ids(sp, [*args.parts, args.thresholds_from], ledger)
    pred_dir = os.path.abspath(args.pred_dir or os.path.join(args.data, "results"))
    cal_rows, _, _ = load_part(args.data, sp, ledger, [args.thresholds_from])
    cal_path = predictions_path(pred_dir, args.thresholds_from)
    if not os.path.exists(cal_path):
        raise ValueError(f"{args.thresholds_from} 구간 예측 파일이 없다({cal_path}) — 먼저 predict 하라")
    ths = thresholds(cal_rows, read_predictions(cal_path))
    reps = []
    for part in args.parts:
        rows, _, _ = load_part(args.data, sp, ledger, [part])
        path = predictions_path(pred_dir, part)
        if not os.path.exists(path):
            raise ValueError(f"{part} 구간 예측 파일이 없다({path}) — 먼저 predict 하라")
        mark = os.path.splitext(path)[0] + ".meta.json"
        model = json.load(open(mark, encoding="utf-8"))["modelSha256"] if os.path.exists(mark) else None
        reps.append({"part": part, "thresholdsFrom": args.thresholds_from, "model": model,
                     **report(rows, read_predictions(path), ths)})
    if args.json:
        print(json.dumps(reps, ensure_ascii=False, indent=1))
    else:
        print("\n\n".join(format_report(r) for r in reps))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--data", default=collect.DATA, help="데이터 폴더(기본 $SG_BENCH_DATA 또는 bench/datasets/v2)")
        p.add_argument("--split-json", default=split.SPLIT, help=argparse.SUPPRESS)
        return p

    c = common(sub.add_parser("cv", help="학습 구간 묶음 5겹 교차 검증(개발용)"))
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_cv)
    t = common(sub.add_parser("train", help="학습 구간으로 학습 → 모델 파일 + 메타"))
    t.add_argument("--out", help=f"모델 파일(기본 <데이터>/models/{MODEL_NAME})")
    t.set_defaults(fn=cmd_train)
    p = common(sub.add_parser("predict", help="구간마다 ml-<구간>.jsonl"))
    p.add_argument("--model", help=f"모델 파일(기본 <데이터>/models/{MODEL_NAME})")
    p.add_argument("--parts", nargs="+", required=True, choices=split.PARTS, help="봉인 구간은 연 기록이 있을 때만")
    p.add_argument("--out-dir", help="결과 폴더(기본 <데이터>/results)")
    p.set_defaults(fn=cmd_predict)
    r = common(sub.add_parser("report", help="후보 M-static@<예산> 별 지표"))
    r.add_argument("--parts", nargs="+", required=True, choices=split.PARTS)
    r.add_argument("--thresholds-from", default="calibration", choices=split.PARTS,
                   help="임계값을 만드는 구간(기본 calibration — protocol budgets)")
    r.add_argument("--pred-dir", help="예측 파일 폴더(기본 <데이터>/results)")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_report)
    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except split.SealedError as e:
        sys.exit(f"거부: {e}")
    except (ValueError, OSError) as e:
        sys.exit(f"멈춤: {e}")


if __name__ == "__main__":
    main()
