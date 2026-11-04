#!/usr/bin/env python3
"""M1 정적 검사 실험 모델 — 규칙 판정 vs 로지스틱 회귀 vs HistGradientBoosting 오프라인 비교.

판정 · kill 에 쓰지 않는다(deploymentApproved=false). 절차는 bench/ml/protocol.json 에 먼저 고정했다.

  python3 -m venv bench/.venv && bench/.venv/bin/pip install -r bench/ml/requirements.txt
  bench/.venv/bin/python bench/ml/train.py            # → bench/ml/selection.json · bench/reports/model.json
  bench/.venv/bin/python bench/ml/train.py --scope all  # npm 정상 세트가 있을 때만 — model.json 에 byEcosystem
  bench/.venv/bin/python -B -m unittest discover -s bench/ml -p 'test_*.py'

순서: 분할 → 학습 구간으로 학습 → 보정 구간으로 임계값 · 선택 → selection.json 저장 → 시험 구간 1회 평가.
선택 함수(fit_and_select)는 시험 구간을 인자로 받지 않는다.
"""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
import sys

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(ROOT, "bench", "reports", "static-items.jsonl")
PROTOCOL = os.environ.get("SG_ML_PROTOCOL") or os.path.join(ROOT, "bench", "ml", "protocol.json")
SELECTION = os.path.join(ROOT, "bench", "ml", "selection.json")
OUT = os.path.join(ROOT, "bench", "reports", "model.json")

NUMERIC = ["score", "installThreats", "threats", "capabilities", "testFindings", "log1p(files)", "log1p(bytes)"]
PARTS = ("train", "calibration", "test")
MAX_FPR = 0.05
PROB_DIGITS = 6
CANDIDATES = [  # 순서 = 보정 F1 동률일 때의 우선순위(단순한 쪽 먼저)
    ("rule-malicious", "규칙 판정 (악성)"),
    ("rule-suspicious", "규칙 판정 (악성+주의)"),
    ("logreg", "로지스틱 회귀"),
    ("hgb", "HistGradientBoosting"),
]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def load_rows(data_bytes):
    return [json.loads(l) for l in data_bytes.decode("utf-8").splitlines() if l.strip()]


def label(row):
    return 1 if row["set"].startswith("datadog-") else 0


def usable(rows, ecosystem):
    return [r for r in rows if r["ecosystem"] == ecosystem and r["verdict"] != "error"]


SCOPES = {"pypi": ("pypi",), "all": ("npm", "pypi")}


def scoped(rows, scope):
    """주 실험 행 · 참고 행. all 은 생태계마다 악성 · 정상이 모두 있어야 한다(없으면 생태계 단서만 배운다)."""
    ecos = SCOPES[scope]
    main = [r for e in ecos for r in usable(rows, e)]
    for e in ecos:
        ys = {label(r) for r in main if r["ecosystem"] == e}
        if ys != {0, 1}:
            raise ValueError(f"scope={scope}: {e} 에 {'정상' if 1 in ys else '악성'} 표본이 없다 — "
                             "정상 세트(benign-npm 등)를 측정한 뒤 실행한다")
    ref = [r for r in rows if r["ecosystem"] not in ecos and r["verdict"] != "error" and label(r) == 1]
    return main, ref


# ---------- 분할 ----------

def split_groups(rows, seed, fractions):
    """(생태계, 라벨) 층화 그룹 분할 → {packageGroup: 구간}. 한 그룹에 두 라벨 · 생태계가 섞이면 실패."""
    gkey = {}
    for r in rows:
        g, k = r["packageGroup"], (r["ecosystem"], label(r))
        if gkey.setdefault(g, k) != k:
            raise ValueError(f"packageGroup {g} 에 악성 · 정상(또는 생태계)이 섞였다")
    rng = np.random.default_rng(seed)
    assign = {}
    for stratum in sorted(set(gkey.values())):  # 고정 순서 — pypi 만이면 (pypi,0) → (pypi,1)
        groups = sorted(g for g, v in gkey.items() if v == stratum)
        order = rng.permutation(len(groups))
        n = len(groups)
        a = round(n * fractions["train"])
        b = round(n * (fractions["train"] + fractions["calibration"]))
        for i, idx in enumerate(order):
            assign[groups[idx]] = "train" if i < a else ("calibration" if i < b else "test")
    return assign


def partition(rows, assign):
    out = {p: [] for p in PARTS}
    for r in rows:
        out[assign[r["packageGroup"]]].append(r)
    return out


def counts(rows):
    y = [label(r) for r in rows]
    return {"malicious": int(sum(y)), "benign": int(len(y) - sum(y))}


# ---------- 특징 ----------

def rule_vocab(train_rows, min_count=2):
    c = {}
    for r in train_rows:
        for rule in set(r["rules"] or []):
            c[rule] = c.get(rule, 0) + 1
    return sorted(k for k, v in c.items() if v >= min_count)


def feature_names(vocab, numeric=NUMERIC):
    return list(numeric) + [f"rule:{k}" for k in vocab]


def numeric_value(row, name):
    """빈 값은 채우지 않고 실패한다 — 0 으로 채우면 「값 없음」 자체가 단서가 된다."""
    key = name[len("log1p("):-1] if name.startswith("log1p(") else name
    v = row[key]
    if v is None:
        raise ValueError(f"{row['set']} 행 {row['id']} 의 {key} 가 비었다 — protocol 의 입력에서 빼야 한다")
    return math.log1p(v) if name.startswith("log1p(") else float(v)


def featurize(rows, vocab, numeric=NUMERIC):
    idx = {k: i for i, k in enumerate(vocab)}
    X = np.zeros((len(rows), len(numeric) + len(vocab)), dtype=np.float64)
    for i, r in enumerate(rows):
        X[i, :len(numeric)] = [numeric_value(r, n) for n in numeric]
        for rule in r["rules"] or []:
            j = idx.get(rule)
            if j is not None:
                X[i, len(numeric) + j] = 1.0
    return X


def labels(rows):
    return np.array([label(r) for r in rows], dtype=np.int64)


# ---------- 평가 ----------

def confusion(y, pred):
    y, pred = np.asarray(y, bool), np.asarray(pred, bool)
    return {"tp": int(np.sum(y & pred)), "fn": int(np.sum(y & ~pred)),
            "fp": int(np.sum(~y & pred)), "tn": int(np.sum(~y & ~pred))}


def metrics(y, pred):
    c = confusion(y, pred)
    tp, fn, fp, tn = c["tp"], c["fn"], c["fp"], c["tn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    r4 = lambda v: round(v, 4)
    return {"f1": r4(f1), "precision": r4(precision), "recall": r4(recall), "fpr": r4(fpr)}, c


def choose_threshold(y, p, max_fpr=MAX_FPR):
    """p >= t 를 양성으로, FPR <= max_fpr 인 t 중 F1 최대(동률: FPR 낮은 쪽 → 큰 t)."""
    best = None
    for t in sorted(set(p.tolist()) | {1.0 + 10 ** -PROB_DIGITS}):
        m, _ = metrics(y, p >= t)
        if m["fpr"] > max_fpr:
            continue
        key = (m["f1"], -m["fpr"], t)
        if best is None or key > best[0]:
            best = (key, t)
    return best[1]


def proba(model, X):
    return np.round(model.predict_proba(X)[:, 1], PROB_DIGITS)


def rule_pred(rows, cid):
    ok = ("malicious",) if cid == "rule-malicious" else ("malicious", "suspicious")
    return np.array([r["verdict"] in ok for r in rows])


def make_models(seed):
    return {
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(
            C=1.0, class_weight="balanced", solver="lbfgs", max_iter=5000)),
        "hgb": HistGradientBoostingClassifier(
            max_iter=200, learning_rate=0.05, max_leaf_nodes=15, min_samples_leaf=10, l2_regularization=1.0,
            early_stopping=False, class_weight="balanced", random_state=seed),
    }


def fit_and_select(train_rows, cal_rows, seed, numeric):
    """학습 · 보정 구간만으로 모델 · 임계값 · 선택을 정한다(시험 구간은 받지 않는다)."""
    vocab = rule_vocab(train_rows)
    Xtr, ytr = featurize(train_rows, vocab, numeric), labels(train_rows)
    Xcal, ycal = featurize(cal_rows, vocab, numeric), labels(cal_rows)
    models = make_models(seed)
    for m in models.values():
        m.fit(Xtr, ytr)
    thresholds, cal = {}, {}
    for cid, _ in CANDIDATES:
        if cid in models:
            p = proba(models[cid], Xcal)
            thresholds[cid] = choose_threshold(ycal, p)
            pred = p >= thresholds[cid]
        else:
            pred = rule_pred(cal_rows, cid)
        m, c = metrics(ycal, pred)
        cal[cid] = dict(m, confusion=c)
    eligible = [cid for cid, _ in CANDIDATES if cal[cid]["fpr"] <= MAX_FPR]
    preferred = max(eligible, key=lambda cid: (cal[cid]["f1"], -[c for c, _ in CANDIDATES].index(cid)))
    selection = {
        "rule": "보정 FPR<=5% 후보 중 보정 F1 최대(동률은 단순한 쪽) — 시험 구간 계산 전에 저장",
        "numeric": list(numeric),
        "vocab": vocab,
        "thresholds": thresholds,
        "calibration": cal,
        "preferredId": preferred,
    }
    return selection, models


def evaluate(cid, rows, models, selection):
    if cid in models:
        X = featurize(rows, selection["vocab"], selection["numeric"])
        return proba(models[cid], X) >= selection["thresholds"][cid]
    return rule_pred(rows, cid)


def top_features(models, vocab, numeric, k=10):
    coef = models["logreg"][-1].coef_[0]
    names = feature_names(vocab, numeric)
    order = sorted(range(len(names)), key=lambda i: (-round(abs(coef[i]), 6), names[i]))[:k]
    return [{"feature": names[i], "weight": round(float(coef[i]), 4)} for i in order]


def score_rows(rows, models, selection):
    """후보별 (지표, 혼동 행렬)"""
    y = labels(rows)
    return {cid: metrics(y, evaluate(cid, rows, models, selection)) for cid, _ in CANDIDATES}


def run(rows, protocol, on_selection=None, scope="pypi"):
    """→ (selection, report 본문). on_selection 은 시험 구간 계산 전에 불린다."""
    seed = protocol["split"]["seed"]
    main_rows, ref = scoped(rows, scope)
    assign = split_groups(main_rows, seed, protocol["split"]["fractions"])
    parts = partition(main_rows, assign)
    selection, models = fit_and_select(parts["train"], parts["calibration"], seed, protocol["features"]["numeric"])
    selection = dict(selection, scope=scope, seed=seed, partitions={p: counts(parts[p]) for p in PARTS})
    if on_selection:
        on_selection(selection)

    # ---- 여기부터 시험 구간(1회) ----
    test = score_rows(parts["test"], models, selection)
    candidates = []
    for cid, lab in CANDIDATES:
        m, c = test[cid]
        cal = selection["calibration"][cid]
        item = {"id": cid, "label": lab,
                "calibration": {k: cal[k] for k in ("f1", "fpr", "precision", "recall")},
                "test": m, "confusion": c}
        if cid in selection["thresholds"]:
            item["threshold"] = selection["thresholds"][cid]
        candidates.append(item)
    by_eco = {}
    for e in SCOPES[scope]:
        sub = [r for r in parts["test"] if r["ecosystem"] == e]
        by_eco[e] = {"test": counts(sub),
                     "candidates": {cid: {"test": m, "confusion": c}
                                    for cid, (m, c) in score_rows(sub, models, selection).items()}}
    ref_recall = {cid: m["recall"] for cid, (m, _) in score_rows(ref, models, selection).items()} if ref else {}
    report = {
        "scope": scope, "used": {e: counts([r for r in main_rows if r["ecosystem"] == e]) for e in SCOPES[scope]},
        "refRows": len(ref), "refRecall": ref_recall, "byEcosystem": by_eco,
        "parts": selection["partitions"], "groups": {p: len({r["packageGroup"] for r in parts[p]}) for p in PARTS},
        "features": feature_names(selection["vocab"], selection["numeric"]), "candidates": candidates,
        "topFeatures": top_features(models, selection["vocab"], selection["numeric"]),
    }
    return selection, report


def limits(report, protocol):
    t, scope = report["parts"]["test"], report["scope"]
    out = [
        f"표본이 작다 — 시험 구간은 악성 {t['malicious']}행 · 정상 {t['benign']}행(그룹 {report['groups']['test']}개)뿐이라 "
        "후보 간 F1 차이 몇 %p 는 우연 범위 안일 수 있다.",
        "악성 데이터셋(malicious-software-packages-dataset)과 입력을 만든 GuardDog 이 모두 DataDog 제작이다 — "
        "GuardDog 규칙이 이 표본에 맞춰져 있을 수 있어 규칙 · 모델 모두 낙관적이다.",
        ("정상 표본은 인기 PyPI 300개(wheel + 같은 패키지 sdist)뿐이다 — 덜 알려진 정상 패키지 · npm 정상에서의 오탐률은 재지 않았다."
         if scope == "pypi" else
         "정상 표본은 인기 패키지(PyPI wheel + sdist · npm)뿐이다 — 덜 알려진 정상 패키지에서의 오탐률은 재지 않았다."),
        "모델은 운영에 적용하지 않는다(deploymentApproved=false) — 서버 판정 · kill 은 그대로 scan/verdict.go 규칙이다.",
        "입력이 GuardDog 결과(점수 · 규칙 · 개수)라 GuardDog 이 못 보는 악성은 모델도 못 본다 — 모델은 GuardDog 신호의 재가중일 뿐이다.",
        "같은 정상 패키지의 wheel · sdist 는 같은 구간에 묶었다 — 정상 행 수는 패키지 수의 약 2배라 정상 쪽 표본이 서로 독립이 아니다.",
    ]
    if scope == "pypi":
        out.append(f"npm 은 정상 표본이 없어 학습에서 뺐다 — npmReference 는 PyPI 모델을 그대로 적용한 재현율(악성 {report['refRows']}행)이고, "
                   "npm 전용 규칙은 PyPI 학습 어휘에 없어 모델 입력에서 빠진다.")
    out += protocol["features"].get("limits", [])
    return out


def build(data_bytes, protocol_bytes, now=None, on_selection=None, scope="pypi"):
    rows = load_rows(data_bytes)
    protocol = json.loads(protocol_bytes)
    selection, rep = run(rows, protocol, on_selection, scope)
    used = {}
    for e, c in rep["used"].items():
        used[f"{e}Malicious"], used[f"{e}Benign"] = c["malicious"], c["benign"]
    if scope == "pypi":
        used["npmMalicious"] = rep["refRows"]
        npm_ref = {"note": "정상 표본 없음 — 재현율만", "rows": rep["refRows"], "recall": rep["refRecall"]}
    else:
        npm_ref = {"note": "all 범위 — npm 은 주 실험에 들어 있다. 아래는 시험 구간 npm 재현율(byEcosystem.npm 참고)",
                   "rows": rep["byEcosystem"]["npm"]["test"]["malicious"],
                   "recall": {cid: v["test"]["recall"] for cid, v in rep["byEcosystem"]["npm"]["candidates"].items()}}
    model = {
        "schema": 1,
        "generatedAt": (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": {"source": "bench/reports/static-items.jsonl", "sha256": sha256_bytes(data_bytes),
                    "rows": len(rows), "used": used, "excluded": "verdict == error 행(검사 실패)"},
        "protocol": {"seed": protocol["split"]["seed"],
                     "split": "packageGroup 그룹 분할 60/20/20 (" + ("PyPI" if scope == "pypi" else "PyPI + npm, 생태계 · 라벨 층화") + ")",
                     "selection": "보정 FPR≤5% 에서 F1 최대 · 시험은 선택에 쓰지 않음",
                     "sha256": sha256_bytes(protocol_bytes),
                     "selectionSha256": sha256_bytes(selection_bytes(selection)),
                     "scope": scope, "partitions": rep["parts"], "groups": rep["groups"]},
        "features": rep["features"],
        "candidates": rep["candidates"],
        "preferredId": selection["preferredId"],
        "deploymentApproved": False,
        "npmReference": npm_ref,
        "topFeatures": rep["topFeatures"],
        "limits": limits(rep, protocol),
    }
    if scope != "pypi":
        model["byEcosystem"] = rep["byEcosystem"]
    return model, selection


def selection_bytes(selection):
    return (json.dumps(selection, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write(path, b):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(b)
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scope", choices=sorted(SCOPES), default="pypi",
                    help="pypi(기본, 주 실험) · all(npm 정상 세트가 있을 때만 — 없으면 오류)")
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--protocol", default=PROTOCOL)
    ap.add_argument("--selection", default=None, help="기본 bench/ml/selection.json (all 은 selection-all.json)")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    sel_path = a.selection or (SELECTION if a.scope == "pypi" else SELECTION.replace(".json", f"-{a.scope}.json"))
    with open(a.data, "rb") as f:
        data = f.read()
    with open(a.protocol, "rb") as f:
        proto = f.read()
    try:
        model, _ = build(data, proto, on_selection=lambda s: write(sel_path, selection_bytes(s)), scope=a.scope)
    except ValueError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2
    write(a.out, (json.dumps(model, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    for c in model["candidates"]:
        print(f"{c['id']:16} cal F1 {c['calibration']['f1']:.4f} FPR {c['calibration']['fpr']:.4f} | "
              f"test F1 {c['test']['f1']:.4f} P {c['test']['precision']:.4f} R {c['test']['recall']:.4f} "
              f"FPR {c['test']['fpr']:.4f} {c['confusion']}")
    print("preferred", model["preferredId"], "→", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
