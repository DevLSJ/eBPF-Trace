#!/usr/bin/env python3
"""평가 규칙 v2 지표 — 복합 판정(층 OR) · 탐지율 · 오탐률 · 윌슨 구간 · 보정 구간 운영점 선택 · 절제.

규칙은 bench/v2/protocol.json(target · layers · selection · metrics). 표준 라이브러리만 쓴다.
층의 판정 값이 None(그 층이 그 표본을 처리하지 못함)이면 「못 잡음」으로 세고, 분모에서 빼지 않는다.
"""
import itertools
import math

TARGET_DETECTION = 0.98
MAX_FPR = 0.02
Z95 = 1.959964
FPR_BUDGETS = (0.0, 0.0025, 0.005, 0.01, 0.015, 0.02)
LAYER_ORDER = ("static", "llm", "dynamic", "ml")
SCORE_DIGITS = 6
DIGITS = 4


def analyzable(row):
    """분석할 코드가 있는 표본(주 지표의 악성 분모)."""
    return row["codeLines"] >= 1


def main_rows(rows):
    """주 지표에 드는 줄: 정상 전부 + 분석할 코드가 있는 악성. 코드 없는 악성은 따로 보고한다."""
    return [r for r in rows if r["label"] == "benign" or analyzable(r)]


def labels(rows):
    return [1 if r["label"] == "malicious" else 0 for r in rows]


def wilson(k, n, z=Z95):
    """비율 k/n 의 윌슨 구간 (아래, 위). n = 0 이면 (0, 1)."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, mid - half), min(1.0, mid + half))


def any_layer(flag_lists):
    """층별 판정 목록 → 표본마다 하나라도 양성이면 양성. None 은 음성."""
    return [any(bool(v) for v in col) for col in zip(*flag_lists)]


def confusion(y, pred):
    tp = sum(1 for a, b in zip(y, pred) if a == 1 and b)
    fn = sum(1 for a, b in zip(y, pred) if a == 1 and not b)
    fp = sum(1 for a, b in zip(y, pred) if a == 0 and b)
    tn = sum(1 for a, b in zip(y, pred) if a == 0 and not b)
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn}


def rates(c):
    """반올림하지 않은 비율. 분모가 0 이면 그 비율은 0."""
    pos, neg, flagged = c["tp"] + c["fn"], c["fp"] + c["tn"], c["tp"] + c["fp"]
    detection = c["tp"] / pos if pos else 0.0
    fpr = c["fp"] / neg if neg else 0.0
    precision = c["tp"] / flagged if flagged else 0.0
    f1 = 2 * precision * detection / (precision + detection) if precision + detection else 0.0
    return {"detection": detection, "fpr": fpr, "precision": precision, "f1": f1}


def goal_met(detection, fpr):
    """달성 판정은 반올림 전 값으로."""
    return detection >= TARGET_DETECTION and fpr <= MAX_FPR


def summary(y, pred):
    """보고용 한 묶음: 혼동 행렬 · 비율(소수 4자리) · 95% 구간 · 달성 여부."""
    c = confusion(y, pred)
    r = rates(c)
    pos, neg = c["tp"] + c["fn"], c["fp"] + c["tn"]
    return {
        **c,
        **{k: round(v, DIGITS) for k, v in r.items()},
        "detectionCi95": [round(x, DIGITS) for x in wilson(c["tp"], pos)],
        "fprCi95": [round(x, DIGITS) for x in wilson(c["fp"], neg)],
        "met": goal_met(r["detection"], r["fpr"]),
    }


def score_flags(scores, threshold):
    """점수 >= 임계값이면 양성. 점수가 None 이면 음성."""
    return [s is not None and round(s, SCORE_DIGITS) >= threshold for s in scores]


def budget_points(scores, y, budgets=FPR_BUDGETS):
    """점수형 층의 후보 임계값 [(후보 이름, 임계값)]. 예산마다, 그 층만 켰을 때 보정 구간 정상 오탐률이 예산 이하가 되는
    가장 낮은 임계값. 같은 임계값은 한 번만(먼저 나온 예산의 이름으로)."""
    benign = sorted(round(s, SCORE_DIGITS) for s, a in zip(scores, y) if a == 0 and s is not None)
    n_benign = sum(1 for a in y if a == 0)
    cands = sorted({round(s, SCORE_DIGITS) for s in scores if s is not None})
    out, used = [], set()
    for b in budgets:
        chosen = None
        for t in cands:  # 낮은 임계값부터 — 처음 예산 안에 드는 것이 가장 낮은 것
            fp = sum(1 for s in benign if s >= t)
            if (fp / n_benign if n_benign else 0.0) <= b:
                chosen = t
                break
        if chosen is not None and chosen not in used:
            used.add(chosen)
            out.append((f"fpr<={b}", chosen))
    return out


def select(y, layers, max_fpr=MAX_FPR):
    """보정 구간 운영점 선택.
    layers = [(층 이름, [(후보 이름, 판정 목록), ...]), ...] — 순서가 우선순위. 층마다 「끔」 또는 후보 하나.
    복합 오탐률 <= max_fpr 인 조합 가운데 복합 탐지율 최대 → 오탐률 낮은 쪽 → 켠 층이 적은 쪽 → 순서가 앞인 쪽."""
    best = None
    for combo in itertools.product(*[range(len(points) + 1) for _, points in layers]):
        active = [(layers[i][0], layers[i][1][j - 1]) for i, j in enumerate(combo) if j > 0]
        if not active:
            continue
        c = confusion(y, any_layer([flags for _, (_, flags) in active]))
        r = rates(c)
        if r["fpr"] > max_fpr:
            continue
        # 순서가 앞인 쪽: 앞 층을 켠 조합이 먼저, 같은 층이면 앞 후보가 먼저(끔은 그 층의 맨 뒤로 친다)
        rank = tuple(j if j > 0 else len(layers[i][1]) + 1 for i, j in enumerate(combo))
        key = (-r["detection"], r["fpr"], len(active), rank)
        if best is None or key < best[0]:
            best = (key, active, c, r)
    if best is None:
        raise ValueError(f"보정 구간 복합 오탐률 <= {max_fpr} 인 조합이 없다")
    _, active, c, r = best
    return {
        "points": {layer: point for layer, (point, _) in active},
        "calibration": {**c, **{k: round(v, DIGITS) for k, v in r.items()}},
    }


def ablation(y, layer_flags, order=LAYER_ORDER):
    """층 하나씩, 그리고 order 순서로 더해 가며. layer_flags = {층 이름: 판정 목록} — 고른 운영점의 판정만 넣는다."""
    present = [name for name in order if name in layer_flags]
    alone = {name: summary(y, any_layer([layer_flags[name]])) for name in present}
    cumulative, stack = [], []
    for name in present:
        stack.append(layer_flags[name])
        cumulative.append({"through": name, **summary(y, any_layer(stack))})
    return {"alone": alone, "cumulative": cumulative}


def by_year(rows, pred):
    """악성 발견 연도별 탐지율(보조 지표). rows · pred 는 같은 순서."""
    buckets = {}
    for r, p in zip(rows, pred):
        if r["label"] != "malicious":
            continue
        year = (r.get("date") or "")[:4] or "unknown"
        hit, n = buckets.get(year, (0, 0))
        buckets[year] = (hit + (1 if p else 0), n + 1)
    return {year: {"detected": hit, "rows": n, "detection": round(hit / n, DIGITS)} for year, (hit, n) in sorted(buckets.items())}
