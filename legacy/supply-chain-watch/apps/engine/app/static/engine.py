"""정적 분석 본체 (docs/03 §3.3). 파일별 룰 매칭 → (룰, 파일) 단위 집계 → 점수·등급."""
from __future__ import annotations

import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.static.preprocess import ParsedFile
from app.static.rules_loader import Rule

SNIPPET_MAX = 160


@dataclass
class Hit:
    rule: Rule
    file: ParsedFile
    snippet: str
    count: int = 1


def _snip(line: str) -> str:
    s = line.strip()
    return s if len(s) <= SNIPPET_MAX else s[: SNIPPET_MAX - 1] + "…"


def _applies(rule: Rule, f: ParsedFile) -> bool:
    if f.lang not in rule.languages:
        return False
    return rule.path_pattern is None or bool(rule.path_pattern.search(f.path))


def _line_hits(rule: Rule, lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        if not rule.pattern.search(line):  # type: ignore[union-attr]
            continue
        if rule.also_pattern and not rule.also_pattern.search(line):
            continue
        if rule.exclude_pattern and rule.exclude_pattern.search(line):
            continue
        out.append(line)
    return out


def _window_hits(rule: Rule, lines: list[str]) -> list[str]:
    """pattern 줄과 with_pattern 줄이 window 줄 이내에 함께 있으면 pattern 줄을 근거로 남긴다."""
    a_idx = [i for i, ln in enumerate(lines) if rule.pattern.search(ln)]  # type: ignore[union-attr]
    if not a_idx:
        return []
    b_idx = [i for i, ln in enumerate(lines) if rule.with_pattern.search(ln)]  # type: ignore[union-attr]
    out: list[str] = []
    for i in a_idx:
        if rule.exclude_pattern and rule.exclude_pattern.search(lines[i]):
            continue
        if any(abs(i - j) <= rule.window for j in b_idx):
            out.append(lines[i])
    return out


# ---- detectors: 정규식만으로 어려운 검사 ----

def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    """Damerau-Levenshtein(인접 전치 포함). cap 초과면 cap+1로 조기 종료."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


_PKG_JSON_DEP = re.compile(r'^\s*"(?P<name>@?[a-z0-9][\w.-]*(?:/[\w.-]+)?)"\s*:\s*"(?P<ver>[\^~><=*\d][^"]*|latest|npm:[^"]*)"\s*,?\s*$', re.I)
_REQ_DEP = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~]=|[<>]|;|$)")
_PYPROJECT_DEP = re.compile(r'^\s*"(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~]=|[<>])[^"]*"\s*,?\s*$')


def _dep_names(f: ParsedFile) -> list[tuple[str, str]]:
    name = f.path.rsplit("/", 1)[-1]
    rx = _PKG_JSON_DEP if name == "package.json" else _PYPROJECT_DEP if name == "pyproject.toml" else _REQ_DEP
    out = []
    for line in f.added:
        m = rx.match(line)
        if m and not line.lstrip().startswith("#"):
            out.append((m.group("name").lower(), line))
    return out


def _detect_typosquat(rule: Rule, f: ParsedFile) -> list[str]:
    """인기 패키지와 편집거리가 가까운 새 의존성. 같은 생태계 목록과만 비교하고 스코프 패키지는 제외."""
    eco = "popular_npm" if f.path.endswith("package.json") else "popular_pypi"
    popular = {p.lower() for p in rule.params.get(eco, [])}
    allow = {p.lower() for p in rule.params.get("allow", [])}
    out = []
    for dep, line in _dep_names(f):
        if dep.startswith("@") or dep in popular or dep in allow or len(dep) < 4:
            continue
        for p in popular:
            limit = 1 if len(p) < 8 else 2
            if _edit_distance(dep, p, cap=limit) <= limit:
                out.append(line)
                break
    return out


DETECTORS: dict[str, Callable[[Rule, ParsedFile], list[str]]] = {"typosquat": _detect_typosquat}


# ---- 실행 ----

@dataclass
class StaticOutcome:
    hits: list[Hit]
    score: int
    level: str
    latency_ms: int


def level_of(score: int) -> str:
    return "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"


def score_hits(hits: list[Hit]) -> int:
    """docs/03 §3.3: Σ 가중치 × 파일 배수 × (1 + log2(같은 룰 반복 수)), 상한 100."""
    total = sum(h.rule.weight * h.file.multiplier * (1 + math.log2(h.count)) for h in hits)
    return min(100, round(total))


def run_rules(rules: list[Rule], files: list[ParsedFile]) -> StaticOutcome:
    t0 = time.perf_counter()
    hits: list[Hit] = []
    for f in files:
        file_hits: dict[str, Hit] = {}
        for rule in rules:
            if rule.mode == "combo":
                matched = set(file_hits)
                if any(all(set(g) & matched for g in combo) for combo in rule.combos):
                    parts = [file_hits[g].snippet for combo in rule.combos for grp in combo for g in grp if g in file_hits]
                    file_hits[rule.id] = Hit(rule, f, _snip(" ⟷ ".join(dict.fromkeys(parts))[:SNIPPET_MAX]))
                continue
            if not _applies(rule, f):
                continue
            lines = f.removed if rule.target == "removed" else f.added
            if rule.mode == "line":
                found = _line_hits(rule, lines)
            elif rule.mode == "window":
                found = _window_hits(rule, lines)
            else:
                found = DETECTORS[rule.detector](rule, f)  # type: ignore[index]
            if found and rule.unless_added_pattern and any(rule.unless_added_pattern.search(ln) for ln in f.added):
                found = []
            if found:
                file_hits[rule.id] = Hit(rule, f, _snip(found[0]), count=len(found))
        hits.extend(file_hits.values())
    score = score_hits(hits)
    return StaticOutcome(hits=hits, score=score, level=level_of(score), latency_ms=round((time.perf_counter() - t0) * 1000))
