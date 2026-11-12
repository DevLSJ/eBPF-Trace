"""룰 YAML 로더 (docs/03 §3.1). rules/*.yaml을 읽어 검증·컴파일하고 파일 변경 시각 기준으로 캐시한다.

룰 매칭 방식(mode):
- line   : 추가(또는 삭제) 라인 1줄에 pattern이 맞고, also_pattern이 있으면 같은 줄에 그것도 맞아야 한다.
- window : pattern 줄과 with_pattern 줄이 window 줄 이내(같은 줄 포함)에 함께 있다.
- combo  : 같은 파일에서 combos의 한 조합이 성립(각 그룹에서 룰 1개 이상 매칭).
- detector: 정규식으로 표현하기 어려운 검사(예: 타이포스쿼팅 편집거리). 이름으로 코드에 연결.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

from app.models import Severity, Tag

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

Lang = Literal["JS", "PY", "SHELL", "DOCKER", "WORKFLOW", "MAKE", "CONFIG", "OTHER"]
ALL_LANGS: tuple[str, ...] = ("JS", "PY", "SHELL", "DOCKER", "WORKFLOW", "MAKE", "CONFIG", "OTHER")
SEVERITY_WEIGHT: dict[str, int] = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}
_TAGS = set(Tag.__args__)  # type: ignore[attr-defined]
_FLAGS = re.MULTILINE


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    languages: tuple[str, ...]
    description_ko: str
    mode: str = "line"
    target: str = "added"
    pattern: re.Pattern[str] | None = None
    also_pattern: re.Pattern[str] | None = None
    with_pattern: re.Pattern[str] | None = None
    window: int = 5
    exclude_pattern: re.Pattern[str] | None = None
    path_pattern: re.Pattern[str] | None = None
    exclude_path_pattern: re.Pattern[str] | None = None
    unless_added_pattern: re.Pattern[str] | None = None
    combos: tuple[tuple[tuple[str, ...], ...], ...] = ()
    detector: str | None = None
    params: dict = field(default_factory=dict, hash=False, compare=False)
    false_positive_hint: str | None = None
    source: str = ""

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]


def _compile(raw: dict, key: str, rid: str) -> re.Pattern[str] | None:
    pat = raw.get(key)
    if pat is None:
        return None
    try:
        return re.compile(pat, _FLAGS)
    except re.error as e:
        raise RuleError(f"{rid}.{key} 정규식 오류: {e}") from e


def _parse_rule(raw: dict, source: str) -> Rule:
    rid = raw.get("id")
    if not isinstance(rid, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]+", rid):
        raise RuleError(f"{source}: id는 대문자_언더스코어 형식이어야 합니다: {rid!r}")
    if raw.get("category") not in _TAGS:
        raise RuleError(f"{rid}: 알 수 없는 category {raw.get('category')!r}")
    if raw.get("severity") not in SEVERITY_WEIGHT:
        raise RuleError(f"{rid}: severity는 LOW|MEDIUM|HIGH|CRITICAL")
    langs = raw.get("languages", ["ANY"])
    langs = ALL_LANGS if langs == ["ANY"] else tuple(langs)
    if any(lang not in ALL_LANGS for lang in langs):
        raise RuleError(f"{rid}: languages 값 오류 {langs}")
    mode = raw.get("mode", "line")
    if mode not in ("line", "window", "combo", "detector"):
        raise RuleError(f"{rid}: mode 오류 {mode}")
    if not raw.get("description_ko"):
        raise RuleError(f"{rid}: description_ko 필수")
    if not (raw.get("exclude_pattern") or raw.get("false_positive_hint")):
        raise RuleError(f"{rid}: exclude_pattern 또는 false_positive_hint 중 하나는 필수 (static-analyzer skill)")

    rule = Rule(
        id=rid,
        category=raw["category"],
        severity=raw["severity"],
        languages=langs,
        description_ko=raw["description_ko"],
        mode=mode,
        target=raw.get("target", "added"),
        pattern=_compile(raw, "pattern", rid),
        also_pattern=_compile(raw, "also_pattern", rid),
        with_pattern=_compile(raw, "with_pattern", rid),
        window=int(raw.get("window", 5)),
        exclude_pattern=_compile(raw, "exclude_pattern", rid),
        path_pattern=_compile(raw, "path_pattern", rid),
        exclude_path_pattern=_compile(raw, "exclude_path_pattern", rid),
        unless_added_pattern=_compile(raw, "unless_added_pattern", rid),
        combos=tuple(tuple(tuple(g) for g in c["all"]) for c in raw.get("combos", [])),
        detector=raw.get("detector"),
        params=raw.get("params", {}) or {},
        false_positive_hint=raw.get("false_positive_hint"),
        source=source,
    )
    if mode in ("line", "window") and rule.pattern is None:
        raise RuleError(f"{rid}: {mode} 모드는 pattern 필수")
    if mode == "window" and rule.with_pattern is None:
        raise RuleError(f"{rid}: window 모드는 with_pattern 필수")
    if mode == "combo" and not rule.combos:
        raise RuleError(f"{rid}: combo 모드는 combos 필수")
    if mode == "detector" and not rule.detector:
        raise RuleError(f"{rid}: detector 모드는 detector 이름 필수")
    if rule.target not in ("added", "removed"):
        raise RuleError(f"{rid}: target은 added|removed")
    return rule


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(rules_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for raw in data:
            if raw.get("enabled", True) is False:
                continue
            rule = _parse_rule(raw, path.name)
            if rule.id in seen:
                raise RuleError(f"{rule.id}: 중복 id ({path.name})")
            seen.add(rule.id)
            rules.append(rule)
    known = {r.id for r in rules}
    for r in rules:
        for combo in r.combos:
            for group in combo:
                missing = set(group) - known
                if missing:
                    raise RuleError(f"{r.id}: combo가 없는 룰을 참조 {sorted(missing)}")
    # combo는 다른 룰 결과를 쓰므로 맨 뒤에서 평가
    rules.sort(key=lambda r: r.mode == "combo")
    return rules


_cache: tuple[float, list[Rule]] | None = None


def get_rules() -> list[Rule]:
    """rules/*.yaml 수정 시각이 바뀌면 다시 읽는다 (프로세스 재시작 없이 룰 반영)."""
    global _cache
    mtime = max((p.stat().st_mtime for p in RULES_DIR.glob("*.yaml")), default=0.0)
    if _cache is None or _cache[0] != mtime:
        _cache = (mtime, load_rules())
    return _cache[1]
