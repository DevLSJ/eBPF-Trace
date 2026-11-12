"""프롬프트 템플릿 (docs/03 §5.6). 단일 소스는 DB prompt_templates, 이름별 활성 버전을 60초 캐시한다."""
from __future__ import annotations

import time
from dataclasses import dataclass

import psycopg

from app.config import settings

CACHE_SECONDS = 60


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    version: int
    system_prompt: str
    user_template: str


_cache: dict[str, tuple[float, PromptTemplate]] = {}


def get_template(name: str) -> PromptTemplate:
    hit = _cache.get(name)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    with psycopg.connect(settings.database_url, connect_timeout=5) as conn:
        row = conn.execute(
            "SELECT name, version, system_prompt, user_template FROM prompt_templates WHERE name = %s AND is_active",
            (name,),
        ).fetchone()
    if row is None:
        if name != "default":
            return get_template("default")
        raise LookupError("활성 프롬프트(default)가 없습니다 — infra/sql/0003_prompts_v1.sql 적용 필요")
    tpl = PromptTemplate(*row)
    _cache[name] = (time.monotonic(), tpl)
    return tpl


def reload() -> dict[str, int]:
    _cache.clear()
    return {n: get_template(n).version for n in ("default", "ci")}


class _Safe(dict):
    def __missing__(self, key: str) -> str:  # 템플릿에 없는 값은 빈칸
        return ""


def render(tpl: PromptTemplate, values: dict) -> str:
    return tpl.user_template.format_map(_Safe(values))
