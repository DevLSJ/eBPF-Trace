"""비용 가드 (docs/03 §4, docs/04 Redis): 시간당 호출 상한(전역·레포별) + 같은 diff 결과 24시간 재사용."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import redis.asyncio as aioredis

from app.config import settings

_r: aioredis.Redis | None = None


def _redis() -> aioredis.Redis:
    global _r
    if _r is None:
        _r = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _r


def _hour() -> str:
    return datetime.now(UTC).strftime("%Y%m%d%H")


async def try_acquire(repo: str) -> bool:
    """호출 1회분 예산을 잡는다. 넘치면 되돌리고 False."""
    r = _redis()
    h = _hour()
    gk, rk = f"llm:budget:global:{h}", f"llm:budget:repo:{repo}:{h}"
    pipe = r.pipeline()
    pipe.incr(gk)
    pipe.expire(gk, 7200)
    pipe.incr(rk)
    pipe.expire(rk, 7200)
    g, _, n, _ = await pipe.execute()
    if g > settings.llm_max_per_hour or n > settings.llm_max_per_repo_hour:
        await r.decr(gk)
        await r.decr(rk)
        return False
    return True


async def cache_get(key: str) -> dict | None:
    raw = await _redis().get(f"llm:cache:{key}")
    return json.loads(raw) if raw else None


async def cache_set(key: str, value: dict) -> None:
    await _redis().set(f"llm:cache:{key}", json.dumps(value, ensure_ascii=False), ex=settings.llm_cache_ttl_s)


async def flag_get(name: str) -> bool:
    return bool(await _redis().get(f"llm:flag:{name}"))


async def flag_set(name: str, ttl_s: int) -> None:
    await _redis().set(f"llm:flag:{name}", "1", ex=ttl_s)
