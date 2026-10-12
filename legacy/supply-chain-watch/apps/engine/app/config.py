"""엔진 설정. 루트 .env 공유 (docs/10 §4, docs/03 §5.1)."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_ROOT_ENV = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ROOT_ENV, extra="ignore")

    engine_port: int = 8000
    anthropic_api_key: str | None = None
    anthropic_base_url: str = "https://ai.cs.kookmin.ac.kr"
    llm_model: str = "claude-opus-5"
    llm_model_cheap: str = "claude-haiku-4-5"
    llm_effort: str = "medium"
    llm_threshold: int = 20  # docs/03 §4 게이트 기본값
    llm_max_per_hour: int = 200  # 전역 시간당 LLM 호출 상한 (docs/03 §4)
    llm_max_per_repo_hour: int = 30  # 레포별 시간당 상한
    llm_timeout_s: float = 30.0
    llm_two_stage: bool = True  # 1차 저렴한 모델로 거르고 위험한 것만 정밀 모델 (2026-10-12 사용자 결정)
    llm_triage_threshold: int = 40  # 1차 점수가 이 이상이면 2차 정밀 분석
    llm_cache_ttl_s: int = 86400  # 같은 diff 결과 재사용 (docs/04 llm:cache)
    database_url: str = "postgresql://capstone:capstone@localhost:5433/capstone"
    redis_url: str = "redis://localhost:6380/0"


settings = Settings()
