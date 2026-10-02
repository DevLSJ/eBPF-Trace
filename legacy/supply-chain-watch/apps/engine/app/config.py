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


settings = Settings()
