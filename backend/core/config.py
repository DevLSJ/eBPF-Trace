from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)
    database_url: str = "sqlite+aiosqlite:///./ebpf.db"
    postgres_host: str = ""
    postgres_user: str = "ebpf"
    postgres_password: SecretStr = SecretStr("")
    postgres_db: str = "ebpf_ids"
    redis_url: str = "redis://127.0.0.1:6379/0"
    model_path: str = "ml/models/isolation_forest.pkl"
    scaler_path: str = "ml/models/scaler.pkl"
    collector_token: SecretStr = SecretStr("")
    admin_token: SecretStr = SecretStr("")
    slack_webhook_url: SecretStr = SecretStr("")
    metrics_collect_interval_sec: float = Field(default=10, ge=1)
    metrics_enabled: bool = True
    auto_create_schema: bool = False
    log_level: str = "INFO"
    allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    event_cooldown_sec: float = Field(default=10, ge=0)

    @model_validator(mode="after")
    def postgres_url(self):
        if self.postgres_host:
            self.database_url = URL.create(
                "postgresql+asyncpg",
                username=self.postgres_user,
                password=self.postgres_password.get_secret_value(),
                host=self.postgres_host,
                port=5432,
                database=self.postgres_db,
            ).render_as_string(hide_password=False)
        return self
