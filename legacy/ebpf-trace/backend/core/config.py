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
    slack_enabled: bool = False
    metrics_collect_interval_sec: float = Field(default=10, ge=1)
    metrics_enabled: bool = True
    auto_create_schema: bool = False
    log_level: str = "INFO"
    allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    event_cooldown_sec: float = Field(default=10, ge=0)
    public_base_url: str = "http://127.0.0.1:5173"
    ops_worker_enabled: bool = True
    ops_notifications_enabled: bool = False
    ops_session_hours: int = Field(default=8, ge=1, le=24)
    ops_allow_insecure_local: bool = False
    ops_test_account_mode: bool = False
    incident_window_seconds: int = Field(default=600, ge=30, le=3600)
    ops_retention_days: int = Field(default=30, ge=1, le=365)
    slack_bot_token: SecretStr = SecretStr("")
    slack_signing_secret: SecretStr = SecretStr("")
    slack_team_id: str = ""
    slack_channel: str = ""
    slack_escalation_channel: str = ""
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from: str = ""
    notification_email: str = ""
    shadow_manifest_path: str = ""
    shadow_sample_modulus: int = Field(default=100, ge=1, le=10000)
    response_live_enabled: bool = False
    response_max_ttl_seconds: int = Field(default=300, ge=30, le=900)
    response_freshness_seconds: int = Field(default=30, ge=5, le=120)
    recovery_observation_seconds: int = Field(default=60, ge=10, le=3600)

    @model_validator(mode="after")
    def postgres_url(self):
        if self.ops_test_account_mode and (
            self.response_live_enabled or self.ops_notifications_enabled or self.slack_enabled
        ):
            raise ValueError(
                "Test accounts require live responses and external notifications disabled"
            )
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
