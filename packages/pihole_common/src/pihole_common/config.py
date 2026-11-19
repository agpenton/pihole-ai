"""Shared configuration for all pihole-ai applications."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """PostgreSQL connection configuration."""

    host: str = "localhost"
    port: int = 5432
    database: str = "pihole_ai"
    user: str = "pihole_ai"
    password: str = ""
    pool_size: int = 5
    max_overflow: int = 5
    pool_timeout: int = 30
    pool_recycle: int = 1800
    echo: bool = False

    @property
    def url(self) -> str:
        """Build the async database URL."""
        from sqlalchemy.engine import URL

        return URL.create(
            "postgresql+asyncpg",
            username=self.user,
            password=self.password or None,
            host=self.host,
            port=self.port,
            database=self.database,
        ).render_as_string(hide_password=False)

    @property
    def sync_url(self) -> str:
        """Build the synchronous database URL for Alembic."""
        from sqlalchemy.engine import URL

        return URL.create(
            "postgresql+psycopg",
            username=self.user,
            password=self.password or None,
            host=self.host,
            port=self.port,
            database=self.database,
        ).render_as_string(hide_password=False)

    model_config = SettingsConfigDict(
        env_prefix="DB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class PiholeSettings(BaseSettings):
    """Pi-hole v6 API configuration.

    Prefer PIHOLE_HOST, PIHOLE_PORT and PIHOLE_SCHEME. PIHOLE_URL can
    override the host/port when a reverse proxy or non-standard path is used.
    """

    host: str = "192.168.178.110"
    port: int = 80
    scheme: Literal["http", "https"] = "http"
    url: str | None = None

    # Pi-hole v6 uses a session created from the web/app password.
    password: str | None = None

    # Kept temporarily so old deployments fail visibly rather than silently
    # breaking their environment. Pi-hole v6 does not use the old static token.
    api_token: str | None = None

    timeout: float = 10.0
    poll_interval: float = 60.0
    call_sign: str = "pihole-ai"
    query_limit: int = 10000
    initial_lookback_hours: int = 24

    @property
    def api_base_url(self) -> str:
        """Return the normalized Pi-hole v6 API root."""
        raw = self.url or f"{self.scheme}://{self.host}:{self.port}"
        parsed = urlsplit(raw.rstrip("/"))

        path = parsed.path.rstrip("/")
        path = path.removesuffix("/admin/api.php")
        if path.endswith("/api"):
            api_path = path
        else:
            api_path = f"{path}/api" if path else "/api"

        return urlunsplit((parsed.scheme, parsed.netloc, api_path, "", ""))

    @property
    def effective_password(self) -> str | None:
        """Return the v6 application password."""
        return self.password

    model_config = SettingsConfigDict(
        env_prefix="PIHOLE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class LlmSettings(BaseSettings):
    """LLM / OpenRouter configuration."""

    api_key: str = ""
    base_url: str = "https://openrouter.ai/api/v1"
    model: str = "openrouter/free"
    daily_quota: int = 40
    timeout: float = 45.0
    max_retries: int = 1
    retry_backoff: float = 1.0
    max_output_tokens: int = 700
    cache_ttl_hours: int = 24
    max_concurrent_requests: int = 1
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 60

    model_config = SettingsConfigDict(
        env_prefix="LLM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class AnalyzerSettings(BaseSettings):
    """Security analyzer configuration."""

    suspicious_tld_weights: dict[str, float] = Field(
        default_factory=lambda: {
            ".xyz": 2.0,
            ".top": 2.0,
            ".tk": 3.0,
            ".ml": 3.0,
            ".ga": 3.0,
            ".cf": 3.0,
            ".gq": 3.0,
            ".ru": 1.5,
            ".cn": 1.5,
        }
    )
    min_suspicion_score: float = 0.5
    llm_retry_interval_minutes: int = 60
    blocklist_patterns: list[str] = Field(
        default_factory=lambda: [
            r"^[\w-]{1,15}\.(xyz|top|tk|ml|ga|cf|gq)$",
            r"^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}$",
        ]
    )

    model_config = SettingsConfigDict(
        env_prefix="ANALYZER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class TelemetrySettings(BaseSettings):
    """Observability configuration."""

    service_name: str = "pihole-ai"
    metrics_enabled: bool = True
    metrics_port: int = 9090
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    model_config = SettingsConfigDict(
        env_prefix="TELEMETRY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class Settings(BaseSettings):
    """Top-level application settings."""

    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    pihole: PiholeSettings = Field(default_factory=PiholeSettings)
    llm: LlmSettings = Field(default_factory=LlmSettings)
    analyzer: AnalyzerSettings = Field(default_factory=AnalyzerSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings."""
    return Settings()
