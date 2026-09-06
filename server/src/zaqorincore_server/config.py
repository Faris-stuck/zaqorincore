"""Application configuration loaded from ZAQORIN_* environment variables."""

from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ZAQORIN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    server_host: str = "0.0.0.0"
    server_port: int = 8000
    log_level: Literal["debug", "info", "warn", "error"] = "info"
    database_url: str = "postgresql+asyncpg://zaqorin:***@127.0.0.1:25432/zaqorin"
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_echo: bool = False
    redis_url: str = "redis://127.0.0.1:6379/0"
    stream_name: str = "zaqorin:events"
    stream_maxlen: int = 10_000
    stream_group: str = "zaqorin-detectors"
    detectors_enabled: bool = True
    ssh_bruteforce_threshold: int = Field(default=5, ge=1, le=10_000)
    ssh_bruteforce_window_sec: int = Field(default=60, ge=1, le=86_400)
    ssh_bruteforce_cooldown_sec: int = Field(default=300, ge=1, le=86_400)
    max_frame_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)
    streams_enabled: bool = True
    dispatcher_enabled: bool = True
    dispatcher_poll_sec: float = Field(default=5.0, ge=0.1, le=60.0)
    deployment_mode: str = "startup"
    rules_dir: str = "rules/builtin"
    soar_enabled: bool = True
    soar_config: str = "config/soar.toml"

    # Authentication is fail-closed by default. Set
    # ZAQORIN_ALLOW_UNAUTHENTICATED=true only for explicitly isolated
    # local development/test deployments.
    api_key: str = ""
    api_key_read: str = ""
    api_key_write: str = ""
    api_key_ingest: str = ""
    allow_unauthenticated: bool = False

    rate_limit_enabled: bool = True
    rate_limit_per_min: int = Field(default=120, ge=1, le=1_000_000)
    cors_origins: str = ""
    ws_max_msg_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    ws_max_msg_per_min: int = Field(default=100, ge=1, le=10_000)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
