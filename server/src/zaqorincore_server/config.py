"""Application configuration.

Settings are loaded from environment variables (and optionally a .env
file) using pydantic-settings. All vars are prefixed with ZAQORIN_
to avoid collision with the agent's vars on the same host.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Server settings. Read once at process start."""

    model_config = SettingsConfigDict(
        env_prefix="ZAQORIN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- HTTP server ---
    server_host: str = "0.0.0.0"
    server_port: int = 8000

    # --- Logging ---
    log_level: Literal["debug", "info", "warn", "error"] = "info"

    # --- Database ---
    # Change zaqorin:*** before any non-dev deploy.
    database_url: str = (
        "postgresql+asyncpg://zaqorin:***@127.0.0.1:25432/zaqorin"
    )
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_echo: bool = False  # set true for SQL debug

    # --- Redis ---
    redis_url: str = "redis://127.0.0.1:6379/0"

    # --- Streams ---
    stream_name: str = "zaqorin:events"
    stream_maxlen: int = 10_000
    stream_group: str = "zaqorin-detectors"

    # --- Detectors ---
    # When False, the server skips starting the detector runner
    # task in its lifespan. Tests that don't want a background
    # event loop set this to False.
    detectors_enabled: bool = True
    # Per-detector tunables. Phase 5 may move these to DB-backed
    # `detector_configs` for live tuning; for now they're
    # static env vars.
    ssh_bruteforce_threshold: int = Field(default=5, ge=1, le=10_000)
    ssh_bruteforce_window_sec: int = Field(default=60, ge=1, le=86_400)
    ssh_bruteforce_cooldown_sec: int = Field(default=300, ge=1, le=86_400)

    # --- Limits / sanity ---
    # Reject a single WS frame larger than this. 64 KiB is generous for
    # one event and stops a misbehaving agent from eating memory.
    max_frame_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)

    # --- Test-only switches ---
    # When False, the server skips Redis (no streams, no consumer group).
    # Used by integration tests that don't want a Redis dependency.
    streams_enabled: bool = True

    # --- Dispatcher (Phase 4) ---
    # When False, the dispatcher is not started; actions stay pending.
    dispatcher_enabled: bool = True
    # Poll interval for the action queue. Cheap to be aggressive;
    # the table has an index on (status, created_at) so the
    # query stays O(pending) regardless of total actions.
    dispatcher_poll_sec: float = Field(default=5.0, ge=0.1, le=60.0)


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the singleton Settings. Created on first call."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
