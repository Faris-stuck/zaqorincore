"""Structured logging setup.

We use structlog so every log line is a single JSON document that
includes enough context to grep / aggregate. The format is:
    {"ts": "...", "level": "...", "logger": "...", "event": "...", ...}
"""

from __future__ import annotations

import logging
import sys

import structlog

from .config import get_settings


def configure_logging() -> None:
    """Wire structlog on top of stdlib logging. Idempotent."""
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # stdlib root: send to stderr at the chosen level
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=level,
        force=True,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # JSON for production. Swap for ConsoleRenderer if you want
            # pretty colors locally.
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Convenience wrapper around structlog.get_logger()."""
    return structlog.get_logger(name)
