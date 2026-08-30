"""Public API routers, v1 namespace.

Each sub-module is a FastAPI APIRouter. The package is also re-
exported so main.py can `from .api import v1` and mount them all.
"""

from . import (
    agents,
    alerts,
    audit,
    auth,
    canary,
    evidence,
    events,
    healthcheck,
    hosts,
    hunt,
    ingest_cloudflare,
    ingest_webhook,
    security,
    stream,
)

__all__ = [
    "stream",
    "hosts",
    "events",
    "alerts",
    "hunt",
    "canary",
    "evidence",
    "ingest_cloudflare",
    "ingest_webhook",
    "auth",
    "audit",
    "healthcheck",
    "agents",
    "security",
]
