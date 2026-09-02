"""Public API routers, v1 namespace.

Each sub-module is a FastAPI APIRouter. The package is also re-
exported so main.py can `from .api import v1` and mount them all.
"""

from . import (
    agents,
    agents_provision,
    alerts,
    audit,
    audit_bots,
    auth,
    canary,
    evidence,
    events,
    healthcheck,
    hosts,
    hunt,
    ingest_cloudflare,
    ingest_webhook,
    rules_studio,
    security,
    sources,
    stats,
    stream,
    version,
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
    "audit_bots",
    "healthcheck",
    "agents",
    "agents_provision",
    "rules_studio",
    "sources",
    "security",
    "stats",
    "version",
]
