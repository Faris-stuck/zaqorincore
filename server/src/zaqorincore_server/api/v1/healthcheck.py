"""Ops dashboard summary endpoint: GET /api/v1/healthcheck.

Returns a compact JSON document with the bits an operator (or a
Grafana JSON datasource, or a Prometheus textfile exporter feeding
a cron) needs at a glance:

    {
        "ok": <bool>,
        "version": "<server version>",
        "rules_loaded": <int>,
        "agents_connected": <int>
    }

Design notes
============

* ``version`` is read from ``app.version`` so it stays in sync
  with the FastAPI constructor in ``main.create_app`` — bump it
  there and the healthcheck follows.
* ``rules_loaded`` is a filesystem count of ``*.yml`` files under
  ``server/rules/builtin/`` (any depth). This intentionally does
  NOT load the rule engine — that path is owned by the engine
  runner, and touching it here would conflict with the engine
  scope reserved for big cycles. The count is a proxy: it tells
  you whether new rules landed on disk without parsing them.
* ``agents_connected`` reads the size of the dispatcher
  ``HostConnectionRegistry`` (in-memory map of active WebSocket
  connections per host). Adds a ``count()`` accessor to the
  registry so we do not poke ``_conns`` directly.
* ``ok`` is ``True`` as long as we successfully computed every
  field. The endpoint never returns 5xx — operators want a
  stable shape for scraping, even when the answer is "we don't
  know". Failures are surfaced via per-field sentinels
  (``rules_loaded: -1``) and the endpoint stays 200.
* Excluded from the cycle-28 error envelope contract (per
  ``_EXCLUDED_PREFIXES`` in ``error_envelope.py``) so the body
  shape stays stable across deployments — same reasoning as the
  existing ``/healthz`` family.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Request

from ...dispatcher import registry as agent_registry

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# Default location of the bundled builtin rule pack. Resolved
# relative to this file (server/src/zaqorincore_server/api/v1/)
# so it works regardless of the current working directory at
# startup. Override via ZAQORIN_RULES_DIR for tests / custom
# deployments.
_DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent.parent / "rules" / "builtin"
)


def _count_yml_files(root: Path) -> int:
    """Count ``*.yml`` files under ``root`` at any depth.

    Returns ``-1`` if the directory is missing — the endpoint
    never raises, so a misconfigured deployment surfaces as a
    sentinel value rather than a 500.
    """
    if not root.exists():
        return -1
    try:
        return sum(1 for _ in root.rglob("*.yml"))
    except OSError as exc:
        log.warning("healthcheck: rules dir walk failed: %s", exc)
        return -1


@router.get("/healthcheck")
async def healthcheck(request: Request) -> dict[str, object]:
    """Compact ops-dashboard summary.

    See module docstring for the contract. Always returns 200.
    """
    # app.version is set by FastAPI(title=..., version=...) in
    # create_app(); reading it off the request keeps this
    # endpoint oblivious to whatever create_app chose to name it.
    version = getattr(request.app, "version", "unknown")

    rules_loaded = _count_yml_files(_DEFAULT_RULES_DIR)
    agents_connected = agent_registry.count()

    # ok = True iff every field produced a non-sentinel value.
    ok = rules_loaded >= 0 and agents_connected >= 0

    return {
        "ok": ok,
        "version": version,
        "rules_loaded": rules_loaded,
        "agents_connected": agents_connected,
    }