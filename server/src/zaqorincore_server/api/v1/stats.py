"""Ops-dashboard aggregate endpoint: GET /api/v1/stats.

Returns a compact JSON document with the longer-form ops view,
building on the cycle-30 ``/api/v1/healthcheck`` payload:

    {
        "version": "<app.version>",
        "git_sha": "<short sha or 'unknown'>",
        "rules_loaded": <int>,
        "agents_connected": <int>,
        "uptime_seconds": <int>,
        "pid": <int>
    }

Design notes
============

* ``rules_loaded`` is a filesystem count of ``*.yml`` files under
  ``server/rules/builtin/`` (any depth). Reuses the cycle-30
  helper to keep the read path identical to ``/healthcheck``.
* ``agents_connected`` reads the size of the dispatcher
  ``HostConnectionRegistry`` (same accessor the healthcheck
  uses). Adding a third reader here proves the accessor is
  stable under repeated reads.
* ``git_sha`` is read from the cycle-47 build-info JSON file
  so this endpoint does not shell out to ``git``. When the file
  is missing (local dev, clean checkout, minimal containers)
  we surface ``"unknown"`` — same contract as ``/api/v1/version``.
* ``uptime_seconds`` is measured from process start
  (``STARTED_AT`` is captured at module import). Capping the
  value at a non-negative int (``max(0, ...)``) keeps the
  field stable in tests that patch ``time.monotonic``.
* ``pid`` is ``os.getpid()``. Useful for correlating log lines
  against ``journalctl -t zaqorin-server`` entries that
  mention the PID.
* The endpoint never returns 5xx. Per-field sentinels
  (``rules_loaded: -1``) keep the shape stable across
  deployments — same contract as ``/healthcheck``.
* Excluded from the cycle-28 error envelope contract (per
  ``_EXCLUDED_PREFIXES`` in ``error_envelope.py``) so the body
  shape stays stable across deployments — same reasoning as
  ``/healthcheck`` and ``/api/v1/version``.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, Request

from ...auth import Role, require_role
from ...dispatcher import registry as agent_registry
from .healthcheck import _count_yml_files

log = logging.getLogger(__name__)

# F-006 fix (v3.2.2): gate the operator dashboard counters behind
# ``require_role(READ)`` so an unauthenticated probe gets 401 instead
# of the running version, git SHA, pid, and connected-agent count.
# The WebUI still reaches the endpoint via its own auth context.
router = APIRouter(
    prefix="/api/v1",
    dependencies=[Depends(require_role(Role.READ))],
)

# Default location of the bundled builtin rule pack. Mirrors the
# cycle-30 healthcheck resolution so the two endpoints agree on
# which directory they read. Override via ZAQORIN_RULES_DIR for
# tests / custom deployments.
_DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent.parent / "rules" / "builtin"
)

# Module-level start time captured at import. ``time.monotonic``
# is the right clock here — wall clocks can step backwards under
# NTP correction; monotonic cannot. We only ever expose the
# delta against this anchor so the clock-source choice stays
# invisible to callers.
STARTED_AT: float = time.monotonic()

# Default location of the build-info file. Same resolution as
# ``version.py`` so /stats and /version read the same path.
_DEFAULT_BUILD_INFO = (
    Path(__file__).resolve().parent.parent.parent.parent.parent / "build_info.json"
)


def _read_git_sha(path: Path) -> str:
    """Return the short ``git_sha`` from a build_info.json file.

    Returns ``"unknown"`` when the file is missing or malformed.
    Mirrors the cycle-47 ``version`` endpoint contract so the
    two endpoints never disagree on the value of ``git_sha``.
    """
    if not path.exists():
        return "unknown"
    try:
        import json

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        log.warning("stats: build_info.json read failed: %s", exc)
        return "unknown"
    short = data.get("git_sha") if isinstance(data, dict) else None
    if not isinstance(short, str) or not short:
        return "unknown"
    return short


@router.get("/stats")
async def stats(request: Request) -> dict[str, object]:
    """Aggregate ops-dashboard stats.

    Body shape::

        {
            "version":          "<app.version>",
            "git_sha":          "<short sha or 'unknown'>",
            "rules_loaded":     <int>,
            "agents_connected": <int>,
            "uptime_seconds":   <int>,
            "pid":              <int>
        }

    Always returns 200. See module docstring for the contract.
    """
    app_version = getattr(request.app, "version", "unknown")

    rules_loaded = _count_yml_files(_DEFAULT_RULES_DIR)
    agents_connected = agent_registry.count()

    # Floor at 0 so a test that back-dates ``STARTED_AT`` (or a
    # monotonic clock regression on resume from suspend) still
    # gets a sane integer instead of a negative value.
    uptime_seconds = max(0, int(time.monotonic() - STARTED_AT))

    return {
        "version": app_version,
        "git_sha": _read_git_sha(_DEFAULT_BUILD_INFO),
        "rules_loaded": rules_loaded,
        "agents_connected": agents_connected,
        "uptime_seconds": uptime_seconds,
        "pid": os.getpid(),
    }


__all__ = ["router", "STARTED_AT"]