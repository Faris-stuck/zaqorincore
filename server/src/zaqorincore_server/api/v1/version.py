"""Version endpoint: GET /api/v1/version.

Returns the build identity for the running server:

    {
        "version": "<app.version>",
        "git_sha": "<short commit hash or 'unknown'>",
        "git_sha_full": "<full commit hash or 'unknown'>"
    }

Design notes
============

* ``version`` is read from ``app.version`` so it stays in sync
  with the FastAPI constructor in ``main.create_app`` — bump it
  there and this endpoint follows. Same source of truth as
  ``/api/v1/healthcheck``.
* ``git_sha`` is read from a static file written at build time
  (``server/build_info.json``) so we do not shell out to ``git``
  from the request path. When the file is missing — local dev,
  minimal containers, a clean checkout — we surface
  ``"unknown"`` rather than raising. This matches the cycle-30
  healthcheck contract: never 5xx, always a stable shape.
* The build-info file is gitignored by convention so it never
  lands in the repo. Production deployments write it from CI
  with ``git rev-parse --short=7 HEAD`` + ``--verify``.
* Excluded from the cycle-28 error envelope contract (per
  ``_EXCLUDED_PREFIXES`` in ``error_envelope.py``) so the body
  shape stays stable across deployments — same reasoning as the
  existing ``/healthz`` family and ``/api/v1/healthcheck``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# Default location of the build-info file. Resolved relative to
# this file (server/src/zaqorincore_server/api/v1/) so it works
# regardless of the current working directory at startup. The
# file is optional — see module docstring.
_DEFAULT_BUILD_INFO = (
    Path(__file__).resolve().parent.parent.parent.parent.parent / "build_info.json"
)


def _read_build_info(path: Path) -> tuple[str, str]:
    """Return ``(short_sha, full_sha)`` from a build_info.json file.

    Returns ``("unknown", "unknown")`` when the file is missing or
    malformed. The endpoint never raises, so a missing or stale
    build artifact surfaces as a sentinel value rather than a 500.
    """
    if not path.exists():
        return "unknown", "unknown"
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("version: build_info.json read failed: %s", exc)
        return "unknown", "unknown"

    short = data.get("git_sha") if isinstance(data, dict) else None
    full = data.get("git_sha_full") if isinstance(data, dict) else None

    if not isinstance(short, str) or not short:
        short = "unknown"
    if not isinstance(full, str) or not full:
        full = "unknown"

    return short, full


@router.get("/version")
async def version(request: Request) -> dict[str, str]:
    """Build identity for the running server.

    See module docstring for the contract. Always returns 200.
    """
    # app.version is set by FastAPI(title=..., version=...) in
    # create_app(); reading it off the request keeps this
    # endpoint oblivious to whatever create_app chose to name it.
    app_version = getattr(request.app, "version", "unknown")

    git_sha, git_sha_full = _read_build_info(_DEFAULT_BUILD_INFO)

    return {
        "version": app_version,
        "git_sha": git_sha,
        "git_sha_full": git_sha_full,
    }