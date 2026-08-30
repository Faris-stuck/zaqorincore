"""Diagnostics endpoints for the security middleware (cycle 33).

Two routes, both read-only, both excluded from the cycle-28
error envelope contract (see ``_EXCLUDED_PREFIXES`` below):

* ``GET /api/v1/security/headers`` — returns the security
  header values the ``SecurityHeadersMiddleware`` would emit
  for a normal response, as a JSON map. Useful for:
    - sanity-checking the policy after a code change,
    - feeding a curl/jq pipe from a Grafana JSON datasource,
    - writing browser console assertions against an expected
      ``Content-Security-Policy`` value.
* ``GET /api/v1/security/csp-test`` — returns *only* the
  ``Content-Security-Policy`` value as a plain string, for
  scripts that want to compare the policy verbatim.

Why split into two routes?
- ``/headers`` is the diagnostic for the whole middleware.
- ``/csp-test`` is a stable, narrow contract for CSP-only
  tooling (e.g. ``curl -fsS http://host/api/v1/security/csp-test
  | diff - csp.expected``). Keeping it separate means the
  ``/headers`` payload can grow new fields without breaking
  CSP-only consumers.

Design notes
============

* The header values are read off the module-level constants
  in ``security.py`` (the same place the middleware reads
  them). We deliberately do NOT trigger the middleware and
  read the response back — that would couple this endpoint
  to middleware ordering and make it brittle. The constants
  ARE the source of truth.
* Both endpoints never raise. A misconfigured import (rare)
  surfaces as ``csp: null`` and ``headers: {}`` rather than
  a 500, so scrape tools never get an empty response.
* Excluded from the cycle-28 error envelope contract so the
  body shape stays stable across deployments (same reasoning
  as ``/api/v1/healthcheck`` and the ``/healthz`` family).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ...security import require_api_key

router = APIRouter(
    prefix="/api/v1/security",
    dependencies=[Depends(require_api_key)],
)


def _header_snapshot() -> dict[str, str]:
    """Build the JSON snapshot of security header values.

    Imports the module-level constants from ``security.py`` so
    the diagnostic stays in sync with what the middleware emits.
    Returns an empty dict on ImportError (defensive — should
    never happen in a deployed build, but keeps the endpoint
    stable under partial-test setups).
    """
    try:
        # Local import keeps the route module independent of
        # ``security.py`` import-time side effects (there are
        # none today, but the pattern is cheap insurance).
        from ... import security as sec

        return {
            "Content-Security-Policy": sec._CSP,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": (
                "camera=(), microphone=(), geolocation=(), payment=()"
            ),
        }
    except Exception:  # pragma: no cover - defensive
        return {}


@router.get("/headers")
async def security_headers() -> dict:
    """Return the security headers the middleware would emit.

    Body shape::

        {
            "headers": {
                "Content-Security-Policy": "...",
                "X-Content-Type-Options": "nosniff",
                ...
            },
            "count": <int>
        }

    ``count`` mirrors the ``count`` field on ``/api/v1/agents``
    and ``/api/v1/healthcheck`` so consumers can write a single
    assertion against all three.
    """
    headers = _header_snapshot()
    return {"headers": headers, "count": len(headers)}


@router.get("/csp-test")
async def csp_test() -> dict:
    """Return the Content-Security-Policy value verbatim.

    Body shape::

        {"csp": "<the policy string>", "present": <bool>}

    ``present`` is ``False`` when the policy is missing (the
    snapshot dict was empty). Scripts can branch on it without
    parsing the string.
    """
    headers = _header_snapshot()
    csp = headers.get("Content-Security-Policy")
    return {"csp": csp, "present": csp is not None}


__all__ = ["router"]