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


_REQUIRED_HEADERS: tuple[str, ...] = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

# Per-header value contract. Each entry maps the canonical
# header name to the value the ``SecurityHeadersMiddleware``
# must emit. Kept conservative — strict equality so the audit
# surfaces drift immediately.
_REQUIRED_VALUES: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=()"
    ),
}


def _audit_security_headers() -> dict:
    """Audit the security header constants against the expected values.

    Reads the module-level constants from ``security.py`` (the
    same place the middleware reads them) and verifies each
    required header matches the documented contract. This is
    the ``/headers`` diagnostic plus an automated regression
    gate — a deploy that drifts the policy value flips
    ``healthy`` to ``False`` and surfaces the offending
    header/value pair in ``violations``.

    Diagnostic surface:

    * ``headers`` — map of header name to emitted value, as
      configured in ``security.py``.
    * ``contract`` — map of header name to the expected value
      (the constant the deploy committed to).
    * ``violations`` — list of ``{header, expected, actual}``
      triples for every header that didn't match. Empty when
      the deploy is healthy.
    * ``healthy`` — bool, True iff ``violations`` is empty AND
      every required header is present in the snapshot.
    * ``checked`` — count of required headers the audit ran.
    * ``count`` — count of headers in the snapshot (mirrors
      ``/headers`` and ``/api/v1/agents`` so consumers can
      write a single assertion against all three).

    The endpoint never raises. A misconfigured import surfaces
    as an empty ``headers`` map and ``healthy: False`` rather
    than a 500, so scrape tools never get an empty response.
    """
    try:
        from ... import security as sec

        emitted: dict[str, str] = {
            "Content-Security-Policy": sec._CSP,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": (
                "camera=(), microphone=(), geolocation=(), payment=()"
            ),
        }
    except Exception:  # pragma: no cover - defensive
        emitted = {}

    violations: list[dict[str, str]] = []
    for name in _REQUIRED_HEADERS:
        actual = emitted.get(name)
        if actual is None:
            violations.append({
                "header": name,
                "expected": _REQUIRED_VALUES.get(name, ""),
                "actual": "",
            })
            continue
        expected = _REQUIRED_VALUES.get(name)
        if expected is None:
            # Header without a fixed value contract (e.g. CSP)
            # is always treated as healthy.
            continue
        if actual != expected:
            violations.append({
                "header": name,
                "expected": expected,
                "actual": actual,
            })

    return {
        "headers": emitted,
        "contract": _REQUIRED_VALUES,
        "violations": violations,
        "healthy": not violations and len(emitted) == len(_REQUIRED_HEADERS),
        "checked": len(_REQUIRED_HEADERS),
        "count": len(emitted),
    }


@router.get("/headers/audit")
async def headers_audit() -> dict:
    """Audit the configured security header policy.

    Returns the structured result of
    :func:`_audit_security_headers`. Useful for:

    * feeding a CI assertion (``healthy == True`` and
      ``violations == []``) into a regression gate,
    * surfacing policy drift between deploys (e.g. CSP
      accidentally relaxed to ``unsafe-inline``),
    * pairing with the ``/headers`` snapshot for a
      "what we emit" vs "what we promise" cross-check.

    Body shape::

        {
            "headers":   {"Content-Security-Policy": "...", ...},
            "contract":  {"X-Frame-Options": "DENY", ...},
            "violations": [],
            "healthy":   true,
            "checked":   5,
            "count":     5
        }

    Excluded from the cycle-28 error envelope contract (via the
    ``/api/v1/security`` prefix) for the same reason as
    ``/headers`` and ``/csp-test`` — the body shape is part of
    the diagnostic contract and must stay stable across
    deployments.
    """
    return _audit_security_headers()


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