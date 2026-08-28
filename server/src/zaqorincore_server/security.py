"""Security headers middleware + API-key dependency.

Two pieces:

1. ``SecurityHeadersMiddleware`` — applies a CSP and other
   browser-facing headers to every response. The
   Content-Security-Policy here is permissive on purpose:
   the ZaqorinCore console is a single-page app served from
   the same origin and currently loads React 18 from the
   esm.sh CDN. Once the React bundle is vendored locally
   (post-1.0), the CSP can be tightened to ``default-src 'self'``.

2. ``require_api_key`` — FastAPI dependency that enforces the
   ``X-API-Key`` shared secret on protected routers (currently
   the SOAR ``/api/v1/soar/*`` family). Constant-time
   comparison via ``hmac.compare_digest`` so a brute-force
   timing leak is not feasible. When ``api_key`` is unset the
   dependency is a no-op and a startup warning is logged once
   (operators must explicitly opt in to a no-auth deploy).
"""
from __future__ import annotations

import hmac
import logging

from fastapi import Header, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .config import get_settings

log = logging.getLogger(__name__)

_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://esm.sh; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        return response


# Module-level flag so the warning fires once per process, not
# on every protected request.
_unauth_warned = False


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency that enforces the X-API-Key header.

    Behavior:

    - If ``Settings.api_key`` is empty: pass through and warn
      once (operator-acknowledged dev mode).
    - If the header is missing: 401.
    - If the header does not match (constant-time): 401.

    The X-API-Key name is conventional for an API gateway /
    reverse proxy model. The SOAR endpoints are intended to
    be hit by an internal scheduler or a SOC operator, not
    by an end-user browser session.
    """
    global _unauth_warned
    expected = get_settings().api_key
    if not expected:
        if not _unauth_warned:
            log.warning(
                "soar: ZAQORIN_API_KEY is unset; SOAR endpoints "
                "are open. Set ZAQORIN_API_KEY in any non-dev deploy."
            )
            _unauth_warned = True
        return
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header missing",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not hmac.compare_digest(x_api_key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key invalid",
            headers={"WWW-Authenticate": "ApiKey"},
        )
