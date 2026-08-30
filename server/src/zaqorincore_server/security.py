"""Security headers middleware + API-key dependency.

Two pieces:

1. ``SecurityHeadersMiddleware`` — applies a CSP and other
   browser-facing headers to every response. The
   Content-Security-Policy here is permissive on purpose:
   the ZaqorinCore console is a single-page app served from
   the same origin and currently loads React 18 from the
   esm.sh CDN. Once the React bundle is vendored locally
   (post-1.0), the CSP can be tightened to ``default-src 'self'``.

2. ``require_api_key`` — thin re-export of the role-based
   ``require_role`` dependency from ``auth.py``. Kept here for
   backward compatibility with routers/tests written against the
   F6 (v1.7.6) binary ``X-API-Key`` contract. New code should
   import ``require_role`` from ``auth`` directly so it can read
   the resolved role off ``request.state``.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

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


# F6 (v1.7.6) used to keep the verification logic here. The
# role-based dep in ``auth.py`` owns the constant-time comparison
# and the no-auth-dev-mode warning now. We re-export it under the
# old name so routers written against the F6 contract keep working.
from .auth import require_role as require_api_key  # noqa: E402,F401


__all__ = [
    "SecurityHeadersMiddleware",
    "require_api_key",
]
