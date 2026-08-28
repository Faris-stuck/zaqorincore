"""Security headers middleware.

Applies a baseline of HTTP security headers to every response. The
Content-Security-Policy here is permissive on purpose: the ZaqorinCore
console is a single-page app served from the same origin and currently
loads React 18 from the esm.sh CDN. Once the React bundle is vendored
locally (post-1.0), the CSP can be tightened to ``default-src 'self'``.

Headers applied:
    * Content-Security-Policy
    * X-Content-Type-Options: nosniff
    * X-Frame-Options: DENY
    * Referrer-Policy: no-referrer
    * Permissions-Policy: deny everything (this is a SOC console, not a
      consumer web app; we never need camera, mic, geolocation, etc.)
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

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
