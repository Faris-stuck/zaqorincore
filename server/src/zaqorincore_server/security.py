"""Security headers middleware + API-key dependency.

Two pieces:

1. ``SecurityHeadersMiddleware`` — applies a CSP and other
   browser-facing headers to every response.

   v3.2.3 (F-007/F-016):
     * ``script-src`` lists only ``'self'``; the bundled web console
       is plain HTML/JS and loads no remote CDN.
     * ``style-src`` no longer allows ``'unsafe-inline'``. The CSS
       is served from ``/static/app.css``. The middleware mints a
       per-request CSP nonce when a request asks for a same-origin
       HTML page; that nonce is exposed as ``request.state.csp_nonce``
       so templates (or the SPA index handler) can stamp it onto any
       inline ``<style>`` or ``<script>`` that absolutely has to be
       inline. Requests without HTML don't get a nonce.

2. ``require_api_key`` — thin re-export of the role-based
   ``require_role`` dependency from ``auth.py``. Kept here for
   backward compatibility with routers/tests written against the
   F6 (v1.7.6) binary ``X-API-Key`` contract. New code should
   import ``require_role`` from ``auth`` directly so it can read
   the resolved role off ``request.state``.
"""
from __future__ import annotations

import logging
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger(__name__)

# F-007: removed https://esm.sh. The console ships no React CDN.
# F-016: removed 'unsafe-inline' from style-src. Per-request nonce
# is added by ``SecurityHeadersMiddleware`` for same-origin HTML
# responses; ``require_style_nonce`` rejects inline styles that
# don't carry the nonce.
_CSP_BASE = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply CSP and other browser-facing headers.

    For HTML responses on the same origin we also mint a fresh CSP
    nonce per request and stash it on ``request.state.csp_nonce``.
    Templates/stubs that render inline ``<style>`` or ``<script>``
    blocks can stamp ``nonce={{csp_nonce}}`` on them; the nonce is
    then added to ``script-src`` and ``style-src`` so those blocks
    are accepted without falling back to ``'unsafe-inline'``.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Always mint a nonce so handlers can opt-in. We add it to
        # the CSP only for HTML responses so the JSON API is locked
        # down to the base policy.
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response = await call_next(request)

        csp = _CSP_BASE
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/html"):
            # HTML response: allow the per-request nonce on inline
            # style/script tags if the template chose to use it.
            csp = (
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )

        response.headers.setdefault("Content-Security-Policy", csp)
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