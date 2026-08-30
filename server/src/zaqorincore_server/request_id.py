"""Request-ID middleware (v2.5.0 cycle 26).

Binds a correlation id into structlog's contextvars for the lifetime
of every request, so every log line emitted while handling the
request (rate-limit 429s from cycle 24, audit.query reads from cycle
25, ingest errors, etc.) carries the same ``request_id`` field.

Why a middleware and not a per-handler concern?
- Handlers don't share state across the middleware chain. A rate-limit
  429 is emitted by ``RateLimitMiddleware`` BEFORE any handler runs;
  a request_id set inside the handler wouldn't be visible to that
  early log line. A middleware at the OUTSIDE of the chain (added
  LAST so it executes FIRST in Starlette's LIFO ordering) sees every
  request and every response.
- structlog's ``merge_contextvars`` processor is already wired into
  ``configure_logging``. We just need to bind before the next
  middleware runs and clear after, so the next request on the same
  worker thread doesn't inherit the previous request's id.

Contract:

* If the inbound request carries an ``X-Request-ID`` header, that
  value is used verbatim (so a load balancer / agent can correlate
  end-to-end). The header is NOT trusted blindly for security —
  it's used purely as a correlation key — but it IS length-capped
  and character-restricted to keep log consumers safe from header
  injection / log forgery.
* Otherwise a 16-char hex string is generated locally.
* The chosen id is echoed back on the response as ``X-Request-ID``
  so callers can pin the id they saw vs the id we logged.

No new dependencies. No response-shape changes.
"""

from __future__ import annotations

import re
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Inbound header is treated as an opaque correlation key. The regex
# keeps log consumers safe from a malicious client stuffing newlines
# or control characters into a header that ends up in a JSON log
# line. We do NOT use the header for any security decision — only
# for correlation — so a truncated/forbidden value just falls back
# to a freshly generated id.
_HEADER = "x-request-id"
_MAX_LEN = 64
_SAFE_RE = re.compile(r"^[A-Za-z0-9._\-]+$")


def _resolve_request_id(request: Request) -> str:
    """Pick the request_id for ``request``.

    Honors ``X-Request-ID`` if it's present, ASCII-printable, and
    short enough; otherwise generates a fresh 16-char hex id.
    """
    raw = request.headers.get(_HEADER, "").strip()
    if raw and len(raw) <= _MAX_LEN and _SAFE_RE.fullmatch(raw):
        return raw
    return uuid.uuid4().hex[:16]


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Bind a per-request ``request_id`` into structlog contextvars.

    The id is bound BEFORE the next middleware in the chain runs and
    cleared AFTER the response is produced, so every log line emitted
    while handling the request — from any layer — carries the same
    ``request_id`` field. The id is also echoed on the response so
    the caller can pin it.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = _resolve_request_id(request)
        structlog.contextvars.bind_contextvars(request_id=rid)
        try:
            response = await call_next(request)
        finally:
            # Clear even on exception so the next request on this
            # worker doesn't inherit the previous request's id. The
            # log call below is best-effort: if ``bind_contextvars``
            # itself blew up (it can't, but be defensive) we still
            # want to clear.
            structlog.contextvars.clear_contextvars()
        # Echo on the response. Starlette's MutableHeaders accepts
        # plain string assignments; we don't need to copy.
        response.headers[_HEADER] = rid
        return response


__all__ = ["RequestIDMiddleware"]