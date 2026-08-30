"""Structured error response envelope (v2.5.0 candidate, opt-in).

Why opt-in
==========

The cycle-14 attempt at this feature failed because it changed the
response shape globally and broke two public contracts:

* ``test_ingest_cloudflare.py`` asserts the 401 path returns an
  EMPTY body — that's how the HMAC endpoint denies a bad
  signature without leaking an oracle. Wrapping that body in a
  JSON envelope broke the assertion.
* ``test_auth_roles.py`` reads ``r.json()["detail"]`` — a
  FastAPI HTTPException contract that callers (and other tests
  across the suite) depend on.

This middleware defaults to **OFF** and only activates when the
operator sets ``ZAQORIN_ERROR_ENVELOPE=1``. When OFF the
middleware is a pass-through — every existing test keeps
behaving exactly as it does today, no exceptions, no surprises.

Shape (when ON)
===============

For any 4xx / 5xx response on a NON-excluded route, the body is
rewritten to::

    {
        "error": {
            "code": "<machine-readable code>",
            "message": "<human-readable message>",
            "request_id": "<request id from structlog contextvars>"
        },
        # Back-compat mirror so callers reading ``detail`` keep working:
        "detail": "<original human-readable message>"
    }

The ``code`` is derived from the status code (e.g. ``"unauthorized"``,
``"forbidden"``, ``"rate_limited"``, ``"not_found"``, ``"conflict"``,
``"unprocessable_entity"``, ``"internal_error"``, plus a generic
``"http_error"`` for anything else). Callers that switch to the
new ``error.code`` get a stable identifier to key off; callers
that still read ``detail`` see the original message verbatim.

Per-route exclusion list
========================

Even when the envelope is ON, the following path prefixes are
NEVER wrapped — the response passes through untouched:

* ``/healthz``, ``/readyz``, ``/healthz/deps`` — orchestrator
  probes must keep their plain text / status-only contract.
* ``/api/v1/ingest/cloudflare``, ``/api/v1/ingest/webhook`` —
  HMAC-signed endpoints that intentionally return an empty 401
  body on a bad signature. Wrapping that body would leak an
  oracle ("invalid signature" vs "missing signature") which is
  exactly what the empty-body contract was designed to prevent.
* ``/``, ``/static/`` — bundled SPA. Errors here are 404s from
  the static file handler and have no body to wrap.

If a future endpoint needs the same protection, add its prefix
to ``_EXCLUDED_PREFIXES``. Keep the list short and conservative.

Streaming-response handling
============================

``BaseHTTPMiddleware`` returns the downstream response as a
``_StreamingResponse`` whose body lives in ``body_iterator``
chunks rather than a single ``.body`` bytes attribute. To wrap
the body we drain the iterator, build a new ``Response`` with
the wrapped body, and forward the original headers / status
code / media type. If the iterator yields nothing (empty body,
e.g. the ingest 401 contract), we pass through untouched so
the empty-body oracle-leak guard is preserved end-to-end.

Constraints
===========

* No new dependencies.
* No edits to existing test files.
* No edits to response shape when env var is unset.
* Wraps the response ONCE — re-entry is safe because we look at
  the response's actual body bytes and re-emit a single JSON
  document.
* Works for both ``HTTPException`` (FastAPI auto-renders to
  ``{"detail": ...}``) and raw ``Response(status_code=...)``
  with a plain text body (we synthesise a message from the
  body bytes or fall back to the status text).
"""

from __future__ import annotations

import json
import os
from typing import AsyncIterator

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ``request_id`` is bound by RequestIDMiddleware for the lifetime of
# every request. Reading it from contextvars keeps the envelope in
# sync with the rest of the log line without re-parsing headers.

# Prefix match; per-route opt-out. Order doesn't matter — we just
# check ``startswith`` for each entry.
_EXCLUDED_PREFIXES: tuple[str, ...] = (
    "/healthz",
    "/readyz",
    "/api/v1/healthcheck",
    "/api/v1/ingest/cloudflare",
    "/api/v1/ingest/webhook",
    "/api/v1/security",
    "/api/v1/stats",
    "/api/v1/kanban",
    "/static",
)


def _is_excluded(path: str) -> bool:
    """True if ``path`` matches one of the safe-by-default exclusions.

    The root path ``/`` is matched via equality (it doesn't match
    any other prefix so we have to handle it explicitly).
    """
    if path == "/":
        return True
    for prefix in _EXCLUDED_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


# Status code -> machine-readable code. Stable identifiers so callers
# can branch on them without parsing English.
_STATUS_CODE_TO_ERROR_CODE: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    406: "not_acceptable",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "unprocessable_entity",
    429: "rate_limited",
    500: "internal_error",
    501: "not_implemented",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
}

# Tiny status-text table so the envelope never has an empty
# ``detail`` when the original body is empty (e.g. the
# /healthz/* 503 from a degraded deps probe).
_HTTP_STATUS_TEXT: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    409: "Conflict",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


def _error_code_for(status_code: int) -> str:
    """Stable machine-readable code for ``status_code``.

    Falls back to ``"http_error"`` for anything not in the table so
    adding a new status code upstream doesn't crash the middleware.
    """
    return _STATUS_CODE_TO_ERROR_CODE.get(status_code, "http_error")


def _is_envelope_enabled() -> bool:
    """Read the opt-in env var.

    Truthy values are exactly ``"1"``, ``"true"``, ``"yes"`` (case
    insensitive). Anything else — including unset — keeps the
    middleware in pass-through mode.
    """
    raw = os.environ.get("ZAQORIN_ERROR_ENVELOPE", "").strip().lower()
    return raw in ("1", "true", "yes")


def _extract_detail(body: bytes, content_type: str) -> str:
    """Best-effort extraction of a human-readable detail from ``body``.

    * JSON with a ``detail`` key → that string.
    * JSON without ``detail`` → the whole body as a string.
    * Anything else (plain text, empty) → the raw body decoded
      as UTF-8 with replacement.
    """
    if not body:
        return ""
    if "json" in content_type.lower():
        try:
            parsed = json.loads(body)
        except (ValueError, json.JSONDecodeError):
            return body.decode("utf-8", errors="replace")
        if isinstance(parsed, dict):
            detail = parsed.get("detail")
            if isinstance(detail, str):
                return detail
            if detail is not None:
                # Non-string detail (rare; list/dict from
                # FastAPI's validation envelope) — serialise it
                # so the caller still gets something useful.
                return json.dumps(detail, separators=(",", ":"))
        # JSON body without a detail key: fall back to the
        # whole body so the envelope isn't empty.
        return body.decode("utf-8", errors="replace")
    return body.decode("utf-8", errors="replace")


async def _drain_body(body_iterator: AsyncIterator[bytes]) -> bytes:
    """Read every chunk from ``body_iterator`` and join into one
    bytes object.

    The iterator is exhausted as a side effect — that's fine
    because BaseHTTPMiddleware creates a fresh iterator per
    request and we replace the response with a non-streaming
    one below.
    """
    chunks: list[bytes] = []
    async for chunk in body_iterator:
        if isinstance(chunk, (bytes, bytearray)):
            chunks.append(bytes(chunk))
        else:
            # Starlette guarantees bytes here, but be defensive
            # against a future ASGI server that yields str.
            chunks.append(str(chunk).encode("utf-8"))
    return b"".join(chunks)


class ErrorEnvelopeMiddleware(BaseHTTPMiddleware):
    """Wrap 4xx/5xx responses in a stable error envelope (opt-in).

    See module docstring for the full contract. In short:

    * Reads ``ZAQORIN_ERROR_ENVELOPE`` once per request via
      ``_is_envelope_enabled`` — changing the env var at
      runtime is NOT supported; restart required.
    * When OFF → pass-through. ``dispatch`` returns the
      downstream response unchanged.
    * When ON → only wraps responses on non-excluded paths.
    * The wrapped body keeps the original ``detail`` key so
      callers depending on it (and the tests that read it)
      still work; the new ``error.code`` is the recommended
      stable identifier.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        # Pass-through when disabled OR when the response is
        # successful. Successful responses always look like the
        # endpoint author intended; only errors get wrapped.
        if not _is_envelope_enabled():
            return response
        if response.status_code < 400:
            return response
        if _is_excluded(request.url.path):
            return response

        # Drain the streaming body. ``BaseHTTPMiddleware`` hands
        # us a ``_StreamingResponse`` whose body is the
        # ``body_iterator`` async generator; reading it gives us
        # the raw bytes the downstream app emitted.
        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is None:
            # Non-streaming response (rare in Starlette, but
            # ``Response(status_code=...)`` can do it). Read the
            # ``.body`` attribute if present, otherwise treat as
            # empty.
            body_bytes = bytes(getattr(response, "body", b"") or b"")
        else:
            body_bytes = await _drain_body(body_iterator)

        # Empty body: nothing to wrap. This is the belt to the
        # per-route exclusion braces for the HMAC 401-empty-body
        # contract — even if a future endpoint slips past the
        # exclusion list, an empty body stays empty.
        if not body_bytes:
            return response

        content_type = response.headers.get("content-type", "")
        detail = _extract_detail(body_bytes, content_type)
        if not detail:
            # Use the HTTP status text as the human-readable
            # fallback so the envelope never has an empty
            # ``detail`` field.
            detail = _HTTP_STATUS_TEXT.get(
                response.status_code, f"HTTP {response.status_code}"
            )

        # The request_id lives on the response header (set by
        # RequestIDMiddleware). Reading it from the header
        # rather than structlog contextvars avoids a subtle
        # ordering bug: by the time we drain the streaming body
        # here, RequestIDMiddleware's ``finally`` has already
        # cleared the contextvar. The header value is the
        # canonical record anyway and survives middleware
        # re-ordering. Fall back to contextvars if the header
        # is absent (the middleware wasn't wired).
        request_id = response.headers.get("x-request-id") or structlog.contextvars.get_contextvars().get("request_id")
        envelope: dict[str, object] = {
            "error": {
                "code": _error_code_for(response.status_code),
                "message": detail,
                "request_id": request_id,
            },
            # Back-compat: preserve ``detail`` so callers (and
            # ``test_auth_roles.py``-style contracts) that read
            # the FastAPI HTTPException shape keep working.
            "detail": detail,
        }
        # Build a fresh Response (not JSONResponse) so we keep
        # the original headers and status code; ``init_headers``
        # is the public API for copying headers from an existing
        # Response into a new one without mutating the original.
        wrapped = Response(
            content=json.dumps(envelope).encode("utf-8"),
            status_code=response.status_code,
            media_type="application/json",
            headers=dict(response.headers),
        )
        return wrapped


__all__ = ["ErrorEnvelopeMiddleware"]