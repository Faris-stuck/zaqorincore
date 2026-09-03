"""CORS middleware (v3.2.3, F-010).

Wraps Starlette's :class:`CORSMiddleware` with an explicit
allow-list driven by the ``ZAQORIN_API_CORS_ORIGINS`` env var
(``Settings.cors_origins``). Without this middleware Starlette's
default is wildcard, which is the root cause of the F-010 finding.

When ``cors_origins`` is empty (the default) the middleware is NOT
mounted, which means browsers reject all cross-origin XHR/fetch
calls — the safe baseline.

When ``cors_origins`` is set, the middleware:

* parses the comma-separated list into a list of exact origins
  (no scheme/host inference, no regex),
* rejects ``"*"`` if it would coincide with credentialed requests
  (it never does here because ``allow_credentials`` is hard-coded
  False), and
* limits methods to ``GET/POST/PUT/DELETE`` and headers to
  ``X-ZaQorin-Key`` + ``Content-Type``.

The list of allowed origins is logged once at startup so operators
can audit it without reading source.
"""
from __future__ import annotations

import logging
from typing import Iterable

from starlette.middleware.cors import CORSMiddleware

from .config import get_settings

log = logging.getLogger(__name__)

_ALLOWED_METHODS: list[str] = ["GET", "POST", "PUT", "DELETE"]
_ALLOWED_HEADERS: list[str] = ["X-ZaQorin-Key", "Content-Type"]


def _parse_origins(raw: str) -> list[str]:
    """Split ``ZAQORIN_API_CORS_ORIGINS`` into a clean list.

    Empty entries are dropped. Wildcards are kept as ``"*"`` but the
    caller (``build_cors_middleware``) refuses to combine them with
    credentialed requests.
    """
    return [o.strip() for o in raw.split(",") if o.strip()]


def build_cors_middleware() -> CORSMiddleware | None:
    """Return a configured :class:`CORSMiddleware` or ``None``.

    ``None`` means CORS is disabled entirely — Starlette will not
    emit ``Access-Control-Allow-*`` headers at all and browsers
    will block cross-origin requests. This is the right answer for
    a server-only deployment or a same-origin console.
    """
    settings = get_settings()
    origins: list[str] = _parse_origins(settings.cors_origins)
    if not origins:
        log.info(
            "cors: ZAQORIN_API_CORS_ORIGINS unset; cross-origin browser "
            "requests will be blocked by the browser (safe default)"
        )
        return None

    # F-010: a wildcard combined with credentialed requests is a CORS
    # spec violation (browsers ignore the response). We never set
    # allow_credentials=True here, so this is belt-and-braces, but
    # the check makes the policy explicit and prevents a future
    # maintainer from accidentally turning credentials on.
    allow_credentials = False
    if "*" in origins and allow_credentials:
        raise RuntimeError(
            "CORS misconfiguration: wildcard origin '*' is incompatible "
            "with credentialed requests. Either narrow the allow-list "
            "or set allow_credentials=False."
        )

    log.info(
        "cors: allowlist=%s methods=%s headers=%s credentials=%s",
        origins, _ALLOWED_METHODS, _ALLOWED_HEADERS, allow_credentials,
    )
    return CORSMiddleware(
        app=None,  # wired by app.add_middleware() at startup
        allow_origins=origins,
        allow_methods=_ALLOWED_METHODS,
        allow_headers=_ALLOWED_HEADERS,
        allow_credentials=allow_credentials,
        allow_origin_regex=None,
        expose_headers=[],
    )


def describe_cors_policy() -> dict:
    """Return a small dict describing the active policy.

    Used by ``/api/v1/security/policy`` (audit endpoint) and by
    tests. Mirrors the runtime values without exposing secrets.
    """
    settings = get_settings()
    origins = _parse_origins(settings.cors_origins)
    return {
        "enabled": bool(origins),
        "allow_origins": origins,
        "allow_methods": _ALLOWED_METHODS,
        "allow_headers": _ALLOWED_HEADERS,
        "allow_credentials": False,
    }


__all__ = ["build_cors_middleware", "describe_cors_policy"]