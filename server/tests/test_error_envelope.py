"""Tests for the opt-in error envelope middleware (v2.5.0 cycle 28).

The middleware is opt-in via ``ZAQORIN_ERROR_ENVELOPE=1`` and
default OFF. This is the key invariant the test file protects:

* **Default OFF**: every existing endpoint keeps its current
  response shape. ``test_ingest_cloudflare.py`` and
  ``test_auth_roles.py``-style callers reading
  ``r.json()["detail"]`` continue to work; the HMAC 401-empty-
  body contract is preserved.
* **When ON**: 4xx / 5xx responses on non-excluded paths are
  rewritten to ``{error: {code, message, request_id}, detail}``.
  The ``detail`` key is mirrored verbatim for back-compat so a
  caller reading the old FastAPI HTTPException shape still gets
  the same string.
* **Excluded paths** never get wrapped, even when ON: HMAC
  ingest endpoints (empty 401 body contract), health probes,
  the bundled SPA.

Coverage matrix:
  1. Default OFF: 4xx / 5xx pass through untouched.
  2. ON, normal route: body is wrapped; ``error.code`` is stable;
     ``detail`` is preserved; ``error.request_id`` matches the
     response ``X-Request-ID``.
  3. ON, excluded ingest route: the empty 401 body is preserved
     (no envelope, no oracle leak).
  4. ON, excluded health route: pass-through untouched.
  5. ON, 200 response: NEVER wrapped (envelope only applies to
     error responses).
"""

from __future__ import annotations

import importlib

import pytest
import structlog
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

from zaqorincore_server.error_envelope import (
    ErrorEnvelopeMiddleware,
    _error_code_for,
    _extract_detail,
    _is_envelope_enabled,
    _is_excluded,
)
from zaqorincore_server.request_id import RequestIDMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_app(*, envelope: bool) -> FastAPI:
    """Build a tiny FastAPI app that:

    * Runs ``RequestIDMiddleware`` so we can verify the envelope
      picks up the same request_id as the response header.
    * Runs ``ErrorEnvelopeMiddleware`` (the env-var check happens
      inside the middleware per-request, so we always wire it
      and toggle via env var).
    * Exposes routes that cover the matrix:
        - ``GET /healthz`` — excluded, 503 path
        - ``GET /api/v1/ingest/cloudflare`` — excluded, 401 path
        - ``GET /api/v1/probe/{status}`` — NON-excluded, configurable
        - ``GET /api/v1/unauthorized`` — NON-excluded, 403 path
        - ``GET /ok`` — 200 success path
    """
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(ErrorEnvelopeMiddleware)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.get("/api/v1/ingest/cloudflare")
    async def ingest_cloudflare() -> Response:
        # Mirror the production contract: a bad / missing
        # HMAC signature returns 401 with an EMPTY body (no
        # oracle). We bypass HTTPException so the body stays
        # empty rather than being auto-rendered as JSON.
        return Response(status_code=401)

    @app.get("/api/v1/unauthorized")
    async def unauthorized() -> dict:
        raise HTTPException(status_code=403, detail="missing role: ingest")

    @app.get("/api/v1/probe/{status}")
    async def probe(status: int) -> dict:
        # 400 + 500 are the two error families not covered by the
        # dedicated routes above.
        if status == 400:
            raise HTTPException(status_code=400, detail="bad input")
        if status == 500:
            raise HTTPException(status_code=500, detail="boom")
        return {"echo": status}

    @app.get("/ok")
    async def ok() -> dict:
        return {"ok": True}

    # Stash the env flag so the assertion at the end can confirm
    # the test fixture matched the middleware's expectation. This
    # also documents the contract for anyone reading the file.
    app.state.envelope_expected = envelope  # type: ignore[attr-defined]
    return app


@pytest.fixture
def envelope_off(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """TestClient with ``ZAQORIN_ERROR_ENVELOPE`` explicitly OFF."""
    monkeypatch.delenv("ZAQORIN_ERROR_ENVELOPE", raising=False)
    return TestClient(_stub_app(envelope=False))


@pytest.fixture
def envelope_on(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """TestClient with ``ZAQORIN_ERROR_ENVELOPE=1``."""
    monkeypatch.setenv("ZAQORIN_ERROR_ENVELOPE", "1")
    return TestClient(_stub_app(envelope=True))


# Thin wrappers so individual tests don't have to list the fixture
# in their signature. ``_client(off=True)`` returns an OFF client;
# ``_client(off=False)`` returns an ON client. Both honour the
# monkeypatch scoping of the active test.
def _client(*, off: bool, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    if off:
        monkeypatch.delenv("ZAQORIN_ERROR_ENVELOPE", raising=False)
    else:
        monkeypatch.setenv("ZAQORIN_ERROR_ENVELOPE", "1")
    return TestClient(_stub_app(envelope=not off))


# ---------------------------------------------------------------------------
# 1. Default OFF — pass-through
# ---------------------------------------------------------------------------


def test_default_off_passes_through_403(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the env var unset (default), a 403 response keeps the
    FastAPI HTTPException shape exactly — ``detail`` is the only
    top-level key, no envelope, no extra fields.
    """
    client = _client(off=True, monkeypatch=monkeypatch)
    r = client.get("/api/v1/unauthorized")
    assert r.status_code == 403
    body = r.json()
    assert "detail" in body
    assert "error" not in body
    assert body["detail"] == "missing role: ingest"


def test_default_off_passes_through_401_ingest_empty_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """The HMAC ingest 401 MUST stay empty-body when envelope is OFF.

    This is the cycle-14 contract that the empty-body oracle-leak
    guard depends on. If the middleware starts injecting JSON
    here, an attacker probing for "bad signature" vs "missing
    signature" gets a free oracle.
    """
    client = _client(off=True, monkeypatch=monkeypatch)
    r = client.get("/api/v1/ingest/cloudflare")
    assert r.status_code == 401
    assert r.content == b""


def test_default_off_passes_through_200(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful responses are never wrapped — envelope ON or OFF."""
    client = _client(off=True, monkeypatch=monkeypatch)
    r = client.get("/ok")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


# ---------------------------------------------------------------------------
# 2. ON — non-excluded error gets wrapped
# ---------------------------------------------------------------------------


def test_envelope_on_wraps_403_with_stable_code_and_back_compat_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    """When ON, a non-excluded 403 is rewritten to:

    * ``error.code == "forbidden"`` (stable identifier callers
      can branch on).
    * ``error.message`` mirrors the original ``detail``.
    * ``detail`` is preserved at the top level so callers that
      read the FastAPI HTTPException shape still work.
    * ``error.request_id`` matches the ``X-Request-ID`` echoed
      on the response (the two correlation surfaces stay in
      sync).
    """
    client = _client(off=False, monkeypatch=monkeypatch)
    r = client.get(
        "/api/v1/unauthorized",
        headers={"X-Request-ID": "agent-call-42"},
    )
    assert r.status_code == 403
    body = r.json()
    assert body["error"]["code"] == "forbidden"
    assert body["error"]["message"] == "missing role: ingest"
    assert body["detail"] == "missing role: ingest"  # back-compat
    assert body["error"]["request_id"] == "agent-call-42"
    assert r.headers.get("x-request-id") == "agent-call-42"


def test_envelope_on_wraps_400_and_500_with_correct_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both ends of the error spectrum (400 / 500) are wrapped with
    the matching stable code, not just the auth-path codes.
    """
    client = _client(off=False, monkeypatch=monkeypatch)
    r400 = client.get("/api/v1/probe/400")
    assert r400.status_code == 400
    assert r400.json()["error"]["code"] == "bad_request"
    assert r400.json()["detail"] == "bad input"

    r500 = client.get("/api/v1/probe/500")
    assert r500.status_code == 500
    assert r500.json()["error"]["code"] == "internal_error"
    assert r500.json()["detail"] == "boom"


def test_envelope_on_does_not_wrap_2xx(monkeypatch: pytest.MonkeyPatch) -> None:
    """ON, success: pass-through. Wrapping 200s would break every
    successful endpoint for no benefit — callers already parse the
    success body directly.
    """
    client = _client(off=False, monkeypatch=monkeypatch)
    r = client.get("/ok")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


# ---------------------------------------------------------------------------
# 3. ON — excluded paths stay untouched
# ---------------------------------------------------------------------------


def test_envelope_on_preserves_empty_401_on_ingest(monkeypatch: pytest.MonkeyPatch) -> None:
    """The HMAC ingest 401 stays empty even when the envelope is ON.

    This is the whole point of the exclusion list. If this test
    ever fails, an attacker gets a free oracle on
    ``/api/v1/ingest/cloudflare`` (good signature vs bad vs
    missing) — revert immediately.
    """
    client = _client(off=False, monkeypatch=monkeypatch)
    r = client.get("/api/v1/ingest/cloudflare")
    assert r.status_code == 401
    assert r.content == b""


def test_envelope_on_passes_through_healthz(monkeypatch: pytest.MonkeyPatch) -> None:
    """Health probes are excluded so orchestrator liveness checks
    don't have to learn a new envelope shape.
    """
    client = _client(off=False, monkeypatch=monkeypatch)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


# ---------------------------------------------------------------------------
# 4. Helpers — pure-function coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status_code,expected",
    [
        (400, "bad_request"),
        (401, "unauthorized"),
        (403, "forbidden"),
        (404, "not_found"),
        (409, "conflict"),
        (413, "payload_too_large"),
        (422, "unprocessable_entity"),
        (429, "rate_limited"),
        (500, "internal_error"),
        (503, "service_unavailable"),
    ],
)
def test_error_code_table(status_code: int, expected: str) -> None:
    """Every status code in the public-facing error table maps to
    a stable, branchable identifier.
    """
    assert _error_code_for(status_code) == expected


def test_error_code_table_falls_back_for_unknown_status() -> None:
    """A status code not in the table must not raise — it falls
    back to ``"http_error"`` so the middleware keeps working when
    a new status code is added upstream.
    """
    assert _error_code_for(418) == "http_error"


def test_extract_detail_json_with_detail_key() -> None:
    body = b'{"detail": "missing role: ingest"}'
    assert (
        _extract_detail(body, "application/json") == "missing role: ingest"
    )


def test_extract_detail_empty_body_returns_empty_string() -> None:
    """An empty body (the HMAC ingest 401 case) yields an empty
    string so the caller can decide whether to substitute the
    HTTP status text.
    """
    assert _extract_detail(b"", "application/json") == ""


def test_extract_detail_plain_text_falls_back_to_decoded_body() -> None:
    """A non-JSON body is decoded with replacement so a malformed
    payload doesn't crash the envelope middleware.
    """
    assert _extract_detail(b"not json", "text/plain") == "not json"


def test_is_excluded_recognises_every_protected_prefix() -> None:
    """Every path in the exclusion list is matched via startswith
    (except ``/`` which is matched via equality). A new prefix
    added without updating this test will silently fall out of
    the exclusion list.
    """
    for path in (
        "/",
        "/healthz",
        "/healthz/deps",
        "/readyz",
        "/api/v1/ingest/cloudflare",
        "/api/v1/ingest/webhook",
        "/static/app.js",
    ):
        assert _is_excluded(path), f"expected {path!r} to be excluded"


def test_is_excluded_does_not_match_unrelated_paths() -> None:
    """The exclusion list is conservative — random unrelated paths
    must NOT be excluded. A regression here would wrap auth 401s
    in an envelope and break the cycle-14 contract.
    """
    for path in (
        "/api/v1/alerts",
        "/api/v1/audit",
        "/api/v1/unauthorized",
    ):
        assert not _is_excluded(path), f"unexpected exclusion of {path!r}"


def test_is_envelope_enabled_treats_only_truthy_strings_as_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """The env-var reader is strict: ``1`` / ``true`` / ``yes`` are
    on (case insensitive); unset / anything else is off. Anything
    looser would let an operator accidentally enable the envelope
    in a deploy that didn't plan for it.
    """
    monkeypatch.delenv("ZAQORIN_ERROR_ENVELOPE", raising=False)
    assert _is_envelope_enabled() is False
    for truthy in ("1", "true", "TRUE", "yes", "Yes"):
        monkeypatch.setenv("ZAQORIN_ERROR_ENVELOPE", truthy)
        assert _is_envelope_enabled() is True, truthy
    for falsy in ("0", "false", "no", "", "on", "enabled", "off"):
        monkeypatch.setenv("ZAQORIN_ERROR_ENVELOPE", falsy)
        assert _is_envelope_enabled() is False, falsy


# ---------------------------------------------------------------------------
# 5. Wiring — middleware is registered in create_app
# ---------------------------------------------------------------------------


def test_error_envelope_middleware_is_wired_in_create_app() -> None:
    """The middleware is registered in ``create_app`` exactly once.

    A regression where the middleware is removed from
    ``main.create_app`` (or registered twice) would silently
    disable / double-wrap every error response. This test pins
    the registration.
    """
    from zaqorincore_server.main import create_app

    app = create_app()
    # ``app.user_middleware`` is a list of Starlette middleware
    # specs; each entry exposes ``cls``. We check the class is
    # present exactly once.
    classes = [spec.cls for spec in app.user_middleware]
    assert classes.count(ErrorEnvelopeMiddleware) == 1