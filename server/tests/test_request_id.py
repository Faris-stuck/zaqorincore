"""Tests for the Request-ID middleware (v2.5.0 cycle 26).

The middleware binds a per-request ``request_id`` into structlog's
contextvars so every log line emitted during the request shares the
same correlation id, and echoes that id back on the response so the
caller can pin it.

Coverage matrix:
  1. Inbound X-Request-ID is honored when ASCII-safe; unsafe/oversize
     values fall back to a freshly generated 16-char hex id.
  2. The chosen id is echoed back on the response.
  3. structlog's contextvars are bound during the handler and cleared
     after the response (no leak to the next request).
  4. The middleware is wired in ``create_app``.
"""

from __future__ import annotations

import re

import structlog
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from zaqorincore_server.request_id import (
    RequestIDMiddleware,
    _resolve_request_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StubRequest:
    url = type("U", (), {"path": "/api/v1/test"})()
    headers: dict[str, str] = {}

    class _Client:
        host = "127.0.0.1"

    client = _Client()


def _stub(request: object) -> Request:
    return request  # type: ignore[return-value]


def _stub_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)

    @app.get("/probe")
    async def probe() -> dict:
        return {"ok": True}

    return app


_HEX16 = re.compile(r"[0-9a-f]{16}")


# ---------------------------------------------------------------------------
# 1. Header honoring
# ---------------------------------------------------------------------------


def test_inbound_header_honored_verbatim() -> None:
    """An ASCII-safe X-Request-ID header is used verbatim."""
    req = _StubRequest()
    req.headers = {"x-request-id": "agent-abc-123"}
    assert _resolve_request_id(_stub(req)) == "agent-abc-123"


def test_inbound_header_unsafe_or_oversize_falls_back() -> None:
    """Control chars, spaces, oversize values are discarded.

    These would let a hostile client forge log lines or bloat every
    log record on the request. The middleware must always fall back
    to a fresh 16-char hex id in those cases.
    """
    bad_inputs = [
        "a" * 65,            # oversize
        "abc\ndef",          # newline
        "abc def",           # space
        "abc;rm -rf",        # shell metachar
        "abc\x00def",        # null byte
        "<script>",          # html-ish
        "   ",               # whitespace only
    ]
    for bad in bad_inputs:
        req = _StubRequest()
        req.headers = {"x-request-id": bad}
        rid = _resolve_request_id(_stub(req))
        assert rid != bad
        assert _HEX16.fullmatch(rid), f"bad fallback for {bad!r}: {rid!r}"


def test_missing_header_generates_fresh_id() -> None:
    """No header at all -> a freshly generated 16-char hex id."""
    req = _StubRequest()
    req.headers = {}
    rid = _resolve_request_id(_stub(req))
    assert _HEX16.fullmatch(rid)


# ---------------------------------------------------------------------------
# 2. Round-trip on the response
# ---------------------------------------------------------------------------


def test_response_echoes_request_id_when_provided() -> None:
    """Caller-provided id round-trips on the response."""
    client = TestClient(_stub_app())
    resp = client.get("/probe", headers={"X-Request-ID": "round-trip-1"})
    assert resp.status_code == 200
    assert resp.headers.get("x-request-id") == "round-trip-1"


def test_response_carries_generated_id_when_header_absent() -> None:
    """Generated id is exposed on the response so callers can learn it."""
    client = TestClient(_stub_app())
    resp = client.get("/probe")
    assert resp.status_code == 200
    rid = resp.headers.get("x-request-id")
    assert rid is not None and _HEX16.fullmatch(rid)


# ---------------------------------------------------------------------------
# 3. Contextvar lifecycle
# ---------------------------------------------------------------------------


def test_contextvars_cleared_between_requests() -> None:
    """The structlog contextvar MUST be cleared at the end of each
    request, otherwise a long-lived worker thread would leak the
    previous request's id into the next request's log lines.
    """
    client = TestClient(_stub_app())

    resp = client.get("/probe", headers={"X-Request-ID": "first-id-1234"})
    assert resp.status_code == 200
    assert "request_id" not in structlog.contextvars.get_contextvars()

    resp = client.get("/probe", headers={"X-Request-ID": "second-id-5678"})
    assert resp.status_code == 200
    assert resp.headers.get("x-request-id") == "second-id-5678"
    assert "request_id" not in structlog.contextvars.get_contextvars()


def test_handler_observes_bound_request_id() -> None:
    """While the handler runs, structlog.contextvars is bound with
    the resolved request_id, so a log line emitted from inside the
    handler carries the same correlation id as the response header.
    """
    from zaqorincore_server.logging import get_logger

    log = get_logger("test.request_id")
    captured: list[dict] = []

    def _capture(_logger, _method, event_dict):  # type: ignore[no-untyped-def]
        captured.append(dict(event_dict))
        return ""

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            _capture,
            structlog.processors.JSONRenderer(),
        ]
    )
    try:
        app = FastAPI()
        app.add_middleware(RequestIDMiddleware)

        @app.get("/log")
        async def _log_route() -> dict:
            log.info("handler_running")
            return {"ok": True}

        client = TestClient(app)
        resp = client.get("/log", headers={"X-Request-ID": "trace-xyz-9"})
        assert resp.status_code == 200
        matching = [e for e in captured if e.get("event") == "handler_running"]
        assert matching, f"no handler_running event in {captured!r}"
        assert matching[0]["request_id"] == "trace-xyz-9"
    finally:
        # Restore the production processor chain.
        from zaqorincore_server.logging import configure_logging

        configure_logging()


# ---------------------------------------------------------------------------
# 4. Wiring
# ---------------------------------------------------------------------------


def test_middleware_is_wired_in_create_app() -> None:
    """The middleware is mounted by ``create_app`` so every request
    to the live app goes through it.
    """
    from zaqorincore_server.main import create_app

    middleware_classes = [m.cls for m in create_app().user_middleware]
    assert RequestIDMiddleware in middleware_classes, (
        f"RequestIDMiddleware not wired into create_app; "
        f"got {middleware_classes!r}"
    )