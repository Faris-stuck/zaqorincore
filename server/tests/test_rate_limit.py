"""Tests for the in-process sliding-window rate limiter (v2.3.0 IMP-2).

The middleware is pure (no DB, no Redis), so most tests construct
the bucket directly and drive ``allow()`` with synthetic timestamps.
The two integration-style tests exercise the middleware via the
FastAPI app to confirm (a) it is wired in ``create_app`` and (b) it
respects the excluded-path list.

Coverage matrix:
  1. Bucket math: under budget -> accept; at budget -> reject with
     retry_after > 0; once a hit ages out -> accept again.
  2. Identity resolution: same key shares the bucket; different
     keys/IPs get separate buckets.
  3. Middleware wiring: a small-budget config returns 429 after
     the configured number of requests.
  4. Excluded paths: /healthz and / never get 429 even when the
     budget is exhausted.
"""

from __future__ import annotations

import pytest

from zaqorincore_server.rate_limit import (
    RateLimitMiddleware,
    _Bucket,
    _bucket_key,
    _is_excluded,
)


# ---------------------------------------------------------------------------
# 1. Bucket math
# ---------------------------------------------------------------------------


def test_bucket_accepts_under_budget() -> None:
    """A fresh bucket should accept up to its limit."""
    bucket = _Bucket(window_sec=60.0, limit=5)
    now = 1000.0
    for _ in range(5):
        allowed, retry = bucket.allow(now)
        assert allowed is True
        assert retry == 0.0


def test_bucket_rejects_at_budget() -> None:
    """Once the bucket is full, further calls are rejected with a
    positive ``retry_after`` equal to the seconds until the oldest
    hit ages out.
    """
    bucket = _Bucket(window_sec=60.0, limit=3)
    now = 1000.0
    for _ in range(3):
        allowed, _ = bucket.allow(now)
        assert allowed is True
    allowed, retry = bucket.allow(now)
    assert allowed is False
    # The oldest hit was at t=1000.0; with window=60s it ages out
    # at t=1060.0. So retry_after = 60.0.
    assert retry == pytest.approx(60.0)


def test_bucket_recovers_after_window() -> None:
    """Once the window has slid past the oldest hit, that hit is
    dropped and a new request is accepted.
    """
    bucket = _Bucket(window_sec=60.0, limit=2)
    bucket.allow(1000.0)
    bucket.allow(1001.0)
    # Now full. Advance time past the window. The two old hits age
    # out and the next call is accepted.
    allowed, retry = bucket.allow(1100.0)
    assert allowed is True
    assert retry == 0.0


# ---------------------------------------------------------------------------
# 2. Identity resolution
# ---------------------------------------------------------------------------


def test_bucket_key_prefers_x_api_key() -> None:
    """When ``X-API-Key`` is present, it is used (not the IP)."""

    class _StubClient:
        host = "10.0.0.5"

    class _StubRequest:
        headers = {"x-api-key": "key-alpha"}
        client = _StubClient()

    assert _bucket_key(_StubRequest()) == "key:key-alpha"


def test_bucket_key_falls_back_to_ip() -> None:
    """When no API key is presented, the client IP is the bucket key."""

    class _StubClient:
        host = "192.0.2.10"

    class _StubRequest:
        headers: dict[str, str] = {}
        client = _StubClient()

    assert _bucket_key(_StubRequest()) == "ip:192.0.2.10"


def test_bucket_key_anonymous_when_no_client() -> None:
    """If neither header nor client IP is available, the bucket key
    is the literal ``"anonymous"`` so a misbehaving in-process
    caller cannot bypass the limiter.
    """

    class _StubRequest:
        headers: dict[str, str] = {}
        client = None

    assert _bucket_key(_StubRequest()) == "anonymous"


# ---------------------------------------------------------------------------
# 3. Excluded-path list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/healthz",
        "/healthz/deps",
        "/readyz",
        "/static/app.js",
        "/",
        "/index.html",
    ],
)
def test_is_excluded_returns_true_for_probes_and_spa(path: str) -> None:
    """Health probes and the bundled SPA must never be throttled."""
    assert _is_excluded(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/alerts",
        "/api/v1/events",
        "/api/v1/hosts",
        "/api/v1/canary",
        "/api/v1/auth/whoami",
    ],
)
def test_is_excluded_returns_false_for_api(path: str) -> None:
    """API paths are not in the exclude list — they are throttled."""
    assert _is_excluded(path) is False


# ---------------------------------------------------------------------------
# 4. Middleware wiring (integration-style, in-process)
# ---------------------------------------------------------------------------


def test_middleware_short_circuits_when_disabled() -> None:
    """When ``_enabled`` is False the middleware is a pass-through.

    We construct a bare middleware with ``_enabled`` flipped and
    assert ``call_next`` is invoked exactly once even after the
    configured budget is exceeded. The middleware has no
    ``app`` attribute of its own to drive, so we use a sentinel.
    """
    seen: list[str] = []

    async def _next(request):  # type: ignore[no-untyped-def]
        seen.append("called")
        return _StubResponse(200, {"status": "ok"})

    class _StubResponse:
        def __init__(self, status_code: int, body: dict) -> None:
            self.status_code = status_code
            self._body = body

        def json(self) -> dict:
            return self._body

    mw = RateLimitMiddleware(app=_StubApp())
    mw._enabled = False
    mw._limit = 2
    # Drive the dispatch coroutine manually.
    import asyncio

    async def _drive() -> None:
        # Make 5 calls; if enabled they would hit the budget at 2.
        for _ in range(5):
            await mw.dispatch(_StubRequest(), _next)

    asyncio.run(_drive())
    assert len(seen) == 5


def test_middleware_returns_429_with_retry_after_when_over_budget() -> None:
    """When the budget is exceeded, dispatch returns a JSONResponse
    with status 429 and a positive Retry-After header.
    """
    mw = RateLimitMiddleware(app=_StubApp())
    mw._enabled = True
    mw._limit = 2
    import asyncio

    async def _drive() -> None:
        async def _next(request):  # type: ignore[no-untyped-def]
            return _StubResponse(200, {"status": "ok"})

        r1 = await mw.dispatch(_StubRequest(), _next)
        r2 = await mw.dispatch(_StubRequest(), _next)
        r3 = await mw.dispatch(_StubRequest(), _next)
        return r1, r2, r3

    r1, r2, r3 = asyncio.run(_drive())
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert int(r3.headers["Retry-After"]) >= 1
    # JSONResponse exposes the body as bytes; decode and parse.
    import json

    body = json.loads(bytes(r3.body).decode("utf-8"))
    assert body["detail"] == "rate limit exceeded"
    assert body["limit_per_min"] == 2


def test_middleware_skips_excluded_paths() -> None:
    """Excluded paths bypass the limiter even when the budget is 1
    and the caller has already exhausted it.
    """
    mw = RateLimitMiddleware(app=_StubApp())
    mw._enabled = True
    mw._limit = 1
    import asyncio

    async def _drive() -> None:
        async def _next(request):  # type: ignore[no-untyped-def]
            return _StubResponse(200, {"status": "ok"})

        results = []
        for _ in range(5):
            r = await mw.dispatch(_HealthzRequest(), _next)
            results.append(r.status_code)
        return results

    statuses = asyncio.run(_drive())
    assert statuses == [200, 200, 200, 200, 200]


# ---------------------------------------------------------------------------
# 5. End-to-end probe-bypass (real FastAPI app)
# ---------------------------------------------------------------------------


async def test_probe_paths_bypass_rate_limit_in_real_app(engine) -> None:
    """Integration test: build the FastAPI app with a rate-limit
    budget of 1 per minute and hammer every probe path 10 times each.
    None of the probes may return 429, because ``_EXCLUDED_PREFIXES``
    in ``rate_limit.py`` short-circuits them before the bucket
    lookup. This pins the contract introduced in cycle 13 so a
    future change cannot accidentally start throttling ``/healthz``,
    ``/readyz``, or the cycle-8 ``/healthz/deps`` endpoint that ops
    dashboards scrape.
    """
    import os  # noqa: PLC0415
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from zaqorincore_server.config import reset_settings  # noqa: PLC0415
    from zaqorincore_server.main import create_app  # noqa: PLC0415

    os.environ["ZAQORIN_RATE_LIMIT_PER_MIN"] = "1"
    os.environ.pop("ZAQORIN_API_KEY", None)
    reset_settings()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 10 hits on each probe path. None should ever be 429.
        for path in ("/healthz", "/healthz/deps", "/readyz"):
            for _ in range(10):
                r = await client.get(path)
                assert r.status_code != 429, (
                    f"{path} must never be rate-limited"
                )


async def test_api_path_is_rate_limited_in_real_app(engine) -> None:
    """Companion to ``test_probe_paths_bypass_rate_limit_in_real_app``
    — proves the budget=1 config DOES throttle an API path. Without
    this companion, the previous test could pass trivially even if
    the rate limiter was disabled entirely.
    """
    import os  # noqa: PLC0415
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from zaqorincore_server.config import reset_settings  # noqa: PLC0415
    from zaqorincore_server.main import create_app  # noqa: PLC0415

    os.environ["ZAQORIN_RATE_LIMIT_PER_MIN"] = "1"
    os.environ.pop("ZAQORIN_API_KEY", None)
    reset_settings()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/api/v1/alerts")
        r2 = await client.get("/api/v1/alerts")
        assert r1.status_code == 200
        # Second call exceeds budget=1 -> 429.
        assert r2.status_code == 429


# ---------------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------------


class _StubApp:
    """Minimal stand-in for the ASGI app the middleware wraps."""


class _StubRequest:
    """Bare request stub for the middleware unit tests.

    Mirrors the attributes the middleware reads: ``url.path``,
    ``headers`` (dict with .get), and ``client.host``.
    """

    url = type("U", (), {"path": "/api/v1/test"})()
    headers: dict[str, str] = {}
    method = "GET"

    class _Client:
        host = "127.0.0.1"

    client = _Client()


class _HealthzRequest(_StubRequest):
    url = type("U", (), {"path": "/healthz"})()


class _StubResponse:
    """Minimal response — what the test's ``call_next`` returns."""

    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return self._body