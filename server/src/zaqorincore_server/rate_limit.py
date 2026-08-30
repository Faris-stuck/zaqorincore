"""In-process sliding-window API rate limiter (v2.3.0 IMP-2 first slice).

Counts requests per ``X-API-Key`` (or per remote IP when the key
is absent) over a rolling one-minute window and returns ``429 Too
Many Requests`` with a ``Retry-After`` header once a caller exceeds
the configured budget.

Why per-process and not Redis-backed?

* The middleware is defence-in-depth, not the canonical access
  control layer — the role-based ``require_role`` dep is. A
  multi-replica deploy will get N * budget effective limit, which
  is acceptable for a single-tenant SOC tool where the budget is
  sized in the hundreds per minute.
* It costs zero extra dependencies. A Redis token-bucket will be
  a follow-up if/when the operator wants a global limit.

Config (both optional):

* ``ZAQORIN_RATE_LIMIT_ENABLED`` — set to ``false`` to disable the
  middleware entirely (default ``true``).
* ``ZAQORIN_RATE_LIMIT_PER_MIN`` — the per-key/IP budget for a
  rolling 60-second window. Default ``120`` (two per second average,
  which is well above what any ZaqorinCore endpoint actually needs).

Excluded paths (never throttled):

* ``/healthz``, ``/readyz``, ``/healthz/deps`` — orchestrator probes
  must keep working even if a misconfigured caller is being
  rate-limited.
* ``/static/*``, ``/`` (the bundled SPA) — the static shell is
  served from the same origin and is not API traffic.

Identity resolution (in order):

1. ``X-API-Key`` header — uses the presented key as the bucket key.
2. ``request.client.host`` — fall back to the client IP. ``None``
   clients (e.g. in-process ASGI tests) are bucketed under the
   literal string ``"anonymous"`` so a misbehaving in-process
   caller cannot bypass the limiter.

Cleanup:

* The bucket map is pruned every ``prune_every`` accepted requests
  (default 256) so a long-running process doesn't accumulate
  dead buckets for clients that never come back. Pruning removes
  any bucket whose window start is older than the current window.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from threading import Lock
from typing import Deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from .config import get_settings

log = logging.getLogger(__name__)

# Header the agent already uses; do not invent a new contract.
_API_KEY_HEADER = "x-api-key"

# Public paths that are never throttled. The bundled SPA at "/" is
# excluded because it is not API traffic and the operator's dashboard
# hammers it. Probes are excluded because kubernetes / load balancer
# health checks must never be denied.
_EXCLUDED_PREFIXES: tuple[str, ...] = (
    "/healthz",
    "/readyz",
    "/static/",
)


def _is_excluded(path: str) -> bool:
    """Return True iff ``path`` should bypass the rate limiter."""
    if path in ("/", "/index.html"):
        return True
    return any(path.startswith(p) for p in _EXCLUDED_PREFIXES)


def _bucket_key(request: Request) -> str:
    """Resolve the bucket key for ``request``.

    Preference order:
      1. ``X-API-Key`` header (treat empty/missing as anonymous).
      2. ``request.client.host`` (the immediate peer IP).
      3. Literal ``"anonymous"`` when neither is available.
    """
    presented = request.headers.get(_API_KEY_HEADER, "").strip()
    if presented:
        return f"key:{presented}"
    client = request.client
    if client and client.host:
        return f"ip:{client.host}"
    return "anonymous"


class _Bucket:
    """One caller's sliding window.

    Stores the unix timestamps of recent accepted requests in a
    deque; on each call we drop timestamps older than ``window``
    seconds and count what remains. The deque never holds more
    than ``limit`` entries because we reject (and do not record)
    any request that would exceed the budget.
    """

    __slots__ = ("hits", "window_sec", "limit")

    def __init__(self, window_sec: float, limit: int) -> None:
        self.hits: Deque[float] = deque()
        self.window_sec = window_sec
        self.limit = limit

    def allow(self, now: float) -> tuple[bool, float]:
        """Record ``now`` if under budget.

        Returns ``(allowed, retry_after_sec)``. ``retry_after_sec``
        is 0 on success; on rejection it is the seconds until the
        oldest in-window hit ages out.
        """
        # Drop hits older than the window.
        cutoff = now - self.window_sec
        while self.hits and self.hits[0] < cutoff:
            self.hits.popleft()
        if len(self.hits) >= self.limit:
            # Oldest hit is at self.hits[0]; it ages out at
            # self.hits[0] + window. Round up so the client doesn't
            # retry one millisecond too early.
            retry_after = max(0.0, self.hits[0] + self.window_sec - now)
            return False, retry_after
        self.hits.append(now)
        return True, 0.0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter middleware.

    The middleware is stateless across requests — buckets are kept
    in a module-level dict guarded by a ``Lock`` because Starlette
    middleware instances are shared across the event loop and
    multiple worker threads. The lock is short-held (dict get/set
    + bucket allow) so contention is negligible at the budgets
    ZaqorinCore cares about (≤10k rps).
    """

    WINDOW_SEC = 60.0
    PRUNE_EVERY = 256

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()
        self._accepted_since_prune = 0
        # Snapshot settings at construction. The middleware reads the
        # settings once and then uses its own snapshot, so an operator
        # who flips ``enabled`` mid-process needs a restart. This is
        # intentional: it matches how ``SecurityHeadersMiddleware``
        # behaves and keeps the surface area boring.
        settings = get_settings()
        self._enabled: bool = settings.rate_limit_enabled
        self._limit: int = settings.rate_limit_per_min

    def _prune(self, now: float) -> None:
        """Drop buckets whose window is fully empty.

        Called from inside ``_lock``. A bucket is pruned iff its
        oldest in-window hit is older than ``now - WINDOW_SEC``.
        """
        cutoff = now - self.WINDOW_SEC
        dead: list[str] = []
        for key, bucket in self._buckets.items():
            while bucket.hits and bucket.hits[0] < cutoff:
                bucket.hits.popleft()
            if not bucket.hits:
                dead.append(key)
        for key in dead:
            self._buckets.pop(key, None)

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self._enabled:
            return await call_next(request)
        path = request.url.path
        if _is_excluded(path):
            return await call_next(request)

        key = _bucket_key(request)
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(self.WINDOW_SEC, self._limit)
                self._buckets[key] = bucket
            allowed, retry_after = bucket.allow(now)
            self._accepted_since_prune += 1
            if self._accepted_since_prune >= self.PRUNE_EVERY:
                self._prune(now)
                self._accepted_since_prune = 0

        if not allowed:
            # Per RFC 6585 / 7231, Retry-After is an integer number of
            # seconds. Round up so the client doesn't hammer us before
            # the window actually slides.
            retry_seconds = max(1, int(retry_after + 0.999))
            log.warning(
                "rate limit exceeded",
                extra={
                    "bucket_key_prefix": key.split(":", 1)[0],
                    "path": path,
                    "limit_per_min": self._limit,
                    "retry_after_sec": retry_seconds,
                },
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "rate limit exceeded",
                    "limit_per_min": self._limit,
                    "retry_after_sec": retry_seconds,
                },
                headers={"Retry-After": str(retry_seconds)},
            )

        return await call_next(request)


__all__ = ["RateLimitMiddleware"]