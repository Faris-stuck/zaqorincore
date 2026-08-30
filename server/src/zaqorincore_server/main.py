"""FastAPI app factory and entrypoint.

Lifespan:
  * configure logging
  * open the SQLAlchemy async engine
  * open the Redis client + ensure the consumer group exists
  * start the detector runner (Phase 3) as a background task
  * start the dispatcher (Phase 4) as a background task
  * on shutdown, cancel both, close Redis + DB
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import health, v1
from .api.v1 import (
    agents as agents_api,
    alerts,
    audit as audit_api,
    auth as auth_api,
    canary,
    evidence,
    events,
    healthcheck as healthcheck_api,
    hosts,
    hunt,
    ingest_cloudflare,
    ingest_webhook,
    soar as soar_api,
    stream,
)
from .config import get_settings
from .db import dispose_engine, get_session_factory, init_engine
from .detectors import runner as detector_runner
from .dispatcher import Dispatcher
from .logging import configure_logging, get_logger
from .rate_limit import RateLimitMiddleware
from .request_id import RequestIDMiddleware
from .security import SecurityHeadersMiddleware
from .error_envelope import ErrorEnvelopeMiddleware
from .soar.worker import SoarWorker
from .streams.publisher import close_redis, ensure_consumer_group, get_redis

# Path to the bundled SPA (index.html + static/app.js). Resolved relative
# to this file so it works regardless of the current working directory.
_WEBUI_DIR = Path(__file__).resolve().parent.parent.parent.parent / "webui"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    log = get_logger("zaqorin.lifespan")
    settings = get_settings()
    log.info(
        "zaqorin starting",
        host=settings.server_host,
        port=settings.server_port,
    )

    init_engine()
    settings = get_settings()
    factory = get_session_factory()
    runner_task: asyncio.Task[None] | None = None
    dispatcher: Dispatcher | None = None
    soar_worker: SoarWorker | None = None
    if settings.streams_enabled:
        # Touch Redis so we fail fast at startup if it's unreachable.
        await get_redis()
        await ensure_consumer_group()
        if settings.detectors_enabled:
            runner_task = asyncio.create_task(
                detector_runner.run(), name="zaqorin-detector-runner"
            )
    if settings.dispatcher_enabled:
        dispatcher = Dispatcher(settings, factory)
        dispatcher.start()
    if settings.soar_enabled:
        soar_worker = SoarWorker(settings, factory)
        soar_worker.start()
        # Attach to app.state for the API router.
        app.state.soar_worker = soar_worker  # type: ignore[attr-defined]

    try:
        yield
    finally:
        log.info("zaqorin shutting down")
        if soar_worker is not None:
            await soar_worker.stop()
        if dispatcher is not None:
            await dispatcher.stop()
        if runner_task is not None and not runner_task.done():
            runner_task.cancel()
            try:
                await runner_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                log.warning("detector runner shutdown error: %s", exc)
        if settings.streams_enabled:
            await close_redis()
        await dispose_engine()


def create_app() -> FastAPI:
    app = FastAPI(
        title="ZaqorinCore Server",
        version="2.1.0",
        description=(
            "Central server for ZaqorinCore. Accepts WebSocket streams "
            "from zaqorin-agent, persists events to PostgreSQL, runs "
            "detectors, persists alerts, and (Phase 4) dispatches "
            "auto-response actions back to the originating host. "
            "Phase 9 ships the bundled web console at /."
        ),
        lifespan=lifespan,
    )

    # Security headers first (innermost in Starlette = outermost in response)
    app.add_middleware(SecurityHeadersMiddleware)
    # Rate limiter next; it sees the request before any router
    # handler does and short-circuits with 429 before the auth
    # dependency runs, which protects ``require_role`` itself from
    # a flood. Health probes (``/healthz``, ``/readyz``,
    # ``/healthz/deps``) and the bundled SPA (``/``, ``/static/``)
    # are excluded inside the middleware.
    app.add_middleware(RateLimitMiddleware)
    # Request-ID middleware LAST so it runs FIRST in Starlette's
    # LIFO ordering — every log line emitted by any downstream
    # layer (rate_limit, audit, ingest) inherits the same
    # ``request_id`` structlog contextvar for the lifetime of
    # this request. See ops/cycle-26.
    app.add_middleware(RequestIDMiddleware)
    # Error envelope (opt-in via ZAQORIN_ERROR_ENVELOPE=1,
    # default OFF so the cycle-14 contracts on 401-empty-body and
    # ``r.json()["detail"]`` keep holding). When ON, every
    # non-excluded 4xx/5xx response is wrapped in
    # ``{error: {code, message, request_id}, detail}``.
    # See security/cycle-28.
    app.add_middleware(ErrorEnvelopeMiddleware)

    # Health (no /api prefix)
    app.include_router(health.router)

    # API v1
    app.include_router(stream.router)
    app.include_router(hosts.router)
    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(hunt.router)
    app.include_router(canary.router)
    app.include_router(evidence.router)
    app.include_router(soar_api.router)
    app.include_router(ingest_cloudflare.router)
    app.include_router(ingest_webhook.router)
    app.include_router(auth_api.router)
    app.include_router(audit_api.router)
    app.include_router(healthcheck_api.router)
    app.include_router(agents_api.router)

    # Bundled web console (Phase 9). The SPA lives in /webui/ at the repo
    # root; if the directory is missing (e.g. server-only deployment), the
    # / route 404s gracefully and the API still works.
    if _WEBUI_DIR.exists():
        static_dir = _WEBUI_DIR / "static"
        if static_dir.exists():
            app.mount("/static", StaticFiles(directory=static_dir), name="webui-static")

        @app.get("/", include_in_schema=False)
        async def spa_index() -> FileResponse:
            return FileResponse(_WEBUI_DIR / "index.html")

    return app


app = create_app()


def run() -> None:
    """Console-script entry point: `zaqorin-server`."""
    configure_logging()
    settings = get_settings()
    uvicorn.run(
        "zaqorincore_server.main:app",
        host=settings.server_host,
        port=settings.server_port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    run()
