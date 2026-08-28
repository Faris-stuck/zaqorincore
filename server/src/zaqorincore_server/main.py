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

import uvicorn
from fastapi import FastAPI

from .api import health, v1
from .api.v1 import alerts, events, hosts, stream
from .config import get_settings
from .db import dispose_engine, get_session_factory, init_engine
from .detectors import runner as detector_runner
from .dispatcher import Dispatcher
from .logging import configure_logging, get_logger
from .streams.publisher import close_redis, ensure_consumer_group, get_redis


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

    try:
        yield
    finally:
        log.info("zaqorin shutting down")
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
        version="0.4.0",
        description=(
            "Central server for ZaqorinCore. Accepts WebSocket streams "
            "from zaqorin-agent, persists events to PostgreSQL, runs "
            "detectors, persists alerts, and (Phase 4) dispatches "
            "auto-response actions back to the originating host."
        ),
        lifespan=lifespan,
    )

    # Health (no /api prefix)
    app.include_router(health.router)

    # API v1
    app.include_router(stream.router)
    app.include_router(hosts.router)
    app.include_router(events.router)
    app.include_router(alerts.router)

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
