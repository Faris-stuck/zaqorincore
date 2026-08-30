"""Shared test fixtures.

Tests use a real Postgres + Redis (already running on the test host)
but a SEPARATE database / db number so we don't trample dev data.

Strategy: a function-scoped engine is created and torn down per test.
That's wasteful but it sidesteps the pytest-asyncio 0.24 / event-loop
mismatch that bites any test that uses a session-scoped async engine
plus async fixtures.

Required environment before running tests:
    ZAQORIN_DATABASE_URL=postgresql+asyncpg://zaqorin:***@127.0.0.1:25432/zaqorin_test
    ZAQORIN_REDIS_URL=redis://127.0.0.1:6379/15
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Force test env BEFORE app is imported anywhere.
os.environ.setdefault(
    "ZAQORIN_DATABASE_URL",
    "postgresql+asyncpg://zaqorin:***@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
# Tests that don't explicitly need Redis can opt in via this flag
# to keep their event loops isolated. The streaming integration
# (smoke.py) still hits Redis.
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
# Tests don't start the detector runner either; detector tests
# drive the runner directly.
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

from zaqorincore_server.config import get_settings, reset_settings  # noqa: E402
from zaqorincore_server.models import Base  # noqa: E402


@pytest_asyncio.fixture
async def engine():
    """One engine per test, NullPool so no connection pooling across
    the test boundary. We:
      1. Ensure the test database exists (idempotent).
      2. Create the schema.
      3. Truncate at the end.
      4. Wire this engine into the zaqorincore_server.db module-level
         singleton so the WS handler (which reads the singleton via
         get_session_factory()) uses THIS engine on THIS loop.
    """
    from sqlalchemy.pool import NullPool  # noqa: PLC0415

    from zaqorincore_server import db as zdb  # noqa: PLC0415

    settings = get_settings()
    db_name = settings.database_url.rsplit("/", 1)[1]
    maint_url = settings.database_url.rsplit("/", 1)[0] + "/postgres"
    maint = create_async_engine(maint_url, isolation_level="AUTOCOMMIT")
    async with maint.connect() as conn:
        exists = await conn.scalar(
            text("SELECT 1 FROM pg_database WHERE datname = :n"),
            {"n": db_name},
        )
        if not exists:
            await conn.execute(text(f'CREATE DATABASE "{db_name}"'))
    await maint.dispose()

    test_engine = create_async_engine(
        settings.database_url, poolclass=NullPool
    )

    # Wire the module-level singleton so the WS handler uses this
    # engine + this event loop.
    prev_engine = zdb._engine
    prev_factory = zdb._session_factory
    zdb._engine = test_engine
    zdb._session_factory = async_sessionmaker(
        test_engine, expire_on_commit=False
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield test_engine
    finally:
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await test_engine.dispose()
        # Restore previous singletons.
        zdb._engine = prev_engine
        zdb._session_factory = prev_factory


@pytest_asyncio.fixture
async def session(engine) -> AsyncIterator[AsyncSession]:
    """A fresh AsyncSession per test."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        yield s


@pytest_asyncio.fixture
async def app_client(engine) -> AsyncIterator[AsyncClient]:
    """An httpx AsyncClient wired to the FastAPI app via ASGI in-memory.

    Default mode is "dev" (ZAQORIN_API_KEY unset, so require_api_key
    is a no-op). Tests that want to exercise the auth path explicitly
    use the ``app_client_with_auth`` fixture from
    ``test_routers_api_auth.py`` or ``test_soar_api_auth.py``.

    The shell that runs pytest may have ZAQORIN_API_KEY set (e.g. a
    security audit), so we clear it here to keep the test default
    behavior unchanged from before F6 / v1.7.6.
    """
    import os

    from zaqorincore_server.main import create_app  # noqa: PLC0415

    os.environ.pop("ZAQORIN_API_KEY", None)
    reset_settings()
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
