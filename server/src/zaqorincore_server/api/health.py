"""Health endpoints: /healthz and /readyz."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from ..db import get_session_factory
from ..streams.publisher import get_redis

router = APIRouter(include_in_schema=False)
log = logging.getLogger(__name__)


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: the process is up and able to handle HTTP. Does not
    touch dependencies so it stays cheap."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(response: Response) -> dict[str, str]:
    """Readiness: both Postgres and Redis are reachable.

    Returns 200 only if both checks pass; otherwise 503 with the
    failing component in the body so an operator can grep it.
    """
    failures: list[str] = []

    try:
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        failures.append(f"postgres: {exc!s}")

    try:
        client = await get_redis()
        await client.ping()
    except Exception as exc:  # noqa: BLE001
        failures.append(f"redis: {exc!s}")

    if failures:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        log.warning("readyz failed", extra={"failures": failures})
        return {"status": "unready", "detail": "; ".join(failures)}

    return {"status": "ready"}
