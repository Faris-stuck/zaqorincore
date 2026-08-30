"""Health endpoints: /healthz, /readyz, /healthz/deps."""

from __future__ import annotations

import logging
import time

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


async def _probe_postgres() -> dict[str, object]:
    """Return {ok, latency_ms, error?} for the Postgres SELECT 1 probe."""
    started = time.perf_counter()
    try:
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
        return {"ok": True, "latency_ms": round((time.perf_counter() - started) * 1000, 2)}
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": str(exc),
        }


async def _probe_redis() -> dict[str, object]:
    """Return {ok, latency_ms, error?} for the Redis PING probe."""
    started = time.perf_counter()
    try:
        client = await get_redis()
        await client.ping()
        return {"ok": True, "latency_ms": round((time.perf_counter() - started) * 1000, 2)}
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": str(exc),
        }


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


@router.get("/healthz/deps")
async def healthz_deps(response: Response) -> dict[str, object]:
    """Per-dependency health for ops dashboards and scrape targets.

    Probes every external dependency the server relies on, returning
    a structured {name: {ok, latency_ms, error?}} map. Suitable for
    Prometheus textfile exporters, Grafana JSON datasource, or
    ad-hoc curl-and-grep by an operator. Always returns 200 with a
    JSON body — the body's ``ok`` field is the truth, not the HTTP
    code, so a scrape tool never gets an empty response. 503 is
    returned when any dep fails so simple alerting rules can match
    on status code.
    """
    postgres = await _probe_postgres()
    redis = await _probe_redis()

    deps: dict[str, dict[str, object]] = {
        "postgres": postgres,
        "redis": redis,
    }
    all_ok = all(bool(d["ok"]) for d in deps.values())

    if not all_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        log.warning("healthz/deps failing", extra={"deps": deps})

    return {
        "status": "ok" if all_ok else "degraded",
        "ok": all_ok,
        "deps": deps,
    }
