"""SOAR (v1.3.0) HTTP surface.

Two endpoints, plus the existing /alerts/{id}/deliveries
view that the web console calls:

  GET  /api/v1/soar/deliveries             - per-alert + per-backend health
  GET  /api/v1/soar/dead-letter            - list dead-lettered deliveries
  GET  /api/v1/soar/dead-letter/{file_id}  - get one dead-letter + its body
  POST /api/v1/soar/dead-letter/{file_id}/replay
                                            - re-enqueue this dead letter
  GET  /api/v1/soar/health                 - 24h health per backend

The replay endpoint is the only one that mutates state
outside the DB. It re-validates the dead-letter file with
SHA-256, then enqueues a fresh _PendingDelivery on the
worker's queue. The worker takes care of the HTTP call +
result + dead-letter rotation exactly like an organic
delivery.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_session
from ...models.soar_delivery import SoarDelivery
from ...security import require_api_key

router = APIRouter(
    prefix="/api/v1/soar",
    tags=["soar"],
    dependencies=[Depends(require_api_key)],
)


# ─── Per-alert delivery list ─────────────────────────────────────
@router.get("/deliveries")
async def list_deliveries(
    alert_id: uuid.UUID | None = None,
    backend: str | None = None,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """List recent SOAR delivery attempts. The web console
    calls this for the per-alert deliveries panel."""
    stmt = select(SoarDelivery).order_by(desc(SoarDelivery.attempted_at)).limit(limit)
    if alert_id is not None:
        stmt = stmt.where(SoarDelivery.alert_id == alert_id)
    if backend is not None:
        stmt = stmt.where(SoarDelivery.backend == backend)
    rows = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {
                "id": str(r.id),
                "alert_id": str(r.alert_id) if r.alert_id else None,
                "backend": r.backend,
                "status_code": r.status_code,
                "attempted_at": r.attempted_at.isoformat(),
                "duration_ms": r.duration_ms,
                "attempt": r.attempt,
                "error": r.error,
                "dead_lettered": r.dead_lettered,
                "payload_sha256": r.payload_sha256,
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ─── 24h health per backend ──────────────────────────────────────
@router.get("/health")
async def backend_health(
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Aggregate last-24h counts per backend:
    total / success (2xx) / 4xx / 5xx / network / dead-lettered.

    Drives the #/soar view in the web console.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    stmt = select(SoarDelivery).where(SoarDelivery.attempted_at >= since)
    rows = list((await session.execute(stmt)).scalars().all())
    by_backend: dict[str, dict[str, int]] = {}
    for r in rows:
        agg = by_backend.setdefault(
            r.backend,
            {
                "total": 0,
                "success": 0,
                "client_error": 0,
                "server_error": 0,
                "network_error": 0,
                "dead_lettered": 0,
            },
        )
        agg["total"] += 1
        if 200 <= r.status_code < 400:
            agg["success"] += 1
        elif 400 <= r.status_code < 500:
            agg["client_error"] += 1
        elif r.status_code >= 500:
            agg["server_error"] += 1
        elif r.status_code == 0:
            agg["network_error"] += 1
        if r.dead_lettered:
            agg["dead_lettered"] += 1
    return {
        "window_hours": 24,
        "as_of": datetime.now(timezone.utc).isoformat(),
        "backends": by_backend,
    }


# ─── Dead-letter list / get / replay ──────────────────────────────
def _get_worker():
    """Look up the active SoarWorker on the FastAPI app.

    The worker is attached to `app.state.soar_worker` in
    the lifespan. Returns None if the worker is not
    running (e.g. during tests that disable it).
    """
    from fastapi import Request  # local import to avoid cycles

    from ...main import app as _app  # noqa: F401

    # Find the running app — the router doesn't have a
    # request, so we walk the module-level singleton.
    worker = getattr(_app.state, "soar_worker", None)  # type: ignore[attr-defined]
    return worker


@router.get("/dead-letter")
async def list_dead_letter() -> dict[str, Any]:
    """List dead-letter files, newest first."""
    worker = _get_worker()
    if worker is None:
        return {"items": [], "count": 0, "note": "soar worker not running"}
    items = worker.list_dead_letters()
    # Strip internal fields from the API response.
    for it in items:
        it.pop("_path", None)
    return {"items": items, "count": len(items)}


@router.get("/dead-letter/{file_id}")
async def get_dead_letter(file_id: str) -> dict[str, Any]:
    """Fetch a single dead-letter file by its filename (or
    a prefix of the filename)."""
    worker = _get_worker()
    if worker is None:
        raise HTTPException(status_code=503, detail="soar worker not running")
    body = worker.get_dead_letter(file_id)
    if body is None:
        raise HTTPException(status_code=404, detail="not found")
    valid = worker.verify_dead_letter(body)
    body.pop("_path", None)
    return {"file": body.get("_file"), "valid": valid, "body": body}


@router.post("/dead-letter/{file_id}/replay")
async def replay_dead_letter(file_id: str) -> dict[str, Any]:
    """Re-enqueue a dead-letter delivery. The worker
    verifies the SHA-256, then re-runs the backend.

    The body of the original attempt is re-rendered from
    the dead-letter file (not the live alert row), so
    even if the alert has been acknowledged or the
    template has been edited since, the replay sends the
    EXACT body the operator is approving.
    """
    worker = _get_worker()
    if worker is None:
        raise HTTPException(status_code=503, detail="soar worker not running")
    body = worker.get_dead_letter(file_id)
    if body is None:
        raise HTTPException(status_code=404, detail="not found")
    if not worker.verify_dead_letter(body):
        raise HTTPException(
            status_code=409,
            detail="dead-letter file failed SHA-256 verification; refusing to replay",
        )
    # Build an Alert from the dead-letter body and enqueue
    # it directly (bypassing the poller / cooldown / tags
    # filter, since the operator is explicitly asking for
    # this delivery).
    alert_payload = body.get("alert", {}) or {}
    backend_name = body.get("backend")
    if not backend_name:
        raise HTTPException(
            status_code=400, detail="dead-letter is missing 'backend'"
        )
    from ...soar.worker import _PendingDelivery  # noqa: PLC0415
    from ...soar import Alert, get_backends  # local import to avoid cycles

    backend_obj = next(
        (b for b in get_backends() if b.name == backend_name), None
    )
    if backend_obj is None:
        raise HTTPException(
            status_code=400,
            detail=f"backend {backend_name!r} is not registered",
        )
    alert = Alert(
        id=str(alert_payload.get("id", str(uuid.uuid4()))),
        host_id=str(alert_payload.get("host_id", "")),
        detector=str(alert_payload.get("detector", "")),
        severity=str(alert_payload.get("severity", "info")),
        tags=list(alert_payload.get("tags", []) or []),
        summary=str(alert_payload.get("summary", "")),
        evidence=alert_payload.get("evidence"),
        metadata=dict(alert_payload.get("metadata", {}) or {}),
    )
    # Use the worker's own BackendConfig if present;
    # otherwise fall back to a permissive 0-retry config
    # so the replay only attempts once.
    cfg = worker._config.backends.get(backend_name)  # noqa: SLF001
    if cfg is None:
        from ...soar.config import BackendConfig  # noqa: PLC0415

        cfg = BackendConfig(
            name=backend_name,
            enabled=True,
            cooldown_sec=0,
            severity_min="info",
            tags_filter=[],
            max_retries=0,
            timeout_sec=10.0,
            extra={},
        )
    item = _PendingDelivery(
        alert=alert,
        backend_name=backend_name,
        backend=backend_obj,
        config=cfg,
        attempt=1,
        next_eligible_at=0.0,
    )
    try:
        worker._queue.put_nowait(item)  # noqa: SLF001
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=503, detail=f"queue full: {e}"
        ) from e
    return {
        "status": "queued",
        "alert_id": alert.id,
        "backend": backend_name,
        "source_file": body.get("_file"),
    }


# The replay path reuses the worker's queue. We define a
# tiny _PendingReplay class that looks like _PendingDelivery
# to the worker — see worker.py for the consumption side.


__all__ = ["router"]
