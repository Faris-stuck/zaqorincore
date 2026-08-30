"""``GET /api/v1/audit`` — read-only audit log of recent operator
actions (cycle 19, security/obs track).

The audit module keeps a bounded ring-buffer of ``record()``
entries. This endpoint exposes the buffer with sensible filters
so the operator can answer "who did what in the last hour"
without grep'ing logs.

Filters:
* ``actor`` — substring match on the recorded actor (role name
  or key hint).
* ``action`` — substring match on the recorded action.
* ``since`` — ISO-8601 timestamp; entries older than this are
  excluded.
* ``limit`` — page size (1..1000, default 100).

The endpoint is read-only. Writes go through ``audit.record()``
which is currently called from a few key paths; broader
auto-instrumentation is a future cycle.

Auth: requires the ``read`` role via ``require_api_key``
(alias of ``require_role``). In dev mode the dep is a no-op
and the endpoint returns whatever has been recorded.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query

from ... import audit
from ...security import require_api_key


router = APIRouter(
    prefix="/api/v1/audit",
    tags=["audit"],
    dependencies=[Depends(require_api_key)],
)


@router.get("")
async def list_audit(
    actor: str | None = Query(default=None, description="substring match on actor"),
    action: str | None = Query(default=None, description="substring match on action"),
    since: datetime | None = Query(default=None, description="ISO-8601 lower bound (inclusive)"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict:
    """Return the most recent ``limit`` audit entries (newest first).

    Optional filters narrow the result set. An empty buffer
    yields ``{"count": 0, "items": []}`` so callers never see a
    ``null``.
    """
    raw = audit.snapshot(limit=limit)
    items = raw
    if actor:
        items = [it for it in items if actor in it.get("actor", "")]
    if action:
        items = [it for it in items if action in it.get("action", "")]
    if since is not None:
        # Entries come back as ISO-8601 strings; parse and compare.
        cutoff = since
        if cutoff.tzinfo is None:
            # Treat naive timestamps as UTC for symmetry with
            # audit.record() which always stamps tz-aware UTC.
            from datetime import timezone

            cutoff = cutoff.replace(tzinfo=timezone.utc)
        filtered: list[dict] = []
        for it in items:
            ts_str = it.get("ts")
            if not isinstance(ts_str, str):
                continue
            try:
                ts = datetime.fromisoformat(ts_str)
            except ValueError:
                continue
            if ts >= cutoff:
                filtered.append(it)
        items = filtered
    return {"count": len(items), "items": items}


__all__ = ["router"]