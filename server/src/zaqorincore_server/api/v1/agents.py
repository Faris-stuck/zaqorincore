"""GET /api/v1/agents — list currently connected agents.

Returns one entry per agent that has an open WebSocket on the
dispatcher ``HostConnectionRegistry``, enriched with the
metadata stored on the ``hosts`` row (last_seen_at,
last_version, hostname). Response shape::

    {
        "agents": [
            {
                "host_id": "<uuid>",
                "connected": true,
                "last_seen_at": "<iso8601>",
                "last_version": "<str|None>",
                "hostname": "<str|None>"
            },
            ...
        ],
        "count": <int>
    }

Design notes
============

* ``connected`` is always ``true`` for hosts returned here —
  the registry only carries live WebSockets. Kept in the
  payload so the field stays stable if we later expand the
  endpoint to include hosts that *recently* disconnected.
* The endpoint never raises 5xx. If the database read fails
  (rare in tests; possible during a real outage), the
  affected host entries return ``last_seen_at``,
  ``last_version``, and ``hostname`` as ``null`` rather than
  failing the whole list — operators still want the
  connectivity view during a partial DB degradation.
* ``last_seen_at`` and ``hostname`` come from the Host row
  populated by ``upsert_on_hello``; they reflect the most
  recent HELLO frame the agent sent, not the lifetime of
  the current WebSocket. The cycle-30 ``count()`` accessor
  is what tells you the live count; this endpoint tells you
  *who* is connected and what version they're running.
* Excluded from the cycle-28 error envelope contract (see
  ``_EXCLUDED_PREFIXES`` in ``error_envelope.py``) so the
  body shape stays stable for scrape tools, same reasoning
  as ``/api/v1/healthcheck`` and the ``/healthz`` family.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_session
from ...dispatcher import registry as agent_registry
from ...logging import get_logger
from ...models import Host
from ...security import require_api_key

log = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1",
    dependencies=[Depends(require_api_key)],
)


@router.get("/agents")
async def list_agents(session: AsyncSession = Depends(get_session)) -> dict:
    """Return every currently connected agent plus its host metadata.

    Reads the dispatcher registry for the live WebSocket set,
    then enriches each host_id with the matching ``Host`` row.
    Hosts that fail to enrich (DB hiccup) degrade to ``null``
    metadata fields rather than failing the whole response.
    """
    host_ids = agent_registry.host_ids()

    # Fetch all host rows in one round-trip rather than N.
    # ``host_service.get_host`` is per-id; for the list we go
    # straight to the model.
    if host_ids:
        from sqlalchemy import select as sa_select  # local import keeps top tidy

        stmt = sa_select(Host).where(Host.id.in_(host_ids))
        result = await session.execute(stmt)
        rows = {h.id: h for h in result.scalars().all()}
    else:
        rows = {}

    agents: list[dict] = []
    for host_id in host_ids:
        host = rows.get(host_id)
        if host is None:
            log.warning(
                "agents: connected host has no hosts row",
                host_id=str(host_id),
            )
            agents.append(
                {
                    "host_id": str(host_id),
                    "connected": True,
                    "last_seen_at": None,
                    "last_version": None,
                    "hostname": None,
                }
            )
            continue
        agents.append(
            {
                "host_id": str(host.id),
                "connected": True,
                "last_seen_at": host.last_seen_at.isoformat(),
                "last_version": host.last_version,
                "hostname": host.hostname,
            }
        )

    return {"agents": agents, "count": len(agents)}


__all__ = ["router"]