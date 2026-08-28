"""Alert persistence.

`write_alert` inserts one row into the `alerts` table. The
cooldown/dedup is enforced at the **detector layer** via
Redis (so multiple server processes share the same
cooldown window); this function just writes the row.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import async_sessionmaker

from ..models.alert import Alert

logger = logging.getLogger(__name__)


async def write_alert(
    session_factory: async_sessionmaker[Any],
    *,
    detector: str,
    severity: str,
    summary: str,
    detail: dict[str, Any],
    host_id: uuid.UUID | None,
    dedup_key: str = "",
    cooldown_sec: int = 0,
) -> uuid.UUID:
    """Insert an alert. Returns the new alert id."""
    alert_id = uuid.uuid4()

    # Compose the dedup signature into the JSONB detail so it
    # shows up in the API response without a schema change.
    enriched_detail = dict(detail)
    if dedup_key:
        enriched_detail["dedup_key"] = dedup_key
    if cooldown_sec:
        enriched_detail["cooldown_sec"] = cooldown_sec

    async with session_factory() as session:
        alert = Alert(
            id=alert_id,
            host_id=host_id,
            detector=detector,
            severity=severity,
            summary=summary[:512],
            detail=enriched_detail,
            created_at=datetime.now(tz=timezone.utc),
        )
        session.add(alert)
        await session.commit()
        return alert_id


__all__ = ["write_alert"]
