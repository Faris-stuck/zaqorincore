"""Service layer: business logic for the event table + stream publish."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Event
from ..schemas.wire import EventFrame
from ..streams.publisher import publish_event

log = get_logger(__name__)


class DuplicateEvent(Exception):
    """Raised when an event with this id was already persisted. The
    WS handler turns this into a silent ack so a redelivered event
    after a reconnect doesn't fail the connection.
    """


async def persist_event(
    session: AsyncSession, frame: EventFrame
) -> Event:
    """Insert the event row. Idempotent on event.id (PK).

    Raises DuplicateEvent if the row already existed.
    """
    inner = frame.event
    stmt = (
        pg_insert(Event)
        .values(
            id=inner.id,
            host_id=inner.host_id,
            schema=inner.event_schema,
            occurred_at=inner.timestamp,
            source=inner.source,
            raw=inner.raw,
            metadata_=inner.metadata,
        )
        .on_conflict_do_nothing(index_elements=[Event.id])
        .returning(Event)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        # The row already existed. The ON CONFLICT skipped; reload so
        # the caller can see what's there.
        existing = await session.execute(
            select(Event).where(Event.id == inner.id)
        )
        existing_row = existing.scalar_one()
        # Capture the timestamp before any state change so the message
        # is meaningful regardless of what happens next.
        existing_received_at = existing_row.received_at
        # Roll back the in-progress transaction so the next operation
        # on this session starts from a clean state. After the
        # rollback `existing_row` is detached — that's why we
        # captured received_at above.
        await session.rollback()
        raise DuplicateEvent(
            f"event {inner.id} already persisted at {existing_received_at}"
        )
    await session.commit()
    log.info(
        "event persisted",
        event_id=str(row.id),
        host_id=str(row.host_id),
        source=row.source,
    )

    # Best-effort: publish to the stream after a successful commit.
    # A failure here does not roll back the row — the API is the
    # source of truth, the stream is for downstream consumers.
    try:
        await publish_event(
            event_id=row.id,
            host_id=row.host_id,
            source=row.source,
            occurred_at=row.occurred_at,
        )
    except Exception:  # noqa: BLE001 — logged, not re-raised
        log.exception(
            "stream publish failed",
            event_id=str(row.id),
        )

    return row


async def list_events(
    session: AsyncSession,
    *,
    host_id: uuid.UUID | None,
    since: datetime | None,
    limit: int,
    offset: int,
) -> list[Event]:
    stmt = select(Event).order_by(Event.received_at.desc()).limit(limit).offset(offset)
    if host_id is not None:
        stmt = stmt.where(Event.host_id == host_id)
    if since is not None:
        stmt = stmt.where(Event.received_at > since)
    result = await session.execute(stmt)
    return list(result.scalars().all())
