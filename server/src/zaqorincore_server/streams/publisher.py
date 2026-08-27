"""Redis Streams publisher.

The publisher's job is small but explicit: take a persisted event and
XADD it to the configured stream. The consumer side is a separate
module (consumer.py) that Phase 3 detectors will use.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from ..config import get_settings

logger = logging.getLogger(__name__)

# Module-level singleton — one client per process is enough.
_client: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    """Return a connected async Redis client. Idempotent."""
    global _client
    if _client is None:
        settings = get_settings()
        _client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _client


async def close_redis() -> None:
    """Close the client. Called from FastAPI lifespan shutdown."""
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None


async def ensure_consumer_group() -> None:
    """Create the consumer group if it doesn't already exist.

    We always start reading new messages (id '$') so the first run
    doesn't try to replay a backlog. Phase 3 will revisit this.
    """
    settings = get_settings()
    client = await get_redis()
    try:
        await client.xgroup_create(
            name=settings.stream_name,
            groupname=settings.stream_group,
            id="$",
            mkstream=True,
        )
        logger.info(
            "redis consumer group created",
            extra={
                "stream": settings.stream_name,
                "group": settings.stream_group,
            },
        )
    except ResponseError as exc:
        # BUSYGROUP means the group already exists. That's fine.
        if "BUSYGROUP" not in str(exc):
            raise
        logger.debug(
            "redis consumer group already exists",
            extra={
                "stream": settings.stream_name,
                "group": settings.stream_group,
            },
        )


async def publish_event(
    event_id: uuid.UUID,
    host_id: uuid.UUID,
    source: str,
    occurred_at: datetime,
) -> str:
    """XADD an event onto the stream. Returns the entry id."""
    settings = get_settings()
    client = await get_redis()
    entry_id = await client.xadd(
        name=settings.stream_name,
        fields={
            "event_id": str(event_id),
            "host_id": str(host_id),
            "source": source,
            "occurred_at_unix": str(int(occurred_at.timestamp())),
        },
        maxlen=settings.stream_maxlen,
        approximate=True,  # ~ in XADD = efficient trim
    )
    return entry_id
