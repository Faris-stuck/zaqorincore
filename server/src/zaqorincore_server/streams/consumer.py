"""Redis Streams consumer stub.

The real consumer is a separate process started by Phase 3's
detector pipeline. This module exists so the path is exercisable in
smoke tests and so a `make consume` style command works locally.
"""

from __future__ import annotations

import logging
import signal

import redis.asyncio as aioredis

from ..config import get_settings
from .publisher import get_redis

logger = logging.getLogger(__name__)


async def run_consumer() -> None:
    """Read new entries from the events stream and log them.

    The detector pipeline replaces this body in Phase 3. Until then
    this is the placeholder: it proves the wiring is end-to-end.
    """
    settings = get_settings()
    client = await get_redis()

    stop = False

    def _stop(*_: object) -> None:
        nonlocal stop
        stop = True

    loop = __import__("asyncio").get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass  # Windows / restricted envs

    logger.info(
        "redis consumer started",
        extra={
            "stream": settings.stream_name,
            "group": settings.stream_group,
        },
    )

    while not stop:
        try:
            entries = await client.xreadgroup(
                groupname=settings.stream_group,
                consumername="stub",
                streams={settings.stream_name: ">"},
                count=10,
                block=1000,  # ms
            )
        except aioredis.ResponseError as exc:
            # NOGROUP: group not yet created. Re-create and retry.
            if "NOGROUP" in str(exc):
                from .publisher import ensure_consumer_group

                await ensure_consumer_group()
                continue
            raise

        for _stream, msgs in entries or []:
            for msg_id, fields in msgs:
                logger.info(
                    "redis consumer received",
                    extra={
                        "msg_id": msg_id,
                        "event_id": fields.get("event_id"),
                        "host_id": fields.get("host_id"),
                        "source": fields.get("source"),
                    },
                )
                await client.xack(
                    settings.stream_name, settings.stream_group, msg_id
                )

    logger.info("redis consumer stopped")
