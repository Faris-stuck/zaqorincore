"""Detector runner — owns the XREADGROUP loop.

Spawned once per server process, started in the FastAPI
lifespan, cancelled on shutdown. Reads events off the
`zaqorin:events` stream via the `zaqorin-detectors` consumer
group, fans them through every registered detector, persists
alerts for any `DetectionResult` returned, and acks the
stream message only after persistence succeeds (or fails —
we ack-on-error too, otherwise one bad message blocks the
whole stream).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..config import Settings
from ..streams.publisher import ensure_consumer_group, get_redis
from .alert_service import write_alert
from .base import Detector, DetectorContext, ParsedEvent
from . import BUILTIN_DETECTORS

logger = logging.getLogger(__name__)


# Block timeout on XREADGROUP. Long enough that idle periods
# don't hammer Redis, short enough that the cancel propagates
# within ~1s when the server is shutting down.
_BLOCK_MS = 1000
_BATCH = 100
# Per-message processing timeout. Detectors should be fast; if
# one is stuck, we drop the message and move on.
_MSG_TIMEOUT_SEC = 5.0


def _consumer_name() -> str:
    return f"zaqorin-detector-{os.getpid()}"


def _parse_event(fields: dict[str, str]) -> ParsedEvent | None:
    """Build a ParsedEvent from a stream entry's fields.

    The publisher writes `event_id`, `host_id`, `source`,
    `occurred_at_unix`; everything else (raw, metadata) lives
    in the DB row referenced by `event_id`. We re-read the
    event row to get the full payload. This is the price of
    keeping the stream entries small.
    """
    # We don't actually have raw/metadata in the stream — we
    # need to fetch them from the DB. The runner does that
    # inline; this helper only constructs the partial
    # ParsedEvent that the lookup will fill in.
    try:
        return ParsedEvent(
            event_id=_to_uuid(fields["event_id"]),
            host_id=_to_uuid(fields["host_id"]),
            source=fields.get("source", ""),
            raw="",  # filled in by the runner after DB lookup
            metadata={},
            occurred_at=datetime.fromtimestamp(
                int(fields["occurred_at_unix"]), tz=timezone.utc
            ),
        )
    except (KeyError, ValueError) as exc:
        logger.warning("malformed stream entry: %s", exc)
        return None


def _to_uuid(s: str) -> Any:
    import uuid as _uuid

    return _uuid.UUID(s)


async def _load_event_payload(
    session_factory: async_sessionmaker[Any],
    event_id: Any,
) -> tuple[str, dict[str, str]] | None:
    """Fetch raw + metadata for a single event by id."""
    from sqlalchemy import select

    from ..models.event import Event

    async with session_factory() as session:
        stmt = select(Event.raw, Event.metadata_).where(Event.id == event_id)
        result = await session.execute(stmt)
        row = result.one_or_none()
        if row is None:
            return None
        raw, meta = row
        # meta is JSONB; coerce keys to str.
        return raw, {str(k): str(v) for k, v in (meta or {}).items()}


async def _process_one(
    msg_id: str,
    fields: dict[str, str],
    detectors: list[Detector],
    ctx: DetectorContext,
    session_factory: async_sessionmaker[Any],
    redis: aioredis.Redis,
) -> None:
    """Process a single stream entry: load, fan out, alert, ack."""
    parsed = _parse_event(fields)
    if parsed is None:
        await redis.xack(ctx.settings.stream_name, ctx.settings.stream_group, msg_id)
        return

    payload = await _load_event_payload(session_factory, parsed.event_id)
    if payload is None:
        # Event row was deleted between publish and consume.
        # Ack and move on.
        await redis.xack(ctx.settings.stream_name, ctx.settings.stream_group, msg_id)
        return
    raw, meta = payload
    parsed = ParsedEvent(
        event_id=parsed.event_id,
        host_id=parsed.host_id,
        source=parsed.source,
        raw=raw,
        metadata=meta,
        occurred_at=parsed.occurred_at,
    )

    for detector in detectors:
        try:
            results = await asyncio.wait_for(
                detector.on_event(parsed, ctx),
                timeout=_MSG_TIMEOUT_SEC,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "detector timed out, skipping message",
                extra={"detector": detector.name, "msg_id": msg_id},
            )
            continue
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.exception(
                "detector raised, skipping message",
                extra={"detector": detector.name, "err": str(exc)},
            )
            continue

        for r in results:
            alert_id: uuid.UUID | None = None
            try:
                alert_id = await write_alert(
                    session_factory,
                    detector=r.detector,
                    severity=r.severity,
                    summary=r.summary,
                    detail=r.detail,
                    host_id=parsed.host_id,
                    dedup_key=r.dedup_key,
                    cooldown_sec=r.cooldown_sec,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "alert write failed",
                    extra={"detector": r.detector, "err": str(exc)},
                )

            # Phase 4: if the detector also returned a
            # DetectionAction, enqueue a pending Action row.
            # The dispatcher picks it up on its next tick.
            if alert_id is not None and r.action is not None:
                try:
                    from . import action_service

                    await action_service.write_action(
                        session_factory,
                        host_id=parsed.host_id,
                        alert_id=alert_id,
                        kind=r.action.kind,
                        target=r.action.target,
                        ttl_sec=r.action.ttl_sec,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "action enqueue failed",
                        extra={
                            "detector": r.detector,
                            "kind": r.action.kind,
                            "err": str(exc),
                        },
                    )

    await redis.xack(ctx.settings.stream_name, ctx.settings.stream_group, msg_id)


async def _process_sigma_one(
    msg_id: str,
    fields: dict[str, str],
    ctx: DetectorContext,
    session_factory: async_sessionmaker[Any],
    redis: aioredis.Redis,
) -> None:
    """Phase 6: run Sigma rules against one event and persist
    any fires as alerts + actions. Mirrors _process_one but
    uses the rule engine instead of Python detector plugins.
    """
    parsed = _parse_event(fields)
    if parsed is None:
        return
    payload = await _load_event_payload(session_factory, parsed.event_id)
    if payload is None:
        return
    raw, meta = payload
    parsed = ParsedEvent(
        event_id=parsed.event_id,
        host_id=parsed.host_id,
        source=parsed.source,
        raw=raw,
        metadata=meta,
        occurred_at=parsed.occurred_at,
    )

    from ..rule_engine import SigmaRuleRunner, persist_fire
    from ..rule_engine.sigma import load_rules_from_dir

    rules_dir = ctx.settings.rules_dir
    rules = load_rules_from_dir(rules_dir)
    if not rules:
        return
    sigma_runner = SigmaRuleRunner(redis, rules)
    fires = await sigma_runner.evaluate(parsed)
    for fire in fires:
        try:
            async with session_factory() as session:
                await persist_fire(session, fire)
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "sigma fire persist failed",
                extra={"rule": fire.rule.id, "err": str(exc)},
            )


async def run() -> None:
    """Main consumer loop. Runs until cancelled."""
    settings: Settings = _settings()  # type: ignore[name-defined]
    redis = await get_redis()
    await ensure_consumer_group()

    from ..db import get_session_factory

    session_factory: async_sessionmaker[Any] = get_session_factory()
    ctx = DetectorContext(
        redis=redis,
        settings=settings,
        session_factory=session_factory,
    )

    consumer = _consumer_name()
    logger.info(
        "detector runner started",
        extra={
            "stream": settings.stream_name,
            "group": settings.stream_group,
            "consumer": consumer,
            "detectors": [d.name for d in BUILTIN_DETECTORS],
        },
    )

    stop = False

    def _stop(*_: object) -> None:
        nonlocal stop
        stop = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass  # Windows / restricted envs

    while not stop:
        try:
            entries = await redis.xreadgroup(
                groupname=settings.stream_group,
                consumername=consumer,
                streams={settings.stream_name: ">"},
                count=_BATCH,
                block=_BLOCK_MS,
            )
        except aioredis.ResponseError as exc:
            if "NOGROUP" in str(exc):
                await ensure_consumer_group()
                continue
            logger.exception("xreadgroup failed, retrying")
            await asyncio.sleep(1)
            continue
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.exception("consumer loop error: %s", exc)
            await asyncio.sleep(1)
            continue

        for _stream, msgs in entries or []:
            for msg_id, fields in msgs:
                try:
                    await _process_one(
                        msg_id,
                        fields,
                        BUILTIN_DETECTORS,
                        ctx,
                        session_factory,
                        redis,
                    )
                    # Phase 6: also evaluate Sigma rules.
                    await _process_sigma_one(
                        msg_id,
                        fields,
                        ctx,
                        session_factory,
                        redis,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "process_one failed for %s: %s", msg_id, exc
                    )
                    # Best-effort ack so the stream doesn't stall.
                    try:
                        await redis.xack(
                            settings.stream_name,
                            settings.stream_group,
                            msg_id,
                        )
                    except Exception:  # noqa: BLE001
                        pass

    logger.info("detector runner stopped")


# Helper so `run()` can grab settings at call time without a
# module-level import (avoids a circular import with main.py).
def _settings() -> Settings:
    from ..config import get_settings

    return get_settings()


__all__ = ["run", "BUILTIN_DETECTORS"]
