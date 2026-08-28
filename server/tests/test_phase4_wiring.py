"""Phase 4 wiring: detector + alert_service + action_service
together, no Redis Streams. We feed the detector ParsedEvent
objects directly and assert that BOTH an Alert and an Action
row are produced when the detector returns a DetectionResult
with a DetectionAction attached."""

from __future__ import annotations

import datetime as _dt
import uuid

import pytest
import redis.asyncio as aioredis
from sqlalchemy import select

from zaqorincore_server.config import get_settings
from zaqorincore_server.detectors import action_service
from zaqorincore_server.detectors.alert_service import write_alert
from zaqorincore_server.detectors.base import (
    DetectionResult,
    DetectorContext,
    ParsedEvent,
)
from zaqorincore_server.detectors.ssh_bruteforce import (
    SSHBruteForceDetector,
)
from zaqorincore_server.models import Action, Alert, Host

pytestmark = pytest.mark.asyncio


async def _make_ctx(engine) -> DetectorContext:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    settings = get_settings()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return DetectorContext(
        redis=redis,
        settings=settings,
        session_factory=async_sessionmaker(engine, expire_on_commit=False),
    )


async def test_ssh_bruteforce_attaches_block_action(
    engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The detector sets `action=DetectionAction(kind=block_ip, target=src_ip)`
    on the first fire (and resets to None during cooldown)."""
    settings = get_settings()
    monkeypatch.setattr(settings, "ssh_bruteforce_threshold", 2)
    monkeypatch.setattr(settings, "ssh_bruteforce_window_sec", 60)
    monkeypatch.setattr(settings, "ssh_bruteforce_cooldown_sec", 60)

    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()
    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret="s",
            )
        )
        await session.commit()

    src_ip = "198.51.100.7"
    ctx = await _make_ctx(engine)
    det = SSHBruteForceDetector()

    # 1st event: count=1, below threshold.
    pe1 = ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=host_id,
        source="sshd",
        raw=f"Failed password for root from {src_ip} port 50001 ssh2",
        metadata={"status": "failed", "source_ip": src_ip},
        occurred_at=_dt.datetime.now(_dt.timezone.utc),
    )
    r1 = await det.on_event(pe1, ctx)
    assert r1 == []  # below threshold

    # 2nd event: count=2, at threshold -> first fire.
    pe2 = ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=host_id,
        source="sshd",
        raw=f"Failed password for root from {src_ip} port 50002 ssh2",
        metadata={"status": "failed", "source_ip": src_ip},
        occurred_at=_dt.datetime.now(_dt.timezone.utc),
    )
    r2 = await det.on_event(pe2, ctx)
    assert len(r2) == 1
    result = r2[0]
    assert result.action is not None
    assert result.action.kind == "block_ip"
    assert result.action.target == src_ip
    assert result.action.ttl_sec == 3600

    # 3rd event: cooldown still active -> no fire.
    pe3 = ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=host_id,
        source="sshd",
        raw=f"Failed password for root from {src_ip} port 50003 ssh2",
        metadata={"status": "failed", "source_ip": src_ip},
        occurred_at=_dt.datetime.now(_dt.timezone.utc),
    )
    r3 = await det.on_event(pe3, ctx)
    assert r3 == []  # cooldown

    # Now persist the alert + action and verify the DB.
    alert_id = await write_alert(
        factory,
        detector=result.detector,
        severity=result.severity,
        summary=result.summary,
        detail=result.detail,
        host_id=host_id,
        dedup_key=result.dedup_key,
        cooldown_sec=result.cooldown_sec,
    )
    assert alert_id is not None
    action_id = await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=alert_id,
        kind=result.action.kind,
        target=result.action.target,
        ttl_sec=result.action.ttl_sec,
    )
    assert action_id is not None

    async with factory() as session:
        alerts = (
            (
                await session.execute(
                    select(Alert).where(Alert.host_id == host_id)
                )
            )
            .scalars()
            .all()
        )
        actions = (
            (
                await session.execute(
                    select(Action).where(Action.host_id == host_id)
                )
            )
            .scalars()
            .all()
        )
        assert len(alerts) == 1
        assert alerts[0].detector == "ssh_bruteforce"
        assert len(actions) == 1
        assert actions[0].kind == "block_ip"
        assert actions[0].target == src_ip
        assert actions[0].status == "pending"
        assert actions[0].alert_id == alert_id

    await ctx.redis.aclose()


async def test_detection_result_without_action_is_alert_only(
    engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the detector returns a DetectionResult with action=None,
    no Action row is enqueued (defensive: don't break v0.3.0
    detectors)."""
    settings = get_settings()
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()
    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret="s",
            )
        )
        await session.commit()

    # Simulate v0.3.0-style result: no action.
    result = DetectionResult(
        detector="ssh_bruteforce",
        severity="medium",
        summary="from 1.1.1.1: 3 failed logins in 60s",
        detail={"source_ip": "1.1.1.1", "count": 3},
        action=None,  # explicit
    )
    alert_id = await write_alert(
        factory,
        detector=result.detector,
        severity=result.severity,
        summary=result.summary,
        detail=result.detail,
        host_id=host_id,
    )
    assert alert_id is not None
    # The runner's branch: `if alert_id is not None and r.action is not None`
    # doesn't fire, so no action row.
    async with factory() as session:
        actions = (
            (
                await session.execute(
                    select(Action).where(Action.host_id == host_id)
                )
            )
            .scalars()
            .all()
        )
        assert actions == []
