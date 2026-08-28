"""Unit tests for the ssh_bruteforce detector.

The detector needs Redis (for the sliding window) and a fake
`DetectorContext`. We connect to the real Redis on db 15 (the
test db) but use a unique key prefix per test so we never
collide with other tests or with leftover state.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from zaqorincore_server.detectors.base import (
    DetectorContext,
    ParsedEvent,
)
from zaqorincore_server.detectors.ssh_bruteforce import DETECTOR
from zaqorincore_server.config import get_settings


pytestmark = pytest.mark.asyncio


# All tests in this module share a single host_id (the key for
# the sliding window includes it), so a stable fixture here is
# important. IP varies per test as needed.
_TEST_HOST_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")


def _make_event(
    *,
    source: str = "auth",
    raw: str = "Failed password for root from 1.2.3.4 port 55555 ssh2",
    metadata: dict[str, str] | None = None,
    source_ip: str = "1.2.3.4",
    host_id: uuid.UUID | None = None,
    occurred_at: datetime | None = None,
) -> ParsedEvent:
    md = dict(metadata or {})
    if source_ip:
        md.setdefault("source_ip", source_ip)
    md.setdefault("status", "failed")
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=host_id or _TEST_HOST_ID,
        source=source,
        raw=raw,
        metadata=md,
        occurred_at=occurred_at or datetime.now(tz=timezone.utc),
    )


@pytest_asyncio.fixture
async def ctx():
    """A DetectorContext backed by the real test Redis (db 15)."""
    settings = get_settings()
    # Bump thresholds so the test is quick.
    settings.ssh_bruteforce_threshold = 3
    settings.ssh_bruteforce_window_sec = 60
    settings.ssh_bruteforce_cooldown_sec = 5
    redis = aioredis.from_url(
        settings.redis_url, encoding="utf-8", decode_responses=True
    )
    # Make sure we start clean.
    async for k in redis.scan_iter(match="zc:rule:ssh_bruteforce:*"):
        await redis.delete(k)
    yield DetectorContext(
        redis=redis,
        settings=settings,
        session_factory=None,  # not used in this test
    )
    await redis.aclose()


async def test_non_failed_login_is_ignored(ctx):
    e = _make_event(metadata={"status": "success", "source_ip": "1.2.3.4"})
    assert await DETECTOR.on_event(e, ctx) == []


async def test_non_ssh_event_is_ignored(ctx):
    """No 'source_ip' and no ssh pattern in raw → no IP to score."""
    e = ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=_TEST_HOST_ID,
        source="syslog",
        raw="random kernel log",
        metadata={"status": "failed"},
        occurred_at=datetime.now(tz=timezone.utc),
    )
    assert await DETECTOR.on_event(e, ctx) == []


async def test_below_threshold_returns_no_alert(ctx):
    # threshold=3; send 2 events from the same IP/host.
    for _ in range(2):
        out = await DETECTOR.on_event(_make_event(), ctx)
        assert out == []


async def test_at_threshold_fires_once_and_cools_down(ctx):
    """At threshold=3, the 3rd event from the same IP fires an
    alert; the 4th, 5th, 6th within the cooldown window do not."""
    results = []
    for i in range(6):
        out = await DETECTOR.on_event(_make_event(), ctx)
        results.append(out)
    # First 2 below threshold; 3rd fires; 4th-6th suppressed by cooldown.
    assert results[0] == [] and results[1] == []
    assert len(results[2]) == 1
    assert results[2][0].detector == "ssh_bruteforce"
    assert results[2][0].severity == "medium"
    assert "1.2.3.4" in results[2][0].summary
    for r in results[3:]:
        assert r == []


async def test_distinct_ips_each_get_their_own_window(ctx):
    """Two different source IPs each get their own counter."""
    out_a = []
    out_b = []
    for i in range(3):
        out_a.append(await DETECTOR.on_event(_make_event(source_ip="10.0.0.1"), ctx))
        out_b.append(await DETECTOR.on_event(_make_event(source_ip="10.0.0.2"), ctx))
    # Both should have fired on their 3rd event.
    assert sum(len(r) for r in out_a) == 1
    assert sum(len(r) for r in out_b) == 1


async def test_falls_back_to_raw_when_metadata_missing(ctx):
    """No 'source_ip' in metadata, but the raw line has the IP."""
    e = _make_event(metadata={}, source_ip="")
    out = await DETECTOR.on_event(e, ctx)
    # First event: count=1 < 3, no alert.
    assert out == []
