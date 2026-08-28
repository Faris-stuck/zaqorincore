"""Tests for the Sigma rule runner (runner.py).

Uses fakeredis to simulate the Redis state. We exercise:
  - basic matching + firing
  - sliding window (count threshold)
  - cooldown
  - action rendering
  - dedup_key
  - builtin rules load
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.runner import SigmaRuleRunner
from zaqorincore_server.rule_engine.sigma import (
    CompiledSigmaRule,
    load_rules_from_dir,
    parse_rule_file,
)
from .fake_redis import FakeRedis


def _event(**metadata) -> ParsedEvent:
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="sshd",
        raw="Failed password for root from 203.0.113.42 port 54321 ssh2",
        metadata=metadata,
        occurred_at=datetime.now(timezone.utc),
    )


def _ssh_bf_rule() -> CompiledSigmaRule:
    yaml = """
title: SSH bf
id: ssh-bf
level: high
detection:
  selection:
    source: "sshd"
    status: "failed"
  condition: selection
  timeframe: 60s
  count: 5
action:
  kind: block_ip
  target: "{{source_ip}}"
  ttl_sec: 3600
cooldown_sec: 300
dedup_key: "{{source_ip}}"
"""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(yaml)
        p = f.name
    return parse_rule_file(Path(p))[0]


@pytest.mark.asyncio
async def test_runner_fires_after_threshold() -> None:
    redis = FakeRedis()
    rule = _ssh_bf_rule()
    runner = SigmaRuleRunner(redis, [rule])
    # 4 events below threshold — should not fire.
    for _ in range(4):
        fires = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
        assert fires == []
    # 5th event — should fire once.
    fires = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    assert len(fires) == 1
    fire = fires[0]
    assert fire.rule.id == "ssh-bf"
    assert fire.count == 5
    assert fire.rendered_action == {
        "kind": "block_ip", "target": "1.2.3.4", "ttl_sec": 3600,
    }

@pytest.mark.asyncio
async def test_runner_does_not_fire_when_selection_fails() -> None:
    redis = FakeRedis()
    runner = SigmaRuleRunner(redis, [_ssh_bf_rule()])
    # 6 events that DO NOT match selection.
    for _ in range(6):
        fires = await runner.evaluate(_event(source_ip="1.2.3.4", status="ok", source="sshd"))
    assert fires == []


@pytest.mark.asyncio
async def test_runner_dedups_per_source_ip() -> None:
    redis = FakeRedis()
    runner = SigmaRuleRunner(redis, [_ssh_bf_rule()])
    # 5 events from IP A — should fire once.
    last_a = []
    for _ in range(5):
        last_a = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    assert len(last_a) == 1
    # Cooldown for IP A is set; another event for IP A should not fire.
    fires = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    assert fires == []
    # 5 events from IP B — also fires (different dedup key).
    last_b = []
    for _ in range(5):
        last_b = await runner.evaluate(_event(source_ip="5.6.7.8", status="failed", source="sshd"))
    assert len(last_b) == 1
    assert last_b[0].dedup_key == "5.6.7.8"


@pytest.mark.asyncio
async def test_runner_cooldown_blocks_repeat() -> None:
    redis = FakeRedis()
    runner = SigmaRuleRunner(redis, [_ssh_bf_rule()])
    # First burst — fires.
    for _ in range(5):
        await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    # Immediate second burst — cooldown blocks.
    fires = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    assert fires == []


@pytest.mark.asyncio
async def test_runner_sliding_window_drops_old_events() -> None:
    redis = FakeRedis()
    # Use a fixed clock so we can advance time.
    clock = [1000.0]
    rule = _ssh_bf_rule()  # 5 in 60s
    runner = SigmaRuleRunner(redis, [rule], clock=lambda: clock[0])
    # 3 events at t=0.
    for _ in range(3):
        await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    # Advance past the 60s window.
    clock[0] += 120
    # 2 more events at t=120 — the old 3 are out of the window.
    for _ in range(2):
        fires = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
        assert fires == []
    # A 3rd event at t=120 brings the count to 3, still under threshold.
    fires = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    assert fires == []


@pytest.mark.asyncio
async def test_runner_hunt_mode() -> None:
    redis = FakeRedis()
    runner = SigmaRuleRunner(redis, [_ssh_bf_rule()], mode="hunt")
    assert runner.mode == "hunt"
    # Hunt mode also fires — same matching, just doesn't persist.
    last = []
    for _ in range(5):
        last = await runner.evaluate(_event(source_ip="1.2.3.4", status="failed", source="sshd"))
    assert len(last) == 1
    assert last[0].rule.id == "ssh-bf"


def test_builtin_rules_load() -> None:
    """The 5 builtin rules ship under rules/builtin/ and all load."""
    rules = load_rules_from_dir(Path("rules/builtin"))
    ids = {r.id for r in rules}
    assert "builtin-ssh-bruteforce" in ids
    assert "builtin-port-scan" in ids
    assert "builtin-web-attack" in ids
    assert "builtin-dns-tunnel" in ids
    assert "builtin-impossible-travel" in ids
    # All have the required fields populated.
    for r in rules:
        assert r.title
        assert r.level in ("low", "medium", "high", "critical")
        assert r.timeframe_sec > 0
        assert r.count >= 1
        assert r.cooldown_sec >= 0
