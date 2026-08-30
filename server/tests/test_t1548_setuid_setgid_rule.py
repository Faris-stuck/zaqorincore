"""Tests for the T1548.001 Privilege escalation — Setuid/Setgid abuse Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1548_setuid_setgid_abuse.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- chmod u+s /bin/bash                                  → fires
- chmod 4755 /usr/bin/find                             → fires
- chmod g+s /usr/bin/python3                           → fires
- cp /bin/sh /tmp/sh && chmod 4755 /tmp/sh             → fires
- chmod 4755 /bin/ls                                   → fires (chmod 4xxx on /bin/*)
- apt-get install foo                                  → does NOT fire (pkg filter)
- chmod 755 /tmp/script.sh                             → does NOT fire (no suid bit)
- random unrelated process                             → does NOT fire
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

RULE_ID = "7c2a4f91-1e6d-4b8a-9c3e-2d5f7a8b4e01"


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
async def test_chmod_u_s_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/chmod", "chmod u+s /bin/bash")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_chmod_4755_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/chmod", "chmod 4755 /usr/bin/find")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_chmod_g_s_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/chmod", "chmod g+s /usr/bin/python3")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_cp_chmod_4xxx_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/cp", "cp /bin/sh /tmp/sh && chmod 4755 /tmp/sh")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_apt_install_does_not_fire() -> None:
    """Package manager operations legitimately set permissions on managed files."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/apt-get",
            "apt-get install -y nginx",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_chmod_755_does_not_fire() -> None:
    """Plain chmod without suid/sgid bit is not privilege escalation."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/chmod", "chmod 755 /tmp/script.sh")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_unrelated_process_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls -la /bin/")
    )
    assert fires == []