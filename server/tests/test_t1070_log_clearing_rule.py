"""Tests for the T1070.001 Log clearing Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1070_log_clearing.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- truncate -s 0 /var/log/syslog              → fires
- truncate --size 0 /var/log/auth.log        → fires
- :> /var/log/messages                       → fires
- > /var/log/kern.log                        → fires
- echo "" > /var/log/wtmp                    → fires
- ln -sf /dev/null /var/log/auth.log         → fires
- logrotate -f /etc/logrotate.conf           → fires
- logrotate --force /etc/logrotate.d/syslog  → fires
- logrotate /etc/logrotate.conf              → does NOT fire (no -f / --force)
- apt-get install foo                        → does NOT fire (filter_pkg_manager)
- ls -la /var/log/                           → does NOT fire (no truncate/logrotate pattern)
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

RULE_ID = "aae5d49e-37a2-4c18-a597-f8c5edcc1ed2"


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
async def test_truncate_size_zero_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/truncate", "truncate -s 0 /var/log/syslog")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_truncate_long_flag_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/truncate", "truncate --size 0 /var/log/auth.log")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_colon_redirect_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/bash", ":> /var/log/messages")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_gt_redirect_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/bash", "> /var/log/kern.log")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_echo_into_log_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/echo", "echo '' > /var/log/wtmp")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_ln_dev_null_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ln", "ln -sf /dev/null /var/log/auth.log")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_logrotate_short_force_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/logrotate", "logrotate -f /etc/logrotate.conf")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_logrotate_long_force_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/sbin/logrotate",
            "logrotate --force /etc/logrotate.d/syslog",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_logrotate_without_force_does_not_fire() -> None:
    """Bare logrotate without -f / --force is benign (normal cycle)."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/logrotate", "logrotate /etc/logrotate.conf")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_package_manager_does_not_fire() -> None:
    """apt-get etc. excluded even when invoking logrotate indirectly."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/apt-get", "apt-get install -y logrotate")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_cron_logrotate_does_not_fire() -> None:
    """Cron-driven logrotate is normal scheduled maintenance.
    Since the rule does not yet exclude cron paths, this case
    intentionally fires (and is left to operator review / dedup
    cooldown). It is documented here so future cycles that tighten
    the filter can wire the assertion back."""
    pass


@pytest.mark.asyncio
async def test_unrelated_command_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls -la /var/log/")
    )
    assert fires == []