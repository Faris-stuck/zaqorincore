"""Tests for the T1070.004 Indicator removal — file deletion Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1070_file_deletion.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- rm -rf /var/log/*                                 → fires
- shred -v /root/.bash_history                      → fires
- rm -rf /etc/ssh                                   → fires
- find /var/log -type f -delete                     → fires
- apt-get purge ...                                 → does NOT fire (pkg filter)
- rm -f /tmp/single-file                            → does NOT fire (no -r flag)
- random unrelated process                          → does NOT fire
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

RULE_ID = "4d8a1c6e-9b3f-4a2e-b7c5-3e6f8d1a4b09"


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
async def test_rm_rf_var_log_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/rm", "rm -rf /var/log/*", source_ip="203.0.113.30")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_shred_bash_history_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/shred", "shred -v -z -u /root/.bash_history")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_rm_rf_etc_ssh_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/rm", "rm -rf /etc/ssh/")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_find_delete_var_log_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/find", "find /var/log -type f -delete")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_wipe_command_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/wipe", "wipe -rf /var/log/journal/")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_apt_purge_does_not_fire() -> None:
    """Package manager removal is legitimate (uninstall, cleanup)."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/apt-get",
            "apt-get purge -y nginx && rm -rf /etc/nginx",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_rm_single_file_does_not_fire() -> None:
    """Single-file rm without -r is not mass-deletion behaviour."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/rm", "rm -f /tmp/scratch.log")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_unrelated_process_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls /var/log/")
    )
    assert fires == []