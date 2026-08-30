"""Tests for the T1056.001 Keylogging Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1056_001_keylogging.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- logkeys tool execution                          → fires
- xspy on X11 session                             → fires
- ad-hoc strace -e read on /dev/input             → fires
- write to /var/log/kbdlog                        → fires
- write to /tmp/.logkeys                          → fires
- xdotool (legitimate input automation)           → does NOT fire
- xset (legitimate keyboard config)               → does NOT fire
- normal strace (no -e read, e.g. -e trace=open) → does NOT fire
- substring trap: logkeys vs logkeyed.bin         → does NOT fire
- non-process event type                          → does NOT fire
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

RULE_ID = "2b4e7c91-5d3a-4f8b-9e6c-1a2b3c4d5e6f"


def _rules() -> list:
    return load_rules_from_dir(Path("rules/builtin/mitre_attack"))


def _find(rules: list):
    return next(r for r in rules if r.id == RULE_ID)


def _event(command: str, user: str = "root", **md) -> ParsedEvent:
    meta = {
        "event_type": "process_create",
        "user": user,
        "command": command,
        "process": command.split()[0] if command else "",
        "source_ip": "203.0.113.50",
    }
    meta.update(md)
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="edr.process",
        raw="",
        metadata=meta,
        occurred_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_logkeys_tool_fires() -> None:
    """The `logkeys` tool is a well-known Linux keylogger — must trigger."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="logkeys --start --output /var/log/kbdlog",
    ))
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_xspy_x11_fires() -> None:
    """xspy sniffs X11 keyboard events."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="xspy -display :0",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_strace_read_on_input_fires() -> None:
    """strace -e read on /dev/input/eventN is the ad-hoc keylogger technique."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="strace -e read -p 1234 -o /tmp/strace.out /dev/input/event0",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_kbdlog_path_fires() -> None:
    """Writing to the canonical keylogger output path fires."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="/usr/bin/tee /var/log/kbdlog",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_tmp_dot_logkeys_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="/bin/sh -c 'cat /tmp/.logkeys'",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_xdotool_filtered() -> None:
    """xdotool is legitimate input automation, not keylogging."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="xdotool type 'hello world'",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_xset_filtered() -> None:
    """xset configures X11 keyboard — filtered out as legitimate input tooling."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="xset r rate 200 30",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_plain_strace_does_not_fire() -> None:
    """strace without -e read is general debugging — must NOT fire."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="strace -e trace=open,openat -p 1234",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_substring_trap_logkeys_vs_logkeyed() -> None:
    """Word-boundary anchors must NOT match 'logkeys' inside 'logkeyed.bin'.

    A naive substring search would flag any process whose argv contains
    the letters 'logkeys'; the lookarounds require the token to be
    delimited by non-word chars on both sides.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        command="/opt/backup/logkeyed.bin --rotate",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_non_process_event_does_not_fire() -> None:
    """selection requires event_type=process_create."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    meta = {
        "event_type": "file_write",
        "user": "root",
        "command": "logkeys --start",
        "process": "logkeys",
        "source_ip": "203.0.113.50",
    }
    fires = await runner.evaluate(ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="edr.file",
        raw="",
        metadata=meta,
        occurred_at=datetime.now(timezone.utc),
    ))
    assert fires == []