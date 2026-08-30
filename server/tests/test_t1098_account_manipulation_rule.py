"""Tests for the T1098 Account Manipulation Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1098_account_manipulation.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- useradd / adduser (account creation)                          → fires
- userdel / deluser (account deletion)                          → fires
- usermod (account mutation)                                    → fires
- groupadd / groupmod / gpasswd (group mutation)                → fires
- chsh / chfn (shell / GECOS change)                            → fires
- passwd invoked on another user (changing alice's pw)          → fires
- usermod -aG wheel (privilege escalation pattern)              → fires
- bare `passwd` (no arg, self-change)                           → does NOT fire
- passwd --help (flag-only invocation)                          → does NOT fire
- apt/dpkg invoking useradd (package manager)                   → does NOT fire
- adduser --system (package hook service account)               → does NOT fire
- substring trap: `usermodhelper` (process name collision)      → no fire
- substring trap: `passwdgen` (process name collision)           → no fire
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

RULE_ID = "9d4f1a62-3b7e-4c2d-8e5a-1f6b9c3d2e47"


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
async def test_useradd_fires() -> None:
    """Canonical post-foothold persistence: create a new user."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/useradd", "useradd -m -s /bin/bash backdoor")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_adduser_fires() -> None:
    """Debian-flavored account creation primitive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/adduser", "adduser --home /srv/ops ops")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_userdel_fires() -> None:
    """Account deletion — covers log-tampering cleanup of an old account."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/userdel", "userdel -r tempuser")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_usermod_fires() -> None:
    """Modifying an existing account (e.g. add to a privileged group)."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/usermod", "usermod -aG wheel alice")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_groupmod_fires() -> None:
    """Group mutation is a T1098 primitive too."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/groupmod", "groupmod -A users ops")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_gpasswd_fires() -> None:
    """gpasswd is the canonical group-admin tool — T1098 primitive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/gpasswd", "gpasswd -a alice sudo")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_chsh_fires() -> None:
    """Changing a user's login shell — persistence via shell swap."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/chsh", "chsh -s /bin/bash alice")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_passwd_other_user_fires() -> None:
    """`passwd alice` — changing another user's password is T1098."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/passwd", "passwd alice")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_bare_passwd_does_not_fire() -> None:
    """`passwd` with no argument = self-change, not account manipulation."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/passwd", "passwd")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_passwd_help_does_not_fire() -> None:
    """`passwd --help` — flag-only, not a manipulation step."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/passwd", "passwd --help")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_apt_useradd_does_not_fire() -> None:
    """Package manager hook creating a system account — noise filter."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/apt",
            "apt-get install -y nginx && useradd -r -M nginx",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_adduser_system_does_not_fire() -> None:
    """`adduser --system` is the package-hook idiom for service accounts."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/adduser", "adduser --system --no-create-home svc")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_usermodhelper_does_not_match() -> None:
    """Substring trap: process name `usermodhelper` (a custom binary) must
    NOT match the rule. The `\\b` boundary on the regex requires the
    utility to be its own token."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/local/bin/usermodhelper", "usermodhelper --check")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_passwdgen_does_not_match() -> None:
    """Substring trap: process `passwdgen` (password generator tool) must
    NOT match the `passwd <user>` branch. The regex requires the literal
    `passwd` followed by whitespace and a username-shaped argument."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/local/bin/passwdgen", "passwdgen 16")
    )
    assert fires == []
