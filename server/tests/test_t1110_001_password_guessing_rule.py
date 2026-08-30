"""Tests for the T1110.001 Password Guessing Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1110_001_password_guessing.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- hydra brute-force tool against a service user   → fires
- medusa against admin                            → fires
- ncrack targeting sa                             → fires
- default user "admin" + default pwd "password"   → fires
- default user "root" + default pwd "toor"        → fires
- hydra against sshd binary (filter_legit)        → does NOT fire
- normal failure (alice/wrongpassword)            → does NOT fire
- substring trap: hydra vs dehydrated             → does NOT fire
- successful login (status=success) does not fire → does NOT fire
- non-auth event type                             → does NOT fire
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

RULE_ID = "4f7c2e8b-9a13-4d56-8e2a-1b6d5c9f0e34"


def _rules() -> list:
    return load_rules_from_dir(Path("rules/builtin/mitre_attack"))


def _find(rules: list):
    return next(r for r in rules if r.id == RULE_ID)


def _event(
    user: str = "alice",
    password: str = "wrongpass",
    command: str = "/usr/sbin/sshd-session",
    status: str = "failed",
    **md,
) -> ParsedEvent:
    meta = {
        "event_type": "auth_login",
        "user": user,
        "password": password,
        "command": command,
        "status": status,
        "source_ip": "203.0.113.10",
    }
    meta.update(md)
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="edr.auth",
        raw="",
        metadata=meta,
        occurred_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_hydra_bruteforce_tool_fires() -> None:
    """Hydra is a well-known password-guessing tool — must trigger."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="root",
        password="guess1",
        command="hydra -l root -P /tmp/wordlist.txt ssh://10.0.0.5",
    ))
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_medusa_against_admin_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="admin",
        password="admin123",
        command="medusa -h 10.0.0.5 -u admin -P pass.txt -M ssh",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_ncrack_against_sa_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="sa",
        password="sapwd",
        command="ncrack -u sa -P /usr/share/wordlists/rockyou.txt 10.0.0.5:445",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_default_admin_password_fires() -> None:
    """Common admin/admin and root/toor default credential pairs trigger."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="admin",
        password="password",
        command="/usr/bin/login",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_default_root_toor_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="root",
        password="toor",
        command="/usr/bin/su",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_sshd_bruteforce_filtered_by_legit() -> None:
    """filter_legit suppresses the legitimate sshd PAM path."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="root",
        password="toor",
        command="/usr/sbin/sshd-session",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_sudo_bruteforce_filtered_by_legit() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="admin",
        password="password",
        command="/usr/bin/sudo -S -k",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_normal_failed_login_does_not_fire() -> None:
    """A normal failed login for a non-default user is not T1110.001."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="alice",
        password="MyStr0ng!Pass#2026",
        command="/usr/bin/login",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_substring_trap_hydra_vs_dehydrated() -> None:
    """The 'hydra' anchor uses lookarounds so 'dehydrated' must NOT match.

    Uses a non-default credential so the rule only has the tool-name
    anchor to fire on — proving the lookarounds work.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="svc_backup",
        password="C0rrectHorseBatteryStaple!",
        command="/usr/sbin/dehydrated-hook.sh",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_substring_trap_admin_in_administrator_user() -> None:
    """Bare word 'admin' as prefix of 'administrator' must NOT match.

    Anchoring on (^|\\b) followed by word chars + (\\b|$) prevents
    'administrator' from being flagged as 'admin'.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="administrator_svc",
        password="changeme",
        command="/usr/bin/login",
    ))
    # 'administrator_svc' contains 'administrator' (which IS in our list)
    # but the anchor requires \\b/$ AFTER the literal — 'administrator'
    # is followed by '_svc', so the anchor must reject it.
    assert fires == []


@pytest.mark.asyncio
async def test_successful_login_does_not_fire() -> None:
    """selection requires status=failed; a successful login must not match."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        user="root",
        password="toor",
        command="/usr/bin/login",
        status="success",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_non_auth_event_type_does_not_fire() -> None:
    """selection requires event_type=auth_login."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    meta = {
        "event_type": "process_exec",
        "user": "root",
        "password": "toor",
        "command": "hydra -l root -P w.txt ssh://host",
        "status": "failed",
        "source_ip": "203.0.113.10",
    }
    fires = await runner.evaluate(ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="edr.process",
        raw="",
        metadata=meta,
        occurred_at=datetime.now(timezone.utc),
    ))
    assert fires == []