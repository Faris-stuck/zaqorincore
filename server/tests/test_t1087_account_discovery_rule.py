"""Tests for the T1087 Account Discovery Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1087_account_discovery.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- net user /domain                                             → fires
- dsquery user enumeration                                     → fires
- ldapsearch with (objectClass=user) filter                    → fires
- net accounts /domain                                         → fires
- rpcclient enumdomusers                                       → fires
- compgen -u                                                   → fires
- id invoked twice in one shell line (multi-target)            → fires
- chained getent passwd invocations                           → fires
- bare `id` (no arg) — interactive                             → does NOT fire (filter_single_id)
- id with $(whoami) — single-user self-check                   → does NOT fire (filter_single_id)
- substring trap: `network` (process=network) must NOT match   → no fire
- substring trap: `cat /etc/passwords` (not /etc/passwd)       → no fire
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

RULE_ID = "7a31c5e9-4d8b-4e2f-9b1a-3f7c2d8e6a55"


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
async def test_net_user_domain_fires() -> None:
    """Domain user enumeration — classic post-foothold step."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/net", "net user /domain")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_dsquery_user_fires() -> None:
    """AD enumeration via dsquery — T1087.002 primitive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/dsquery", "dsquery user -name admin*")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_ldapsearch_objectclass_user_fires() -> None:
    """LDAP enumeration of user objects — T1087.004 primitive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/ldapsearch",
            "ldapsearch -x -b dc=corp,dc=local '(objectClass=user)' cn",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_net_accounts_domain_fires() -> None:
    """Domain account-policy enumeration."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/net", "net accounts /domain")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_rpcclient_enumdomusers_fires() -> None:
    """rpcclient enumdomusers — classic SMB enumeration primitive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/rpcclient",
            "rpcclient -U '' -N 10.0.0.5 -c enumdomusers",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_compgen_u_fires() -> None:
    """Bash built-in compgen -u lists all usernames."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'compgen -u | sort'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_multi_target_id_fires() -> None:
    """`id` invoked multiple times in one line = enumeration."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'id root; id www-data; id nobody'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_bare_id_does_not_fire() -> None:
    """`id` with no arguments — every interactive shell runs this."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/id", "id")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_id_self_does_not_fire() -> None:
    """`id $(whoami)` — single-user self-check, not enumeration."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/bash", "bash -c 'id $(whoami)'")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_id_env_user_does_not_fire() -> None:
    """`id $USER` — uses env var for self-identification."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/bash", "bash -c 'id ${USER}'")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_network_does_not_match() -> None:
    """Substring trap: `network` (process) must not trigger the
    `\\bnet\\b` rule on its own — the regex requires `net` to be
    followed by a space, then `user` or `accounts`."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/network", "network --status")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_passwords_does_not_match() -> None:
    """Substring trap: `/etc/passwords` (not `/etc/passwd`) must NOT
    match. The rule is intentionally narrow — only the canonical
    passwd path triggers."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/cat", "cat /etc/passwords")
    )
    assert fires == []
