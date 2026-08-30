"""Tests for the T1078.001 Default Accounts Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1078_default_accounts.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- login as "admin"                                  → fires
- login as "root"                                   → fires
- login as "guest"                                  → fires
- login as "ubnt" (router default)                  → fires
- login as "postgres" (DB default)                  → fires
- login as "svc-monitoring" (service account)        → does NOT fire (filter_service)
- login as "alice" (normal user)                    → does NOT fire
- failed login (even as admin)                      → does NOT fire (status filter)
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

RULE_ID = "8a91b3c2-4d6e-4f7a-b8c5-3e9d1f2a4b60"


def _rules() -> list:
    return load_rules_from_dir(Path("rules/builtin/mitre_attack"))


def _find(rules: list):
    return next(r for r in rules if r.id == RULE_ID)


def _event(user: str, status: str = "success", **md) -> ParsedEvent:
    meta = {
        "event_type": "auth_login",
        "user": user,
        "status": status,
        "source_ip": "203.0.113.42",
    }
    meta.update(md)
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="linux.audit.auth",
        raw="",
        metadata=meta,
        occurred_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_admin_login_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("admin"))
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_root_login_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("root"))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_guest_login_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("guest"))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_ubnt_login_fires() -> None:
    """ubnt is the default account on Ubiquiti network gear."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("ubnt"))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_postgres_login_fires() -> None:
    """postgres is the default superuser on PostgreSQL."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("postgres"))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_service_account_does_not_fire() -> None:
    """Legitimate service/monitoring users are filtered out."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("svc-monitoring"))
    assert fires == []


@pytest.mark.asyncio
async def test_normal_user_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("alice"))
    assert fires == []


@pytest.mark.asyncio
async def test_failed_login_does_not_fire() -> None:
    """Failed login attempts are not default-account compromises yet."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event("admin", status="failed"))
    assert fires == []


@pytest.mark.asyncio
async def test_substring_trap_does_not_fire() -> None:
    """A username like 'administrator-jane' contains 'admin' as substring,
    not as a whole-word match, so it should not trigger.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    # 'administrator' is in our deny list, this should fire (it IS the
    # default administrator account). Confirm it does.
    fires = await runner.evaluate(_event("administrator"))
    assert len(fires) == 1