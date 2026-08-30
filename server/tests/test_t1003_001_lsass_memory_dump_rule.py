"""Tests for the T1003.001 LSASS memory dump Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1003_001_lsass_memory_dump.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- procdump -ma lsass.exe                    → fires
- rundll32 comsvcs.dll MiniDump lsass       → fires
- mimikatz sekurlsa::logonpasswords         → fires
- pwdump / gsecdump / fgdump on lsass.exe   → fires
- procdump -ma lsass.exe to AV-known path   → does NOT fire (filter_lab)
- procdump on a different process           → does NOT fire
- mimikatz against a non-lsass target       → does NOT fire
- substring trap: lsass.dll vs lsass.exe    → does NOT fire
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

RULE_ID = "a3b8e2d1-6f47-4c89-9b12-7e4d5a8c1f90"


def _rules() -> list:
    return load_rules_from_dir(Path("rules/builtin/mitre_attack"))


def _find(rules: list):
    return next(r for r in rules if r.id == RULE_ID)


def _event(target_file: str, command: str, **md) -> ParsedEvent:
    meta = {
        "event_type": "process_access",
        "target_file": target_file,
        "command": command,
        "user": "alice",
        "source_ip": "203.0.113.10",
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
async def test_procdump_lsass_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file=r"C:\Windows\System32\lsass.exe",
        command="procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
    ))
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_rundll32_comsvcs_minidump_fires() -> None:
    """The classic LOLBIN chain: rundll32 comsvcs.dll MiniDump."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file=r"C:\Windows\System32\lsass.exe",
        command="rundll32.exe comsvcs.dll MiniDump 648 C:\\Temp\\lsass.dmp full",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_mimikatz_sekurlsa_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file=r"C:\Windows\System32\lsass.exe",
        command="mimikatz.exe sekurlsa::logonpasswords",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_pwdump_on_lsass_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file="lsass.exe",
        command="pwdump.exe /o lsass.dmp",
    ))
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_lab_procdump_to_known_av_path_does_not_fire() -> None:
    """filter_lab suppresses procdump writes to legitimate debug paths."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file=r"C:\Windows\System32\lsass.exe",
        command="procdump.exe -ma lsass.exe C:\\WINDOWS\\Temp\\debug.dmp",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_procdump_on_other_process_does_not_fire() -> None:
    """Procdump is legitimate for many processes; only lsass.exe matters."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file=r"C:\Windows\System32\svchost.exe",
        command="procdump.exe -ma svchost.exe svchost.dmp",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_mimikatz_against_non_lsass_does_not_fire() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file=r"C:\Windows\System32\lsass.dll",
        command="mimikatz.exe crypto::exportPFX",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_substring_trap_lsass_dll_does_not_fire() -> None:
    """lsass.dll contains 'lsass.exe' as substring but anchored to .dll suffix.

    The anchored pattern requires 'lsass.exe' to end at word boundary, so
    'lsass.dll' (a legit resource DLL) must not trigger.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(_event(
        target_file=r"C:\Windows\System32\lsass.dll",
        command="rundll32.exe lsass.dll SomeExport",
    ))
    assert fires == []


@pytest.mark.asyncio
async def test_unrelated_event_type_does_not_fire() -> None:
    """T1003.001 selection requires event_type=process_access."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    meta = {
        "event_type": "file_write",
        "target_file": r"C:\Windows\System32\lsass.exe",
        "command": "procdump.exe -ma lsass.exe out.dmp",
        "user": "alice",
        "source_ip": "203.0.113.10",
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