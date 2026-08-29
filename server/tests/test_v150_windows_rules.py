"""Tests for the v1.5.0 Windows Sigma rule expansion.

5 new rules:
- T1059 cmd from Office (T1059.003, parent ∈ Office)
- T1546 WMI subscription (T1546.012, 5861)
- T1547 Startup folder (T1547.001, 4663 + path regex)
- T1053 Scheduled task (T1053.005, 4698)
- T1078 RDP from unusual source (T1078, 4624 type 10)
"""

from pathlib import Path

import pytest

from zaqorincore_server.rule_engine.runner import SigmaRuleRunner
from .fake_redis import FakeRedis


def _windows_rules():
    from zaqorincore_server.rule_engine.sigma import load_rules_from_dir
    return load_rules_from_dir(
        Path("rules/builtin/windows_eventlog")
    )


def _find(rules, rule_id):
    for r in rules:
        if r.id == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not found")


# Reuse the _event helper from test_windows_eventlog_rules
# (avoids duplicating uuid + datetime plumbing)
from tests.test_windows_eventlog_rules import _event  # noqa: E402


@pytest.mark.asyncio
async def test_t1059_cmd_from_office_fires_on_office_parent() -> None:
    """cmd.exe spawned by winword.exe during off-hours → fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4688-cmd-from-office")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            process_name="cmd.exe",
            parent_process_name="winword.exe",
            pid=9999,
            **{"metadata.hour": "23"},
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_t1059_cmd_from_office_no_fire_on_business_hour() -> None:
    """cmd.exe from Office during business hours → no fire (off-hours rule)."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4688-cmd-from-office")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            process_name="cmd.exe",
            parent_process_name="winword.exe",
            pid=9999,
            **{"metadata.hour": "10"},
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_t1546_wmi_subscription_fires_on_create() -> None:
    """5861 with operation=Created → fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-5861-wmi-subscription")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.5861",
            operation="Created",
            subscription_name="evil_sub",
            pid=1234,
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_t1546_wmi_subscription_no_fire_on_modify() -> None:
    """5861 with operation != Created → no fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-5861-wmi-subscription")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.5861",
            operation="Modified",
            subscription_name="evil_sub",
            pid=1234,
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_t1547_startup_folder_fires() -> None:
    """4663 WriteData on path containing \\Start Menu\\Programs\\Startup → fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4663-startup-folder")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4663",
            access_mask="WriteData",
            target_path="C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe",
            pid=1234,
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_t1547_startup_folder_no_fire_on_unrelated_path() -> None:
    """4663 WriteData on non-startup path → no fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4663-startup-folder")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4663",
            access_mask="WriteData",
            target_path="C:\\Users\\admin\\Documents\\report.docx",
            pid=1234,
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_t1053_scheduled_task_fires() -> None:
    """4698 Scheduled Task created → fire (no off-hours filter)."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4698-scheduled-task")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4698",
            task_name="\\Microsoft\\EvilTask",
            pid=1234,
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_t1053_scheduled_task_no_fire_on_other_event() -> None:
    """Non-4698 event → no fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4698-scheduled-task")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4700",  # task deleted
            task_name="\\Microsoft\\EvilTask",
            pid=1234,
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_t1078_rdp_unusual_source_fires() -> None:
    """4624 type 10 from non-allowlisted IP off-hours → fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4624-rdp-unusual-source")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4624",
            logon_type="10",
            subject_user="admin",
            source_ip="203.0.113.42",
            pid=1234,
            **{"metadata.hour": "23"},
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_t1078_rdp_unusual_source_no_fire_on_allowlisted() -> None:
    """4624 type 10 from allowlisted IP → no fire."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4624-rdp-unusual-source")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4624",
            logon_type="10",
            subject_user="admin",
            source_ip="10.0.0.1",
            pid=1234,
            **{"metadata.hour": "23"},
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_t1078_rdp_unusual_source_no_fire_business_hour() -> None:
    """4624 type 10: the T1078 rule does NOT narrow to off-hours
    (operators add that via local_overrides). This test just
    verifies the allowlist filter works regardless of hour."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4624-rdp-unusual-source")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4624",
            logon_type="10",
            subject_user="admin",
            source_ip="10.0.0.1",  # allowlisted
            pid=1234,
            **{"metadata.hour": "10"},
        )
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_t1078_rdp_unusual_source_fires_with_hour() -> None:
    """Even at business hour, an off-allowlist IP still fires."""
    rules = _windows_rules()
    rule = _find(rules, "builtin-windows-4624-rdp-unusual-source")
    runner = SigmaRuleRunner(FakeRedis(), [rule])
    fires = await runner.evaluate(
        _event(
            "windows.security.4624",
            logon_type="10",
            subject_user="admin",
            source_ip="203.0.113.42",
            pid=1234,
            **{"metadata.hour": "10"},
        )
    )
    assert len(fires) == 1
