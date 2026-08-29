"""Tests for the 5 Windows Event Log Sigma rules shipped in v1.4.0.

These rules are pure-pattern Sigma rules; they need no
Windows runtime. The runner exercises the same code path
the Linux rules use. We assert:
  - each rule loads and parses
  - each rule's detection matches a representative event
  - each rule's detection rejects a non-matching event
  - each rule's action renders with the right template
  - all 5 rules land under rules/builtin/windows_eventlog/

The test event metadata mirrors what the Windows agent's
eventlog_common.go decoder produces for the corresponding
Event ID. If the decoder changes a field name, these
tests will catch the drift.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.runner import SigmaRuleRunner
from zaqorincore_server.rule_engine.sigma import (
    load_rules_from_dir,
)

from .fake_redis import FakeRedis


def _event(
    source: str,
    **metadata,
) -> ParsedEvent:
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source=source,
        raw="",
        metadata=metadata,
        occurred_at=datetime.now(timezone.utc),
    )


def _windows_rules() -> list:
    """Load only the rules under rules/builtin/windows_eventlog/."""
    rules = load_rules_from_dir(Path("rules/builtin/windows_eventlog"))
    return rules


def _find(rules: list, rule_id: str):
    return next(r for r in rules if r.id == rule_id)


# --------------------------------------------------------------------
# Slice A — T1110 brute force (4625)
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1110_brute_force_fires_on_10_failures() -> None:
    rules = _windows_rules()
    t1110 = _find(rules, "builtin-windows-4625-brute-force")
    runner = SigmaRuleRunner(FakeRedis(), [t1110])
    last = []
    for _ in range(10):
        last = await runner.evaluate(
            _event(
                "windows.security.4625",
                ip_address="203.0.113.42",
                target_user_name="Administrator",
                logon_type=3,
            )
        )
    assert len(last) == 1
    fire = last[0]
    assert fire.rule.id == "builtin-windows-4625-brute-force"
    assert fire.rendered_action is not None
    assert fire.rendered_action["kind"] == "block_ip"
    assert fire.rendered_action["target"] == "203.0.113.42"
    assert fire.dedup_key == "203.0.113.42"


@pytest.mark.asyncio
async def test_t1110_does_not_fire_under_threshold() -> None:
    rules = _windows_rules()
    t1110 = _find(rules, "builtin-windows-4625-brute-force")
    runner = SigmaRuleRunner(FakeRedis(), [t1110])
    fires: list = []
    for _ in range(9):
        fires = await runner.evaluate(
            _event(
                "windows.security.4625",
                ip_address="203.0.113.42",
            )
        )
    assert fires == []


@pytest.mark.asyncio
async def test_t1110_does_not_fire_on_successful_logon() -> None:
    """Sanity: 4624 is success, 4625 is failure. Only 4625 should match."""
    rules = _windows_rules()
    t1110 = _find(rules, "builtin-windows-4625-brute-force")
    runner = SigmaRuleRunner(FakeRedis(), [t1110])
    fires = []
    for _ in range(20):
        fires = await runner.evaluate(
            _event(
                "windows.security.4624",  # success
                ip_address="203.0.113.42",
            )
        )
    assert fires == []


# --------------------------------------------------------------------
# Slice B — T1218 LOLBin parent (4688)
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1218_suspicious_parent_fires_on_mshta() -> None:
    rules = _windows_rules()
    t1218 = _find(rules, "builtin-windows-4688-suspicious-parent")
    runner = SigmaRuleRunner(FakeRedis(), [t1218])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            pid=7777,
            parent_process_name="mshta.exe",
            command_line=(
                "mshta.exe javascript:document.write();"
                " new ActiveXObject..."
            ),
        )
    )
    assert len(fires) == 1
    fire = fires[0]
    assert fire.rule.id == "builtin-windows-4688-suspicious-parent"
    assert fire.rendered_action is not None
    assert fire.rendered_action["kind"] == "snapshot_processes"
    assert fire.rendered_action["target"] == "7777"


@pytest.mark.asyncio
async def test_t1218_does_not_fire_on_normal_parent() -> None:
    rules = _windows_rules()
    t1218 = _find(rules, "builtin-windows-4688-suspicious-parent")
    runner = SigmaRuleRunner(FakeRedis(), [t1218])
    fires = await runner.evaluate(
        _event(
            "windows.security.4688",
            pid=7777,
            parent_process_name="explorer.exe",  # user-launched
            command_line="notepad.exe",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_t1218_does_not_fire_on_all_lolbins_at_default() -> None:
    """Each LOLBin in the list is a valid match — but the
    rule has a 1-event threshold (no count), so a single
    event fires immediately."""
    rules = _windows_rules()
    t1218 = _find(rules, "builtin-windows-4688-suspicious-parent")
    runner = SigmaRuleRunner(FakeRedis(), [t1218])
    for parent in [
        "regsvr32.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "certutil.exe",
        "bitsadmin.exe",
    ]:
        fires = await runner.evaluate(
            _event(
                "windows.security.4688",
                pid=1001,
                parent_process_name=parent,
            )
        )
        assert len(fires) == 1, f"failed to fire on {parent}"


# --------------------------------------------------------------------
# Slice C — T1003 LSASS read (4663 with `lsass.exe` filename)
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1003_lsass_read_fires_on_lsass_handle_open() -> None:
    rules = _windows_rules()
    t1003 = _find(rules, "builtin-windows-lsass-read")
    runner = SigmaRuleRunner(FakeRedis(), [t1003])
    fires = await runner.evaluate(
        _event(
            "windows.security.4663",
            pid=9999,
            target_filename="C:\\Windows\\System32\\lsass.exe",
        )
    )
    assert len(fires) == 1
    fire = fires[0]
    assert fire.rule.id == "builtin-windows-lsass-read"
    assert fire.rendered_action is not None
    assert fire.rendered_action["kind"] == "snapshot_processes"
    assert fire.rendered_action["target"] == "9999"


@pytest.mark.asyncio
async def test_t1003_does_not_fire_on_other_process() -> None:
    rules = _windows_rules()
    t1003 = _find(rules, "builtin-windows-lsass-read")
    runner = SigmaRuleRunner(FakeRedis(), [t1003])
    fires = await runner.evaluate(
        _event(
            "windows.security.4663",
            pid=9999,
            target_filename="C:\\Windows\\System32\\notepad.exe",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_t1003_fires_on_lsass_in_any_path() -> None:
    """`contains:lsass.exe` matches wherever lsass.exe appears in the
    target filename, not just the canonical path."""
    rules = _windows_rules()
    t1003 = _find(rules, "builtin-windows-lsass-read")
    runner = SigmaRuleRunner(FakeRedis(), [t1003])
    fires = await runner.evaluate(
        _event(
            "windows.security.4663",
            pid=9999,
            target_filename="\\Device\\HarddiskVolume2\\lsass.exe",
        )
    )
    assert len(fires) == 1


# --------------------------------------------------------------------
# Slice D — T1098 user added to privileged group (4732)
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1098_fires_on_domain_admins_add() -> None:
    rules = _windows_rules()
    t1098 = _find(rules, "builtin-windows-4732-priv-group-add")
    runner = SigmaRuleRunner(FakeRedis(), [t1098])
    fires = await runner.evaluate(
        _event(
            "windows.security.4732",
            target_group_name="Domain Admins",
            member_name="alice",
            pid=1234,
        )
    )
    assert len(fires) == 1
    fire = fires[0]
    assert fire.rule.id == "builtin-windows-4732-priv-group-add"
    assert fire.rendered_action is not None
    assert fire.rendered_action["kind"] == "snapshot_processes"


@pytest.mark.asyncio
async def test_t1098_does_not_fire_on_non_priv_group() -> None:
    rules = _windows_rules()
    t1098 = _find(rules, "builtin-windows-4732-priv-group-add")
    runner = SigmaRuleRunner(FakeRedis(), [t1098])
    # "Remote Desktop Users" — not in the rule's allowlist.
    fires = await runner.evaluate(
        _event(
            "windows.security.4732",
            target_group_name="Remote Desktop Users",
            member_name="bob",
            pid=1234,
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_t1098_fires_on_all_listed_priv_groups() -> None:
    """All 8 target groups in the v1.4.y allowlist should fire."""
    rules = _windows_rules()
    t1098 = _find(rules, "builtin-windows-4732-priv-group-add")
    runner = SigmaRuleRunner(FakeRedis(), [t1098])
    for group in [
        "BUILTIN\\Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Account Operators",
        "Server Operators",
        "Print Operators",
        "Backup Operators",
    ]:
        fires = await runner.evaluate(
            _event(
                "windows.security.4732",
                target_group_name=group,
                member_name="charlie",
                pid=1234,
            )
        )
        assert len(fires) == 1, f"failed to fire on {group}"


# --------------------------------------------------------------------
# Slice E — T1136 user account created (4720)
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_t1136_fires_on_account_create() -> None:
    rules = _windows_rules()
    t1136 = _find(rules, "builtin-windows-4720-account-create")
    runner = SigmaRuleRunner(FakeRedis(), [t1136])
    fires = await runner.evaluate(
        _event(
            "windows.security.4720",
            target_user_name="svc_backup",
            pid=5555,
            **{"metadata.hour": "23"},  # off-hours
        )
    )
    assert len(fires) == 1
    fire = fires[0]
    assert fire.rule.id == "builtin-windows-4720-account-create"
    assert fire.rendered_action is not None
    assert fire.rendered_action["kind"] == "snapshot_processes"


@pytest.mark.asyncio
async def test_t1136_does_not_fire_on_logon_event() -> None:
    rules = _windows_rules()
    t1136 = _find(rules, "builtin-windows-4720-account-create")
    runner = SigmaRuleRunner(FakeRedis(), [t1136])
    fires = await runner.evaluate(
        _event(
            "windows.security.4624",  # logon, not 4720
            target_user_name="svc_backup",
        )
    )
    assert fires == []


# --------------------------------------------------------------------
# Loader sanity
# --------------------------------------------------------------------


def test_windows_eventlog_rules_load() -> None:
    """All Windows rules load and have the required fields.

    v1.4.0 shipped 5; v1.4.x adds 2 more (PowerShell EncodedCommand
    and PowerShell DownloadString), so 7 total.
    """
    rules = _windows_rules()
    ids = {r.id for r in rules}
    assert "builtin-windows-4625-brute-force" in ids
    assert "builtin-windows-4688-suspicious-parent" in ids
    assert "builtin-windows-lsass-read" in ids
    assert "builtin-windows-4732-priv-group-add" in ids
    assert "builtin-windows-4720-account-create" in ids
    # v1.4.x additions
    assert "builtin-windows-4688-powershell-encoded" in ids
    assert "builtin-windows-4688-powershell-download" in ids
    assert len(rules) == 7
    for r in rules:
        assert r.title
        assert r.level in ("low", "medium", "high", "critical")
        assert r.timeframe_sec > 0
        assert r.count >= 1
        assert r.cooldown_sec >= 0
