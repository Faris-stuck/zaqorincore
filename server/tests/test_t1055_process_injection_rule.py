"""Tests for the T1055 Process Injection Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1055_process_injection.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- VirtualAllocEx + WriteProcessMemory in a shell script       → fires
- CreateRemoteThread invoked from a bash one-liner            → fires
- QueueUserAPC + SetWindowsHookEx in PowerShell wrapper       → fires
- dd writing to /proc/1234/mem (cross-process)                → fires
- gdb -p 4242 (attach to running process)                     → fires
- ptrace PTRACE_ATTACH shell snippet                          → fires
- /proc/self/mem reference (self-debug)                       → does NOT fire (filter_dev_self)
- strace -p 1 (debug init — dev pattern)                      → does NOT fire (filter_dev_self)
- gdb --args /bin/program (debug child binary — dev pattern)  → does NOT fire (filter_dev_self)
- substring trap: MyVirtualAllocEx must NOT match (\b anchors)
- substring trap: WriteProcessMemoryLite must NOT match (\b anchors)
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

RULE_ID = "5d2f8a91-6b3e-4c7d-9a1f-2e4b8c3d6f01"


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
async def test_virtualallocex_writeprocessmemory_fires() -> None:
    """Classic shellcode injection: alloc + write + thread, in one shell."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'VirtualAllocEx; WriteProcessMemory; CreateRemoteThread'",
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_createremotethread_one_liner_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/sh",
            "sh -c 'exec CreateRemoteThread /tmp/evil'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_queueuserapc_hook_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/pwsh",
            "pwsh -c 'QueueUserAPC; SetWindowsHookEx'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_dd_to_proc_mem_cross_process_fires() -> None:
    """Unix-equivalent injection: dd writing to another process's /proc/PID/mem."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/dd",
            "dd if=/tmp/sc.bin of=/proc/1234/mem bs=4096 conv=notrunc",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_gdb_attach_to_pid_fires() -> None:
    """gdb -p PID is a T1055 primitive — attach + write memory."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/gdb",
            "gdb -p 4242 -batch -ex 'set {int}0x41414141=1'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_ptrace_attach_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'ptrace(PTRACE_ATTACH, 4242)'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_proc_self_mem_does_not_fire() -> None:
    """A debugger writing to its OWN /proc/self/mem is dev/self-debug,
    not cross-process injection. Must be filtered."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/gdb",
            "gdb -batch -ex 'dump binary memory /proc/self/mem 0 100'",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_strace_init_does_not_fire() -> None:
    """strace -p 1 (debug init) is a dev-only pattern; should be filtered."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/strace",
            "strace -p 1",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_gdb_debug_child_binary_does_not_fire() -> None:
    """gdb --args /bin/program is the standard debug-child workflow."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/gdb",
            "gdb --args /bin/program --flag x",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_myvirtualallocex_does_not_match() -> None:
    """Anti-substring safety: `MyVirtualAllocEx` (which contains
    VirtualAllocEx as a substring but no \\bVirtualAllocEx\\b boundary)
    must NOT match. Anchoring requires word boundary."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'MyVirtualAllocEx runs first'",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_writeprocessmemorylite_does_not_match() -> None:
    """Anti-substring safety: `WriteProcessMemoryLite` (custom wrapper)
    must NOT match — \bWriteProcessMemory\b requires the exact word."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'use WriteProcessMemoryLite for fast injection'",
        )
    )
    assert fires == []