"""Tests for the T1485 Data Destruction Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1485_data_destruction.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- rm -rf /                                            → fires (root wipe)
- rm -rf /etc                                         → fires (system path wipe)
- rm -rf /var/log                                     → fires (log + system wipe)
- dd if=/dev/zero of=/dev/sda                         → fires (raw device write)
- mkfs.ext4 /dev/sda                                  → fires (reformat)
- mkswap /dev/nvme0n1                                 → fires (swap on raw device)
- shred /dev/sda                                      → fires (secure erase device)
- wipefs -a /dev/sda                                  → fires (signature wipe)
- echo junk > /dev/sdb                                → fires (truncate device)
- apt-get remove foo                                  → does NOT fire (pkg filter)
- rm -rf /tmp/cache                                   → does NOT fire (safe tmp path)
- dd if=image.iso of=/dev/null                         → does NOT fire (no device target)
- random unrelated process                            → does NOT fire
- rm -f firmware.bin                                  → does NOT fire (no path; substring trap)
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

RULE_ID = "b4e2c7f8-3a91-4f6d-9e2b-5c8a1d4f7e02"


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
        "hostname": "victim01",
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
async def test_rm_rf_root_fires() -> None:
    """Canonical destruction primitive: wipe the filesystem root."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/rm", "rm -rf /")
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_rm_rf_etc_fires() -> None:
    """Targeted wipe of /etc to destroy configuration / lock out admins."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/rm", "rm -rf /etc")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_rm_rf_var_log_fires() -> None:
    """Log directory wipe is T1485 + T1070 cover-band."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/rm", "rm -rf /var/log")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_dd_of_device_fires() -> None:
    """Raw block-device overwrite — the textbook T1485 primitive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/dd", "dd if=/dev/zero of=/dev/sda bs=1M")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_mkfs_device_fires() -> None:
    """Reformatting a block device destroys any filesystem present."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/mkfs.ext4", "mkfs.ext4 /dev/sda")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_mkswap_nvme_fires() -> None:
    """mkswap on a raw NVMe device — destructive reformat."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/mkswap", "mkswap /dev/nvme0n1")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_shred_device_fires() -> None:
    """shred against a raw device is destructive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/shred", "shred -v /dev/sda")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_wipefs_device_fires() -> None:
    """wipefs -a wipes filesystem signatures — destructive."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/sbin/wipefs", "wipefs -a /dev/sda")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_redirect_to_device_fires() -> None:
    """Bare shell redirect targeting a block device truncates it."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/sh", "echo junk > /dev/sdb")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_apt_remove_does_not_fire() -> None:
    """Package manager invocations are filtered out."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/apt-get", "apt-get remove --purge nginx")
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_rm_rf_tmp_does_not_fire() -> None:
    """Recursive rm against /tmp is routine cleanup, not destruction."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/rm", "rm -rf /tmp/cache/build")
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_dd_to_dev_null_does_not_fire() -> None:
    """Writing to /dev/null is not destructive — must not fire."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/dd", "dd if=image.iso of=/dev/null")
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_unrelated_process_does_not_fire() -> None:
    """Plain shell commands do not match."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/ls", "ls -la /home/alice")
    )
    assert len(fires) == 0


@pytest.mark.asyncio
async def test_rm_firmware_substring_does_not_fire() -> None:
    """Substring-trap: rm of a file named 'firmware*' is not a wipe.
    'rm' as a process name must not match 'firmware', 'charm', etc."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/rm", "rm -f firmware.bin")
    )
    assert len(fires) == 0