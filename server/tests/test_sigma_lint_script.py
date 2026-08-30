"""Tests for ``server/scripts/lint_sigma_rules.sh`` (cycle 27).

The lint script is a thin wrapper around the rule engine's
``parse_rule_file`` — it walks the rules tree and rejects the
commit if any file fails to compile. These tests pin the contract:

1. The script exists, is executable, and exits 0 against the
   real rules tree.
2. A broken YAML (unparseable) makes the script exit non-zero and
   the failure path is printed on stderr.
3. A directory with no YAML files is rejected with exit 2.

We invoke the script in a subprocess so the test exercises the
real shell wrapper, not just the embedded Python.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "server" / "scripts" / "lint_sigma_rules.sh"
REAL_RULES_DIR = REPO_ROOT / "server" / "rules"


def test_script_exists_and_is_executable() -> None:
    """The lint script must be present and runnable as bash.

    Pin this so a future rename or chmod 644 doesn't silently
    disable the lint gate.
    """
    assert SCRIPT.is_file(), f"missing script: {SCRIPT}"
    mode = SCRIPT.stat().st_mode
    assert mode & 0o111, f"script is not executable: {oct(mode)}"


def test_script_passes_against_real_rules_tree() -> None:
    """Linting the shipped rules tree must exit 0.

    If this regresses it means someone shipped a Sigma rule whose
    YAML won't compile under the real engine. That is exactly
    the failure the lint gate exists to catch.
    """
    result = subprocess.run(
        ["bash", str(SCRIPT), str(REAL_RULES_DIR)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"lint failed (rc={result.returncode})\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )
    # The success line should mention the rule count we expect.
    assert "OK:" in result.stdout
    assert "rules" in result.stdout


def test_script_rejects_unparseable_yaml(tmp_path: Path) -> None:
    """A malformed YAML must fail the gate (exit 1) and the file
    path must appear on stderr so the operator can find it.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    broken = rules_dir / "broken.yml"
    # Unclosed flow sequence — guaranteed to break yaml.safe_load.
    broken.write_text(
        "title: broken\n"
        "id: deadbeef-dead-beef-dead-beefdeadbeef\n"
        "detection:\n"
        "  selection:\n"
        '    process: "test"\n'
        "  condition: [invalid\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["bash", str(SCRIPT), str(rules_dir)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1, (
        f"expected rc=1 for broken yaml, got {result.returncode}\n"
        f"stderr: {result.stderr}"
    )
    assert "broken.yml" in result.stderr
    assert "FAIL" in result.stderr


def test_script_rejects_missing_directory(tmp_path: Path) -> None:
    """A nonexistent rules directory must exit 2 (usage error).

    Distinguishing the 'no such dir' case from 'rules are broken'
    lets the operator diagnose the failure at a glance.
    """
    missing = tmp_path / "does-not-exist"
    result = subprocess.run(
        ["bash", str(SCRIPT), str(missing)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "not found" in result.stderr


def test_script_rejects_empty_rules_directory(tmp_path: Path) -> None:
    """A directory with no .yml/.yaml files must exit 2.

    An empty rules tree would silently make the engine load zero
    rules; failing the gate is the right behaviour.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.md").write_text("# no rules here\n", encoding="utf-8")

    result = subprocess.run(
        ["bash", str(SCRIPT), str(empty)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "no .yml" in result.stderr or "no .yaml" in result.stderr