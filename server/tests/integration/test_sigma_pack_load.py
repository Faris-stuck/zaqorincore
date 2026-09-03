"""End-to-end test for load_rules_from_dir.

The Round 13 audit (cycle 83) verified the 18 self-defense Sigma
rules offline by parsing the YAML and inspecting the structure.
This test exercises the same checks through the actual loader at
runtime — proving the audit findings are correct (and not just
re-reading the YAML in a different way).

If this test ever fails, the audit was wrong: either the
loader skips rules the audit thought it loaded, or it loads
rules the audit didn't see.
"""

from __future__ import annotations

import os
import secrets
import uuid
from pathlib import Path

# Boot-time env so the package import does not fail.
os.environ.setdefault("ZAQORIN_EVIDENCE_KEY", secrets.token_urlsafe(32))
os.environ.setdefault("ZAQORIN_CLOUDFLARE_INGEST_SECRET", secrets.token_urlsafe(32))
os.environ.setdefault("ZAQORIN_WEBHOOK_INGEST_SECRET", secrets.token_urlsafe(32))
os.environ.setdefault(
    "ZAQORIN_DATABASE_URL",
    "postgresql+asyncpg://zaqorin:secret@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

import pytest  # noqa: E402

from zaqorincore_server.rule_engine.sigma import (  # noqa: E402
    CompiledSigmaRule,
    load_rules_from_dir,
)

pytestmark = pytest.mark.integration


SELF_DEFENSE_DIR = (
    Path(__file__).resolve().parents[2]
    / "rules"
    / "builtin"
    / "self_defense"
)


def test_load_rules_from_dir_returns_20():
    """Cycle 98: 22 rules in the self-defense pack.

    The loader uses ``*.yml`` + ``*.yaml`` rglob and returns
    CompiledSigmaRule instances. We assert exactly 21.
    """
    rules = load_rules_from_dir(SELF_DEFENSE_DIR)
    assert len(rules) == 22, f"expected 22 rules, got {len(rules)}"


def test_load_rules_all_are_compiled():
    """Every loaded rule must be a CompiledSigmaRule instance."""
    rules = load_rules_from_dir(SELF_DEFENSE_DIR)
    for r in rules:
        assert isinstance(r, CompiledSigmaRule), (
            f"unexpected rule type: {type(r).__name__}"
        )


def test_load_rules_unique_ids():
    """Round 13 audit claim: 18/18 unique UUID4 IDs."""
    rules = load_rules_from_dir(SELF_DEFENSE_DIR)
    ids = [str(r.id) for r in rules]
    assert len(ids) == len(set(ids)), f"duplicate IDs: {ids}"


def test_load_rules_all_valid_uuid4():
    """Every rule ID must be a valid UUID4."""
    rules = load_rules_from_dir(SELF_DEFENSE_DIR)
    for r in rules:
        try:
            parsed = uuid.UUID(str(r.id))
        except ValueError as e:
            pytest.fail(f"invalid UUID {r.id!r}: {e}")
        assert parsed.version == 4, f"not UUID4: {parsed}"


def test_load_rules_level_distribution():
    """Cycle 98: 14 high, 7 medium, 1 low, 0 critical."""
    rules = load_rules_from_dir(SELF_DEFENSE_DIR)
    levels = {}
    for r in rules:
        levels[r.level] = levels.get(r.level, 0) + 1
    assert levels.get("high", 0) == 14, f"high count: {levels}"
    assert levels.get("medium", 0) == 7, f"medium count: {levels}"
    assert levels.get("low", 0) == 1, f"low count: {levels}"
    assert levels.get("critical", 0) == 0, f"critical count: {levels}"
