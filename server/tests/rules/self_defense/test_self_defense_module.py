"""Tests for the self_defense module public surface."""

from __future__ import annotations

from pathlib import Path

from zaqorincore_server import self_defense
from zaqorincore_server.self_defense import (
    RULE_TITLES,
    SELF_DEFENSE_RULES,
    ZaqorinEvent,
    drain,
    emit,
    load_rules,
)


def test_singleton_rules_loaded() -> None:
    assert len(SELF_DEFENSE_RULES) == 15


def test_rule_titles_match_rules() -> None:
    assert len(RULE_TITLES) == len(SELF_DEFENSE_RULES)
    assert all(t for t in RULE_TITLES)


def test_load_rules_returns_fresh_list() -> None:
    fresh = load_rules()
    assert len(fresh) == len(SELF_DEFENSE_RULES)


def test_load_rules_handles_missing_dir(tmp_path: Path) -> None:
    # Patch the path resolver indirectly by deleting the rules dir.
    import zaqorincore_server.self_defense as sd
    original = sd._RULES_DIR
    sd._RULES_DIR = tmp_path / "does-not-exist"
    try:
        assert sd.load_rules() == []
    finally:
        sd._RULES_DIR = original


def test_emit_and_drain() -> None:
    ev = ZaqorinEvent(ts="2026-09-03T00:00:00Z", event_type="ws.hello", src_ip="x")
    emit(ev)
    snap = list(drain())
    assert any(e.event_type == "ws.hello" for e in snap)


def test_drain_respects_max_items() -> None:
    snap = drain(max_items=5)
    assert len(snap) <= 5


def test_all_rules_have_uuid_ids() -> None:
    import uuid
    for r in SELF_DEFENSE_RULES:
        uuid.UUID(r.id, version=4)


def test_all_rules_have_expected_levels() -> None:
    levels = {r.level for r in SELF_DEFENSE_RULES}
    assert levels.issubset({"low", "medium", "high", "critical"})
    # Two highs expected: T1190, T1499 — plus the audit rule T1098.
    assert "high" in levels
    assert "medium" in levels


def test_module_exports_complete() -> None:
    for name in (
        "SELF_DEFENSE_RULES",
        "RULE_TITLES",
        "ZaqorinEvent",
        "emit",
        "drain",
        "load_rules",
    ):
        assert hasattr(self_defense, name), name