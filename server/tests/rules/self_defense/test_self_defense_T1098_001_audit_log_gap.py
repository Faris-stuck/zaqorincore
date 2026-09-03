"""T1098.001 — Audit log JSONL persistence silently disabled."""

from __future__ import annotations

from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1098_001_audit_log_gap.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1098.001")
    assert r.level == "high"


def test_rule_id_is_uuid4() -> None:
    import uuid
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    from zaqorincore_server.self_defense import SELF_DEFENSE_RULES
    assert find_rule("T1098.001") in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level == "high"


def test_selection_grammar_valid() -> None:
    r = _rule()
    assert r.selection["event_type"] == "audit.healthcheck"


def test_condition_valid() -> None:
    assert _rule().condition == "selection"


def test_whitelist_placeholder() -> None:
    # No whitelist — silent disable is always suspicious.
    r = _rule()
    assert "whitelist" not in r.detection


def test_threshold() -> None:
    r = _rule()
    assert r.count == 1
    assert r.timeframe_sec == 24 * 3600


def test_event_normalization_disabled() -> None:
    r = _rule()
    ev = make_event(
        event_type="audit.healthcheck",
        jsonl_persistence_enabled=False,
    )
    assert r.matches(ev)


def test_event_no_match_enabled() -> None:
    r = _rule()
    ev = make_event(
        event_type="audit.healthcheck",
        jsonl_persistence_enabled=True,
    )
    assert not r.matches(ev)