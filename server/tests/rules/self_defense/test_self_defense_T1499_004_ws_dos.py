"""T1499.004 — WS frame size or rate limit exceeded."""

from __future__ import annotations

from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1499_004_ws_dos.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1499.004")
    assert r.level == "high"


def test_rule_id_is_uuid4() -> None:
    import uuid
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    from zaqorincore_server.self_defense import SELF_DEFENSE_RULES
    assert find_rule("T1499.004") in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level == "high"


def test_selection_grammar_valid() -> None:
    r = _rule()
    assert r.selection["event_type"] == "ws.dos"


def test_condition_valid() -> None:
    assert _rule().condition == "selection"


def test_whitelist_placeholder() -> None:
    assert _rule().title


def test_threshold() -> None:
    r = _rule()
    assert r.count == 5
    assert r.timeframe_sec == 60


def test_event_normalization_frame_size() -> None:
    r = _rule()
    ev = make_event(
        event_type="ws.dos",
        trigger="frame_size_exceeded",
    )
    assert r.matches(ev)


def test_event_normalization_rate_limit() -> None:
    r = _rule()
    ev = make_event(
        event_type="ws.dos",
        trigger="rate_limit_exceeded",
    )
    assert r.matches(ev)


def test_event_no_match_unknown_trigger() -> None:
    r = _rule()
    ev = make_event(
        event_type="ws.dos",
        trigger="something_else",
    )
    assert not r.matches(ev)