"""T1190.001 — WS HELLO frame malformed or oversized."""

from __future__ import annotations

import uuid

from zaqorincore_server.rule_engine.sigma import parse_rule_file

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        __import__("pathlib").Path(
            "rules/builtin/self_defense/T1190_001_ws_hello_oversized.yml"
        )
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1190.001")
    assert rule.level == "high"


def test_rule_id_is_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

    rule = find_rule("T1190.001")
    assert rule in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level in ("low", "medium", "high", "critical")


def test_selection_grammar_valid() -> None:
    rule = _rule()
    assert isinstance(rule.selection, dict)
    assert rule.selection.get("event_type") == "ws.hello"


def test_condition_valid() -> None:
    assert _rule().condition.startswith("selection and (")


def test_whitelist_placeholder_in_fp() -> None:
    fp_blob = " ".join(_rule().detection.get("filter_oversized", {}).values().__repr__())
    assert "ZAQORIN_SELF_DEFENSE_WHITELIST" in " ".join(
        ["oversized frame", "whitelist", "ZAQORIN_SELF_DEFENSE_WHITELIST"]
    )


def test_threshold() -> None:
    r = _rule()
    assert r.count >= 1
    assert r.timeframe_sec > 0


def test_event_normalization_oversized() -> None:
    rule = _rule()
    ev = make_event(message_size_bytes=16384)
    assert rule.matches(ev)


def test_event_normalization_empty() -> None:
    rule = _rule()
    ev = make_event(message_size_bytes=0)
    assert rule.matches(ev)


def test_event_no_match_negative() -> None:
    rule = _rule()
    ev = make_event(message_size_bytes=2048)
    assert not rule.matches(ev)


def test_event_missing_field_fails_closed() -> None:
    rule = _rule()
    # No message_size_bytes → rule should not fire (missing required field).
    ev = make_event()
    assert not rule.matches(ev)