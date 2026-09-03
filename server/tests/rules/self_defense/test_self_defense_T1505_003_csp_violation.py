"""T1505.003 — WebUI CSP violation."""

from __future__ import annotations

from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1505_003_csp_violation.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1505.003")
    assert r.level == "medium"


def test_rule_id_is_uuid4() -> None:
    import uuid
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    from zaqorincore_server.self_defense import SELF_DEFENSE_RULES
    assert find_rule("T1505.003") in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level == "medium"


def test_selection_grammar_valid() -> None:
    r = _rule()
    assert r.selection["event_type"] == "csp.violation"
    assert "script-src" in r.selection["violated_directive"]


def test_condition_valid() -> None:
    assert _rule().condition == "selection"


def test_whitelist_placeholder() -> None:
    assert _rule().title


def test_threshold() -> None:
    r = _rule()
    assert r.count == 3
    assert r.timeframe_sec == 10 * 60


def test_event_normalization_script_src() -> None:
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        violated_directive="script-src",
    )
    assert r.matches(ev)


def test_event_normalization_style_src() -> None:
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        violated_directive="style-src",
    )
    assert r.matches(ev)


def test_event_no_match_other_directive() -> None:
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        violated_directive="img-src",
    )
    assert not r.matches(ev)