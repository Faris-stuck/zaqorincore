"""T1505.004 — CSP report burst from single src_ip (F-017 follow-up rule)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import RULE_TITLES, SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1505_004_csp_report_burst.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1505.004")


def test_rule_id_is_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_rule_registered_in_pack() -> None:
    assert find_rule("T1505.004") in SELF_DEFENSE_RULES


def test_rule_title_exported() -> None:
    """RULE_TITLES must include the new title so the status page
    lists it."""
    titles = " | ".join(RULE_TITLES)
    assert "T1505.004" in titles


def test_rule_tier_matches() -> None:
    assert _rule().level == "medium"


def test_selection_grammar_valid() -> None:
    r = _rule()
    assert r.selection["event_type"] == "csp.violation"
    assert r.selection["status"] == 429


def test_condition_valid() -> None:
    assert _rule().condition == "selection"


def test_threshold() -> None:
    """A single 429 is enough — a rate-limit probe is itself the
    signal. The 5-minute window catches slow burns too."""
    r = _rule()
    assert r.count == 1
    assert r.timeframe_sec == 5 * 60


def test_event_matches_429() -> None:
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        src_ip="203.0.113.10",
        status=429,
    )
    assert r.matches(ev)


def test_event_no_match_204() -> None:
    """A successful 204 must not match — those are normal CSP
    reports, not rate-limit probes."""
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        src_ip="203.0.113.10",
        status=204,
    )
    assert not r.matches(ev)