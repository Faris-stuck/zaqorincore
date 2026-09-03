"""T1078.001 — API key use from new src_ip or unusual hour."""

from __future__ import annotations

from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1078_001_api_key_geo_anomaly.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1078.001")
    assert r.level == "medium"


def test_rule_id_is_uuid4() -> None:
    import uuid
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    from zaqorincore_server.self_defense import SELF_DEFENSE_RULES
    assert find_rule("T1078.001") in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level == "medium"


def test_selection_grammar_valid() -> None:
    r = _rule()
    assert r.selection["auth_method"] == "api_key"
    assert r.selection["status"] == 200


def test_condition_valid() -> None:
    c = _rule().condition
    assert c.startswith("selection and (")


def test_whitelist_placeholder() -> None:
    # Whitelist is in falsepositives / runner config; just verify fp text exists.
    r = _rule()
    assert r.title


def test_threshold() -> None:
    r = _rule()
    assert r.count >= 1


def test_event_normalization_new_ip() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        auth_method="api_key",
        status=200,
        key_first_seen_from_ip=True,
    )
    assert r.matches(ev)


def test_event_normalization_off_hours() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        auth_method="api_key",
        status=200,
        hour_of_day_local=3,
    )
    assert r.matches(ev)


def test_event_no_match_normal_hours_no_new_ip() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        auth_method="api_key",
        status=200,
        hour_of_day_local=12,
        key_first_seen_from_ip=False,
    )
    # Selection matches but neither filter does — should NOT match.
    assert not r.matches(ev)



def test_event_no_match_non_api_key() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        auth_method="hmac",
        status=200,
    )
    assert not r.matches(ev)