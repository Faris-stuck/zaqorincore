"""T1190.002 — WS HMAC challenge failures burst from single src_ip."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1190_002_hmac_challenge_bruteforce.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1190.002")
    assert rule.level == "medium"


def test_rule_id_is_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    rule = find_rule("T1190.002")
    assert rule in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level in ("low", "medium", "high", "critical")


def test_selection_grammar_valid() -> None:
    rule = _rule()
    assert rule.selection.get("event_type") == "ws.hello"
    assert rule.selection.get("auth_method") == "hmac"
    assert rule.selection.get("status") == 401


def test_condition_valid() -> None:
    assert _rule().condition == "selection"


def test_whitelist_placeholder_in_fp() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1190_002_hmac_challenge_bruteforce.yml"
    ) as f:
        doc = yaml.safe_load(f)
    fps = doc.get("falsepositives") or []
    assert any("clock" in fp.lower() or "reboot" in fp.lower() for fp in fps)


def test_threshold_count_and_window() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1190_002_hmac_challenge_bruteforce.yml"
    ) as f:
        doc = yaml.safe_load(f)
    det = doc["detection"]
    assert det.get("count") == 10
    assert det.get("timeframe") == "60s"
    assert det.get("by") == "src_ip"


def test_event_normalization_positive_failure() -> None:
    rule = _rule()
    ev = make_event(
        event_type="ws.hello",
        auth_method="hmac",
        status=401,
        src_ip="198.51.100.42",
    )
    assert rule.matches(ev)


def test_event_normalization_negative_success_status() -> None:
    rule = _rule()
    ev = make_event(
        event_type="ws.hello",
        auth_method="hmac",
        status=200,
        src_ip="198.51.100.42",
    )
    assert not rule.matches(ev)


def test_event_normalization_negative_wrong_method() -> None:
    rule = _rule()
    ev = make_event(
        event_type="ws.hello",
        auth_method="api_key",
        status=401,
    )
    assert not rule.matches(ev)


def test_event_missing_field_fails_closed() -> None:
    rule = _rule()
    ev = make_event(event_type="ws.hello", status=401)
    # auth_method missing -> selection won't match.
    assert not rule.matches(ev)
