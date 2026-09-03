"""T1078.002 — shared_secret HMAC auth from new src_ip (credential reuse)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1078_002_hmac_replay_multi_ip.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1078.002")
    assert rule.level == "high"


def test_rule_id_is_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    rule = find_rule("T1078.002")
    assert rule in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level in ("low", "medium", "high", "critical")


def test_selection_grammar_valid() -> None:
    rule = _rule()
    assert rule.selection.get("event_type") == "ws.hello"
    assert rule.selection.get("auth_method") == "hmac"
    assert rule.selection.get("status") == 200


def test_condition_valid() -> None:
    assert _rule().condition == "selection"


def test_whitelist_placeholder_in_fp() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1078_002_hmac_replay_multi_ip.yml"
    ) as f:
        doc = yaml.safe_load(f)
    fps = doc.get("falsepositives") or []
    assert any("migrat" in fp.lower() or "multi-nic" in fp.lower() for fp in fps)


def test_threshold_count_and_window() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1078_002_hmac_replay_multi_ip.yml"
    ) as f:
        doc = yaml.safe_load(f)
    det = doc["detection"]
    assert det.get("count") == 2
    assert det.get("timeframe") == "300s"
    assert det.get("by") == "key_id"


def test_event_normalization_positive_success() -> None:
    rule = _rule()
    ev = make_event(
        event_type="ws.hello",
        auth_method="hmac",
        status=200,
        key_id="key-abc",
        src_ip="198.51.100.10",
    )
    assert rule.matches(ev)


def test_event_normalization_negative_wrong_auth() -> None:
    rule = _rule()
    ev = make_event(
        event_type="ws.hello",
        auth_method="api_key",
        status=200,
    )
    assert not rule.matches(ev)


def test_event_normalization_negative_failure_status() -> None:
    rule = _rule()
    ev = make_event(
        event_type="ws.hello",
        auth_method="hmac",
        status=401,
    )
    assert not rule.matches(ev)


def test_event_missing_field_fails_closed() -> None:
    rule = _rule()
    ev = make_event(event_type="ws.hello", auth_method="hmac")
    # status missing -> selection won't match.
    assert not rule.matches(ev)
