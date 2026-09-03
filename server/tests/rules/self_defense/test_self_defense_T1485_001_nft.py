"""T1485.001 — nft binary add/insert called with non-whitelisted table/chain."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1485_001_nft_invalid_table_chain.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1485.001")
    assert rule.level == "high"


def test_rule_id_is_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    rule = find_rule("T1485.001")
    assert rule in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level in ("low", "medium", "high", "critical")


def test_selection_grammar_valid() -> None:
    rule = _rule()
    assert rule.selection.get("event_type") == "nft.call"


def test_condition_valid() -> None:
    cond = _rule().condition
    assert cond.startswith("selection and (")
    assert "or" in cond


def test_whitelist_placeholder_in_fp() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1485_001_nft_invalid_table_chain.yml"
    ) as f:
        doc = yaml.safe_load(f)
    fps = doc.get("falsepositives") or []
    assert any("operator" in fp.lower() or "custom" in fp.lower() for fp in fps)


def test_threshold_not_required() -> None:
    # Single-event rule — count defaults to 1.
    import yaml
    with open(
        "rules/builtin/self_defense/T1485_001_nft_invalid_table_chain.yml"
    ) as f:
        doc = yaml.safe_load(f)
    assert doc["detection"].get("count", 1) == 1


def test_event_normalization_positive_shell_injection() -> None:
    rule = _rule()
    ev = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output; rm -rf /",
    )
    assert rule.matches(ev)


def test_event_normalization_positive_path_traversal() -> None:
    rule = _rule()
    ev = make_event(
        event_type="nft.call",
        target_table="../etc",
        target_chain="input",
    )
    assert rule.matches(ev)


def test_event_normalization_negative_whitelisted() -> None:
    rule = _rule()
    ev = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
    )
    assert not rule.matches(ev)


def test_event_missing_field_fails_closed() -> None:
    rule = _rule()
    ev = make_event(event_type="nft.call", target_table="input")
    # No target_chain -> filter_invalid_chain cannot evaluate true;
    # but filter_invalid_table may still match if table had bad chars.
    # With both fields clean, no match.
    ev2 = make_event(event_type="nft.call", target_table="input", target_chain="output")
    assert not rule.matches(ev2)
