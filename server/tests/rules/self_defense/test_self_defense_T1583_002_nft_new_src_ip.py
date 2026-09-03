"""T1583.002 — nft.call from new src_ip (24h baseline)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1583_002_nft_call_new_src_ip.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1583.002")
    assert rule.level == "medium"


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_level_is_medium() -> None:
    assert _rule().level == "medium"


def test_rule_registered_in_pack() -> None:
    rule = find_rule("T1583.002")
    assert rule in SELF_DEFENSE_RULES


def test_match_emits_csp_violation_or_nft_call() -> None:
    """Engine sanity: the rule must match an nft.call event whose
    metadata flags the source IP as new. A non-nft event must NOT
    match even if `new_src_ip: true` is set (selection guards).
    """
    rule = _rule()
    # Positive: nft.call from a brand-new IP (baseline flag set)
    positive = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        new_src_ip=True,
    )
    assert rule.matches(positive), (
        "rule must fire when an nft.call originates from a src_ip "
        "not seen in the last 24h"
    )

    # Negative: known src_ip (baseline flag explicitly false)
    known = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        new_src_ip=False,
    )
    assert not rule.matches(known), (
        "rule must NOT fire for src_ip present in the 24h baseline"
    )

    # Negative: unrelated event_type even with new_src_ip flag
    other = make_event(event_type="ws.hello", new_src_ip=True)
    assert not rule.matches(other), (
        "rule must NOT fire for non-nft events regardless of the "
        "baseline flag"
    )


def test_selection_grammar_valid() -> None:
    rule = _rule()
    assert rule.selection.get("event_type") == "nft.call"


def test_condition_uses_pattern_2() -> None:
    """This rule uses condition pattern 2 (selection and not filter)."""
    cond = _rule().condition
    assert cond.startswith("selection and not ")
    assert "filter_known_src_ip" in cond


def test_threshold_not_required() -> None:
    """Single-event rule — count defaults to 1. The runner is the
    component responsible for tracking baseline state across the
    24h window; the rule itself fires on a single nft.call."""
    import yaml
    with open(
        "rules/builtin/self_defense/T1583_002_nft_call_new_src_ip.yml"
    ) as f:
        doc = yaml.safe_load(f)
    assert doc["detection"].get("count", 1) == 1


def test_fp_mentions_operator_and_ephemeral() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1583_002_nft_call_new_src_ip.yml"
    ) as f:
        doc = yaml.safe_load(f)
    fps = doc.get("falsepositives") or []
    joined = " ".join(fps).lower()
    assert "operator" in joined
    assert "ephemeral" in joined