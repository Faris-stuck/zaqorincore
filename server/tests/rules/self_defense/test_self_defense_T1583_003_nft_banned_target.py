"""T1583.003 — nft.call with banned target (C2 / sinkhole / Tor exit)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1583_003_nft_call_banned_target.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1583.003")
    assert rule.level == "high"


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_level_is_high() -> None:
    assert _rule().level == "high"


def test_rule_registered_in_pack() -> None:
    rule = find_rule("T1583.003")
    assert rule in SELF_DEFENSE_RULES


def test_no_match_when_target_not_banned() -> None:
    """Engine sanity: the rule must NOT fire when the nft.call
    targets a host that is not on the operator's banned list.
    """
    rule = _rule()
    benign = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        target_banned=False,
    )
    assert not rule.matches(benign), (
        "rule must NOT fire for an nft.call whose target is not on "
        "the banned-target list"
    )

    # Negative: a different event_type even with target_banned=True
    other = make_event(event_type="ws.hello", target_banned=True)
    assert not rule.matches(other), (
        "rule must NOT fire for non-nft events even when the "
        "banned-target flag is set"
    )


def test_match_when_target_banned() -> None:
    """Engine sanity: the rule MUST fire when the nft.call targets
    a host on the banned-target list (operator-curated Tor exits,
    sinkholes, deny-listed blocks).
    """
    rule = _rule()
    flagged = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        target_banned=True,
    )
    assert rule.matches(flagged), (
        "rule must fire when an nft.call targets a host on the "
        "operator's banned-target list"
    )


def test_selection_grammar_valid() -> None:
    rule = _rule()
    assert rule.selection.get("event_type") == "nft.call"


def test_condition_uses_pattern_2() -> None:
    """This rule uses condition pattern 2 (selection and not filter).

    The engine's ADR-010 grammar only supports `selection`,
    `selection and not filter`, or OR-filter combinations — it does
    NOT support a bare `selection and filter`. We invert the filter
    name to encode the same intent within the supported grammar.
    """
    cond = _rule().condition
    assert cond.startswith("selection and not ")
    assert "filter_not_banned" in cond


def test_threshold_not_required() -> None:
    """Single-event rule — count defaults to 1. The runner is the
    component responsible for projecting the banned-target metadata
    flag from the operator's curated list; the rule itself fires on
    a single nft.call.
    """
    import yaml
    with open(
        "rules/builtin/self_defense/T1583_003_nft_call_banned_target.yml"
    ) as f:
        doc = yaml.safe_load(f)
    assert doc["detection"].get("count", 1) == 1


def test_fp_mentions_operator_testing() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1583_003_nft_call_banned_target.yml"
    ) as f:
        doc = yaml.safe_load(f)
    fps = doc.get("falsepositives") or []
    joined = " ".join(fps).lower()
    assert "operator" in joined