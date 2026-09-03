"""T1583.007 — nft.call policy violation (CWE-285)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1583_007_nft_call_policy_violation.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1583.007")
    assert rule.level == "high"


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_level_is_high() -> None:
    assert _rule().level == "high"


def test_no_match_when_no_policy_violation() -> None:
    rule = _rule()
    benign = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        policy_violation=False,
    )
    assert not rule.matches(benign), (
        "rule must NOT fire for an nft.call that does not violate policy"
    )
    positive = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        policy_violation=True,
    )
    assert rule.matches(positive), (
        "rule must fire when an nft.call contradicts its registered policy"
    )