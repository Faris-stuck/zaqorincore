"""T1583.006 — nft.call rule shadowing (CWE-285)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1583_006_nft_call_rule_shadow.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1583.006")
    assert rule.level == "high"


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_level_is_high() -> None:
    assert _rule().level == "high"


def test_no_match_when_not_shadowed() -> None:
    """Engine sanity: the rule must NOT fire when the nft.call does not
    carry the rule_shadowed metadata, and must NOT fire for non-nft
    events even if rule_shadowed somehow leaks into another event type.
    """
    rule = _rule()
    clean = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        rule_shadowed=False,
    )
    assert not rule.matches(clean), (
        "rule must NOT fire for an nft.call whose rule is not shadowed"
    )

    other = make_event(
        event_type="ws.hello",
        rule_shadowed=True,
    )
    assert not rule.matches(other), (
        "rule must NOT fire for non-nft events even when rule_shadowed "
        "is present"
    )