"""T1583.004 — nft.call from unauthorized actor (binary not in runtime allowlist)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1583_004_nft_call_unauthorized_actor.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1583.004")
    assert rule.level == "high"


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_level_is_high() -> None:
    assert _rule().level == "high"


def test_rule_registered_in_pack() -> None:
    rule = find_rule("T1583.004")
    assert rule in SELF_DEFENSE_RULES


def test_no_match_when_actor_authorized() -> None:
    """Engine sanity: the rule must NOT fire when the nft.call is
    issued by a binary in the operator's runtime allowlist.
    """
    rule = _rule()
    benign = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        actor_authorized=True,
    )
    assert not rule.matches(benign), (
        "rule must NOT fire for an nft.call whose actor binary is on "
        "the runtime allowlist"
    )

    # Negative: a different event_type even with actor_authorized=False
    other = make_event(event_type="ws.hello", actor_authorized=False)
    assert not rule.matches(other), (
        "rule must NOT fire for non-nft events even when the "
        "actor-authorized flag is unset"
    )