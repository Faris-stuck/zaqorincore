"""T1583.005 — nft.call with bypass signature (CWE-285 / rule shadowing)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1583_005_nft_call_bypass_signature.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1583.005")
    assert rule.level == "high"


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_level_is_high() -> None:
    assert _rule().level == "high"


def test_rule_registered_in_pack() -> None:
    rule = find_rule("T1583.005")
    assert rule in SELF_DEFENSE_RULES


def test_no_match_when_signature_clean() -> None:
    """Engine sanity: the rule must NOT fire when the nft.call carries
    a clean (non-bypass) signature, and must NOT fire for non-nft events
    even if a bypass signature somehow leaks into another event type.
    """
    rule = _rule()
    clean = make_event(
        event_type="nft.call",
        target_table="input",
        target_chain="output",
        bypass_signature=False,
    )
    assert not rule.matches(clean), (
        "rule must NOT fire for an nft.call whose rule body carries a "
        "clean (non-bypass) signature"
    )

    other = make_event(
        event_type="ws.hello",
        bypass_signature=True,
    )
    assert not rule.matches(other), (
        "rule must NOT fire for non-nft events even when a bypass "
        "signature flag is present"
    )