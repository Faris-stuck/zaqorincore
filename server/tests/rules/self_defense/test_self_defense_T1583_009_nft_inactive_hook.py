"""T1583.009 — nft.call inactive hook (CWE-1188)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1583_009_nft_call_inactive_hook.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1583.009")
    assert rule.level == "high"


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_level_is_high() -> None:
    assert _rule().level == "high"


def test_no_match_when_hook_active() -> None:
    rule = _rule()
    benign = make_event(
        event_type="nft.call",
        target_table="filter",
        target_chain="input",
        hook_name="input",
        inactive_hook=False,
    )
    assert not rule.matches(benign), (
        "rule must NOT fire when the hook chain is active"
    )
    positive = make_event(
        event_type="nft.call",
        target_table="nat",
        target_chain="postrouting",
        hook_name="postrouting",
        inactive_hook=True,
    )
    assert rule.matches(positive), (
        "rule must fire when an nft.call references a disabled hook chain"
    )