"""T1485.001 — nft.call event normalizer coverage."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES
from zaqorincore_server.self_defense.event_normalizer import ZaqorinEvent

from tests.rules.self_defense._helpers import find_rule


def _event(**md):
    md.setdefault("event_type", "nft.call")
    md.setdefault("src_ip", "198.51.100.10")
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="zaqorincore",
        raw="",
        metadata=md,
        occurred_at=datetime.now(timezone.utc),
    )


def test_nft_event_normalizer_basic() -> None:
    ev = ZaqorinEvent.from_log_record(
        {"event_type": "nft.call", "target_table": "input", "target_chain": "output"}
    )
    assert ev.event_type == "nft.call"
    assert ev.target_table == "input"
    assert ev.target_chain == "output"


def test_nft_event_metadata_strips_none() -> None:
    ev = ZaqorinEvent.from_log_record({"event_type": "nft.call"})
    md = ev.to_metadata()
    assert "target_table" not in md
    assert "target_chain" not in md


def test_nft_event_normalizer_coerces_non_string() -> None:
    ev = ZaqorinEvent.from_log_record(
        {"event_type": "nft.call", "target_table": 12345, "target_chain": None}
    )
    assert ev.target_table is None
    assert ev.target_chain is None


def test_nft_rule_fires_on_shell_metachar_in_chain() -> None:
    rule = find_rule("T1485.001")
    ev = _event(target_table="input", target_chain="output; id")
    assert rule.matches(ev)


def test_nft_rule_does_not_fire_on_clean_input() -> None:
    rule = find_rule("T1485.001")
    ev = _event(target_table="input", target_chain="output")
    assert not rule.matches(ev)


def test_nft_rule_registered() -> None:
    titles = [r.title for r in SELF_DEFENSE_RULES]
    assert any("T1485.001" in t for t in titles)
