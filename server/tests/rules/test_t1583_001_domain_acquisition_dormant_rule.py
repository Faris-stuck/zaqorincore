"""Tests for the T1583.001 dormant-domain Sigma rule."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import parse_rule_file


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/mitre_attack/T1583_001_domain_acquisition_dormant.yml")
    )
    assert len(rules) == 1
    return rules[0]


def _event(**md) -> ParsedEvent:
    md.setdefault("event_type", "dns_query")
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="zeek_dns",
        raw="",
        metadata=md,
        occurred_at=datetime.now(timezone.utc),
    )


def test_dormant_rule_loads() -> None:
    """Dormant rule is medium severity with 10-event threshold."""
    rule = _rule()
    assert rule.level == "medium"
    assert rule.count == 10


def test_dormant_rule_fires_on_reactivation() -> None:
    """Fires when dns_last_seen_days >= 90 and burst flag is set."""
    rule = _rule()
    assert rule.matches(
        _event(
            dns_last_seen_days=120,
            dns_reactivation_burst=True,
            query="reactivated.example.com",
        )
    )


def test_dormant_rule_suppresses_recent_domain() -> None:
    """Domain last seen recently does NOT fire."""
    rule = _rule()
    assert not rule.matches(
        _event(
            dns_last_seen_days=5,
            dns_reactivation_burst=True,
            query="fresh.example.com",
        )
    )


def test_dormant_rule_suppresses_cdn() -> None:
    """CDN host on a reactivated 90-day-old query is not flagged."""
    rule = _rule()
    assert not rule.matches(
        _event(
            dns_last_seen_days=120,
            dns_reactivation_burst=True,
            query="asset.cloudfront.net",
        )
    )