"""Tests for the T1583.001 NRD Sigma rule."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import parse_rule_file


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/mitre_attack/T1583_001_domain_acquisition_nrd.yml")
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


def test_nrd_rule_loads() -> None:
    """The rule loads with the expected level and promotion."""
    rule = _rule()
    assert rule.level == "medium"
    assert rule.count == 3


def test_nrd_rule_fires_on_internal_nrd() -> None:
    """NRD rule fires when source is internal and age is fresh."""
    rule = _rule()
    assert rule.matches(
        _event(
            dns_age_seconds=60,
            source_internal=True,
            query="fresh.example.com",
        )
    )


def test_nrd_rule_suppresses_cdn() -> None:
    """NRD rule does NOT fire when query is a CDN host."""
    rule = _rule()
    assert not rule.matches(
        _event(
            dns_age_seconds=60,
            source_internal=True,
            query="asset.cloudfront.net",
        )
    )


def test_nrd_rule_suppresses_old_domain() -> None:
    """NRD rule does NOT fire when the domain age exceeds 5 minutes."""
    rule = _rule()
    assert not rule.matches(
        _event(
            dns_age_seconds=10000,
            source_internal=True,
            query="old.example.com",
        )
    )