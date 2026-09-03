"""Tests for the T1583.001 TLD-burst Sigma rule."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import parse_rule_file


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/mitre_attack/T1583_001_domain_acquisition_tld_burst.yml")
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


def test_tld_burst_rule_loads() -> None:
    """TLD burst rule has level=high and 60s/5-event threshold."""
    rule = _rule()
    assert rule.level == "high"
    assert rule.count == 5
    assert rule.timeframe_sec == 60


def test_tld_burst_fires_on_xyz() -> None:
    """Fires when the queried SLD ends in .xyz."""
    rule = _rule()
    assert rule.matches(_event(query="foo.xyz"))


def test_tld_burst_fires_on_each_suspicious_tld() -> None:
    """Fires for every TLD in the cheap-TLD set."""
    rule = _rule()
    for tld in ("xyz", "top", "tk", "ml", "cf", "ga"):
        assert rule.matches(_event(query=f"foo.{tld}")), f"missing {tld}"


def test_tld_burst_suppresses_cloudfront() -> None:
    """CDN queries are not flagged even when on a permissive TLD."""
    rule = _rule()
    assert not rule.matches(_event(query="asset.cloudfront.net"))


def test_tld_burst_suppresses_normal_tld() -> None:
    """Common TLDs do not fire the rule."""
    rule = _rule()
    assert not rule.matches(_event(query="foo.com"))
    assert not rule.matches(_event(query="foo.org"))