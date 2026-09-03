"""End-to-end log -> Sigma rule -> alert flow test for T1583.001."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import (
    load_rules_from_dir,
    parse_rule_file,
)


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


def test_load_rules_dir_includes_t1583_pack() -> None:
    """All 5 T1583.001 rules load from the rules directory."""
    rules_dir = Path("rules/builtin/mitre_attack")
    assert rules_dir.exists()
    rules = load_rules_from_dir(rules_dir)
    t1583 = [r for r in rules if "T1583.001" in r.title]
    assert len(t1583) == 5


def test_alert_flow_nrd_to_alert() -> None:
    """An NRD event flows through the rule and produces a positive match."""
    rule = parse_rule_file(
        Path("rules/builtin/mitre_attack/T1583_001_domain_acquisition_nrd.yml")
    )[0]
    ev = _event(
        dns_age_seconds=42,
        source_internal=True,
        query="veryfresh.example.com",
    )
    assert rule.matches(ev) is True


def test_alert_flow_typosquat_to_alert() -> None:
    """Typosquat detection path: brand_protection stamps flags, rule fires."""
    from zaqorincore_server.detection.brand_protection import first_typosquat

    observed = "mlcrosoft.com"
    match = first_typosquat(observed)
    assert match is not None and match.distance == 1 and match.is_legitimate is False

    rule = parse_rule_file(
        Path("rules/builtin/mitre_attack/T1583_001_domain_acquisition_typosquat.yml")
    )[0]
    ev = _event(
        typosquat_brand=True,
        typosquat_distance=match.distance,
        typosquat_is_legitimate=match.is_legitimate,
        query=observed,
    )
    assert rule.matches(ev) is True


def test_alert_flow_cdn_event_does_not_alert() -> None:
    """A CDN event must not produce an alert from any T1583.001 rule."""
    cdn_query = "asset.cloudfront.net"
    t1583_files = [
        "T1583_001_domain_acquisition_nrd.yml",
        "T1583_001_domain_acquisition_tld_burst.yml",
        "T1583_001_domain_acquisition_typosquat.yml",
        "T1583_001_domain_acquisition_dormant.yml",
    ]
    for fname in t1583_files:
        rule = parse_rule_file(Path("rules/builtin/mitre_attack") / fname)[0]
        ev = _event(query=cdn_query)
        # Dormant requires dns_last_seen_days + reactivation_burst, so
        # without those flags the rule will not match anyway.
        assert rule.matches(ev) is False, f"{fname} should not match CDN event"