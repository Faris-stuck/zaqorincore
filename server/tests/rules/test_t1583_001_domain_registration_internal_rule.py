"""Tests for the T1583.001 internal-registration Sigma rule."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import parse_rule_file


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/mitre_attack/T1583_001_domain_registration_internal.yml")
    )
    assert len(rules) == 1
    return rules[0]


def _event(**md) -> ParsedEvent:
    md.setdefault("event_type", "http_request")
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="zeek_http",
        raw="",
        metadata=md,
        occurred_at=datetime.now(timezone.utc),
    )


def test_registration_rule_loads() -> None:
    """Registration rule is high severity."""
    rule = _rule()
    assert rule.level == "high"
    assert rule.count == 1


def test_registration_rule_fires_on_register_post() -> None:
    """Internal POST to /register with custom UA fires the rule."""
    rule = _rule()
    assert rule.matches(
        _event(
            method="POST",
            source_internal=True,
            uri="/api/register",
            user_agent="EvilReg/1.0",
            host="registrar.example.com",
        )
    )


def test_registration_rule_fires_on_create_post() -> None:
    """Internal POST to /create with custom UA fires the rule."""
    rule = _rule()
    assert rule.matches(
        _event(
            method="POST",
            source_internal=True,
            uri="/account/create",
            user_agent="EvilReg/1.0",
            host="registrar.example.com",
        )
    )


def test_registration_rule_suppresses_curl_ua() -> None:
    """Known automation UA is suppressed."""
    rule = _rule()
    assert not rule.matches(
        _event(
            method="POST",
            source_internal=True,
            uri="/api/register",
            user_agent="curl/8.5.0",
            host="registrar.example.com",
        )
    )


def test_registration_rule_suppresses_non_register_path() -> None:
    """POST to /login (not /register or /create) does not fire."""
    rule = _rule()
    assert not rule.matches(
        _event(
            method="POST",
            source_internal=True,
            uri="/api/login",
            user_agent="EvilReg/1.0",
            host="app.example.com",
        )
    )