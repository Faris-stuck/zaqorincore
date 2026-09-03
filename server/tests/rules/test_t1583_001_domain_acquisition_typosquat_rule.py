"""Tests for the T1583.001 typosquat Sigma rule and brand_protection helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.detection.brand_protection import (
    check_typosquat,
    first_typosquat,
    levenshtein,
    protected_brands,
)
from zaqorincore_server.rule_engine.sigma import parse_rule_file


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/mitre_attack/T1583_001_domain_acquisition_typosquat.yml")
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


def test_typosquat_rule_loads() -> None:
    """Typosquat rule is high severity with 1-event threshold."""
    rule = _rule()
    assert rule.level == "high"
    assert rule.count == 1


def test_typosquat_rule_fires_on_homograph() -> None:
    """Homograph (mlcrosoft.com) fires the rule."""
    rule = _rule()
    assert rule.matches(
        _event(
            typosquat_brand=True,
            typosquat_distance=1,
            typosquat_is_legitimate=False,
            query="mlcrosoft.com",
        )
    )


def test_typosquat_rule_suppresses_legitimate_brand() -> None:
    """Legitimate microsoft.com is NOT flagged."""
    rule = _rule()
    assert not rule.matches(
        _event(
            typosquat_brand=True,
            typosquat_distance=0,
            typosquat_is_legitimate=True,
            query="microsoft.com",
        )
    )


def test_typosquat_rule_suppresses_distance_too_high() -> None:
    """Distance > 2 is not flagged even when typosquat_brand=True."""
    rule = _rule()
    assert not rule.matches(
        _event(
            typosquat_brand=True,
            typosquat_distance=5,
            typosquat_is_legitimate=False,
        )
    )


def test_levenshtein_basic() -> None:
    """Levenshtein distance matches textbook examples."""
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("flaw", "lawn") == 2
    assert levenshtein("intention", "execution") == 5


def test_levenshtein_same_string_is_zero() -> None:
    """Same strings have distance 0."""
    assert levenshtein("microsoft.com", "microsoft.com") == 0


def test_check_typosquat_matches_legitimate() -> None:
    """Distance 0 returns a match with is_legitimate=True."""
    match = check_typosquat("microsoft.com", "microsoft.com")
    assert match is not None
    assert match.distance == 0
    assert match.is_legitimate is True


def test_check_typosquat_matches_homograph() -> None:
    """Distance 1 against microsoft returns a non-legit match."""
    match = check_typosquat("mlcrosoft.com", "microsoft.com")
    assert match is not None
    assert match.distance == 1
    assert match.is_legitimate is False


def test_check_typosquat_suppresses_unrelated() -> None:
    """Unrelated domain returns None."""
    assert check_typosquat("foo-bar-baz.example", "microsoft.com") is None


def test_first_typosquat_iterates_brand_list() -> None:
    """first_typosquat finds a match against any protected brand."""
    match = first_typosquat("komatsu.co.id", protected_brands())
    assert match is not None
    assert match.brand == "komatsu.co.id"