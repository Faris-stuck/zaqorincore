"""T1505.005 — CSP report with empty blocked-uri (probe signal)."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1505_005_csp_report_no_blocked_uri.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1505.005")


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_no_match_when_blocked_uri_present() -> None:
    """A real browser sends blocked_uri='inline' or an actual URL.
    The rule only fires on empty-string blocked_uri."""
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        src_ip="203.0.113.40",
        document_uri="https://example.test/app",
        violated_directive="script-src",
        blocked_uri="inline",
    )
    assert not r.matches(ev)


def test_no_match_when_blocked_uri_is_url() -> None:
    """A real browser sends blocked_uri as a URL. The rule only fires
    on empty-string blocked_uri."""
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        src_ip="203.0.113.42",
        document_uri="https://example.test/app",
        violated_directive="script-src",
        blocked_uri="https://evil.test/x.js",
    )
    assert not r.matches(ev)


def test_match_when_blocked_uri_is_empty_string() -> None:
    """Empty-string blocked_uri is the probe signal — a non-browser
    client or hand-crafted POST that bypassed the normaliser."""
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        src_ip="203.0.113.41",
        document_uri="https://probe.test/x",
        violated_directive="script-src",
        blocked_uri="",
    )
    assert r.matches(ev)


def test_level_is_low() -> None:
    assert _rule().level == "low"


def test_rule_registered_in_pack() -> None:
    assert find_rule("T1505.005") in SELF_DEFENSE_RULES
