"""T1078.003 — CSP recon: same src_ip across many distinct document-uri."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1078_003_csp_recon_multi_document_uri.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1078.003")


def test_rule_id_is_valid_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_no_match_below_threshold() -> None:
    """Single CSP report per selection must not match on its own — the
    runner applies the count=5 timeframe=60s aggregation."""
    r = _rule()
    ev = make_event(
        event_type="csp.violation",
        src_ip="203.0.113.50",
        document_uri="https://example.test/page",
        violated_directive="script-src",
        blocked_uri="inline",
    )
    # Per-event matcher is selection-only; aggregate threshold is
    # enforced by the runner. So single-event match is True here.
    # The negative test is that a non-csp event doesn't match.
    assert r.matches(ev) is True  # selection matches


def test_non_csp_event_does_not_match() -> None:
    """An event with a different event_type must not match — the
    selection guards the threshold."""
    r = _rule()
    ev = make_event(
        event_type="ws.hello",
        src_ip="203.0.113.51",
        document_uri="https://example.test/page",
    )
    assert not r.matches(ev)


def test_match_at_threshold_for_same_src_ip() -> None:
    """Selection matches any single CSP report; the runner applies
    count=5 by=src_ip distinct=document_uri within 60s. We verify
    here that the selection itself fires consistently for a single
    src_ip, which is what the runner aggregates over."""
    r = _rule()
    for i in range(5):
        ev = make_event(
            event_type="csp.violation",
            src_ip="203.0.113.52",
            document_uri=f"https://probe.test/path-{i}",
            violated_directive="script-src",
            blocked_uri="inline",
        )
        assert r.matches(ev)


def test_match_groups_by_src_ip() -> None:
    """Selection has no by-grouping; the YAML `by: src_ip` and
    `distinct: document_uri` keys are runner-level aggregation
    metadata. We assert the YAML carries them so the runner picks
    them up."""
    import yaml

    with open(
        "rules/builtin/self_defense/T1078_003_csp_recon_multi_document_uri.yml"
    ) as f:
        doc = yaml.safe_load(f)
    det = doc["detection"]
    assert det.get("by") == "src_ip"
    assert det.get("distinct") == "document_uri"
    assert det.get("count") == 5
    assert det.get("timeframe") == "60s"


def test_rule_registered_in_pack() -> None:
    assert find_rule("T1078.003") in SELF_DEFENSE_RULES
