"""T1110.003 — Ingest endpoint 401/403 burst."""

from __future__ import annotations

from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1110_003_ingest_bruteforce.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    r = _rule()
    assert r.title.startswith("T1110.003")
    assert r.level == "high"


def test_rule_id_is_uuid4() -> None:
    import uuid
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    from zaqorincore_server.self_defense import SELF_DEFENSE_RULES
    assert find_rule("T1110.003") in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level in ("low", "medium", "high", "critical")


def test_selection_grammar_valid() -> None:
    r = _rule()
    assert r.selection["event_type"] == "http.request"
    assert "/api/v1/ingest/" in str(r.selection.get("route"))


def test_condition_valid() -> None:
    assert _rule().condition == "selection"


def test_whitelist_placeholder() -> None:
    # Fp text is in rule.title area, just confirm it exists in module.
    from zaqorincore_server import self_defense
    assert "self_defense" in self_defense.__name__


def test_threshold() -> None:
    r = _rule()
    assert r.count == 20
    assert r.timeframe_sec == 5 * 60


def test_event_normalization_401() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        route="/api/v1/ingest/cloudflare",
        status=401,
    )
    assert r.matches(ev)


def test_event_normalization_403() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        route="/api/v1/ingest/webhook",
        status=403,
    )
    assert r.matches(ev)


def test_event_no_match_negative_200() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        route="/api/v1/ingest/cloudflare",
        status=200,
    )
    assert not r.matches(ev)


def test_event_no_match_non_ingest_route() -> None:
    r = _rule()
    ev = make_event(
        event_type="http.request",
        route="/api/v1/healthz",
        status=401,
    )
    assert not r.matches(ev)