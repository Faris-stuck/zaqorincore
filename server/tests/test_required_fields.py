"""Tests for the v1.4.z `required_fields` fail-safe.

The `required_fields` rule attribute enforces strict
fail-closed semantics: if any of the listed metadata keys
is missing from the event, the rule does NOT fire.

This prevents noise from agents that haven't yet
implemented a particular metadata field (e.g. agents
that don't send `metadata.hour` for off-hours rules).

Covers:
- No required_fields: backwards compatible, rules fire
  based on condition alone (existing behavior)
- required_fields with all present: rule fires normally
- required_fields with one missing: rule does NOT fire
- required_fields with multiple required: all must be
  present, any missing → no fire
- Loader: invalid type for required_fields (not a list)
  raises SigmaRuleLoadError
- Loader: required_fields can be a top-level YAML key
  separate from `detection`
"""

from pathlib import Path

import uuid
from datetime import datetime, timezone

import pytest

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import (
    CompiledSigmaRule,
    SigmaRuleLoadError,
    parse_rule_file,
)


def _event(metadata: dict) -> ParsedEvent:
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="test.event",
        raw="{}",
        metadata=metadata,
        occurred_at=datetime.now(timezone.utc),
    )


def _rule_with_required(required: tuple[str, ...]) -> CompiledSigmaRule:
    return CompiledSigmaRule(
        id="r1",
        title="r1",
        level="high",
        selection={"source": "test.event"},
        detection={"selection": {"source": "test.event"}},
        condition="selection",
        count=1,
        timeframe_sec=0,
        cooldown_sec=0,
        dedup_key="",
        action=None,
        required_fields=required,
    )


def test_no_required_fields_fires_normally() -> None:
    """Default: no required_fields → rule fires on condition match."""
    rule = _rule_with_required(())
    assert rule.matches(_event({}))


def test_required_fields_all_present_fires() -> None:
    """All required fields present → rule fires on condition match."""
    rule = _rule_with_required(("foo", "bar"))
    assert rule.matches(_event({"foo": "1", "bar": "2"}))


def test_required_fields_one_missing_no_fire() -> None:
    """One required field missing → rule does NOT fire (fail-closed)."""
    rule = _rule_with_required(("foo", "bar"))
    assert not rule.matches(_event({"foo": "1"}))  # bar missing


def test_required_fields_all_missing_no_fire() -> None:
    """All required fields missing → no fire."""
    rule = _rule_with_required(("foo", "bar"))
    assert not rule.matches(_event({}))


def test_required_fields_extra_metadata_ok() -> None:
    """Required fields are a subset of metadata → rule fires."""
    rule = _rule_with_required(("foo",))
    assert rule.matches(_event({"foo": "1", "extra": "ok"}))


def test_required_fields_with_compound_condition_still_fail_closed() -> None:
    """required_fields check happens BEFORE condition dispatch.
    A `selection and (X or Y) and not Z` rule with missing
    required field must not fire even if compound would match."""
    rule = CompiledSigmaRule(
        id="r2",
        title="r2",
        level="high",
        selection={"source": "test.event"},
        detection={
            "selection": {"source": "test.event"},
            "filter_a": {"foo": "x"},
        },
        condition="selection and not filter_a",
        count=1,
        timeframe_sec=0,
        cooldown_sec=0,
        dedup_key="",
        action=None,
        required_fields=("metadata.hour",),
    )
    # metadata.hour missing → fail-closed
    assert not rule.matches(_event({"foo": "x"}))
    # metadata.hour present, but filter_a matches → not filter_a
    # fails → rule does NOT fire
    assert not rule.matches(
        _event({"foo": "x", "metadata.hour": "10"})
    )
    # metadata.hour present AND filter_a doesn't match
    # → rule fires
    assert rule.matches(
        _event({"bar": "x", "metadata.hour": "10"})
    )


def test_loader_accepts_required_fields_top_level() -> None:
    """The YAML loader reads `required_fields` from the top
    level of the rule (next to `id`, `title`, `level`).
    """
    rule = parse_rule_file(
        Path("rules/builtin/windows_eventlog/T1136_account_create.yml")
    )[0]
    assert rule.required_fields == ("metadata.hour",)


def test_loader_rejects_required_fields_not_a_list(tmp_path: Path) -> None:
    """YAML `required_fields: 42` (not a list) must raise
    SigmaRuleLoadError, not silently fall back to empty."""
    p = tmp_path / "bad.yml"
    p.write_text(
        "id: bad\n"
        "title: Bad\n"
        "level: low\n"
        "required_fields: 42\n"
        "detection:\n"
        "  selection:\n"
        "    source: test\n"
    )
    with pytest.raises(SigmaRuleLoadError, match="must be a list"):
        parse_rule_file(p)


def test_loader_default_required_fields_is_empty(tmp_path: Path) -> None:
    """A rule without `required_fields` loads with empty tuple."""
    p = tmp_path / "no_req.yml"
    p.write_text(
        "id: no-req\n"
        "title: No req\n"
        "level: low\n"
        "detection:\n"
        "  selection:\n"
        "    source: test\n"
    )
    rule = parse_rule_file(p)[0]
    assert rule.required_fields == ()
