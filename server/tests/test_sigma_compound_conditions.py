"""Tests for the Sigma engine compound condition parsing shipped in v1.4.y.

ADR-010 extends `CompiledSigmaRule.matches()` from 2 patterns
to 4:

1. `selection` — existing behavior, no change
2. `selection and not filter` — NOW EVALUATES the filter
   (v1.4.0 silently dropped it)
3. `selection and (X or Y or Z)` — match if selection
   matches AND at least one of the listed filters matches
4. `selection and (X or Y) and not Z` — match if selection
   matches AND at least one of the OR filters matches AND
   the AND-NOT filter does not match

The previous v1.4.0 behavior of treating "selection and
not filter" as plain "selection" was a documented
limitation. v1.4.y fixes it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import CompiledSigmaRule


def _event(**metadata) -> ParsedEvent:
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="windows.security.4688",
        raw="",
        metadata=metadata,
        occurred_at=datetime.now(timezone.utc),
    )


# --------------------------------------------------------------------
# Pattern 2: `selection and not filter` — NOW EVALUATES the filter
# --------------------------------------------------------------------


def test_pattern2_fires_when_filter_does_not_match() -> None:
    """`selection and not filter` fires when filter does NOT match."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4688"},
        detection={
            "selection": {"source": "windows.security.4688"},
            "filter_workhours": {
                "metadata.hour": "hour|ge: 9",
            },
        },
        condition="selection and not filter_workhours",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # Hour 3 (early morning) → filter_workhours does NOT match → fire
    assert rule.matches(_event(**{"metadata.hour": 3}))


def test_pattern2_does_not_fire_when_filter_matches() -> None:
    """`selection and not filter` does NOT fire when filter matches."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4688"},
        detection={
            "selection": {"source": "windows.security.4688"},
            "filter_workhours": {
                "metadata.hour": "hour|ge: 9",
            },
        },
        condition="selection and not filter_workhours",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # Hour 14 (work hours) → filter_workhours matches → no fire
    assert not rule.matches(_event(**{"metadata.hour": 14}))


def test_pattern2_unknown_filter_does_not_match() -> None:
    """Unknown filter name → no match (don't fail-open)."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4688"},
        detection={
            "selection": {"source": "windows.security.4688"},
        },
        condition="selection and not nonexistent_filter",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    assert not rule.matches(_event())


# --------------------------------------------------------------------
# Pattern 3: `selection and (X or Y or Z)`
# --------------------------------------------------------------------


def test_pattern3_fires_when_at_least_one_filter_matches() -> None:
    """`selection and (X or Y)` fires when at least one filter matches."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4688"},
        detection={
            "selection": {"source": "windows.security.4688"},
            "filter_powershell": {
                "parent_process_name": "powershell.exe",
            },
            "filter_pwsh": {
                "parent_process_name": "pwsh.exe",
            },
        },
        condition="selection and (filter_powershell or filter_pwsh)",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # parent = powershell.exe → filter_powershell matches → fire
    assert rule.matches(
        _event(parent_process_name="powershell.exe")
    )
    # parent = pwsh.exe → filter_pwsh matches → fire
    assert rule.matches(_event(parent_process_name="pwsh.exe"))


def test_pattern3_does_not_fire_when_no_filter_matches() -> None:
    """`selection and (X or Y)` does NOT fire when no filter matches."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4688"},
        detection={
            "selection": {"source": "windows.security.4688"},
            "filter_powershell": {
                "parent_process_name": "powershell.exe",
            },
            "filter_pwsh": {
                "parent_process_name": "pwsh.exe",
            },
        },
        condition="selection and (filter_powershell or filter_pwsh)",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # parent = cmd.exe → no filter matches → no fire
    assert not rule.matches(
        _event(parent_process_name="cmd.exe")
    )


def test_pattern3_does_not_fire_when_selection_fails() -> None:
    """Even if a filter matches, the selection must also match."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4624"},
        detection={
            "selection": {"source": "windows.security.4624"},
            "filter_powershell": {
                "parent_process_name": "powershell.exe",
            },
        },
        condition="selection and (filter_powershell)",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # source is 4688 (not 4624) → selection fails → no fire even
    # though filter_powershell would match
    assert not rule.matches(
        _event(source="windows.security.4688",
               parent_process_name="powershell.exe")
    )


def test_pattern3_three_way_or() -> None:
    """Three filters in the OR group: any one matches → fire."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4688"},
        detection={
            "selection": {"source": "windows.security.4688"},
            "filter_a": {"metadata.hour": 1},
            "filter_b": {"metadata.hour": 2},
            "filter_c": {"metadata.hour": 3},
        },
        condition="selection and (filter_a or filter_b or filter_c)",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    assert rule.matches(_event(**{"metadata.hour": 2}))
    assert not rule.matches(_event(**{"metadata.hour": 4}))


# --------------------------------------------------------------------
# Pattern 4: `selection and (X or Y) and not Z`
# --------------------------------------------------------------------


def test_pattern4_fires_when_or_matches_and_not_doesnt() -> None:
    """Pattern 4 fires when at least one OR filter matches AND
    the AND-NOT filter does NOT match.

    Concrete off-hours check:
    - `filter_late` (hour >= 22) OR `filter_early` (hour < 6)
    - NOT `filter_business` (9 <= hour <= 17)

    Hour 23 is past 17 so it IS in the off-hours window
    (filter_business says 9 <= hour <= 17, hour=23 fails
    that range). We model filter_business as a 9-band list.
    Note: the engine compares event metadata value (a string
    in this fixture) against the list — int values would
    never match string list elements.
    """
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4720"},
        detection={
            "selection": {"source": "windows.security.4720"},
            "filter_late": {"metadata.hour": "hour|ge: 22"},
            "filter_early": {"metadata.hour": "hour|lt: 6"},
            "filter_business": {
                "metadata.hour": [
                    "9", "10", "11", "12", "13",
                    "14", "15", "16", "17",
                ],
            },
        },
        condition=(
            "selection and (filter_late or filter_early) "
            "and not filter_business"
        ),
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # Hour 23 (late) → filter_late matches (ge 22)
    # → not in business list → fire
    assert rule.matches(
        _event(
            source="windows.security.4720",
            **{"metadata.hour": "23"},
        )
    )
    # Hour 3 (early) → filter_early matches (lt 6)
    # → not in business list → fire
    assert rule.matches(
        _event(
            source="windows.security.4720",
            **{"metadata.hour": "3"},
        )
    )
    # Hour 14 (business) → no OR filter matches
    # (14 < 22 so not late, 14 >= 6 so not early)
    # → no fire
    assert not rule.matches(
        _event(
            source="windows.security.4720",
            **{"metadata.hour": "14"},
        )
    )


def test_pattern4_does_not_fire_when_not_filter_matches() -> None:
    """Pattern 4 does NOT fire when the AND-NOT filter matches."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4720"},
        detection={
            "selection": {"source": "windows.security.4720"},
            "filter_late": {"metadata.hour": "hour|ge: 22"},
            "filter_business": {
                "metadata.hour": "hour|ge: 9",
            },
        },
        condition=(
            "selection and (filter_late) and not filter_business"
        ),
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # Hour 23 (late) but filter_business says ge 9 → 23 >= 9 → matches
    # → not filter_business fails → no fire
    # (This is the off-hours check — you can't be both late AND business)
    assert not rule.matches(
        _event(**{"metadata.hour": "23"})
    )


def test_pattern4_does_not_fire_when_no_or_matches() -> None:
    """Pattern 4 does NOT fire when no OR filter matches."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4720"},
        detection={
            "selection": {"source": "windows.security.4720"},
            "filter_late": {"metadata.hour": "hour|ge: 22"},
            "filter_business": {
                "metadata.hour": "hour|ge: 9",
            },
        },
        condition=(
            "selection and (filter_late) and not filter_business"
        ),
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    # Hour 14 — late filter doesn't match (14 < 22) → no fire
    assert not rule.matches(
        _event(**{"metadata.hour": "14"})
    )


# --------------------------------------------------------------------
# Backward-compat sanity check
# --------------------------------------------------------------------


def test_pattern1_still_works() -> None:
    """`selection` alone still works after v1.4.y changes."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4625"},
        detection={
            "selection": {"source": "windows.security.4625"},
        },
        condition="selection",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    assert rule.matches(
        _event(source="windows.security.4625")
    )
    assert not rule.matches(
        _event(source="windows.security.4624")
    )


def test_unknown_condition_does_not_match() -> None:
    """An unknown condition string still returns False
    (don't fail-open)."""
    rule = CompiledSigmaRule(
        id="r1",
        title="t",
        level="high",
        selection={"source": "windows.security.4688"},
        detection={
            "selection": {"source": "windows.security.4688"},
        },
        condition="selection and (filter_x or filter_y) and not filter_z and filter_w",
        count=1,
        timeframe_sec=60,
        cooldown_sec=600,
        dedup_key="{{pid}}",
        action=None,
    )
    assert not rule.matches(_event())
