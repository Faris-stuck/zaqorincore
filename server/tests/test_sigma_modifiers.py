"""Tests for the Sigma spec modifier support shipped in v1.4.x.

Modifiers are checked in `_match_field` (via `_is_modifier_value`
+ `_match_modifier`) before the prefix-style `re:` / `contains:`
checks. The supported modifiers are:

  - `field|startswith: literal` — case-sensitive prefix
  - `field|endswith: literal`   — case-sensitive suffix
  - `field|ge: number`          — actual >= number
  - `field|lt: number`          — actual < number

The `field` portion of the syntax is redundant (the matcher
already received the key) but is kept for spec compatibility —
unmodified SigmaHQ rules can be dropped into the engine.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.rule_engine.sigma import (
    _is_modifier_value,
    _match_modifier,
)


def _event(**metadata) -> ParsedEvent:
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="test.event",
        raw="",
        metadata=metadata,
        occurred_at=datetime.now(timezone.utc),
    )


# --------------------------------------------------------------------
# _is_modifier_value — syntactic recognition
# --------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("field|startswith: foo", True),
        ("field|endswith: foo", True),
        ("field|ge: 5", True),
        ("field|lt: 18", True),
        ("powershell.exe", False),  # no `|`
        ("foo|bar", False),  # no `:`
        ("foo|unknown: bar", False),  # unknown modifier
        ("re:foo", False),  # prefix-style, not modifier
        ("contains:bar", False),  # prefix-style, not modifier
    ],
)
def test_is_modifier_value_recognises_known_modifiers(
    value: str, expected: bool
) -> None:
    assert _is_modifier_value(value) is expected


# --------------------------------------------------------------------
# startswith
# --------------------------------------------------------------------


def test_startswith_matches() -> None:
    assert _match_modifier("powershell.exe -enc ...", "field|startswith: powershell")


def test_startswith_rejects_non_prefix() -> None:
    assert not _match_modifier(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "field|startswith: powershell ",
    )


def test_startswith_case_sensitive() -> None:
    """Sigma spec says startswith is case-sensitive; we follow that."""
    assert not _match_modifier(
        "PowerShell.exe", "field|startswith: powershell"
    )


# --------------------------------------------------------------------
# endswith
# --------------------------------------------------------------------


def test_endswith_matches() -> None:
    assert _match_modifier("C:\\Windows\\lsass.exe", "field|endswith: lsass.exe")


def test_endswith_rejects_non_suffix() -> None:
    assert not _match_modifier(
        "C:\\Windows\\lsass.exe.bak", "field|endswith: lsass.exe"
    )


def test_endswith_case_sensitive() -> None:
    assert not _match_modifier("C:\\Windows\\LSASS.EXE", "field|endswith: lsass.exe")


# --------------------------------------------------------------------
# ge (greater than or equal)
# --------------------------------------------------------------------


@pytest.mark.parametrize("actual, lit, expected", [
    (10, "5", True),
    (5, "5", True),  # boundary
    (4, "5", False),
    ("10", "5", True),  # string-form numeric
    ("abc", "5", False),  # fail-safe: non-numeric actual → False
])
def test_ge(actual, lit: str, expected: bool) -> None:
    assert _match_modifier(actual, f"field|ge: {lit}") is expected


# --------------------------------------------------------------------
# lt (less than)
# --------------------------------------------------------------------


@pytest.mark.parametrize("actual, lit, expected", [
    (4, "5", True),
    (5, "5", False),  # boundary: < not <=
    (10, "5", False),
    ("4", "5", True),
    ("abc", "5", False),  # fail-safe
])
def test_lt(actual, lit: str, expected: bool) -> None:
    assert _match_modifier(actual, f"field|lt: {lit}") is expected


# --------------------------------------------------------------------
# Backwards-compat: existing prefix-style values still work
# --------------------------------------------------------------------


def test_re_prefix_still_works() -> None:
    """A `re:` value must NOT be mis-parsed as a modifier."""
    import sys
    from pathlib import Path
    from zaqorincore_server.rule_engine.sigma import load_rules_from_dir

    rules_dir = Path("rules/builtin")
    if not rules_dir.exists():
        pytest.skip("rules dir not present in this checkout")
    rules = load_rules_from_dir(rules_dir)
    # Find at least one rule that uses `re:` in its selection. The
    # ssh_bruteforce rule (v0.3.0) is a known user.
    re_rules = [
        r for r in rules
        if any(isinstance(v, str) and v.startswith("re:") for v in r.selection.values())
    ]
    if not re_rules:
        pytest.skip("no `re:` rules in this checkout to regression-test")
    # The parser must not have raised on the `re:` value, and the
    # rule must be callable.
    for r in re_rules:
        assert r.matches is not None


def test_contains_prefix_still_works() -> None:
    """A `contains:` value must NOT be mis-parsed as a modifier."""
    import sys
    from pathlib import Path
    from zaqorincore_server.rule_engine.sigma import load_rules_from_dir

    rules_dir = Path("rules/builtin")
    if not rules_dir.exists():
        pytest.skip("rules dir not present in this checkout")
    rules = load_rules_from_dir(rules_dir)
    contains_rules = [
        r for r in rules
        if any(
            isinstance(v, str) and v.startswith("contains:")
            for v in r.selection.values()
        )
    ]
    if not contains_rules:
        pytest.skip("no `contains:` rules in this checkout to regression-test")
    for r in contains_rules:
        assert r.matches is not None


# --------------------------------------------------------------------
# End-to-end: a Sigma rule using |startswith fires through the runner
# --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_startswith_modifier_fires_through_runner() -> None:
    """Wire the modifier syntax through a real rule + runner
    to make sure the matcher is reachable from the engine path,
    not just the helper functions."""
    import sys
    from pathlib import Path
    from zaqorincore_server.rule_engine.runner import SigmaRuleRunner
    from zaqorincore_server.rule_engine.sigma import load_rules_from_dir

    sys.path.insert(0, "tests")
    from fake_redis import FakeRedis  # type: ignore[import-not-found]

    # We need a rule that uses the modifier syntax. The T1059.001
    # PowerShell EncodedCommand rule (v1.4.x) uses both
    # `|startswith:` and `contains:` — so loading the rule dir
    # and asking for that one rule is the cleanest fixture.
    rules_dir = Path("rules/builtin/windows_eventlog")
    if not rules_dir.exists():
        pytest.skip("windows_eventlog rules not present in this checkout")
    rules = load_rules_from_dir(rules_dir)
    matches = [
        r for r in rules if r.id == "builtin-windows-4688-powershell-encoded"
    ]
    if not matches:
        pytest.skip(
            "T1059.001 rule not yet shipped; will be added with the "
            "v1.4.x rule bundle"
        )
    runner = SigmaRuleRunner(FakeRedis(), matches)
    fires = await runner.evaluate(
        _event(
            source="windows.security.4688",
            pid=4321,
            command_line=(
                "powershell.exe -EncodedCommand "
                "ZQBjAGgAbwAgACIAdABlAHMAdAAiAA=="
            ),
        )
    )
    assert len(fires) == 1
