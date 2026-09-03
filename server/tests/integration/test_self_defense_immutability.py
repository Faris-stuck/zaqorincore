"""Runtime immutability checks for the self_defense rule registry.

Cycle 91 hardening (``perf(self-defense): use tuple for rule list``)
moved both ``SELF_DEFENSE_RULES`` and ``RULE_TITLES`` from ``list`` to
``tuple`` so the module-level caches cannot be mutated by accident.

These tests pin that property at runtime:

* both containers are tuples,
* mutation methods (``append``) raise ``AttributeError``,
* the rule count is exactly 20,
* every rule has a unique human-readable title.

Marked ``integration`` to share the import-time env setup in
``conftest.py`` and the boot env used by ``test_self_defense_stream``.
"""

from __future__ import annotations

import os
import secrets

# Boot-time env so the package import does not fail.
os.environ.setdefault(
    "ZAQORIN_EVIDENCE_KEY", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_CLOUDFLARE_INGEST_SECRET", secrets.token_urlsafe(32)
)

import pytest

from zaqorincore_server.self_defense import RULE_TITLES, SELF_DEFENSE_RULES


def test_self_defense_rules_is_tuple() -> None:
    """SELF_DEFENSE_RULES must be a tuple (cycle 91 hardening)."""
    assert isinstance(SELF_DEFENSE_RULES, tuple), (
        f"expected tuple, got {type(SELF_DEFENSE_RULES).__name__}"
    )


def test_rule_titles_is_tuple() -> None:
    """RULE_TITLES must mirror SELF_DEFENSE_RULES as a tuple."""
    assert isinstance(RULE_TITLES, tuple), (
        f"expected tuple, got {type(RULE_TITLES).__name__}"
    )


def test_self_defense_rules_not_mutable() -> None:
    """Calling ``.append`` on SELF_DEFENSE_RULES must raise AttributeError."""
    with pytest.raises(AttributeError):
        SELF_DEFENSE_RULES.append(object())  # type: ignore[attr-defined]


def test_self_defense_rules_count_is_21() -> None:
    """The cache must contain exactly 21 compiled rules (cycle 94)."""
    assert len(SELF_DEFENSE_RULES) == 21, (
        f"expected 21 rules, got {len(SELF_DEFENSE_RULES)}"
    )
    # RULE_TITLES must mirror the rule count.
    assert len(RULE_TITLES) == len(SELF_DEFENSE_RULES)


def test_self_defense_rules_have_unique_titles() -> None:
    """No two rules may share the same human-readable title."""
    titles = [r.title for r in SELF_DEFENSE_RULES]
    duplicates = {t for t in titles if titles.count(t) > 1}
    assert not duplicates, f"duplicate rule titles found: {sorted(duplicates)}"