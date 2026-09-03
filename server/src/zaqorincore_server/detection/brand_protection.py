"""Brand protection utilities for T1583.001 typosquat detection.

Implements a small Levenshtein edit-distance routine and a
``check_typosquat`` helper that compares an observed second-level
domain against the configured brand list. The default brand list is
overridable via the ``ZAQORIN_PROTECTED_BRANDS`` env var (comma-
separated second-level domains) so operators can extend it without
editing source.

The detector stage writes its findings onto the event metadata as
``typosquat_brand`` (the matched brand), ``typosquat_distance`` (the
computed edit distance), and ``typosquat_is_legitimate`` (True when
the registrant matches the brand itself).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


# Default brand list. Override via ZAQORIN_PROTECTED_BRANDS env var.
DEFAULT_PROTECTED_BRANDS: tuple[str, ...] = (
    "komatsu.co.id",
    "microsoft.com",
    "google.com",
)


@dataclass(frozen=True)
class TyposquatMatch:
    """Result of a brand typosquat comparison.

    Attributes:
        observed: The SLD we compared (e.g. ``"mlcrosoft.com"``).
        brand: The matched brand SLD (e.g. ``"microsoft.com"``).
        distance: Levenshtein edit distance between the two SLDs.
        length_delta: ``abs(len(observed) - len(brand))``. Used to
            guard against implausibly long or short comparisons.
        is_legitimate: True when the observed domain IS the brand
            (distance == 0).
    """

    observed: str
    brand: str
    distance: int
    length_delta: int
    is_legitimate: bool


def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings.

    Classic O(len(a) * len(b)) dynamic-programming implementation.
    Pure Python, no external dependencies, stable across Python 3.9+.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = curr_row[j - 1] + 1
            delete_cost = prev_row[j] + 1
            replace_cost = prev_row[j - 1] + (ca != cb)
            curr_row.append(min(insert_cost, delete_cost, replace_cost))
        prev_row = curr_row
    return prev_row[-1]


def protected_brands() -> tuple[str, ...]:
    """Return the active protected-brand list.

    Reads ``ZAQORIN_PROTECTED_BRANDS`` (comma-separated). Falls back
    to ``DEFAULT_PROTECTED_BRANDS`` when the env var is unset.
    """
    raw = os.environ.get("ZAQORIN_PROTECTED_BRANDS")
    if not raw:
        return DEFAULT_PROTECTED_BRANDS
    parsed = tuple(part.strip().lower() for part in raw.split(",") if part.strip())
    return parsed or DEFAULT_PROTECTED_BRANDS


def check_typosquat(
    observed: str,
    brand: str,
    *,
    max_distance: int = 2,
    max_length_delta: int = 3,
) -> TyposquatMatch | None:
    """Compare an observed domain to one brand.

    Returns a ``TyposquatMatch`` when:
      - Levenshtein distance between ``observed`` and ``brand`` is
        between 1 and ``max_distance`` (inclusive), and
      - ``abs(len(observed) - len(brand))`` is <= ``max_length_delta``.

    Returns ``None`` when the comparison does not meet the thresholds.
    Returns a match with ``is_legitimate=True`` only when distance is
    exactly 0 (i.e. the observed domain IS the brand).
    """
    o = observed.strip().lower()
    b = brand.strip().lower()
    distance = levenshtein(o, b)
    length_delta = abs(len(o) - len(b))
    if distance == 0:
        return TyposquatMatch(
            observed=o,
            brand=b,
            distance=0,
            length_delta=length_delta,
            is_legitimate=True,
        )
    if distance <= max_distance and length_delta <= max_length_delta:
        return TyposquatMatch(
            observed=o,
            brand=b,
            distance=distance,
            length_delta=length_delta,
            is_legitimate=False,
        )
    return None


def first_typosquat(
    observed: str,
    brands: tuple[str, ...] | None = None,
    *,
    max_distance: int = 2,
    max_length_delta: int = 3,
) -> TyposquatMatch | None:
    """Return the first matching typosquat across the brand list.

    Convenience wrapper used by the collector stage. ``brands``
    defaults to ``protected_brands()`` (env-driven).
    """
    for brand in brands or protected_brands():
        match = check_typosquat(
            observed,
            brand,
            max_distance=max_distance,
            max_length_delta=max_length_delta,
        )
        if match is not None:
            return match
    return None