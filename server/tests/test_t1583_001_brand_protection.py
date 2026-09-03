"""Unit tests for zaqorincore_server.detection.brand_protection.Levenshtein helpers."""

from __future__ import annotations

from zaqorincore_server.detection.brand_protection import (
    DEFAULT_PROTECTED_BRANDS,
    TyposquatMatch,
    check_typosquat,
    first_typosquat,
    levenshtein,
    protected_brands,
)


def test_levenshtein_identical() -> None:
    """Same string yields distance 0."""
    assert levenshtein("foo", "foo") == 0


def test_levenshtein_empty() -> None:
    """Distance to empty string equals the other string's length."""
    assert levenshtein("", "abc") == 3
    assert levenshtein("abc", "") == 3


def test_levenshtein_one_substitution() -> None:
    """One-character substitution is distance 1."""
    assert levenshtein("cat", "bat") == 1


def test_levenshtein_insertion_and_deletion() -> None:
    """Insertion and deletion are both counted."""
    assert levenshtein("cat", "cats") == 1
    assert levenshtein("cats", "cat") == 1


def test_levenshtein_case_sensitive() -> None:
    """The implementation is case-sensitive (caller should normalize)."""
    assert levenshtein("Cat", "cat") == 1


def test_default_brand_list_present() -> None:
    """The default brand list contains the three brands from the task spec."""
    assert "komatsu.co.id" in DEFAULT_PROTECTED_BRANDS
    assert "microsoft.com" in DEFAULT_PROTECTED_BRANDS
    assert "google.com" in DEFAULT_PROTECTED_BRANDS


def test_protected_brands_returns_default_when_env_unset(monkeypatch) -> None:
    """protected_brands() returns the defaults when no env override."""
    monkeypatch.delenv("ZAQORIN_PROTECTED_BRANDS", raising=False)
    assert protected_brands() == DEFAULT_PROTECTED_BRANDS


def test_protected_brands_honors_env_override(monkeypatch) -> None:
    """protected_brands() reads ZAQORIN_PROTECTED_BRANDS when set."""
    monkeypatch.setenv("ZAQORIN_PROTECTED_BRANDS", "apple.com, stripe.com")
    brands = protected_brands()
    assert "apple.com" in brands
    assert "stripe.com" in brands


def test_check_typosquat_legitimate_match() -> None:
    """Distance 0 yields is_legitimate=True."""
    match = check_typosquat("microsoft.com", "microsoft.com")
    assert isinstance(match, TyposquatMatch)
    assert match.is_legitimate is True
    assert match.distance == 0


def test_check_typosquat_within_distance_window() -> None:
    """Distance 1-2 with reasonable length delta yields a match."""
    match = check_typosquat("mlcrosoft.com", "microsoft.com")
    assert match is not None
    assert match.distance == 1
    assert match.is_legitimate is False


def test_check_typosquat_suppresses_long_distance() -> None:
    """Distance > max_distance returns None."""
    assert check_typosquat("totally-different.example", "microsoft.com") is None


def test_check_typosquat_suppresses_long_length_delta() -> None:
    """Length delta > max_length_delta returns None even for small distance."""
    # distance is 1, but length delta is far too large.
    assert check_typosquat("m.com", "microsoft.com") is None


def test_first_typosquat_finds_first_match() -> None:
    """first_typosquat returns the first matching brand in the list."""
    match = first_typosquat("mlcrosoft.com", ("microsoft.com", "google.com"))
    assert match is not None
    assert match.brand == "microsoft.com"


def test_first_typosquat_returns_none_when_no_match() -> None:
    """first_typosquat returns None when no brand matches."""
    assert first_typosquat("zzz.example", ("microsoft.com", "google.com")) is None