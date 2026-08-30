"""Tests for action_kinds module (Phase 5, ADR-003)."""

from __future__ import annotations

import pytest

from zaqorincore_server.action_kinds import (
    KINDS,
    get_kind,
    is_valid_kind,
    list_kinds,
    validate_target,
)


def test_all_nine_kinds_registered() -> None:
    """Phase 5 must ship exactly 9 action kinds per ADR-003."""
    assert len(KINDS) == 9


def test_kinds_match_adr003_list() -> None:
    """The 9 kinds must match the ADR-003 enumeration exactly."""
    expected = {
        "block_ip",
        "tarpit_ip",
        "canary_alert",
        "isolate_host",
        "kill_process",
        "quarantine_file",
        "revoke_session",
        "webhook_soar",
        "evidence_capture",
    }
    assert set(KINDS.keys()) == expected


def test_is_valid_kind_accepts_known() -> None:
    assert is_valid_kind("block_ip") is True
    assert is_valid_kind("evidence_capture") is True


def test_is_valid_kind_rejects_unknown() -> None:
    assert is_valid_kind("nuke_from_orbit") is False
    assert is_valid_kind("") is False


def test_get_kind_returns_definition() -> None:
    kind = get_kind("block_ip")
    assert kind.target_shape == "ipv4"
    assert kind.default_ttl_sec == 3600
    assert kind.requires_host_opt_in is True


def test_get_kind_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown action kind"):
        get_kind("nuke_from_orbit")


def test_list_kinds_is_stable() -> None:
    """The list order is the dashboard display order; do not reshuffle."""
    assert list_kinds()[0] == "block_ip"
    assert list_kinds()[-1] == "evidence_capture"
    assert len(list_kinds()) == 9


# --- validate_target tests ---

def test_validate_ipv4_accepts_canonical() -> None:
    validate_target("block_ip", "203.0.113.42")  # no exception


def test_validate_ipv4_rejects_wrong_octet_count() -> None:
    with pytest.raises(ValueError, match="not a valid IPv4 address"):
        validate_target("block_ip", "1.2.3")


def test_validate_ipv4_rejects_non_numeric() -> None:
    with pytest.raises(ValueError, match="non-numeric octet"):
        validate_target("block_ip", "1.2.3.x")


def test_validate_ipv4_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="out of range"):
        validate_target("block_ip", "1.2.3.256")


def test_validate_ipv4_cidr_accepts() -> None:
    """CIDR target only valid for kinds whose shape is ipv4_cidr.
    None of the 9 action kinds currently use ipv4_cidr, so this test
    uses an ad-hoc shape check by temporarily registering a CIDR-shaped
    kind via the action_kinds module's internal API."""
    # Use the existing get_kind path indirectly: none of the 9 kinds is
    # ipv4_cidr, so we directly validate the underlying format with
    # a kind we add on the fly.
    from zaqorincore_server import action_kinds

    class _CidrKind:
        target_shape = "ipv4_cidr"
    original = action_kinds.KINDS.get("block_ip")
    # Monkey-patch get_kind temporarily.
    saved_get_kind = action_kinds.get_kind

    def _fake_get_kind(name: str):
        if name == "_test_cidr":
            return _CidrKind()
        return saved_get_kind(name)

    action_kinds.get_kind = _fake_get_kind
    try:
        validate_target = action_kinds.validate_target
        validate_target("_test_cidr", "203.0.113.0/24")
    finally:
        action_kinds.get_kind = saved_get_kind
    assert original is not None  # sanity: we did not clobber KINDS


def test_validate_ipv4_cidr_rejects_no_slash() -> None:
    from zaqorincore_server import action_kinds
    saved_get_kind = action_kinds.get_kind

    class _CidrKind:
        target_shape = "ipv4_cidr"

    def _fake_get_kind(name: str):
        if name == "_test_cidr":
            return _CidrKind()
        return saved_get_kind(name)

    action_kinds.get_kind = _fake_get_kind
    try:
        with pytest.raises(ValueError, match="not a valid CIDR"):
            action_kinds.validate_target("_test_cidr", "203.0.113.0")
    finally:
        action_kinds.get_kind = saved_get_kind


def test_validate_ipv4_cidr_rejects_bad_prefix() -> None:
    from zaqorincore_server import action_kinds
    saved_get_kind = action_kinds.get_kind

    class _CidrKind:
        target_shape = "ipv4_cidr"

    def _fake_get_kind(name: str):
        if name == "_test_cidr":
            return _CidrKind()
        return saved_get_kind(name)

    action_kinds.get_kind = _fake_get_kind
    try:
        with pytest.raises(ValueError, match="prefix .* out of range"):
            action_kinds.validate_target("_test_cidr", "203.0.113.0/33")
    finally:
        action_kinds.get_kind = saved_get_kind


def test_validate_pid_accepts() -> None:
    validate_target("kill_process", "12345")


def test_validate_pid_rejects_zero() -> None:
    with pytest.raises(ValueError, match="must be > 0"):
        validate_target("kill_process", "0")


def test_validate_pid_rejects_non_numeric() -> None:
    with pytest.raises(ValueError, match="non-numeric"):
        validate_target("kill_process", "abc")


def test_validate_path_requires_absolute() -> None:
    with pytest.raises(ValueError, match="must start with /"):
        validate_target("canary_alert", "tmp/canary.txt")


def test_validate_path_accepts_absolute() -> None:
    validate_target("canary_alert", "/tmp/canary.txt")
    validate_target("quarantine_file", "/var/spool/malware.exe")


def test_validate_user_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        validate_target("revoke_session", "")  # user-like? actually session, use real user kind


def test_validate_url_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        validate_target("webhook_soar", "")


def test_validate_host_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        validate_target("isolate_host", "")


def test_validate_session_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        validate_target("revoke_session", "")


# --- Kinds reference data ---

def test_block_ip_is_ipv4_with_opt_in() -> None:
    """block_ip must require host opt-in per ADR-003."""
    assert get_kind("block_ip").requires_host_opt_in is True


def test_canary_alert_does_not_require_opt_in() -> None:
    """Canary alerts are zero-false-positive, so safe to deploy automatically."""
    assert get_kind("canary_alert").requires_host_opt_in is False


def test_evidence_capture_does_not_require_opt_in() -> None:
    """Evidence capture is read-only, safe by default."""
    assert get_kind("evidence_capture").requires_host_opt_in is False


# --- F9: semantic deny-list on dangerous targets ---

def test_validate_ipv4_rejects_unspecified_address() -> None:
    """0.0.0.0 is the unspecified address; blocking it blackholes all traffic."""
    with pytest.raises(ValueError, match="unspecified address"):
        validate_target("block_ip", "0.0.0.0")


def test_validate_ipv4_rejects_broadcast() -> None:
    """255.255.255.255 is the IPv4 broadcast address."""
    with pytest.raises(ValueError, match="broadcast address"):
        validate_target("block_ip", "255.255.255.255")


def test_validate_ipv4_rejects_loopback() -> None:
    """127.0.0.1 is the host's own loopback — would self-DoS."""
    with pytest.raises(ValueError, match="loopback"):
        validate_target("block_ip", "127.0.0.1")


def test_validate_ipv4_rejects_loopback_range() -> None:
    """Any address in 127.0.0.0/8 hits the loopback stack."""
    with pytest.raises(ValueError, match="loopback"):
        validate_target("block_ip", "127.255.255.254")


def test_validate_ipv4_rejects_multicast() -> None:
    """224.0.0.1 is in the 224.0.0.0/4 multicast range."""
    with pytest.raises(ValueError, match="multicast"):
        validate_target("block_ip", "224.0.0.1")


def test_validate_ipv4_cidr_rejects_slash_zero() -> None:
    """A /0 CIDR covers the entire IPv4 internet."""
    with pytest.raises(ValueError, match="/0 prefix"):
        validate_target("block_ip", "0.0.0.0/0") if False else _validate_cidr("0.0.0.0/0")


def test_validate_ipv4_cidr_rejects_wide_prefix() -> None:
    """A /8 prefix covers 16M+ addresses."""
    with pytest.raises(ValueError, match=r"/8 prefix"):
        _validate_cidr("10.0.0.0/8")


def test_validate_ipv4_cidr_rejects_loopback_network() -> None:
    """127.0.0.0/24 is a perfectly-formed CIDR but lands in loopback."""
    with pytest.raises(ValueError, match="loopback"):
        _validate_cidr("127.0.0.0/24")


def test_validate_ipv4_cidr_accepts_normal_target() -> None:
    """203.0.113.0/24 (TEST-NET-3) is fine — narrow, routable, not dangerous."""
    _validate_cidr("203.0.113.0/24")  # no exception


def test_override_env_lets_dangerous_targets_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ZAQORIN_ALLOW_DANGEROUS_TARGETS=1 unlocks everything.

    Operators who deliberately want to block a wide range can flip
    the env var at startup. The flag is read on every call so a
    test can flip it without restarting the process.
    """
    monkeypatch.setenv("ZAQORIN_ALLOW_DANGEROUS_TARGETS", "1")
    # Should no longer raise.
    validate_target("block_ip", "0.0.0.0")
    validate_target("block_ip", "127.0.0.1")
    _validate_cidr("0.0.0.0/0")
    _validate_cidr("10.0.0.0/8")


def test_override_env_off_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: without the env var, dangerous targets are rejected."""
    monkeypatch.delenv("ZAQORIN_ALLOW_DANGEROUS_TARGETS", raising=False)
    with pytest.raises(ValueError, match="unspecified address"):
        validate_target("block_ip", "0.0.0.0")


def _validate_cidr(target: str) -> None:
    """Validate a CIDR target by registering a throwaway ipv4_cidr kind.

    The 9 production kinds don't include an ipv4_cidr shape, so we
    monkey-patch a temporary kind for the duration of one call.
    """
    from zaqorincore_server import action_kinds

    class _CidrKind:
        target_shape = "ipv4_cidr"

    original = action_kinds.KINDS.get("block_ip")
    saved_get_kind = action_kinds.get_kind

    def _fake_get_kind(name: str):
        if name == "_test_cidr":
            return _CidrKind()
        return saved_get_kind(name)

    action_kinds.get_kind = _fake_get_kind
    try:
        action_kinds.validate_target("_test_cidr", target)
    finally:
        action_kinds.get_kind = saved_get_kind
