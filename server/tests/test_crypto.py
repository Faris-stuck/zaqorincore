"""Unit tests for HMAC sign/verify."""

from __future__ import annotations

import pytest

from zaqorincore_server.crypto import (
    canonical_form,
    new_host_secret,
    sign_command,
    verify_command,
)


def test_new_host_secret_is_long_enough() -> None:
    s = new_host_secret()
    # 32 bytes base64url-encoded (no padding) is 43 chars.
    assert len(s) >= 32
    assert s.replace("-", "").replace("_", "").isalnum()


def test_sign_then_verify_roundtrip() -> None:
    secret = new_host_secret()
    sig = sign_command(
        secret=secret,
        command_id="abc-123",
        kind="block_ip",
        target="1.2.3.4",
        ttl_sec=3600,
        issued_at="2026-08-28T12:00:00Z",
    )
    assert verify_command(
        secret=secret,
        command_id="abc-123",
        kind="block_ip",
        target="1.2.3.4",
        ttl_sec=3600,
        issued_at="2026-08-28T12:00:00Z",
        hmac_hex=sig,
    )


def test_verify_fails_on_wrong_secret() -> None:
    sig = sign_command(
        secret="secret-a",
        command_id="x",
        kind="block_ip",
        target="1.1.1.1",
        ttl_sec=10,
        issued_at="2026-01-01T00:00:00Z",
    )
    assert not verify_command(
        secret="secret-b",
        command_id="x",
        kind="block_ip",
        target="1.1.1.1",
        ttl_sec=10,
        issued_at="2026-01-01T00:00:00Z",
        hmac_hex=sig,
    )


def test_verify_fails_on_tampered_target() -> None:
    secret = new_host_secret()
    sig = sign_command(
        secret=secret,
        command_id="x",
        kind="block_ip",
        target="1.1.1.1",
        ttl_sec=10,
        issued_at="2026-01-01T00:00:00Z",
    )
    assert not verify_command(
        secret=secret,
        command_id="x",
        kind="block_ip",
        target="2.2.2.2",  # tampered
        ttl_sec=10,
        issued_at="2026-01-01T00:00:00Z",
        hmac_hex=sig,
    )


def test_canonical_form_is_stable() -> None:
    a = canonical_form(
        command_id="a",
        kind="block_ip",
        target="1.2.3.4",
        ttl_sec=0,
        issued_at="2026-01-01T00:00:00Z",
    )
    b = canonical_form(
        command_id="a",
        kind="block_ip",
        target="1.2.3.4",
        ttl_sec=0,
        issued_at="2026-01-01T00:00:00Z",
    )
    assert a == b
    assert b"1.2.3.4" in a
    assert a == b"a|block_ip|1.2.3.4|0|2026-01-01T00:00:00Z"


def test_signatures_are_deterministic() -> None:
    secret = new_host_secret()
    sig1 = sign_command(
        secret=secret,
        command_id="x",
        kind="block_ip",
        target="9.9.9.9",
        ttl_sec=60,
        issued_at="2026-01-01T00:00:00Z",
    )
    sig2 = sign_command(
        secret=secret,
        command_id="x",
        kind="block_ip",
        target="9.9.9.9",
        ttl_sec=60,
        issued_at="2026-01-01T00:00:00Z",
    )
    assert sig1 == sig2


def test_signature_length_is_64_hex() -> None:
    sig = sign_command(
        secret="s",
        command_id="x",
        kind="k",
        target="t",
        ttl_sec=0,
        issued_at="2026-01-01T00:00:00Z",
    )
    assert len(sig) == 64
    int(sig, 16)  # parses as hex


def test_lowercase_hex_input_accepted() -> None:
    sig = sign_command(
        secret="s",
        command_id="x",
        kind="k",
        target="t",
        ttl_sec=0,
        issued_at="2026-01-01T00:00:00Z",
    )
    # Mix of upper/lower should still verify (we lowercase before compare).
    assert verify_command(
        secret="s",
        command_id="x",
        kind="k",
        target="t",
        ttl_sec=0,
        issued_at="2026-01-01T00:00:00Z",
        hmac_hex=sig.upper(),
    )


def test_wrong_kind_fails() -> None:
    secret = new_host_secret()
    sig = sign_command(
        secret=secret,
        command_id="x",
        kind="block_ip",
        target="1.1.1.1",
        ttl_sec=10,
        issued_at="2026-01-01T00:00:00Z",
    )
    assert not verify_command(
        secret=secret,
        command_id="x",
        kind="unblock_ip",
        target="1.1.1.1",
        ttl_sec=10,
        issued_at="2026-01-01T00:00:00Z",
        hmac_hex=sig,
    )


def test_wrong_ttl_fails() -> None:
    secret = new_host_secret()
    sig = sign_command(
        secret=secret,
        command_id="x",
        kind="k",
        target="t",
        ttl_sec=10,
        issued_at="2026-01-01T00:00:00Z",
    )
    assert not verify_command(
        secret=secret,
        command_id="x",
        kind="k",
        target="t",
        ttl_sec=11,
        issued_at="2026-01-01T00:00:00Z",
        hmac_hex=sig,
    )
