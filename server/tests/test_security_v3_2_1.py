"""Regression tests for v3.2.1 security fixes.

F1 — WebSocket /ws/agent HMAC challenge-response.
F2 — Agent secret file mode 0o600 + state_dir mode 0o700.
F3 — SOAR generic_webhook SSRF guard.
F4 — nft input validation (defence-in-depth).

These tests are intentionally hermetic. F3 imports the
package directly. F1 / F2 / F4 use source-level
inspection so the test does not require a running database
or a loaded FastAPI app (which has a hard dependency on
the ZAQORIN_EVIDENCE_KEY env var being set).
"""

from __future__ import annotations

import os

import pytest


# ---------------------------------------------------------------------------
# F1: WebSocket HMAC challenge-response
# ---------------------------------------------------------------------------


def _stream_source() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.normpath(
        os.path.join(
            here,
            "..", "src", "zaqorincore_server", "api", "v1", "stream.py",
        )
    )
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def test_f1_challenge_nonce_uses_secrets():
    src = _stream_source()
    assert '"type": "challenge"' in src
    assert "secrets.token_hex" in src


def test_f1_hello_must_carry_v2():
    src = _stream_source()
    assert 'if first.get("v") != 2' in src
    # Legacy agents are refused with 1002.
    assert "1002" in src


def test_f1_signature_verified_with_constant_time():
    src = _stream_source()
    assert "hmac.compare_digest" in src


def test_f1_hello_ack_no_longer_carries_shared_secret():
    """F1: the legacy field `shared_secret` in HELLO_ACK is
    gone. We parse the source of the hello_ack block and
    confirm the field name does not appear there."""
    src = _stream_source()
    # Locate the HELLO_ACK frame construction.
    start = src.find('"type": "hello_ack"')
    assert start > 0
    # Take the next 800 chars — more than enough to cover
    # the dict literal.
    chunk = src[start:start + 800]
    assert "shared_secret" not in chunk
    # And the literal value `host.secret` is not in this
    # region (it would have been a dead-code copy).
    assert "host.secret" not in chunk


def test_f1_bad_signature_closes_1008():
    src = _stream_source()
    assert "ws hello bad signature" in src
    assert "1008" in src  # policy violation


def test_f1_legacy_close_codes_preserved():
    """Regression: malformed-JSON still 1003, protocol
    error still 1002."""
    src = _stream_source()
    assert "1003" in src
    assert "1002" in src


# ---------------------------------------------------------------------------
# F2: secret file permissions
# ---------------------------------------------------------------------------


def _response_go_source() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.normpath(
        os.path.join(
            here, "..", "..", "agent", "internal", "response", "response.go",
        )
    )
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def test_f2_response_uses_0o700_state_dir():
    src = _response_go_source()
    assert "os.MkdirAll(cfg.StateDir, 0o700)" in src


def test_f2_write_secret_helper_writes_0o600():
    src = _response_go_source()
    assert "func WriteSecret(stateDir, secret string) error" in src
    assert "os.WriteFile(path, []byte(secret+\"\\n\"), 0o600)" in src
    assert "os.Chmod(path, 0o600)" in src
    # state_dir is also re-chmod'd in case it pre-existed
    # with looser perms.
    assert "os.Chmod(stateDir, 0o700)" in src


# ---------------------------------------------------------------------------
# F3: SOAR SSRF guard
# ---------------------------------------------------------------------------


def test_f3_validate_webhook_url_blocks_loopback_ipv4():
    from zaqorincore_server.soar.backends.generic_webhook import (
        validate_webhook_url,
    )

    err = validate_webhook_url("http://127.0.0.1/hook")
    assert err is not None
    assert "blocked" in err


def test_f3_validate_webhook_url_blocks_rfc1918():
    from zaqorincore_server.soar.backends.generic_webhook import (
        validate_webhook_url,
    )

    for u in (
        "http://10.0.0.5/hook",
        "http://192.168.1.10/hook",
        "http://172.16.0.5/hook",
    ):
        err = validate_webhook_url(u)
        assert err is not None, u


def test_f3_validate_webhook_url_blocks_link_local():
    from zaqorincore_server.soar.backends.generic_webhook import (
        validate_webhook_url,
    )

    # 169.254.169.254 is the cloud metadata service.
    err = validate_webhook_url("http://169.254.169.254/latest")
    assert err is not None
    assert "blocked" in err


def test_f3_validate_webhook_url_blocks_ipv6_loopback():
    from zaqorincore_server.soar.backends.generic_webhook import (
        validate_webhook_url,
    )

    assert validate_webhook_url("http://[::1]/hook") is not None


def test_f3_validate_webhook_url_blocks_malformed():
    from zaqorincore_server.soar.backends.generic_webhook import (
        validate_webhook_url,
    )

    assert validate_webhook_url("") is not None
    assert validate_webhook_url("not-a-url") is not None
    assert validate_webhook_url("ftp://example.com") is not None


def test_f3_validate_webhook_url_allowlist_bypasses(monkeypatch):
    """An operator who explicitly opts in via the env var
    can call an internal target."""
    from zaqorincore_server.soar.backends import generic_webhook

    monkeypatch.setenv(
        "ZAQORIN_SOAR_WEBHOOK_URL_ALLOWLIST",
        "hooks.internal, slack.example",
    )
    assert (
        generic_webhook.validate_webhook_url("https://hooks.internal/x") is None
    )
    # Case-insensitive.
    assert (
        generic_webhook.validate_webhook_url("https://HOOKS.INTERNAL/x") is None
    )
    # A different host is still blocked.
    assert generic_webhook.validate_webhook_url("https://10.0.0.5/x") is not None


def test_f3_validate_webhook_url_resolves_blocked_hostname(monkeypatch):
    """A hostname that resolves to a private IP is rejected
    even if the operator did not put an IP in the URL."""
    import socket

    from zaqorincore_server.soar.backends import generic_webhook

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.7", 0))
        ]

    monkeypatch.setattr(generic_webhook.socket, "getaddrinfo", _fake_getaddrinfo)
    err = generic_webhook.validate_webhook_url("http://internal.example/hook")
    assert err is not None
    assert "10.0.0.7" in err


# ---------------------------------------------------------------------------
# F4: nft input validation (defence-in-depth)
# ---------------------------------------------------------------------------


def _kinds_go_source() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.normpath(
        os.path.join(
            here, "..", "..", "agent", "internal", "response", "kinds",
            "kinds.go",
        )
    )
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def test_f4_nft_validators_guard_every_action():
    src = _kinds_go_source()
    # Both BlockIP and TarpitIP must validate the IP.
    assert src.count("if !IsValidIPv4(ip) {") >= 2


def test_f4_nft_never_invokes_a_shell():
    import re

    src = _kinds_go_source()
    assert "/bin/sh" not in src
    assert "sh -c" not in src
    # Every nft invocation uses exec.CommandContext.
    nft_calls = re.findall(
        r'exec\.(?:Command|CommandContext)\([^)]*"nft"', src
    )
    assert len(nft_calls) >= 4, nft_calls


def test_f4_injection_targets_defined_in_test():
    """The new F4 tests in kinds_test.go must cover the
    injection set: shell metacharacters, newlines, and
    command substitution."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.normpath(
        os.path.join(
            here, "..", "..", "agent", "internal", "response", "kinds",
            "kinds_test.go",
        )
    )
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    assert "TestF4_TarpitIPRejectsInjectionTargets" in src
    assert "TestF4_BlockIPRejectsInjectionTargets" in src
    # At least one shell-metacharacter literal in the test.
    assert "rm -rf" in src
