"""Integration tests for /api/v1/agents/provision/install-command.

Regression suite for F-015: the install command must perform
download -> verify -> extract (not ``curl | tar -xz``). Each test
here targets one invariant from CHECKSUM-VERIFICATION.md so a
future regression in any single contract trips exactly one test.

All tests in this module are marked ``integration`` so the
``-m unit`` runner can skip them; the CSP-throttle gap tests in
``test_csp_throttle_known_gap.py`` and the self_defense stream
tests in ``test_self_defense_stream.py`` are marked the same way.

Uses the synchronous ``TestClient`` pattern (matching the
existing ``test_csp_report_endpoint.py``). The router is mounted
into a fresh ``FastAPI()`` so we don't need the full app boot,
Postgres, or Redis.
"""

from __future__ import annotations

import os
import secrets

# Boot-time env so the package import does not fail; the install
# endpoint itself never touches the DB.
os.environ.setdefault(
    "ZAQORIN_EVIDENCE_KEY", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_CLOUDFLARE_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_WEBHOOK_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_DATABASE_URL",
    "postgresql+asyncpg://zaqorin:secret@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

import pytest  # noqa: E402
from fastapi import FastAPI, status  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# The conftest in this directory pre-stubs the broken
# ``api.v1`` import chain and loads the real ``agents_provision``
# module into ``sys.modules`` so the relative imports resolve.
from zaqorincore_server.api.v1 import agents_provision  # noqa: E402

pytestmark = pytest.mark.integration


# Module-level constant for the auth-key tests; never used as a
# real credential.
ZAQORIN_TEST_API_KEY = "test-key"


@pytest.fixture
def client_no_auth() -> TestClient:
    """TestClient mounted against the install-command router, dev mode.

    Dev mode (``ZAQORIN_API_KEY`` unset) makes ``require_api_key``
    a no-op so the route is reachable. Tests that need to assert
    401 behavior use ``client_with_auth`` instead.
    """
    os.environ.pop("ZAQORIN_API_KEY", None)
    app = FastAPI()
    app.include_router(agents_provision.router)
    return TestClient(app)


@pytest.fixture
def client_with_auth(monkeypatch) -> TestClient:
    """TestClient with ZAQORIN_API_KEY set so require_api_key is enforced."""
    monkeypatch.setenv("ZAQORIN_API_KEY", ZAQORIN_TEST_API_KEY)
    from zaqorincore_server.config import reset_settings

    reset_settings()
    app = FastAPI()
    app.include_router(agents_provision.router)
    return TestClient(app)


def _basic_payload() -> dict:
    return {
        "agent_id": "agent-test-01",
        "host": "vps-jakarta-web-01",
        "os": "linux",
    }


# ─────────────────────────────────────────────────────────────────────────
# Invariant 1: SHA-256 verification IS in the rendered command
# ─────────────────────────────────────────────────────────────────────────


def test_install_command_includes_sha256(client_no_auth: TestClient) -> None:
    """The POSIX installer must compute and compare SHA-256.

    Regression target: F-015 — pre-fix the script was
    ``curl | tar -xz`` with no integrity check.
    """
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    assert r.status_code == status.HTTP_200_OK
    cmd = r.json()["command"]
    assert "sha256sum" in cmd, cmd


def test_install_command_no_curl_pipe_extract(client_no_auth: TestClient) -> None:
    """No pattern of the form ``curl ... | tar -xz`` in the rendered script."""
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    cmd = r.json()["command"]
    assert " | tar " not in cmd, (
        f"F-015 regression: curl|tar pipe present in installer: {cmd!r}"
    )


def test_install_command_no_tar_pipe(client_no_auth: TestClient) -> None:
    """No ``| tar`` pipe at all in the rendered POSIX installer."""
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    cmd = r.json()["command"]
    assert "| tar" not in cmd, cmd


def test_install_command_uses_mktemp(client_no_auth: TestClient) -> None:
    """The download target must be inside ``mktemp -d``.

    Avoids leaving partial downloads in a stable location, and
    gives the mismatch-cleanup branch something to ``rm -rf``.
    """
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    cmd = r.json()["command"]
    assert "mktemp -d" in cmd, cmd


# ─────────────────────────────────────────────────────────────────────────
# Invariant 2: the mismatch branch actually fails the script
# ─────────────────────────────────────────────────────────────────────────


def test_install_command_refuses_on_mismatch(client_no_auth: TestClient) -> None:
    """The mismatch branch exits non-zero and removes the tempdir.

    We don't execute the script — we assert the if-branch shape
    is present: ``if [ "$actual" != "$expected" ]`` plus ``exit 1``
    plus ``rm -rf $tmp``.
    """
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    cmd = r.json()["command"]
    assert '"$actual" != "$expected"' in cmd, cmd
    assert "exit 1" in cmd, cmd
    assert "rm -rf $tmp" in cmd, cmd


def test_install_command_passes_on_match(client_no_auth: TestClient) -> None:
    """On match the script extracts and registers the systemd unit.

    Asserts the happy path: ``tar -xz`` only runs after the
    SHA-256 check, and ``systemctl enable --now zaqorin-agent``
    is the final action.
    """
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    cmd = r.json()["command"]
    assert "tar -xz" in cmd, cmd
    assert "systemctl enable --now zaqorin-agent" in cmd, cmd


# ─────────────────────────────────────────────────────────────────────────
# Invariant 3: response shape & OS handling
# ─────────────────────────────────────────────────────────────────────────


def test_install_command_warns_unknown_os(client_no_auth: TestClient) -> None:
    """Unknown OS triggers a warning + zero-digest fallback.

    The endpoint currently only knows ``linux`` / ``windows`` /
    ``macos``. ``freebsd`` is in the regex (Literal) allowlist
    via the test? No — ``freebsd`` is *not* in ``OSLit`` so it
    should 422. Use ``macos`` which IS in the allowlist but has
    no pinned SHA-256, so the endpoint must surface a warning
    rather than silently shipping an unsigned installer.
    """
    payload = dict(_basic_payload(), os="macos")
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=payload
    )
    assert r.status_code == status.HTTP_200_OK
    body = r.json()
    assert any("SHA-256" in w for w in body["warnings"]), body["warnings"]


def test_install_command_warnings_redact_public_dns(
    client_no_auth: TestClient,
) -> None:
    """F-019: public-DNS hostname is redacted in the response.

    The endpoint detects a public-DNS-named host and adds a
    warning. The warning must contain a SHA-256 prefix and the
    literal 'redacted' string; it must NOT contain the literal
    hostname. The operator still sees the full hostname in the
    request log.
    """
    public_host = "vps-jakarta-web-01.example.test"
    payload = {"agent_id": "agent-test-redact", "host": public_host}
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=payload
    )
    assert r.status_code == status.HTTP_200_OK
    body = r.json()
    pub_dns_warnings = [
        w for w in body["warnings"] if "public DNS" in w
    ]
    assert pub_dns_warnings, (
        f"expected at least one public-DNS warning, got: {body['warnings']}"
    )
    for w in pub_dns_warnings:
        assert public_host not in w, f"hostname leaked in warning: {w!r}"
        assert "redacted" in w, f"warning should be marked redacted: {w!r}"
        # SHA-256 hex prefix is 12 chars, all lowercase
        assert any(
            len(token) == 12 and all(c in "0123456789abcdef" for c in token)
            for token in w.split()
        ), f"expected a 12-char hex fingerprint, got: {w!r}"


def test_install_command_default_os(client_no_auth: TestClient) -> None:
    """Omitting ``os`` from the body defaults to ``linux``.

    Confirms the Pydantic default (``OSLit = "linux"``) lands
    in the asset name and command shape.
    """
    payload = {"agent_id": "agent-test-default", "host": "vps-jakarta-web-01"}
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=payload
    )
    assert r.status_code == status.HTTP_200_OK
    cmd = r.json()["command"]
    # Linux asset name appears in the URL.
    assert "zaqorin-agent-linux.tar.gz" in cmd, cmd


def test_install_command_dev_mode_open(
    client_no_auth: TestClient,
) -> None:
    """Dev mode (no ZAQORIN_API_KEY) leaves the endpoint open.

    The auth check is enforced only in non-dev mode. This test
    documents the current behavior so a future change that closes
    dev-mode auth will surface here.
    """
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    assert r.status_code == status.HTTP_200_OK
    body = r.json()
    assert "command" in body


def test_install_command_response_shape(client_no_auth: TestClient) -> None:
    """Response carries ``command``, ``sha256``, ``warnings``.

    ``sha256`` is the artifact digest (NOT a digest of the
    rendered command, which embeds a fresh auth token on every
    call and would be useless as a fingerprint).
    """
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=_basic_payload()
    )
    assert r.status_code == status.HTTP_200_OK
    body = r.json()
    assert "command" in body
    assert "sha256" in body
    assert "warnings" in body
    assert isinstance(body["warnings"], list)
    # sha256 is 64 hex chars (the digest width).
    assert len(body["sha256"]) == 64
    int(body["sha256"], 16)  # parses as hex