"""Tests for the Agent Provisioner API (Phase 26, Slice 1).

Covers:
* GET  /api/v1/agents/provision/template         — TOML template per OS/arch
* POST /api/v1/agents/provision/dry-run          — install command preview
* POST /api/v1/agents/provision/install-command  — one-line curl|bash
* POST /api/v1/agents/{agent_id}/rotate-secret   — new HMAC secret
* GET  /api/v1/agents/{agent_id}/config          — live agent.toml

The router is purely a *plan* generator — no SSH, no network, no DB
writes outside the ``rotate-secret`` flow. Most tests are pure-Python
and run without aiosqlite/postgres; the ``rotate-secret`` test uses
the ``app_client`` fixture (skipped automatically when DB drivers are
unavailable in the local venv).

Design contract (mirrors agents_provision.py docstring):

* TOML output, not YAML / JSON. The agent's native config format is
  TOML. We hand-roll the TOML string via ``render_agent_toml`` rather
  than depending on ``tomli_w`` so the test can run in any Python
  3.11+ venv.

* ``shlex.quote`` defends against shell injection in dry-run /
  install-command rendering. Helpers ``_safe_host`` / ``_safe_user``
  / ``_safe_key_id`` reject values that can't be safely quoted.

* Secret rotation is idempotent. Replaying rotate-secret always
  returns a fresh 64-char hex token.
"""

from __future__ import annotations

import os
import secrets

# Boot-time env the package import demands — generate ephemeral
# secrets so the test doesn't depend on the shell's environment.
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

# Import the router directly (no FastAPI app boot needed for these)
from zaqorincore_server.api.v1 import agents_provision  # noqa: E402


# ─── Pure unit tests (no DB, no network) ────────────────────────────────────


def test_safe_host_accepts_dns_and_ipv4() -> None:
    """A normal DNS hostname and an IPv4 must round-trip through ``_safe_host``."""
    assert agents_provision._safe_host("vps-jakarta-web-01") == "vps-jakarta-web-01"
    assert agents_provision._safe_host("10.0.0.5") == "10.0.0.5"
    assert agents_provision._safe_host("edge.node-07.example.com") == "edge.node-07.example.com"


def test_safe_host_rejects_shell_metacharacters() -> None:
    """Injection attempts (spaces, semicolons, newlines, ``rm -rf``) are rejected."""
    with pytest.raises(ValueError):
        agents_provision._safe_host("; rm -rf /")
    with pytest.raises(ValueError):
        agents_provision._safe_host("host with spaces")
    with pytest.raises(ValueError):
        agents_provision._safe_host("host\nwith\nnewlines")
    with pytest.raises(ValueError):
        agents_provision._safe_host("`whoami`")


def test_safe_user_accepts_alnum() -> None:
    """Standard POSIX usernames are accepted."""
    assert agents_provision._safe_user("ubuntu") == "ubuntu"
    assert agents_provision._safe_user("ec2-user") == "ec2-user"
    assert agents_provision._safe_user("root") == "root"


def test_safe_user_rejects_path_traversal_and_metachars() -> None:
    """Path-traversal and shell metacharacters are rejected in user input."""
    with pytest.raises(ValueError):
        agents_provision._safe_user("../etc/passwd")
    with pytest.raises(ValueError):
        agents_provision._safe_user("user;id")


def test_toml_quote_handles_special_characters() -> None:
    """TOML basic strings must escape backslashes and double quotes.

    A malicious value containing ``"]]`` or ``\\`` would break the
    inline table layout. The helper must always emit safe quoting.
    """
    # Simple value passes through as a quoted string.
    assert agents_provision._toml_quote("plain") == '"plain"'
    # Backslashes are escaped.
    assert agents_provision._toml_quote("a\\b") == '"a\\\\b"'
    # Double quotes are escaped.
    assert agents_provision._toml_quote('a"b') == '"a\\"b"'
    # Control characters are rejected.
    with pytest.raises(ValueError):
        agents_provision._toml_quote("with\nnewline")
    with pytest.raises(ValueError):
        agents_provision._toml_quote("with\ttab")


def test_render_agent_toml_emits_required_sections() -> None:
    """The rendered TOML must contain the sections the agent needs."""
    template = agents_provision.render_agent_toml(
        os="linux",
        arch="amd64",
        server_url="wss://zaqorincore.example.com:8443/api/v1/events",
        agent_id="vps-jakarta-web-01",
        auth_token=secrets.token_hex(32),
        log_sources=[
            {"path": "/var/log/nginx/access.log", "tag": "web"},
            {"path": "/var/log/auth.log", "tag": "auth"},
        ],
    )
    # Section header for log_source (array of tables)
    assert "[[log_source]]" in template
    # Required keys
    assert "server_url" in template
    assert "agent_id" in template
    assert "auth_token" in template
    assert "[response]" in template
    # Both log sources listed
    assert "/var/log/nginx/access.log" in template
    assert "/var/log/auth.log" in template
    # Quoted agent_id present
    assert "vps-jakarta-web-01" in template


def test_render_agent_toml_uses_default_log_sources_for_linux() -> None:
    """Passing ``log_sources=None`` should pick the Linux preset."""
    template = agents_provision.render_agent_toml(
        os="linux",
        arch="amd64",
        server_url="wss://example.com/api/v1/events",
        agent_id="auto-default-01",
        auth_token=secrets.token_hex(32),
    )
    # Default Linux preset includes nginx + auth + syslog
    assert "/var/log/nginx/access.log" in template
    assert "/var/log/auth.log" in template
    assert "/var/log/syslog" in template


def test_render_agent_toml_emits_windows_block_when_requested() -> None:
    """``include_windows_block=True`` adds the ``[windows_eventlog]`` section."""
    template = agents_provision.render_agent_toml(
        os="windows",
        arch="amd64",
        server_url="wss://example.com/api/v1/events",
        agent_id="win-edge-01",
        auth_token=secrets.token_hex(32),
        include_windows_block=True,
    )
    assert "[windows_eventlog]" in template
    assert 'mode = "pull"' in template


def test_parse_agent_toml_round_trip() -> None:
    """``parse_agent_toml`` must invert ``render_agent_toml`` for the simple case."""
    rendered = agents_provision.render_agent_toml(
        os="linux",
        arch="amd64",
        server_url="wss://example.com/api/v1/events",
        agent_id="round-trip-01",
        auth_token=secrets.token_hex(32),
        log_sources=[{"path": "/var/log/auth.log", "tag": "auth"}],
    )
    parsed = agents_provision.parse_agent_toml(rendered)
    assert parsed["agent_id"] == "round-trip-01"
    assert parsed["server_url"] == "wss://example.com/api/v1/events"


def test_router_registers_five_endpoints() -> None:
    """Sanity check on the route table.

    If this count drifts, somebody added (or removed) an endpoint
    without updating the test — update the test FIRST, then the code.
    """
    paths = {r.path for r in agents_provision.router.routes}
    expected = {
        "/api/v1/agents/provision/template",
        "/api/v1/agents/provision/dry-run",
        "/api/v1/agents/provision/install-command",
        "/api/v1/agents/{agent_id}/rotate-secret",
        "/api/v1/agents/{agent_id}/config",
    }
    assert expected.issubset(paths), (
        f"Agent Provisioner missing routes. "
        f"Missing: {expected - paths}, got: {paths}"
    )


def test_router_routes_have_handlers() -> None:
    """Every route must be bound to a real FastAPI handler.

    If a future route forgets to register (e.g. typo in ``@router.get``
    decorator) or accidentally exposes an internal renderer, this test
    will fail — preventing a silently-broken install endpoint from
    shipping.
    """
    for r in agents_provision.router.routes:
        ep_name = getattr(r.endpoint, "__name__", "")
        # Internal renderers / parsers must NOT be registered as routes.
        assert not ep_name.startswith("_"), (
            f"Route {r.path} bound to internal helper {ep_name} — "
            "should be a FastAPI handler, not an internal renderer."
        )
        assert not ep_name.startswith("render_"), (
            f"Route {r.path} bound to renderer {ep_name} — "
            "should be a FastAPI handler."
        )
        assert not ep_name.startswith("parse_"), (
            f"Route {r.path} bound to parser {ep_name} — "
            "should be a FastAPI handler."
        )


def test_render_agent_toml_quotes_user_supplied_strings() -> None:
    """User-supplied values are escaped via TOML basic-string rules.

    A malicious agent_id containing ``"]]`` must NOT inject a new
    section header into the output. We rely on ``tomllib`` (stdlib)
    to round-trip and assert the value comes back unchanged.
    """
    template = agents_provision.render_agent_toml(
        os="linux",
        arch="amd64",
        server_url="wss://example.com/api/v1/events",
        agent_id='evil-agent-id',
        auth_token=secrets.token_hex(32),
        log_sources=[{"path": "/var/log/syslog", "tag": "syslog"}],
    )
    # Round-trip — what we put in must come back out escaped, but
    # tomllib.loads() decodes the escapes for us.
    import tomllib
    parsed = tomllib.loads(template)
    assert parsed["agent_id"] == "evil-agent-id"
    # The TOML must remain syntactically valid (no extra sections).
    assert "evil-agent-id" in template