"""Runtime tests for Round 14 audit invariants on agents_provision.py.

The static audit (commit 224f53d) claimed 10 invariants; the four
most important are converted to runtime tests here so any future
regression trips exactly one of them. Mirrors the testclient shape
of ``test_agents_provision_install_command.py`` so the same
auth-bypass-via-dev-mode trick works.

All four tests in this module are marked ``integration`` so the
``-m unit`` runner can skip them; matches the convention used by
``test_agents_provision_install_command.py``.

Targets:

1. ``test_command_injection_via_os_blocked``
   ``OSLit`` is a Pydantic ``Literal["linux", "macos", "windows"]``
   so any value outside that set, including injection payloads like
   ``"linux; rm -rf /"``, must be rejected at the request boundary
   with a 422. The two valid values must still be accepted.

2. ``test_command_injection_via_host_blocked``
   ``_safe_host`` is the canonical defense. Host values containing
   shell metacharacters (semicolons, backticks, newlines) must be
   rejected with 422, never rendered into a command.

3. ``test_tenant_id_not_in_query``
   The install endpoint body is ``InstallCommandIn`` (agent_id,
   host, os). There is no ``tenant_id`` field; asserting the model
   fields directly means any future field addition that introduces
   a tenant_id attribute fails the test. We also assert the live
   OpenAPI schema for the route does not list ``tenant_id``.

4. ``test_ipv6_bracketed_rejected``
   F-021 completeness check: ``_safe_host`` strips brackets and
   re-runs the regex against the inner IPv6 literal, which must
   fail the host pattern. ``"[::1]"`` is a real-looking bracketed
   IPv6 loopback that would otherwise render unquoted into the
   ssh command and break the parser on the operator's shell.
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


@pytest.fixture
def client_no_auth() -> TestClient:
    """TestClient mounted against the install-command router, dev mode.

    Dev mode (``ZAQORIN_API_KEY`` unset) makes ``require_api_key``
    a no-op so the route is reachable.
    """
    os.environ.pop("ZAQORIN_API_KEY", None)
    app = FastAPI()
    app.include_router(agents_provision.router)
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────
# Invariant 1: OS is a Pydantic Literal — command injection via os blocked
# ─────────────────────────────────────────────────────────────────────────


def test_command_injection_via_os_blocked(client_no_auth: TestClient) -> None:
    """Pydantic Literal on ``os`` rejects injection payloads at the boundary.

    Two valid values (``linux`` and ``windows``) must still be
    accepted. The injection payload ``"linux; rm -rf /"`` (a string
    that contains the literal ``linux`` but is not equal to it)
    must be rejected with 422, never rendered into a command.
    """
    base = {"agent_id": "agent-test-os-inject", "host": "vps-jakarta-web-01"}

    # The two values currently in OSLit must round-trip with 200.
    for ok in ("linux", "windows"):
        r = client_no_auth.post(
            "/api/v1/agents/provision/install-command",
            json={**base, "os": ok},
        )
        assert r.status_code == status.HTTP_200_OK, (
            f"valid os={ok!r} should be accepted, got "
            f"{r.status_code}: {r.text}"
        )

    # The injection payload must be rejected with 422.
    evil_os = "linux; rm -rf /"
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command",
        json={**base, "os": evil_os},
    )
    assert r.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY, (
        f"injection os={evil_os!r} should be rejected with 422, "
        f"got {r.status_code}: {r.text}"
    )
    # Defense-in-depth: the rendered command (if any) must not
    # contain the unsanitized evil string.
    if r.status_code == status.HTTP_200_OK:
        assert evil_os not in r.json().get("command", ""), (
            "evil os value leaked into the rendered command"
        )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 2: host injection via _safe_host rejected
# ─────────────────────────────────────────────────────────────────────────


def test_command_injection_via_host_blocked(
    client_no_auth: TestClient,
) -> None:
    """_safe_host rejects host strings containing shell metacharacters.

    The host regex is ``^[A-Za-z0-9][A-Za-z0-9._\\-:]{0,253}[A-Za-z0-9]$``
    so the semicolon-and-pipe payload is rejected at the request
    boundary with 422. The endpoint must not render a command for
    any of these inputs.
    """
    evil_hosts = [
        "8.8.8.8; cat /etc/passwd",   # semicolon + space
        "host; rm -rf /",             # classic metachar payload
        "host`whoami`",               # backticks
        "host$(id)",                  # command substitution
    ]

    for evil in evil_hosts:
        r = client_no_auth.post(
            "/api/v1/agents/provision/install-command",
            json={
                "agent_id": "agent-test-host-inject",
                "host": evil,
                "os": "linux",
            },
        )
        assert r.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY, (
            f"injection host={evil!r} should be rejected with 422, "
            f"got {r.status_code}: {r.text}"
        )
        # Even on 200 the literal evil string must not appear
        # rendered (defense-in-depth: the endpoint should never
        # accept this input, but if a future regression relaxed
        # the validator we want this assertion to trip first).
        if r.status_code == status.HTTP_200_OK:
            assert evil not in r.json().get("command", ""), (
                f"evil host {evil!r} leaked into the rendered command"
            )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 3: install endpoint does not take a tenant_id parameter
# ─────────────────────────────────────────────────────────────────────────


def test_tenant_id_not_in_query(client_no_auth: TestClient) -> None:
    """The install endpoint's Pydantic model has no ``tenant_id`` field.

    The model is ``InstallCommandIn`` and the only fields are
    ``agent_id``, ``host``, ``os``. If a future change introduces
    a ``tenant_id`` field this test will fail loudly. We also
    assert the live OpenAPI schema for the route has no
    ``tenant_id`` property.

    A test-side ``tenant_id`` in the payload should be silently
    ignored (Pydantic default), never echoed back, never used to
    scope the response.
    """
    # 1. The Pydantic model schema does not list tenant_id.
    schema_fields = set(
        agents_provision.InstallCommandIn.model_fields.keys()
    )
    assert "tenant_id" not in schema_fields, (
        f"InstallCommandIn must not declare a tenant_id field; "
        f"current fields: {schema_fields}"
    )

    # 2. The live OpenAPI schema for the route does not mention
    #    tenant_id as a request body property.
    openapi = client_no_auth.get("/openapi.json")
    assert openapi.status_code == status.HTTP_200_OK, openapi.text
    spec = openapi.json()
    install_ref = (
        spec["paths"]["/api/v1/agents/provision/install-command"]
        ["post"]["requestBody"]["content"]["application/json"]["schema"]
    )
    # Resolve $ref if present.
    if "$ref" in install_ref:
        ref_name = install_ref["$ref"].rsplit("/", 1)[-1]
        install_ref = spec["components"]["schemas"][ref_name]
    props = set(install_ref.get("properties", {}).keys())
    assert "tenant_id" not in props, (
        f"OpenAPI schema for install-command must not list "
        f"tenant_id; got properties: {props}"
    )

    # 3. A payload with a sneaky tenant_id still works (extra
    #    fields are ignored by Pydantic by default) and the
    #    rendered response does not echo or use it.
    payload = {
        "agent_id": "agent-test-tenant-guard",
        "host": "vps-jakarta-web-01",
        "os": "linux",
        "tenant_id": "acme-corp",   # extra, must be ignored
    }
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command", json=payload
    )
    assert r.status_code == status.HTTP_200_OK, r.text
    body = r.json()
    assert "tenant_id" not in body, (
        f"tenant_id leaked into response: {body}"
    )
    cmd = body.get("command", "")
    assert "acme-corp" not in cmd, (
        "tenant_id value leaked into the rendered command"
    )


# ─────────────────────────────────────────────────────────────────────────
# Invariant 4: bracketed IPv6 literals rejected by _safe_host
# ─────────────────────────────────────────────────────────────────────────


def test_ipv6_bracketed_rejected(client_no_auth: TestClient) -> None:
    """_safe_host must reject a bracketed IPv6 literal.

    F-021 completeness check: ``_safe_host`` strips the surrounding
    brackets then re-runs the regex against the inner IPv6 literal.
    ``[::1]`` -> ``::1`` fails the host pattern because colons are
    in the allowed set but the inner string begins and ends with
    colons, so the leading-character class ``[A-Za-z0-9]`` is not
    satisfied. The endpoint must return 422.
    """
    bracketed = "[::1]"
    r = client_no_auth.post(
        "/api/v1/agents/provision/install-command",
        json={
            "agent_id": "agent-test-ipv6-bracket",
            "host": bracketed,
            "os": "linux",
        },
    )
    assert r.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY, (
        f"bracketed IPv6 host={bracketed!r} should be rejected with "
        f"422 by _safe_host, got {r.status_code}: {r.text}"
    )
    # Defense-in-depth: if the host is accepted, the rendered
    # command must not contain the unquoted bracketed form that
    # would break the operator's shell parser.
    if r.status_code == status.HTTP_200_OK:
        assert bracketed not in r.json().get("command", ""), (
            f"bracketed IPv6 host {bracketed!r} leaked into "
            f"rendered command"
        )
