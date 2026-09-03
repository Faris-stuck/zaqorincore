"""v3.2.2 security hardening regression tests (PHASE 4).

One regression test per finding closed in v3.2.2:

* ``test_f005_app_version_from_package_metadata`` — F-005
  the FastAPI ``app.version`` is read from ``importlib.metadata``
  so it cannot drift from pyproject.toml again.
* ``test_f006_stats_requires_auth`` / ``test_f006_version_requires_auth``
  F-006: ``/api/v1/stats`` and ``/api/v1/version`` reject
  unauthenticated callers in production mode.
* ``test_f012_whoami_omits_role_list_in_production`` /
  ``test_f012_whoami_omits_dev_mode_in_production`` /
  ``test_f012_whoami_includes_dev_mode_in_development`` — F-012:
  the redacted ``/auth/whoami`` payload excludes ``configured_roles``
  in every environment and excludes ``dev_mode`` outside
  ``ZAQORIN_ENV=development``.
* ``test_f008_persistent_audit_log_writes_jsonl`` /
  ``test_f008_persistent_audit_log_rotates_daily`` /
  ``test_f008_in_memory_audit_still_works_when_dir_unset`` /
  ``test_f008_disk_failure_falls_back_to_memory`` — F-008: the
  audit log appends one JSONL line per event under
  ``ZAQORIN_AUDIT_LOG_DIR`` with daily rotation, while the
  in-memory ring buffer keeps working as a fallback.
* ``test_f013_ingest_cloudflare_records_audit`` /
  ``test_f013_ingest_webhook_records_audit`` /
  ``test_f013_sources_create_records_audit`` /
  ``test_f013_sources_delete_records_audit`` — F-013: ingest
  endpoints and source CRUD call ``audit.record()``.

Tests run in dev mode (no API keys) by default; tests that
exercise auth-sensitive paths use the local ``app_client_with_auth``
fixture shape via ``monkeypatch`` + ``reset_settings``.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import AsyncClient

from zaqorincore_server import audit
from zaqorincore_server.config import reset_settings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_audit_between_tests():
    """Reset the audit module (in-memory tier + cached handle)
    between tests so each case starts from a clean log.

    The persistent tier is NOT cleared — operators inspect the
    on-disk file separately. We DO close the file handle so the
    next ``record()`` call reopens it (and picks up an env-var
    change that another fixture may have made).
    """
    import zaqorincore_server.audit as audit_mod

    audit_mod.reset()
    # Also force the module-level dir / handle state so a test that
    # sets ``ZAQORIN_AUDIT_LOG_DIR`` starts with no stale file from
    # a previous test.
    audit_mod._persist_dir = (
        Path(os.environ.get("ZAQORIN_AUDIT_LOG_DIR")).expanduser().resolve()
        if os.environ.get("ZAQORIN_AUDIT_LOG_DIR")
        else None
    )
    if audit_mod._persist_handle is not None:
        try:
            audit_mod._persist_handle.close()
        except Exception:  # noqa: BLE001
            pass
    audit_mod._persist_handle = None
    audit_mod._persist_file = None
    audit_mod._persist_date = None
    audit_mod._persist_warned = False
    yield


@pytest.fixture
def app_client_with_auth(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """Production-like — one role-key set so ``require_role``
    enforces the API-key path. Mirrors the pattern in
    ``test_routers_api_auth.py`` so the two fixture trees
    stay in sync.
    """
    monkeypatch.setenv("ZAQORIN_API_KEY_READ", "read-secret-v3-2-2")
    monkeypatch.setenv("ZAQORIN_API_KEY_WRITE", "write-secret-v3-2-2")
    monkeypatch.delenv("ZAQORIN_API_KEY", raising=False)
    monkeypatch.delenv("ZAQORIN_API_KEY_INGEST", raising=False)
    reset_settings()
    return app_client


# ---------------------------------------------------------------------------
# F-005 — app.version from package metadata
# ---------------------------------------------------------------------------


async def test_f005_app_version_from_package_metadata(
    app_client: AsyncClient,
) -> None:
    """``/api/v1/version`` reflects the package metadata version.

    Before v3.2.2, ``main.py`` carried a literal ``version="3.2.0"``
    while pyproject.toml said ``3.2.1`` — operator-visible drift.
    The fix reads from ``importlib.metadata.version(...)`` so the
    two surfaces are guaranteed to agree.
    """
    from importlib.metadata import version as _pkg_version

    expected = _pkg_version("zaqorincore-server")
    r = await app_client.get("/api/v1/version")
    assert r.status_code == 200
    assert r.json()["version"] == expected
    assert expected  # package must be installed


# ---------------------------------------------------------------------------
# F-006 — /stats + /version require auth in production mode
# ---------------------------------------------------------------------------


async def test_f006_stats_requires_auth(
    app_client_with_auth: AsyncClient,
) -> None:
    """Unauthenticated ``GET /api/v1/stats`` returns 401.

    Before v3.2.2 the endpoint was reachable without an API key
    and leaked the running version, git SHA, pid, and
    connected-agent count. Now ``require_role(READ)`` gates the
    router.
    """
    r = await app_client_with_auth.get("/api/v1/stats")
    assert r.status_code == 401, r.text
    assert r.headers.get("www-authenticate") == "ApiKey"


async def test_f006_version_requires_auth(
    app_client_with_auth: AsyncClient,
) -> None:
    """Unauthenticated ``GET /api/v1/version`` returns 401.

    Same rationale as ``test_f006_stats_requires_auth``: the
    build-identity payload (version + git SHA) is operator-only.
    """
    r = await app_client_with_auth.get("/api/v1/version")
    assert r.status_code == 401, r.text
    assert r.headers.get("www-authenticate") == "ApiKey"


async def test_f006_stats_works_with_valid_read_key(
    app_client_with_auth: AsyncClient,
) -> None:
    """A valid ``read`` role key still gets the full stats payload.

    The fix must NOT remove operator visibility — it gates the
    endpoint on auth. The WebUI's read-role credentials must
    still get the same shape it had pre-v3.2.2.
    """
    r = await app_client_with_auth.get(
        "/api/v1/stats",
        headers={"X-API-Key": "read-secret-v3-2-2"},
    )
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {
        "version",
        "git_sha",
        "rules_loaded",
        "agents_connected",
        "uptime_seconds",
        "pid",
    }


# ---------------------------------------------------------------------------
# F-012 — whoami redacts configured_roles + dev_mode
# ---------------------------------------------------------------------------


async def test_f012_whoami_omits_role_list_in_production(
    app_client: AsyncClient,
) -> None:
    """``/auth/whoami`` no longer exposes the full configured_roles.

    The list lets a ``read``-role user enumerate the auth surface
    (which keys exist, which roles are configured). The fix drops
    the field from the public response.
    """
    r = await app_client.get("/api/v1/auth/whoami")
    assert r.status_code == 200
    body = r.json()
    assert "configured_roles" not in body, (
        "F-012: configured_roles must not be exposed on /auth/whoami"
    )


async def test_f012_whoami_omits_dev_mode_in_production(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``/auth/whoami`` omits ``dev_mode`` in production.

    ``dev_mode: true`` from a remote deployment is a recon signal
    ("the server is running without any API keys configured"). The
    field is only emitted when ``ZAQORIN_ENV=development``.
    """
    monkeypatch.delenv("ZAQORIN_ENV", raising=False)
    reset_settings()
    r = await app_client.get("/api/v1/auth/whoami")
    assert r.status_code == 200
    body = r.json()
    assert body.get("dev_mode") in (None, False), (
        "F-012: dev_mode must not surface in production; got "
        f"{body.get('dev_mode')!r}"
    )


async def test_f012_whoami_includes_dev_mode_in_development(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``ZAQORIN_ENV=development``, ``dev_mode: true`` is present.

    The dev path still works — a developer on localhost can verify
    the boot mode.
    """
    monkeypatch.setenv("ZAQORIN_ENV", "development")
    reset_settings()
    r = await app_client.get("/api/v1/auth/whoami")
    assert r.status_code == 200
    body = r.json()
    assert body.get("dev_mode") is True


# ---------------------------------------------------------------------------
# F-008 — persistent audit log (JSONL, daily rotation)
# ---------------------------------------------------------------------------


async def test_f008_persistent_audit_log_writes_jsonl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each ``audit.record()`` appends one JSONL line under the
    configured directory.

    Lines are JSON-decodable and contain the audit fields the
    module documents (ts, actor, action, target, status).
    """
    monkeypatch.setenv("ZAQORIN_AUDIT_LOG_DIR", str(tmp_path))
    audit_mod = audit
    audit_mod.reset()
    audit_mod._persist_dir = tmp_path
    audit_mod._persist_handle = None
    audit_mod._persist_file = None
    audit_mod._persist_date = None

    audit.record(
        actor="test-actor",
        action="test-action",
        target="test-target",
        status=200,
        extra={"foo": "bar"},
    )

    files = list(tmp_path.glob("audit-*.jsonl"))
    assert len(files) == 1, f"expected 1 audit file, got {files}"
    lines = files[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["actor"] == "test-actor"
    assert entry["action"] == "test-action"
    assert entry["target"] == "test-target"
    assert entry["status"] == 200
    assert entry["foo"] == "bar"
    # ``ts`` is ISO-8601 so jq / grep / log shippers handle it.
    assert isinstance(entry["ts"], str)
    # And it's a parseable ISO-8601 timestamp.
    datetime.fromisoformat(entry["ts"].replace("Z", "+00:00"))


async def test_f008_persistent_audit_log_rotates_daily(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the date boundary moves, a new file is opened.

    We simulate the rotation by writing under two fake dates and
    confirming the module reopens rather than appending to the old
    file.
    """
    monkeypatch.setenv("ZAQORIN_AUDIT_LOG_DIR", str(tmp_path))
    audit_mod = audit
    audit_mod.reset()
    audit_mod._persist_dir = tmp_path
    audit_mod._persist_handle = None
    audit_mod._persist_file = None
    audit_mod._persist_date = None

    # First entry under "today"
    audit.record(actor="a", action="first", target="t1")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_file = tmp_path / f"audit-{today}.jsonl"
    assert today_file.exists()

    # Force rotation by rewriting the cached date.
    audit_mod._persist_date = "1999-01-01"
    audit.record(actor="a", action="after_rotation", target="t2")

    # The new entry must land in today's file, not the old one.
    old_file = tmp_path / "audit-1999-01-01.jsonl"
    if old_file.exists():
        old_lines = old_file.read_text(encoding="utf-8").splitlines()
        # If the date-rolled-over path is taken, the rotated
        # handle will close and reopen today's. The 1999 file
        # may exist briefly with no entries, OR may be opened
        # and then closed. Either way: today's file gets the
        # entry written AFTER the rotation.
        assert all(
            json.loads(ln)["action"] != "after_rotation"
            for ln in old_lines
        )
    today_lines = today_file.read_text(encoding="utf-8").splitlines()
    actions = [json.loads(ln)["action"] for ln in today_lines]
    assert "first" in actions
    assert "after_rotation" in actions


async def test_f008_in_memory_audit_still_works_when_dir_unset() -> None:
    """When ``ZAQORIN_AUDIT_LOG_DIR`` is unset, the in-memory tier
    keeps working — operators on a dev box get the existing
    cycle-19 behaviour with no env-var change required.
    """
    audit_mod = audit
    audit_mod.reset()
    audit_mod._persist_dir = None
    audit_mod._persist_handle = None
    audit_mod._persist_file = None

    item = audit.record(
        actor="a", action="memory-only", target="t"
    )
    assert item["action"] == "memory-only"

    snap = audit.snapshot()
    actions = [e.get("action") for e in snap]
    assert "memory-only" in actions


async def test_f008_disk_failure_falls_back_to_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the directory is unwritable, the audit module still
    records into the in-memory tier and emits a single warning.

    ``record()`` must never raise out of a filesystem failure —
    audit must not block the request path.
    """
    # Point the dir at a path under a non-existent parent so the
    # mkdir fails. We use a deeply-nested path under /dev/null
    # which can't have children.
    audit_mod = audit
    audit_mod.reset()
    audit_mod._persist_dir = Path("/dev/null/this/should/fail")
    audit_mod._persist_handle = None
    audit_mod._persist_file = None
    audit_mod._persist_date = None
    audit_mod._persist_warned = False

    # Must not raise.
    item = audit.record(
        actor="a", action="fallback", target="t"
    )
    assert item["action"] == "fallback"

    # In-memory snapshot still has the entry.
    snap = audit.snapshot()
    actions = [e.get("action") for e in snap]
    assert "fallback" in actions


# ---------------------------------------------------------------------------
# F-013 — audit hooks on ingest + sources CRUD
# ---------------------------------------------------------------------------


async def test_f013_ingest_cloudflare_records_audit(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``POST /api/v1/ingest/cloudflare`` writes one audit entry.

    Auth on this endpoint is HMAC, not X-API-Key, so the
    dev-mode ``app_client`` fixture (no keys set) can reach it.
    We use a precomputed signature so the body is accepted.
    """
    import hashlib
    import hmac as _hmac

    from zaqorincore_server.api.v1.ingest_cloudflare import (
        HMAC_HEADER_NAME,
        _HMAC_SECRET,
    )

    # Set up the HMAC secret the ingest module needs.
    monkeypatch.setenv(
        "ZAQORIN_CLOUDFLARE_INGEST_SECRET", "test-cloudflare-secret"
    )
    # Force the ingest module to re-import with the new env var.
    import zaqorincore_server.api.v1.ingest_cloudflare as cf_mod

    monkeypatch.setattr(cf_mod, "_HMAC_SECRET", b"test-cloudflare-secret")

    body = b'{"ClientIP":"1.2.3.4","EdgeStartTimestamp":"2026-09-03T00:00:00Z"}\n'
    sig = _hmac.new(b"test-cloudflare-secret", body, hashlib.sha256).hexdigest()

    audit.reset()
    r = await app_client.post(
        "/api/v1/ingest/cloudflare",
        content=body,
        headers={
            "Content-Type": "application/x-ndjson",
            HMAC_HEADER_NAME: sig,
        },
    )
    assert r.status_code == 200, r.text

    snap = audit.snapshot()
    actions = [e.get("action") for e in snap]
    assert "ingest cloudflare" in actions


async def test_f013_ingest_webhook_records_audit(
    app_client: AsyncClient,
) -> None:
    """``POST /api/v1/ingest/webhook`` writes one audit entry."""
    body = {
        "src_ip": "10.1.2.3",
        "occurred_at": "2026-09-03T00:00:00Z",
    }
    audit.reset()
    r = await app_client.post("/api/v1/ingest/webhook", json=body)
    assert r.status_code == 200, r.text

    snap = audit.snapshot()
    actions = [e.get("action") for e in snap]
    assert "ingest webhook" in actions


async def test_f013_sources_create_records_audit(
    app_client: AsyncClient,
) -> None:
    """``POST /api/v1/sources/webhook`` writes one audit entry.

    We use the webhook flavour because it requires the fewest
    upstream-specific fields (Cloudflare wants a zone_id, AWS
    wants an IAM ARN, syslog wants a host/port).
    """
    audit.reset()
    r = await app_client.post(
        "/api/v1/sources/webhook",
        json={"name": "test-connector", "format": "generic"},
    )
    assert r.status_code == 201, r.text

    snap = audit.snapshot()
    actions = [e.get("action") for e in snap]
    assert "create source (webhook)" in actions


async def test_f013_sources_delete_records_audit(
    app_client: AsyncClient,
) -> None:
    """``DELETE /api/v1/sources/{id}`` writes one audit entry."""
    # Create first so we have an id to delete.
    r = await app_client.post(
        "/api/v1/sources/webhook",
        json={"name": "delete-me", "format": "generic"},
    )
    assert r.status_code == 201
    connector_id = r.json()["id"]

    audit.reset()
    r = await app_client.delete(f"/api/v1/sources/{connector_id}")
    assert r.status_code == 204

    snap = audit.snapshot()
    actions = [e.get("action") for e in snap]
    assert "delete source" in actions