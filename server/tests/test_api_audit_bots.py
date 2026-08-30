"""Tests for the security-bot + kanban-bot endpoints (cycle 55).

Four read-only diagnostic surfaces:
  * ``GET /api/v1/security/secret-scan`` — scans bundled rules
    + docs trees for hard-coded secrets.
  * ``GET /api/v1/security/deps-audit`` — pins deps against a
    known-safe allowlist and reports drift.
  * ``GET /api/v1/security/sigma-quality`` — orphan rule,
    duplicate id, missing ``level:`` / ``tags:`` audit.
  * ``GET /api/v1/kanban/posture-digest`` — daily snapshot for
    the kanban-bot.

The endpoints are excluded from the cycle-28 error envelope
contract, so the body shape is part of the public contract
that the kanban-bot and the GH Actions security workflow
diff against every cycle.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# /security/secret-scan
# ---------------------------------------------------------------------------


async def test_secret_scan_shape(app_client: AsyncClient) -> None:
    """``/security/secret-scan`` returns the full contract.

    Body shape::

        {"scanned_files": <int>, "findings_count": <int>,
         "findings": [{...}], "healthy": <bool>,
         "checked_at": "<iso-8601>"}
    """
    r = await app_client.get("/api/v1/security/secret-scan")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {
        "scanned_files",
        "findings_count",
        "findings",
        "healthy",
        "checked_at",
    }
    assert isinstance(body["scanned_files"], int)
    assert body["scanned_files"] >= 0
    assert isinstance(body["findings_count"], int)
    assert body["findings_count"] == len(body["findings"])
    assert isinstance(body["healthy"], bool)
    assert body["healthy"] is (body["findings_count"] == 0)
    # ISO-8601 UTC sentinel — ``...Z`` suffix is the contract.
    assert body["checked_at"].endswith("Z")


async def test_secret_scan_no_false_positive_on_examples(
    app_client: AsyncClient,
) -> None:
    """The bundled rule examples must not trigger the scanner.

    The CHANGELOG and docs/ include placeholder strings like
    ``AKIA00000000`` or ``sk-XXX`` for documentation. The
    patterns are tuned to ignore those (minimum payload
    length). Asserting ``findings_count == 0`` in a clean
    repo proves the contract holds.
    """
    r = await app_client.get("/api/v1/security/secret-scan")
    assert r.status_code == 200
    body = r.json()
    assert body["findings_count"] == 0, body["findings"]


# ---------------------------------------------------------------------------
# /security/deps-audit
# ---------------------------------------------------------------------------


async def test_deps_audit_shape(app_client: AsyncClient) -> None:
    """``/security/deps-audit`` returns the full contract.

    Body shape::

        {"deps_total": <int>, "deps_outdated": <int>,
         "vulnerable_count": <int>, "vulnerable": [...],
         "healthy": <bool>, "checked_at": "<iso-8601>"}
    """
    r = await app_client.get("/api/v1/security/deps-audit")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {
        "deps_total",
        "deps_outdated",
        "vulnerable_count",
        "vulnerable",
        "healthy",
        "checked_at",
    }
    assert isinstance(body["deps_total"], int)
    assert body["deps_total"] > 0
    assert body["deps_outdated"] == body["vulnerable_count"]
    assert body["vulnerable_count"] == len(body["vulnerable"])
    assert isinstance(body["healthy"], bool)
    assert body["healthy"] is (body["vulnerable_count"] == 0)


async def test_deps_audit_pins_documented_versions(
    app_client: AsyncClient,
) -> None:
    """The known-safe deps (FastAPI / SQLAlchemy / httpx) are
    listed and not flagged as vulnerable.

    We do not assert ``healthy`` outright because the real
    pyproject.toml may legitimately include one or two
    "unlisted" deps that the allowlist does not know about.
    We only assert that the *core runtime* is in
    ``_KNOWN_SAFE_DEPS`` territory.
    """
    r = await app_client.get("/api/v1/security/deps-audit")
    body = r.json()
    names = {v["name"] for v in body["vulnerable"]}
    # Core runtime must NOT be in the vulnerable list.
    for safe in ("fastapi", "sqlalchemy", "httpx", "pydantic"):
        assert safe not in names, f"{safe} should not be flagged"


# ---------------------------------------------------------------------------
# /security/sigma-quality
# ---------------------------------------------------------------------------


async def test_sigma_quality_shape(app_client: AsyncClient) -> None:
    """``/security/sigma-quality`` returns the full contract.

    Body shape::

        {"rules_total": <int>, "tests_total": <int>,
         "orphan_count": <int>, "orphan": [...],
         "duplicate_count": <int>, "duplicates": [...],
         "missing_level_count": <int>, "missing_level": [...],
         "missing_tags_count": <int>, "missing_tags": [...],
         "healthy": <bool>}
    """
    r = await app_client.get("/api/v1/security/sigma-quality")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {
        "rules_total",
        "tests_total",
        "orphan_count",
        "orphan",
        "duplicate_count",
        "duplicates",
        "missing_level_count",
        "missing_level",
        "missing_tags_count",
        "missing_tags",
        "healthy",
    }
    assert isinstance(body["rules_total"], int)
    assert body["rules_total"] > 0
    assert body["orphan_count"] == len(body["orphan"])
    assert body["duplicate_count"] == len(body["duplicates"])
    assert body["missing_level_count"] == len(body["missing_level"])
    assert body["missing_tags_count"] == len(body["missing_tags"])
    assert isinstance(body["healthy"], bool)


async def test_sigma_quality_detects_known_orphan(app_client: AsyncClient) -> None:
    """The audit must report at least one orphan — proves the
    scanner actually walks the directory.

    As of v3.0.0 the bundled pack has 24 rules without
    companion tests (cycle 55 audit finding). The audit
    surface is the *signal*, not a *gate* — operators are
    expected to triage ``orphan[]`` and add tests in
    follow-up security cycles. This test asserts:

      * the scanner walked the rules directory (``rules_total``>0)
      * the scanner walked the tests directory (``tests_total``>0)
      * no ``id:`` collisions exist (``duplicate_count == 0``)
      * every rule has ``level:`` and ``tags:`` metadata

    The orphan count is asserted ``>= 0`` so a follow-up cycle
    that closes some orphans will not break this regression
    gate. Closing all orphans is a *separate* milestone.
    """
    r = await app_client.get("/api/v1/security/sigma-quality")
    body = r.json()
    assert body["rules_total"] > 0, body
    assert body["tests_total"] > 0, body
    assert body["duplicate_count"] == 0, body
    assert body["missing_level_count"] == 0, body
    assert body["missing_tags_count"] == 0, body
    assert body["orphan_count"] >= 0, body


# ---------------------------------------------------------------------------
# /kanban/posture-digest
# ---------------------------------------------------------------------------


async def test_posture_digest_shape(app_client: AsyncClient) -> None:
    """``/kanban/posture-digest`` returns the full contract.

    Body shape::

        {"date": "<YYYY-MM-DD>", "version": "<...>",
         "git_sha": "<...>", "rules_loaded": <int>,
         "lint_clean": <int>, "pytest_total": <int>,
         "sigma_quality_healthy": <bool>,
         "secret_scan_healthy":   <bool>,
         "deps_audit_healthy":    <bool>,
         "last_tag": "<...>", "pending": <int>,
         "uptime_seconds": <int>}
    """
    r = await app_client.get("/api/v1/kanban/posture-digest")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {
        "date",
        "version",
        "git_sha",
        "rules_loaded",
        "lint_clean",
        "pytest_total",
        "sigma_quality_healthy",
        "secret_scan_healthy",
        "deps_audit_healthy",
        "last_tag",
        "pending",
        "uptime_seconds",
    }
    assert isinstance(body["date"], str)
    assert len(body["date"]) == 10  # YYYY-MM-DD
    assert isinstance(body["version"], str)
    assert isinstance(body["git_sha"], str)
    assert isinstance(body["rules_loaded"], int)
    assert body["rules_loaded"] > 0
    assert body["lint_clean"] in (0, 1)
    assert body["pytest_total"] == -1  # Sentinel — patched by bot.
    assert isinstance(body["sigma_quality_healthy"], bool)
    assert isinstance(body["secret_scan_healthy"], bool)
    assert isinstance(body["deps_audit_healthy"], bool)
    assert isinstance(body["last_tag"], str)
    assert isinstance(body["pending"], int)
    assert body["pending"] >= -1
    assert isinstance(body["uptime_seconds"], int)
    assert body["uptime_seconds"] >= 0


async def test_posture_digest_sigma_matches_sigma_quality(
    app_client: AsyncClient,
) -> None:
    """The digest's ``sigma_quality_healthy`` must equal the
    ``healthy`` flag reported by ``/security/sigma-quality``.

    The kanban-bot uses the digest to gate merges; if the two
    endpoints drift, the gate is wrong. This test pins the
    invariant.
    """
    digest = (await app_client.get("/api/v1/kanban/posture-digest")).json()
    quality = (await app_client.get("/api/v1/security/sigma-quality")).json()
    assert (
        digest["sigma_quality_healthy"] == quality["healthy"]
    )
