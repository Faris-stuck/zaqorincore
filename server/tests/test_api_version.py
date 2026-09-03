"""Tests for /api/v1/version."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_api_v1_version_shape(app_client: AsyncClient) -> None:
    """GET /api/v1/version returns the build identity contract.

    Contract: {version: str, git_sha: str, git_sha_full: str}.
    The endpoint is always 200 so scrape tools get a stable body
    shape — same rationale as the existing /healthz family.
    """
    r = await app_client.get("/api/v1/version")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"version", "git_sha", "git_sha_full"}
    assert isinstance(body["version"], str)
    assert body["version"]  # non-empty
    assert isinstance(body["git_sha"], str)
    assert isinstance(body["git_sha_full"], str)


async def test_api_v1_version_reflects_app_version(app_client: AsyncClient) -> None:
    """version field mirrors app.version set in main.create_app.

    v3.2.2 (F-005 fix): the version is now read from package
    metadata (``importlib.metadata.version("zaqorincore-server")``)
    so the endpoint always reflects pyproject.toml without a
    separate edit in main.create_app.
    """
    from importlib.metadata import version as _pkg_version

    expected = _pkg_version("zaqorincore-server")
    r = await app_client.get("/api/v1/version")
    body = r.json()
    assert body["version"] == expected
    # Sanity check: the installed package version must be a
    # non-empty string. If the package is uninstalled in some
    # future change this test will surface it as a missing
    # import instead of a silent body["version"] == "".
    assert expected


async def test_api_v1_version_no_build_info_file(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When build_info.json is missing, the endpoint surfaces
    ``"unknown"`` sentinels rather than 5xx'ing. Mirrors the
    healthcheck contract: never 5xx, always a stable shape.
    """
    from zaqorincore_server.api.v1 import version as version_module

    missing = Path("/nonexistent/build_info.json")

    def _fake(path: Path) -> tuple[str, str]:
        assert path == missing
        return "unknown", "unknown"

    monkeypatch.setattr(version_module, "_read_build_info", _fake)
    monkeypatch.setattr(version_module, "_DEFAULT_BUILD_INFO", missing)

    r = await app_client.get("/api/v1/version")
    assert r.status_code == 200
    body = r.json()
    assert body["git_sha"] == "unknown"
    assert body["git_sha_full"] == "unknown"


async def test_api_v1_version_with_build_info_file(
    app_client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When build_info.json is present, git_sha flows through.

    Verifies the helper actually reads and parses the JSON file
    so a CI step that writes build_info.json works as expected.
    """
    from zaqorincore_server.api.v1 import version as version_module

    info = tmp_path / "build_info.json"
    info.write_text(json.dumps({"git_sha": "abc1234", "git_sha_full": "abc1234567def"}))

    monkeypatch.setattr(version_module, "_DEFAULT_BUILD_INFO", info)

    r = await app_client.get("/api/v1/version")
    assert r.status_code == 200
    body = r.json()
    assert body["git_sha"] == "abc1234"
    assert body["git_sha_full"] == "abc1234567def"


async def test_read_build_info_handles_missing_file() -> None:
    """Unit test for the helper: missing file -> ('unknown', 'unknown')."""
    from zaqorincore_server.api.v1.version import _read_build_info

    missing = Path("/definitely/not/here/build_info.json")
    short, full = _read_build_info(missing)
    assert short == "unknown"
    assert full == "unknown"


async def test_read_build_info_handles_malformed_file(
    tmp_path: Path,
) -> None:
    """Unit test for the helper: malformed JSON -> ('unknown', 'unknown')."""
    from zaqorincore_server.api.v1.version import _read_build_info

    bad = tmp_path / "build_info.json"
    bad.write_text("not json {{{")

    short, full = _read_build_info(bad)
    assert short == "unknown"
    assert full == "unknown"