"""Tests for the SOAR ticketing backends (v1.3.0 / Slice 3).

Covers the v1.3.0 SOAR contract for the three ticketing /
incident-management backends:

PagerDuty (Events API v2):
- name and Backend protocol conformance
- Missing routing_key -> dead-lettered
- 2xx success, payload_action=trigger, severity mapping
- dedup_key is set (so retries are deduplicated server-side)
- 4xx dead-letters
- 5xx does NOT dead-letter (transient, worker retries)

TheHive (alert create):
- name and Backend protocol conformance
- Missing api_url or api_key -> dead-lettered
- Bad URL prefix -> dead-lettered
- 2xx success, payload shape (title/source/sourceRef)
- 4xx dead-letters
- 5xx does NOT dead-letter

Jira (issue create):
- name and Backend protocol conformance
- Missing api_url/project_key/email/api_token -> dead-lettered
- 2xx success, payload shape (project, issuetype, summary)
- Auth header is Basic base64(email:api_token)
- 4xx dead-letters
- 5xx does NOT dead-letter
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import httpx
import pytest

from zaqorincore_server.soar import Alert, Backend
from zaqorincore_server.soar.backends.pagerduty import PagerDuty
from zaqorincore_server.soar.backends.thehive import TheHive
from zaqorincore_server.soar.backends.jira import Jira
from zaqorincore_server.soar.config import BackendConfig


def _install_mock_transport(monkeypatch, handler):
    original = httpx.AsyncClient

    class _PatchedAsyncClient:
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            self._client = original(*args, **kwargs)

        async def __aenter__(self):
            await self._client.__aenter__()
            return self._client

        async def __aexit__(self, *args):
            return await self._client.__aexit__(*args)

    monkeypatch.setattr(httpx, "AsyncClient", _PatchedAsyncClient)


def _make_alert(**overrides) -> Alert:
    base_kwargs: dict = dict(
        id="00000000-0000-0000-0000-000000000001",
        host_id="host-a",
        detector="ssh_bruteforce",
        severity="high",
        tags=["attack.credential_access"],
        summary="5 failed SSH logins from 203.0.113.42",
        evidence="203.0.113.42 -> host-a:22 x5",
        metadata={"src_ip": "203.0.113.42"},
        created_at=datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc),
    )
    base_kwargs.update(overrides)
    return Alert(**base_kwargs)


def _pd_config(extra: dict) -> BackendConfig:
    return BackendConfig(
        name="pagerduty",
        enabled=True,
        severity_min="info",
        tags_filter=[],
        cooldown_sec=0,
        max_retries=2,
        timeout_sec=5.0,
        extra=extra,
    )


def _hive_config(extra: dict) -> BackendConfig:
    return BackendConfig(
        name="thehive",
        enabled=True,
        severity_min="info",
        tags_filter=[],
        cooldown_sec=0,
        max_retries=2,
        timeout_sec=5.0,
        extra=extra,
    )


def _jira_config(extra: dict) -> BackendConfig:
    return BackendConfig(
        name="jira",
        enabled=True,
        severity_min="info",
        tags_filter=[],
        cooldown_sec=0,
        max_retries=2,
        timeout_sec=5.0,
        extra=extra,
    )


# ---- PagerDuty ----


@pytest.mark.asyncio
async def test_pagerduty_name_and_protocol():
    backend = PagerDuty(_pd_config({"routing_key": "RK123"}))
    assert backend.name == "pagerduty"
    assert isinstance(backend, Backend)


@pytest.mark.asyncio
async def test_pagerduty_missing_routing_key_dead_letters():
    backend = PagerDuty(_pd_config({}))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "routing_key" in (out.result.error or "")


@pytest.mark.asyncio
async def test_pagerduty_2xx_success(monkeypatch):
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(202, text="queued")

    _install_mock_transport(monkeypatch, handler)
    backend = PagerDuty(_pd_config({"routing_key": "RK123"}))
    out = await backend.deliver(
        None, _make_alert(severity="critical")
    )
    assert out.result.status_code == 202
    assert out.result.dead_lettered is False
    # Events API v2 endpoint
    assert captured["url"] == "https://events.pagerduty.com/v2/enqueue"
    # Required fields
    assert captured["body"]["routing_key"] == "RK123"
    assert captured["body"]["event_action"] == "trigger"
    # Severity is mapped
    assert captured["body"]["payload"]["severity"] == "critical"
    # dedup_key is set so retries dedupe server-side
    assert captured["body"].get("dedup_key")


@pytest.mark.asyncio
async def test_pagerduty_4xx_dead_letters(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad key")

    _install_mock_transport(monkeypatch, handler)
    backend = PagerDuty(_pd_config({"routing_key": "RK123"}))
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 400
    assert out.result.dead_lettered is True


@pytest.mark.asyncio
async def test_pagerduty_5xx_not_dead_lettered(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="down")

    _install_mock_transport(monkeypatch, handler)
    backend = PagerDuty(_pd_config({"routing_key": "RK123"}))
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 503
    assert out.result.dead_lettered is False


# ---- TheHive ----


@pytest.mark.asyncio
async def test_thehive_name_and_protocol():
    backend = TheHive(_hive_config({
        "api_url": "https://hive.example.com",
        "api_key": "KEY123",
    }))
    assert backend.name == "thehive"
    assert isinstance(backend, Backend)


@pytest.mark.asyncio
async def test_thehive_missing_api_url_dead_letters():
    backend = TheHive(_hive_config({"api_key": "KEY123"}))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "api_url" in (out.result.error or "")


@pytest.mark.asyncio
async def test_thehive_missing_api_key_dead_letters():
    backend = TheHive(_hive_config({"api_url": "https://hive.example.com"}))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "api_key" in (out.result.error or "")


@pytest.mark.asyncio
async def test_thehive_bad_url_prefix_dead_letters():
    backend = TheHive(_hive_config({
        "api_url": "ftp://hive.example.com",
        "api_key": "KEY123",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "http" in (out.result.error or "")


@pytest.mark.asyncio
async def test_thehive_2xx_success(monkeypatch):
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        captured["headers"] = dict(request.headers)
        return httpx.Response(201, text='{"_id":"alert-123"}')

    _install_mock_transport(monkeypatch, handler)
    backend = TheHive(_hive_config({
        "api_url": "https://hive.example.com",
        "api_key": "KEY123",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 201
    assert out.result.dead_lettered is False
    assert captured["url"] == "https://hive.example.com/api/v1/alert"
    # Payload shape
    assert "zaqorin:" in captured["body"]["sourceRef"]
    assert captured["body"]["source"] == "zaqorincore"
    assert "ssh_bruteforce" in captured["body"]["title"]
    # API key is forwarded as Bearer
    assert captured["headers"]["authorization"] == "Bearer KEY123"


@pytest.mark.asyncio
async def test_thehive_4xx_dead_letters(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    _install_mock_transport(monkeypatch, handler)
    backend = TheHive(_hive_config({
        "api_url": "https://hive.example.com",
        "api_key": "KEY123",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 401
    assert out.result.dead_lettered is True


@pytest.mark.asyncio
async def test_thehive_5xx_not_dead_lettered(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="oops")

    _install_mock_transport(monkeypatch, handler)
    backend = TheHive(_hive_config({
        "api_url": "https://hive.example.com",
        "api_key": "KEY123",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is False


# ---- Jira ----


@pytest.mark.asyncio
async def test_jira_name_and_protocol():
    backend = Jira(_jira_config({
        "api_url": "https://company.atlassian.net",
        "project_key": "SEC",
        "email": "ops@example.com",
        "api_token": "TOK",
    }))
    assert backend.name == "jira"
    assert isinstance(backend, Backend)


@pytest.mark.asyncio
async def test_jira_missing_api_url_dead_letters():
    backend = Jira(_jira_config({
        "project_key": "SEC",
        "email": "ops@example.com",
        "api_token": "TOK",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "api_url" in (out.result.error or "")


@pytest.mark.asyncio
async def test_jira_missing_project_key_dead_letters():
    backend = Jira(_jira_config({
        "api_url": "https://company.atlassian.net",
        "email": "ops@example.com",
        "api_token": "TOK",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "project_key" in (out.result.error or "")


@pytest.mark.asyncio
async def test_jira_missing_credentials_dead_letters():
    backend = Jira(_jira_config({
        "api_url": "https://company.atlassian.net",
        "project_key": "SEC",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    # Validation reports the first missing field; either is acceptable
    err = (out.result.error or "").lower()
    assert "email" in err or "api_token" in err


@pytest.mark.asyncio
async def test_jira_2xx_success(monkeypatch):
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        captured["headers"] = dict(request.headers)
        return httpx.Response(201, text='{"key":"SEC-123"}')

    _install_mock_transport(monkeypatch, handler)
    backend = Jira(_jira_config({
        "api_url": "https://company.atlassian.net",
        "project_key": "SEC",
        "email": "ops@example.com",
        "api_token": "TOK",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 201
    assert out.result.dead_lettered is False
    assert captured["url"] == "https://company.atlassian.net/rest/api/3/issue"
    # Payload shape (Jira issue create wraps content in "fields")
    assert captured["body"]["fields"]["project"]["key"] == "SEC"
    assert captured["body"]["fields"]["issuetype"]["name"]
    # Basic auth: base64(email:api_token)
    expected = base64.b64encode(
        b"ops@example.com:TOK"
    ).decode("ascii")
    assert captured["headers"]["authorization"] == f"Basic {expected}"


@pytest.mark.asyncio
async def test_jira_4xx_dead_letters(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    _install_mock_transport(monkeypatch, handler)
    backend = Jira(_jira_config({
        "api_url": "https://company.atlassian.net",
        "project_key": "SEC",
        "email": "ops@example.com",
        "api_token": "TOK",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 403
    assert out.result.dead_lettered is True


@pytest.mark.asyncio
async def test_jira_5xx_not_dead_lettered(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="bad gateway")

    _install_mock_transport(monkeypatch, handler)
    backend = Jira(_jira_config({
        "api_url": "https://company.atlassian.net",
        "project_key": "SEC",
        "email": "ops@example.com",
        "api_token": "TOK",
    }))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is False
