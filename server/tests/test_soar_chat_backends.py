"""Tests for the SOAR Slack and Discord backends (v1.3.0 / Slice 2).

Covers the v1.3.0 SOAR contract for the chat-style backends:
- name and Backend protocol conformance
- Missing webhook_url -> error, dead-lettered
- Bad URL prefix -> error, dead-lettered
- 2xx success
- 4xx dead-letters
- 5xx does NOT dead-letter (transient, worker retries)
- Body has correct shape (Block Kit for Slack, embed for Discord)
- Severity emoji/color mapping
- Console URL appended in View button / embed URL
- Body SHA-256 is computed on the bytes
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import httpx
import pytest

from zaqorincore_server.soar import Alert, Backend, DeliverOutcome
from zaqorincore_server.soar.backends.slack import Slack
from zaqorincore_server.soar.backends.discord import Discord
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




class _Ctx:
    """Minimal ctx stub exposing public_base_url for backends
    that read the console URL from context rather than from a
    third positional argument."""
    def __init__(self, public_base_url: str = "") -> None:
        self.public_base_url = public_base_url

def _make_alert(**overrides) -> Alert:
    base = dict(
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
    base.update(overrides)
    return Alert(**base)


def _slack_config(extra: dict) -> BackendConfig:
    return BackendConfig(
        name="slack",
        enabled=True,
        severity_min="info",
        tags_filter=[],
        cooldown_sec=0,
        max_retries=2,
        timeout_sec=5.0,
        extra=extra,
    )


def _discord_config(extra: dict) -> BackendConfig:
    return BackendConfig(
        name="discord",
        enabled=True,
        severity_min="info",
        tags_filter=[],
        cooldown_sec=0,
        max_retries=2,
        timeout_sec=5.0,
        extra=extra,
    )


# ---- Slack ----


@pytest.mark.asyncio
async def test_slack_name_and_protocol():
    backend = Slack(
        _slack_config({"webhook_url": "https://hooks.slack.com/services/A"})
    )
    assert backend.name == "slack"
    assert isinstance(backend, Backend)


@pytest.mark.asyncio
async def test_slack_missing_webhook_url_dead_letters():
    backend = Slack(_slack_config({}))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "webhook_url" in (out.result.error or "")


@pytest.mark.asyncio
async def test_slack_bad_url_prefix_dead_letters():
    backend = Slack(
        _slack_config({"webhook_url": "https://example.com/not-slack"})
    )
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "https://hooks.slack.com" in (out.result.error or "")


@pytest.mark.asyncio
async def test_slack_posts_block_kit_2xx(monkeypatch):
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, text="ok")

    _install_mock_transport(monkeypatch, handler)

    backend = Slack(
        _slack_config(
            {"webhook_url": "https://hooks.slack.com/services/A/B/C"}
        )
    )
    ctx = _Ctx(public_base_url="https://console.example.com")
    out = await backend.deliver(
        ctx, _make_alert(severity="critical")
    )

    assert out.result.status_code == 200
    assert out.result.error is None
    assert out.result.dead_lettered is False
    assert captured["url"] == "https://hooks.slack.com/services/A/B/C"
    assert captured["body"].get("blocks"), "Slack payload must have `blocks`"
    # Severity emoji :fire: for critical
    header_text = (
        captured["body"]["blocks"][0]["text"]["text"]
    )
    assert ":fire:" in header_text


@pytest.mark.asyncio
async def test_slack_button_links_to_console(monkeypatch):
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200)

    _install_mock_transport(monkeypatch, handler)

    backend = Slack(
        _slack_config(
            {"webhook_url": "https://hooks.slack.com/services/A/B/C"}
        )
    )
    ctx = _Ctx(public_base_url="https://console.example.com")
    await backend.deliver(ctx, _make_alert())
    # Find the actions block
    actions_block = next(
        b for b in captured["body"]["blocks"] if b.get("type") == "actions"
    )
    button = actions_block["elements"][0]
    assert button["type"] == "button"
    assert "console.example.com" in button["url"]
    assert "00000000-0000-0000-0000-000000000001" in button["url"]


@pytest.mark.asyncio
async def test_slack_4xx_dead_letters(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    _install_mock_transport(monkeypatch, handler)
    backend = Slack(
        _slack_config(
            {"webhook_url": "https://hooks.slack.com/services/A/B/C"}
        )
    )
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 403
    assert out.result.dead_lettered is True


@pytest.mark.asyncio
async def test_slack_5xx_not_dead_lettered(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="down")

    _install_mock_transport(monkeypatch, handler)
    backend = Slack(
        _slack_config(
            {"webhook_url": "https://hooks.slack.com/services/A/B/C"}
        )
    )
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 503
    assert out.result.dead_lettered is False


@pytest.mark.asyncio
async def test_slack_body_sha256_matches(monkeypatch):
    captured_body = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured_body["bytes"] = request.content
        return httpx.Response(200)

    _install_mock_transport(monkeypatch, handler)
    backend = Slack(
        _slack_config(
            {"webhook_url": "https://hooks.slack.com/services/A/B/C"}
        )
    )
    out = await backend.deliver(None, _make_alert())
    assert out.payload_sha256 == hashlib.sha256(
        captured_body["bytes"]
    ).hexdigest()


# ---- Discord ----


@pytest.mark.asyncio
async def test_discord_name_and_protocol():
    backend = Discord(
        _discord_config(
            {
                "webhook_url": (
                    "https://discord.com/api/webhooks/123/abc"
                )
            }
        )
    )
    assert backend.name == "discord"
    assert isinstance(backend, Backend)


@pytest.mark.asyncio
async def test_discord_missing_webhook_url_dead_letters():
    backend = Discord(_discord_config({}))
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "webhook_url" in (out.result.error or "")


@pytest.mark.asyncio
async def test_discord_bad_url_prefix_dead_letters():
    backend = Discord(
        _discord_config({"webhook_url": "https://example.com/not-discord"})
    )
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is True
    assert "discord.com/api/webhooks" in (out.result.error or "")


@pytest.mark.asyncio
async def test_discord_posts_embed_2xx(monkeypatch):
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(204)

    _install_mock_transport(monkeypatch, handler)
    backend = Discord(
        _discord_config(
            {"webhook_url": "https://discord.com/api/webhooks/123/abc"}
        )
    )
    ctx = _Ctx(public_base_url="https://console.example.com")
    out = await backend.deliver(ctx, _make_alert(severity="critical"))
    assert out.result.status_code == 204
    assert out.result.dead_lettered is False
    assert captured["body"].get("embeds"), "Discord payload must have `embeds`"
    embed = captured["body"]["embeds"][0]
    # critical severity -> red 0xE74C3C = 15158332
    assert embed["color"] == 0xE74C3C
    # URL references console
    assert "console.example.com" in embed.get("url", "")


@pytest.mark.asyncio
async def test_discord_severity_color_mapping(monkeypatch):
    seen_colors = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen_colors["c"] = json.loads(request.content)["embeds"][0]["color"]
        return httpx.Response(200)

    _install_mock_transport(monkeypatch, handler)
    backend = Discord(
        _discord_config(
            {"webhook_url": "https://discord.com/api/webhooks/123/abc"}
        )
    )
    # high severity -> 0xE67E22 orange
    await backend.deliver(_Ctx(public_base_url=""), _make_alert(severity="high"))
    assert seen_colors["c"] == 0xE67E22


@pytest.mark.asyncio
async def test_discord_4xx_dead_letters(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    _install_mock_transport(monkeypatch, handler)
    backend = Discord(
        _discord_config(
            {"webhook_url": "https://discord.com/api/webhooks/123/abc"}
        )
    )
    out = await backend.deliver(None, _make_alert())
    assert out.result.status_code == 404
    assert out.result.dead_lettered is True


@pytest.mark.asyncio
async def test_discord_5xx_not_dead_lettered(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="oops")

    _install_mock_transport(monkeypatch, handler)
    backend = Discord(
        _discord_config(
            {"webhook_url": "https://discord.com/api/webhooks/123/abc"}
        )
    )
    out = await backend.deliver(None, _make_alert())
    assert out.result.dead_lettered is False


@pytest.mark.asyncio
async def test_discord_body_sha256_matches(monkeypatch):
    captured_body = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured_body["bytes"] = request.content
        return httpx.Response(200)

    _install_mock_transport(monkeypatch, handler)
    backend = Discord(
        _discord_config(
            {"webhook_url": "https://discord.com/api/webhooks/123/abc"}
        )
    )
    out = await backend.deliver(None, _make_alert())
    assert out.payload_sha256 == hashlib.sha256(
        captured_body["bytes"]
    ).hexdigest()
