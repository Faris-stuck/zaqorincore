"""Slack backend (v1.3.0 / ADR-008 / Slice 3).

Posts a Block-Kit-formatted message to a Slack Incoming
Webhook URL.

Block Kit shape:

    {
      "blocks": [
        {
          "type": "header",
          "text": { "type": "plain_text", "text": ":fire: ZaqorinCore alert" }
        },
        {
          "type": "section",
          "fields": [
            { "type": "mrkdwn", "text": "*Detector:*\\n`ssh_bruteforce`" },
            { "type": "mrkdwn", "text": "*Severity:*\\n`high`" },
            { "type": "mrkdwn", "text": "*Host:*\\n`host-1`" },
            { "type": "mrkdwn", "text": "*Tags:*\\n`attack.credential_access`" }
          ]
        },
        { "type": "section", "text": { "type": "mrkdwn", "text": "<alert summary>" } },
        {
          "type": "actions",
          "elements": [
            {
              "type": "button",
              "text": { "type": "plain_text", "text": "View" },
              "url": "<console_url>#/alerts/<alert_id>",
              "style": "danger"
            }
          ]
        }
      ]
    }

Severity -> emoji and accent color:

    critical  -> :fire:    danger
    high      -> :rotating_light:  danger
    medium    -> :warning: primary
    low       -> :information_source: default
    info      -> :information_source: default

The Slack Webhook URL is configured via `webhook_url` in
soar.toml. Optional `username` and `channel` overrides are
passed if set.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .. import Alert, DeliverOutcome, DeliveryResult
from ..config import BackendConfig


_SEVERITY_EMOJI = {
    "critical": ":fire:",
    "high": ":rotating_light:",
    "medium": ":warning:",
    "low": ":information_source:",
    "info": ":information_source:",
}

_SEVERITY_BUTTON_STYLE = {
    "critical": "danger",
    "high": "danger",
    "medium": "primary",
    "low": "default",
    "info": "default",
}


class Slack:
    """Backend name: `slack`. Posts to a Slack Incoming
    Webhook URL using Block Kit."""

    name = "slack"

    def __init__(self, config: BackendConfig) -> None:
        self._config = config

    def _validate(self) -> str | None:
        url = self._config.extra.get("webhook_url")
        if not url or not isinstance(url, str):
            return "slack: missing `webhook_url` in config"
        if not str(url).startswith("https://hooks.slack.com/"):
            return (
                "slack: webhook_url must start with "
                "https://hooks.slack.com/"
            )
        return None

    def _render(self, alert: Alert, console_url: str) -> dict[str, Any]:
        sev = (alert.severity or "info").lower()
        emoji = _SEVERITY_EMOJI.get(sev, ":information_source:")
        style = _SEVERITY_BUTTON_STYLE.get(sev, "default")
        tags = ", ".join(f"`{t}`" for t in (alert.tags or [])) or "—"
        host = alert.host_id or "—"
        view_url = f"{console_url.rstrip('/')}/#/alerts/{alert.id}"
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} ZaqorinCore alert",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Detector:*\n`{alert.detector}`",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n`{sev}`",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Host:*\n`{host}`",
                        },
                        {"type": "mrkdwn", "text": f"*Tags:*\n{tags}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": alert.summary or "(no summary)",
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "View",
                            },
                            "url": view_url,
                            "style": style,
                        }
                    ],
                },
            ]
        }

    async def deliver(self, ctx: Any, alert: Alert) -> DeliverOutcome:
        started = datetime.now(timezone.utc)
        public_base_url = ""
        if ctx is not None and hasattr(ctx, "public_base_url"):
            public_base_url = str(getattr(ctx, "public_base_url") or "")

        err = self._validate()
        if err is not None:
            return DeliverOutcome(
                result=DeliveryResult(
                    backend=self.name,
                    alert_id=alert.id,
                    status_code=0,
                    attempted_at=started,
                    duration_ms=0,
                    error=err,
                    dead_lettered=True,
                ),
                payload_sha256="",
            )

        body = self._render(alert, public_base_url)
        # Optional overrides from soar.toml.
        if self._config.extra.get("username"):
            body["username"] = str(self._config.extra["username"])
        if self._config.extra.get("channel"):
            body["channel"] = str(self._config.extra["channel"])

        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        body_sha = hashlib.sha256(raw).hexdigest()
        url = str(self._config.extra["webhook_url"])

        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_sec
            ) as client:
                resp = await client.post(
                    url, content=raw, headers={"Content-Type": "application/json"}
                )
            duration = int(
                (datetime.now(timezone.utc) - started).total_seconds() * 1000
            )
            status = int(resp.status_code)
            error_msg: str | None = None
            dead_lettered = False
            if status >= 500:
                error_msg = f"http {status}: {resp.text[:200]}"
            elif status >= 400:
                error_msg = f"http {status}: {resp.text[:200]}"
                dead_lettered = True
            return DeliverOutcome(
                result=DeliveryResult(
                    backend=self.name,
                    alert_id=alert.id,
                    status_code=status,
                    attempted_at=started,
                    duration_ms=duration,
                    error=error_msg,
                    dead_lettered=dead_lettered,
                ),
                payload_sha256=body_sha,
            )
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            duration = int(
                (datetime.now(timezone.utc) - started).total_seconds() * 1000
            )
            return DeliverOutcome(
                result=DeliveryResult(
                    backend=self.name,
                    alert_id=alert.id,
                    status_code=0,
                    attempted_at=started,
                    duration_ms=duration,
                    error=f"network error: {type(e).__name__}: {e}",
                    dead_lettered=False,
                ),
                payload_sha256=body_sha,
            )


__all__ = ["Slack"]
