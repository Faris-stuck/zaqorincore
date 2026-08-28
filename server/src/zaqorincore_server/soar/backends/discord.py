"""Discord backend (v1.3.0 / ADR-008 / Slice 4).

Posts a single embed to a Discord webhook URL.

Shape (Discord webhook payload):

    {
      "username": "ZaqorinCore",
      "embeds": [
        {
          "title": "ZaqorinCore alert: ssh_bruteforce",
          "description": "<summary>",
          "color": 15158332,         // 0xE74C3C red
          "fields": [
            { "name": "Severity", "value": "high", "inline": true },
            { "name": "Host", "value": "host-1", "inline": true },
            { "name": "Detector", "value": "ssh_bruteforce", "inline": true },
            { "name": "Tags", "value": "attack.credential_access", "inline": false }
          ],
          "url": "<console_url>#/alerts/<alert_id>",
          "timestamp": "<ISO8601>"
        }
      ]
    }

Severity -> color:

    critical -> 0xE74C3C (red)
    high     -> 0xE67E22 (orange)
    medium   -> 0xF1C40F (yellow)
    low      -> 0x2ECC71 (green)
    info     -> 0x3498DB (blue)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .. import Alert, DeliverOutcome, DeliveryResult
from ..config import BackendConfig


_SEVERITY_COLOR = {
    "critical": 0xE74C3C,
    "high": 0xE67E22,
    "medium": 0xF1C40F,
    "low": 0x2ECC71,
    "info": 0x3498DB,
}


class Discord:
    """Backend name: `discord`. Posts a single embed to a
    Discord webhook URL."""

    name = "discord"

    def __init__(self, config: BackendConfig) -> None:
        self._config = config

    def _validate(self) -> str | None:
        url = self._config.extra.get("webhook_url")
        if not url or not isinstance(url, str):
            return "discord: missing `webhook_url` in config"
        if not str(url).startswith("https://discord.com/api/webhooks/"):
            return (
                "discord: webhook_url must start with "
                "https://discord.com/api/webhooks/"
            )
        return None

    def _render(self, alert: Alert, console_url: str) -> dict[str, Any]:
        sev = (alert.severity or "info").lower()
        color = _SEVERITY_COLOR.get(sev, 0x95A5A6)
        host = alert.host_id or "—"
        tags = ", ".join(alert.tags or []) or "—"
        view_url = f"{console_url.rstrip('/')}/#/alerts/{alert.id}"
        return {
            "username": "ZaqorinCore",
            "embeds": [
                {
                    "title": f"ZaqorinCore alert: {alert.detector}",
                    "description": alert.summary or "(no summary)",
                    "color": color,
                    "url": view_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                    "fields": [
                        {
                            "name": "Severity",
                            "value": sev,
                            "inline": True,
                        },
                        {
                            "name": "Host",
                            "value": host,
                            "inline": True,
                        },
                        {
                            "name": "Detector",
                            "value": alert.detector,
                            "inline": True,
                        },
                        {
                            "name": "Tags",
                            "value": tags,
                            "inline": False,
                        },
                    ],
                }
            ],
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
        # Optional username override.
        if self._config.extra.get("username"):
            body["username"] = str(self._config.extra["username"])

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


__all__ = ["Discord"]
