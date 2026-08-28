"""PagerDuty backend (v1.3.0 / ADR-008 / Slice 5).

Posts an event to the PagerDuty Events API v2
(https://events.pagerduty.com/v2/enqueue).

Payload shape:

    {
      "routing_key": "<integration key>",
      "event_action": "trigger",
      "dedup_key": "zaqorin:<alert.id>",
      "payload": {
        "summary": "<alert.summary>",
        "source": "zaqorincore",
        "severity": "error",        // mapped from ZaqorinCore severity
        "component": "<alert.detector>",
        "group": "zaqorincore",
        "class": "<alert.detector>",
        "custom_details": {
          "alert_id": "<alert.id>",
          "host_id": "<alert.host_id>",
          "tags": ["..."],
          "console_url": "<console_url>#/alerts/<alert.id>"
        }
      }
    }

The `dedup_key` is `zaqorin:<alert.id>` so subsequent
attempts (e.g. retry after a 5xx) collapse into the same
PagerDuty incident. The replay endpoint also re-uses
this key.

Severity mapping (configurable via `severity_map` in
soar.toml; defaults below):

    critical -> critical
    high     -> error
    medium   -> warning
    low      -> info
    info     -> info

A 2xx response from PagerDuty is success. PagerDuty
returns a `dedup_key` in the body which we don't currently
echo back, but the response body is recorded in the
result.error field on failure for debugging.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .. import Alert, DeliverOutcome, DeliveryResult
from ..config import BackendConfig


_DEFAULT_SEVERITY_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


class PagerDuty:
    """Backend name: `pagerduty`. Posts to PagerDuty
    Events API v2."""

    name = "pagerduty"
    endpoint = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, config: BackendConfig) -> None:
        self._config = config
        sev_map = config.extra.get("severity_map")
        if isinstance(sev_map, dict):
            self._sev_map = {str(k): str(v) for k, v in sev_map.items()}
        else:
            self._sev_map = dict(_DEFAULT_SEVERITY_MAP)

    def _validate(self) -> str | None:
        key = self._config.extra.get("routing_key")
        if not key or not isinstance(key, str):
            return "pagerduty: missing `routing_key` in config"
        return None

    def _render(self, alert: Alert, console_url: str) -> dict[str, Any]:
        sev = (alert.severity or "info").lower()
        pd_sev = self._sev_map.get(sev, "info")
        dedup_key = f"zaqorin:{alert.id}"
        view_url = (
            f"{console_url.rstrip('/')}/#/alerts/{alert.id}"
            if console_url
            else ""
        )
        return {
            "routing_key": str(self._config.extra["routing_key"]),
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": alert.summary or f"ZaqorinCore alert {alert.id}",
                "source": "zaqorincore",
                "severity": pd_sev,
                "component": alert.detector,
                "group": "zaqorincore",
                "class": alert.detector,
                "custom_details": {
                    "alert_id": alert.id,
                    "host_id": alert.host_id,
                    "tags": list(alert.tags or []),
                    "console_url": view_url,
                },
            },
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
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        body_sha = hashlib.sha256(raw).hexdigest()

        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_sec
            ) as client:
                resp = await client.post(
                    self.endpoint,
                    content=raw,
                    headers={"Content-Type": "application/json"},
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
                # PagerDuty returns 400 on bad routing key
                # or malformed payload. We do NOT retry.
                error_msg = f"http {status}: {resp.text[:200]}"
                dead_lettered = True
            elif status == 202:
                # PagerDuty's success code for /enqueue.
                pass
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


__all__ = ["PagerDuty"]
