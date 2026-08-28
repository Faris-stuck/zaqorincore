"""TheHive backend (v1.3.0 / ADR-008 / Slice 6).

Creates an alert in TheHive v5 via the
`POST {api_url}/api/v1/alert` endpoint. TheHive then
either auto-promotes the alert to a case (if a case
template is configured) or leaves it in the alert
queue for an analyst to triage.

Body shape (TheHive v5):

    {
      "type": "<alert_type>",
      "source": "<source>",
      "sourceRef": "zaqorin:<alert.id>",
      "title": "<alert.detector>: <alert.summary>",
      "description": "<markdown body>",
      "severity": 2,                 // 1=low 2=medium 3=high 4=critical
      "date": "<ISO8601>",
      "tags": ["zaqorincore", ...alert.tags],
      "caseTemplate": "<optional>",
      "customFields": {},
      "observables": [...]
    }

Severity mapping (TheHive uses 1..4):

    info     -> 1 (low)
    low      -> 1 (low)
    medium   -> 2 (medium)
    high     -> 3 (high)
    critical -> 4 (critical)

Authentication: `Authorization: Bearer <api_key>`. The
API key is org-level; rotate via TheHive's UI.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .. import Alert, DeliverOutcome, DeliveryResult
from ..config import BackendConfig


_SEVERITY_TO_HIVE = {
    "info": 1,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class TheHive:
    """Backend name: `thehive`. POSTs to
    `<api_url>/api/v1/alert`."""

    name = "thehive"

    def __init__(self, config: BackendConfig) -> None:
        self._config = config

    def _validate(self) -> str | None:
        api_url = self._config.extra.get("api_url")
        api_key = self._config.extra.get("api_key")
        if not api_url or not isinstance(api_url, str):
            return "thehive: missing `api_url` in config"
        if not str(api_url).startswith(("http://", "https://")):
            return f"thehive: api_url must be http(s), got {api_url!r}"
        if not api_key or not isinstance(api_key, str):
            return "thehive: missing `api_key` in config"
        return None

    def _endpoint(self) -> str:
        base = str(self._config.extra["api_url"]).rstrip("/")
        return f"{base}/api/v1/alert"

    def _render(self, alert: Alert) -> dict[str, Any]:
        sev = (alert.severity or "info").lower()
        hive_sev = _SEVERITY_TO_HIVE.get(sev, 1)
        # Build a markdown description that includes the
        # console link so an analyst can click through.
        desc_lines = [
            alert.summary or "(no summary)",
            "",
            f"- **alert_id**: `{alert.id}`",
            f"- **host_id**: `{alert.host_id}`",
            f"- **detector**: `{alert.detector}`",
            f"- **severity**: `{sev}`",
        ]
        if alert.tags:
            desc_lines.append(
                "- **tags**: " + ", ".join(f"`{t}`" for t in alert.tags)
            )
        if alert.evidence:
            desc_lines.extend(["", "### Evidence", "```", alert.evidence, "```"])
        body: dict[str, Any] = {
            "type": str(
                self._config.extra.get("alert_type", "external")
            ),
            "source": str(self._config.extra.get("source", "zaqorincore")),
            "sourceRef": f"zaqorin:{alert.id}",
            "title": f"{alert.detector}: {alert.summary or alert.id}",
            "description": "\n".join(desc_lines),
            "severity": hive_sev,
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tags": ["zaqorincore"] + list(alert.tags or []),
        }
        if self._config.extra.get("case_template"):
            body["caseTemplate"] = str(self._config.extra["case_template"])
        return body

    async def deliver(self, ctx: Any, alert: Alert) -> DeliverOutcome:
        started = datetime.now(timezone.utc)

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

        body = self._render(alert)
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        body_sha = hashlib.sha256(raw).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._config.extra['api_key']}",
        }

        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_sec
            ) as client:
                resp = await client.post(
                    self._endpoint(), content=raw, headers=headers
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


__all__ = ["TheHive"]
