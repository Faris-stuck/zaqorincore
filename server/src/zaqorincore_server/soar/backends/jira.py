"""Jira backend (v1.3.0 / ADR-008 / Slice 7).

Creates an issue via the Atlassian Cloud REST API v3:

    POST {api_url}/rest/api/3/issue

Body shape (Atlassian Document Format for the
description):

    {
      "fields": {
        "project": { "key": "<project_key>" },
        "issuetype": { "name": "<issue_type>" },
        "summary": "<alert.detector>: <alert.summary>",
        "description": {
          "type": "doc",
          "version": 1,
          "content": [
            { "type": "paragraph",
              "content": [{"type": "text", "text": "<summary>"}] },
            { "type": "paragraph",
              "content": [{"type": "text", "text": "host: <host_id>"}] },
            ...
          ]
        },
        "labels": ["zaqorincore", ...alert.tags]
      }
    }

Authentication: HTTP Basic with `<email>:<api_token>`.
Generate the API token at
https://id.atlassian.com/manage-profile/security/api-tokens
and rotate out of band.

Priority mapping (default; can be overridden via
`priority_map` in soar.toml):

    critical -> "Highest"
    high     -> "High"
    medium   -> "Medium"
    low      -> "Low"
    info     -> "Low"

If the priority name doesn't exist in the project (some
Jira projects use a custom priority scheme), the
priority field is omitted rather than failing the
issue creation.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .. import Alert, DeliverOutcome, DeliveryResult
from ..config import BackendConfig


_DEFAULT_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
}


def _adf_text(text: str) -> dict[str, Any]:
    """A single ADF text paragraph."""
    return {
        "type": "paragraph",
        "content": [{"type": "text", "text": text}],
    }


def _adf_code(text: str) -> dict[str, Any]:
    """An ADF code block (monospaced)."""
    return {
        "type": "codeBlock",
        "attrs": {"language": "plaintext"},
        "content": [{"type": "text", "text": text}],
    }


class Jira:
    """Backend name: `jira`. POSTs to
    `<api_url>/rest/api/3/issue`."""

    name = "jira"

    def __init__(self, config: BackendConfig) -> None:
        self._config = config
        pmap = config.extra.get("priority_map")
        if isinstance(pmap, dict):
            self._priority = {str(k): str(v) for k, v in pmap.items()}
        else:
            self._priority = dict(_DEFAULT_PRIORITY)

    def _validate(self) -> str | None:
        api_url = self._config.extra.get("api_url")
        project_key = self._config.extra.get("project_key")
        email = self._config.extra.get("email")
        token = self._config.extra.get("api_token")
        if not api_url or not isinstance(api_url, str):
            return "jira: missing `api_url` in config"
        if not str(api_url).startswith("https://"):
            return "jira: api_url must be https"
        if not project_key:
            return "jira: missing `project_key` in config"
        if not email:
            return "jira: missing `email` in config"
        if not token:
            return "jira: missing `api_token` in config"
        return None

    def _endpoint(self) -> str:
        base = str(self._config.extra["api_url"]).rstrip("/")
        return f"{base}/rest/api/3/issue"

    def _auth_header(self) -> str:
        raw = f"{self._config.extra['email']}:{self._config.extra['api_token']}"
        return "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")

    def _render(
        self, alert: Alert, console_url: str
    ) -> dict[str, Any]:
        sev = (alert.severity or "info").lower()
        priority = self._priority.get(sev)
        view_url = (
            f"{console_url.rstrip('/')}/#/alerts/{alert.id}"
            if console_url
            else ""
        )
        content: list[dict[str, Any]] = [
            _adf_text(alert.summary or "(no summary)"),
        ]
        if view_url:
            content.append(_adf_text(f"console: {view_url}"))
        content.append(_adf_text(f"host: {alert.host_id}"))
        content.append(_adf_text(f"detector: {alert.detector}"))
        if alert.tags:
            content.append(
                _adf_text("tags: " + ", ".join(alert.tags))
            )
        if alert.evidence:
            content.append(_adf_code(alert.evidence))
        fields: dict[str, Any] = {
            "project": {"key": str(self._config.extra["project_key"])},
            "issuetype": {
                "name": str(
                    self._config.extra.get("issue_type", "Task")
                )
            },
            "summary": f"{alert.detector}: {alert.summary or alert.id}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": content,
            },
            "labels": ["zaqorincore"] + list(alert.tags or []),
        }
        if priority:
            fields["priority"] = {"name": priority}
        return {"fields": fields}

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
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self._auth_header(),
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
                # Jira returns 400 on schema mismatches
                # (unknown priority, bad ADF, missing
                # required field) and 401/403 on bad
                # creds. All of those are configuration
                # problems — no retry.
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


__all__ = ["Jira"]
