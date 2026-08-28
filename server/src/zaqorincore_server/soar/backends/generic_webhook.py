"""Generic Webhook backend (v1.3.0 / ADR-008 / Slice 2).

The default backend. Sends a templated HTTP request to the
URL configured in `soar.toml`. The body is rendered from
`template` with Jinja2-style `{{ alert.field }}` substitution.

Available variables:

  alert.id, alert.host_id, alert.detector, alert.severity,
  alert.summary, alert.tags (list), alert.evidence (text),
  alert.metadata (dict), console_url, ts (ISO timestamp)

Filter chain (handled by the worker, NOT this class):

  - `severity_min` — fire only at or above this severity
  - `tags_filter` — fire only if alert.tags intersects
  - `cooldown_sec` — debounce per (backend, host, detector)
  - `max_retries` — exponential backoff on 5xx / network

Retry semantics:

  - 2xx → success, no retry
  - 3xx → success (the redirect is the target's problem;
    we report the status as-is)
  - 4xx → permanent error, no retry, dead-lettered
  - 5xx → transient error, retry up to `max_retries`
  - network/timeout → transient error, retry

Body hashing:

  We SHA-256 the body we *attempted to send* (the rendered
  template, not the Jinja source). The worker records this
  on the soar_deliveries row, and the dead-letter replay
  endpoint uses it to verify integrity before re-sending —
  the source template can drift between the original
  attempt and the replay; the body is the only thing that
  has to match byte-for-byte.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

import httpx
from jinja2 import Environment, StrictUndefined, TemplateError

from .. import Alert, DeliverOutcome, DeliveryResult
from ..config import BackendConfig


class GenericWebhook:
    """Backend name: `generic_webhook`.

    Sends a templated JSON (or arbitrary content-type) POST
    to a user-supplied URL. The worker's per-attempt
    retry loop handles 5xx; this class makes one HTTP call
    and reports what happened.
    """

    name = "generic_webhook"

    def __init__(self, config: BackendConfig) -> None:
        self._config = config
        # Per-instance Jinja2 environment. StrictUndefined so
        # a typo in `{{ alrt.id }}` raises instead of silently
        # rendering empty.
        self._jinja = Environment(
            undefined=StrictUndefined,
            autoescape=False,
            keep_trailing_newline=True,
        )
        template_src = str(config.extra.get("template", ""))
        self._template_err: str | None = None
        if template_src.strip():
            try:
                self._template = self._jinja.from_string(template_src)
            except TemplateError as e:
                self._template = None
                self._template_err = (
                    f"generic_webhook: template parse error: {e.message}"
                )
        else:
            self._template = None
            if config.enabled:
                # Only complain if the operator actually
                # wants this backend on. A disabled backend
                # with no template is just "off".
                self._template_err = "generic_webhook: `template` is empty"

    def _validate(self) -> str | None:
        """Return an error message if the config is bad,
        else None."""
        url = self._config.extra.get("url")
        if not url or not isinstance(url, str):
            return "generic_webhook: missing `url` in config"
        if not str(url).startswith(("http://", "https://")):
            return f"generic_webhook: url must be http(s), got {url!r}"
        if self._template is None:
            return (
                self._template_err
                or "generic_webhook: `template` is missing or invalid"
            )
        return None

    def _render(self, alert: Alert, console_url: str) -> str:
        """Render the template. Raises TemplateError on
        undefined variables."""
        if self._template is None:
            raise RuntimeError("template not configured")
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        ctx: dict[str, Any] = {
            "alert": {
                "id": alert.id,
                "host_id": alert.host_id,
                "detector": alert.detector,
                "severity": alert.severity,
                "summary": alert.summary,
                "tags": list(alert.tags or []),
                "evidence": alert.evidence or "",
                "metadata": dict(alert.metadata or {}),
            },
            "console_url": console_url.rstrip("/"),
            "ts": ts,
        }
        return self._template.render(**ctx)

    def render_body(self, alert: Alert, console_url: str) -> bytes:
        """Render and return the request body as bytes.

        Public so the dead-letter replay path can produce
        the *same* body the worker would have rendered
        today — used to recompute the SHA-256 that the
        stored record references.
        """
        return self._render(alert, console_url).encode("utf-8")

    async def deliver(self, ctx: Any, alert: Alert) -> DeliverOutcome:
        """Send the alert. Returns a DeliverOutcome.

        `ctx` is opaque to the backend; it is whatever the
        worker hands us. In practice, `ctx` exposes
        `public_base_url` and the dead-letter directory.
        """
        started = datetime.now(timezone.utc)
        public_base_url: str = ""
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

        try:
            body_bytes = self.render_body(alert, public_base_url)
        except TemplateError as e:
            return DeliverOutcome(
                result=DeliveryResult(
                    backend=self.name,
                    alert_id=alert.id,
                    status_code=0,
                    attempted_at=started,
                    duration_ms=0,
                    error=f"template render error: {e.message}",
                    dead_lettered=True,
                ),
                payload_sha256="",
            )

        body_sha = hashlib.sha256(body_bytes).hexdigest()
        url = str(self._config.extra["url"])
        method = str(self._config.extra.get("method", "POST")).upper()
        content_type = str(
            self._config.extra.get("content_type", "application/json")
        )
        headers: dict[str, str] = {"Content-Type": content_type}
        if self._config.extra.get("auth_header"):
            headers["Authorization"] = str(self._config.extra["auth_header"])
        extra_headers = self._config.extra.get("headers")
        if isinstance(extra_headers, dict):
            for k, v in extra_headers.items():
                headers[str(k)] = str(v)

        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_sec
            ) as client:
                resp = await client.request(
                    method, url, content=body_bytes, headers=headers
                )
            duration = int(
                (datetime.now(timezone.utc) - started).total_seconds() * 1000
            )
            status = int(resp.status_code)
            error_msg: str | None = None
            dead_lettered = False
            if status >= 500:
                error_msg = f"http {status}: {resp.text[:200]}"
                # 5xx is transient — the worker will retry.
                dead_lettered = False
            elif status >= 400:
                error_msg = f"http {status}: {resp.text[:200]}"
                # 4xx is permanent — the worker will NOT retry
                # and will dead-letter this attempt.
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


__all__ = ["GenericWebhook"]
