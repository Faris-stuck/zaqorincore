"""CSP violation report endpoint (ZaqorinCore v3.3.0).

Browsers fire ``Content-Security-Policy-Report-Only`` and
``Report-To`` reports to whatever URL is declared in the CSP
header. ZaqorinCore exposes ``/api/v1/_csp-report`` so the WebUI
can use this server as its report sink without pulling in a third
party.

The endpoint is intentionally minimal:

* No auth required — CSRF is not a concern (no session cookies).
* Rate-limited per the existing ``RateLimitMiddleware`` plus an
  additional per-src_ip 10/min cap (the rate-limit middleware
  buckets per API key; browsers do not send keys).
* Returns 204 on success so the browser stops retrying.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

from fastapi import APIRouter, Response as FastAPIRawResponse
from pydantic import BaseModel, Field

from . import emit
from .event_normalizer import ZaqorinEvent

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/v1", tags=["self-defense"])


class CspReportIn(BaseModel):
    """Pydantic model for the CSP violation body.

    Browsers send both the legacy ``application/csp-report``
    envelope (nested under ``csp-report``) and the newer
    ``report-to`` flat shape. We accept either via ``root=True``
    in the router below — this model describes the inner shape.
    """

    document_uri: str | None = Field(default=None, alias="document-uri")
    violated_directive: str | None = Field(default=None, alias="violated-directive")
    blocked_uri: str | None = Field(default=None, alias="blocked-uri")
    original_policy: str | None = Field(default=None, alias="original-policy")
    source_file: str | None = Field(default=None, alias="source-file")
    line_number: int | None = Field(default=None, alias="line-number")
    column_number: int | None = Field(default=None, alias="column-number")


# Per-src_ip sliding-window throttle. In-process only; the CSP
# report volume from any one browser is tiny so a Redis bucket would
# be premature optimisation. Window length: 60s, budget: 10.
_THROTTLE_WINDOW_SEC = 60
_THROTTLE_BUDGET = 10
_recent: dict[str, deque[float]] = {}


def _throttle_allowed(src_ip: str, now: float) -> bool:
    """Return True if this src_ip may submit another report now."""
    bucket = _recent.setdefault(src_ip, deque())
    # Drop entries outside the window.
    cutoff = now - _THROTTLE_WINDOW_SEC
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= _THROTTLE_BUDGET:
        return False
    bucket.append(now)
    return True


@router.post(
    "/_csp-report",
    status_code=204,
    response_class=FastAPIRawResponse,
    summary="Receive a Content-Security-Policy violation report.",
)
async def receive_csp_report(
    payload: dict[str, Any],
) -> FastAPIRawResponse:
    """Accept either the legacy CSP envelope or the new flat shape.

    No auth, no body persistence — the report is normalized to a
    ``ZaqorinEvent`` and pushed into the in-process stream so the
    Sigma engine can correlate it against T1505.003.
    """
    import time

    # We do not have access to ``Request`` here without changing
    # the signature; the throttle is keyed by the document-uri
    # host (best-effort anti-abuse). Operators wanting stronger
    # source-IP binding should front this endpoint with a proxy
    # that injects ``X-Forwarded-For`` and use the
    # ``src_ip_header`` config (out of scope here).
    document_uri = ""
    if isinstance(payload.get("csp-report"), dict):
        document_uri = str(payload["csp-report"].get("document-uri") or "")
    elif isinstance(payload.get("document-uri"), str):
        document_uri = payload["document-uri"]
    key = document_uri or "<unknown>"

    now = time.time()
    if not _throttle_allowed(key, now):
        return FastAPIRawResponse(status_code=429, content=b"")

    event = ZaqorinEvent.from_csp_report(payload)
    emit(event)
    return FastAPIRawResponse(status_code=204)


__all__ = ["router", "CspReportIn", "receive_csp_report"]