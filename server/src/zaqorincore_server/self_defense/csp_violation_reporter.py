"""CSP violation report endpoint (ZaqorinCore v3.3.0, F-017 fixed v3.4.2,
F-023 fixed v3.4.14).

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
* Body is capped at 16 KiB to prevent ingestion of arbitrary-size
  JSON (F-023, CWE-400).

F-017 fix (cycle 58): the throttle is now keyed by the request's
source IP (``request.client.host``) rather than the report body's
``document-uri``. Keying on ``document-uri`` allowed an attacker
to bypass the budget by submitting one report per unique
``document-uri``. Operators running behind a proxy that injects
``X-Forwarded-For`` can opt into the forwarded header by setting
``ZAQORIN_SRC_IP_HEADER`` to its canonical name (default behaviour
remains the FastAPI ``Request.client.host``).

F-023 fix (cycle 72): the throttle and recent-IP dict are now
guarded by a single threading.Lock (closes the TOCTOU race and
the missing eviction). Throttled requests no longer emit events
(prevents amplification of F-008 stream-eviction). Body size is
capped at 16 KiB.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Any

from fastapi import APIRouter, Request, Response as FastAPIRawResponse
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
# F-023: cap body size to 16 KiB. Browsers send ≤8 KiB for legitimate
# reports; anything larger is either an attacker or a misconfigured
# upstream. (CWE-400)
_MAX_BODY_BYTES = 16 * 1024

# F-023: lock guards BOTH _recent dict and per-key deques, fixing the
# TOCTOU race on _throttle_allowed. Also drives the eviction sweep
# (in _evict_stale below) so a rotating-IP attacker cannot OOM the
# process.
_throttle_lock = threading.Lock()
_recent: dict[str, deque[float]] = {}


def _evict_stale(now: float) -> None:
    """Remove entries whose deque is fully outside the window.

    Called under ``_throttle_lock`` once per request. Cheaper than a
    periodic sweep timer; bounded by the number of distinct src_ips
    seen in the last ``_THROTTLE_WINDOW_SEC`` seconds.
    """
    cutoff = now - _THROTTLE_WINDOW_SEC
    stale = [ip for ip, bucket in _recent.items() if not bucket or bucket[-1] < cutoff]
    for ip in stale:
        del _recent[ip]


def _throttle_allowed(src_ip: str, now: float) -> bool:
    """Return True if this src_ip may submit another report now.

    F-023: the dict + deque mutation is atomic under
    ``_throttle_lock`` so the per-IP budget cannot be exceeded by
    concurrent FastAPI threadpool workers. Previously a
    check-then-append TOCTOU window let bursts of >10 in
    quick succession slip through.
    """
    with _throttle_lock:
        _evict_stale(now)
        bucket = _recent.setdefault(src_ip, deque())
        # Drop entries outside the window.
        cutoff = now - _THROTTLE_WINDOW_SEC
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= _THROTTLE_BUDGET:
            return False
        bucket.append(now)
        return True


def _resolve_src_ip(request: Request) -> str:
    """Determine the source IP for throttling and event metadata.

    Precedence:

    1. The header named by ``ZAQORIN_SRC_IP_HEADER`` if the operator
       configured one (commonly ``X-Forwarded-For`` behind a trusted
       reverse proxy).
    2. Otherwise ``request.client.host`` (the FastAPI default).
    3. Final fallback ``"<unknown>"`` so the throttle dict never
       keys on ``None``.
    """
    configured = os.environ.get("ZAQORIN_SRC_IP_HEADER", "").strip()
    if configured:
        raw = request.headers.get(configured)
        if raw:
            # X-Forwarded-For may carry a comma-separated chain;
            # the left-most entry is the originating client.
            return raw.split(",", 1)[0].strip() or "<unknown>"
    host = getattr(request.client, "host", None) if request.client else None
    if host:
        return host
    return "<unknown>"


@router.post(
    "/_csp-report",
    status_code=204,
    response_class=FastAPIRawResponse,
    summary="Receive a Content-Security-Policy violation report.",
)
async def receive_csp_report(
    payload: dict[str, Any],
    request: Request,
) -> FastAPIRawResponse:
    """Accept either the legacy CSP envelope or the new flat shape.

    No auth, no body persistence — the report is normalized to a
    ``ZaqorinEvent`` and pushed into the in-process stream so the
    Sigma engine can correlate it against T1505.003 / T1505.004.
    """
    # F-023: cap body size. Browsers always send a small fixed body
    # for CSP reports (≤8 KiB), so legitimate clients can never
    # legitimately use chunked transfer encoding here.
    #
    # F-024: reject Transfer-Encoding: chunked outright, since
    # chunked bodies bypass the Content-Length-only cap. Browsers
    # do not chunk CSP reports; non-browser clients (curl, Go
    # http.Client) usually set Content-Length. The chunked header
    # is therefore a strong signal of either a misconfigured client
    # or an attacker trying to stream an unbounded body.
    te = request.headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        return FastAPIRawResponse(status_code=411, content=b"")
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _MAX_BODY_BYTES:
                return FastAPIRawResponse(status_code=413, content=b"")
        except ValueError:
            # Malformed Content-Length — reject defensively.
            return FastAPIRawResponse(status_code=400, content=b"")

    src_ip = _resolve_src_ip(request)
    now = time.time()
    if not _throttle_allowed(src_ip, now):
        # F-023: throttled requests do NOT emit an event. The
        # 429 alone is the signal — emitting an event here would
        # amplify F-008 (attacker evicts legitimate events from
        # the bounded _STREAM by triggering throttle + emit at
        # 10/min/IP × N IPs). The T1505.004 rule still fires on
        # successful submissions.
        return FastAPIRawResponse(status_code=429, content=b"")

    event = ZaqorinEvent.from_csp_report(payload, src_ip=src_ip, status=204)
    emit(event)
    return FastAPIRawResponse(status_code=204, content=b"")


__all__ = ["router", "CspReportIn", "receive_csp_report", "_resolve_src_ip"]
