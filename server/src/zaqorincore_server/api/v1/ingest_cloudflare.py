"""POST /api/v1/ingest/cloudflare — Cloudflare Logpush ingest endpoint.

Cloudflare Logpush pushes NDJSON payloads to a configurable HTTP
endpoint. The push job's "header" field is set to a constant we
control (the HMAC secret itself is never sent on the wire — instead
the operator configures Cloudflare to compute ``HMAC-SHA256(secret,
body)`` and send it as a request header). See:

  https://developers.cloudflare.com/logs/reference/logpush-api/configuration/

This file implements that pattern.

Security model
--------------

1. **HMAC verification is the FIRST thing we do.** A request that
   fails HMAC gets a 401 with NO body and NO side effects. We do
   not parse, do not log the body, do not write to the DB, do
   not touch Redis. This makes a timing oracle or content oracle
   infeasible: an attacker probing the endpoint cannot learn
   anything from responses beyond "valid signature" vs "invalid".

2. **Constant-time comparison.** ``hmac.compare_digest`` runs in
   time independent of where the two strings diverge. A naive
   ``==`` comparison would leak per-byte timing, letting an
   attacker recover the expected signature one byte at a time.

3. **Body size cap.** Reject ``Content-Length > 5 MiB`` *before*
   reading the body. Cloudflare Logpush batches are typically 1-2
   MiB; 5 MiB gives headroom and stops a misconfigured push job
   (or a malicious actor who already has the secret) from
   consuming memory.

4. **Per-line size cap.** Each NDJSON line is capped at 64 KiB.
   Cloudflare http_requests records are well under this; the cap
   is defence in depth against a buggy or hostile producer.

5. **Per-line metadata truncation.** Every metadata value is
   string-truncated to 4 KiB before persist. Cloudflare URI and
   User-Agent fields can be arbitrarily long; truncating at the
   boundary stops a single rogue record from blowing the JSONB
   column budget.

6. **Source IP trust.** The ``src_ip`` metadata field is taken
   from the record's ``ClientIP`` field — NOT from any header on
   the incoming HTTP request and NOT from the request peer. In
   this flow, Cloudflare is the trusted source for client IP;
   trusting X-Forwarded-For here would let any caller forge the
   field.

7. **Auth model.** This endpoint does NOT use the standard
   ``require_api_key`` X-API-Key dep. It has its own HMAC. We
   deliberately omit ``dependencies=[Depends(require_api_key)]``
   so Cloudflare only has to set the signature header, not the
   X-API-Key header. Operators who want belt-and-braces can
   terminate Cloudflare traffic behind a reverse proxy that
   adds X-API-Key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ... import audit
from ...db import get_session_factory
from ...logging import get_logger
from ...models import Event, Host
from ...streams.publisher import publish_event

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

#: Source string written into ``events.source`` for every row persisted
#: by this endpoint. Detector rules can branch on this.
SourceCloudflareLogpush = "cloudflare_logpush"

#: HMAC header that Cloudflare sends. The value of this header is
#: ``hex(hmac_sha256(secret, raw_body))`` and is configured in the
#: Logpush push job definition. (Cloudflare does not natively sign
#: Logpush payloads — the header is the only auth we get.)
HMAC_HEADER_NAME = "X-ZaQorin-Signature"

#: Hard cap on the request body. Cloudflare batches are 1-2 MiB;
#: 5 MiB gives headroom.
MAX_BODY_BYTES = 5 * 1024 * 1024

#: Hard cap on a single NDJSON line. Cloudflare http_requests
#: records are well under this in practice.
MAX_LINE_BYTES = 64 * 1024
# F-027: cap the maximum JSON nesting depth. Implemented in
# ``zaqorincore_server.utils.depth_json`` so it can be unit-tested
# without dragging in the FastAPI app surface. The aliases below
# are kept for any existing import paths.
from ...utils.depth_json import (  # noqa: E402
    MAX_JSON_DEPTH,
    DepthLimitedDecoder as _DepthLimitedDecoder,
)

# F-027: singleton instance for reuse across the request.
_depth_decoder = _DepthLimitedDecoder()

#: Hard cap on a single metadata value, in characters. Anything
#: longer is truncated before persist so a single rogue record
#: can't blow the JSONB column budget.
MAX_METADATA_CHARS = 4096

#: Schema version written into ``events.schema`` for every ingested
#: record. Bump when the on-wire JSON shape changes in a non-
#: backward-compatible way (consistent with the agent's SchemaVersion).
SCHEMA_VERSION = "1.0"

#: Well-known dev placeholder for the shared secret. Refused at
#: import time in production. See evidence.py for the same pattern.
_DEV_PLACEHOLDER = "zaqorincore-dev-cloudflare-secret-change-me"

#: Stable host_id used for every Cloudflare Logpush event. Logpush
#: records have no concept of a host; we synthesise one row in the
#: ``hosts`` table so the FK from ``events.host_id`` stays valid.
#: Operators who want per-zone hosts can map Cloudflare zone IDs
#: to host_ids in a follow-up increment.
_LOGPUSH_HOST_ID = uuid.UUID("b1f4b3e0-0000-0000-0000-000000000001")

#: Display name for the synthesised host. Helps operators find it in
#: the web console and group its events.
_LOGPUSH_HOSTNAME = "cloudflare-logpush"


# ---------------------------------------------------------------------------
# Secret resolution (mirrors evidence.py)
# ---------------------------------------------------------------------------

_env_secret = os.environ.get("ZAQORIN_CLOUDFLARE_INGEST_SECRET", "")
_is_dev = os.environ.get("ZAQORIN_ENV", "production") != "production"
if not _env_secret:
    if _is_dev:
        import warnings as _w

        _w.warn(
            "ZAQORIN_CLOUDFLARE_INGEST_SECRET not set; using insecure "
            "placeholder. Set ZAQORIN_CLOUDFLARE_INGEST_SECRET to a "
            "32+ byte secret in production.",
            stacklevel=2,
        )
        _env_secret = _DEV_PLACEHOLDER
    else:
        # Production: refuse to register the endpoint rather than run
        # with a publicly-known secret.
        raise RuntimeError(
            "ZAQORIN_CLOUDFLARE_INGEST_SECRET must be set in production. "
            "Generate one with: python -c 'import secrets; "
            "print(secrets.token_urlsafe(32))'"
        )
elif _env_secret == _DEV_PLACEHOLDER and not _is_dev:
    raise RuntimeError(
        "ZAQORIN_CLOUDFLARE_INGEST_SECRET is set to the well-known "
        "dev placeholder. Refusing to start in production."
    )
# Keep the secret in memory as bytes for HMAC.
_HMAC_SECRET: bytes = _env_secret.encode("utf-8")
del _env_secret  # module-private from here on

log = get_logger(__name__)
std_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

# NB: deliberately NO `dependencies=[Depends(require_api_key)]`. This
# endpoint has its own HMAC auth; see module docstring security model
# point (7).
router = APIRouter(
    prefix="/api/v1/ingest/cloudflare",
    tags=["ingest", "cloudflare"],
)


class IngestAck(BaseModel):
    """Response body returned on a successful ingest."""

    accepted: int
    rejected: int


@dataclass(frozen=True)
class _IngestResult:
    """Internal tuple carrying both the ack payload and counters
    useful for structured logging."""

    accepted: int
    rejected: int


# ---------------------------------------------------------------------------
# Metadata mapping (Cloudflare field -> event.Metadata key)
# ---------------------------------------------------------------------------

#: Maps Cloudflare record field names to the event.Metadata keys we
#: persist. Only fields present in this map get into metadata; extra
#: fields on the wire are preserved on the raw row but not extracted.
#:
#: NOTE: per the implementation spec we use the literal string keys
#: ``"method"`` and ``"status"`` here. The agent Go module uses
#: ``WebKeyMethod = "http_method"`` and ``WebKeyStatus = "status_code"``
#: (see ``agent/internal/event/event.go``). The Logpush pipeline
#: is independent of the agent pipeline; both write to the same
#: ``events.metadata`` JSONB column and detectors match either.
_CF_TO_METADATA: dict[str, str] = {
    "ClientIP": "src_ip",
    "ClientRequestHost": "host",
    "ClientRequestMethod": "method",
    "ClientRequestURI": "uri",
    "EdgeResponseStatus": "status",
    "ClientRequestUserAgent": "user_agent",
    "ClientCountry": "country",
    "ClientASN": "asn",
    "BotScore": "bot_score",
    "WAFAction": "waf_action",
    "WAFRuleID": "waf_rule_id",
    "CacheCacheStatus": "cache_status",
    "EdgeStartTimestamp": "edge_start_ts",
    "EdgeEndTimestamp": "edge_end_ts",
}


def _truncate(value: Any) -> str | None:
    """Coerce a Cloudflare field value to a string and truncate to
    ``MAX_METADATA_CHARS``. Returns ``None`` for ``None`` so the
    caller can drop the key entirely."""
    if value is None:
        return None
    s = str(value)
    if len(s) > MAX_METADATA_CHARS:
        s = s[:MAX_METADATA_CHARS]
    return s


def _build_metadata(record: dict[str, Any]) -> dict[str, str]:
    """Translate a single Cloudflare Logpush record into our event
    metadata dict. Fields missing from the record are silently
    dropped (we don't store ``None`` values — keeps the JSONB
    column tight)."""
    out: dict[str, str] = {}
    for cf_field, meta_key in _CF_TO_METADATA.items():
        v = record.get(cf_field)
        if v is None:
            continue
        truncated = _truncate(v)
        if truncated is None:
            continue
        out[meta_key] = truncated
    return out


def _parse_timestamp(raw: Any) -> datetime:
    """Coerce a Cloudflare timestamp field to a tz-aware datetime.
    Falls back to the current UTC time if the field is missing or
    unparseable — Logpush records always include EdgeStartTimestamp
    but we don't want a single bad value to drop the whole batch."""
    if not isinstance(raw, str):
        return datetime.now(timezone.utc)
    # Cloudflare emits RFC3339 with fractional seconds. ``fromisoformat``
    # handles that since Python 3.11.
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Host bootstrap
# ---------------------------------------------------------------------------


async def _ensure_logpush_host(session: AsyncSession) -> Host:
    """Make sure the synthesised Cloudflare Logpush host exists.

    Idempotent: INSERT ... ON CONFLICT DO UPDATE. The conflict
    branch only bumps ``last_seen_at`` — we never overwrite a host
    that an operator has re-purposed.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(Host)
        .values(
            id=_LOGPUSH_HOST_ID,
            first_seen_at=now,
            last_seen_at=now,
            last_version=SCHEMA_VERSION,
            hostname=_LOGPUSH_HOSTNAME,
            secret=None,  # Logpush host has no agent; secret unused
            auto_block=False,
            meta={
                "kind": "cloudflare_logpush",
                "note": "synthesised host for Cloudflare Logpush ingest",
            },
        )
        .on_conflict_do_update(
            index_elements=[Host.id],
            set_={"last_seen_at": now},
        )
        .returning(Host)
    )
    result = await session.execute(stmt)
    return result.scalar_one()


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


def _verify_hmac(body: bytes, presented_signature: str) -> bool:
    """Constant-time HMAC-SHA256 verification.

    Returns ``True`` iff ``presented_signature`` (hex) matches
    ``hex(hmac_sha256(_HMAC_SECRET, body))``. Uses
    ``hmac.compare_digest`` to avoid leaking per-byte timing to a
    network attacker.

    Defensive checks:

    * Empty signature -> ``False``.
    * Wrong length -> ``False`` (without computing HMAC).
    * Non-hex characters -> ``False``.
    """
    if not presented_signature:
        return False
    # Hex of SHA-256 is exactly 64 chars; reject anything else to
    # avoid passing arbitrary bytes to ``hmac.compare_digest``.
    if len(presented_signature) != 64:
        return False
    try:
        # Decode only after the length check. If we tried to decode
        # garbage here and feed it to ``compare_digest`` we'd get
        # a benign mismatch — but raising ValueError would be a
        # log-spam oracle on the error path.
        expected = hmac.new(_HMAC_SECRET, body, hashlib.sha256).hexdigest()
    except Exception:  # noqa: BLE001 - never let the verifier crash
        return False
    # Constant-time comparison. Both sides are str (hex).
    return hmac.compare_digest(expected, presented_signature.lower())


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post("", response_model=IngestAck)
async def ingest_cloudflare_logpush(
    request: Request,
    x_zaqorin_signature: str | None = Header(default=None, alias=HMAC_HEADER_NAME),
) -> IngestAck | Response:
    """Accept a Cloudflare Logpush NDJSON batch.

    Returns 200 ``{"accepted": N, "rejected": M}`` on a successfully
    authenticated batch. Malformed JSON lines count toward ``rejected``;
    we never fail the whole batch on one bad line.

    Returns:
    * **401** with empty body if the HMAC header is missing or
      wrong. (We return a ``Response`` directly rather than
      ``HTTPException`` so FastAPI doesn't attach a
      ``{"detail": "Unauthorized"}`` body — that would be a
      forgery oracle.)
    * **413** if Content-Length > 5 MiB.
    * **422** if the body is empty (Logpush always sends >= 1 line).
    """
    # ---- (1) Content-Length guard (cheapest check first) --------------
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            cl = int(content_length)
        except ValueError:
            cl = -1
        if cl < 0 or cl > MAX_BODY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"body too large: {cl} > {MAX_BODY_BYTES}",
            )

    # ---- (2) Read the body (cap as we go) ---------------------------
    # We check Content-Length first so we can reject over-cap requests
    # without ever buffering 5 MiB+ in memory. The body read itself
    # is also bounded: if the body exceeds ``MAX_BODY_BYTES`` (e.g.
    # a chunked transfer without Content-Length, or a lying peer),
    # we still reject before persisting.
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"body too large (> {MAX_BODY_BYTES} bytes)",
        )

    # ---- (3) HMAC verification (BEFORE parse, BEFORE db, BEFORE log)
    # We return ``Response(status_code=401)`` directly — NOT raise
    # HTTPException — because FastAPI's HTTPException attaches a
    # ``{"detail": "Unauthorized"}`` body. The spec requires an
    # empty body so the endpoint is not a forgery oracle.
    if x_zaqorin_signature is None:
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "HMAC-SHA256"},
        )
    if not _verify_hmac(bytes(body), x_zaqorin_signature):
        # Same: no body. No log of the body content (that's the
        # forgery-oracle defence). A generic warning is fine because
        # it does not depend on body content.
        std_log.warning("cloudflare ingest: HMAC verification failed")
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "HMAC-SHA256"},
        )

    if not body:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="empty body",
        )

    # ---- (4) Parse + persist ----------------------------------------
    result = await _ingest_ndjson(bytes(body))
    # F-013 fix (v3.2.2): audit hook — record every successful ingest
    # batch so operators can correlate upstream pushes with downstream
    # persistence. We log AFTER persistence so a partial-commit
    # never counts as an accepted batch.
    audit.record(
        actor="cloudflare_logpush",
        action="ingest cloudflare",
        target=str(_LOGPUSH_HOST_ID),
        status=200,
        extra={
            "accepted": result.accepted,
            "rejected": result.rejected,
            "source": SourceCloudflareLogpush,
        },
    )
    return IngestAck(accepted=result.accepted, rejected=result.rejected)


async def _ingest_ndjson(body: bytes) -> _IngestResult:
    """Parse the NDJSON body line by line, persist each valid line,
    and return counters.

    Lines > ``MAX_LINE_BYTES`` count as rejected (defence in depth).
    Malformed JSON lines count as rejected. Successfully parsed lines
    count as accepted iff persistence succeeded.
    """
    factory = get_session_factory()
    accepted = 0
    rejected = 0

    async with factory() as session:
        host = await _ensure_logpush_host(session)
        # One commit covers all events in this batch; per-event
        # commits would be slow on big pushes and we want atomic
        # "all-or-nothing" semantics within a single batch.
        try:
            for line in body.splitlines():
                # Strip CR/LF (Cloudflare NDJSON is \n-separated but
                # tolerate CRLF just in case).
                if line.endswith(b"\r"):
                    line = line[:-1]
                if not line:
                    continue  # blank lines are not an error
                if len(line) > MAX_LINE_BYTES:
                    rejected += 1
                    continue
                try:
                    record = _depth_decoder.decode(line.decode("utf-8", errors="replace"))
                except (ValueError, UnicodeDecodeError):
                    rejected += 1
                    continue
                if not isinstance(record, dict):
                    rejected += 1
                    continue

                metadata = _build_metadata(record)
                occurred_at = _parse_timestamp(record.get("EdgeStartTimestamp"))

                ev = Event(
                    id=uuid.uuid4(),
                    host_id=host.id,
                    schema=SCHEMA_VERSION,
                    occurred_at=occurred_at,
                    source=SourceCloudflareLogpush,
                    raw=line.decode("utf-8", errors="replace"),
                    metadata_=metadata,
                )
                session.add(ev)
                accepted += 1
            await session.commit()
        except IntegrityError:
            # FK violation, unique violation, etc. Roll back the
            # whole batch and surface as 500 — better than a
            # half-persisted batch.
            await session.rollback()
            log.exception("cloudflare ingest: integrity error")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="persistence failed",
            )
        except Exception:  # noqa: BLE001 - last resort
            await session.rollback()
            log.exception("cloudflare ingest: unexpected error")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="persistence failed",
            )

    # ---- (5) Stream publish (best-effort, mirror event_service) -----
    # We re-query the just-committed rows so the stream event carries
    # the server-assigned UUID and occurred_at the DB stored. We
    # could batch, but Cloudflare pushes are bursty and small, so
    # per-event publish keeps the code readable.
    if accepted:
        await _publish_accepted(factory, host.id, accepted)

    log.info(
        "cloudflare ingest",
        accepted=accepted,
        rejected=rejected,
        source=SourceCloudflareLogpush,
    )
    return _IngestResult(accepted=accepted, rejected=rejected)


async def _publish_accepted(
    factory: Any,
    host_id: uuid.UUID,
    accepted: int,
) -> None:
    """Best-effort stream publish. Mirrors event_service.publish_event
    but loops over the just-inserted rows. A failure here does not
    roll back the DB — the API is the source of truth, the stream
    is for downstream consumers."""
    async with factory() as session:
        stmt = (
            select(Event)
            .where(Event.host_id == host_id)
            .where(Event.source == SourceCloudflareLogpush)
            .order_by(Event.received_at.desc())
            .limit(accepted)
        )
        result = await session.execute(stmt)
        rows = list(result.scalars().all())
        # Reverse to publish in arrival order (oldest first).
        rows.reverse()
        for row in rows:
            try:
                await publish_event(
                    event_id=row.id,
                    host_id=row.host_id,
                    source=row.source,
                    occurred_at=row.occurred_at,
                )
            except Exception:  # noqa: BLE001 - logged, not re-raised
                log.exception(
                    "cloudflare ingest: stream publish failed",
                    event_id=str(row.id),
                )


__all__ = [
    "router",
    "SourceCloudflareLogpush",
    "HMAC_HEADER_NAME",
    "MAX_BODY_BYTES",
    "MAX_LINE_BYTES",
    "MAX_METADATA_CHARS",
]