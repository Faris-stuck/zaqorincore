"""POST /api/v1/ingest/webhook - generic SIEM-to-SIEM webhook ingest.

The Cloudflare endpoint (``ingest_cloudflare.py``) handles a single
upstream with a fixed wire shape and HMAC auth. This endpoint handles
the long tail: Splunk HTTP Event Collector, Elastic Watcher,
Sumo Logic, and any other SIEM that can POST a JSON document at us.
Each upstream wraps its actual record in a vendor-specific envelope;
this file translates the envelope into our internal event shape.

Wire format
-----------

Two shapes:

* **Single record**: ``{"src_ip": "203.0.113.10", "uri": "/api/auth",
  "method": "POST", "status": 401, "user_agent": "curl/8.4.0", ...}``
* **Batch**: ``{"events": [{...}, {...}]}`` - array of same-shaped
  records.

Field names match the existing metadata keys (src_ip, host, method,
uri, status, user_agent, referer, country, asn, bot_score,
waf_action, waf_rule_id, cache_status). Vendor translators are
responsible for reshaping the upstream envelope; passthrough (the
``generic`` vendor) sends field names straight through.

Source detection
----------------

The persisted ``events.source`` value comes from:

1. ``X-Event-Source`` request header (wins over body)
2. The body's top-level ``"source"`` field
3. The literal string ``"webhook"`` if neither is set

Vendor selection
----------------

The vendor translator is selected by:

1. ``?vendor=`` query parameter (wins over header)
2. ``X-Event-Source`` request header
3. ``generic`` (passthrough) if neither is set

The translator may also seed ``source`` itself (e.g. Splunk HEC
uses ``sourcetype``), but the header still wins.

Security model
--------------

1. **X-API-Key auth.** This endpoint uses the standard
   ``require_api_key`` X-API-Key dep, like every other v1 router
   that is operator-facing. Operators generate the shared secret
   with ``ZAQORIN_API_KEY``; it rotates with the rest of the API.
   This is intentionally LOWER trust than the Cloudflare HMAC
   path: the X-API-Key is a single shared secret that ops knows,
   not a per-push job secret rotated per zone.

2. **No HMAC.** We do NOT verify an HMAC over the body here. A
   vendor that wants HMAC can be added as a translator in a
   future increment. The threat model assumes the operator who
   can reach the endpoint has already passed the gateway.

3. **Body size cap.** Reject ``Content-Length > 1 MiB`` before
   reading the body. Webhook payloads are typically small; 1 MiB
   gives headroom and stops a misconfigured producer from
   consuming memory.

4. **Per-field metadata truncation.** Every metadata value is
   string-truncated to 4 KiB before persist so a single rogue
   field cannot blow the JSONB column budget. Same pattern as
   ``ingest_cloudflare.py``.

5. **Source IP trust.** The ``src_ip`` field in the JSON body is
   TRUSTED because the endpoint is gated by ``X-API-Key`` - this
   is operator-only access. This is a lower-trust model than the
   Cloudflare path, where ``src_ip`` is read from the Cloudflare
   ``ClientIP`` field and the X-API-Key is NOT used (HMAC only).
   If you proxy untrusted traffic to this endpoint, terminate
   it behind a reverse proxy that enforces the API key for you.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel

from ... import audit
from ...db import get_session_factory
from ...logging import get_logger
from ...models import Event, Host
from ...security import require_api_key
from ...streams.publisher import publish_event
# F-028: cap JSON nesting depth to prevent parser DoS via deeply-nested
# payloads (F-027 sibling). Re-uses the same depth-limited decoder the
# Cloudflare Logpush endpoint uses. Body-size cap of 1 MiB still applies
# at the Content-Length check above.
from ...utils.depth_json import safe_loads

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

#: Source string written into ``events.source`` for every row persisted
#: by this endpoint when no upstream-identifying value is supplied.
#: Detector rules can branch on this.
SourceWebhookDefault = "webhook"

#: Hard cap on the request body. Webhook payloads are typically small;
#: 1 MiB gives headroom and stops a misconfigured producer.
MAX_BODY_BYTES = 1 * 1024 * 1024

#: Hard cap on a single metadata value, in characters. Anything longer
#: is truncated before persist. Matches the Cloudflare ingest.
MAX_METADATA_CHARS = 4096

#: Schema version written into ``events.schema`` for every ingested
#: record. Bump when the on-wire JSON shape changes in a non-
#: backward-compatible way (consistent with the agent's SchemaVersion).
SCHEMA_VERSION = "1.0"

#: Header operators use to identify the upstream vendor / source.
#: Wins over the body's top-level ``source`` field.
EVENT_SOURCE_HEADER = "X-Event-Source"

#: Field names the endpoint recognises on the wire. Vendors are
#: responsible for translating their envelope into these keys; the
#: ``generic`` vendor sends them straight through.
_RECOGNISED_FIELDS: frozenset[str] = frozenset(
    {
        "src_ip",
        "host",
        "method",
        "uri",
        "status",
        "user_agent",
        "referer",
        "country",
        "asn",
        "bot_score",
        "waf_action",
        "waf_rule_id",
        "cache_status",
        "occurred_at",
    }
)

#: Stable host_id used for every webhook event. Webhook payloads
#: have no concept of a host; we synthesise one row in the
#: ``hosts`` table so the FK from ``events.host_id`` stays valid.
#: Operators who want per-vendor hosts can map vendor names to
#: host_ids in a follow-up increment.
_WEBHOOK_HOST_ID = uuid.UUID("b1f4b3e0-0000-0000-0000-000000000002")

#: Display name for the synthesised host. Helps operators find it in
#: the web console and group its events.
_WEBHOOK_HOSTNAME = "webhook-ingest"

#: Friendly label for the synthesised host's metadata.
_WEBHOOK_HOST_KIND = "webhook"

#: Regex used by the Sumo Logic translator to parse ``key=value``
#: pairs out of a free-form ``message`` string. Greedy on the key
#: side, non-whitespace on the value side; values that contain
#: spaces won't round-trip but that's already lossy.
_SUMO_KV_RE = re.compile(r"(\w+)=(\S+)")

log = get_logger(__name__)
std_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

# This endpoint DOES use the standard ``require_api_key`` X-API-Key
# dep. See the module docstring security-model section.
router = APIRouter(
    prefix="/api/v1/ingest/webhook",
    tags=["ingest", "webhook"],
    dependencies=[Depends(require_api_key)],
)


class IngestAck(BaseModel):
    """Response body returned on a successful ingest."""

    accepted: int
    rejected: int
    source: str


@dataclass(frozen=True)
class _IngestResult:
    """Internal tuple carrying both the ack payload and counters
    useful for structured logging."""

    accepted: int
    rejected: int
    source: str


# ---------------------------------------------------------------------------
# Vendor translation table
# ---------------------------------------------------------------------------

#: Translator signature. Receives the parsed JSON body and returns:
#:
#: * a list of records (each a dict whose keys come from
#:   ``_RECOGNISED_FIELDS`` - anything else is dropped)
#: * a source string to use when neither the header nor the body's
#:   ``source`` field provided one (may be empty; caller falls back
#:   to ``SourceWebhookDefault``)
#:
#: Translators MUST NOT raise on malformed input - the caller treats
#: exceptions as "this body was rejected" and increments the
#: rejected counter.
Translator = Callable[[dict[str, Any]], tuple[list[dict[str, Any]], str]]


def _translate_generic(
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    """Pass fields through unchanged.

    A single record is the body itself; a batch is ``body["events"]``.
    Unknown fields are dropped.
    """
    if "events" in body:
        events_raw = body["events"]
        if not isinstance(events_raw, list):
            return [], ""
        records: list[dict[str, Any]] = []
        for item in events_raw:
            if isinstance(item, dict):
                records.append(_filter_fields(item))
        return records, ""
    return [_filter_fields(body)], ""


def _translate_splunk_hec(
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    """Splunk HTTP Event Collector: ``{"event": {...}, "sourcetype": "..."}``.

    The actual record lives under ``"event"``. ``"sourcetype"`` is a
    Splunk-specific field name; we expose it via the source string
    so detectors can branch on it.
    """
    inner = body.get("event")
    if not isinstance(inner, dict):
        return [], ""
    sourcetype = body.get("sourcetype")
    seed_source = str(sourcetype) if isinstance(sourcetype, str) else ""
    return [_filter_fields(inner)], seed_source


def _translate_elastic_webhook(
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    """Elastic Watcher: ``{"hits": {"hits": [{"_source": {...}}]}}``.

    Walks into ``hits.hits[*]._source`` and treats each as a
    separate record. Multiple hits become a batch.
    """
    hits = body.get("hits")
    if not isinstance(hits, dict):
        return [], ""
    inner_hits = hits.get("hits")
    if not isinstance(inner_hits, list):
        return [], ""
    records = []
    for hit in inner_hits:
        if isinstance(hit, dict):
            src = hit.get("_source")
            if isinstance(src, dict):
                records.append(_filter_fields(src))
    return records, ""


def _translate_sumo_logic(
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    """Sumo Logic: ``{"records": [{"message": "..."}]}``.

    Each record's ``message`` is a free-form string. If it's valid
    JSON, parse it and use the result as the record. Otherwise,
    parse ``key=value`` pairs and use them as fields.
    """
    records_raw = body.get("records")
    if not isinstance(records_raw, list):
        return [], ""
    records = []
    for rec in records_raw:
        if not isinstance(rec, dict):
            continue
        msg = rec.get("message")
        if not isinstance(msg, str):
            continue
        # Try JSON first. F-028: cap nesting depth so a deeply-nested
        # `message` value cannot blow the recursion limit. The
        # individual `message` field is also bounded by the per-call
        # string-length cap that the vendor translators apply.
        try:
            parsed = safe_loads(msg)
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            records.append(_filter_fields(parsed))
            continue
        # Fall back to key=value regex.
        pairs = _SUMO_KV_RE.findall(msg)
        if pairs:
            records.append(_filter_fields(dict(pairs)))
            continue
        # Free-form message with no parseable structure; preserve
        # the raw text under user_agent so detectors still see it.
        records.append({"user_agent": msg[:MAX_METADATA_CHARS]})
    return records, ""


def _filter_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Drop keys that aren't in the recognised set and coerce values
    to ``str | int | float`` (the JSONB column accepts those
    natively)."""
    out: dict[str, Any] = {}
    for k, v in record.items():
        if k not in _RECOGNISED_FIELDS:
            continue
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


#: Map of vendor name -> translator. Vendor names are lower-case
#: identifiers an operator passes via ``?vendor=`` or
#: ``X-Event-Source``. An unknown vendor falls back to ``generic``.
VENDOR_TRANSLATORS: dict[str, Translator] = {
    "generic": _translate_generic,
    "splunk_hec": _translate_splunk_hec,
    "elastic_webhook": _translate_elastic_webhook,
    "sumo_logic": _translate_sumo_logic,
}


def _pick_translator(
    vendor: str | None,
    header_source: str | None,
) -> Translator:
    """Pick the translator for the current request.

    Priority: explicit ``vendor`` query param > ``X-Event-Source``
    header > ``generic``. Unknown values fall back to ``generic``
    rather than 400-ing: a malformed ``?vendor=foo`` is a config
    bug, not a security event.
    """
    chosen = (vendor or header_source or "generic").lower()
    return VENDOR_TRANSLATORS.get(chosen, _translate_generic)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(value: Any) -> str | None:
    """Coerce a field value to a string and truncate to
    ``MAX_METADATA_CHARS``. Returns ``None`` for ``None`` so the
    caller can drop the key entirely."""
    if value is None:
        return None
    s = str(value)
    if len(s) > MAX_METADATA_CHARS:
        s = s[:MAX_METADATA_CHARS]
    return s


def _build_metadata(record: dict[str, Any]) -> dict[str, str]:
    """Translate a single webhook record into our event metadata dict.
    Fields missing from the record are silently dropped (we don't
    store ``None`` values - keeps the JSONB column tight)."""
    out: dict[str, str] = {}
    for key, raw in record.items():
        if key == "occurred_at":
            # ``occurred_at`` is metadata in the JSONB sense, but
            # the DB column is a real timestamp; handled separately.
            continue
        truncated = _truncate(raw)
        if truncated is None:
            continue
        out[key] = truncated
    return out


def _parse_occurred_at(raw: Any) -> datetime:
    """Coerce an ``occurred_at`` field to a tz-aware datetime.
    Falls back to the current UTC time if the field is missing or
    unparseable."""
    if not isinstance(raw, str):
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


async def _ensure_webhook_host(session: Any) -> Host:
    """Make sure the synthesised webhook host exists. Idempotent:
    INSERT ... ON CONFLICT DO UPDATE. Mirrors
    ``_ensure_logpush_host`` in ``ingest_cloudflare.py``."""
    now = datetime.now(timezone.utc)
    from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: PLC0415

    stmt = (
        pg_insert(Host)
        .values(
            id=_WEBHOOK_HOST_ID,
            first_seen_at=now,
            last_seen_at=now,
            last_version=SCHEMA_VERSION,
            hostname=_WEBHOOK_HOSTNAME,
            secret=None,  # Webhook host has no agent; secret unused
            auto_block=False,
            meta={
                "kind": _WEBHOOK_HOST_KIND,
                "note": "synthesised host for generic webhook ingest",
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
# Endpoint
# ---------------------------------------------------------------------------


@router.post("", response_model=IngestAck)
async def ingest_webhook(
    request: Request,
    vendor: str | None = Query(default=None),
    x_event_source: str | None = Header(default=None, alias=EVENT_SOURCE_HEADER),
) -> IngestAck:
    """Accept a generic webhook payload and persist one or more events.

    Returns 200 ``{"accepted": N, "rejected": M, "source": "..."}`` on
    a successfully authenticated batch. Malformed JSON or records
    missing ``src_ip`` count toward ``rejected``; we never fail the
    whole batch on one bad record.

    Returns:

    * **401** when ``X-API-Key`` is missing or wrong (via
      ``require_api_key``).
    * **413** if ``Content-Length`` > 1 MiB.
    * **422** if the body is empty or the top-level JSON is not an
      object.
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
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"body too large (> {MAX_BODY_BYTES} bytes)",
        )

    if not body:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="empty body",
        )

    # ---- (3) Parse JSON ---------------------------------------------
    # F-028: use depth-limited JSON decoder (F-027 sibling) so a
    # 1 MiB body of deeply-nested JSON cannot blow the interpreter
    # recursion limit and 500 the whole batch.
    try:
        parsed = safe_loads(body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        # Whole-body parse failure: treat as one rejected record.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="malformed JSON",
        )

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="top-level JSON must be an object",
        )

    # ---- (4) Translate vendor envelope -------------------------------
    translator = _pick_translator(vendor, x_event_source)
    try:
        records, vendor_source = translator(parsed)
    except Exception:  # noqa: BLE001 - never let a vendor crash the endpoint
        std_log.exception("webhook ingest: translator raised")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="translator failed",
        )

    # ---- (5) Source detection (header > body > default) --------------
    # Header wins over body's top-level ``source`` field. Vendor
    # translator may have provided a seed (e.g. Splunk ``sourcetype``)
    # which is used only when both the header and the body are
    # silent.
    header_source = (x_event_source or "").strip() or None
    body_source_raw = parsed.get("source")
    body_source = (
        str(body_source_raw).strip()
        if isinstance(body_source_raw, str) and body_source_raw.strip()
        else None
    )
    detected_source = (
        header_source
        or body_source
        or (vendor_source.strip() if vendor_source else "")
        or SourceWebhookDefault
    )

    # ---- (6) Persist + publish ---------------------------------------
    result = await _ingest_records(
        records=records,
        source=detected_source,
        vendor=vendor or header_source or "generic",
    )
    # F-013 fix (v3.2.2): audit hook — see ingest_cloudflare for
    # rationale. Log AFTER persistence so a partial-commit never
    # counts as an accepted batch.
    audit.record(
        actor="webhook",
        action="ingest webhook",
        target=detected_source,
        status=200,
        extra={
            "accepted": result.accepted,
            "rejected": result.rejected,
            "vendor": vendor or header_source or "generic",
        },
    )
    return IngestAck(
        accepted=result.accepted,
        rejected=result.rejected,
        source=result.source,
    )


async def _ingest_records(
    *,
    records: list[dict[str, Any]],
    source: str,
    vendor: str,
) -> _IngestResult:
    """Persist each translated record and return counters.

    Records lacking ``src_ip`` count toward ``rejected``. Other
    unknown fields are silently dropped (the translator has
    already filtered them). Persistence failure rolls back the
    whole batch.
    """
    factory = get_session_factory()
    accepted = 0
    rejected = 0
    persisted_ids: list[uuid.UUID] = []

    async with factory() as session:
        host = await _ensure_webhook_host(session)
        try:
            for record in records:
                src_ip = record.get("src_ip")
                if not isinstance(src_ip, str) or not src_ip:
                    rejected += 1
                    continue
                metadata = _build_metadata(record)
                # ``src_ip`` is the required field; make sure it's
                # always in metadata even if the translator put it
                # somewhere else.
                metadata.setdefault("src_ip", _truncate(src_ip) or "")
                metadata["vendor"] = _truncate(vendor) or vendor
                occurred_at = _parse_occurred_at(record.get("occurred_at"))
                ev = Event(
                    id=uuid.uuid4(),
                    host_id=host.id,
                    schema=SCHEMA_VERSION,
                    occurred_at=occurred_at,
                    source=source,
                    raw=json.dumps(record, separators=(",", ":")),
                    metadata_=metadata,
                )
                session.add(ev)
                persisted_ids.append(ev.id)
                accepted += 1
            await session.commit()
        except Exception:  # noqa: BLE001 - last resort
            await session.rollback()
            log.exception("webhook ingest: persistence failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="persistence failed",
            )

    # ---- (7) Stream publish (best-effort) ---------------------------
    if persisted_ids:
        await _publish_persisted(factory, host.id, persisted_ids)

    log.info(
        "webhook ingest",
        accepted=accepted,
        rejected=rejected,
        source=source,
        vendor=vendor,
    )
    return _IngestResult(accepted=accepted, rejected=rejected, source=source)


async def _publish_persisted(
    factory: Any,
    host_id: uuid.UUID,
    ids: list[uuid.UUID],
) -> None:
    """Best-effort stream publish for the just-inserted rows. A
    failure here does not roll back the DB - the API is the source
    of truth, the stream is for downstream consumers."""
    from sqlalchemy import select  # noqa: PLC0415

    async with factory() as session:
        rows = list(
            (
                await session.execute(
                    select(Event).where(Event.id.in_(ids))
                )
            )
            .scalars()
            .all()
        )
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
                    "webhook ingest: stream publish failed",
                    event_id=str(row.id),
                )


__all__ = [
    "router",
    "SourceWebhookDefault",
    "MAX_BODY_BYTES",
    "MAX_METADATA_CHARS",
    "EVENT_SOURCE_HEADER",
    "SCHEMA_VERSION",
    "VENDOR_TRANSLATORS",
]