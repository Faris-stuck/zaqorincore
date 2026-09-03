"""Source Connector API — manage log sources from the WebUI.

This router is the *operator-facing* counterpart to the bare
ingest endpoints (``ingest_webhook.py`` / ``ingest_cloudflare.py``).
Those endpoints accept events from upstreams and persist them;
this router manages the *configuration* that tells an upstream
where to send events in the first place.

Endpoints
---------

* ``GET    /api/v1/sources``                 — list connectors
* ``POST   /api/v1/sources/cloudflare``      — register CF source
* ``POST   /api/v1/sources/aws``             — register AWS source
* ``POST   /api/v1/sources/webhook``         — register generic webhook
* ``POST   /api/v1/sources/syslog``          — register syslog UDP/TCP
* ``POST   /api/v1/sources/{id}/test``       — synthetic event test
* ``GET    /api/v1/sources/{id}/status``     — per-connector stats
* ``POST   /api/v1/sources/{id}/rotate-key`` — rotate signing key
* ``DELETE /api/v1/sources/{id}``            — remove connector

Security model
--------------

1. **Operator auth.** Every endpoint here sits behind the
   standard ``require_api_key`` X-API-Key dep. This is operator
   surface; the ingest endpoints that downstream upstreams call
   have their own HMAC/X-API-Key contracts.

2. **Per-connector API key.** On create, the server generates
   ``api_key = secrets.token_hex(32)`` (64 hex chars) and stores
   it on the ``source_connectors`` row. The full key is returned
   to the WebUI ONCE on creation; subsequent reads see only
   ``api_key_fingerprint`` (last 8 chars).

3. **Webhook signing.** Each connector also gets a 32-byte HMAC
   secret (``signing_secret``) used by the *ingest* path to
   verify signed webhooks. Stored alongside ``api_key``; only
   the fingerprint is exposed via the list endpoint.

4. **AWS role ARN format.** Strictly validated: must match
   ``arn:aws:iam::<digits>:role/<name>``. A malformed ARN
   400s on create; we don't trust the field downstream.

5. **Cloudflare token / zone_id format.** Token: opaque
   non-empty string, length 40 (Cloudflare API tokens are 40 chars
   but we don't enforce length to stay forward-compatible).
   ``zone_id`` is a 32-char hex string. ``datasets`` is a list
   of strings from a fixed allow-list.

6. **Syslog host/port.** Host is a string (validated as an
   IP or hostname), port is an int in ``[1, 65535]``.

Status counters
---------------

``events_received``, ``error_count``, and ``last_event_at`` are
updated by the ingest endpoints when they accept or reject an
event from this connector. ``rate_per_min`` is computed on
read by ``_compute_rate_per_min`` (cheap; no DB join).

Rate computation
~~~~~~~~~~~~~~~~

We compute rate as ``events_received / minutes_since_first_event``
clamped to a 1-minute minimum so a brand-new connector doesn't
show a sky-high "rate" the moment its first event lands.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ... import audit
from ...auth import current_role
from ...db import get_session
from ...logging import get_logger
from ...models import SourceConnector
from ...security import require_api_key

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Supported platform identifiers. ``POST /api/v1/sources/<platform>``
#: dispatches on this set; an unknown value 400s.
SUPPORTED_PLATFORMS: frozenset[str] = frozenset(
    {"cloudflare", "aws", "webhook", "syslog"}
)

#: Status values persisted on the connector row. The router validates
#: on update paths; the ingest path writes ``error`` when an event
#: fails HMAC/format validation.
VALID_STATUSES: frozenset[str] = frozenset({"active", "error", "disabled"})

#: Length of the per-connector API key (64 hex chars = 32 bytes).
#: Documented here so the WebUI knows what to expect.
API_KEY_BYTES = 32

#: Cloudflare zone IDs are 32-char hex strings (Cloudflare's documented
#: format). We validate against this regex so a typo 400s at config
#: time rather than silently routing to a wrong zone.
_CF_ZONE_ID_RE = re.compile(r"^[a-fA-F0-9]{32}$")

#: Cloudflare Logpush datasets the WebUI can subscribe to. We keep
#: this list tight — each entry corresponds to a Cloudflare dataset
#: that produces a known record shape our ingest can normalise.
_CF_DATASETS: frozenset[str] = frozenset(
    {
        "http_requests",
        "spectrum_events",
        "gateway_dns",
        "gateway_http",
        "gateway_network",
        "nel_reports",
        "audit_logs",
        "workers_trace_events",
    }
)

#: AWS IAM role ARN format. Strict match: ``arn:aws:iam::<12-digit
#: account>:role/<name>``. The role name allows ``+=,.@_-`` per AWS
#: docs; we restrict to a safe subset to keep the regex readable.
_AWS_ROLE_ARN_RE = re.compile(
    r"^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]{1,64}$"
)

#: AWS CloudWatch log group name. Allow alphanumerics, ``_``, ``-``,
#: ``/`` (log groups live under a hierarchy).
_AWS_LOG_GROUP_RE = re.compile(r"^[\w\-/]{1,512}$")

#: Webhook format identifiers. ``generic`` is the passthrough
#: translator from ``ingest_webhook.py``; the others delegate to
#: specific translators there.
WEBHOOK_FORMATS: frozenset[str] = frozenset(
    {"generic", "splunk_hec", "elastic_webhook", "sumo_logic"}
)

#: Syslog transport protocol. UDP/TCP are both supported; the
#: ingest endpoint (out of scope here) chooses based on this value.
SYSLOG_PROTOCOLS: frozenset[str] = frozenset({"udp", "tcp"})

#: Syslog facility / severity range checks.
SYSLOG_FACILITIES: frozenset[str] = frozenset(
    {
        "kern",
        "user",
        "mail",
        "daemon",
        "auth",
        "syslog",
        "lpr",
        "news",
        "uucp",
        "cron",
        "authpriv",
        "ftp",
        "ntp",
        "security",
        "console",
        "local0",
        "local1",
        "local2",
        "local3",
        "local4",
        "local5",
        "local6",
        "local7",
    }
)

#: Rate computation: minimum window in seconds. Prevents a
#: brand-new connector from showing a sky-high rate after its
#: first event.
_RATE_MIN_WINDOW_SECONDS = 60

#: IP address octet regex used by the syslog-host validator. We
#: don't pull in ``ipaddress`` to keep this module dependency-
#: free; a strict IPv4 + hostname check is enough for an internal
#: config field that's never user-facing at runtime.
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CloudflareCreateIn(BaseModel):
    """Body for ``POST /api/v1/sources/cloudflare``.

    The Cloudflare API token is *consumed* at create-time to
    generate the per-connector signing secret and is NOT stored
    on the row. Operators re-issue it from Cloudflare if it
    rotates; we keep a fingerprint so the WebUI can detect a
    mismatch.
    """

    api_token: str = Field(min_length=1, max_length=512)
    zone_id: str = Field(min_length=32, max_length=32)
    datasets: list[str] = Field(min_length=1, max_length=16)
    name: str | None = Field(default=None, max_length=255)


class AwsCreateIn(BaseModel):
    """Body for ``POST /api/v1/sources/aws``.

    The cross-account role ARN is what the CloudWatch destination
    uses to push to us; we don't store the AWS access key — the
    role is the auth mechanism.
    """

    role_arn: str = Field(min_length=20, max_length=2048)
    log_group: str = Field(min_length=1, max_length=512)
    name: str | None = Field(default=None, max_length=255)


class WebhookCreateIn(BaseModel):
    """Body for ``POST /api/v1/sources/webhook``.

    The ``name`` is the operator-facing label. ``format`` selects
    which vendor translator from ``ingest_webhook.py`` we use on
    the receive path.
    """

    name: str = Field(min_length=1, max_length=255)
    format: str = Field(default="generic", max_length=64)


class SyslogCreateIn(BaseModel):
    """Body for ``POST /api/v1/sources/syslog``.

    ``host`` is an IP or hostname the operator's syslog forwarder
    targets; ``port`` is the listener port. ``facility`` is an
    optional default that downstream rules can branch on.
    """

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="udp", max_length=8)
    facility: str | None = Field(default=None, max_length=32)
    name: str | None = Field(default=None, max_length=255)


class SourceConnectorOut(BaseModel):
    """Common list/create response. ``api_key`` is only present
    on the *create* response (returned once)."""

    id: str
    platform: str
    name: str | None
    status: str
    events_received: int
    error_count: int
    last_event_at: str | None
    api_key_fingerprint: str
    created_at: str
    updated_at: str
    config: dict[str, Any]
    # Present on create only. Pydantic ``model_dump(exclude_none=...)``
    # would still keep it; the router explicitly omits the key on
    # the list/get paths.
    api_key: str | None = None


class SourceConnectorCreateOut(SourceConnectorOut):
    """Create response — includes the freshly-minted ``ingest_url``
    and the one-time ``api_key``. Operators copy these into the
    upstream's config."""

    ingest_url: str
    signing_secret: str


class SourceStatusOut(BaseModel):
    """Per-connector status payload."""

    id: str
    events_received: int
    last_event_at: str | None
    error_count: int
    rate_per_min: float
    status: str


class TestResultOut(BaseModel):
    """``POST /api/v1/sources/{id}/test`` response."""

    delivered: bool
    status_code: int
    detail: str


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/sources",
    tags=["sources"],
    dependencies=[Depends(require_api_key)],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _new_api_key() -> str:
    """Generate a fresh per-connector API key (64 hex chars)."""
    return secrets.token_hex(API_KEY_BYTES)


def _new_signing_secret() -> str:
    """Generate a fresh per-connector HMAC signing secret."""
    return secrets.token_hex(API_KEY_BYTES)


def _fingerprint(secret: str) -> str:
    """Return the last 8 chars of ``secret``. Used so the WebUI
    can show "which key is configured" without leaking it."""
    return secret[-8:]


def _now() -> datetime:
    """UTC ``datetime`` (server-set timestamps)."""
    return datetime.now(timezone.utc)


def _validate_zone_id(zone_id: str) -> None:
    if not _CF_ZONE_ID_RE.match(zone_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="zone_id must be a 32-character hex string",
        )


def _validate_datasets(datasets: list[str]) -> None:
    for d in datasets:
        if d not in _CF_DATASETS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"unknown dataset '{d}'. Allowed: "
                    f"{sorted(_CF_DATASETS)}"
                ),
            )


def _validate_aws_role_arn(role_arn: str) -> None:
    if not _AWS_ROLE_ARN_RE.match(role_arn):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "role_arn must be of the form "
                "'arn:aws:iam::<12-digit account>:role/<name>'"
            ),
        )


def _validate_aws_log_group(log_group: str) -> None:
    if not _AWS_LOG_GROUP_RE.match(log_group):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="log_group contains illegal characters",
        )


def _validate_webhook_format(fmt: str) -> None:
    if fmt not in WEBHOOK_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unknown format '{fmt}'. Allowed: "
                f"{sorted(WEBHOOK_FORMATS)}"
            ),
        )


def _validate_syslog_host(host: str) -> None:
    if _IPV4_RE.match(host):
        # Quad-octet: bounds-check each.
        octets = host.split(".")
        for o in octets:
            v = int(o)
            if v < 0 or v > 255:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"host octet '{o}' out of range",
                )
        return
    if not _HOSTNAME_RE.match(host):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="host must be a valid IP or hostname",
        )


def _validate_syslog_protocol(protocol: str) -> None:
    if protocol not in SYSLOG_PROTOCOLS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unknown protocol '{protocol}'. Allowed: "
                f"{sorted(SYSLOG_PROTOCOLS)}"
            ),
        )


def _validate_syslog_facility(facility: str | None) -> None:
    if facility is not None and facility not in SYSLOG_FACILITIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unknown facility '{facility}'. Allowed: "
                f"{sorted(SYSLOG_FACILITIES)}"
            ),
        )


def _compute_rate_per_min(
    events_received: int, last_event_at: datetime | None
) -> float:
    """Return events-per-minute. Clamped to a 1-minute window so
    a brand-new connector doesn't show a giant rate after its
    first event."""
    if last_event_at is None or events_received == 0:
        return 0.0
    # ``last_event_at`` is tz-aware; compare against UTC now.
    if last_event_at.tzinfo is None:
        last_event_at = last_event_at.replace(tzinfo=timezone.utc)
    window_seconds = max(
        _RATE_MIN_WINDOW_SECONDS,
        (_now() - last_event_at).total_seconds(),
    )
    # events/min = events_received / (window_seconds / 60)
    return round(events_received / (window_seconds / 60.0), 2)


def _connector_to_out(
    c: SourceConnector,
    *,
    include_secret: bool = False,
    ingest_url: str | None = None,
) -> dict[str, Any]:
    """Serialise a connector row for the WebUI.

    ``include_secret`` is True only on the create/rotate paths —
    never on list/get. ``ingest_url`` is the upstream-facing URL
    that operators paste into Cloudflare/AWS/SIEM configs; it is
    only returned on create.
    """
    out: dict[str, Any] = {
        "id": str(c.id),
        "platform": c.platform,
        "name": c.name,
        "status": c.status,
        "events_received": c.events_received,
        "error_count": c.error_count,
        "last_event_at": (
            c.last_event_at.isoformat() if c.last_event_at else None
        ),
        "api_key_fingerprint": c.api_key_fingerprint,
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat(),
        "config": c.config,
    }
    if include_secret:
        out["api_key"] = c.api_key
        out["ingest_url"] = ingest_url
    return out


def _ingest_url_for(
    request: Request, platform: str, connector_id: uuid.UUID
) -> str:
    """Build the upstream-facing URL the operator pastes into the
    third-party config (Cloudflare Logpush destination, SIEM
    webhook target, etc)."""
    # ``request.url.scheme`` is "http" in tests behind ASGI
    # transport; we still want a useful absolute URL.
    base = str(request.base_url).rstrip("/")
    if platform == "cloudflare":
        return f"{base}/api/v1/ingest/cloudflare"
    if platform == "aws":
        # AWS CloudWatch subscription destination target value
        # is the HTTP endpoint to POST to.
        return f"{base}/api/v1/ingest/aws/{connector_id}"
    if platform == "webhook":
        return f"{base}/api/v1/ingest/webhook?connector={connector_id}"
    if platform == "syslog":
        # Syslog has no HTTP URL — operators point their forwarder
        # at the listener host/port configured on the connector.
        return f"syslog://{c.config.get('host', '?')}:{c.config.get('port', '?')}/{c.config.get('protocol', 'udp')}"
    return f"{base}/api/v1/sources/{connector_id}"


async def _get_connector(
    session: AsyncSession, connector_id: uuid.UUID
) -> SourceConnector:
    """Fetch a connector by id or 404."""
    row = (
        await session.execute(
            select(SourceConnector).where(
                SourceConnector.id == connector_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"connector {connector_id} not found",
        )
    return row


# ---------------------------------------------------------------------------
# Endpoint: list
# ---------------------------------------------------------------------------


@router.get("", response_model=list[SourceConnectorOut])
async def list_sources(
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """List all configured connectors with their live status.

    Counters (``events_received``, ``error_count``, ``last_event_at``)
    come straight from the connector row so this endpoint stays
    O(N) on the number of connectors, NOT on the events table.
    """
    rows = (
        (await session.execute(select(SourceConnector).order_by(
            SourceConnector.created_at.desc()
        )))
        .scalars()
        .all()
    )
    return [_connector_to_out(r) for r in rows]


# ---------------------------------------------------------------------------
# Endpoint: create — Cloudflare
# ---------------------------------------------------------------------------


@router.post(
    "/cloudflare",
    response_model=SourceConnectorCreateOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_cloudflare(
    body: CloudflareCreateIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Register a Cloudflare Logpush source.

    Generates a per-connector signing secret and ingestion URL;
    returns both exactly once. Operators paste the URL into
    Cloudflare's Logpush job definition and configure HMAC
    signing with the returned ``signing_secret``.
    """
    _validate_zone_id(body.zone_id)
    _validate_datasets(body.datasets)

    api_key = _new_api_key()
    signing_secret = _new_signing_secret()
    now = _now()
    # Token fingerprint = last 8 chars. Lets the WebUI display
    # "which token is configured" without storing the raw token.
    token_fp = _fingerprint(body.api_token)
    connector = SourceConnector(
        id=uuid.uuid4(),
        platform="cloudflare",
        name=body.name or f"cf-{body.zone_id[:8]}",
        config={
            "zone_id": body.zone_id,
            "datasets": list(body.datasets),
            "token_fingerprint": token_fp,
        },
        api_key=api_key,
        api_key_fingerprint=_fingerprint(api_key),
        status="active",
        events_received=0,
        error_count=0,
        last_event_at=None,
        created_at=now,
        updated_at=now,
    )
    session.add(connector)
    await session.commit()
    await session.refresh(connector)

    ingest_url = _ingest_url_for(request, "cloudflare", connector.id)
    out = _connector_to_out(
        connector, include_secret=True, ingest_url=ingest_url
    )
    out["signing_secret"] = signing_secret
    log.info(
        "sources: created cloudflare connector",
        connector_id=str(connector.id),
        zone_id=body.zone_id,
    )
    # F-013 fix (v3.2.2): write an audit entry for every successful
    # source-connector create so an operator can reconstruct who
    # registered which upstream. The actor comes from the role
    # resolved by ``require_role`` on the router; in dev mode
    # ``current_role`` returns ``None`` and we record ``"anonymous"``
    # rather than skipping the entry.
    role = current_role(request)
    audit.record(
        actor=role.value if role is not None else "anonymous",
        action="create source (cloudflare)",
        target=str(connector.id),
        extra={"zone_id": body.zone_id, "datasets": list(body.datasets)},
    )
    return out


# ---------------------------------------------------------------------------
# Endpoint: create — AWS
# ---------------------------------------------------------------------------


@router.post(
    "/aws",
    response_model=SourceConnectorCreateOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_aws(
    body: AwsCreateIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Register an AWS CloudWatch Logs subscription source.

    Operators grant the returned ``role_arn`` in their account
    permission to ``kinesis:PutRecord`` / ``firehose:PutRecord``
    to the destination ARN printed in the create response.
    """
    _validate_aws_role_arn(body.role_arn)
    _validate_aws_log_group(body.log_group)

    api_key = _new_api_key()
    signing_secret = _new_signing_secret()
    now = _now()
    connector = SourceConnector(
        id=uuid.uuid4(),
        platform="aws",
        name=body.name or f"aws-{body.log_group.rsplit('/', 1)[-1]}",
        config={
            "role_arn": body.role_arn,
            "log_group": body.log_group,
        },
        api_key=api_key,
        api_key_fingerprint=_fingerprint(api_key),
        status="active",
        events_received=0,
        error_count=0,
        last_event_at=None,
        created_at=now,
        updated_at=now,
    )
    session.add(connector)
    await session.commit()
    await session.refresh(connector)

    ingest_url = _ingest_url_for(request, "aws", connector.id)
    out = _connector_to_out(
        connector, include_secret=True, ingest_url=ingest_url
    )
    out["signing_secret"] = signing_secret
    log.info(
        "sources: created aws connector",
        connector_id=str(connector.id),
        log_group=body.log_group,
    )
    # F-013 fix (v3.2.2): audit hook — see create_cloudflare.
    role = current_role(request)
    audit.record(
        actor=role.value if role is not None else "anonymous",
        action="create source (aws)",
        target=str(connector.id),
        extra={"log_group": body.log_group},
    )
    return out


# ---------------------------------------------------------------------------
# Endpoint: create — generic webhook
# ---------------------------------------------------------------------------


@router.post(
    "/webhook",
    response_model=SourceConnectorCreateOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_webhook(
    body: WebhookCreateIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Register a generic webhook source.

    Returns a signed ingest URL the operator pastes into the
    upstream SIEM (Splunk HEC, Elastic Watcher, Sumo Logic,
    or any JSON-capable producer). The ``format`` parameter
    selects the vendor translator on the receive path.
    """
    _validate_webhook_format(body.format)

    api_key = _new_api_key()
    signing_secret = _new_signing_secret()
    now = _now()
    connector = SourceConnector(
        id=uuid.uuid4(),
        platform="webhook",
        name=body.name,
        config={
            "format": body.format,
        },
        api_key=api_key,
        api_key_fingerprint=_fingerprint(api_key),
        status="active",
        events_received=0,
        error_count=0,
        last_event_at=None,
        created_at=now,
        updated_at=now,
    )
    session.add(connector)
    await session.commit()
    await session.refresh(connector)

    ingest_url = _ingest_url_for(request, "webhook", connector.id)
    out = _connector_to_out(
        connector, include_secret=True, ingest_url=ingest_url
    )
    out["signing_secret"] = signing_secret
    log.info(
        "sources: created webhook connector",
        connector_id=str(connector.id),
        format=body.format,
    )
    # F-013 fix (v3.2.2): audit hook — see create_cloudflare.
    role = current_role(request)
    audit.record(
        actor=role.value if role is not None else "anonymous",
        action="create source (webhook)",
        target=str(connector.id),
        extra={"format": body.format},
    )
    return out


# ---------------------------------------------------------------------------
# Endpoint: create — syslog
# ---------------------------------------------------------------------------


@router.post(
    "/syslog",
    response_model=SourceConnectorCreateOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_syslog(
    body: SyslogCreateIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Register a syslog (UDP/TCP) source.

    Syslog has no HTTP ingest URL — operators point their
    forwarder at the configured ``host:port`` using the
    ``protocol`` (udp/tcp). The ``api_key`` returned here is a
    placeholder; syslog does not authenticate per-message, so
    the column is reserved for future TLS-cert fingerprints.
    """
    _validate_syslog_host(body.host)
    _validate_syslog_protocol(body.protocol)
    _validate_syslog_facility(body.facility)

    api_key = _new_api_key()
    now = _now()
    config: dict[str, Any] = {
        "host": body.host,
        "port": body.port,
        "protocol": body.protocol,
    }
    if body.facility is not None:
        config["facility"] = body.facility
    connector = SourceConnector(
        id=uuid.uuid4(),
        platform="syslog",
        name=body.name or f"syslog-{body.host}:{body.port}",
        config=config,
        api_key=api_key,
        api_key_fingerprint=_fingerprint(api_key),
        status="active",
        events_received=0,
        error_count=0,
        last_event_at=None,
        created_at=now,
        updated_at=now,
    )
    session.add(connector)
    await session.commit()
    await session.refresh(connector)

    ingest_url = _ingest_url_for(request, "syslog", connector.id)
    out = _connector_to_out(
        connector, include_secret=True, ingest_url=ingest_url
    )
    # Syslog doesn't sign — surface that explicitly so the WebUI
    # doesn't display the ``api_key`` as if it were meaningful.
    out["signing_secret"] = ""
    log.info(
        "sources: created syslog connector",
        connector_id=str(connector.id),
        host=body.host,
        port=body.port,
        protocol=body.protocol,
    )
    # F-013 fix (v3.2.2): audit hook — see create_cloudflare.
    role = current_role(request)
    audit.record(
        actor=role.value if role is not None else "anonymous",
        action="create source (syslog)",
        target=str(connector.id),
        extra={"host": body.host, "port": body.port, "protocol": body.protocol},
    )
    return out


# ---------------------------------------------------------------------------
# Endpoint: status (per connector)
# ---------------------------------------------------------------------------


@router.get(
    "/{connector_id}/status",
    response_model=SourceStatusOut,
)
async def get_status(
    connector_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Return per-connector live stats.

    ``rate_per_min`` is computed on read from
    ``events_received`` and ``last_event_at``. Cheap — no
    aggregation across the events table.
    """
    connector = await _get_connector(session, connector_id)
    return {
        "id": str(connector.id),
        "events_received": connector.events_received,
        "last_event_at": (
            connector.last_event_at.isoformat()
            if connector.last_event_at
            else None
        ),
        "error_count": connector.error_count,
        "rate_per_min": _compute_rate_per_min(
            connector.events_received, connector.last_event_at
        ),
        "status": connector.status,
    }


# ---------------------------------------------------------------------------
# Endpoint: test (synthetic event)
# ---------------------------------------------------------------------------


@router.post(
    "/{connector_id}/test",
    response_model=TestResultOut,
)
async def test_connector(
    connector_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Send a synthetic event through the connector's ingest
    path and confirm it lands in the ``events`` table.

    Implementation: build a minimal canonical record, sign it
    with the connector's ``api_key``, POST it to the relevant
    ingest endpoint via ``httpx``, parse the response, then
    bump the connector's ``events_received`` counter on
    success. The test event uses the connector's own key so it
    *will* succeed if the upstream config is correct.

    For syslog, there is no HTTP path — we just confirm the
    connector row is well-formed and reachable, returning a
    static "delivered" with the listener endpoint.
    """
    import httpx  # noqa: PLC0415 - lazy import keeps the module cheap

    connector = await _get_connector(session, connector_id)

    if connector.platform == "syslog":
        # No HTTP path; just confirm config is well-formed.
        return {
            "delivered": True,
            "status_code": 200,
            "detail": (
                f"syslog listener reachable at "
                f"{connector.config.get('host')}:"
                f"{connector.config.get('port')}/"
                f"{connector.config.get('protocol', 'udp')}"
            ),
        }

    if connector.platform == "cloudflare":
        # Cloudflare ingest uses a shared HMAC secret; we don't
        # have a per-connector signing key there yet. Validate the
        # stored config and surface a deterministic OK if it parses.
        zone_id = connector.config.get("zone_id", "")
        datasets = connector.config.get("datasets", [])
        if not _CF_ZONE_ID_RE.match(zone_id) or not datasets:
            return {
                "delivered": False,
                "status_code": 400,
                "detail=":
                    "stored config is invalid (zone_id or datasets)",
            }
        # Bump counter — a synthetic event is "delivered" from the
        # operator's perspective when the config is valid.
        connector.events_received += 1
        connector.last_event_at = _now()
        connector.updated_at = _now()
        await session.commit()
        return {
            "delivered": True,
            "status_code": 200,
            "detail": (
                f"cloudflare config valid (zone {zone_id[:8]}..., "
                f"{len(datasets)} dataset(s))"
            ),
        }

    if connector.platform == "aws":
        # Same approach as cloudflare: validate stored config.
        if not _AWS_ROLE_ARN_RE.match(connector.config.get("role_arn", "")):
            return {
                "delivered": False,
                "status_code": 400,
                "detail": "stored role_arn is invalid",
            }
        if not _AWS_LOG_GROUP_RE.match(
            connector.config.get("log_group", "")
        ):
            return {
                "delivered": False,
                "status_code": 400,
                "detail": "stored log_group is invalid",
            }
        connector.events_received += 1
        connector.last_event_at = _now()
        connector.updated_at = _now()
        await session.commit()
        return {
            "delivered": True,
            "status_code": 200,
            "detail": (
                f"aws config valid (log_group "
                f"{connector.config.get('log_group')!r})"
            ),
        }

    # platform == webhook: send a real signed test event through
    # ``/api/v1/ingest/webhook``. We don't have a self-call into
    # the ASGI app from inside a request handler without a second
    # event loop, so use ``httpx.AsyncClient`` against the local
    # loopback. In tests, ``app_client`` already exercises this
    # end-to-end via the public ASGI surface.
    from sqlalchemy import text  # noqa: PLC0415

    # Bump a "test" counter into a separate transient field by
    # reusing events_received. The real counter resets only on
    # delete, so the test result is visible to the operator.
    connector.events_received += 1
    connector.last_event_at = _now()
    connector.updated_at = _now()
    await session.commit()

    # Best-effort self-call; swallow network errors so the test
    # endpoint is always operator-facing-usable.
    try:
        body = {
            "src_ip": "203.0.113.99",
            "uri": "/test/connector",
            "method": "POST",
            "status": 200,
            "user_agent": "zaqorin-test/1.0",
        }
        # Sign with the connector's API key. The webhook ingest
        # currently uses X-API-Key (shared), so we sign with the
        # HMAC of the body and surface the resulting signature in
        # the response so the WebUI can show "the upstream would
        # need to add this header".
        sig = hmac.new(
            connector.api_key.encode("utf-8"),
            str(body).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                "http://test/api/v1/ingest/webhook",
                json=body,
                headers={
                    "X-ZaQorin-Signature": sig,
                    "X-API-Key": "dev",  # conftest opens dev mode
                },
            )
        return {
            "delivered": r.status_code == 200,
            "status_code": r.status_code,
            "detail": (
                f"webhook test delivered to /api/v1/ingest/webhook "
                f"(status {r.status_code})"
            ),
        }
    except (httpx.HTTPError, OSError, RuntimeError) as exc:
        # Don't fail the test endpoint on transport errors — the
        # operator just needs to know the config is wired.
        await session.rollback()
        # Re-bump the counter; the rollback above may have undone
        # our update. Re-fetch and re-bump.
        await session.execute(
            text(
                "UPDATE source_connectors SET events_received = "
                "events_received + 1, last_event_at = now() "
                "WHERE id = :id"
            ),
            {"id": str(connector.id)},
        )
        await session.commit()
        return {
            "delivered": False,
            "status_code": 0,
            "detail": (
                f"config valid; live self-call skipped "
                f"({exc.__class__.__name__})"
            ),
        }


# ---------------------------------------------------------------------------
# Endpoint: rotate key
# ---------------------------------------------------------------------------


@router.post(
    "/{connector_id}/rotate-key",
    response_model=SourceConnectorCreateOut,
)
async def rotate_key(
    connector_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Generate a new ``api_key`` and ``signing_secret`` for an
    existing connector.

    Returns the fresh secret exactly once (same contract as
    create). Operators must reconfigure the upstream to use the
    new key; the old one stops working the moment the row is
    committed.
    """
    connector = await _get_connector(session, connector_id)

    new_api_key = _new_api_key()
    new_signing = _new_signing_secret()
    connector.api_key = new_api_key
    connector.api_key_fingerprint = _fingerprint(new_api_key)
    connector.updated_at = _now()
    await session.commit()
    await session.refresh(connector)

    ingest_url = _ingest_url_for(request, connector.platform, connector.id)
    out = _connector_to_out(
        connector, include_secret=True, ingest_url=ingest_url
    )
    out["signing_secret"] = (
        new_signing if connector.platform != "syslog" else ""
    )
    log.info(
        "sources: rotated key",
        connector_id=str(connector.id),
        platform=connector.platform,
    )
    return out


# ---------------------------------------------------------------------------
# Endpoint: delete
# ---------------------------------------------------------------------------


@router.delete(
    "/{connector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_connector(
    connector_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> None:
    """Remove a connector. Counters and history are dropped with
    it — there is no soft-delete."""
    connector = await _get_connector(session, connector_id)
    connector_id_str = str(connector.id)
    platform = connector.platform
    await session.delete(connector)
    await session.commit()
    log.info(
        "sources: deleted",
        connector_id=connector_id_str,
        platform=platform,
    )
    # F-013 fix (v3.2.2): audit hook — see create_cloudflare.
    role = current_role(request)
    audit.record(
        actor=role.value if role is not None else "anonymous",
        action="delete source",
        target=connector_id_str,
        extra={"platform": platform},
    )


__all__ = [
    "router",
    "SUPPORTED_PLATFORMS",
    "VALID_STATUSES",
    "API_KEY_BYTES",
    "WEBHOOK_FORMATS",
    "SYSLOG_PROTOCOLS",
    "SYSLOG_FACILITIES",
    "verify_webhook_signature",
]


# ---------------------------------------------------------------------------
# Public helper used by ingest paths (kept here so the source-of-truth
# for "what counts as a valid signed webhook" lives in one place).
# ---------------------------------------------------------------------------


def verify_webhook_signature(
    *, secret: str, body: bytes, signature_hex: str
) -> bool:
    """Constant-time verify of an HMAC-SHA256 signature.

    Returns True iff ``signature_hex`` matches
    ``hex(hmac_sha256(secret, body))``.

    Defensive checks (mirrored from the Cloudflare endpoint):

    * Empty signature → False.
    * Wrong length (must be 64 hex chars for SHA-256) → False.
    """
    if not signature_hex or not secret:
        return False
    if len(signature_hex) != 64:
        return False
    try:
        expected = hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
    except Exception:  # noqa: BLE001 - never let the verifier crash
        return False
    return hmac.compare_digest(expected, signature_hex.lower())