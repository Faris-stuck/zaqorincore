"""SourceConnector model: one row per configured log source.

A connector is a *managed* feed of incoming events. It is
distinct from the synthetic host rows used by the bare ingest
endpoints (Cloudflare Logpush, generic webhook) because:

* The connector carries an operator-issued API key (the HMAC
  secret or webhook signing key) that the WebUI generates and
  shows ONCE on creation. Subsequent views only see a masked
  fingerprint.
* The connector tracks its own event ingestion stats
  (``events_received``, ``error_count``, ``last_event_at``,
  ``rate_per_min``) so the WebUI status table can show a live
  view without recomputing it from the ``events`` table on
  every list call.
* The connector persists the *configuration* the operator
  chose (Cloudflare zone_id + datasets, AWS role_arn +
  log_group, generic webhook format) so it can be re-rendered
  in the WebUI without asking the operator to re-enter the
  values.

Schema choices
--------------

* ``id``: UUIDv4 — primary key. Same shape as every other
  table in this codebase.
* ``platform``: short string discriminator
  (``cloudflare`` / ``aws`` / ``webhook`` / ``syslog``). The
  endpoint validates against a fixed set on create.
* ``name``: human-friendly label chosen by the operator.
  Nullable so the auto-generated name (e.g. ``cf-<zone_id>``)
  is the fallback.
* ``config``: JSONB. Holds the platform-specific config
  (token, zone_id, role_arn, log_group, format, host:port).
  Sensitive values are NEVER stored in plain text — the
  ``api_key`` column is the canonical secret; config holds
  *references* (role ARN, zone id, datasets list).
* ``api_key``: the per-connector signing/API key. Generated
  server-side with ``secrets.token_hex(32)`` on create.
  Returned to the WebUI exactly once on creation; subsequent
  reads only expose ``api_key_fingerprint`` (last 8 chars).
* ``api_key_fingerprint``: last 8 chars of ``api_key``. Lets
  the WebUI show *which* key is currently configured without
  leaking the full secret.
* ``status``: ``active`` / ``error`` / ``disabled``.
* ``events_received``: monotonically increasing counter
  bumped by the ingest endpoints when they accept an event
  from this connector.
* ``error_count``: monotonically increasing counter bumped
  when an ingest from this connector fails HMAC/format.
* ``last_event_at``: server-set on each accepted event.
* ``created_at`` / ``updated_at``: server-managed.

The status counters are stored on the connector row so the
list endpoint can return them without an aggregation query
across ``events``. This is the simplest "live" view and is
the WebUI's only consumer.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class SourceConnector(Base):
    __tablename__ = "source_connectors"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    # Platform discriminator. Validated against a fixed set in
    # the router; the column stays ``String(32)`` so adding a
    # new platform later is just a code change, not a migration.
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # JSONB for platform-specific configuration (zone_id, role_arn,
    # log_group, format, host, port, datasets). Sensitive values
    # (API tokens, secrets) live in ``api_key`` — NEVER in here.
    config: Mapped[dict] = mapped_column(
        JSONB, server_default="{}", nullable=False, default=dict
    )
    # Per-connector signing/API key. Generated on create with
    # ``secrets.token_hex(32)``. Returned ONCE on create.
    api_key: Mapped[str] = mapped_column(String(128), nullable=False)
    # Last 8 chars of api_key. Safe to show in the WebUI so the
    # operator can verify which key is configured.
    api_key_fingerprint: Mapped[str] = mapped_column(
        String(8), nullable=False
    )
    # ``active`` / ``error`` / ``disabled``. ``error`` is set by
    # the ingest path when an event fails validation. ``disabled``
    # is set by the operator via a future toggle endpoint.
    status: Mapped[str] = mapped_column(
        String(16), server_default="active", nullable=False
    )
    # Live counters. Updated by the ingest endpoints; never reset
    # by the operator. ``rate_per_min`` is computed on read
    # (see router helper).
    events_received: Mapped[int] = mapped_column(
        Integer, server_default="0", nullable=False, default=0
    )
    error_count: Mapped[int] = mapped_column(
        Integer, server_default="0", nullable=False, default=0
    )
    last_event_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


__all__ = ["SourceConnector"]