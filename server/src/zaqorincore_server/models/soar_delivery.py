"""SoarDelivery model: one row per HTTP delivery attempt.

Added in v1.3.0 (ADR-008) so the operator can audit every
webhook call the SOAR worker makes. Schema:

    id            UUID primary key
    alert_id      UUID -> alerts.id (cascade delete)
    backend       text  (generic_webhook, slack, ...)
    status_code   int   (HTTP status; 0 for network error)
    attempted_at  timestamptz
    duration_ms   int
    attempt       int   (1-based; 1..max_retries+1)
    error         text  (nullable; populated on failure)
    dead_lettered bool  (true if this attempt gave up)
    payload_sha256 text (hex of the body we sent)

Indexes:
    (alert_id)         - "show me everything for this alert"
    (backend, attempted_at desc) - "24h health per backend"
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class SoarDelivery(Base):
    __tablename__ = "soar_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    backend: Mapped[str] = mapped_column(String(32), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    error: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    dead_lettered: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    payload_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index(
            "ix_soar_deliveries_backend_attempted_at",
            "backend",
            "attempted_at",
        ),
    )
