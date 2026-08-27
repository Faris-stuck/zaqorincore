"""Host model: one row per agent (identified by agent_id = UUID)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )  # = agent_id from HELLO
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    meta: Mapped[dict] = mapped_column(
        JSONB, server_default="{}", nullable=False, default=dict
    )

    events: Mapped[list["Event"]] = relationship(  # noqa: F821
        back_populates="host", cascade="all, delete-orphan"
    )
