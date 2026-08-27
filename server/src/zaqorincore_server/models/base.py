"""SQLAlchemy declarative base. All models import Base from here."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Single declarative base shared by every model."""
