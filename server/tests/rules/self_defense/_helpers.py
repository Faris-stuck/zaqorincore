"""Shared fixtures for self-defense rule tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from zaqorincore_server.detectors.base import ParsedEvent
from zaqorincore_server.self_defense import SELF_DEFENSE_RULES


def make_event(**md):
    """Build a ParsedEvent with given metadata (event_type defaults to ws.hello)."""
    md.setdefault("event_type", "ws.hello")
    md.setdefault("src_ip", "198.51.100.10")
    return ParsedEvent(
        event_id=uuid.uuid4(),
        host_id=uuid.uuid4(),
        source="zaqorincore",
        raw="",
        metadata=md,
        occurred_at=datetime.now(timezone.utc),
    )


def find_rule(needle: str):
    for r in SELF_DEFENSE_RULES:
        if needle in r.title:
            return r
    raise AssertionError(f"no rule matches {needle!r}")