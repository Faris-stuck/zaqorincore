"""Tests for canary token management (Phase 7)."""

from __future__ import annotations

import json

from zaqorincore_server.canary import (
    CanaryDescriptor,
    CanarySpec,
    CanaryTouchedEvent,
    make_canary,
    persist_canary_descriptor,
)


def test_make_canary_creates_unique_id_and_secret() -> None:
    a = make_canary(CanarySpec(kind="file", path="/var/lib/canary/m1.txt"))
    b = make_canary(CanarySpec(kind="file", path="/var/lib/canary/m1.txt"))
    assert a.id != b.id
    assert a.secret != b.secret
    assert a.kind == "file"
    assert a.path == "/var/lib/canary/m1.txt"


def test_persist_canary_writes_json(tmp_path) -> None:
    desc = make_canary(CanarySpec(kind="file", path="/var/lib/canary/m1.txt"))
    out = persist_canary_descriptor(tmp_path, desc)
    assert out.exists()
    body = json.loads(out.read_text())
    assert body["id"] == desc.id
    assert body["kind"] == "file"
    assert body["secret"] == desc.secret


def test_touched_event_requires_touched_by() -> None:
    ev = CanaryTouchedEvent(canary_id="c1", touched_by="203.0.113.7")
    assert ev.canary_id == "c1"
    assert ev.touched_by == "203.0.113.7"
    assert ev.evidence_path is None


def test_touched_event_serialises_to_json() -> None:
    ev = CanaryTouchedEvent(
        canary_id="c1", touched_by="inode:RENAME", evidence_path="/var/lib/canary/m1.txt",
    )
    blob = ev.model_dump_json()
    parsed = json.loads(blob)
    assert parsed["canary_id"] == "c1"
    assert parsed["evidence_path"] == "/var/lib/canary/m1.txt"
