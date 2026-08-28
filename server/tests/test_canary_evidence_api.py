"""Tests for canary + evidence HTTP APIs (Phase 7)."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tarfile

import pytest
from fastapi.testclient import TestClient

from zaqorincore_server.main import create_app


@pytest.fixture
def client(monkeypatch, tmp_path) -> TestClient:
    """Point the evidence store at tmp_path and reset canary state."""
    monkeypatch.setenv("ZAQORIN_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("ZAQORIN_EVIDENCE_KEY", "x" * 64)
    from zaqorincore_server.api.v1 import canary as canary_mod
    canary_mod._IN_MEMORY.clear()
    from zaqorincore_server.api.v1 import evidence as evidence_mod
    evidence_mod._STORE.base_dir = tmp_path / "evidence"
    return TestClient(create_app())


def test_canary_create_list_delete(client: TestClient) -> None:
    r = client.post(
        "/api/v1/canary",
        params={"host_id": "host-1"},
        json={"kind": "file", "path": "/var/lib/canary/m1.txt"},
    )
    assert r.status_code == 201, r.text
    out = r.json()
    cid = out["id"]
    assert out["kind"] == "file"
    assert out["host_id"] == "host-1"

    r = client.get("/api/v1/canary")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["id"] == cid

    r = client.delete(f"/api/v1/canary/{cid}")
    assert r.status_code == 204
    r = client.get("/api/v1/canary")
    assert r.json() == []


def test_canary_touched_returns_accepted(client: TestClient) -> None:
    r = client.post(
        "/api/v1/canary/touched",
        json={"canary_id": "c1", "host_id": "host-1", "touched_by": "203.0.113.7"},
    )
    assert r.status_code == 202
    body = r.json()
    assert body["canary_id"] == "c1"
    assert body["touched_by"] == "203.0.113.7"


def test_evidence_submit_and_verify(client: TestClient) -> None:
    # Build a real tarball in memory.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in (("a.txt", b"alpha"), ("b.txt", b"bravo")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    bundle = buf.getvalue()
    sha = hashlib.sha256(bundle).hexdigest()
    # The wire format is base64 — pydantic v2 `bytes` validation
    # is ambiguous (str→bytes, not base64-decode), so the schema
    # uses `tarball_b64` for explicit safety.
    payload = {
        "alert_id": "alert-1",
        "host_id": "host-1",
        "captured_at": "2026-08-28T12:00:00",
        "captured_by": "operator-1",
        "bundle_sha256": sha,
        "source_hashes": {
            "a.txt": hashlib.sha256(b"alpha").hexdigest(),
            "b.txt": hashlib.sha256(b"bravo").hexdigest(),
        },
        "tarball_b64": base64.b64encode(bundle).decode("ascii"),
    }
    r = client.post("/api/v1/evidence", json=payload)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["alert_id"] == "alert-1"
    assert body["bundle_sha256"] == sha
    assert len(body["sidecar_signature"]) == 64

    r = client.get("/api/v1/evidence/alert-1/verify")
    assert r.status_code == 200
    assert r.json()["verified"] is True

    r = client.get("/api/v1/evidence/alert-1/sidecar")
    assert r.status_code == 200
    sidecar = r.json()
    assert sidecar["alert_id"] == "alert-1"
    assert sidecar["captured_by"] == "operator-1"


def test_evidence_rejects_bad_hash(client: TestClient) -> None:
    # Build a real (small) tarball so we have real bytes to
    # tamper with.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in (("x.txt", b"data"),):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    bundle = buf.getvalue()
    real_sha = hashlib.sha256(bundle).hexdigest()
    # Build a tampered tarball (one byte flipped) for the
    # mismatch test.
    tampered = bytearray(bundle)
    tampered[10] ^= 0xFF
    payload = {
        "alert_id": "alert-bad",
        "host_id": "host-1",
        "captured_at": "2026-08-28T12:00:00",
        "captured_by": "operator-1",
        "bundle_sha256": real_sha,
        "source_hashes": {"x.txt": hashlib.sha256(b"data").hexdigest()},
        "tarball_b64": base64.b64encode(bytes(tampered)).decode("ascii"),
    }
    r = client.post("/api/v1/evidence", json=payload)
    assert r.status_code == 400
    assert "mismatch" in r.json()["detail"]
