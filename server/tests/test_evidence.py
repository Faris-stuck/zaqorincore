"""Tests for the evidence locker (Phase 7)."""

from __future__ import annotations

import hashlib
import hmac
import json
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zaqorincore_server.evidence import (
    EvidenceStore,
    EvidenceSubmit,
)


def _make_submit(alert_id: str = "alert-1") -> EvidenceSubmit:
    """Build a tiny tar.gz with two files and matching hashes."""
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        path = f.name
    with tarfile.open(path, "w:gz") as tf:
        for name, body in (("a.txt", b"alpha"), ("b.txt", b"bravo")):
            import io
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    bundle = Path(path).read_bytes()
    import base64
    return EvidenceSubmit(
        alert_id=alert_id,
        host_id="host-1",
        captured_at=datetime(2026, 8, 28, tzinfo=timezone.utc),
        captured_by="operator-1",
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        source_hashes={"a.txt": hashlib.sha256(b"alpha").hexdigest(),
                        "b.txt": hashlib.sha256(b"bravo").hexdigest()},
        tarball_b64=base64.b64encode(bundle).decode("ascii"),
    )


def test_submit_persists_bundle_and_sidecar(tmp_path) -> None:
    store = EvidenceStore(base_dir=tmp_path)
    record = store.submit(_make_submit())
    assert record.bundle_path.endswith("bundle.tar.gz")
    assert record.sidecar_path.endswith("bundle.coc.json")
    assert Path(record.bundle_path).exists()
    assert Path(record.sidecar_path).exists()
    # Sidecar signature file written.
    sig_path = Path(record.sidecar_path).with_suffix(".sig")
    assert sig_path.exists()
    # Sign and verify: signature file is hex hmac-sha256 (64 chars).
    assert len(record.sidecar_signature) == 64
    assert store.verify("alert-1") is True


def test_submit_rejects_bundle_hash_mismatch(tmp_path) -> None:
    s = _make_submit()
    s.bundle_sha256 = "0" * 64  # obviously wrong
    store = EvidenceStore(base_dir=tmp_path)
    with pytest.raises(ValueError, match="bundle_sha256 mismatch"):
        store.submit(s)
    # Nothing should have been written. The alert-1 dir may or may
    # not exist (we don't mkdir until after verify passes), so check
    # that no bundle file is present anywhere.
    assert not (tmp_path / "alert-1" / "bundle.tar.gz").exists()


def test_verify_detects_tampered_sidecar(tmp_path) -> None:
    store = EvidenceStore(base_dir=tmp_path)
    store.submit(_make_submit())
    # Tamper with the sidecar JSON.
    sidecar = tmp_path / "alert-1" / "bundle.coc.json"
    body = json.loads(sidecar.read_text())
    body["captured_by"] = "evil"
    sidecar.write_text(json.dumps(body))
    assert store.verify("alert-1") is False


def test_verify_returns_false_for_missing_alert(tmp_path) -> None:
    store = EvidenceStore(base_dir=tmp_path)
    assert store.verify("nope") is False
