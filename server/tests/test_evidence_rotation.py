"""Tests for evidence key rotation (Phase 8)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

import tarfile
import io
import base64
import hashlib

from zaqorincore_server.evidence import EvidenceStore, EvidenceSubmit


def _make_submit(alert_id: str = "alert-1") -> EvidenceSubmit:
    with NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        path = f.name
    with tarfile.open(path, "w:gz") as tf:
        for name, body in (("a.txt", b"alpha"), ("b.txt", b"bravo")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    bundle = Path(path).read_bytes()
    return EvidenceSubmit(
        alert_id=alert_id,
        host_id="host-1",
        captured_at=datetime(2026, 8, 28, tzinfo=timezone.utc),
        captured_by="operator-1",
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        source_hashes={"a.txt": hashlib.sha256(b"alpha").hexdigest()},
        tarball_b64=base64.b64encode(bundle).decode("ascii"),
    )


def test_rotate_changes_active_key(tmp_path) -> None:
    store = EvidenceStore(base_dir=tmp_path)
    old_key = store.signing_key
    new_id = store.rotate()
    assert new_id in store.keys
    assert store.signing_key != old_key
    # The old key should still be in the rotation history.
    assert "previous" in store.keys
    assert store.keys["previous"] == old_key
    # "current" must point at the new key.
    assert store.keys["current"] == store.signing_key


def test_evidence_verifies_across_rotation(tmp_path) -> None:
    """Evidence signed with the old key should still verify
    after a rotation, because the old key is kept in history.
    """
    store = EvidenceStore(base_dir=tmp_path)
    store.submit(_make_submit("alert-1"))
    assert store.verify("alert-1") is True

    # Rotate; old evidence must still verify.
    store.rotate()
    assert store.verify("alert-1") is True

    # New evidence signed with new key.
    store.submit(_make_submit("alert-2"))
    assert store.verify("alert-2") is True

    # Both old and new still verify.
    assert store.verify("alert-1") is True
    assert store.verify("alert-2") is True


def test_sidecar_records_key_id(tmp_path) -> None:
    """The sidecar JSON should record which key signed it."""
    import json
    store = EvidenceStore(base_dir=tmp_path)
    store.submit(_make_submit("alert-1"))
    sidecar = json.loads((tmp_path / "alert-1" / "bundle.coc.json").read_text())
    assert "key_id" in sidecar
    assert sidecar["key_id"] == "current"


def test_verify_fails_for_evidence_signed_with_unknown_key(tmp_path) -> None:
    """Evidence signed with a key that's been completely removed
    from rotation should fail verification.
    """
    store = EvidenceStore(base_dir=tmp_path)
    store.submit(_make_submit("alert-1"))
    # Replace the keys dict entirely (simulating key wipe).
    store.keys = {"newkey": b"\x00" * 32}
    store.signing_key = b"\x00" * 32
    assert store.verify("alert-1") is False
