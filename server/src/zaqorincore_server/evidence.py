"""Evidence locker (Phase 7, ADR-005).

When an alert fires, an operator (or the auto-response policy)
can attach an `evidence_capture` action. The agent collects a
snapshot of the relevant files, tar+SHA-256 hashes them, and
ships the bundle to the server. The server stores it under
`evidence/<alert_id>.tar.gz` with a chain-of-custody sidecar.

This module runs on the server. The agent's collector lives
in `agent/internal/evidence/evidence.go`.

Chain-of-custody model:

  1. Agent captures files into a tarball. SHA-256 of the
     original files is computed BEFORE they go into the tar.
  2. The tarball's SHA-256 is computed after the tar.
  3. Both hashes are sent to the server in the
     `evidence.submit` frame, plus the agent's host id and
     the operator (or auto-policy) that triggered the capture.
  4. The server writes the tarball to
     `evidence/<alert_id>.tar.gz` and the sidecar
     `evidence/<alert_id>.coc.json` with:
       - alert_id
       - host_id
       - captured_at (UTC)
       - source_hashes: {filename: sha256}
       - bundle_sha256: sha256
       - captured_by: string
       - signed_by: server HMAC of the sidecar

The sidecar signature is what makes the bundle admissible in
a forensic review: any change to either the tarball or the
sidecar invalidates the chain.
"""

from __future__ import annotations

import hashlib
import hmac
import base64
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from pydantic import BaseModel, Field, field_validator


class EvidenceSubmit(BaseModel):
    """Payload the agent sends with the captured tarball."""

    model_config = {"arbitrary_types_allowed": True}

    alert_id: str
    host_id: str
    captured_at: datetime
    captured_by: str = Field(..., description="Username or auto-policy name that triggered the capture")
    bundle_sha256: str = Field(..., description="SHA-256 of the tarball bytes")
    source_hashes: dict[str, str] = Field(
        default_factory=dict,
        description="Map of filename -> SHA-256, computed before the tar was made",
    )
    # The wire format is a base64-encoded string (so the field is
    # JSON-safe). Pydantic decodes it on the way in. We accept
    # `tarball_b64` as the canonical name and `tarball` as a
    # legacy alias for raw bytes — both are converted to `bytes`
    # before they reach the store.
    tarball_b64: str = Field(..., description="Base64-encoded tar+gz bytes")
    tarball: bytes | None = Field(default=None, description="Raw bytes (alternative to tarball_b64; not recommended)")

    @field_validator("tarball_b64", mode="before")
    @classmethod
    def _decode_b64(cls, v: Any) -> Any:
        if isinstance(v, (bytes, bytearray)):
            return v.decode("ascii")
        return v

    def as_tarball(self) -> bytes:
        """Return the tarball as raw bytes, regardless of which
        field was used to transport it.
        """
        if self.tarball is not None:
            return self.tarball
        return base64.b64decode(self.tarball_b64)


class EvidenceRecord(BaseModel):
    """Server-side record returned to the operator."""

    alert_id: str
    host_id: str
    captured_at: datetime
    captured_by: str
    bundle_sha256: str
    source_hashes: dict[str, str]
    bundle_path: str
    sidecar_path: str
    sidecar_signature: str


@dataclass
class EvidenceStore:
    """Disk-backed evidence locker."""

    base_dir: Path
    signing_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def _alert_dir(self, alert_id: str) -> Path:
        return self.base_dir / alert_id

    def submit(self, payload: EvidenceSubmit) -> EvidenceRecord:
        """Persist a tarball + sidecar. Returns the record.

        Verifies the bundle SHA-256 matches the payload before
        writing anything. A mismatch is a fatal error — we
        don't store evidence we can't vouch for.
        """
        tarball = payload.as_tarball()
        actual = hashlib.sha256(tarball).hexdigest()
        if not hmac.compare_digest(actual, payload.bundle_sha256):
            raise ValueError(
                f"bundle_sha256 mismatch: claimed {payload.bundle_sha256!r}, "
                f"actual {actual!r}"
            )
        out_dir = self._alert_dir(payload.alert_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = out_dir / "bundle.tar.gz"
        bundle_path.write_bytes(tarball)
        sidecar = {
            "alert_id": payload.alert_id,
            "host_id": payload.host_id,
            "captured_at": payload.captured_at.astimezone(timezone.utc).isoformat(),
            "captured_by": payload.captured_by,
            "bundle_sha256": payload.bundle_sha256,
            "source_hashes": payload.source_hashes,
        }
        sidecar_bytes = json.dumps(sidecar, sort_keys=True, indent=2).encode("utf-8")
        sig = hmac.new(self.signing_key, sidecar_bytes, hashlib.sha256).hexdigest()
        sidecar_path = out_dir / "bundle.coc.json"
        sidecar_path.write_bytes(sidecar_bytes)
        (out_dir / "bundle.coc.sig").write_text(sig)
        return EvidenceRecord(
            alert_id=payload.alert_id,
            host_id=payload.host_id,
            captured_at=payload.captured_at,
            captured_by=payload.captured_by,
            bundle_sha256=payload.bundle_sha256,
            source_hashes=payload.source_hashes,
            bundle_path=str(bundle_path),
            sidecar_path=str(sidecar_path),
            sidecar_signature=sig,
        )

    def verify(self, alert_id: str) -> bool:
        """Return True if the sidecar signature still matches the
        sidecar bytes. Used by the audit endpoint and tests to
        detect tampering.
        """
        out_dir = self._alert_dir(alert_id)
        sidecar_path = out_dir / "bundle.coc.json"
        sig_path = out_dir / "bundle.coc.sig"
        if not sidecar_path.exists() or not sig_path.exists():
            return False
        sidecar_bytes = sidecar_path.read_bytes()
        sig = sig_path.read_text()
        return hmac.compare_digest(
            hmac.new(self.signing_key, sidecar_bytes, hashlib.sha256).hexdigest(),
            sig,
        )


__all__ = [
    "EvidenceSubmit",
    "EvidenceRecord",
    "EvidenceStore",
]
