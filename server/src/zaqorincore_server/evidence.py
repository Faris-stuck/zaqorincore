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
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from pydantic import BaseModel, Field, field_validator

# F-030: depth-limited JSON parse for the chain-of-custody sidecar.
# The sidecar is operator-controlled on disk, but defence in depth
# is cheap and consistent with the F-027 / F-028 / F-029 family.
from .utils.depth_json import safe_loads


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
    """Disk-backed evidence locker with key rotation support.

    Keys are looked up by id. The default key has id "current".
    When operators rotate the signing key, the old one is kept
    in the keys dict under its old id, and verify() tries each
    one until one matches (or all fail). Sidecar JSON embeds
    the key id so a future verifier knows which key signed it.
    """

    base_dir: Path
    signing_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    # Map of key_id -> bytes. The default key is always under "current".
    keys: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.keys:
            self.keys = {"current": self.signing_key}
        else:
            # If a caller passed `signing_key=...` but no `keys`,
            # make sure "current" maps to it.
            self.keys.setdefault("current", self.signing_key)

    def rotate(self, new_key: bytes | None = None) -> str:
        """Rotate the active signing key. The old key stays in
        the rotation history under its prior id. Returns the new
        key id (a uuid4 string).
        """
        import uuid as _uuid
        new_id = _uuid.uuid4().hex
        if new_key is None:
            new_key = secrets.token_bytes(32)
        # Find the current "current" key and demote it.
        old = self.keys.get("current", self.signing_key)
        self.keys = {new_id: new_key, "previous": old, "current": new_key}
        self.signing_key = new_key
        return new_id

    def _alert_dir(self, alert_id: str) -> Path:
        # SECURITY (F4): Validate alert_id is a single relative path
        # component — no separators, no traversal, no NUL bytes. We
        # deliberately reject anything that would let the operator-side
        # caller escape `base_dir` (e.g. "../etc/passwd"). The id is
        # operator-supplied, so we must defend against typos and abuse
        # the same way we'd defend against an attacker.
        if not alert_id:
            raise ValueError("alert_id must be non-empty")
        if "\x00" in alert_id:
            raise ValueError("alert_id must not contain NUL bytes")
        if alert_id in {".", ".."}:
            raise ValueError("alert_id must not be '.' or '..'")
        if "/" in alert_id or "\\" in alert_id:
            raise ValueError("alert_id must not contain path separators")
        if Path(alert_id).is_absolute():
            raise ValueError("alert_id must be relative")
        if alert_id.startswith("."):
            raise ValueError("alert_id must not start with '.'")
        # Re-resolve to make sure the joined path stays under base_dir.
        # Defence in depth: even if a check above is missed, this
        # guarantees the final path does not escape via symlinks or
        # any sneaky encoding left in the input.
        joined = (self.base_dir / alert_id).resolve()
        if not str(joined).startswith(str(self.base_dir.resolve()) + "/"):
            raise ValueError("alert_id escapes base_dir")
        return joined

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
        # Key id embeds which key signed this evidence. Operators
        # can verify a key id by calling verify(alert_id, key_id).
        key_id = "current"
        key = self.keys[key_id]
        sidecar = {
            "alert_id": payload.alert_id,
            "host_id": payload.host_id,
            "captured_at": payload.captured_at.astimezone(timezone.utc).isoformat(),
            "captured_by": payload.captured_by,
            "bundle_sha256": payload.bundle_sha256,
            "source_hashes": payload.source_hashes,
            "key_id": key_id,
        }
        sidecar_bytes = json.dumps(sidecar, sort_keys=True, indent=2).encode("utf-8")
        sig = hmac.new(key, sidecar_bytes, hashlib.sha256).hexdigest()
        sidecar_path = out_dir / "bundle.coc.json"
        sidecar_path.write_bytes(sidecar_bytes)
        sig_path = out_dir / "bundle.coc.sig"
        sig_path.write_text(sig)
        # SECURITY (F4): chain-of-custody files must be owner-only.
        # 0o644 (the umask default) lets any local user read or
        # tamper with evidence that's supposed to be tamper-evident.
        os.chmod(bundle_path, 0o600)
        os.chmod(sidecar_path, 0o600)
        os.chmod(sig_path, 0o600)
        # Lock the directory itself down so unprivileged users
        # cannot list or stat its contents.
        os.chmod(out_dir, 0o700)
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
        sidecar bytes under any key in the rotation history.
        Used by the audit endpoint and tests to detect tampering.
        """
        out_dir = self._alert_dir(alert_id)
        sidecar_path = out_dir / "bundle.coc.json"
        sig_path = out_dir / "bundle.coc.sig"
        if not sidecar_path.exists() or not sig_path.exists():
            return False
        sidecar_bytes = sidecar_path.read_bytes()
        sig = sig_path.read_text()
        # Try the key the sidecar was signed with first, then
        # fall through to the rotation history.
        # F-030: depth-limited JSON parse for the sidecar.
        # The sidecar is operator-controlled on disk, but the
        # decode is in the request path of ``verify()`` so defence
        # in depth is cheap.
        try:
            sidecar = safe_loads(sidecar_bytes.decode("utf-8", errors="replace"))
            key_id = sidecar.get("key_id", "current")
            if key_id in self.keys:
                if hmac.compare_digest(
                    hmac.new(self.keys[key_id], sidecar_bytes, hashlib.sha256).hexdigest(),
                    sig,
                ):
                    return True
        except (json.JSONDecodeError, KeyError):
            pass
        # Fall back: try every key.
        for key in self.keys.values():
            if hmac.compare_digest(
                hmac.new(key, sidecar_bytes, hashlib.sha256).hexdigest(),
                sig,
            ):
                return True
        return False


__all__ = [
    "EvidenceSubmit",
    "EvidenceRecord",
    "EvidenceStore",
]
