"""HMAC signing + verification for COMMAND frames.

Wire format (canonical, pipe-separated, no JSON):
    {id}|{kind}|{target}|{ttl_sec}|{issued_at}

`issued_at` is the RFC3339 string. The receiver re-canonicalises
the frame's fields and compares HMAC-SHA256(secret, canonical)
to the hex `hmac` field using `hmac.compare_digest`.

Why canonical-form signing and not "sign the JSON"?
- It removes the JSON-encoding ambiguity (whitespace,
  key ordering, unicode escapes).
- It mirrors how the Go verifier will reconstruct the
  payload on the agent side.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_HASH = hashlib.sha256


def new_host_secret() -> str:
    """32 random bytes, base64url-encoded (no padding). 43 chars."""
    return secrets.token_urlsafe(32)


def canonical_form(
    *,
    command_id: str,
    kind: str,
    target: str,
    ttl_sec: int,
    issued_at: str,
) -> bytes:
    """Bytes the HMAC is computed over."""
    return f"{command_id}|{kind}|{target}|{ttl_sec}|{issued_at}".encode("utf-8")


def sign_command(
    *,
    secret: str,
    command_id: str,
    kind: str,
    target: str,
    ttl_sec: int,
    issued_at: str,
) -> str:
    """Return the hex HMAC-SHA256 of the canonical form."""
    payload = canonical_form(
        command_id=command_id,
        kind=kind,
        target=target,
        ttl_sec=ttl_sec,
        issued_at=issued_at,
    )
    return hmac.new(secret.encode("utf-8"), payload, _HASH).hexdigest()


def verify_command(
    *,
    secret: str,
    command_id: str,
    kind: str,
    target: str,
    ttl_sec: int,
    issued_at: str,
    hmac_hex: str,
) -> bool:
    """Constant-time compare of the received HMAC to a fresh computation."""
    expected = sign_command(
        secret=secret,
        command_id=command_id,
        kind=kind,
        target=target,
        ttl_sec=ttl_sec,
        issued_at=issued_at,
    )
    return hmac.compare_digest(expected, hmac_hex.lower())
