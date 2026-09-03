"""Operator-facing API for the evidence locker (Phase 7, ADR-005).

Endpoints:
  POST /api/v1/evidence   — agent submits a captured bundle
  GET  /api/v1/evidence/{alert_id}/verify — operator verifies chain-of-custody
  GET  /api/v1/evidence/{alert_id}/sidecar — fetch the sidecar metadata
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ...evidence import EvidenceStore, EvidenceSubmit
from ...security import require_api_key
# F-030: depth-limited JSON parse for the sidecar metadata read.
# The sidecar is operator-controlled on disk, but defence in
# depth is cheap.
from ...utils.depth_json import safe_loads


router = APIRouter(
    prefix="/api/v1/evidence",
    tags=["evidence"],
    dependencies=[Depends(require_api_key)],
)


# Disk-backed store. The base dir is configurable via env so
# production deployments can mount a separate volume.
_BASE_DIR = Path(os.environ.get(
    "ZAQORIN_EVIDENCE_DIR",
    "/var/lib/zaqorincore/evidence",
))
# The signing key comes from env. SECURITY (F5): in production the
# placeholder below is REJECTED at import time so an operator cannot
# accidentally run with the well-known dev key. In dev (ZAQORIN_ENV=dev
# or absence of ZAQORIN_EVIDENCE_KEY together with --allow-dev-keys
# flag passed via PYTHONHINTS — out of scope here), the placeholder is
# used and a loud warning is logged. We do this at import time so a
# misconfigured prod deploy fails to start rather than silently signing
# evidence with a public key.
_PROD_PLACEHOLDER = "zaqorincore-dev-evidence-key-change-me"
_env_key = os.environ.get("ZAQORIN_EVIDENCE_KEY", "")
_is_dev = os.environ.get("ZAQORIN_ENV", "production") != "production"
if not _env_key:
    if _is_dev:
        import warnings as _w
        _w.warn(
            "ZAQORIN_EVIDENCE_KEY not set; using insecure placeholder. "
            "Set ZAQORIN_EVIDENCE_KEY to a 32+ byte secret in production.",
            stacklevel=2,
        )
        _env_key = _PROD_PLACEHOLDER
    else:
        raise RuntimeError(
            "ZAQORIN_EVIDENCE_KEY must be set to a 32+ byte secret. "
            "Refusing to start with the well-known dev placeholder in "
            "production. Generate one with: python -c 'import secrets; "
            "print(secrets.token_urlsafe(32))'"
        )
elif _env_key == _PROD_PLACEHOLDER and not _is_dev:
    raise RuntimeError(
        "ZAQORIN_EVIDENCE_KEY is set to the well-known dev placeholder. "
        "Refusing to start in production. Generate a real secret with: "
        "python -c 'import secrets; print(secrets.token_urlsafe(32))'"
    )
_SIGNING_KEY = _env_key.encode("utf-8")
_STORE = EvidenceStore(base_dir=_BASE_DIR, signing_key=_SIGNING_KEY)


class SubmitAck(BaseModel):
    alert_id: str
    bundle_sha256: str
    sidecar_signature: str


@router.post("", response_model=SubmitAck, status_code=status.HTTP_201_CREATED)
async def submit_evidence(payload: EvidenceSubmit) -> SubmitAck:
    """Agent posts a captured bundle. We verify the SHA-256,
    write the bundle + sidecar + sig, and return the chain-of-
    custody signature for the agent's audit log.
    """
    try:
        rec = _STORE.submit(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SubmitAck(
        alert_id=rec.alert_id,
        bundle_sha256=rec.bundle_sha256,
        sidecar_signature=rec.sidecar_signature,
    )


@router.get("/{alert_id}/verify", response_model=dict)
async def verify_evidence(alert_id: str) -> dict:
    """Verify the chain-of-custody sidecar signature."""
    ok = _STORE.verify(alert_id)
    return {"alert_id": alert_id, "verified": ok}


@router.get("/{alert_id}/sidecar", response_model=dict)
async def get_sidecar(alert_id: str) -> dict:
    """Fetch the sidecar metadata for an alert."""
    sidecar_path = _STORE._alert_dir(alert_id) / "bundle.coc.json"
    if not sidecar_path.exists():
        raise HTTPException(status_code=404, detail="not found")
    return safe_loads(sidecar_path.read_text())


__all__ = ["router"]
