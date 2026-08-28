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

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from ...evidence import EvidenceStore, EvidenceSubmit


router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


# Disk-backed store. The base dir is configurable via env so
# production deployments can mount a separate volume.
_BASE_DIR = Path(os.environ.get(
    "ZAQORIN_EVIDENCE_DIR",
    "/var/lib/zaqorincore/evidence",
))
# The signing key comes from env. Phase 7 ships a placeholder
# so the endpoint works in dev. Operators must set
# ZAQORIN_EVIDENCE_KEY to a real 32-byte secret in production.
_SIGNING_KEY = os.environ.get(
    "ZAQORIN_EVIDENCE_KEY",
    "zaqorincore-dev-evidence-key-change-me",
).encode("utf-8")
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
    return json.loads(sidecar_path.read_text())


__all__ = ["router"]
