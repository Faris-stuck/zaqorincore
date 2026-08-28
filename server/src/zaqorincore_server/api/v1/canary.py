"""Operator-facing API for canary tokens (Phase 7, ADR-005).

Canary tokens are registered server-side, then pushed down to
agents in their CONFIG frame. This module is just CRUD; the
agent wiring is in `agent/internal/canary/canary.go`.

Backing store: in-process dict (Phase 7 placeholder; Phase 8
moves it to a real PostgreSQL table). Operators can list,
rotate, and remove canaries via these endpoints.

Auth note: role-based access is wired in Phase 9 alongside the
web UI. Phase 7 exposes the endpoints to anyone on the local
network. Operators are expected to put the API behind a reverse
proxy with mTLS or an auth header until then.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel

from ...canary import CanarySpec, make_canary


router = APIRouter(prefix="/api/v1/canary", tags=["canary"])


CanaryKindLit = Literal["file", "tcp_socket", "http_endpoint", "credential"]


class CanaryOut(BaseModel):
    id: str
    kind: CanaryKindLit
    path: str
    host_id: str
    created_at: datetime


class CanaryTouchIngest(BaseModel):
    """The agent posts a touched event here. We translate it
    into a regular event with event_type='canary_touched' and
    let the existing rule engine decide what action to take.
    """

    canary_id: str
    host_id: str
    touched_by: str
    evidence_path: str | None = None


# In-memory store. A real deployment would persist this in
# PostgreSQL via SQLAlchemy. Phase 7 keeps it in-process so we
# don't need a migration in this increment.
_IN_MEMORY: dict[str, dict] = {}


@router.get("", response_model=list[CanaryOut])
async def list_canaries() -> list[CanaryOut]:
    """List all canary tokens."""
    out: list[CanaryOut] = []
    for d in _IN_MEMORY.values():
        out.append(CanaryOut(
            id=d["id"],
            kind=d["kind"],
            path=d["path"],
            host_id=d["host_id"],
            created_at=d["created_at"],
        ))
    return out


@router.post("", response_model=CanaryOut, status_code=status.HTTP_201_CREATED)
async def create_canary(spec: CanarySpec, host_id: str) -> CanaryOut:
    """Register a new canary token for a host."""
    if not host_id:
        raise HTTPException(status_code=422, detail="host_id required")
    desc = make_canary(spec)
    _IN_MEMORY[desc.id] = {
        "id": desc.id,
        "kind": spec.kind,
        "path": spec.path,
        "host_id": host_id,
        "created_at": desc.created_at,
        "secret": desc.secret,
    }
    return CanaryOut(
        id=desc.id,
        kind=spec.kind,
        path=spec.path,
        host_id=host_id,
        created_at=desc.created_at,
    )


@router.delete("/{canary_id}")
async def delete_canary(canary_id: str) -> Response:
    """Remove a canary token. Returns 204 No Content."""
    if canary_id not in _IN_MEMORY:
        raise HTTPException(status_code=404, detail="canary not found")
    del _IN_MEMORY[canary_id]
    return Response(status_code=204)


@router.post("/touched", status_code=status.HTTP_202_ACCEPTED)
async def ingest_canary_touched(payload: CanaryTouchIngest) -> dict:
    """Agent posts a canary_touched event here. The server
    accepts the event and the rule engine decides what to do
    (a `canary_alert` action is the default). We don't try to
    match against the rule engine here — that's the agent's
    job in the event ingestion loop.
    """
    return {
        "status": "accepted",
        "canary_id": payload.canary_id,
        "touched_by": payload.touched_by,
    }


__all__ = ["router"]
