"""GET /api/v1/alerts — placeholder for Phase 3.

Returns an empty list for now. The endpoint exists so the API
contract is stable and clients can wire up against it.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
async def list_alerts() -> list[dict]:
    return []
