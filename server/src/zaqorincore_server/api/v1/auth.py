"""``/api/v1/auth`` — operator self-introspection endpoint.

Currently a single endpoint, ``GET /api/v1/auth/whoami``, that
returns the role the server resolved from the ``X-API-Key``
header on the request. The web console calls this on dashboard
load to decide whether to show admin-only controls (e.g. the
``Replay dead letter`` button on the SOAR view, the canary
``Add/Remove`` controls).

The endpoint is itself protected by ``require_role`` so an
unauthenticated caller gets 401, not 200. In dev mode (no keys
configured) the dependency is a no-op and the response reports
``role: "write"`` with ``dev_mode: true`` so the dashboard can
still render an admin view during local development.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ...auth import Role, require_role
from ...config import get_settings

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
    dependencies=[Depends(require_role)],
)


class WhoAmIOut(BaseModel):
    """Response body for ``GET /api/v1/auth/whoami``.

    ``role`` is the resolved role (``read`` / ``write`` / ``ingest``).
    In dev mode (no API keys configured), ``dev_mode`` is true and
    ``role`` reports ``write`` so the dashboard can render the
    admin view.
    """

    role: Role
    dev_mode: bool
    configured_roles: list[Role]


@router.get("/whoami", response_model=WhoAmIOut)
async def whoami(role: Role = Depends(require_role)) -> WhoAmIOut:
    """Return the role resolved from the caller's X-API-Key header.

    The dependency runs twice (once at the router level, once for
    this handler) but FastAPI caches the result within a single
    request so the lookup only happens once.
    """
    settings = get_settings()
    configured: list[Role] = []
    if settings.api_key_read:
        configured.append(Role.READ)
    if settings.api_key_write:
        configured.append(Role.WRITE)
    if settings.api_key_ingest:
        configured.append(Role.INGEST)
    legacy = bool(settings.api_key and settings.api_key not in {
        settings.api_key_read,
        settings.api_key_write,
        settings.api_key_ingest,
    })
    dev_mode = not (
        settings.api_key
        or settings.api_key_read
        or settings.api_key_write
        or settings.api_key_ingest
    )
    if legacy and Role.WRITE not in configured:
        configured.append(Role.WRITE)
    return WhoAmIOut(
        role=role,
        dev_mode=dev_mode,
        configured_roles=configured,
    )


__all__ = ["router"]