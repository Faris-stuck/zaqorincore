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
``role: "write"`` so the dashboard can still render an admin
view during local development.

F-012 fix (v3.2.2)
==================

The original payload also returned ``dev_mode`` and the full
``configured_roles`` list. Both leak state to a half-trusted
operator (a ``read``-role user, or a support engineer debugging
the dashboard) that does not need to know whether the server
is running with no keys at all. The redacted payload returns
only ``role`` to the caller. The dev-mode flag is still used
inside the server (other modules branch on it) — only the
network-visible surface is shrunk. When the server is started
with ``ZAQORIN_ENV=development``, the ``dev_mode`` flag is
included so a developer on localhost can verify which mode the
process booted in.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ...auth import Role, require_role

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
    dependencies=[Depends(require_role)],
)


class WhoAmIOut(BaseModel):
    """Response body for ``GET /api/v1/auth/whoami``.

    ``role`` is the resolved role (``read`` / ``write`` / ``ingest``).

    ``dev_mode`` is ONLY present when the process was started with
    ``ZAQORIN_ENV=development``. Production callers do not need to
    know that the server is running with no API keys configured —
    a leaked ``dev_mode: true`` from a remote deployment is exactly
    the recon signal F-012 documents.
    """

    role: Role
    dev_mode: bool | None = None


@router.get("/whoami", response_model=WhoAmIOut)
async def whoami(role: Role = Depends(require_role)) -> WhoAmIOut:
    """Return the role resolved from the caller's X-API-Key header.

    The dependency runs twice (once at the router level, once for
    this handler) but FastAPI caches the result within a single
    request so the lookup only happens once.
    """
    # F-012 fix (v3.2.2): only surface ``dev_mode`` to a process
    # booted with ``ZAQORIN_ENV=development``. The full
    # ``configured_roles`` list is intentionally NOT exposed to
    # the caller — knowing which roles are configured lets an
    # attacker map the auth surface without owning a key.
    is_dev_env = os.environ.get("ZAQORIN_ENV", "production") == "development"
    return WhoAmIOut(
        role=role,
        dev_mode=True if is_dev_env else None,
    )


__all__ = ["router"]