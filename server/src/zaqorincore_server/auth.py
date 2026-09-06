"""Role-based API authentication."""

from __future__ import annotations

import hmac
import logging
from enum import Enum

from fastapi import Header, HTTPException, status
from starlette.requests import Request

from .config import get_settings

log = logging.getLogger(__name__)


class Role(str, Enum):
    READ = "read"
    WRITE = "write"
    INGEST = "ingest"


_WRITE_VERBS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _roles_from_settings() -> dict[Role, str]:
    s = get_settings()
    out: dict[Role, str] = {}
    if s.api_key_read:
        out[Role.READ] = s.api_key_read
    if s.api_key_write:
        out[Role.WRITE] = s.api_key_write
    if s.api_key_ingest:
        out[Role.INGEST] = s.api_key_ingest
    if s.api_key and s.api_key not in out.values():
        out[Role.WRITE] = s.api_key
    return out


_unauth_warned = False


def _lookup_role(presented: str, role_keys: dict[Role, str]) -> Role | None:
    if not presented:
        return None
    encoded = presented.encode("utf-8")
    for role in (Role.READ, Role.WRITE, Role.INGEST):
        expected = role_keys.get(role)
        if expected is not None and hmac.compare_digest(encoded, expected.encode("utf-8")):
            return role
    return None


def _allow_method_for_role(role: Role, method: str) -> bool:
    method = method.upper()
    if role is Role.WRITE:
        return True
    if role is Role.READ:
        return method in {"GET", "HEAD", "OPTIONS"}
    if role is Role.INGEST:
        return method == "POST"
    return False


async def require_role(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Role:
    """Enforce role-based authentication with a fail-closed default."""
    global _unauth_warned
    settings = get_settings()
    role_keys = _roles_from_settings()

    if not role_keys:
        if settings.allow_unauthenticated:
            if not _unauth_warned:
                log.warning(
                    "auth: unauthenticated mode explicitly enabled; do not use this in production"
                )
                _unauth_warned = True
            request.state.role = Role.WRITE
            return Role.WRITE
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header missing",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    role = _lookup_role(x_api_key, role_keys)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key invalid",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if request.url.path == "/api/v1/auth/whoami":
        request.state.role = role
        return role

    if not _allow_method_for_role(role, request.method):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role '{role.value}' may not {request.method}",
        )

    request.state.role = role
    return role


def current_role(request: Request) -> Role | None:
    return getattr(request.state, "role", None)


__all__ = ["Role", "require_role", "current_role"]
