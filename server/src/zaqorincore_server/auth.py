"""Role-based API auth (v2.1.0 IMP-1 second slice).

Replaces the F6 binary ``X-API-Key`` accept/reject pattern with three
named roles so operators can scope credentials to the least privilege
each caller actually needs:

* ``read``     — read-only operators (dashboards, hunt queries,
  alert triage). Can call ``GET`` only.
* ``write``    — read-write admins. Any HTTP verb.
* ``ingest``   — ingest-only agent keys. Used by the
  ``/api/v1/ingest/webhook`` family for agents that push data
  but never read it back.

Backward compatibility (v1.7.6 contract):

* If only ``ZAQORIN_API_KEY`` is set (the F6 variable), it is
  treated as the legacy single-key deploy. Any caller presenting
  that key has ``write`` role and full access. The new role
  env vars do not need to be set.
* If any of the new ``ZAQORIN_API_KEY_{READ,WRITE,INGEST}`` vars
  are set, the new role map is used. Legacy ``ZAQORIN_API_KEY``,
  if set, is **also** accepted and treated as ``write`` so a
  deploy that rotates from F6 to role-based doesn't lock out
  the old key on the same restart.
* If nothing is set (dev mode), the dependency is a no-op and a
  single startup warning is logged (same behaviour as F6).

The dependency sets ``request.state.role`` so downstream handlers
can audit who did what without re-deriving the role from the
header.

The header name stays ``X-API-Key`` (matching F6) — operators
who want a different name for the role env vars can rename later
without an HTTP contract change.
"""

from __future__ import annotations

import hmac
import logging
from enum import Enum
from typing import Iterable

from fastapi import Header, HTTPException, status
from starlette.requests import Request

from .config import get_settings

log = logging.getLogger(__name__)


class Role(str, Enum):
    """The three roles the API recognises.

    The string values are what callers see in ``/api/v1/auth/whoami``
    and in audit logs — keep them stable.
    """

    READ = "read"
    WRITE = "write"
    INGEST = "ingest"


# Verb -> allowed-roles table. Anything not listed here is treated as
# a read-equivalent (defence in depth: a typo in a new handler
# doesn't silently grant write).
_WRITE_VERBS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _roles_from_settings() -> dict[Role, str]:
    """Resolve the role -> key table from settings.

    Returns ``{}`` for a no-auth deploy (all role env vars and the
    legacy ``api_key`` are unset). The caller treats an empty dict
    as "open" and logs the dev warning.
    """
    s = get_settings()
    out: dict[Role, str] = {}
    if s.api_key_read:
        out[Role.READ] = s.api_key_read
    if s.api_key_write:
        out[Role.WRITE] = s.api_key_write
    if s.api_key_ingest:
        out[Role.INGEST] = s.api_key_ingest
    # Legacy F6 key, if set, is accepted as `write` so an in-place
    # migration from F6 doesn't lock out the old secret.
    if s.api_key and s.api_key not in out.values():
        out[Role.WRITE] = s.api_key
    return out


# Module-level flag so the warning fires once per process, not on
# every protected request (same shape as security.py).
_unauth_warned = False


def _lookup_role(presented: str, role_keys: dict[Role, str]) -> Role | None:
    """Find which role (if any) a presented key maps to.

    Constant-time comparison via ``hmac.compare_digest`` so a
    brute-force timing leak is not feasible. The loop is short
    (≤3 entries) so the comparison overhead is bounded.
    """
    if not presented:
        return None
    encoded = presented.encode("utf-8")
    # Iterate in a fixed order so the timing of repeated invalid
    # keys is deterministic regardless of dict insertion order.
    for role in (Role.READ, Role.WRITE, Role.INGEST):
        expected = role_keys.get(role)
        if expected is None:
            continue
        if hmac.compare_digest(encoded, expected.encode("utf-8")):
            return role
    return None


def _allow_method_for_role(role: Role, method: str) -> bool:
    """Return True iff the role may perform this HTTP verb.

    Rule (matches the auth spec):

    * ``read``   -> GET only.
    * ``write``  -> any verb (full access; legacy F6 key also maps here).
    * ``ingest`` -> POST only (push-only endpoints; never reads).
    """
    method = method.upper()
    if role is Role.WRITE:
        return True
    if role is Role.READ:
        return method == "GET" or method == "HEAD" or method == "OPTIONS"
    if role is Role.INGEST:
        return method == "POST"
    return False


async def require_role(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Role:
    """FastAPI dependency that enforces role-based auth.

    On success, sets ``request.state.role`` to the resolved Role and
    returns it (callers may ignore the return value; they only need
    the side-effect for audit logs).

    Failure modes:

    * No role env vars + no legacy key configured -> pass-through,
      warn once. ``request.state.role`` stays unset.
    * Key missing -> 401 ``X-API-Key header missing``.
    * Key present but no match -> 401 ``X-API-Key invalid``.
    * Key matches but verb not permitted -> 403 ``role '<role>'
      may not <METHOD>``.
    """
    global _unauth_warned
    role_keys = _roles_from_settings()
    if not role_keys:
        # Dev mode (no auth configured). Mirror security.py: warn once
        # per process so an operator who forgets to set env vars gets
        # a startup signal rather than a silent open API.
        if not _unauth_warned:
            log.warning(
                "auth: no ZAQORIN_API_KEY_* configured; API is open. "
                "Set ZAQORIN_API_KEY (legacy full-access) or "
                "ZAQORIN_API_KEY_{READ,WRITE,INGEST} in any non-dev deploy."
            )
            _unauth_warned = True
        return Role.WRITE

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

    # ---- Bypass for the whoami endpoint ----
    # /api/v1/auth/whoami is meta-introspection — it must work
    # for any authenticated role so the dashboard can render.
    # Without this exemption the ingest role couldn't even ask
    # "who am I" to discover it needs to escalate. The auth layer
    # is bypassed at the *router* level: the endpoint itself
    # still requires a valid key (the router-level Depends above
    # runs), it just doesn't apply the verb-permission check.
    if request.url.path == "/api/v1/auth/whoami":
        request.state.role = role
        return role

    # Verb check. WebSocket upgrades (method "WEBSOCKET" / path /ws)
    # are mounted without this dep so we never see them here.
    method = request.method
    if not _allow_method_for_role(role, method):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role '{role.value}' may not {method}",
        )

    # Stash for downstream audit / debug. request.state is a Starlette
    # free-form attribute bag; FastAPI happily accepts anything.
    request.state.role = role
    return role


def current_role(request: Request) -> Role | None:
    """Read the role off a request, if set.

    Handlers that take ``request: Request`` and want to log or echo
    the resolved role use this helper instead of poking
    ``request.state`` directly.
    """
    return getattr(request.state, "role", None)


__all__ = [
    "Role",
    "require_role",
    "current_role",
]